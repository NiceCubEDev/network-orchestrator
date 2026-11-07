use crate::daemon_client::DaemonClient;
use crate::state::AppState;
use net_manager_core::models::{Profile, TunnelBackend, TunnelState, XrayMode};
use serde::Serialize;
use std::collections::HashSet;
use std::future::Future;
use std::sync::Mutex;
use tauri::{Emitter, Manager, State};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AutoConnectResult {
    failed_count: usize,
    startup_failed: bool,
}

#[derive(Default)]
pub(crate) struct AutoConnectStatus {
    result: Mutex<Option<AutoConnectResult>>,
}

impl AutoConnectStatus {
    fn record(&self, result: AutoConnectResult) {
        *self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
    }

    fn current(&self) -> Result<Option<AutoConnectResult>, String> {
        self.result
            .lock()
            .map(|result| *result)
            .map_err(|_| "auto-connect result is unavailable".into())
    }
}

#[tauri::command]
pub(crate) fn get_auto_connect_result(
    status: State<'_, AutoConnectStatus>,
) -> Result<Option<AutoConnectResult>, String> {
    status.current()
}

pub(crate) fn daemon_owner(profile: &Profile) -> Option<String> {
    match profile.backend {
        TunnelBackend::None => Some(profile.id.clone()),
        TunnelBackend::WireGuard => Some(format!("wg:{}", profile.id)),
        TunnelBackend::OpenVpn => Some(format!("ovpn:{}", profile.id)),
        TunnelBackend::Xray if profile.xray_mode == XrayMode::Tun => {
            Some(format!("xray:{}", profile.id))
        }
        TunnelBackend::Xray => None,
    }
}

async fn connect_saved_profiles<F, Fut>(
    profiles: &[Profile],
    owners: &HashSet<String>,
    mut connect: F,
) -> Vec<String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let mut failures = Vec::new();
    let candidates = net_manager_core::connect_plan::auto_connect_candidates(profiles, |profile| {
        owners.contains(&daemon_owner(profile).unwrap_or_else(|| profile.id.clone()))
    });
    for profile in candidates {
        if connect(profile.id.clone()).await.is_err() {
            failures.push(profile.id.clone());
        }
    }
    failures
}

async fn connect_on_startup(app: &tauri::AppHandle) -> AutoConnectResult {
    let profiles = match app.state::<AppState>().profiles.load() {
        Ok(document) => document.profiles,
        Err(_) => {
            return AutoConnectResult {
                failed_count: 0,
                startup_failed: true,
            }
        }
    };
    if !profiles.iter().any(|profile| profile.auto_connect) {
        return AutoConnectResult {
            failed_count: 0,
            startup_failed: false,
        };
    }
    let client = DaemonClient::system();
    let mut owners = HashSet::new();
    let mut startup_failed = false;
    let state = app.state::<AppState>();
    for profile in profiles.iter().filter(|profile| profile.auto_connect) {
        let status = crate::commands::tunnels::linux_profile_status(&client, &state, profile).await;
        let skip = match status {
            Ok(status) => status.state == TunnelState::Running,
            Err(_) => {
                startup_failed = true;
                true // Unknown is not proof that another client has stopped it.
            }
        };
        if skip {
            owners.insert(daemon_owner(profile).unwrap_or_else(|| profile.id.clone()));
        }
    }
    let failures = connect_saved_profiles(&profiles, &owners, |id| {
        let app = app.clone();
        async move {
            let state = app.state::<AppState>();
            crate::commands::tunnels::connect_profile(id, state, app.clone())
                .await
                .map(|_| ())
        }
    })
    .await;
    AutoConnectResult {
        failed_count: failures.len(),
        startup_failed,
    }
}

pub(crate) async fn start(app: tauri::AppHandle) {
    let result = connect_on_startup(&app).await;
    app.state::<AutoConnectStatus>().record(result);
    let _ = app.emit("auto-connect-result", result);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::profile;
    use net_manager_core::models::{TunnelBackend, XrayMode};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    fn auto_profile(id: &str, backend: TunnelBackend) -> net_manager_core::models::Profile {
        let mut profile = profile(id);
        profile.id = id.into();
        profile.backend = backend;
        profile.auto_connect = true;
        profile
    }

    #[tokio::test]
    async fn saved_order_skips_disabled_and_existing_daemon_owners() {
        let mut disabled = auto_profile("disabled", TunnelBackend::WireGuard);
        disabled.auto_connect = false;
        let wg = auto_profile("wg", TunnelBackend::WireGuard);
        let static_routes = auto_profile("routes", TunnelBackend::None);
        let openvpn = auto_profile("ovpn", TunnelBackend::OpenVpn);
        let mut xray_tun = auto_profile("xray", TunnelBackend::Xray);
        xray_tun.xray_mode = XrayMode::Tun;
        let other = auto_profile("other", TunnelBackend::WireGuard);
        let profiles = [disabled, wg, static_routes, openvpn, xray_tun, other];
        let owners = HashSet::from([
            "wg:wg".to_string(),
            "routes".to_string(),
            "xray:xray".to_string(),
        ]);
        let attempted = Arc::new(Mutex::new(Vec::new()));
        let seen = attempted.clone();

        let failures = connect_saved_profiles(&profiles, &owners, move |id| {
            seen.lock().unwrap().push(id);
            async { Ok(()) }
        })
        .await;

        assert!(failures.is_empty());
        assert_eq!(*attempted.lock().unwrap(), ["ovpn", "other"]);
    }

    #[tokio::test]
    async fn failure_does_not_block_later_profiles_or_retry() {
        let profiles: Vec<_> = ["first", "second", "third"]
            .into_iter()
            .map(|id| auto_profile(id, TunnelBackend::WireGuard))
            .collect();
        let attempted = Arc::new(Mutex::new(Vec::new()));
        let seen = attempted.clone();

        let failures = connect_saved_profiles(&profiles, &HashSet::new(), move |id| {
            seen.lock().unwrap().push(id.clone());
            async move {
                if id == "first" {
                    Err("daemon conflict".to_string())
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert_eq!(failures, ["first"]);
        assert_eq!(*attempted.lock().unwrap(), ["first", "second", "third"]);
    }

    #[test]
    fn startup_result_is_available_after_the_ui_mounts() {
        let status = AutoConnectStatus::default();
        assert_eq!(status.current().unwrap(), None);
        status.record(AutoConnectResult {
            failed_count: 2,
            startup_failed: false,
        });
        assert_eq!(
            status.current().unwrap(),
            Some(AutoConnectResult {
                failed_count: 2,
                startup_failed: false,
            })
        );
    }
}
