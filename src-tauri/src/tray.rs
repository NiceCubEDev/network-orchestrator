pub(crate) const TRAY_ID: &str = "network-orchestrator";

use crate::daemon_client::DaemonClient;
use crate::lifecycle;
use crate::state::AppState;
use net_manager_core::daemon_protocol::{method, OwnedListResult, OwnedState};
use net_manager_core::models::{Profile, TunnelBackend, TunnelState, XrayMode};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileAction {
    Connect,
    Disconnect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrayEntry {
    profile_id: String,
    label: String,
    action: Option<ProfileAction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TraySnapshot {
    summary: String,
    entries: Vec<TrayEntry>,
}

fn owner_key(profile: &Profile) -> Option<String> {
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

fn menu_snapshot(
    profiles: &[Profile],
    owners: Option<&HashMap<String, OwnedState>>,
    statuses: &HashMap<String, TunnelState>,
) -> TraySnapshot {
    let mut active = 0;
    let entries: Vec<TrayEntry> = profiles
        .iter()
        .map(|profile| {
            let owner = owner_key(profile);
            let owned = owner
                .as_ref()
                .and_then(|owner| owners.and_then(|owners| owners.get(owner)));
            let status = statuses.get(&profile.id).copied();
            let (state, action) = if owner.is_none() {
                match status {
                    Some(TunnelState::Running) => ("Active", Some(ProfileAction::Disconnect)),
                    Some(TunnelState::Stopped) => ("Disconnected", Some(ProfileAction::Connect)),
                    Some(TunnelState::Failed) => ("Failed", None),
                    None => ("Status unavailable", None),
                }
            } else if owners.is_none() {
                ("Status unavailable", None)
            } else {
                match owned {
                    Some(OwnedState::Applying) => ("Starting", None),
                    Some(OwnedState::Stale) => ("Needs recovery", None),
                    Some(OwnedState::Applied) if profile.backend == TunnelBackend::None => {
                        ("Active", Some(ProfileAction::Disconnect))
                    }
                    _ => match status {
                        Some(TunnelState::Running) => ("Active", Some(ProfileAction::Disconnect)),
                        Some(TunnelState::Failed) if owned == Some(&OwnedState::Applied) => {
                            ("Failed", Some(ProfileAction::Disconnect))
                        }
                        Some(TunnelState::Stopped) if owned == Some(&OwnedState::Applied) => {
                            ("Needs recovery", Some(ProfileAction::Disconnect))
                        }
                        Some(TunnelState::Failed) => ("Failed", None),
                        None if owned == Some(&OwnedState::Applied) => ("Status unavailable", None),
                        Some(TunnelState::Stopped) | None => {
                            ("Disconnected", Some(ProfileAction::Connect))
                        }
                    },
                }
            };
            if state == "Active" {
                active += 1;
            }
            TrayEntry {
                profile_id: profile.id.clone(),
                label: format!("{} — {state}", profile.name),
                action,
            }
        })
        .collect();
    let summary = if owners.is_none() {
        "Network daemon unavailable".to_string()
    } else {
        format!("{active} active")
    };
    TraySnapshot { summary, entries }
}

struct TrayState {
    summary: MenuItem<tauri::Wry>,
    profiles: Submenu<tauri::Wry>,
    last: Mutex<Option<TraySnapshot>>,
}

async fn read_snapshot(app: &tauri::AppHandle) -> TraySnapshot {
    let state = app.state::<AppState>();
    let profiles = match state.profiles.load() {
        Ok(document) => document.profiles,
        Err(_) => {
            return TraySnapshot {
                summary: "Profiles unavailable".into(),
                entries: Vec::new(),
            }
        }
    };
    let client = DaemonClient::system();
    let owned: Result<OwnedListResult, _> = client
        .request(method::OWNED_LIST, serde_json::Value::Null)
        .await;
    let owners = owned.ok().map(|list| {
        list.owners
            .into_iter()
            .map(|entry| (entry.owner, entry.state))
            .collect::<HashMap<_, _>>()
    });
    let statuses = crate::commands::tunnels::get_tunnel_statuses(app.state::<AppState>())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|status| (status.profile_id, status.state))
        .collect();
    menu_snapshot(&profiles, owners.as_ref(), &statuses)
}

fn update_menu(app: &tauri::AppHandle, snapshot: TraySnapshot) -> tauri::Result<()> {
    let tray = app.state::<TrayState>();
    let mut last = tray
        .last
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if last.as_ref() == Some(&snapshot) {
        return Ok(());
    }
    tray.summary.set_text(&snapshot.summary)?;
    while tray.profiles.remove_at(0)?.is_some() {}
    for entry in &snapshot.entries {
        let item = MenuItem::with_id(
            app,
            format!("profile:{}", entry.profile_id),
            &entry.label,
            entry.action.is_some(),
            None::<&str>,
        )?;
        tray.profiles.append(&item)?;
    }
    *last = Some(snapshot);
    Ok(())
}

async fn refresh_menu(app: &tauri::AppHandle) {
    let snapshot = read_snapshot(app).await;
    let _ = update_menu(app, snapshot);
}

pub(crate) async fn refresh_loop(app: tauri::AppHandle) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    loop {
        interval.tick().await;
        refresh_menu(&app).await;
    }
}

async fn toggle_profile(app: tauri::AppHandle, id: String) {
    let snapshot = read_snapshot(&app).await;
    let action = snapshot
        .entries
        .iter()
        .find(|entry| entry.profile_id == id)
        .and_then(|entry| entry.action);
    let result = match action {
        Some(ProfileAction::Connect) => {
            let state = app.state::<AppState>();
            crate::commands::tunnels::connect_profile(id, state, app.clone())
                .await
                .map(|_| ())
        }
        Some(ProfileAction::Disconnect) => {
            let state = app.state::<AppState>();
            crate::commands::tunnels::disconnect_profile(id, state, app.clone())
                .await
                .map(|_| ())
        }
        None => Err("Profile status is unavailable. Open the app for Diagnostics.".into()),
    };
    refresh_menu(&app).await;
    if result.is_err() {
        app.dialog()
            .message("Could not change this profile. Open the app for Diagnostics and retry.")
            .title("Connection failed")
            .show(|_| {});
    }
}

pub(crate) fn install(app: &mut tauri::App) -> tauri::Result<bool> {
    let Some(icon) = app.default_window_icon() else {
        return Ok(false);
    };
    let open = MenuItem::with_id(app, "open", "Open", true, None::<&str>)?;
    let summary = MenuItem::with_id(app, "status", "Loading status", false, None::<&str>)?;
    let profiles = Submenu::new(app, "Profiles", true)?;
    let disconnect =
        MenuItem::with_id(app, "disconnect-all", "Disconnect all", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit UI", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &summary, &profiles, &disconnect, &quit])?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon.clone())
        .menu(&menu)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "disconnect-all" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<AppState>();
                    let result = lifecycle::disconnect_all(&state, &DaemonClient::system()).await;
                    let _ = app.emit("route-changed", ());
                    if let Err(err) = result {
                        app.dialog()
                            .message(err)
                            .title("Disconnect all failed")
                            .show(|_| {});
                    }
                    refresh_menu(&app).await;
                });
            }
            "quit" => app.exit(0),
            id if id.starts_with("profile:") => {
                let id = id.trim_start_matches("profile:").to_string();
                let app = app.clone();
                tauri::async_runtime::spawn(toggle_profile(app, id));
            }
            _ => {}
        })
        .build(app)?;
    app.manage(TrayState {
        summary,
        profiles,
        last: Mutex::new(None),
    });
    Ok(true)
}

#[tauri::command]
pub(crate) fn get_login_autostart(_app: tauri::AppHandle) -> Result<bool, String> {
    net_manager_engine::linux_system::login_autostart()
}

#[tauri::command]
pub(crate) fn set_login_autostart(_app: tauri::AppHandle, enabled: bool) -> Result<bool, String> {
    net_manager_engine::linux_system::set_login_autostart(enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::profile;
    use net_manager_core::daemon_protocol::OwnedState;
    use net_manager_core::models::{TunnelBackend, TunnelState, XrayMode};
    use std::collections::HashMap;

    fn named(id: &str, backend: TunnelBackend) -> net_manager_core::models::Profile {
        let mut profile = profile(id);
        profile.id = id.into();
        profile.name = id.into();
        profile.backend = backend;
        profile
    }

    #[test]
    fn reattached_daemon_owners_appear_active_in_saved_order() {
        let wg = named("home", TunnelBackend::WireGuard);
        let openvpn = named("office", TunnelBackend::OpenVpn);
        let static_routes = named("routes", TunnelBackend::None);
        let mut xray = named("proxy", TunnelBackend::Xray);
        xray.xray_mode = XrayMode::Socks;
        let owners = HashMap::from([
            ("wg:home".into(), OwnedState::Applied),
            ("routes".into(), OwnedState::Applied),
        ]);
        let statuses = HashMap::from([
            ("home".into(), TunnelState::Running),
            ("office".into(), TunnelState::Stopped),
            ("routes".into(), TunnelState::Stopped),
            ("proxy".into(), TunnelState::Running),
        ]);

        let snapshot = menu_snapshot(
            &[wg, openvpn, static_routes, xray],
            Some(&owners),
            &statuses,
        );

        assert_eq!(snapshot.summary, "3 active");
        assert_eq!(
            snapshot
                .entries
                .iter()
                .map(|e| e.profile_id.as_str())
                .collect::<Vec<_>>(),
            ["home", "office", "routes", "proxy"]
        );
        assert_eq!(snapshot.entries[0].action, Some(ProfileAction::Disconnect));
        assert_eq!(snapshot.entries[1].action, Some(ProfileAction::Connect));
        assert_eq!(snapshot.entries[2].action, Some(ProfileAction::Disconnect));
        assert_eq!(snapshot.entries[3].action, Some(ProfileAction::Disconnect));
    }

    #[test]
    fn daemon_unavailable_does_not_offer_tunnel_toggle() {
        let wg = named("home", TunnelBackend::WireGuard);
        let xray = named("proxy", TunnelBackend::Xray);

        let statuses = HashMap::from([
            ("home".into(), TunnelState::Failed),
            ("proxy".into(), TunnelState::Stopped),
        ]);
        let snapshot = menu_snapshot(&[wg, xray], None, &statuses);

        assert_eq!(snapshot.summary, "Network daemon unavailable");
        assert_eq!(snapshot.entries[0].action, None);
        assert_eq!(snapshot.entries[1].action, Some(ProfileAction::Connect));
    }

    #[test]
    fn xray_tun_uses_reattached_status() {
        let mut xray = named("tun", TunnelBackend::Xray);
        xray.xray_mode = XrayMode::Tun;
        let statuses = HashMap::from([("tun".into(), TunnelState::Running)]);

        let snapshot = menu_snapshot(&[xray], Some(&HashMap::new()), &statuses);

        assert_eq!(snapshot.entries[0].action, Some(ProfileAction::Disconnect));
    }

    #[test]
    fn owned_tunnel_with_missing_status_does_not_offer_duplicate_connect() {
        let wg = named("home", TunnelBackend::WireGuard);
        let owners = HashMap::from([("wg:home".into(), OwnedState::Applied)]);

        let snapshot = menu_snapshot(&[wg], Some(&owners), &HashMap::new());

        assert_eq!(snapshot.entries[0].action, None);
    }
}
