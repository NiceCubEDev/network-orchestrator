use crate::state::AppState;
#[cfg(any(not(target_os = "linux"), test))]
use net_manager_core::models::*;
use std::sync::atomic::Ordering;
use tauri::{Emitter, Manager};

#[cfg(any(not(target_os = "linux"), test))]
pub(crate) async fn cleanup_all(state: &AppState) -> Result<(), String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let mut runtime = state.runtime.lock().await;
    let mut errors: Vec<String> = Vec::new();
    if let Err(err) = runtime.proxy.restore_any() {
        errors.push(format!("system proxy: {err}"));
    }
    match runtime.routes.applied_profile_ids().await {
        Ok(ids) => {
            for id in ids {
                if let Err(err) = runtime.routes.remove_profile(&id).await {
                    errors.push(format!("routes for '{id}': {err}"));
                }
            }
        }
        Err(err) => errors.push(format!("route ownership: {err}")),
    }
    for profile in &profiles {
        if runtime.tunnels.status(profile).state == TunnelState::Running {
            if let Err(err) = runtime.tunnels.disconnect(profile) {
                errors.push(format!("tunnel '{}': {err}", profile.id));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn disconnect_all(
    state: &AppState,
    client: &crate::daemon_client::DaemonClient,
) -> Result<(), String> {
    use net_manager_core::daemon_protocol::{method, CleanupResult};

    let mut errors = Vec::new();
    match client
        .request::<_, CleanupResult>(method::RECOVERY_CLEANUP, serde_json::Value::Null)
        .await
    {
        Ok(result) if !result.failed.is_empty() => errors.push(format!(
            "daemon could not disconnect {} owner(s)",
            result.failed.len()
        )),
        Ok(_) => {}
        Err(err) => errors.push(format!(
            "daemon cleanup: {}",
            crate::daemon_client::user_message(&err)
        )),
    }
    let root = state.data_dir().to_path_buf();
    if let Err(err) = client
        .engine_request(move |engine| engine.with_data_root(root).disconnect_local_proxies())
        .await
    {
        errors.push(err);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Linux backends are shared with CLI and outlive the window. Closing the GUI
/// must not disconnect another client's session.
async fn exit_cleanup(state: &AppState) -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        cleanup_all(state).await
    }
    #[cfg(target_os = "linux")]
    {
        let _ = state;
        Ok(())
    }
}

#[cfg(any(not(target_os = "linux"), test))]
fn should_cleanup_on_ui_exit() -> bool {
    !cfg!(target_os = "linux")
}

#[cfg(target_os = "linux")]
fn should_hide_on_close(tray_created: bool) -> bool {
    cfg!(target_os = "linux") && tray_created
}

pub(crate) fn handle_window_event(window: &tauri::Window, event: &tauri::WindowEvent) {
    let tauri::WindowEvent::CloseRequested { api, .. } = event else {
        return;
    };
    if window.label() != "main" {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        if should_hide_on_close(
            window
                .app_handle()
                .tray_by_id(crate::tray::TRAY_ID)
                .is_some(),
        ) && window.hide().is_ok()
        {
            api.prevent_close();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if !should_cleanup_on_ui_exit() {
            return;
        }
        let Some(state) = window.try_state::<AppState>() else {
            return;
        };
        if state.cleanup_complete.load(Ordering::SeqCst) {
            return;
        }
        api.prevent_close();
        if state.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }
        let window = window.clone();
        tauri::async_runtime::spawn(async move {
            let state = window.state::<AppState>();
            match cleanup_all(&state).await {
                Ok(()) => {
                    state.cleanup_complete.store(true, Ordering::SeqCst);
                    let _ = window.close();
                }
                Err(err) => {
                    state.shutting_down.store(false, Ordering::SeqCst);
                    let _ = window.emit("shutdown-failed", err);
                }
            }
        });
    }
}

pub(crate) fn handle_run_event(app: &tauri::AppHandle, event: tauri::RunEvent) {
    let tauri::RunEvent::ExitRequested { api, .. } = event else {
        return;
    };
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    if state.cleanup_complete.load(Ordering::SeqCst) {
        return;
    }
    api.prevent_exit();
    if state.shutting_down.swap(true, Ordering::SeqCst) {
        return;
    }
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = handle.state::<AppState>();
        match exit_cleanup(&state).await {
            Ok(()) => {
                state.cleanup_complete.store(true, Ordering::SeqCst);
                handle.exit(0);
            }
            Err(err) => {
                state.shutting_down.store(false, Ordering::SeqCst);
                let _ = handle.emit("shutdown-failed", err);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_ui_exit_does_not_cleanup_daemon_owners() {
        assert!(!should_cleanup_on_ui_exit());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_close_hides_only_when_tray_was_created() {
        assert!(!should_hide_on_close(false));
        assert!(should_hide_on_close(true));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_ui_exit_keeps_cleanup() {
        assert!(should_cleanup_on_ui_exit());
    }

    #[tokio::test]
    #[cfg_attr(not(target_os = "linux"), allow(irrefutable_let_patterns))]
    async fn cleanup_all_removes_owned_routes_and_persists_empty_registry() {
        let dir = unique_dir("cleanup-all");
        let state = app_state(&dir);
        {
            let mut runtime = state.runtime.lock().await;
            if let crate::route_runtime::RouteRuntime::Local { policies, .. } = &mut runtime.routes
            {
                policies
                    .restore(vec![
                        AppliedProfileRoutes {
                            profile_id: "z".into(),
                            routes: vec![],
                        },
                        AppliedProfileRoutes {
                            profile_id: "a".into(),
                            routes: vec![AppliedRoute {
                                destination: "10.3.0.0/24".parse().unwrap(),
                                interface_index: 4,
                                metric: 10,
                                gateway: None,
                                table: None,
                            }],
                        },
                    ])
                    .unwrap();
            }
        }
        cleanup_all(&state).await.unwrap();
        let mut runtime = state.runtime.lock().await;
        assert!(runtime
            .routes
            .applied_profile_ids()
            .await
            .unwrap()
            .is_empty());
        drop(runtime);
        let loaded =
            net_manager_core::route_state::AppliedRouteStore::new(dir.join("applied-routes.json"))
                .load()
                .unwrap();
        assert!(loaded.profiles.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cleanup_all_reports_daemon_failure_after_attempting_other_cleanup() {
        let dir = unique_dir("cleanup-daemon-unavailable");
        let state = app_state(&dir);
        {
            let mut runtime = state.runtime.lock().await;
            runtime.routes = crate::route_runtime::RouteRuntime::Daemon(
                crate::daemon_client::DaemonClient::new(dir.join("missing.sock")),
            );
        }
        let err = cleanup_all(&state).await.unwrap_err();
        assert!(err.contains("route ownership:"), "{err}");
    }
}
