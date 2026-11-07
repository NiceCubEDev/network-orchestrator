use crate::state::AppState;
use net_manager_engine::linux_runtime::{self, AutoConnectResult};
use tauri::{Emitter, Manager, State};

#[tauri::command]
pub(crate) fn get_auto_connect_result(
    state: State<'_, AppState>,
) -> Result<Option<AutoConnectResult>, String> {
    linux_runtime::auto_connect_result(state.data_dir())
}

pub(crate) async fn start(app: tauri::AppHandle) {
    let state = app.state::<AppState>();
    let root = state.data_dir().to_path_buf();
    let credentials = state.openvpn_credentials.clone();
    let result = crate::daemon_client::DaemonClient::system()
        .engine_request(move |engine| {
            let engine = engine.with_data_root(root.clone());
            linux_runtime::run_auto_connect(
                &engine,
                &root,
                &net_manager_core::config_vault::ConfigVault::new(root.join("configs")),
                &net_manager_core::profiles::ProfileStore::new(root.join("profiles.json")),
                credentials.as_ref(),
            )
        })
        .await;
    match result {
        Ok(result) => {
            let _ = app.emit("route-changed", ());
            let _ = app.emit("auto-connect-result", result);
        }
        Err(_) => {
            let _ = app.emit(
                "auto-connect-result",
                AutoConnectResult {
                    failed_count: 0,
                    startup_failed: true,
                },
            );
        }
    }
}
