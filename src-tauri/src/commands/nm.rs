//! NetworkManager-backed external connections. NM owns profile lifecycle
//! and secrets; the app lists VPN/WireGuard profiles and toggles them so
//! routing orchestration can target their interfaces. Linux only.

use net_manager_core::daemon_protocol::NmListResult;
#[cfg(target_os = "linux")]
use tauri::Emitter;

#[tauri::command]
pub(crate) async fn nm_list_connections() -> Result<NmListResult, String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            net_manager_engine::linux_services::nm_list(
                &net_manager_engine::linux_engine::LinuxEngine::new("network-orchestrator"),
            )
        })
        .await
        .map_err(|_| "NetworkManager task failed".to_string())?
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NmListResult {
            connections: Vec::new(),
            available: false,
        })
    }
}

#[tauri::command]
pub(crate) async fn nm_set_active(
    uuid: String,
    active: bool,
    app: tauri::AppHandle,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(move || {
            net_manager_engine::linux_services::nm_set_active(
                &net_manager_engine::linux_engine::LinuxEngine::new("network-orchestrator"),
                &uuid,
                active,
            )
        })
        .await
        .map_err(|_| "NetworkManager task failed".to_string())??;
        let _ = app.emit("route-changed", ());
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (uuid, active, app);
        Err("NetworkManager connections are only supported on Linux".into())
    }
}
