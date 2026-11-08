#[cfg(not(target_os = "linux"))]
use net_manager_core::explorer;
use net_manager_core::models::*;
use std::net::IpAddr;

#[tauri::command]
pub(crate) async fn get_interfaces() -> Result<Vec<NetworkInterface>, String> {
    #[cfg(target_os = "linux")]
    return net_manager_engine::linux_network::interfaces();
    #[cfg(not(target_os = "linux"))]
    explorer::list_interfaces().map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn get_routes() -> Result<Vec<RouteEntry>, String> {
    #[cfg(target_os = "linux")]
    return net_manager_engine::linux_network::routes().await;
    #[cfg(not(target_os = "linux"))]
    explorer::list_routes().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn lookup_destination(dest: String) -> Result<RouteLookupResult, String> {
    let ip: IpAddr = dest
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    #[cfg(target_os = "linux")]
    return net_manager_engine::linux_network::lookup(ip).await;
    #[cfg(not(target_os = "linux"))]
    explorer::lookup_route(ip).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn set_interface_state(name: String, up: bool) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::set_interface_state(
            &net_manager_engine::linux_engine::LinuxEngine::new("netmanager-gui"),
            &name,
            up,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        explorer::set_interface_state(&name, up).map_err(|e| e.to_string())
    }
}

/// Stop a tunnel interface the app does not own (wg-quick, another VPN app).
/// The daemon stops a live wg-quick unit, deletes WireGuard devices and
/// admin-downs foreign TUN devices. Linux only.
#[tauri::command]
pub(crate) async fn stop_external_tunnel(name: String) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::stop_external_tunnel(
            &net_manager_engine::linux_engine::LinuxEngine::new("netmanager-gui"),
            &name,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err("external tunnel control is only supported on Linux".into())
    }
}
