use crate::commands::profiles::loopback_port_available;
use crate::state::{find_profile, AppState, RuntimeState};
use net_manager_core::analysis;
use net_manager_core::connect_plan::{
    active_profile_conflicts, derive_installable_routes, has_target_interface,
    resolve_install_interface, wait_for_openvpn_pushed_routes, wait_for_tcp_listener,
};
use net_manager_core::explorer;
use net_manager_core::models::*;
use std::io::ErrorKind;
use std::time::Duration;
#[cfg(not(target_os = "linux"))]
use std::time::Instant;
use tauri::{Emitter, State};

#[cfg(target_os = "linux")]
use crate::openvpn_credentials::OpenVpnCredentialStore;
#[cfg(target_os = "linux")]
use net_manager_core::daemon_protocol::{
    method, OpenVpnConnectResult, OpenVpnCredentials, OpenVpnDisconnectResult, OpenVpnProbeResult,
    OpenVpnProfileParams, OpenVpnStatusResult, WireGuardConnectResult, WireGuardDisconnectResult,
    WireGuardProfileParams, WireGuardStatusResult, XrayConnectResult, XrayDisconnectResult,
    XrayProfileParams, XrayStatusResult,
};
#[cfg(target_os = "linux")]
pub(crate) use net_manager_engine::linux::*;

#[cfg(test)]
fn select_connect_ports(
    profiles: &[Profile],
    profile: &Profile,
    available: impl Fn(u16) -> bool,
) -> Result<Option<(u16, Option<u16>)>, String> {
    net_manager_core::profile_import::select_connect_ports(profiles, profile, available)
        .map_err(|err| err.to_string())
}

fn prepare_xray_listener_ports(
    state: &AppState,
    profile: &mut Profile,
    profiles: &mut [Profile],
) -> Result<Option<String>, String> {
    net_manager_core::profile_import::prepare_connect_ports(
        &state.config_vault,
        &state.profiles,
        profile,
        profiles,
        loopback_port_available,
    )
    .map_err(|err| err.to_string())
}

#[cfg(target_os = "linux")]
async fn linux_xray_connect(
    client: &crate::daemon_client::DaemonClient,
    vault: &net_manager_core::config_vault::ConfigVault,
    state: &AppState,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    let mut params = prepare_linux_xray_tun_params(vault, profile)?;
    if let Some(dir) = crate::geo_assets::ensure_geo_assets(state, profile).await? {
        params.geo_assets = Some(crate::geo_assets::protocol_geo_assets(&dir)?);
        check_xray_frame_size(&params)
            .map_err(|_| "geo assets are too large for daemon protocol".to_string())?;
    }
    let result: XrayConnectResult = client
        .request(method::XRAY_CONNECT, params)
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    Ok(linux_xray_tunnel_status(result.status, profile))
}

/// Re-send the profile's current generated config to the running Xray tunnel:
/// the daemon swaps the staged config and restarts the child in place,
/// keeping routes, DNS and the ownership journal. Network-level changes
/// (routes, DNS, interface name, full capture) are rejected by the daemon —
/// the caller is expected to reconnect in that case.
#[cfg(target_os = "linux")]
async fn linux_xray_reload(
    client: &crate::daemon_client::DaemonClient,
    vault: &net_manager_core::config_vault::ConfigVault,
    state: &AppState,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    let mut params = prepare_linux_xray_tun_params(vault, profile)?;
    if let Some(dir) = crate::geo_assets::ensure_geo_assets(state, profile).await? {
        params.geo_assets = Some(crate::geo_assets::protocol_geo_assets(&dir)?);
        check_xray_frame_size(&params)
            .map_err(|_| "geo assets are too large for daemon protocol".to_string())?;
    }
    let result: XrayConnectResult = client
        .request(method::XRAY_RELOAD, params)
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    Ok(linux_xray_tunnel_status(result.status, profile))
}

#[cfg(target_os = "linux")]
pub(crate) async fn linux_xray_status_result(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<XrayStatusResult, String> {
    client
        .request(
            method::XRAY_STATUS,
            XrayProfileParams {
                profile_id: profile.id.clone(),
            },
        )
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))
}

#[cfg(target_os = "linux")]
pub(crate) async fn linux_xray_status(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    Ok(linux_xray_tunnel_status(
        linux_xray_status_result(client, profile).await?,
        profile,
    ))
}

#[cfg(target_os = "linux")]
async fn linux_xray_disconnect(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    let result: XrayDisconnectResult = client
        .request(
            method::XRAY_DISCONNECT,
            XrayProfileParams {
                profile_id: profile.id.clone(),
            },
        )
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    if !result.stopped {
        return Err("Xray daemon did not confirm disconnect".into());
    }
    Ok(TunnelStatus {
        profile_id: profile.id.clone(),
        state: TunnelState::Stopped,
        message: None,
        interface_name: None,
        failover: None,
        watchdog: None,
    })
}

#[cfg(target_os = "linux")]
async fn linux_openvpn_connect(
    client: &crate::daemon_client::DaemonClient,
    vault: &net_manager_core::config_vault::ConfigVault,
    credential_store: &OpenVpnCredentialStore,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    linux_openvpn_connect_with_credentials(client, vault, credential_store, profile, None, false)
        .await
}

#[cfg(target_os = "linux")]
async fn linux_openvpn_connect_with_credentials(
    client: &crate::daemon_client::DaemonClient,
    vault: &net_manager_core::config_vault::ConfigVault,
    credential_store: &OpenVpnCredentialStore,
    profile: &Profile,
    supplied_credentials: Option<OpenVpnCredentials>,
    remember: bool,
) -> Result<TunnelStatus, String> {
    let explicit = supplied_credentials.is_some();
    let (request, load_notice) = prepare_linux_openvpn_request(
        vault,
        credential_store,
        profile,
        supplied_credentials,
        profile.effective_routes(),
        method::OPENVPN_CONNECT,
    )?;
    let credentials = request.credentials.clone();
    let result: OpenVpnConnectResult = client
        .request(method::OPENVPN_CONNECT, request)
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    let notice = if !explicit {
        load_notice
    } else if remember {
        credential_store.remember(&profile.id, credentials.as_ref().unwrap())
    } else {
        let legacy = openvpn_credentials_path(vault, profile).ok();
        credential_store
            .forget(&profile.id, legacy.as_deref())
            .err()
            .map(|_| "OpenVPN started, but old remembered credentials could not be removed")
    };
    Ok(finish_openvpn_connect(result.status, notice))
}

#[cfg(target_os = "linux")]
async fn linux_openvpn_probe(
    client: &crate::daemon_client::DaemonClient,
    vault: &net_manager_core::config_vault::ConfigVault,
    credential_store: &OpenVpnCredentialStore,
    profile: &Profile,
) -> Result<Vec<AnalyzedRoute>, String> {
    let (request, _) = prepare_linux_openvpn_request(
        vault,
        credential_store,
        profile,
        None,
        Vec::new(),
        method::OPENVPN_PROBE,
    )?;
    let result: OpenVpnProbeResult = client
        .request(method::OPENVPN_PROBE, request)
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    Ok(result.routes)
}

#[cfg(target_os = "linux")]
pub(crate) async fn linux_openvpn_status_result(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<OpenVpnStatusResult, String> {
    client
        .request(
            method::OPENVPN_STATUS,
            OpenVpnProfileParams {
                profile_id: profile.id.clone(),
            },
        )
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))
}

#[cfg(target_os = "linux")]
pub(crate) async fn linux_openvpn_status(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    Ok(linux_openvpn_tunnel_status(
        linux_openvpn_status_result(client, profile).await?,
    ))
}

#[cfg(target_os = "linux")]
async fn linux_openvpn_disconnect(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    let result: OpenVpnDisconnectResult = client
        .request(
            method::OPENVPN_DISCONNECT,
            OpenVpnProfileParams {
                profile_id: profile.id.clone(),
            },
        )
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    if !result.stopped {
        return Err("OpenVPN daemon did not confirm disconnect".into());
    }
    Ok(TunnelStatus {
        profile_id: profile.id.clone(),
        state: TunnelState::Stopped,
        message: None,
        interface_name: None,
        watchdog: None,
        failover: None,
    })
}

#[cfg(target_os = "linux")]
async fn linux_wireguard_connect(
    client: &crate::daemon_client::DaemonClient,
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    let params = wireguard_connect_params(vault, profile)?;
    let result: WireGuardConnectResult = client
        .request(method::WIREGUARD_CONNECT, params)
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    Ok(linux_wireguard_tunnel_status(result.status))
}

#[cfg(target_os = "linux")]
pub(crate) async fn linux_wireguard_status_result(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<WireGuardStatusResult, String> {
    let status: WireGuardStatusResult = client
        .request(
            method::WIREGUARD_STATUS,
            WireGuardProfileParams {
                profile_id: profile.id.clone(),
            },
        )
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    Ok(status)
}

#[cfg(target_os = "linux")]
pub(crate) async fn linux_wireguard_status(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    Ok(linux_wireguard_tunnel_status(
        linux_wireguard_status_result(client, profile).await?,
    ))
}

#[cfg(target_os = "linux")]
async fn linux_wireguard_disconnect(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    let result: WireGuardDisconnectResult = client
        .request(
            method::WIREGUARD_DISCONNECT,
            WireGuardProfileParams {
                profile_id: profile.id.clone(),
            },
        )
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))?;
    if !result.stopped {
        return Err("WireGuard daemon did not confirm disconnect".into());
    }
    Ok(TunnelStatus {
        profile_id: profile.id.clone(),
        state: TunnelState::Stopped,
        message: None,
        watchdog: None,
        interface_name: None,
        failover: None,
    })
}

async fn cleanup_stale_routes_before_connect(
    runtime: &mut RuntimeState,
    profile: &Profile,
) -> Result<(), String> {
    if runtime.tunnels.status(profile).state == TunnelState::Running {
        return Err(
            std::io::Error::new(ErrorKind::AlreadyExists, "profile is already running").to_string(),
        );
    }
    if runtime.routes.has_applied(&profile.id).await? {
        runtime
            .routes
            .remove_profile(&profile.id)
            .await
            .map_err(|err| format!("failed to clean previously applied routes: {err}"))?;
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn connect_profile(
    id: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<TunnelStatus, String> {
    let result = connect_profile_inner(id.clone(), state.inner(), &app).await;
    let label = super::logs::profile_label(&state, &id);
    super::logs::record_tunnel_result(&state, "connect", &label, &result);
    result
}

async fn connect_profile_inner(
    id: String,
    state: &AppState,
    app: &tauri::AppHandle,
) -> Result<TunnelStatus, String> {
    let mut profile = find_profile(&state.profiles, &id)?;
    profile.check_role()?;
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::WireGuard {
        let status = linux_wireguard_connect(
            &crate::daemon_client::DaemonClient::system(),
            &state.config_vault,
            &profile,
        )
        .await?;
        let _ = app.emit("route-changed", ());
        return Ok(status);
    }
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::OpenVpn {
        let status = linux_openvpn_connect(
            &crate::daemon_client::DaemonClient::system(),
            &state.config_vault,
            &state.openvpn_credentials,
            &profile,
        )
        .await?;
        let _ = app.emit("route-changed", ());
        return Ok(status);
    }
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun {
        let mut profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
        let port_notice = prepare_xray_listener_ports(state, &mut profile, &mut profiles)?;
        let mut status = linux_xray_connect(
            &crate::daemon_client::DaemonClient::system(),
            &state.config_vault,
            state,
            &profile,
        )
        .await?;
        if let Some(notice) = port_notice {
            status.message = Some(match status.message.take() {
                Some(existing) => format!("{existing}; {notice}"),
                None => notice,
            });
        }
        let _ = app.emit("route-changed", ());
        return Ok(status);
    }
    if profile.backend != TunnelBackend::None {
        state
            .resolve_backend_executable(profile.backend)
            .map_err(|e| e.to_string())?;
    }
    // Xray TUN mode creates a Wintun interface, which requires elevation.
    if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun {
        let elevated = crate::elevation::is_elevated().map_err(|e| e.to_string())?;
        if !elevated {
            return Err(
                "Xray TUN mode requires administrator privileges. Restart the app elevated.".into(),
            );
        }
        // TUN mode captures traffic at the interface level — system proxy is
        // not needed and must not be applied.
        if profile.use_system_proxy {
            profile.use_system_proxy = false;
        }
    }
    // A profile imported from another platform must still connect where the
    // system proxy is unavailable, just without touching proxy settings.
    if !super::system::system_proxy_supported() {
        profile.use_system_proxy = false;
    }
    let mut profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let mut runtime = state.runtime.lock().await;
    cleanup_stale_routes_before_connect(&mut runtime, &profile).await?;
    let port_notice = if profile.backend == TunnelBackend::Xray {
        prepare_xray_listener_ports(state, &mut profile, &mut profiles)?
    } else {
        None
    };
    let candidate_analysis = analysis::analyze_profile(&profile)
        .map_err(|e| format!("cannot analyze profile config: {e}"))?;
    let conflicts =
        active_profile_conflicts(&mut runtime.tunnels, &id, &candidate_analysis, &profiles)?;
    if !conflicts.is_empty() {
        let joined = conflicts
            .iter()
            .map(|c| c.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "connection blocked by active profile conflict: {joined}"
        ));
    }
    if profile.use_system_proxy {
        if let Some(owner) = runtime.proxy.ownership() {
            return Err(format!(
                "system proxy is already owned by profile '{}'",
                owner.profile_id
            ));
        }
    }
    let mut status = runtime
        .tunnels
        .connect(&profile)
        .map_err(|e| e.to_string())?;
    if let Some(notice) = port_notice {
        status.message = Some(match status.message.take() {
            Some(existing) => format!("{existing}; {notice}"),
            None => notice,
        });
    }

    let mut proxy_applied = false;
    if profile.use_system_proxy {
        let port = profile.xray_socks_port.unwrap_or(0);
        if !wait_for_tcp_listener(port, Duration::from_secs(10), Duration::from_millis(200)).await {
            let mut message =
                format!("timed out waiting for Xray SOCKS listener on 127.0.0.1:{port}");
            if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
            }
            return Err(message);
        }
        if let Err(err) = runtime
            .proxy
            .apply(&profile.id, port, &profile.proxy_bypass)
        {
            let mut message = format!("failed to apply system proxy: {err}");
            if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
            }
            return Err(message);
        }
        proxy_applied = true;
    }

    // The app is the sole route installer. When the user has specified
    // explicit policy routes (`profile.routes`), install those. When they have
    // not, derive routes from the backend's own route information (WireGuard
    // AllowedIPs, OpenVPN pushed routes) and install them through
    // `PolicyManager`. This ensures consistent ownership, rollback, and
    // conflict detection regardless of whether policy routes are set.
    let install_routes = if !profile.routes.is_empty() {
        profile.routes.clone()
    } else {
        let pushed = if profile.backend == TunnelBackend::OpenVpn {
            wait_for_openvpn_pushed_routes(
                &mut runtime.tunnels,
                &profile,
                Duration::from_secs(20),
                Duration::from_millis(250),
            )
            .await
        } else {
            Vec::new()
        };
        derive_installable_routes(&candidate_analysis, &pushed, profile.backend)
    };

    let wants_attach = profile.wait_for_interface || !profile.endpoint_bypasses.is_empty();
    if !install_routes.is_empty() || wants_attach {
        let install_interface = match resolve_install_interface(&profile) {
            Some(name) => name,
            None => {
                if !install_routes.is_empty() {
                    // No interface name available — skip route installation with a
                    // notice. This happens for OpenVPN profiles without an explicit
                    // interface name; the backend is up but routes are not installed.
                    status.message = Some(
                        "tunnel is up but routes were not installed: \
                         set a target interface in the profile to enable app-owned routing"
                            .into(),
                    );
                    let _ = app.emit("route-changed", ());
                    return Ok(status);
                }
                // Bypass-only profile: nothing binds to a link by name.
                String::new()
            }
        };
        let install_profile = Profile {
            interface_name: install_interface,
            routes: install_routes,
            ..profile.clone()
        };
        // Deferred attach profiles arm the daemon and return immediately —
        // reconcile installs the routes when the link appears. Others keep
        // polling briefly for the freshly created tunnel interface.
        let interfaces = if profile.wait_for_interface {
            explorer::list_interfaces().unwrap_or_default()
        } else {
            let mut matched_interfaces: Option<Vec<NetworkInterface>> = None;
            let mut list_error: Option<String> = None;
            for _ in 0..40 {
                match explorer::list_interfaces() {
                    Ok(interfaces) => {
                        if has_target_interface(&install_profile, &interfaces) {
                            matched_interfaces = Some(interfaces);
                            break;
                        }
                    }
                    Err(e) => {
                        list_error = Some(e.to_string());
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            if let Some(err) = list_error {
                let mut message = format!("failed to enumerate interfaces: {err}");
                if proxy_applied {
                    if let Err(cleanup) = runtime.proxy.restore(&id) {
                        message.push_str(&format!("; proxy restore failed: {cleanup}"));
                    }
                }
                if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                    message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
                }
                return Err(message);
            }
            match matched_interfaces {
                Some(interfaces) => interfaces,
                None => {
                    let mut message = format!(
                        "timed out waiting for interface '{}' to come up",
                        install_profile.interface_name
                    );
                    if proxy_applied {
                        if let Err(cleanup) = runtime.proxy.restore(&id) {
                            message.push_str(&format!("; proxy restore failed: {cleanup}"));
                        }
                    }
                    if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                        message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
                    }
                    return Err(message);
                }
            }
        };
        if profile.wait_for_interface
            && !install_profile.routes.is_empty()
            && !has_target_interface(&install_profile, &interfaces)
        {
            status.message = Some(format!(
                "routes are armed and will install when interface '{}' appears",
                install_profile.interface_name
            ));
        }
        if let Err(err) = runtime
            .routes
            .apply_profile(&install_profile, &interfaces)
            .await
        {
            let mut message = err;
            if proxy_applied {
                if let Err(cleanup) = runtime.proxy.restore(&id) {
                    message.push_str(&format!("; proxy restore failed: {cleanup}"));
                }
            }
            if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
            }
            return Err(message);
        }
    }

    let _ = app.emit("route-changed", ());
    Ok(status)
}

#[tauri::command]
pub(crate) async fn connect_openvpn_with_credentials(
    id: String,
    credentials: net_manager_core::daemon_protocol::OpenVpnCredentials,
    remember: bool,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<TunnelStatus, String> {
    let result =
        connect_openvpn_with_credentials_inner(id.clone(), credentials, remember, &state, &app)
            .await;
    let label = super::logs::profile_label(&state, &id);
    super::logs::record_tunnel_result(&state, "connect", &label, &result);
    result
}

async fn connect_openvpn_with_credentials_inner(
    id: String,
    credentials: net_manager_core::daemon_protocol::OpenVpnCredentials,
    remember: bool,
    state: &AppState,
    app: &tauri::AppHandle,
) -> Result<TunnelStatus, String> {
    #[cfg(target_os = "linux")]
    {
        let profile = find_profile(&state.profiles, &id)?;
        if profile.backend != TunnelBackend::OpenVpn {
            return Err("profile is not OpenVPN".into());
        }
        let status = linux_openvpn_connect_with_credentials(
            &crate::daemon_client::DaemonClient::system(),
            &state.config_vault,
            &state.openvpn_credentials,
            &profile,
            Some(credentials),
            remember,
        )
        .await?;
        let _ = app.emit("route-changed", ());
        Ok(status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (id, credentials, remember, state, app);
        Err("OpenVPN credentials are supported through the Linux daemon only".into())
    }
}

#[tauri::command]
pub(crate) async fn disconnect_profile(
    id: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<TunnelStatus, String> {
    let result = disconnect_profile_inner(id.clone(), state.inner(), &app).await;
    let label = super::logs::profile_label(&state, &id);
    super::logs::record_tunnel_result(&state, "disconnect", &label, &result);
    result
}

async fn disconnect_profile_inner(
    id: String,
    state: &AppState,
    app: &tauri::AppHandle,
) -> Result<TunnelStatus, String> {
    let profile = find_profile(&state.profiles, &id)?;
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::WireGuard {
        let status =
            linux_wireguard_disconnect(&crate::daemon_client::DaemonClient::system(), &profile)
                .await?;
        let _ = app.emit("route-changed", ());
        return Ok(status);
    }
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::OpenVpn {
        let status =
            linux_openvpn_disconnect(&crate::daemon_client::DaemonClient::system(), &profile)
                .await?;
        let _ = app.emit("route-changed", ());
        return Ok(status);
    }
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun {
        let status =
            linux_xray_disconnect(&crate::daemon_client::DaemonClient::system(), &profile).await?;
        let _ = app.emit("route-changed", ());
        return Ok(status);
    }
    let mut runtime = state.runtime.lock().await;
    if runtime
        .proxy
        .ownership()
        .map(|owner| owner.profile_id.as_str())
        == Some(id.as_str())
    {
        runtime
            .proxy
            .restore(&id)
            .map_err(|e| format!("failed to restore system proxy: {e}"))?;
    }
    if runtime.routes.has_applied(&id).await? {
        runtime.routes.remove_profile(&id).await?;
    }
    let status = runtime.tunnels.disconnect(&profile);
    match status {
        Ok(status) => {
            let _ = app.emit("route-changed", ());
            Ok(status)
        }
        Err(status_err) => Err(status_err.to_string()),
    }
}

/// Authoritative per-profile status: on Linux the network daemon owns WG,
/// OpenVPN, and Xray-TUN tunnels, so those are queried over the daemon socket;
/// everything else falls back to the in-process tunnel manager. Used by both
/// `get_tunnel_statuses` and `get_route_map` so the UI never disagrees with
/// the daemon about what is running.
pub(crate) async fn collect_tunnel_statuses(
    state: &AppState,
    profiles: &[Profile],
) -> Result<Vec<TunnelStatus>, String> {
    #[cfg(target_os = "linux")]
    {
        let mut statuses = Vec::with_capacity(profiles.len());
        let client = crate::daemon_client::DaemonClient::system();
        for profile in profiles {
            if profile.backend == TunnelBackend::WireGuard {
                statuses.push(
                    linux_wireguard_status(&client, profile)
                        .await
                        .unwrap_or_else(|err| TunnelStatus {
                            profile_id: profile.id.clone(),
                            state: TunnelState::Failed,
                            watchdog: None,
                            message: Some(err),
                            interface_name: None,
                            failover: None,
                        }),
                );
            } else if profile.backend == TunnelBackend::OpenVpn {
                statuses.push(
                    linux_openvpn_status(&client, profile)
                        .await
                        .unwrap_or_else(|err| TunnelStatus {
                            profile_id: profile.id.clone(),
                            watchdog: None,
                            state: TunnelState::Failed,
                            message: Some(err),
                            interface_name: None,
                            failover: None,
                        }),
                );
            } else if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun {
                statuses.push(
                    linux_xray_status(&client, profile)
                        .await
                        .unwrap_or_else(|err| TunnelStatus {
                            watchdog: None,
                            profile_id: profile.id.clone(),
                            state: TunnelState::Failed,
                            message: Some(err),
                            interface_name: None,
                            failover: None,
                        }),
                );
            } else {
                statuses.push(state.runtime.lock().await.tunnels.status(profile));
            }
        }
        Ok(statuses)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut runtime = state.runtime.lock().await;
        Ok(profiles
            .iter()
            .map(|profile| runtime.tunnels.status(profile))
            .collect())
    }
}

#[tauri::command]
pub(crate) async fn get_tunnel_statuses(
    state: State<'_, AppState>,
) -> Result<Vec<TunnelStatus>, String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    collect_tunnel_statuses(state.inner(), &profiles).await
}

/// Predicts the deterministic daemon resources an OpenVPN profile would use —
/// interface name, staging directory, config and management socket paths —
/// and reports which of them already collide. Read-only: nothing is staged,
/// spawned, or authorized on Linux.
#[tauri::command]
pub(crate) async fn openvpn_plan(
    id: String,
    state: State<'_, AppState>,
) -> Result<net_manager_core::daemon_protocol::OpenVpnPlanResult, String> {
    let profile = find_profile(&state.profiles, &id)?;
    if profile.backend != TunnelBackend::OpenVpn {
        return Err("plan is only supported for OpenVPN profiles".into());
    }
    #[cfg(target_os = "linux")]
    {
        let (request, _) = prepare_linux_openvpn_request(
            &state.config_vault,
            &state.openvpn_credentials,
            &profile,
            None,
            profile.effective_routes(),
            method::OPENVPN_PLAN,
        )?;
        crate::daemon_client::DaemonClient::system()
            .request(method::OPENVPN_PLAN, request)
            .await
            .map_err(|err| crate::daemon_client::user_message(&err))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("OpenVPN plan is only available on Linux".into())
    }
}

/// Hot-reload a running Xray TUN tunnel: the daemon swaps the staged config
/// and restarts the child in place, keeping routes, DNS and the ownership
/// journal. Rejected when kernel-level parameters changed — the caller
/// should disconnect/connect instead.
#[tauri::command]
pub(crate) async fn reload_xray_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<TunnelStatus, String> {
    let profile = find_profile(&state.profiles, &id)?;
    if profile.backend != TunnelBackend::Xray || profile.xray_mode != XrayMode::Tun {
        return Err("reload is only supported for Xray TUN profiles".into());
    }
    #[cfg(target_os = "linux")]
    {
        linux_xray_reload(
            &crate::daemon_client::DaemonClient::system(),
            &state.config_vault,
            &state,
            &profile,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Xray reload is only available on Linux".into())
    }
}

/// Read-only view of the system `tailscaled`: backend state, tailnet, our
/// addresses and the routes peers advertise. `available:false` when the
/// daemon is absent — that is a state, not an error.
#[tauri::command]
pub(crate) async fn tailscale_status(
) -> Result<net_manager_core::daemon_protocol::TailscaleStatusResult, String> {
    #[cfg(target_os = "linux")]
    {
        crate::daemon_client::DaemonClient::system()
            .request(method::TAILSCALE_STATUS, serde_json::Value::Null)
            .await
            .map_err(|err| crate::daemon_client::user_message(&err))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Tailscale status is only available on Linux".into())
    }
}

/// `tailscale up`/`down` as seen from the daemon: flips tailscaled's
/// WantRunning pref via LocalAPI and returns the fresh status.
#[tauri::command]
pub(crate) async fn tailscale_set_running(
    running: bool,
) -> Result<net_manager_core::daemon_protocol::TailscaleStatusResult, String> {
    #[cfg(target_os = "linux")]
    {
        crate::daemon_client::DaemonClient::system()
            .request(
                if running {
                    method::TAILSCALE_UP
                } else {
                    method::TAILSCALE_DOWN
                },
                serde_json::Value::Null,
            )
            .await
            .map_err(|err| crate::daemon_client::user_message(&err))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = running;
        Err("Tailscale control is only available on Linux".into())
    }
}

/// Probe server-pushed routes for a disconnected managed OpenVPN profile.
///
/// On Linux the daemon owns a journaled temporary process and returns typed
/// routes without applying any OS routes or DNS. Elsewhere the probe runs
/// `openvpn.exe --config <path> --route-nopull` as a transient
/// child process with stdout/stderr captured to a temp log file. It polls the
/// log until either `PUSH_REPLY` or `Initialization Sequence Completed` appears
/// (up to ~20s), then kills the process and returns the parsed routes.
///
/// Neither path installs OS routes or DNS. OpenVPN may create a temporary TUN
/// link while it connects; the probe tears it down before returning routes to
/// the UI for optional copying into `profile.routes`.
#[tauri::command]
pub(crate) async fn probe_openvpn_routes(
    id: String,
    state: State<'_, AppState>,
) -> Result<Vec<AnalyzedRoute>, String> {
    let profile = find_profile(&state.profiles, &id)?;
    if profile.backend != TunnelBackend::OpenVpn {
        return Err("route probe is only supported for OpenVPN profiles".into());
    }
    #[cfg(target_os = "linux")]
    {
        linux_openvpn_probe(
            &crate::daemon_client::DaemonClient::system(),
            &state.config_vault,
            &state.openvpn_credentials,
            &profile,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        if !profile.config_path.is_file() {
            return Err(format!(
                "OpenVPN config '{}' does not exist",
                profile.config_path.display()
            ));
        }
        let exe = state
            .resolve_backend_executable(TunnelBackend::OpenVpn)
            .map_err(|e| e.to_string())?
            .path;
        let config_path = std::path::absolute(&profile.config_path).map_err(|e| e.to_string())?;

        let log_dir = std::env::temp_dir();
        let safe_id = net_manager_core::config_vault::sanitize_profile_id(&profile.id)
            .map_err(|e| e.to_string())?;
        let log_path = log_dir.join(format!("netmgr-probe-{}-{safe_id}.log", std::process::id()));
        // Clean any stale log from a previous probe.
        let _ = std::fs::remove_file(&log_path);
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&log_path)
            .map_err(|e| format!("failed to create probe log: {e}"))?;
        let stderr = log_file
            .try_clone()
            .map_err(|e| format!("failed to dup probe log handle: {e}"))?;

        let mut command = std::process::Command::new(&exe);
        command
            .arg("--config")
            .arg(&config_path)
            .arg("--route-nopull")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(stderr);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("failed to start openvpn probe: {e}"))?;

        let deadline = Instant::now() + Duration::from_secs(20);
        let mut found_push = false;
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&log_path) {
                if text.contains("PUSH_REPLY") {
                    found_push = true;
                    break;
                }
                if text.contains("Initialization Sequence Completed") {
                    found_push = true;
                    break;
                }
                // Auth failure or fatal error — abort early.
                if text.contains("AUTH_FAILED") || text.contains("FATAL") {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = std::fs::remove_file(&log_path);
                    return Err("openvpn probe failed during handshake (check credentials or server reachability)".into());
                }
            }
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let _ = child.kill();
        let _ = child.wait();

        let routes = if found_push {
            let text = std::fs::read_to_string(&log_path).unwrap_or_default();
            net_manager_core::vpn::parse_openvpn_pushed_reply(&text)
        } else {
            Vec::new()
        };
        let _ = std::fs::remove_file(&log_path);

        if !found_push {
            return Err("openvpn probe timed out waiting for PUSH_REPLY (server may be unreachable or credentials invalid)".into());
        }
        Ok(routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    #[cfg(target_os = "linux")]
    use net_manager_core::daemon_protocol::{OpenVpnConnectionState, OpenVpnWarning};

    #[cfg(target_os = "linux")]
    fn test_credential_store() -> OpenVpnCredentialStore {
        OpenVpnCredentialStore::new(Box::new(
            crate::openvpn_credentials::tests::FakeKeyring::default(),
        ))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_openvpn_sends_managed_config_and_assets_to_daemon() {
        use net_manager_core::daemon_protocol::{method, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = unique_dir("ovpn-daemon-bridge");
        let source = dir.join("client.ovpn");
        std::fs::write(&source, "client\nremote vpn.example 1194\nca ca.crt\n").unwrap();
        std::fs::write(dir.join("ca.crt"), b"CERT").unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut profile = profile("tun0");
        profile.backend = TunnelBackend::OpenVpn;
        profile.config_path = vault
            .import(&profile.id, TunnelBackend::OpenVpn, &source)
            .unwrap()
            .config_path;
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            for expected in [
                method::OPENVPN_CONNECT,
                method::OPENVPN_STATUS,
                method::OPENVPN_DISCONNECT,
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let hello: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                writer.write_all(&net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(hello.id, json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}))).unwrap()).await.unwrap();
                let request: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 4096)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(request.method, expected);
                assert_eq!(request.params["profileId"], "p1");
                if expected == method::OPENVPN_CONNECT {
                    assert!(request.params["config"]
                        .as_str()
                        .unwrap()
                        .contains("ca \"assets/0-ca.crt\""));
                    assert_eq!(request.params["assets"]["assets/0-ca.crt"], "Q0VSVA==");
                    assert_eq!(request.params["routes"], json!([]));
                }
                let result = match expected {
                    method::OPENVPN_CONNECT => {
                        json!({"status":{"profileId":"p1","state":"connected","interfaceName":"tun0","rxBytes":0,"txBytes":0,"appliedRoutes":[],"warnings":[]}})
                    }
                    method::OPENVPN_STATUS => {
                        json!({"profileId":"p1","state":"reconnecting","interfaceName":"tun0","rxBytes":12,"txBytes":34,"appliedRoutes":[],"warnings":["dnsNotApplied"]})
                    }
                    _ => json!({"stopped":true}),
                };
                writer
                    .write_all(
                        &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                            request.id, result,
                        ))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        });
        let client = crate::daemon_client::DaemonClient::new(socket);
        assert_eq!(
            linux_openvpn_connect(&client, &vault, &test_credential_store(), &profile)
                .await
                .unwrap()
                .state,
            TunnelState::Running
        );
        let status = linux_openvpn_status(&client, &profile).await.unwrap();
        assert_eq!(status.state, TunnelState::Running);
        assert!(status.message.unwrap().contains("DNS was not applied"));
        assert_eq!(
            linux_openvpn_disconnect(&client, &profile)
                .await
                .unwrap()
                .state,
            TunnelState::Stopped
        );
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_openvpn_requests_missing_credentials_before_daemon_contact() {
        let dir = unique_dir("ovpn-credentials");
        let source = dir.join("client.ovpn");
        std::fs::write(&source, "client\nremote vpn.example\nauth-user-pass\n").unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut profile = profile("tun0");
        profile.backend = TunnelBackend::OpenVpn;
        profile.config_path = vault
            .import(&profile.id, TunnelBackend::OpenVpn, &source)
            .unwrap()
            .config_path;
        let client = crate::daemon_client::DaemonClient::new(dir.join("missing.sock"));
        let error = linux_openvpn_connect(&client, &vault, &test_credential_store(), &profile)
            .await
            .unwrap_err();
        assert_eq!(error, "OpenVPN credentials required");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openvpn_credential_requirements_detect_auth_and_encrypted_key() {
        let config = "client\nremote vpn.example\nauth-user-pass\naskpass\nkey assets/key.pem\n";
        let mut assets = std::collections::BTreeMap::new();
        assets.insert(
            "assets/key.pem".into(),
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----".to_vec(),
        );
        let requirements = openvpn_credential_requirements(config, &assets);
        assert!(requirements.user_pass);
        assert!(requirements.key_passphrase);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_files_and_inline_blocks_satisfy_requirements_without_prompts() {
        let assets: std::collections::BTreeMap<String, Vec<u8>> = [
            ("assets/up.txt".into(), b"alice\nsecret\n".to_vec()),
            (
                "assets/key.pem".into(),
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----".to_vec(),
            ),
            ("assets/pass.txt".into(), b"key-pass\n".to_vec()),
        ]
        .into_iter()
        .collect();
        // File-referenced and inline credentials never reach the
        // management password prompt.
        let file = "client\nremote vpn.example\nauth-user-pass \"assets/up.txt\"\nkey assets/key.pem\naskpass assets/pass.txt\n";
        let requirements = openvpn_credential_requirements(file, &assets);
        assert!(!requirements.user_pass);
        assert!(!requirements.key_passphrase);
        // Inline <auth-user-pass> embeds credentials; the `username-only`
        // flag still triggers a prompt.
        let inline =
            "client\nremote vpn.example\n<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n";
        assert!(!openvpn_credential_requirements(inline, &Default::default()).user_pass);
        let username_only = "client\nremote vpn.example\nauth-user-pass username-only\n";
        assert!(openvpn_credential_requirements(username_only, &Default::default()).user_pass);
        // An encrypted key without an askpass file still needs a passphrase.
        let key_only = "client\nremote vpn.example\nkey assets/key.pem\n";
        assert!(openvpn_credential_requirements(key_only, &assets).key_passphrase);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn implicit_connect_migrates_plaintext_credentials_into_keyring() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = unique_dir("ovpn-remember-migrate");
        let source = dir.join("client.ovpn");
        std::fs::write(&source, "client\nremote vpn.example\nauth-user-pass\n").unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut p = profile("ovpn");
        p.backend = TunnelBackend::OpenVpn;
        p.config_path = vault
            .import(&p.id, TunnelBackend::OpenVpn, &source)
            .unwrap()
            .config_path;
        let credentials = OpenVpnCredentials {
            auth_user_pass: Some(net_manager_core::daemon_protocol::OpenVpnUserPass {
                username: "private-user".into(),
                password: "private-password".into(),
            }),
            private_key_passphrase: None,
        };
        let legacy = openvpn_credentials_path(&vault, &p).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&legacy)
            .and_then(|mut file| {
                std::io::Write::write_all(&mut file, &serde_json::to_vec(&credentials).unwrap())
            })
            .unwrap();
        let keyring = crate::openvpn_credentials::tests::FakeKeyring::default();
        let entries = keyring.entries.clone();
        let store = OpenVpnCredentialStore::new(Box::new(keyring));

        let (request, notice) = prepare_linux_openvpn_request(
            &vault,
            &store,
            &p,
            None,
            Vec::new(),
            method::OPENVPN_CONNECT,
        )
        .unwrap();

        assert_eq!(request.credentials, Some(credentials));
        assert_eq!(notice, None);
        assert!(!legacy.exists());
        assert!(entries.lock().unwrap().contains_key(&p.id));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_credentials_path_rejects_symlinked_profile_directory() {
        let dir = unique_dir("ovpn-remember-symlink");
        let source = dir.join("client.ovpn");
        std::fs::write(&source, "client\nremote vpn.example\nauth-user-pass\n").unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut p = profile("ovpn");
        p.backend = TunnelBackend::OpenVpn;
        p.config_path = vault
            .import(&p.id, TunnelBackend::OpenVpn, &source)
            .unwrap()
            .config_path;
        let profile_dir = vault.root().join(&p.id);
        let external = dir.join("external");
        std::fs::rename(&profile_dir, &external).unwrap();
        std::os::unix::fs::symlink(&external, &profile_dir).unwrap();
        assert!(openvpn_credentials_path(&vault, &p).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_openvpn_sends_typed_credentials_and_remembers_only_after_connect() {
        use net_manager_core::daemon_protocol::{OpenVpnUserPass, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;
        let dir = unique_dir("ovpn-typed-credentials");
        let source = dir.join("client.ovpn");
        std::fs::write(
            &source,
            "client\nremote vpn.example\nauth-user-pass\naskpass\nkey key.pem\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("key.pem"),
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        )
        .unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut p = profile("ovpn");
        p.backend = TunnelBackend::OpenVpn;
        p.config_path = vault
            .import(&p.id, TunnelBackend::OpenVpn, &source)
            .unwrap()
            .config_path;
        let credentials = OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "private-user".into(),
                password: "private-password".into(),
            }),
            private_key_passphrase: Some("private-passphrase".into()),
        };
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let hello: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                writer
                .write_all(
                    &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                        hello.id,
                        json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
                let request: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 16384)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(request.method, method::OPENVPN_CONNECT);
                assert!(
                    request.params["credentials"]["authUserPass"]["username"].as_str()
                        == Some("private-user")
                );
                assert!(
                    request.params["credentials"]["authUserPass"]["password"].as_str()
                        == Some("private-password")
                );
                assert!(
                    request.params["credentials"]["privateKeyPassphrase"].as_str()
                        == Some("private-passphrase")
                );
                writer.write_all(&net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(request.id, json!({"status":{"profileId":"p1","state":"connected","interfaceName":"tun0","rxBytes":0,"txBytes":0,"appliedRoutes":[],"warnings":[]}}))).unwrap()).await.unwrap();
            }
        });
        let client = crate::daemon_client::DaemonClient::new(socket);
        let keyring = crate::openvpn_credentials::tests::FakeKeyring::default();
        let entries = keyring.entries.clone();
        let store = OpenVpnCredentialStore::new(Box::new(keyring));
        let result = linux_openvpn_connect_with_credentials(
            &client,
            &vault,
            &store,
            &p,
            Some(credentials.clone()),
            true,
        )
        .await
        .unwrap();
        assert_eq!(result.state, TunnelState::Running);
        assert_eq!(result.message, None);
        let saved: OpenVpnCredentials =
            serde_json::from_slice(&entries.lock().unwrap()[&p.id]).unwrap();
        assert_eq!(saved, credentials);
        assert!(!openvpn_credentials_path(&vault, &p).unwrap().exists());
        assert_eq!(
            linux_openvpn_connect(&client, &vault, &store, &p)
                .await
                .unwrap()
                .state,
            TunnelState::Running
        );
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_openvpn_probe_uses_managed_bytes_and_remembered_credentials() {
        use net_manager_core::daemon_protocol::{OpenVpnUserPass, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = unique_dir("ovpn-probe-managed");
        let store = test_credential_store();
        let source = dir.join("client.ovpn");
        std::fs::write(&source, "client\nremote vpn.example\nauth-user-pass\n").unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut profile = profile("ovpn");
        profile.backend = TunnelBackend::OpenVpn;
        profile.config_path = vault
            .import(&profile.id, TunnelBackend::OpenVpn, &source)
            .unwrap()
            .config_path;
        profile.routes.push(PolicyRoute {
            destination: "192.0.2.0/24".parse().unwrap(),
            metric: 5,
            via: None,
        });
        assert_eq!(
            prepare_linux_openvpn_request(
                &vault,
                &store,
                &profile,
                None,
                Vec::new(),
                method::OPENVPN_PROBE
            )
            .unwrap_err(),
            "OpenVPN credentials required"
        );
        let credentials = OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "secret-user".into(),
                password: "secret-password".into(),
            }),
            private_key_passphrase: None,
        };
        assert_eq!(store.remember(&profile.id, &credentials), None);
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let hello: RequestFrame = serde_json::from_slice(
                &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            writer
                .write_all(
                    &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                        hello.id,
                        json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
            let request: RequestFrame = serde_json::from_slice(
                &net_manager_core::daemon_protocol::read_frame(&mut reader, 16384)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(request.method, method::OPENVPN_PROBE);
            assert_eq!(request.params["routes"], json!([]));
            assert_eq!(
                request.params["credentials"]["authUserPass"]["username"],
                "secret-user"
            );
            writer
                .write_all(
                    &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                        request.id,
                        json!({"routes":[{"destination":"10.89.0.0/24","source":"OpenVPN pushed","metric":null}]}),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
        });
        let client = crate::daemon_client::DaemonClient::new(socket);
        let routes = linux_openvpn_probe(&client, &vault, &store, &profile)
            .await
            .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "10.89.0.0/24".parse().unwrap());
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_openvpn_rejects_oversize_frame_without_leaking_config() {
        let dir = unique_dir("ovpn-oversize-frame");
        let source = dir.join("secret-client.ovpn");
        std::fs::write(&source, "client\nremote vpn.example 1194\nca large.crt\n").unwrap();
        // Larger than MAX_FRAME_BYTES even before base64 and JSON overhead.
        std::fs::write(
            dir.join("large.crt"),
            vec![b'A'; net_manager_core::daemon_protocol::MAX_FRAME_BYTES + 1],
        )
        .unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut profile = profile("tun0");
        profile.backend = TunnelBackend::OpenVpn;
        profile.config_path = vault
            .import(&profile.id, TunnelBackend::OpenVpn, &source)
            .unwrap()
            .config_path;
        let client = crate::daemon_client::DaemonClient::new(dir.join("missing.sock"));
        let error = linux_openvpn_connect(&client, &vault, &test_credential_store(), &profile)
            .await
            .unwrap_err();
        assert!(error.contains("too large for daemon protocol"), "{error}");
        assert!(!error.contains("secret-client"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_openvpn_rejects_symlinked_managed_config() {
        let dir = unique_dir("ovpn-symlink-config");
        let source = dir.join("client.ovpn");
        std::fs::write(&source, "client\nremote vpn.example 1194\n").unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut profile = profile("tun0");
        profile.backend = TunnelBackend::OpenVpn;
        profile.config_path = vault
            .import(&profile.id, TunnelBackend::OpenVpn, &source)
            .unwrap()
            .config_path;
        std::fs::remove_file(&profile.config_path).unwrap();
        std::os::unix::fs::symlink(&source, &profile.config_path).unwrap();
        let client = crate::daemon_client::DaemonClient::new(dir.join("missing.sock"));
        let error = linux_openvpn_connect(&client, &vault, &test_credential_store(), &profile)
            .await
            .unwrap_err();
        assert!(
            error.contains("managed OpenVPN config is invalid"),
            "{error}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_wireguard_uses_daemon_connect_disconnect_and_status() {
        use net_manager_core::daemon_protocol::{method, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = unique_dir("wg-daemon-bridge");
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut profile = profile("wg-p1");
        profile.config_path = dir.join("p1.conf");
        std::fs::write(
            &profile.config_path,
            "[Interface]\nPrivateKey = fixture\nAddress = 10.77.0.2/32\n[Peer]\nAllowedIPs = 10.77.0.0/24\n",
        )
        .unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        profile.config_path = vault
            .import(&profile.id, TunnelBackend::WireGuard, &profile.config_path)
            .unwrap()
            .config_path;
        let server = tokio::spawn(async move {
            for expected in [
                method::WIREGUARD_CONNECT,
                method::WIREGUARD_STATUS,
                method::WIREGUARD_DISCONNECT,
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let hello: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(hello.method, method::HELLO);
                writer
                    .write_all(
                        &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                            hello.id,
                            json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}),
                        ))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let request: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 4096)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(request.method, expected);
                assert_eq!(request.params["profileId"], "p1");
                if expected == method::WIREGUARD_CONNECT {
                    assert!(request.params["config"]
                        .as_str()
                        .unwrap()
                        .contains("[Interface]"));
                    assert_eq!(request.params["routes"], json!([]));
                }
                let result = match expected {
                    method::WIREGUARD_CONNECT => {
                        json!({"status": {"profileId":"p1","state":"running","interfaceName":"wg-p1","latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[]}})
                    }
                    method::WIREGUARD_STATUS => {
                        json!({"profileId":"p1","state":"stopped","interfaceName":null,"latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[]})
                    }
                    _ => json!({"stopped":true}),
                };
                writer
                    .write_all(
                        &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                            request.id, result,
                        ))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        });
        let client = crate::daemon_client::DaemonClient::new(socket);
        assert_eq!(
            linux_wireguard_connect(&client, &vault, &profile)
                .await
                .unwrap()
                .state,
            TunnelState::Running
        );
        assert_eq!(
            linux_wireguard_status(&client, &profile)
                .await
                .unwrap()
                .state,
            TunnelState::Stopped
        );
        assert_eq!(
            linux_wireguard_disconnect(&client, &profile)
                .await
                .unwrap()
                .state,
            TunnelState::Stopped
        );
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_xray_tun_params_use_vault_config_default_route_and_dns() {
        let dir = unique_dir("xray-tun-params");
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut p = profile("xray-tun");
        p.id = "xray-tun".into();
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        p.xray_socks_port = Some(10808);
        p.xray_http_port = Some(10809);
        let config = net_manager_core::xray::generate_share_link_config_with_http(
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?security=tls",
            10808,
            10809,
        )
        .unwrap();
        p.config_path = vault
            .store_xray_config(&p.id, &serde_json::to_vec(&config).unwrap())
            .unwrap()
            .config_path;
        let params = prepare_linux_xray_tun_params(&vault, &p).unwrap();
        assert_eq!(params.profile_id, p.id);
        assert_eq!(params.routes.len(), 1);
        assert_eq!(params.routes[0].destination.to_string(), "0.0.0.0/0");
        assert_eq!(
            params.dns_servers,
            vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(params.dns_domains.is_empty());
        assert!(params.config.contains("\"http-in\""));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn xray_tun_rejects_arbitrary_json_without_echoing_secret() {
        let dir = unique_dir("xray-tun-reject");
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut p = profile("xray-tun");
        p.id = "xray-tun".into();
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        p.xray_socks_port = Some(10808);
        p.xray_http_port = Some(10809);
        p.config_path = vault
            .store_xray_config(&p.id, br#"{"secret":"private-uuid","outbounds":[]}"#)
            .unwrap()
            .config_path;
        let err = prepare_linux_xray_tun_params(&vault, &p).unwrap_err();
        assert!(!err.contains("private-uuid"));
        assert!(!err.contains(&p.config_path.display().to_string()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn split_default_profile_emits_def1_halves_and_dns_bypasses() {
        let dir = unique_dir("xray-split-default");
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut p = profile("xray-split-def");
        p.id = "xray-split-def".into();
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        p.xray_socks_port = Some(10808);
        p.xray_http_port = Some(10809);
        p.xray_split_default = true;
        p.xray_dns.servers = vec![
            net_manager_core::models::XrayDnsServer {
                address: "udp://9.9.9.9:53".into(),
                route: net_manager_core::models::XrayDnsRoute::Direct,
                domains: Vec::new(),
                port: None,
                skip_fallback: false,
            },
            net_manager_core::models::XrayDnsServer {
                address: "https://dns.resolver.test/dns-query".into(),
                route: net_manager_core::models::XrayDnsRoute::Direct,
                domains: Vec::new(),
                port: None,
                skip_fallback: false,
            },
            net_manager_core::models::XrayDnsServer {
                address: "udp://8.8.4.4".into(),
                route: net_manager_core::models::XrayDnsRoute::Proxy,
                domains: Vec::new(),
                port: None,
                skip_fallback: false,
            },
        ];
        let config = net_manager_core::xray::generate_share_link_config_with_http(
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?security=tls",
            10808,
            10809,
        )
        .unwrap();
        p.config_path = vault
            .store_xray_config(&p.id, &serde_json::to_vec(&config).unwrap())
            .unwrap()
            .config_path;
        let params = prepare_linux_xray_tun_params(&vault, &p).unwrap();
        assert_eq!(
            params
                .routes
                .iter()
                .map(|r| r.destination.to_string())
                .collect::<Vec<_>>(),
            ["0.0.0.0/1", "128.0.0.0/1"]
        );
        // Direct resolvers and the well-known public DNS stay on the
        // physical uplink; the proxy-routed resolver does not (it must be
        // reachable *through* the tunnel).
        for expected in ["1.1.1.1", "8.8.8.8", "9.9.9.9", "dns.resolver.test"] {
            assert!(
                params.dns_bypass.iter().any(|h| h == expected),
                "missing {expected} in {:?}",
                params.dns_bypass
            );
        }
        assert!(!params.dns_bypass.iter().any(|h| h == "8.8.4.4"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn xray_tun_split_routes_do_not_warn_about_intentionally_omitted_dns_or_full_coverage() {
        let mut p = profile("split");
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        p.routes.push(PolicyRoute {
            destination: "10.0.0.0/8".parse().unwrap(),
            metric: 5,
            via: None,
        });
        let status = XrayStatusResult {
            profile_id: p.id.clone(),
            state: TunnelState::Running,
            interface_name: Some("xray-split".into()),
            watchdog: None,
            dns_applied: false,
            ipv4_covered: false,
            ipv6_covered: false,
            rx_bytes: None,
            tx_bytes: None,
            failover: None,
        };
        assert!(linux_xray_tunnel_status(status, &p).message.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn xray_tun_default_route_warns_when_expected_dns_is_missing() {
        let mut p = profile("default");
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        let status = XrayStatusResult {
            profile_id: p.id.clone(),
            state: TunnelState::Running,
            watchdog: None,
            interface_name: Some("xray-default".into()),
            dns_applied: false,
            ipv4_covered: true,
            ipv6_covered: false,
            rx_bytes: None,
            tx_bytes: None,
            failover: None,
        };
        let message = linux_xray_tunnel_status(status, &p).message.unwrap();
        assert!(message.contains("DNS was not applied"));
        assert!(message.contains("IPv6 is not covered"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openvpn_failed_status_has_honest_generic_credential_or_server_hint() {
        let status = OpenVpnStatusResult {
            profile_id: "p1".into(),
            state: OpenVpnConnectionState::Failed,
            interface_name: None,
            rx_bytes: 0,
            tx_bytes: 0,
            applied_routes: Vec::new(),
            warnings: Vec::new(),
            failure_reason: None,
        };
        let message = linux_openvpn_tunnel_status(status).message.unwrap();
        assert!(message.contains("check credentials or server"));
        assert!(!message.contains("wrong password"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openvpn_auth_failure_status_has_specific_safe_message() {
        let status = OpenVpnStatusResult {
            profile_id: "p1".into(),
            state: OpenVpnConnectionState::Failed,
            interface_name: None,
            rx_bytes: 0,
            tx_bytes: 0,
            applied_routes: Vec::new(),
            warnings: vec![OpenVpnWarning::AuthenticationFailed],
            failure_reason: None,
        };
        let message = linux_openvpn_tunnel_status(status).message.unwrap();
        assert_eq!(
            message,
            "OpenVPN authentication failed; check username, password, or private key passphrase"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openvpn_failure_reason_maps_to_specific_safe_messages() {
        use net_manager_core::daemon_protocol::OpenVpnFailure as F;
        for (reason, needle) in [
            (F::CredentialsRequired, "credentials that are not stored"),
            (F::ResolveError, "resolve the server address"),
            (F::ConnectError, "could not reach the server"),
            (F::TlsError, "TLS handshake failed"),
            (F::ConnectionLost, "connection was lost"),
            (F::ExitNotification, "asked the client to disconnect"),
            (F::Terminated, "terminated"),
            (F::ExitWithError, "check credentials or server settings"),
            (F::AuthenticationFailure, "authentication failed"),
        ] {
            let status = OpenVpnStatusResult {
                profile_id: "p1".into(),
                state: OpenVpnConnectionState::Failed,
                interface_name: None,
                rx_bytes: 0,
                tx_bytes: 0,
                applied_routes: Vec::new(),
                warnings: Vec::new(),
                failure_reason: Some(reason),
            };
            let message = linux_openvpn_tunnel_status(status).message.unwrap();
            assert!(message.contains(needle), "{reason:?}: {message}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_only_credentials_notice_does_not_hide_running_tunnel() {
        let status = OpenVpnStatusResult {
            profile_id: "p1".into(),
            state: OpenVpnConnectionState::Connected,
            interface_name: Some("tun0".into()),
            rx_bytes: 0,
            tx_bytes: 0,
            applied_routes: Vec::new(),
            warnings: Vec::new(),
            failure_reason: None,
        };
        let result = finish_openvpn_connect(
            status,
            Some(crate::openvpn_credentials::SESSION_ONLY_NOTICE),
        );
        assert_eq!(result.state, TunnelState::Running);
        let message = result.message.unwrap();
        assert!(message.contains("only until the app exits"), "{message}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_xray_tun_uses_daemon_for_connect_restart_status_and_disconnect() {
        use net_manager_core::daemon_protocol::{RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = unique_dir("xray-tun-daemon");
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut p = profile("xray-p1");
        p.id = "xray-p1".into();
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        p.xray_socks_port = Some(10808);
        p.xray_http_port = Some(10809);
        let config = net_manager_core::xray::generate_share_link_config_with_http(
            "hy2://private-auth@node.test:443",
            10808,
            10809,
        )
        .unwrap();
        p.config_path = vault
            .store_xray_config(&p.id, &serde_json::to_vec(&config).unwrap())
            .unwrap()
            .config_path;
        let server = tokio::spawn(async move {
            for method_name in [
                method::XRAY_CONNECT,
                method::XRAY_STATUS,
                method::XRAY_DISCONNECT,
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let hello: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                writer.write_all(&net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                    hello.id, json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]})
                )).unwrap()).await.unwrap();
                let request: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 8192)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(request.method, method_name);
                assert_eq!(request.params["profileId"], "xray-p1");
                if method_name == method::XRAY_CONNECT {
                    assert_eq!(request.params["routes"][0]["destination"], "0.0.0.0/0");
                    assert_eq!(request.params["dnsServers"], json!(["1.1.1.1"]));
                    let config: serde_json::Value =
                        serde_json::from_str(request.params["config"].as_str().unwrap()).unwrap();
                    assert_eq!(config["outbounds"][0]["protocol"], "hysteria");
                }
                let status = json!({"profileId":"xray-p1","state":"running","interfaceName":"xray-test","dnsApplied":true,"ipv4Covered":true,"ipv6Covered":false});
                let result = match method_name {
                    method::XRAY_CONNECT => json!({"status": status}),
                    method::XRAY_STATUS => status,
                    _ => json!({"stopped":true}),
                };
                writer
                    .write_all(
                        &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                            request.id, result,
                        ))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        });
        let client = crate::daemon_client::DaemonClient::new(socket.clone());
        let state = app_state(&dir);
        let connected = linux_xray_connect(&client, &vault, &state, &p)
            .await
            .unwrap();
        assert_eq!(connected.state, TunnelState::Running);
        assert!(connected.message.unwrap().contains("IPv6 is not covered"));
        let restarted_client = crate::daemon_client::DaemonClient::new(socket);
        assert_eq!(
            linux_xray_status(&restarted_client, &p)
                .await
                .unwrap()
                .state,
            TunnelState::Running
        );
        assert_eq!(
            linux_xray_disconnect(&restarted_client, &p)
                .await
                .unwrap()
                .state,
            TunnelState::Stopped
        );
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_wireguard_forwards_full_and_dns_and_shows_daemon_outcomes() {
        use net_manager_core::daemon_protocol::{method, ErrorCode, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = unique_dir("wg-full-dns-bridge");
        let mut profile = profile("wg-p1");
        profile.config_path = dir.join("p1.conf");
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        std::fs::write(&profile.config_path, "[Interface]\n").unwrap();
        profile.config_path = vault
            .import(&profile.id, TunnelBackend::WireGuard, &profile.config_path)
            .unwrap()
            .config_path;
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            for (index, expected) in ["0.0.0.0/0", "DNS = 10.77.0.1", "0.0.0.0/0"]
                .into_iter()
                .enumerate()
            {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let hello: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(hello.method, method::HELLO);
                writer
                    .write_all(
                        &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                            hello.id,
                            json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}),
                        ))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let request: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 4096)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(request.method, method::WIREGUARD_CONNECT);
                assert!(request.params["config"]
                    .as_str()
                    .unwrap()
                    .contains(expected));
                let response = if index == 2 {
                    ResponseFrame::error(
                        request.id,
                        ErrorCode::InvalidParams,
                        "full tunnel unavailable",
                    )
                } else {
                    let warning = if index == 0 {
                        "ipv6NotCovered"
                    } else {
                        "dnsNotApplied"
                    };
                    ResponseFrame::ok(
                        request.id,
                        json!({"status":{"profileId":"p1","state":"running","interfaceName":"wg-p1","latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[warning]}}),
                    )
                };
                writer
                    .write_all(&net_manager_core::daemon_protocol::encode_line(&response).unwrap())
                    .await
                    .unwrap();
            }
        });
        let client = crate::daemon_client::DaemonClient::new(socket);
        let full = "[Interface]\nPrivateKey = fixture\nAddress = 10.77.0.2/32\n[Peer]\nAllowedIPs = 0.0.0.0/0\n";
        let dns = "[Interface]\nPrivateKey = fixture\nAddress = 10.77.0.2/32\nDNS = 10.77.0.1\n[Peer]\nAllowedIPs = 10.77.0.0/24\n";
        std::fs::write(&profile.config_path, full).unwrap();
        let status = linux_wireguard_connect(&client, &vault, &profile)
            .await
            .unwrap();
        assert!(status.message.unwrap().contains("IPv6 is not covered"));
        std::fs::write(&profile.config_path, dns).unwrap();
        let status = linux_wireguard_connect(&client, &vault, &profile)
            .await
            .unwrap();
        assert!(status.message.unwrap().contains("DNS was not applied"));
        std::fs::write(&profile.config_path, full).unwrap();
        let err = linux_wireguard_connect(&client, &vault, &profile)
            .await
            .unwrap_err();
        assert_eq!(err, "full tunnel unavailable");
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_wireguard_connect_requires_own_managed_config_without_leaking_path() {
        let dir = unique_dir("wg-managed-config");
        let vault = net_manager_core::config_vault::ConfigVault::new(dir.join("configs"));
        let mut profile = profile("wg-p1");
        profile.config_path = dir.join("secret-private-path.conf");
        std::fs::write(&profile.config_path, "[Interface]\nPrivateKey=secret\n").unwrap();
        let client = crate::daemon_client::DaemonClient::new(dir.join("missing.sock"));
        let err = linux_wireguard_connect(&client, &vault, &profile)
            .await
            .unwrap_err();
        assert!(err.contains("managed config"), "{err}");
        assert!(!err.contains("secret-private-path"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    #[cfg_attr(not(target_os = "linux"), allow(irrefutable_let_patterns))]
    async fn cleanup_stale_clears_tracked_routes_and_persists_registry() {
        let dir = unique_dir("cleanup-stale");
        let state = app_state(&dir);
        let mut runtime = state.runtime.lock().await;
        if let crate::route_runtime::RouteRuntime::Local { policies, .. } = &mut runtime.routes {
            policies
                .restore(vec![AppliedProfileRoutes {
                    profile_id: "p1".into(),
                    routes: vec![AppliedRoute {
                        destination: "10.4.0.0/24".parse().unwrap(),
                        interface_index: 5,
                        metric: 11,
                        gateway: None,
                        table: None,
                    }],
                }])
                .unwrap();
        }
        let p = profile("wg-p1");
        cleanup_stale_routes_before_connect(&mut runtime, &p)
            .await
            .unwrap();
        assert!(!runtime.routes.has_applied("p1").await.unwrap());
        let loaded =
            net_manager_core::route_state::AppliedRouteStore::new(dir.join("applied-routes.json"))
                .load()
                .unwrap();
        assert!(loaded.profiles.is_empty());
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;
    use crate::test_support::profile;

    #[test]
    fn connect_port_reallocation_skips_own_http_port_and_other_listeners() {
        let mut current = profile("current");
        current.id = "current".into();
        current.backend = TunnelBackend::Xray;
        current.xray_socks_port = Some(10808);
        current.xray_http_port = Some(10809);
        let mut other = profile("other");
        other.id = "other".into();
        other.backend = TunnelBackend::Xray;
        other.xray_socks_port = Some(10810);
        let selected =
            select_connect_ports(&[current.clone(), other], &current, |port| port != 10808)
                .unwrap();
        assert_eq!(selected, Some((10811, Some(10809))));
    }

    #[test]
    fn connect_port_reallocation_replaces_occupied_http_and_both_ports() {
        let mut current = profile("current");
        current.id = "current".into();
        current.backend = TunnelBackend::Xray;
        current.xray_socks_port = Some(10808);
        current.xray_http_port = Some(10809);
        let mut other = profile("other");
        other.id = "other".into();
        other.backend = TunnelBackend::Xray;
        other.xray_socks_port = Some(10810);
        let profiles = [current.clone(), other];
        assert_eq!(
            select_connect_ports(&profiles, &current, |port| port != 10809).unwrap(),
            Some((10808, Some(10811)))
        );
        assert_eq!(
            select_connect_ports(&profiles, &current, |port| !matches!(port, 10808 | 10809))
                .unwrap(),
            Some((10811, Some(10812)))
        );
    }
}
