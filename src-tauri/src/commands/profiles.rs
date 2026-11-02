use crate::elevation;
use crate::state::{existing_profile_for_update, find_profile, AppState};
#[cfg(test)]
use net_manager_core::config_security;
use net_manager_core::config_vault::{ConfigImport, ConfigVault};
use net_manager_core::models::*;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager, State};

use net_manager_core::subscription::MAX_SUBSCRIPTION_BODY_BYTES;
static SUBSCRIPTION_REFRESH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn validate_refresh_interval(minutes: Option<u32>) -> Result<(), String> {
    if minutes.is_none_or(|minutes| matches!(minutes, 15 | 60 | 360)) {
        Ok(())
    } else {
        Err("unsupported subscription refresh interval".into())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .unwrap_or(0)
}

pub(crate) fn subscription_refresh_due(subscription: &SubscriptionMeta, now: u64) -> bool {
    net_manager_core::subscription::refresh_due(subscription, now)
}

fn should_auto_refresh(profile: &Profile, now: u64, active: bool) -> bool {
    !active
        && profile.backend == TunnelBackend::Xray
        && profile
            .subscription
            .as_ref()
            .is_some_and(|subscription| subscription_refresh_due(subscription, now))
}
use net_manager_core::subscription::{DELAY_PROBE_TIMEOUT, DELAY_PROBE_URL};

#[cfg(test)]
pub(crate) fn select_available_socks_port(
    used: &HashSet<u16>,
    available: impl Fn(u16) -> bool,
) -> Result<u16, String> {
    net_manager_core::profile_import::select_available_socks_port(used, available)
        .map_err(|e| e.to_string())
}
fn select_generated_ports(
    preferred_socks: Option<u16>,
    preferred_http: Option<u16>,
    used: &HashSet<u16>,
    available: impl Fn(u16) -> bool,
) -> Result<(u16, u16), String> {
    net_manager_core::profile_import::select_generated_ports(
        preferred_socks,
        preferred_http,
        used,
        available,
    )
    .map_err(|e| e.to_string())
}
pub(crate) fn profile_listener_ports(profiles: &[Profile], exclude_id: &str) -> HashSet<u16> {
    net_manager_core::profile_import::profile_listener_ports(profiles, exclude_id)
}

pub(crate) fn loopback_port_available(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

pub(crate) fn store_generated_xray(
    vault: &ConfigVault,
    profile_id: &str,
    plaintext_json: &[u8],
) -> std::io::Result<ConfigImport> {
    vault.store_generated_xray(profile_id, plaintext_json)
}

#[cfg(test)]
pub(crate) fn rewrite_generated_proxy_ports(
    vault: &ConfigVault,
    profile: &mut Profile,
    new_socks_port: u16,
    new_http_port: Option<u16>,
) -> Result<PathBuf, String> {
    net_manager_core::profile_import::rewrite_generated_proxy_ports(
        vault,
        profile,
        new_socks_port,
        new_http_port,
    )
    .map_err(|err| err.to_string())
}

pub(crate) fn remove_managed_revision(
    vault: &ConfigVault,
    profile_id: &str,
    path: &Path,
    action: &str,
) -> Result<(), String> {
    if !vault.is_managed_profile_path(profile_id, path) {
        return Ok(());
    }
    vault.remove_revision_for_config(path).map_err(|err| {
        format!(
            "{action}, but managed config cleanup failed for '{}': {err}",
            path.display()
        )
    })
}

fn redact_profiles_for_ipc(mut profiles: Vec<Profile>) -> Vec<Profile> {
    for profile in &mut profiles {
        if let Some(subscription) = &mut profile.subscription {
            subscription.url.clear();
            subscription.hwid.clear();
        }
    }
    profiles
}

fn redact_batch_import_for_ipc(mut result: BatchImportResult) -> BatchImportResult {
    result.profiles = redact_profiles_for_ipc(result.profiles);
    result
}

fn preserve_canonical_subscription(profile: &mut Profile, stored: Option<&Profile>) {
    profile.subscription = if profile.backend == TunnelBackend::Xray {
        stored.and_then(|profile| profile.subscription.clone())
    } else {
        None
    };
}

/// Linux multinode: the node pins live on the profile but are edited through
/// `set_pinned_routes`, never through the generic form save — restore the
/// stored value so editing other fields cannot drop them.
fn preserve_pinned_policies(profile: &mut Profile, stored: Option<&Profile>) {
    profile.pinned_policies = if profile.backend == TunnelBackend::Xray {
        stored.map_or_else(Vec::new, |profile| profile.pinned_policies.clone())
    } else {
        Vec::new()
    };
}

fn preserve_migrated_xray_settings(profile: &mut Profile, stored: Option<&Profile>) {
    if profile.backend != TunnelBackend::Xray {
        profile.xray_sockopts = None;
        profile.xray_traffic_rules.clear();
        profile.xray_interface_routes.clear();
        profile.xray_connection_idle_secs = None;
        profile.xray_tun_mtu = None;
        profile.xray_tun_dns_servers.clear();
        profile.xray_direct_domain_strategy = None;
        profile.xray_quic_reject = false;
        return;
    }

    let Some(stored) = stored.filter(|stored| stored.backend == TunnelBackend::Xray) else {
        return;
    };
    profile.xray_sockopts = stored.xray_sockopts.clone();
    profile.xray_traffic_rules = stored.xray_traffic_rules.clone();
    profile.xray_interface_routes = stored.xray_interface_routes.clone();
    profile.xray_connection_idle_secs = stored.xray_connection_idle_secs;
    profile.xray_tun_mtu = stored.xray_tun_mtu;
    profile.xray_tun_dns_servers = stored.xray_tun_dns_servers.clone();
    profile.xray_direct_domain_strategy = stored.xray_direct_domain_strategy.clone();
    profile.endpoint_bypasses = stored.endpoint_bypasses.clone();

    // xray_quic_reject is deliberately not restored for Xray:
    // the existing Linux form owns its editable toggle.
}

fn preserve_generated_xray_source(profile: &mut Profile, stored: Option<&Profile>) {
    let generated = stored.filter(|existing| {
        profile.backend == TunnelBackend::Xray
            && existing.backend == TunnelBackend::Xray
            && existing.config_path == profile.config_path
    });
    profile.xray_socks_port = generated.and_then(|existing| existing.xray_socks_port);
    profile.xray_http_port = generated.and_then(|existing| existing.xray_http_port);
}

fn validate_xray_routing(profile: &Profile) -> Result<(), String> {
    if profile.backend == TunnelBackend::Xray {
        net_manager_core::xray::validate_routing_policy_selectors(&profile.domain_policies)
            .map_err(|err| format!("invalid Xray routing rule: {err}"))?;
        #[cfg(target_os = "linux")]
        for url in [
            profile.xray_geoip_url.as_deref(),
            profile.xray_geosite_url.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            crate::geo_assets::validate_geo_asset_url(url)
                .map_err(|err| format!("invalid Xray geo data URL: {err}"))?;
        }
    }
    Ok(())
}

fn validate_managed_save_path(
    vault: &ConfigVault,
    stored: Option<&Profile>,
    profile: &Profile,
) -> Result<(), String> {
    if !vault.is_managed_path(&profile.config_path) {
        return Ok(());
    }
    if !vault.is_managed_profile_path(&profile.id, &profile.config_path) {
        return Err(format!(
            "config path '{}' is managed by a different profile",
            profile.config_path.display()
        ));
    }
    if let Some(existing) = stored {
        if existing.config_path == profile.config_path && existing.backend != profile.backend {
            return Err(
                "changing backend requires selecting or importing a new source config".into(),
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn ensure_linux_wireguard_stopped(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
    action: &str,
) -> Result<(), String> {
    let status = crate::commands::tunnels::linux_wireguard_status(client, profile).await?;
    if status.state != TunnelState::Stopped {
        return Err(format!(
            "profile '{}' is active; disconnect before {action}",
            profile.id
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn ensure_linux_openvpn_stopped(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
    action: &str,
) -> Result<(), String> {
    let status = crate::commands::tunnels::linux_openvpn_status(client, profile).await?;
    if status.state != TunnelState::Stopped {
        return Err(format!(
            "profile '{}' is active; disconnect before {action}",
            profile.id
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn ensure_linux_xray_stopped(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
    action: &str,
) -> Result<(), String> {
    let status = crate::commands::tunnels::linux_xray_status(client, profile).await?;
    if status.state != TunnelState::Stopped {
        return Err(format!(
            "Xray TUN profile is active; disconnect before {action}"
        ));
    }
    Ok(())
}

async fn ensure_profile_stopped(
    state: &AppState,
    profile: &Profile,
    action: &str,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::WireGuard {
        return ensure_linux_wireguard_stopped(
            &crate::daemon_client::DaemonClient::system(),
            profile,
            action,
        )
        .await;
    }
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::OpenVpn {
        return ensure_linux_openvpn_stopped(
            &crate::daemon_client::DaemonClient::system(),
            profile,
            action,
        )
        .await;
    }
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun {
        return ensure_linux_xray_stopped(
            &crate::daemon_client::DaemonClient::system(),
            profile,
            action,
        )
        .await;
    }
    let mut runtime = state.runtime.lock().await;
    if runtime.tunnels.status(profile).state == TunnelState::Running {
        return Err(format!(
            "profile '{}' is running; disconnect before {action}",
            profile.id
        ));
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn get_profiles(state: State<'_, AppState>) -> Result<Vec<Profile>, String> {
    state
        .profiles
        .load()
        .map(|doc| redact_profiles_for_ipc(doc.profiles))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn reorder_profiles(
    backend: TunnelBackend,
    ordered_ids: Vec<String>,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let doc = state
        .profiles
        .reorder(backend, &ordered_ids)
        .map_err(|e| e.to_string())?;
    Ok(redact_profiles_for_ipc(doc.profiles))
}

#[tauri::command]
pub(crate) async fn save_profile(
    mut profile: Profile,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let document = state.profiles.load().map_err(|e| e.to_string())?;
    let stored = existing_profile_for_update(&document, &profile.id).cloned();
    preserve_canonical_subscription(&mut profile, stored.as_ref());
    preserve_pinned_policies(&mut profile, stored.as_ref());
    preserve_migrated_xray_settings(&mut profile, stored.as_ref());
    preserve_generated_xray_source(&mut profile, stored.as_ref());
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::Xray
        && profile.xray_mode == XrayMode::Tun
        && (profile.xray_socks_port.is_none() || profile.xray_http_port.is_none())
    {
        return Err("Xray TUN requires a generated share-link profile".into());
    }
    validate_xray_routing(&profile)?;
    if let Some(existing) = &stored {
        #[cfg(target_os = "linux")]
        crate::commands::always_on::ensure_not_enrolled(
            &crate::daemon_client::DaemonClient::system(),
            existing,
        )
        .await?;
        ensure_profile_stopped(&state, existing, "editing").await?;
    }
    validate_managed_save_path(&state.config_vault, stored.as_ref(), &profile)?;
    let imported = if profile.backend == TunnelBackend::None
        || state.config_vault.is_managed_path(&profile.config_path)
    {
        None
    } else {
        let import = state
            .config_vault
            .import(&profile.id, profile.backend, &profile.config_path)
            .map_err(|e| e.to_string())?;
        profile.config_path = import.config_path.clone();
        Some(import.config_path)
    };
    let new_path = profile.config_path.clone();
    let doc = match state.profiles.upsert(profile) {
        Ok(doc) => doc,
        Err(err) => {
            if let Some(path) = imported {
                let _ = state.config_vault.remove_revision_for_config(&path);
            }
            return Err(err.to_string());
        }
    };
    if let Some(existing) = stored {
        if existing.config_path != new_path {
            remove_managed_revision(
                &state.config_vault,
                &existing.id,
                &existing.config_path,
                "profile saved",
            )?;
        }
    }
    Ok(redact_profiles_for_ipc(doc.profiles))
}

#[tauri::command]
pub(crate) async fn delete_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let profile = find_profile(&state.profiles, &id)?;
    #[cfg(target_os = "linux")]
    crate::commands::always_on::ensure_not_enrolled(
        &crate::daemon_client::DaemonClient::system(),
        &profile,
    )
    .await?;
    ensure_profile_stopped(&state, &profile, "deleting").await?;
    {
        let mut runtime = state.runtime.lock().await;
        if runtime.routes.has_applied(&id).await? {
            return Err(format!(
                "profile '{id}' has applied routes; disconnect before deleting"
            ));
        }
    }
    let doc = state.profiles.delete(&id).map_err(|e| e.to_string())?;
    state
        .config_vault
        .remove_profile(&id)
        .map_err(|err| format!("profile deleted, but managed config cleanup failed: {err}"))?;
    #[cfg(target_os = "linux")]
    if profile.backend == TunnelBackend::OpenVpn {
        state.openvpn_credentials.forget(&id, None).map_err(|_| {
            "profile deleted, but remembered OpenVPN credentials could not be removed".to_string()
        })?;
    }
    Ok(redact_profiles_for_ipc(doc.profiles))
}

#[tauri::command]
pub(crate) async fn save_vless_profile(
    mut profile: Profile,
    vless_url: String,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    if profile.backend != TunnelBackend::Xray {
        return Err("share link import requires an Xray profile".into());
    }
    let document = state.profiles.load().map_err(|e| e.to_string())?;
    let used = profile_listener_ports(&document.profiles, &profile.id);
    let (socks_port, http_port) = select_generated_ports(
        profile.xray_socks_port,
        profile.xray_http_port,
        &used,
        loopback_port_available,
    )?;
    profile.xray_socks_port = Some(socks_port);
    profile.xray_http_port = Some(http_port);
    let stored = existing_profile_for_update(&document, &profile.id).cloned();
    preserve_canonical_subscription(&mut profile, stored.as_ref());
    preserve_pinned_policies(&mut profile, stored.as_ref());
    preserve_migrated_xray_settings(&mut profile, stored.as_ref());
    validate_xray_routing(&profile)?;
    if let Some(existing) = &stored {
        ensure_profile_stopped(&state, existing, "editing").await?;
    }
    let config = generate_endpoint_config(vless_url.trim(), socks_port, http_port)?;
    let body = serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?;
    let import =
        store_generated_xray(&state.config_vault, &profile.id, &body).map_err(|e| e.to_string())?;
    profile.config_path = import.config_path.clone();
    let doc = match state.profiles.upsert(profile) {
        Ok(doc) => doc,
        Err(err) => {
            let _ = state
                .config_vault
                .remove_revision_for_config(&import.config_path);
            return Err(err.to_string());
        }
    };
    if let Some(existing) = stored {
        if existing.config_path != import.config_path {
            remove_managed_revision(
                &state.config_vault,
                &existing.id,
                &existing.config_path,
                "profile saved",
            )?;
        }
    }
    Ok(redact_profiles_for_ipc(doc.profiles))
}

fn generate_endpoint_config(
    uri: &str,
    socks_port: u16,
    http_port: u16,
) -> Result<serde_json::Value, String> {
    net_manager_core::xray::generate_share_link_config_with_http(uri, socks_port, http_port)
        .map_err(|e| format!("invalid share link: {e}"))
}

/// Render WireGuard `[Interface]`/`[Peer]` config text from user-supplied
/// fields. Values are written verbatim; the caller validates them.
pub(crate) fn render_wireguard_config(fields: &WireGuardFields) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", fields.private_key.trim()));
    out.push_str(&format!("Address = {}\n", fields.address.trim()));
    if !fields.dns.trim().is_empty() {
        out.push_str(&format!("DNS = {}\n", fields.dns.trim()));
    }
    out.push('\n');
    out.push_str("[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", fields.peer_public_key.trim()));
    out.push_str(&format!("Endpoint = {}\n", fields.peer_endpoint.trim()));
    out.push_str(&format!("AllowedIPs = {}\n", fields.allowed_ips.trim()));
    if !fields.preshared_key.trim().is_empty() {
        out.push_str(&format!("PresharedKey = {}\n", fields.preshared_key.trim()));
    }
    if let Some(keepalive) = fields.persistent_keepalive {
        out.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
    }
    out
}

#[tauri::command]
pub(crate) async fn save_wireguard_profile(
    mut profile: Profile,
    fields: WireGuardFields,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    if profile.backend != TunnelBackend::WireGuard {
        return Err("wireguard fields require a WireGuard profile".into());
    }
    if fields.private_key.trim().is_empty() {
        return Err("WireGuard private key is required".into());
    }
    if fields.address.trim().is_empty() {
        return Err("WireGuard interface address is required".into());
    }
    if fields.peer_public_key.trim().is_empty() {
        return Err("WireGuard peer public key is required".into());
    }
    if fields.peer_endpoint.trim().is_empty() {
        return Err("WireGuard peer endpoint is required".into());
    }
    if fields.allowed_ips.trim().is_empty() {
        return Err("WireGuard allowed IPs are required".into());
    }
    let document = state.profiles.load().map_err(|e| e.to_string())?;
    let stored = existing_profile_for_update(&document, &profile.id).cloned();
    preserve_canonical_subscription(&mut profile, stored.as_ref());
    preserve_pinned_policies(&mut profile, stored.as_ref());
    preserve_migrated_xray_settings(&mut profile, stored.as_ref());
    if let Some(existing) = &stored {
        #[cfg(target_os = "linux")]
        crate::commands::always_on::ensure_not_enrolled(
            &crate::daemon_client::DaemonClient::system(),
            existing,
        )
        .await?;
        ensure_profile_stopped(&state, existing, "editing").await?;
    }
    let body = render_wireguard_config(&fields).into_bytes();
    let import = state
        .config_vault
        .store_wireguard_config(&profile.id, &body)
        .map_err(|e| e.to_string())?;
    profile.config_path = import.config_path.clone();
    let doc = match state.profiles.upsert(profile) {
        Ok(doc) => doc,
        Err(err) => {
            let _ = state
                .config_vault
                .remove_revision_for_config(&import.config_path);
            return Err(err.to_string());
        }
    };
    if let Some(existing) = stored {
        if existing.config_path != import.config_path {
            remove_managed_revision(
                &state.config_vault,
                &existing.id,
                &existing.config_path,
                "profile saved",
            )?;
        }
    }
    Ok(redact_profiles_for_ipc(doc.profiles))
}

#[cfg(test)]
pub(crate) use net_manager_core::profile_import::detect_backend;
pub(crate) use net_manager_core::profile_import::{generate_import_id, import_configs_into};

#[tauri::command]
pub(crate) async fn import_share_link(
    link: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<BatchImportResult, String> {
    let _lock = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let document = net_manager_core::profile_import::import_share_link(
        &state.config_vault,
        &state.profiles,
        &generate_import_id(0),
        &name,
        &link,
        loopback_port_available,
    )
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => {
            "Invalid or unsupported share link. Use vless://, hysteria2:// or hy2://.".to_string()
        }
        _ => "The profile operation could not be completed. Check the input and file permissions."
            .to_string(),
    })?;
    Ok(redact_batch_import_for_ipc(BatchImportResult {
        profiles: document.profiles,
        errors: Vec::new(),
    }))
}

#[tauri::command]
pub(crate) async fn import_configs_batch(
    paths: Vec<String>,
    default_backend: Option<TunnelBackend>,
    state: State<'_, AppState>,
) -> Result<BatchImportResult, String> {
    // Enable SeBackupPrivilege so we can read ACL-protected files
    // (e.g. WireGuard `.conf.dpapi` configs owned by SYSTEM) when the
    // process is elevated. Ignored on non-Windows or when not elevated.
    let _ = elevation::enable_backup_privilege();
    import_configs_into(
        &state.config_vault,
        &state.profiles,
        &paths,
        default_backend,
    )
    .map(redact_batch_import_for_ipc)
    .map_err(|e| e.to_string())
}

#[cfg(test)]
use net_manager_core::subscription::base64_decode;
#[cfg(test)]
use net_manager_core::subscription::parse_subscription_body;

// Subscription metadata parsing lives in the core so the native client
// shares it; these names keep the Tauri call sites and tests stable.
use net_manager_core::subscription::ResponseMeta as SubscriptionResponseMeta;

/// Fetch a subscription and import its supported share links.
pub(crate) async fn import_subscription_into(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    client: &reqwest::Client,
    url: &str,
    hwid: &str,
    refresh_interval_minutes: Option<u32>,
) -> Result<BatchImportResult, String> {
    validate_refresh_interval(refresh_interval_minutes)?;
    let fetched = net_manager_core::subscription::fetch(client, url, hwid)
        .await
        .map_err(|e| e.to_string())?;
    import_subscription_body_into_with_metadata(
        vault,
        store,
        url,
        hwid,
        &fetched.body,
        refresh_interval_minutes,
        fetched.meta,
    )
}

async fn read_subscription_response(mut response: reqwest::Response) -> Result<String, String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "failed to read subscription body".to_string())?
    {
        if chunk.len() > MAX_SUBSCRIPTION_BODY_BYTES - bytes.len() {
            return Err("subscription body exceeds size limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| "subscription body is not UTF-8".to_string())
}

#[cfg(test)]
fn import_subscription_body_into(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    url: &str,
    hwid: &str,
    body: &str,
) -> Result<BatchImportResult, String> {
    import_subscription_body_into_with_metadata(
        vault,
        store,
        url,
        hwid,
        body,
        None,
        SubscriptionResponseMeta::default(),
    )
}

fn import_subscription_body_into_with_metadata(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    url: &str,
    hwid: &str,
    body: &str,
    refresh_interval_minutes: Option<u32>,
    meta: SubscriptionResponseMeta,
) -> Result<BatchImportResult, String> {
    let id = generate_import_id(0);
    let request = net_manager_core::subscription::SubscriptionImport {
        id: &id,
        url,
        hwid,
        name: "",
        refresh_interval_minutes,
    };
    net_manager_core::subscription::import_body(
        vault,
        store,
        &request,
        body,
        meta,
        loopback_port_available,
    )
    .map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidInput {
            error.to_string()
        } else {
            "failed to store subscription profile".to_string()
        }
    })
}

#[tauri::command]
pub(crate) async fn import_subscription(
    url: String,
    hwid: String,
    refresh_interval_minutes: Option<u32>,
    state: State<'_, AppState>,
) -> Result<BatchImportResult, String> {
    let _lock = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let client = net_manager_core::subscription::http_client().map_err(|e| e.to_string())?;
    import_subscription_into(
        &state.config_vault,
        &state.profiles,
        &client,
        &url,
        &hwid,
        refresh_interval_minutes,
    )
    .await
    .map(redact_batch_import_for_ipc)
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionRefreshResult {
    pub endpoint_count: usize,
    pub active_index: usize,
    pub skipped_count: usize,
    pub fallback_used: bool,
    pub cleanup_failed: bool,
    pub pool_report: Option<net_manager_core::node_pool::NodePoolReport>,
}

fn subscription_profile(
    store: &net_manager_core::profiles::ProfileStore,
    id: &str,
) -> Result<Profile, String> {
    let document = store
        .load()
        .map_err(|_| "failed to load profiles".to_string())?;
    let profile = document
        .profiles
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| "subscription profile not found".to_string())?;
    if profile.backend != TunnelBackend::Xray || profile.subscription.is_none() {
        return Err("profile is not an Xray subscription".into());
    }
    Ok(profile)
}

async fn refresh_subscription_into(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    client: &reqwest::Client,
    id: &str,
) -> Result<SubscriptionRefreshResult, String> {
    refresh_subscription_into_with_ports(vault, store, client, id, loopback_port_available).await
}

async fn refresh_subscription_into_with_ports(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    client: &reqwest::Client,
    id: &str,
    available: impl Fn(u16) -> bool,
) -> Result<SubscriptionRefreshResult, String> {
    let profile = subscription_profile(store, id)?;
    let subscription = profile.subscription.as_ref().unwrap();
    let response = client
        .get(&subscription.url)
        .header("X-HWID", &subscription.hwid)
        .send()
        .await
        .map_err(|_| "subscription refresh fetch failed".to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "subscription refresh returned HTTP {}",
            response.status()
        ));
    }
    let headers = response.headers().clone();
    let body = read_subscription_response(response).await?;
    let meta = net_manager_core::subscription::response_meta_from_headers(&headers, &body);
    if subscription_profile(store, id)? != profile {
        return Err("subscription changed during refresh".into());
    }
    refresh_subscription_body_into_with_metadata(vault, store, id, &body, available, meta)
}

#[cfg(test)]
fn refresh_subscription_body_into(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    id: &str,
    body: &str,
    available: impl Fn(u16) -> bool,
) -> Result<SubscriptionRefreshResult, String> {
    refresh_subscription_body_into_with_metadata(
        vault,
        store,
        id,
        body,
        available,
        SubscriptionResponseMeta::default(),
    )
}

fn refresh_subscription_body_into_with_metadata(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    id: &str,
    body: &str,
    available: impl Fn(u16) -> bool,
    meta: SubscriptionResponseMeta,
) -> Result<SubscriptionRefreshResult, String> {
    subscription_profile(store, id)?;
    let outcome =
        net_manager_core::subscription::refresh_body(vault, store, id, body, meta, available)
            .map_err(|error| error.to_string())?;
    Ok(SubscriptionRefreshResult {
        endpoint_count: outcome.endpoint_count,
        active_index: outcome.active_index,
        skipped_count: outcome.skipped_count,
        fallback_used: outcome.fallback_used,
        cleanup_failed: outcome.cleanup_failed,
        pool_report: None,
    })
}

async fn finish_subscription_refresh(
    state: &AppState,
    id: &str,
    mut result: SubscriptionRefreshResult,
) -> Result<SubscriptionRefreshResult, String> {
    let refreshed = subscription_profile(&state.profiles, id)?;
    match rebuild_pool_report(state, id).await {
        Ok(report) => {
            result.pool_report = report;
            Ok(result)
        }
        Err(_) => {
            let recorded = state.profiles.update_profile(id, |current| {
                if current.subscription != refreshed.subscription {
                    return Err(std::io::Error::other("Subscription changed after refresh"));
                }
                let subscription = current
                    .subscription
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("Profile is no longer a subscription"))?;
                subscription.last_refresh_error = Some(
                    "Subscription refreshed, but the backup pool could not be rebuilt".to_string(),
                );
                Ok(())
            });
            Err(if recorded.is_ok() {
                "Subscription refreshed, but backup-pool rebuild failed; \
                 the previously stored pool was not replaced"
                    .into()
            } else {
                "Subscription refreshed, but backup-pool rebuild failed; \
                 its failure notice could not be saved"
                    .into()
            })
        }
    }
}

fn record_subscription_refresh_failure(
    store: &net_manager_core::profiles::ProfileStore,
    id: &str,
    now: u64,
) -> Result<(), String> {
    subscription_profile(store, id)?;
    net_manager_core::subscription::record_refresh_failure(store, id, now)
        .map_err(|_| "failed to store subscription refresh state".to_string())
}

fn set_subscription_refresh_interval_into(
    store: &net_manager_core::profiles::ProfileStore,
    id: &str,
    interval_minutes: Option<u32>,
    now: u64,
) -> Result<Vec<Profile>, String> {
    validate_refresh_interval(interval_minutes)?;
    subscription_profile(store, id)?;
    let document =
        net_manager_core::subscription::set_refresh_interval(store, id, interval_minutes, now)
            .map_err(|_| "failed to store subscription refresh interval".to_string())?;
    Ok(redact_profiles_for_ipc(document.profiles))
}

/// The profile a role change applies to: static routes create no tunnel.
fn tunnel_profile(
    store: &net_manager_core::profiles::ProfileStore,
    id: &str,
) -> Result<Profile, String> {
    let profile = store
        .load()
        .map_err(|_| "failed to load profiles".to_string())?
        .profiles
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| "profile not found".to_string())?;
    if profile.backend == TunnelBackend::None {
        return Err("Static routes do not create a tunnel".into());
    }
    Ok(profile)
}

fn set_tunnel_role_into(
    store: &net_manager_core::profiles::ProfileStore,
    id: &str,
    role: net_manager_core::models::TunnelRole,
) -> Result<Vec<Profile>, String> {
    let mut profile = tunnel_profile(store, id)?;
    profile.tunnel_role = role;
    let document = store
        .upsert(profile)
        .map_err(|_| "failed to store the connection role".to_string())?;
    Ok(redact_profiles_for_ipc(document.profiles))
}

fn set_tunnel_networks_into(
    store: &net_manager_core::profiles::ProfileStore,
    id: &str,
    networks: &str,
    dns_domains: &str,
) -> Result<Vec<Profile>, String> {
    let mut profile = tunnel_profile(store, id)?;
    profile.tunnel_networks = net_manager_core::models::parse_networks(networks)?;
    profile.tunnel_dns_domains = net_manager_core::models::parse_dns_domains(dns_domains)?;
    let document = store
        .upsert(profile)
        .map_err(|_| "failed to store the connection networks".to_string())?;
    Ok(redact_profiles_for_ipc(document.profiles))
}

/// Primary takes all traffic; secondary only its own networks. A running
/// connection is stopped first so the role applies to a fresh start.
#[tauri::command]
pub(crate) async fn set_tunnel_role(
    id: String,
    role: net_manager_core::models::TunnelRole,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let profile = tunnel_profile(&state.profiles, &id)?;
    ensure_profile_stopped(&state, &profile, "changing the connection role").await?;
    set_tunnel_role_into(&state.profiles, &id, role)
}

/// Networks (CIDR or single addresses) and split-DNS domains of a secondary
/// connection, typed as text; validated here, never trusted by the daemon.
#[tauri::command]
pub(crate) async fn set_tunnel_networks(
    id: String,
    networks: String,
    dns_domains: String,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let profile = tunnel_profile(&state.profiles, &id)?;
    ensure_profile_stopped(&state, &profile, "changing the connection networks").await?;
    set_tunnel_networks_into(&state.profiles, &id, &networks, &dns_domains)
}

#[tauri::command]
pub(crate) async fn set_subscription_refresh_interval(
    profile_id: String,
    refresh_interval_minutes: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    set_subscription_refresh_interval_into(
        &state.profiles,
        &profile_id,
        refresh_interval_minutes,
        unix_now(),
    )
}

#[tauri::command]
pub(crate) async fn refresh_subscription(
    id: String,
    state: State<'_, AppState>,
) -> Result<SubscriptionRefreshResult, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let profile = subscription_profile(&state.profiles, &id)?;
    ensure_profile_stopped(&state, &profile, "refreshing subscription").await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(net_manager_core::subscription::SUBSCRIPTION_USER_AGENT)
        .build()
        .map_err(|_| "failed to build subscription HTTP client".to_string())?;
    let result =
        refresh_subscription_into(&state.config_vault, &state.profiles, &client, &id).await;

    match result {
        Ok(result) => finish_subscription_refresh(state.inner(), &id, result).await,
        Err(error) => {
            if record_subscription_refresh_failure(&state.profiles, &id, unix_now()).is_err() {
                return Err(
                    "Subscription refresh failed, and its failure notice could not be saved".into(),
                );
            }
            Err(error)
        }
    }
}

pub(crate) async fn run_subscription_refresh_loop(app: tauri::AppHandle) {
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(net_manager_core::subscription::SUBSCRIPTION_USER_AGENT)
        .build()
    else {
        return;
    };
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let state = app.state::<AppState>();
        if state
            .shutting_down
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        let Ok(document) = state.profiles.load() else {
            continue;
        };
        for profile in document.profiles {
            if !should_auto_refresh(&profile, unix_now(), false) {
                continue;
            }
            let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
            let Ok(current) = subscription_profile(&state.profiles, &profile.id) else {
                continue;
            };
            if !should_auto_refresh(&current, unix_now(), false) {
                continue;
            }
            let active = ensure_profile_stopped(&state, &current, "refreshing subscription")
                .await
                .is_err();
            if !should_auto_refresh(&current, unix_now(), active) {
                continue;
            }
            let refresh = refresh_subscription_into(
                &state.config_vault,
                &state.profiles,
                &client,
                &current.id,
            )
            .await;

            match refresh {
                Ok(result) => {
                    match finish_subscription_refresh(state.inner(), &current.id, result).await {
                        Ok(result) => {
                            let _ = app.emit("subscription-refreshed", (&current.id, &result));
                        }
                        Err(error) => {
                            let _ = app.emit("subscription-refresh-failed", (&current.id, &error));
                            eprintln!("network-orchestrator: {error}");
                        }
                    }
                }
                Err(_) => {
                    let error = if record_subscription_refresh_failure(
                        &state.profiles,
                        &current.id,
                        unix_now(),
                    )
                    .is_ok()
                    {
                        "Subscription refresh failed"
                    } else {
                        "Subscription refresh failed, and its failure notice could not be saved"
                    };
                    let _ = app.emit("subscription-refresh-failed", (&current.id, error));
                    eprintln!("network-orchestrator: {error}");
                }
            }
            let _ = app.emit("route-changed", ());
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionDelayResult {
    pub delay_ms: Option<u64>,
    pub error: Option<String>,
}

async fn measure_delay_with_process(
    uri: &str,
    command: tokio::process::Command,
    probe_url: &str,
    timeout: std::time::Duration,
) -> Result<u64, String> {
    net_manager_core::subscription::measure_delay_with_command(uri, command, probe_url, timeout)
        .await
}

#[tauri::command]
pub(crate) async fn measure_subscription_endpoint_delay(
    profile_id: String,
    endpoint_index: usize,
    state: State<'_, AppState>,
) -> Result<SubscriptionDelayResult, String> {
    let _profile = subscription_profile(&state.profiles, &profile_id)?;
    let endpoints = state
        .config_vault
        .read_subscription_endpoints(&profile_id)
        .map_err(|_| "failed to read subscription endpoints".to_string())?;
    let endpoint = endpoints
        .get(endpoint_index)
        .ok_or_else(|| "endpoint index out of range".to_string())?;
    let executable = state
        .resolve_backend_executable(TunnelBackend::Xray)
        .map_err(|_| "Xray executable unavailable".to_string())?;
    let mut command = tokio::process::Command::new(executable.path);
    command.args(["run", "-config", "stdin:"]);
    Ok(
        match measure_delay_with_process(
            &endpoint.url,
            command,
            DELAY_PROBE_URL,
            DELAY_PROBE_TIMEOUT,
        )
        .await
        {
            Ok(delay_ms) => SubscriptionDelayResult {
                delay_ms: Some(delay_ms),
                error: None,
            },
            Err(error) => SubscriptionDelayResult {
                delay_ms: None,
                error: Some(error),
            },
        },
    )
}

#[tauri::command]
pub(crate) async fn get_subscription_endpoints(
    profile_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SubscriptionEndpointInfo>, String> {
    let _profile = find_profile(&state.profiles, &profile_id)?;
    net_manager_core::subscription::list_endpoints(
        &state.config_vault,
        &state.profiles,
        &profile_id,
    )
    .map_err(|e| e.to_string())
}

/// Node key of the new primary (16 hex chars, never the share-link URL).
#[tauri::command]
pub(crate) async fn switch_subscription_endpoint(
    profile_id: String,
    endpoint_key: String,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let profile = find_profile(&state.profiles, &profile_id)?;
    ensure_profile_stopped(&state, &profile, "switching endpoint").await?;
    switch_subscription_endpoint_into(
        &state.config_vault,
        &state.profiles,
        &profile_id,
        &endpoint_key,
        loopback_port_available,
    )
}

fn switch_subscription_endpoint_into(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    profile_id: &str,
    endpoint_key: &str,
    available: impl Fn(u16) -> bool,
) -> Result<Vec<Profile>, String> {
    let doc = net_manager_core::subscription::switch_endpoint_key(
        vault,
        store,
        profile_id,
        endpoint_key,
        available,
    )
    .map_err(|e| e.to_string())?;
    Ok(redact_profiles_for_ipc(doc.profiles))
}

/// Ordered backup nodes tried after the primary fails its HTTPS probes.
/// Keys are kept even when a node left the subscription (it may reappear).
#[tauri::command]
pub(crate) async fn set_subscription_backups(
    profile_id: String,
    backup_keys: Vec<String>,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let profile = subscription_profile(&state.profiles, &profile_id)?;
    if profile.backend != TunnelBackend::Xray {
        return Err("failover backups need an Xray subscription".into());
    }
    let doc = net_manager_core::subscription::set_backup_endpoints(
        &state.config_vault,
        &state.profiles,
        &profile_id,
        &backup_keys,
    )
    .map_err(|e| e.to_string())?;
    Ok(redact_profiles_for_ipc(doc.profiles))
}

/// Probe the primary over HTTPS while a backup carries traffic and switch
/// back when it answers again. Enabled unless explicitly turned off.
#[tauri::command]
pub(crate) async fn set_subscription_auto_return(
    profile_id: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    subscription_profile(&state.profiles, &profile_id)?;
    let doc = net_manager_core::subscription::set_auto_return_primary(
        &state.profiles,
        &profile_id,
        enabled,
    )
    .map_err(|e| e.to_string())?;
    Ok(redact_profiles_for_ipc(doc.profiles))
}

/// Domain selectors pinned to one node: while that node is down or gone the
/// selectors are blocked, never sent direct or through another node.
#[tauri::command]
pub(crate) async fn set_pinned_routes(
    profile_id: String,
    routes: Vec<PinnedRoute>,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let profile = subscription_profile(&state.profiles, &profile_id)?;
    if profile.backend != TunnelBackend::Xray {
        return Err("node-pinned rules need an Xray subscription".into());
    }
    let doc = net_manager_core::subscription::set_pinned_routes(
        &state.config_vault,
        &state.profiles,
        &profile_id,
        routes,
    )
    .map_err(|e| e.to_string())?;
    Ok(redact_profiles_for_ipc(doc.profiles))
}

/// The opt-in filtered pool: filters plus the country-proof flag; `None`
/// turns the pool off and forgets its members. Members themselves come only
/// from `rebuild_subscription_node_pool` — verified, never hand-picked.
#[tauri::command]
pub(crate) async fn set_subscription_node_pool(
    profile_id: String,
    pool: Option<NodePoolSettings>,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let profile = subscription_profile(&state.profiles, &profile_id)?;
    if profile.backend != TunnelBackend::Xray {
        return Err("the backup pool needs an Xray subscription".into());
    }
    let doc = net_manager_core::node_pool::set_node_pool(&state.profiles, &profile_id, pool)
        .map_err(|e| e.to_string())?;
    Ok(redact_profiles_for_ipc(doc.profiles))
}

/// Probe every filter candidate through a temporary Xray and keep the
/// members whose real exit country passes. The report lists per-candidate
/// verdicts — including wrong-country rejections — and whether the previous
/// pool stayed because nothing usable answered.
async fn rebuild_pool_report(
    state: &AppState,
    profile_id: &str,
) -> Result<Option<net_manager_core::node_pool::NodePoolReport>, String> {
    let profile = subscription_profile(&state.profiles, profile_id)?;
    if profile
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.node_pool.as_ref())
        .is_none()
    {
        return Ok(None);
    }

    let verify = profile
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.node_pool.as_ref())
        .is_some_and(|pool| pool.verify_exit_country);
    let executable = verify
        .then(|| {
            state
                .resolve_backend_executable(TunnelBackend::Xray)
                .map(|resolved| resolved.path)
                .map_err(|_| "Xray executable unavailable".to_string())
        })
        .transpose()?;

    net_manager_core::node_pool::rebuild_node_pool(
        &state.config_vault,
        &state.profiles,
        profile_id,
        &net_manager_core::node_pool::EXIT_COUNTRY_PROBES,
        net_manager_core::node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
        move |_| {
            executable
                .as_ref()
                .ok_or_else(|| std::io::Error::other("Xray executable unavailable"))
                .map(tokio::process::Command::new)
        },
    )
    .await
    .map(Some)
    .map_err(|_| {
        "Backup-pool rebuild failed; the previously stored pool was not replaced".to_string()
    })
}

#[tauri::command]
pub(crate) async fn rebuild_subscription_node_pool(
    profile_id: String,
    state: State<'_, AppState>,
) -> Result<net_manager_core::node_pool::NodePoolReport, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    rebuild_pool_report(state.inner(), &profile_id)
        .await?
        .ok_or_else(|| "Set backup-pool filters before rebuilding the pool".to_string())
}

/// One failover candidate's real exit: where it answers from, what its name
/// claims (flag emoji), and whether the two disagree.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionExitCheck {
    pub key: String,
    pub name: String,
    pub role: String,
    pub named_country: Option<String>,
    pub exit_country: Option<String>,
    pub exit_ip: Option<String>,
    pub mismatch: bool,
    pub error: Option<String>,
}

/// The country a flag emoji names (🇷🇺 → RU), or `None` — a display hint
/// compared against the probed exit, never trusted as one.
fn flag_country(name: &str) -> Option<String> {
    let mut code = String::new();
    for ch in name.chars() {
        let value = ch as u32;
        if (0x1F1E6..=0x1F1FF).contains(&value) {
            code.push(char::from_u32(value - 0x1F1E6 + 'A' as u32)?);
        }
    }
    (code.len() == 2).then_some(code)
}

/// Real exit-country verification of the failover chain — primary, manual
/// backups and pool members — each probed through its own temporary Xray.
/// A node name is not an exit; mismatches are reported, not hidden.
#[tauri::command]
pub(crate) async fn verify_subscription_exits(
    profile_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SubscriptionExitCheck>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let profile = subscription_profile(&state.profiles, &profile_id)?;
    let (nodes, _) = net_manager_core::subscription::failover_plan(&state.config_vault, &profile)
        .map_err(|_| "The failover endpoints could not be resolved".to_string())?;
    if nodes.is_empty() {
        return Err("The profile has no failover candidates".into());
    }
    let expected_nodes = nodes.clone();

    let executable = state
        .resolve_backend_executable(TunnelBackend::Xray)
        .map_err(|_| "Xray executable unavailable".to_string())?
        .path;
    let infos = net_manager_core::subscription::list_endpoints(
        &state.config_vault,
        &state.profiles,
        &profile_id,
    )
    .map_err(|_| "The subscription endpoint list could not be read".to_string())?;
    let roles = infos
        .iter()
        .map(|info| {
            let role = if info.active {
                "primary"
            } else if info.is_backup {
                "backup"
            } else if info.in_pool {
                "pool"
            } else {
                "node"
            };
            (info.key.as_str(), role)
        })
        .collect::<HashMap<_, _>>();

    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(
        net_manager_core::node_pool::POOL_PROBE_PARALLELISM,
    ));
    let mut tasks = tokio::task::JoinSet::new();
    for (index, endpoint) in nodes.into_iter().enumerate() {
        let gate = gate.clone();
        let executable = executable.clone();
        tasks.spawn(async move {
            let _permit = gate
                .acquire_owned()
                .await
                .map_err(|_| "Exit verification was cancelled".to_string())?;
            let key = net_manager_core::subscription::endpoint_key(&endpoint.url);
            let mut command = tokio::process::Command::new(&executable);
            command.args(["run", "-config", "stdin:"]);
            let outcome = net_manager_core::node_pool::measure_exit_country(
                &endpoint.url,
                command,
                &net_manager_core::node_pool::EXIT_COUNTRY_PROBES,
                net_manager_core::node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
            )
            .await;
            Ok::<_, String>((index, key, endpoint.name, outcome))
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(result)) => results.push(result),
            Ok(Err(error)) => {
                tasks.abort_all();
                return Err(error);
            }
            Err(_) => {
                tasks.abort_all();
                return Err("An exit-verification worker failed".into());
            }
        }
    }
    results.sort_by_key(|(index, _, _, _)| *index);

    if subscription_profile(&state.profiles, &profile_id)? != profile {
        return Err("The profile changed during verification; verify again".into());
    }
    let (current_nodes, _) =
        net_manager_core::subscription::failover_plan(&state.config_vault, &profile)
            .map_err(|_| "The current failover endpoints could not be read".to_string())?;
    if current_nodes != expected_nodes {
        return Err("The subscription endpoints changed during verification; verify again".into());
    }

    Ok(results
        .into_iter()
        .map(|(_, key, name, outcome)| {
            let role = roles.get(key.as_str()).copied().unwrap_or("node");
            let named_country = flag_country(&name);
            let (exit_country, exit_ip, error) = match outcome {
                Ok(exit) => (Some(exit.country), Some(exit.ip), None),
                Err(_) => (
                    None,
                    None,
                    Some("Exit-country verification failed".to_string()),
                ),
            };
            let mismatch =
                named_country.is_some() && exit_country.is_some() && named_country != exit_country;

            SubscriptionExitCheck {
                key,
                name: name.trim().to_string(),
                role: role.to_string(),
                named_country,
                exit_country,
                exit_ip,
                mismatch,
                error,
            }
        })
        .collect())
}

/// What a policy migration would set, in client-safe form: counts,
/// selectors and sanitized reasons — never the source's outbounds or links.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct XrayPolicyPreview {
    pub direct: usize,
    pub proxy: usize,
    pub block: usize,
    pub pinned_count: usize,
    pub private_lan_direct: bool,
    pub quic_reject: bool,
    pub domain_strategy: Option<XrayDomainStrategy>,
    pub domain_matcher: Option<XrayDomainMatcher>,
    pub endpoint_bypass_count: usize,
    pub has_geoip_override: bool,
    pub has_geosite_override: bool,
    pub has_dns: bool,
    pub has_sockopts: bool,
    pub traffic_rule_count: usize,
    pub interface_route_count: usize,
    pub dns_server_count: usize,
    pub dns_host_count: usize,
    pub dns_rewrite_rule_count: usize,
    pub tun_dns_server_count: usize,
    pub tun_mtu: Option<u32>,
    pub connection_idle_secs: Option<u32>,
    pub direct_domain_strategy: Option<String>,
    pub dns_enable_parallel_query: Option<bool>,
    pub has_dns_outbound: bool,
    pub backup_count: Option<usize>,
    pub skipped: Vec<String>,
    pub refused: Vec<String>,
}

fn preview_of(
    migration: &net_manager_core::xray_migrate::XrayPolicyMigration,
) -> XrayPolicyPreview {
    let count = |target| {
        migration
            .domain_policies
            .iter()
            .filter(|policy| policy.target == target)
            .map(|policy| policy.domains.len())
            .sum::<usize>()
    };
    XrayPolicyPreview {
        direct: count(DomainRouteTarget::Direct),
        proxy: count(DomainRouteTarget::Proxy),
        block: count(DomainRouteTarget::Block),
        pinned_count: migration.pinned_routes.len(),
        private_lan_direct: migration.private_lan_direct,
        quic_reject: migration.quic_reject,
        domain_strategy: migration.domain_strategy,
        domain_matcher: migration.domain_matcher,
        endpoint_bypass_count: migration.endpoint_bypasses.len(),
        has_geoip_override: migration.geoip_url.is_some(),
        has_geosite_override: migration.geosite_url.is_some(),
        has_dns: !migration.dns.is_empty(),
        has_sockopts: migration.sockopts.is_some(),
        traffic_rule_count: migration.traffic_rules.len(),
        interface_route_count: migration.interface_routes.len(),
        dns_server_count: migration.dns.servers.len(),
        dns_host_count: migration.dns.hosts.len(),
        dns_rewrite_rule_count: migration
            .dns
            .outbound
            .as_ref()
            .map_or(0, |outbound| outbound.rules.len()),
        tun_dns_server_count: migration.tun_dns_servers.len(),
        tun_mtu: migration.tun_mtu,
        connection_idle_secs: migration.connection_idle_secs,
        direct_domain_strategy: migration.direct_domain_strategy.clone(),
        dns_enable_parallel_query: migration.dns.enable_parallel_query,
        has_dns_outbound: migration.dns.outbound.is_some(),
        backup_count: migration.backup_keys.as_ref().map(Vec::len),
        skipped: migration
            .skipped
            .iter()
            .map(|item| item.reason.clone())
            .collect(),
        refused: migration
            .refused
            .iter()
            .map(|item| item.reason.clone())
            .collect(),
    }
}

fn plan_migration(
    state: &AppState,
    profile: &Profile,
    path: &Path,
) -> Result<
    (
        net_manager_core::xray_migrate::XrayPolicyMigration,
        Vec<net_manager_core::config_vault::SubscriptionEndpoint>,
    ),
    String,
> {
    use std::io::Read;
    const LIMIT: u64 = 512 * 1024;
    let mut body = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(LIMIT + 1).read_to_end(&mut body))
        .map_err(|_| "The selected Xray policy file could not be read".to_string())?;
    if body.len() as u64 > LIMIT {
        return Err("The selected Xray policy exceeds 512 KiB".into());
    }
    let source: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| "The selected file is not a JSON Xray configuration".to_string())?;

    let endpoints = if profile.subscription.is_some() {
        state
            .config_vault
            .read_subscription_endpoints(&profile.id)
            .map_err(|_| "The subscription endpoint vault could not be read".to_string())?
    } else {
        Vec::new()
    };

    let primary = profile.subscription.as_ref().and_then(|subscription| {
        subscription.active_key.clone().or_else(|| {
            endpoints
                .get(subscription.active_index)
                .map(|endpoint| net_manager_core::subscription::endpoint_key(&endpoint.url))
        })
    });

    let migration = net_manager_core::xray_migrate::plan_xray_policy_migration(
        &source,
        primary.as_deref(),
        net_manager_core::xray_migrate::subscription_outbound_resolver(
            &endpoints,
            primary.as_deref(),
        ),
    )
    .map_err(|_| "The selected Xray policy could not be planned".to_string())?;

    Ok((migration, endpoints))
}

/// What the file at `path` would change on the profile — and which rules it
/// refuses to fake. Nothing is saved.
#[tauri::command]
pub(crate) async fn preview_xray_policy_migration(
    profile_id: String,
    path: String,
    state: State<'_, AppState>,
) -> Result<XrayPolicyPreview, String> {
    let profile = find_profile(&state.profiles, &profile_id)?;
    if profile.backend != TunnelBackend::Xray {
        return Err("policy migration targets Xray profiles".into());
    }
    let (migration, _) = plan_migration(&state, &profile, Path::new(&path))?;
    Ok(preview_of(&migration))
}

/// Adopt the file's policy on the profile. Refused rules block the whole
/// apply — nothing is half-imported and reported as success.
#[tauri::command]
pub(crate) async fn apply_xray_policy_migration(
    profile_id: String,
    path: String,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let _guard = SUBSCRIPTION_REFRESH_LOCK.lock().await;
    let expected = find_profile(&state.profiles, &profile_id)?;
    if expected.backend != TunnelBackend::Xray {
        return Err("Policy migration requires an Xray profile".into());
    }

    ensure_profile_stopped(&state, &expected, "migrating routing policy").await?;

    let (migration, expected_endpoints) = plan_migration(&state, &expected, Path::new(&path))?;
    if !migration.refused.is_empty() {
        return Err(format!(
            "Policy migration refused {} source construct(s); \
             preview the refusal categories. Nothing was changed.",
            migration.refused.len(),
        ));
    }

    let document = state
        .profiles
        .update_profile(&profile_id, |current| {
            if current != &expected {
                return Err(std::io::Error::other("Profile changed during migration"));
            }

            if expected.subscription.is_some() {
                let endpoints = state
                    .config_vault
                    .read_subscription_endpoints(&profile_id)
                    .map_err(|_| std::io::Error::other("Endpoint vault could not be read"))?;
                if endpoints != expected_endpoints {
                    return Err(std::io::Error::other(
                        "Subscription changed during migration",
                    ));
                }
            }

            net_manager_core::xray_migrate::apply_xray_policy_migration(current, migration)
                .map_err(|_| std::io::Error::other("Policy could not be applied"))?;

            if current.subscription.is_some() {
                let live = expected_endpoints
                    .iter()
                    .map(|endpoint| net_manager_core::subscription::endpoint_key(&endpoint.url))
                    .collect::<HashSet<_>>();
                for pin in &mut current.pinned_policies {
                    pin.missing = !live.contains(&pin.endpoint_key);
                }
            }
            Ok(())
        })
        .map_err(|_| {
            "Policy migration was not saved. The profile or endpoint selection may \
             have changed, the policy may conflict with existing pins, or the store \
             may be unwritable. Preview again before retrying."
                .to_string()
        })?;

    Ok(redact_profiles_for_ipc(document.profiles))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use base64::Engine;
    use std::fs;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_wireguard_edit_and_delete_guards_use_daemon_status() {
        use net_manager_core::daemon_protocol::{method, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = unique_dir("wg-mutation-guard");
        let path = dir.join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            for state in ["running", "running", "stopped"] {
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
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(request.method, method::WIREGUARD_STATUS);
                assert_eq!(request.params["profileId"], "p1");
                writer
                    .write_all(
                        &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                            request.id,
                            json!({"profileId":"p1","state":state,"interfaceName":null,"latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[]}),
                        ))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        });
        let client = crate::daemon_client::DaemonClient::new(path);
        let profile = profile("wg-p1");
        assert!(ensure_linux_wireguard_stopped(&client, &profile, "editing")
            .await
            .unwrap_err()
            .contains("disconnect before editing"));
        assert!(
            ensure_linux_wireguard_stopped(&client, &profile, "deleting")
                .await
                .unwrap_err()
                .contains("disconnect before deleting")
        );
        ensure_linux_wireguard_stopped(&client, &profile, "editing")
            .await
            .unwrap();
        server.await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_openvpn_edit_guard_uses_daemon_status() {
        use net_manager_core::daemon_protocol::{method, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = unique_dir("ovpn-mutation-guard");
        let path = dir.join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
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
                &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(request.method, method::OPENVPN_STATUS);
            writer.write_all(&net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(request.id, json!({"profileId":"p1","state":"reconnecting","interfaceName":"tun0","rxBytes":0,"txBytes":0,"appliedRoutes":[],"warnings":[]}))).unwrap()).await.unwrap();
        });
        let client = crate::daemon_client::DaemonClient::new(path);
        let mut profile = profile("tun0");
        profile.backend = TunnelBackend::OpenVpn;
        let error = ensure_linux_openvpn_stopped(&client, &profile, "editing")
            .await
            .unwrap_err();
        assert!(error.contains("disconnect before editing"), "{error}");
        server.await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_xray_tun_edit_guard_uses_daemon_status_after_restart() {
        use net_manager_core::daemon_protocol::{method, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;
        let dir = unique_dir("xray-tun-mutation-guard");
        let path = dir.join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
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
                &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(request.method, method::XRAY_STATUS);
            writer.write_all(&net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(request.id, json!({"profileId":"p1","state":"running","interfaceName":"xray-test","dnsApplied":true,"ipv4Covered":true,"ipv6Covered":false}))).unwrap()).await.unwrap();
        });
        let client = crate::daemon_client::DaemonClient::new(path);
        let mut p = profile("xray");
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        let err = ensure_linux_xray_stopped(&client, &p, "editing")
            .await
            .unwrap_err();
        assert!(err.contains("disconnect before editing"));
        assert!(!err.contains(&p.id));
        server.await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn validate_managed_save_path_rejects_foreign_and_backend_swap() {
        let dir = unique_dir("managed-save");
        let vault = ConfigVault::new(dir.join("configs"));
        let source = dir.join("src.conf");
        fs::write(&source, b"[Interface]\n").unwrap();
        let import = vault
            .import("owner", TunnelBackend::WireGuard, &source)
            .unwrap();

        let mut incoming = profile("wg");
        incoming.id = "owner".into();
        incoming.config_path = import.config_path.clone();
        let stored = incoming.clone();

        assert!(
            validate_managed_save_path(&vault, Some(&stored), &incoming).is_ok(),
            "same profile, same backend, own managed path"
        );

        let mut foreign = incoming.clone();
        foreign.id = "other".into();
        let err = validate_managed_save_path(&vault, None, &foreign).unwrap_err();
        assert!(err.contains("different profile"), "{err}");

        let mut swapped = incoming.clone();
        swapped.backend = TunnelBackend::OpenVpn;
        let err = validate_managed_save_path(&vault, Some(&stored), &swapped).unwrap_err();
        assert!(err.contains("new source config"), "{err}");

        let mut external = profile("ext");
        external.config_path = dir.join("external.conf");
        assert!(validate_managed_save_path(&vault, None, &external).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn store_generated_xray_writes_platform_appropriate_revision() {
        let dir = unique_dir("gen-xray");
        let vault = ConfigVault::new(dir.join("configs"));
        let body = br#"{"inbounds":[]}"#.to_vec();
        let import = store_generated_xray(&vault, "node-auto", &body).unwrap();
        #[cfg(windows)]
        {
            assert_eq!(import.config_path.file_name().unwrap(), "config.json.dpapi");
            let plain = net_manager_core::config_security::read_xray_config(
                &import.config_path,
                "node-auto",
            )
            .unwrap();
            assert_eq!(plain, body);
            assert_ne!(fs::read(&import.config_path).unwrap(), body);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(import.config_path.file_name().unwrap(), "config.json");
            assert_eq!(fs::read(&import.config_path).unwrap(), body);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vless_generation_errors_do_not_leak_uri() {
        let sentinel = "SENTINEL-UUID-7777";
        let err = net_manager_core::xray::generate_vless_config(
            &format!("vless://{sentinel}@:443?security=tls&sni=x"),
            10808,
        )
        .unwrap_err();
        assert!(!err.to_string().contains(sentinel));
        assert!(net_manager_core::xray::generate_vless_config(
            "vless://id@node.test:443?security=tls&sni=x",
            0,
        )
        .is_err());
    }

    #[test]
    fn select_available_socks_port_skips_used_and_unavailable() {
        let used: HashSet<u16> = [10808, 10809].into_iter().collect();
        let port = select_available_socks_port(&used, |p| p != 10810).unwrap();
        assert_eq!(port, 10811);
        assert_eq!(
            select_available_socks_port(&HashSet::new(), |_| true).unwrap(),
            10808
        );
    }

    #[test]
    fn select_available_socks_port_errors_when_exhausted() {
        let err = select_available_socks_port(&HashSet::new(), |_| false).unwrap_err();
        assert!(err.contains("10808"), "{err}");
    }

    #[test]
    fn generated_ports_skip_used_unavailable_and_duplicate_ports() {
        let used: HashSet<u16> = [10808, 10810].into_iter().collect();
        let ports = select_generated_ports(None, None, &used, |port| port != 10809).unwrap();
        assert_eq!(ports, (10811, 10812));
        assert!(select_generated_ports(Some(10808), None, &used, |_| true).is_err());
        assert_eq!(
            select_generated_ports(Some(10811), Some(10811), &used, |_| true).unwrap(),
            (10811, 10809)
        );
    }

    #[test]
    fn profile_listener_ports_collects_metadata_and_loopback_listeners() {
        let dir = unique_dir("listener-ports");
        let cfg = dir.join("other.json");
        fs::write(
            &cfg,
            r#"{"inbounds":[
                {"tag":"a","listen":"0.0.0.0","port":2080,"protocol":"socks"},
                {"tag":"b","listen":"192.168.1.5","port":2090,"protocol":"socks"}
            ]}"#,
        )
        .unwrap();
        let mut other = profile("x-other");
        other.id = "other".into();
        other.backend = TunnelBackend::Xray;
        other.config_path = cfg;
        other.xray_socks_port = Some(10809);
        let mut me = profile("x-me");
        me.id = "me".into();
        me.xray_socks_port = Some(10810);

        let used = profile_listener_ports(&[other, me], "me");
        assert!(used.contains(&10809));
        assert!(used.contains(&2080));
        assert!(!used.contains(&2090));
        assert!(!used.contains(&10810));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rewrite_generated_proxy_ports_creates_revision_and_rejects_ineligible() {
        let dir = unique_dir("rewrite-socks");
        let vault = ConfigVault::new(dir.join("configs"));
        let mut p = profile("x-gen");
        p.id = "gen".into();
        p.backend = TunnelBackend::Xray;
        p.xray_socks_port = Some(10808);
        p.xray_http_port = Some(10951);
        let body = br#"{"inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":10808,"protocol":"socks"},{"tag":"http-in","listen":"127.0.0.1","port":10951,"protocol":"http"}]}"#;
        let import = vault.store_xray_config("gen", body).unwrap();
        p.config_path = import.config_path.clone();

        assert!(rewrite_generated_proxy_ports(&vault, &mut p, 10951, Some(10951)).is_err());

        let new_path = rewrite_generated_proxy_ports(&vault, &mut p, 10808, Some(10950)).unwrap();
        assert_ne!(new_path, import.config_path);
        assert_eq!(p.config_path, new_path);
        assert_eq!(p.xray_socks_port, Some(10808));
        assert_eq!(p.xray_http_port, Some(10950));
        assert!(import.config_path.exists());
        let raw = config_security::read_xray_config(&new_path, "gen").unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(doc["inbounds"][0]["port"], 10808);
        assert_eq!(doc["inbounds"][0]["tag"], "socks-in");
        assert_eq!(doc["inbounds"][1]["port"], 10950);

        let mut bad = p.clone();
        #[cfg(windows)]
        let broken =
            config_security::protect_user_data(b"{oops", &config_security::xray_context("gen"))
                .unwrap();
        #[cfg(not(windows))]
        let broken = b"{oops".to_vec();
        fs::write(&new_path, &broken).unwrap();
        assert!(rewrite_generated_proxy_ports(&vault, &mut bad, 10960, Some(10950)).is_err());
        assert_eq!(bad.config_path, new_path);
        assert_eq!(bad.xray_socks_port, Some(10808));

        let mut ext = profile("x-ext");
        ext.backend = TunnelBackend::Xray;
        ext.xray_socks_port = Some(10808);
        let before = ext.config_path.clone();
        assert!(rewrite_generated_proxy_ports(&vault, &mut ext, 10960, None).is_err());
        assert_eq!(ext.config_path, before);
        assert_eq!(ext.xray_socks_port, Some(10808));

        let mut no_port = ext.clone();
        no_port.xray_socks_port = None;
        assert!(rewrite_generated_proxy_ports(&vault, &mut no_port, 10960, None).is_err());
        assert!(no_port.xray_socks_port.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detect_backend_uses_extension_for_unambiguous_cases() {
        let dir = unique_dir("detect-ext");
        let wg = dir.join("t.conf");
        fs::write(&wg, b"[Interface]\nPrivateKey=x\n").unwrap();
        let ovpn = dir.join("c.ovpn");
        fs::write(&ovpn, b"client\ndev tun\n").unwrap();
        let xray = dir.join("n.json");
        fs::write(&xray, b"{}").unwrap();
        let dpapi = dir.join("t.conf.dpapi");
        fs::write(&dpapi, b"bytes").unwrap();

        assert_eq!(detect_backend(&wg, None), Some(TunnelBackend::WireGuard));
        assert_eq!(detect_backend(&ovpn, None), Some(TunnelBackend::OpenVpn));
        assert_eq!(detect_backend(&xray, None), Some(TunnelBackend::Xray));
        assert_eq!(detect_backend(&dpapi, None), Some(TunnelBackend::WireGuard));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detect_backend_sniffs_conf_content_to_distinguish_wireguard_and_openvpn() {
        let dir = unique_dir("detect-sniff");
        let wg = dir.join("wg.conf");
        fs::write(
            &wg,
            b"[Interface]\nPrivateKey=AAAA\n[Peer]\nPublicKey=BBBB\n",
        )
        .unwrap();
        let ovpn = dir.join("client.conf");
        fs::write(&ovpn, b"client\ndev tun\nproto udp\nremote host 443\n").unwrap();
        let ovpn_remote = dir.join("r.conf");
        fs::write(&ovpn_remote, b"remote example.com 1194\n").unwrap();

        assert_eq!(detect_backend(&wg, None), Some(TunnelBackend::WireGuard));
        assert_eq!(detect_backend(&ovpn, None), Some(TunnelBackend::OpenVpn));
        assert_eq!(
            detect_backend(&ovpn_remote, None),
            Some(TunnelBackend::OpenVpn)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detect_backend_falls_back_to_default_for_ambiguous_conf() {
        let dir = unique_dir("detect-fallback");
        let unknown = dir.join("x.conf");
        fs::write(&unknown, b"# no recognizable directives\n").unwrap();

        assert_eq!(detect_backend(&unknown, None), None);
        assert_eq!(
            detect_backend(&unknown, Some(TunnelBackend::OpenVpn)),
            Some(TunnelBackend::OpenVpn)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detect_backend_returns_none_for_unrecognized_extension_without_default() {
        let dir = unique_dir("detect-none");
        let txt = dir.join("notes.txt");
        fs::write(&txt, b"hello").unwrap();
        assert_eq!(detect_backend(&txt, None), None);
        assert_eq!(
            detect_backend(&txt, Some(TunnelBackend::WireGuard)),
            Some(TunnelBackend::WireGuard)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_configs_into_creates_profiles_and_collects_errors() {
        let dir = unique_dir("batch-import");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));

        let wg = dir.join("work.conf");
        fs::write(
            &wg,
            b"[Interface]\nPrivateKey=AAAA\n[Peer]\nPublicKey=BBBB\n",
        )
        .unwrap();
        let ovpn = dir.join("client.ovpn");
        fs::write(&ovpn, b"client\ndev tun\nproto udp\nremote host 443\n").unwrap();
        let xray = dir.join("node.json");
        fs::write(&xray, br#"{"outbounds":[]}"#).unwrap();
        let bad = dir.join("missing.conf");

        let paths = vec![
            wg.to_string_lossy().to_string(),
            ovpn.to_string_lossy().to_string(),
            xray.to_string_lossy().to_string(),
            bad.to_string_lossy().to_string(),
        ];
        let result = import_configs_into(&vault, &store, &paths, None).unwrap();

        assert_eq!(result.profiles.len(), 3);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].path, bad.to_string_lossy());
        let backends: Vec<_> = result
            .profiles
            .iter()
            .map(|p| (p.name.as_str(), p.backend))
            .collect();
        assert!(backends.contains(&("work", TunnelBackend::WireGuard)));
        assert!(backends.contains(&("client", TunnelBackend::OpenVpn)));
        assert!(backends.contains(&("node", TunnelBackend::Xray)));
        let xray_profile = result
            .profiles
            .iter()
            .find(|p| p.backend == TunnelBackend::Xray)
            .unwrap();
        assert!(xray_profile.xray_http_port.is_none());
        assert_eq!(
            fs::read(&xray_profile.config_path).unwrap(),
            br#"{"outbounds":[]}"#
        );
        for p in &result.profiles {
            assert!(p.id.starts_with("import-"));
            assert!(p.config_path.starts_with(vault.root()));
            assert!(p.routes.is_empty());
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_configs_into_preserves_openvpn_static_routes() {
        let dir = unique_dir("batch-ovpn-routes");
        fs::remove_dir_all(&dir).unwrap();
        fs::create_dir_all(&dir).unwrap();
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let source = dir.join("client.ovpn");
        fs::write(
            &source,
            "client\nremote vpn.example\nroute 10.20.0.0 255.255.0.0\nroute-ipv6 fd00:1::/64\n",
        )
        .unwrap();
        let result = import_configs_into(
            &vault,
            &store,
            &[source.to_string_lossy().to_string()],
            None,
        )
        .unwrap();
        assert!(result.errors.is_empty());
        assert_eq!(result.profiles[0].routes.len(), 2);
        assert_eq!(
            result.profiles[0].routes[0].destination.to_string(),
            "10.20.0.0/16"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_configs_into_reports_unknown_extension_without_default() {
        let dir = unique_dir("batch-unknown");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let txt = dir.join("readme.txt");
        fs::write(&txt, b"hello").unwrap();

        let result =
            import_configs_into(&vault, &store, &[txt.to_string_lossy().to_string()], None)
                .unwrap();
        assert!(result.profiles.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].error.contains("default backend"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_subscription_body_decodes_base64_vless_urls() {
        let raw = "vless://uuid@host:443?encryption=none\ntrojan://other@host2:443\nvless://uuid2@host3:8443?encryption=none";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let (urls, skipped) = parse_subscription_body(&encoded);
        assert_eq!(urls.len(), 2);
        assert_eq!(skipped, ["trojan"]);
        assert!(urls[0].starts_with("vless://uuid@host"));
        assert!(urls[1].starts_with("vless://uuid2@host3"));
    }

    #[test]
    fn parse_subscription_body_accepts_plain_text() {
        let raw = "vless://uuid@host:443?encryption=none\nnot-a-url\nvless://uuid2@host2:443";
        let (urls, skipped) = parse_subscription_body(raw);
        assert_eq!(urls.len(), 2);
        assert_eq!(skipped.len(), 1);
        assert!(urls[0].starts_with("vless://uuid@host"));
        assert!(urls[1].starts_with("vless://uuid2@host2"));
    }

    #[test]
    fn parse_subscription_body_returns_empty_for_no_vless() {
        let raw = "trojan://other@host:443\nss://something@host:443";
        let (urls, skipped) = parse_subscription_body(raw);
        assert!(urls.is_empty());
        assert_eq!(skipped, ["trojan", "ss"]);
    }

    #[test]
    fn parse_subscription_body_handles_whitespace_and_padding() {
        let raw = "vless://uuid@host:443?encryption=none";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let with_whitespace = format!("  \n{}\n  ", encoded);
        let (urls, skipped) = parse_subscription_body(&with_whitespace);
        assert_eq!(urls.len(), 1);
        assert!(skipped.is_empty());
        assert!(urls[0].starts_with("vless://uuid@host"));
    }

    #[test]
    fn parse_subscription_body_accepts_both_hysteria2_schemes() {
        let raw = "vless://id@one.test:443\nhysteria2://pass@two.test:443\nhy2://pass@three.test:443\ntrojan://private@other.test:443";
        let (urls, skipped) = parse_subscription_body(raw);
        assert_eq!(urls.len(), 3);
        assert_eq!(skipped.len(), 1);
        assert!(urls[1].starts_with("hysteria2://"));
        assert!(urls[2].starts_with("hy2://"));
    }

    #[test]
    fn subscription_userinfo_parses_bounded_usage_and_optional_expiry() {
        let parsed = net_manager_core::subscription::parse_subscription_userinfo(
            "upload=1024; download=2048; total=4096; expire=1798761600",
        )
        .unwrap();
        assert_eq!(parsed.upload_bytes, 1024);
        assert_eq!(parsed.download_bytes, 2048);
        assert_eq!(parsed.total_bytes, Some(4096));
        assert_eq!(parsed.expires_at_unix, Some(1798761600));
        let unlimited = net_manager_core::subscription::parse_subscription_userinfo(
            "upload=0; download=42; total=0; expire=0",
        )
        .unwrap();
        assert_eq!(unlimited.total_bytes, None);
        assert_eq!(unlimited.expires_at_unix, None);
        assert!(net_manager_core::subscription::parse_subscription_userinfo(
            "upload=private-secret; download=3"
        )
        .is_none());
        assert!(
            net_manager_core::subscription::parse_subscription_userinfo(&"x".repeat(513)).is_none()
        );
    }

    #[test]
    fn chosen_refresh_interval_controls_due_time_and_rejects_other_values() {
        assert!(validate_refresh_interval(None).is_ok());
        for minutes in [15, 60, 360] {
            assert!(validate_refresh_interval(Some(minutes)).is_ok());
        }
        for minutes in [0, 1, 14, 361] {
            assert!(validate_refresh_interval(Some(minutes)).is_err());
        }
        let mut meta = SubscriptionMeta {
            url: "https://example.test/private-token".into(),
            hwid: "private-hwid".into(),
            endpoint_count: 1,
            active_index: 0,
            refresh_interval_minutes: Some(15),
            last_refresh_at_unix: Some(1000),
            last_refresh_error: None,
            user_info: None,
            provider_title: None,
            announce: None,
            support_url: None,
            web_page_url: None,
            update_interval_hours: None,
            skipped_protocols: Vec::new(),
            active_key: None,
            backup_keys: Vec::new(),
            auto_return_primary: None,
            probe_url: None,
            node_pool: None,
            pool_keys: Vec::new(),
        };
        assert!(!subscription_refresh_due(&meta, 1899));
        assert!(subscription_refresh_due(&meta, 1900));
        meta.refresh_interval_minutes = None;
        assert!(!subscription_refresh_due(&meta, 10_000));
    }

    #[test]
    fn tunnel_role_and_networks_are_validated_and_persisted() {
        use net_manager_core::models::TunnelRole;
        let dir = unique_dir("tunnel-role");
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        store
            .upsert(Profile {
                id: "wg1".into(),
                name: "Office".into(),
                backend: TunnelBackend::WireGuard,
                config_path: dir.join("wg1.conf"),
                interface_name: "wg1".into(),
                ..Default::default()
            })
            .unwrap();
        store
            .upsert(Profile {
                id: "static".into(),
                name: "Static".into(),
                backend: TunnelBackend::None,
                interface_name: "eth9".into(),
                ..Default::default()
            })
            .unwrap();

        let profiles = set_tunnel_role_into(&store, "wg1", TunnelRole::Secondary).unwrap();
        assert_eq!(profiles[0].tunnel_role, TunnelRole::Secondary);
        let profiles = set_tunnel_networks_into(
            &store,
            "wg1",
            "10.10.4.7/16, 192.168.5.0/24",
            "Corp.Example",
        )
        .unwrap();
        assert_eq!(profiles[0].tunnel_networks.len(), 2);
        assert_eq!(profiles[0].tunnel_dns_domains, vec!["corp.example"]);
        let stored = store.load().unwrap().profiles.remove(0);
        assert_eq!(stored.effective_routes().len(), 2);

        assert!(set_tunnel_networks_into(&store, "wg1", "0.0.0.0/0", "").is_err());
        assert!(set_tunnel_networks_into(&store, "wg1", "10.0.0.0/8", "a/b").is_err());
        assert!(set_tunnel_role_into(&store, "static", TunnelRole::Secondary).is_err());
        assert!(set_tunnel_role_into(&store, "missing", TunnelRole::Primary).is_err());
        // Rejected input leaves the stored networks alone.
        assert_eq!(store.load().unwrap().profiles[0].tunnel_networks.len(), 2);
    }

    #[test]
    fn interval_change_persists_across_store_reload_without_ipc_secrets() {
        let dir = unique_dir("subscription-interval-persist");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(
            &vault,
            &store,
            "https://example.test/private-token",
            "private-hwid",
            "hy2://password@node.test:443#Node",
        )
        .unwrap();
        let id = imported.profiles[0].id.clone();
        let public = set_subscription_refresh_interval_into(&store, &id, Some(60), 1234).unwrap();
        assert!(!serde_json::to_string(&public)
            .unwrap()
            .contains("private-token"));
        let restored = store.load().unwrap().profiles.remove(0);
        assert_eq!(
            restored
                .subscription
                .as_ref()
                .unwrap()
                .refresh_interval_minutes,
            Some(60)
        );
        assert_eq!(
            restored.subscription.as_ref().unwrap().last_refresh_at_unix,
            Some(1234)
        );
        assert_eq!(restored.subscription.as_ref().unwrap().hwid, "private-hwid");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn automatic_refresh_skips_active_tunnel_even_when_interval_elapsed() {
        let mut p = profile("subscription");
        p.backend = TunnelBackend::Xray;
        p.subscription = Some(SubscriptionMeta {
            url: "https://example.test/private-token".into(),
            hwid: "private-hwid".into(),
            endpoint_count: 1,
            active_index: 0,
            refresh_interval_minutes: Some(15),
            last_refresh_at_unix: Some(1000),
            last_refresh_error: None,
            user_info: None,
            provider_title: None,
            announce: None,
            support_url: None,
            web_page_url: None,
            update_interval_hours: None,
            skipped_protocols: Vec::new(),
            active_key: None,
            backup_keys: Vec::new(),
            auto_return_primary: None,
            probe_url: None,
            node_pool: None,
            pool_keys: Vec::new(),
        });
        assert!(!should_auto_refresh(&p, 1900, true));
        assert!(should_auto_refresh(&p, 1900, false));
    }

    #[tokio::test]
    async fn subscription_refresh_lock_serializes_overlapping_attempts() {
        let first = SUBSCRIPTION_REFRESH_LOCK.lock().await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            SUBSCRIPTION_REFRESH_LOCK.lock(),
        )
        .await
        .is_err());
        drop(first);
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(1),
            SUBSCRIPTION_REFRESH_LOCK.lock(),
        )
        .await
        .is_ok());
    }

    #[test]
    fn endpoint_config_accepts_hysteria2_and_redacts_errors() {
        let config =
            generate_endpoint_config("hy2://pass@node.test:443?sni=node.test", 10808, 10809)
                .unwrap();
        assert_eq!(config["outbounds"][0]["protocol"], "hysteria");
        let err =
            generate_endpoint_config("hy2://secret-password@node.test?obfs=gecko", 10808, 10809)
                .unwrap_err();
        assert!(!err.contains("secret-password"));
    }

    #[test]
    fn subscription_import_selects_first_valid_hysteria_endpoint_and_reports_skips_safely() {
        let dir = unique_dir("hy2-subscription");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let body = "trojan://private-credential@other.test:443\nvless://bad-secret@:443?security=tls#Bad\nhy2://good-password@node.test:443?sni=node.test#Good%20Node";
        let result =
            import_subscription_body_into(&vault, &store, "https://example.test/sub", "hwid", body)
                .unwrap();
        assert_eq!(result.profiles.len(), 1);
        assert_eq!(result.errors.len(), 2);
        for error in &result.errors {
            assert!(!error.path.contains("private-credential"));
            assert!(!error.path.contains("bad-secret"));
            assert!(!error.error.contains("private-credential"));
            assert!(!error.error.contains("bad-secret"));
        }
        let profile = &result.profiles[0];
        assert_eq!(profile.name, "Good Node");
        assert_ne!(profile.xray_socks_port, profile.xray_http_port);
        assert!(profile.xray_http_port.is_some());
        let subscription = profile.subscription.as_ref().unwrap();
        assert_eq!(subscription.endpoint_count, 1);
        assert_eq!(subscription.active_index, 0);
        let endpoints = vault.read_subscription_endpoints(&profile.id).unwrap();
        assert_eq!(endpoints.len(), 1);
        let config = config_security::read_xray_config(&profile.config_path, &profile.id).unwrap();
        let config: serde_json::Value = serde_json::from_slice(&config).unwrap();
        assert_eq!(config["outbounds"][0]["protocol"], "hysteria");
        assert_eq!(config["inbounds"][1]["protocol"], "http");
        assert_eq!(
            config["inbounds"][1]["port"],
            profile.xray_http_port.unwrap()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn switching_subscription_endpoint_preserves_both_generated_ports() {
        let dir = unique_dir("subscription-switch-http");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(
            &vault,
            &store,
            "https://example.test/sub",
            "hwid",
            "vless://id@one.test:443?security=tls#First\nhy2://password@two.test:443#Second",
        )
        .unwrap();
        let old = &imported.profiles[0];
        let key = net_manager_core::subscription::list_endpoints(&vault, &store, &old.id).unwrap()
            [1]
        .key
        .clone();
        let profiles =
            switch_subscription_endpoint_into(&vault, &store, &old.id, &key, |_| true).unwrap();
        let switched = &profiles[0];
        assert_eq!(switched.xray_socks_port, old.xray_socks_port);
        assert_eq!(switched.xray_http_port, old.xray_http_port);
        assert_eq!(switched.subscription.as_ref().unwrap().active_index, 1);
        let config =
            config_security::read_xray_config(&switched.config_path, &switched.id).unwrap();
        let config: serde_json::Value = serde_json::from_slice(&config).unwrap();
        assert_eq!(config["outbounds"][0]["protocol"], "hysteria");
        assert_eq!(config["inbounds"][0]["port"], old.xray_socks_port.unwrap());
        assert_eq!(config["inbounds"][1]["port"], old.xray_http_port.unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn subscription_import_removes_vault_data_when_profile_store_fails() {
        let dir = unique_dir("hy2-subscription-rollback");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        fs::create_dir(dir.join("profiles.json.tmp")).unwrap();
        let err = import_subscription_body_into(
            &vault,
            &store,
            "https://example.test/sub",
            "hwid",
            "hy2://password@node.test:443",
        )
        .unwrap_err();
        assert!(err.contains("profile"));
        assert_eq!(fs::read_dir(vault.root()).unwrap().count(), 0);
        assert!(store.load().unwrap().profiles.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_preserves_selected_endpoint_across_reorder_and_renamed_fragment() {
        let dir = unique_dir("subscription-refresh-reorder");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(&vault, &store, "https://secret-url.test/sub", "private-hwid", "vless://id@one.test:443?security=tls#First\nhy2://private-password@two.test:443#Second").unwrap();
        let mut selected = net_manager_core::subscription::switch_endpoint(
            &vault,
            &store,
            &imported.profiles[0].id,
            1,
            |_| true,
        )
        .unwrap()
        .profiles
        .remove(0);
        selected
            .subscription
            .as_mut()
            .unwrap()
            .refresh_interval_minutes = Some(60);
        selected.subscription.as_mut().unwrap().last_refresh_error = Some("Refresh failed".into());
        store.upsert(selected.clone()).unwrap();
        let usage = SubscriptionUserInfo {
            upload_bytes: 10,
            download_bytes: 20,
            total_bytes: Some(100),
            expires_at_unix: None,
        };
        let result = refresh_subscription_body_into_with_metadata(&vault, &store, &selected.id, "trojan://private-token@other.test:443\nhy2://private-password@two.test:443#Renamed%20Node\nvless://id@one.test:443?security=tls#First", |_| true, SubscriptionResponseMeta {
                user_info: Some(usage.clone()),
                ..SubscriptionResponseMeta::default()
            }).unwrap();
        assert_eq!(result.active_index, 0);
        assert_eq!(result.endpoint_count, 2);
        assert_eq!(result.skipped_count, 1);
        assert!(!result.fallback_used);
        assert!(!serde_json::to_string(&result).unwrap().contains("private-"));
        let refreshed = store.load().unwrap().profiles.remove(0);
        assert_eq!(refreshed.name, "Renamed Node");
        let subscription = refreshed.subscription.unwrap();
        assert_eq!(subscription.active_index, 0);
        assert_eq!(subscription.refresh_interval_minutes, Some(60));
        assert!(subscription.last_refresh_error.is_none());
        assert_eq!(subscription.user_info, Some(usage));
        let config =
            config_security::read_xray_config(&refreshed.config_path, &refreshed.id).unwrap();
        let config: serde_json::Value = serde_json::from_slice(&config).unwrap();
        assert_eq!(config["outbounds"][0]["protocol"], "hysteria");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_falls_back_when_selected_endpoint_disappears() {
        let dir = unique_dir("subscription-refresh-fallback");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(
            &vault,
            &store,
            "https://example.test/sub",
            "hwid",
            "vless://id@one.test:443?security=tls#First\nhy2://password@two.test:443#Second",
        )
        .unwrap();
        let selected = net_manager_core::subscription::switch_endpoint(
            &vault,
            &store,
            &imported.profiles[0].id,
            1,
            |_| true,
        )
        .unwrap()
        .profiles
        .remove(0);
        store.upsert(selected.clone()).unwrap();
        let result = refresh_subscription_body_into(
            &vault,
            &store,
            &selected.id,
            "vless://id@one.test:443?security=tls#First",
            |_| true,
        )
        .unwrap();
        assert!(result.fallback_used);
        assert_eq!(result.active_index, 0);
        assert_eq!(result.endpoint_count, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_rolls_back_sidecar_and_config_when_profile_write_fails() {
        let dir = unique_dir("subscription-refresh-rollback");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(
            &vault,
            &store,
            "https://example.test/sub",
            "hwid",
            "hy2://password@one.test:443#First",
        )
        .unwrap();
        let old = imported.profiles[0].clone();
        let old_endpoints = vault.read_subscription_endpoints(&old.id).unwrap();
        let old_files = fs::read_dir(vault.root().join(&old.id)).unwrap().count();
        fs::create_dir(dir.join("profiles.json.tmp")).unwrap();
        let err = refresh_subscription_body_into(
            &vault,
            &store,
            &old.id,
            "hy2://new-password@two.test:443#New",
            |_| true,
        )
        .unwrap_err();
        assert!(!err.contains("new-password"));
        assert_eq!(
            vault.read_subscription_endpoints(&old.id).unwrap(),
            old_endpoints
        );
        assert_eq!(
            fs::read_dir(vault.root().join(&old.id)).unwrap().count(),
            old_files
        );
        assert_eq!(store.load().unwrap().profiles[0], old);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_rolls_back_config_when_sidecar_write_fails() {
        let dir = unique_dir("subscription-refresh-sidecar-failure");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(
            &vault,
            &store,
            "https://example.test/sub",
            "hwid",
            "hy2://password@one.test:443#First",
        )
        .unwrap();
        let old = imported.profiles[0].clone();
        let old_endpoints = vault.read_subscription_endpoints(&old.id).unwrap();
        fs::create_dir(vault.root().join(&old.id).join("subscription.json.tmp")).unwrap();
        let old_files = fs::read_dir(vault.root().join(&old.id)).unwrap().count();
        let err = refresh_subscription_body_into(
            &vault,
            &store,
            &old.id,
            "hy2://new-password@two.test:443#New",
            |_| true,
        )
        .unwrap_err();
        assert!(!err.contains("new-password"));
        assert_eq!(
            vault.read_subscription_endpoints(&old.id).unwrap(),
            old_endpoints
        );
        assert_eq!(
            fs::read_dir(vault.root().join(&old.id)).unwrap().count(),
            old_files
        );
        assert_eq!(store.load().unwrap().profiles[0], old);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn refresh_failed_http_response_preserves_existing_subscription() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let dir = unique_dir("subscription-refresh-http-failure");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let subscription_url = format!("http://{address}/private-token");
        let imported = import_subscription_body_into(
            &vault,
            &store,
            &subscription_url,
            "private-hwid",
            "hy2://password@one.test:443#First",
        )
        .unwrap();
        let old = imported.profiles[0].clone();
        let old_endpoints = vault.read_subscription_endpoints(&old.id).unwrap();
        let err = refresh_subscription_into_with_ports(
            &vault,
            &store,
            &reqwest::Client::new(),
            &old.id,
            |_| true,
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(!err.contains("private-token"));
        assert!(!err.contains("private-hwid"));
        assert_eq!(store.load().unwrap().profiles[0], old);
        assert_eq!(
            vault.read_subscription_endpoints(&old.id).unwrap(),
            old_endpoints
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_error_state_preserves_selected_endpoint_and_redacts_ipc() {
        let dir = unique_dir("subscription-refresh-error-state");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(
            &vault,
            &store,
            "https://example.test/private-token",
            "private-hwid",
            "hy2://password@node.test:443#First",
        )
        .unwrap();
        let old = imported.profiles[0].clone();
        record_subscription_refresh_failure(&store, &old.id, 1234).unwrap();
        let updated = store.load().unwrap().profiles.remove(0);
        assert_eq!(updated.config_path, old.config_path);
        assert_eq!(updated.subscription.as_ref().unwrap().active_index, 0);
        assert_eq!(
            updated.subscription.as_ref().unwrap().last_refresh_at_unix,
            Some(1234)
        );
        assert_eq!(
            updated
                .subscription
                .as_ref()
                .unwrap()
                .last_refresh_error
                .as_deref(),
            Some("Refresh failed")
        );
        let serialized = serde_json::to_string(&redact_profiles_for_ipc(vec![updated])).unwrap();
        assert!(!serialized.contains("private-token"));
        assert!(!serialized.contains("private-hwid"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn refresh_fetches_mixed_body_from_fake_http_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let bytes = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..bytes])
                .to_ascii_lowercase()
                .contains("x-hwid"));
            let body = "trojan://private-secret@other.test:443\nvless://id@two.test:443?security=tls#Other\nhy2://password@one.test:443#Renamed";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSubscription-Userinfo: upload=1024; download=2048; total=4096; expire=1798761600\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let dir = unique_dir("subscription-refresh-http-success");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let subscription_url = format!("http://{address}/private-token");
        let imported = import_subscription_body_into(
            &vault,
            &store,
            &subscription_url,
            "private-hwid",
            "hy2://password@one.test:443#Original",
        )
        .unwrap();
        let old = &imported.profiles[0];
        let result = refresh_subscription_into_with_ports(
            &vault,
            &store,
            &reqwest::Client::new(),
            &old.id,
            |_| true,
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(result.active_index, 1);
        assert_eq!(result.skipped_count, 1);
        assert!(!result.fallback_used);
        let refreshed = store.load().unwrap().profiles.remove(0);
        assert_eq!(refreshed.name, "Renamed");
        let user_info = refreshed.subscription.unwrap().user_info.unwrap();
        assert_eq!(user_info.upload_bytes, 1024);
        assert_eq!(user_info.total_bytes, Some(4096));
        assert_eq!(user_info.expires_at_unix, Some(1798761600));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn subscription_import_keeps_selected_interval_and_userinfo_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await;
            let body = "hy2://password@node.test:443#Node";
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSubscription-Userinfo: upload=100; download=200; total=1000; expire=0\r\n\r\n{body}", body.len());
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let dir = unique_dir("subscription-import-userinfo");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let url = format!("http://{address}/private-token");
        let result = import_subscription_into(
            &vault,
            &store,
            &reqwest::Client::new(),
            &url,
            "private-hwid",
            Some(15),
        )
        .await
        .unwrap();
        server.await.unwrap();
        let subscription = result.profiles[0].subscription.as_ref().unwrap();
        assert_eq!(subscription.refresh_interval_minutes, Some(15));
        assert_eq!(subscription.user_info.as_ref().unwrap().download_bytes, 200);
        assert_eq!(
            subscription.user_info.as_ref().unwrap().expires_at_unix,
            None
        );
        assert!(!serde_json::to_string(&redact_batch_import_for_ipc(result))
            .unwrap()
            .contains("private-token"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_subscription_provider_title_decodes_known_formats() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("AcmeVPN 🇳🇱");
        assert_eq!(
            net_manager_core::subscription::parse_provider_title(&format!("base64:{encoded}"))
                .as_deref(),
            Some("AcmeVPN 🇳🇱")
        );
        assert_eq!(
            net_manager_core::subscription::parse_provider_title("Acme%20VPN").as_deref(),
            Some("Acme VPN")
        );
        assert_eq!(
            net_manager_core::subscription::parse_provider_title("  AcmeVPN  ").as_deref(),
            Some("AcmeVPN")
        );
        assert_eq!(
            net_manager_core::subscription::parse_provider_title("   "),
            None
        );
        assert_eq!(
            net_manager_core::subscription::parse_provider_title("base64:%%%"),
            None
        );
        assert_eq!(
            net_manager_core::subscription::parse_provider_title("bad\nheader"),
            None
        );
        assert_eq!(
            net_manager_core::subscription::parse_provider_title(&"x".repeat(300)),
            None
        );
    }

    #[test]
    fn subscription_profile_name_combines_provider_and_endpoint() {
        assert_eq!(
            net_manager_core::subscription::subscription_profile_name(
                Some("AcmeVPN"),
                "⚡ Нидерланды"
            ),
            "AcmeVPN · ⚡ Нидерланды"
        );
        assert_eq!(
            net_manager_core::subscription::subscription_profile_name(
                Some("AcmeVPN"),
                "AcmeVPN - ⚡ NL"
            ),
            "AcmeVPN · ⚡ NL"
        );
        assert_eq!(
            net_manager_core::subscription::subscription_profile_name(Some("Acme"), "AcmeVPN - NL"),
            "Acme · AcmeVPN - NL"
        );
        assert_eq!(
            net_manager_core::subscription::subscription_profile_name(None, "Node"),
            "Node"
        );
        assert_eq!(
            net_manager_core::subscription::subscription_profile_name(Some("  "), "Node"),
            "Node"
        );
        assert_eq!(
            net_manager_core::subscription::subscription_profile_name(Some("AcmeVPN"), "AcmeVPN"),
            "AcmeVPN"
        );
    }

    #[test]
    fn refresh_keeps_provider_title_when_header_missing() {
        let dir = unique_dir("subscription-refresh-title");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(
            &vault,
            &store,
            "https://secret-url.test/sub",
            "private-hwid",
            "hy2://private-password@one.test:443#First\nhy2://private-password@two.test:443#Second",
        )
        .unwrap();
        let mut selected = imported.profiles[0].clone();
        selected.subscription.as_mut().unwrap().provider_title = Some("AcmeVPN".into());
        store.upsert(selected.clone()).unwrap();
        refresh_subscription_body_into_with_metadata(
            &vault,
            &store,
            &selected.id,
            "hy2://private-password@one.test:443#First\nhy2://private-password@two.test:443#Second\nss://b64@three.test:8388#Shadowsocks\ntrojan://p@four.test:443#Trojan",
            |_| true,
            SubscriptionResponseMeta::default(),
        )
        .unwrap();
        let refreshed = store.load().unwrap().profiles.remove(0);
        assert_eq!(
            refreshed
                .subscription
                .as_ref()
                .unwrap()
                .provider_title
                .as_deref(),
            Some("AcmeVPN")
        );
        assert_eq!(
            refreshed.subscription.as_ref().unwrap().skipped_protocols,
            ["ss", "trojan"]
        );
        assert_eq!(refreshed.name, "AcmeVPN · First");
        refresh_subscription_body_into_with_metadata(
            &vault,
            &store,
            &selected.id,
            "hy2://private-password@one.test:443#First\nhy2://private-password@two.test:443#Second",
            |_| true,
            SubscriptionResponseMeta {
                provider_title: Some("NewVPN".into()),
                ..SubscriptionResponseMeta::default()
            },
        )
        .unwrap();
        let refreshed = store.load().unwrap().profiles.remove(0);
        assert_eq!(
            refreshed
                .subscription
                .as_ref()
                .unwrap()
                .provider_title
                .as_deref(),
            Some("NewVPN")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn subscription_import_stores_profile_title_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await;
            let body = "hy2://password@node.test:443#Node";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nProfile-Title: base64:QWNtZVZQTg==\r\nAnnounce: base64:TWFpbnRlbmFuY2Ugb24gU2F0dXJkYXkK\r\nSupport-Url: https://support.example.test/chat\r\nProfile-Web-Page-Url: https://cabinet.example.test/u/123\r\nProfile-Update-Interval: 12\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let dir = unique_dir("subscription-import-title");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let url = format!("http://{address}/private-token");
        let result = import_subscription_into(
            &vault,
            &store,
            &reqwest::Client::new(),
            &url,
            "private-hwid",
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();
        let subscription = result.profiles[0].subscription.as_ref().unwrap();
        assert_eq!(subscription.provider_title.as_deref(), Some("AcmeVPN"));
        assert_eq!(
            subscription.announce.as_deref(),
            Some("Maintenance on Saturday")
        );
        assert_eq!(
            subscription.support_url.as_deref(),
            Some("https://support.example.test/chat")
        );
        assert_eq!(
            subscription.web_page_url.as_deref(),
            Some("https://cabinet.example.test/u/123")
        );
        assert_eq!(subscription.update_interval_hours, Some(12));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn subscription_url_header_accepts_only_http_links() {
        assert_eq!(
            net_manager_core::subscription::parse_url_header("https://support.example.test")
                .as_deref(),
            Some("https://support.example.test")
        );
        assert!(net_manager_core::subscription::parse_url_header("javascript:alert(1)").is_none());
        assert!(net_manager_core::subscription::parse_url_header("ftp://host/path").is_none());
        assert!(net_manager_core::subscription::parse_url_header("not a url").is_none());
        assert!(net_manager_core::subscription::parse_url_header("   ").is_none());
    }

    #[test]
    fn endpoint_protocol_label_summarizes_scheme_security_and_transport() {
        assert_eq!(
            net_manager_core::xray::endpoint_protocol(
                "vless://id@host.test:443?security=reality&type=grpc#Node"
            )
            .as_deref(),
            Some("VLESS · Reality · GRPC")
        );
        assert_eq!(
            net_manager_core::xray::endpoint_protocol("vless://id@host.test:443?security=tls#Node")
                .as_deref(),
            Some("VLESS · TLS")
        );
        assert_eq!(
            net_manager_core::xray::endpoint_protocol("hy2://pass@host.test:443#Node").as_deref(),
            Some("Hysteria2")
        );
        assert!(net_manager_core::xray::endpoint_protocol("not a url").is_none());
    }

    #[tokio::test]
    async fn refresh_rejects_oversized_body_without_changing_subscription() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await;
            let body = vec![b'x'; MAX_SUBSCRIPTION_BODY_BYTES + 1];
            let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            let _ = stream.write_all(headers.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        });
        let dir = unique_dir("subscription-refresh-large-body");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let subscription_url = format!("http://{address}/private-token");
        let imported = import_subscription_body_into(
            &vault,
            &store,
            &subscription_url,
            "private-hwid",
            "hy2://password@one.test:443#First",
        )
        .unwrap();
        let old = imported.profiles[0].clone();
        let err = refresh_subscription_into_with_ports(
            &vault,
            &store,
            &reqwest::Client::new(),
            &old.id,
            |_| true,
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(err.contains("size limit"));
        assert!(!err.contains("private-token"));
        assert_eq!(store.load().unwrap().profiles[0], old);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn public_profile_and_batch_responses_do_not_serialize_subscription_credentials() {
        let mut stored = profile("subscription");
        stored.backend = TunnelBackend::Xray;
        stored.subscription = Some(SubscriptionMeta {
            url: "https://example.test/private-token".into(),
            hwid: "private-hwid".into(),
            endpoint_count: 2,
            active_index: 1,
            refresh_interval_minutes: None,
            last_refresh_at_unix: None,
            last_refresh_error: None,
            user_info: None,
            provider_title: None,
            announce: None,
            support_url: None,
            web_page_url: None,
            update_interval_hours: None,
            skipped_protocols: Vec::new(),
            active_key: None,
            backup_keys: Vec::new(),
            auto_return_primary: None,
            probe_url: None,
            node_pool: None,
            pool_keys: Vec::new(),
        });
        let public = redact_profiles_for_ipc(vec![stored.clone()]);
        let json = serde_json::to_string(&public).unwrap();
        assert!(!json.contains("private-token"));
        assert!(!json.contains("private-hwid"));
        assert!(!format!("{public:?}").contains("private-hwid"));
        assert_eq!(public[0].subscription.as_ref().unwrap().endpoint_count, 2);
        assert_eq!(stored.subscription.as_ref().unwrap().hwid, "private-hwid");
        let batch = redact_batch_import_for_ipc(BatchImportResult {
            profiles: vec![stored],
            errors: Vec::new(),
        });
        let json = serde_json::to_string(&batch).unwrap();
        assert!(!json.contains("private-token"));
        assert!(!json.contains("private-hwid"));
        assert!(!format!("{batch:?}").contains("private-token"));
    }

    #[test]
    fn save_roundtrip_restores_canonical_subscription_and_rejects_forged_metadata() {
        let dir = unique_dir("subscription-redacted-save");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let imported = import_subscription_body_into(
            &vault,
            &store,
            "https://example.test/private-token",
            "private-hwid",
            "hy2://password@node.test:443#Original",
        )
        .unwrap();
        let stored = imported.profiles[0].clone();
        let mut incoming = redact_profiles_for_ipc(vec![stored.clone()]).remove(0);
        incoming.name = "Renamed".into();
        incoming.subscription.as_mut().unwrap().url = "https://forged.test/secret".into();
        preserve_canonical_subscription(&mut incoming, Some(&stored));
        let response = store.upsert(incoming).unwrap();
        assert_eq!(
            store.load().unwrap().profiles[0].subscription,
            stored.subscription
        );
        assert!(
            !serde_json::to_string(&redact_profiles_for_ipc(response.profiles))
                .unwrap()
                .contains("private-hwid")
        );
        let refreshed = refresh_subscription_body_into(
            &vault,
            &store,
            &stored.id,
            "hy2://password@node.test:443#Updated",
            |_| true,
        )
        .unwrap();
        assert!(!refreshed.fallback_used);
        assert_eq!(
            store.load().unwrap().profiles[0]
                .subscription
                .as_ref()
                .unwrap()
                .hwid,
            "private-hwid"
        );
        let mut new_profile = profile("new");
        new_profile.backend = TunnelBackend::Xray;
        new_profile.subscription = stored.subscription;
        preserve_canonical_subscription(&mut new_profile, None);
        assert!(new_profile.subscription.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generic_save_cannot_forge_generated_xray_source_marker() {
        let mut stored = profile("generated");
        stored.backend = TunnelBackend::Xray;
        stored.config_path = PathBuf::from("/vault/generated/config.json");
        stored.xray_socks_port = Some(10808);
        stored.xray_http_port = Some(10809);
        let mut incoming = stored.clone();
        incoming.xray_socks_port = Some(1000);
        incoming.xray_http_port = Some(1001);
        preserve_generated_xray_source(&mut incoming, Some(&stored));
        assert_eq!(
            (incoming.xray_socks_port, incoming.xray_http_port),
            (Some(10808), Some(10809))
        );
        incoming.config_path = PathBuf::from("/new-user.json");
        preserve_generated_xray_source(&mut incoming, Some(&stored));
        assert_eq!(
            (incoming.xray_socks_port, incoming.xray_http_port),
            (None, None)
        );
        incoming.xray_socks_port = Some(10808);
        preserve_generated_xray_source(&mut incoming, None);
        assert!(incoming.xray_socks_port.is_none());
    }

    #[test]
    fn invalid_geo_rule_is_rejected_before_save_without_echoing_selector() {
        let mut profile = profile("geo-rule");
        profile.backend = TunnelBackend::Xray;
        profile.domain_policies = vec![DomainPolicy {
            domains: vec!["geosite:private-secret/../cn".into()],
            target: DomainRouteTarget::Block,
        }];
        let err = validate_xray_routing(&profile).unwrap_err();
        assert!(!err.contains("private-secret"));
    }

    #[test]
    fn fake_xray_process() {
        use std::io::{Read, Write};
        let Ok(mode) = std::env::var("NET_MANAGER_FAKE_XRAY") else {
            return;
        };
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let config: serde_json::Value = serde_json::from_str(&input).unwrap();
        let port = config["inbounds"][0]["port"].as_u64().unwrap() as u16;
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        if let Ok(path) = std::env::var("NET_MANAGER_FAKE_XRAY_PID") {
            fs::write(path, std::process::id().to_string()).unwrap();
        }
        for connection in listener.incoming() {
            let mut stream = connection.unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut greeting = [0; 2];
            if stream.read_exact(&mut greeting).is_err() {
                continue;
            }
            if greeting[0] != 5 {
                continue;
            }
            let mut methods = vec![0; greeting[1] as usize];
            stream.read_exact(&mut methods).unwrap();
            stream.write_all(&[5, 0]).unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            let address_len = match request[3] {
                1 => 4,
                3 => {
                    let mut length = [0];
                    stream.read_exact(&mut length).unwrap();
                    length[0] as usize
                }
                4 => 16,
                _ => panic!("unexpected address type"),
            };
            let mut destination = vec![0; address_len + 2];
            stream.read_exact(&mut destination).unwrap();
            stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            let mut http = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let size = stream.read(&mut buffer).unwrap();
                if size == 0 {
                    break;
                }
                http.extend_from_slice(&buffer[..size]);
                if http.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            if mode == "hang" {
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
            let response =
                if mode == "ok" && String::from_utf8_lossy(&http).contains("/generate_204") {
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice()
                } else {
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".as_slice()
                };
            let _ = stream.write_all(response);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn delay_probe_uses_socks_get_and_reaps_temporary_xray() {
        let dir = unique_dir("delay-probe");
        let pid_path = dir.join("pid");
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "commands::profiles::tests::fake_xray_process",
            "--nocapture",
        ]);
        command.env("NET_MANAGER_FAKE_XRAY", "ok");
        command.env("NET_MANAGER_FAKE_XRAY_PID", &pid_path);
        let ms = measure_delay_with_process(
            "hy2://private-password@node.test:443",
            command,
            "http://example.test/generate_204",
            std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(ms < 3000);
        let pid: u32 = fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn delay_probe_timeout_reaps_xray_and_redacts_uri() {
        let dir = unique_dir("delay-probe-timeout");
        let pid_path = dir.join("pid");
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "commands::profiles::tests::fake_xray_process",
            "--nocapture",
        ]);
        command.env("NET_MANAGER_FAKE_XRAY", "hang");
        command.env("NET_MANAGER_FAKE_XRAY_PID", &pid_path);
        let err = measure_delay_with_process(
            "hy2://private-password@node.test:443",
            command,
            "http://example.test/generate_204",
            std::time::Duration::from_millis(500),
        )
        .await
        .unwrap_err();
        assert!(!err.contains("private-password"));
        let pid: u32 = fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn delay_probe_rejects_non_204_response_without_leaking_auth() {
        let dir = unique_dir("delay-probe-http-error");
        let pid_path = dir.join("pid");
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "commands::profiles::tests::fake_xray_process",
            "--nocapture",
        ]);
        command.env("NET_MANAGER_FAKE_XRAY", "http-error");
        command.env("NET_MANAGER_FAKE_XRAY_PID", &pid_path);
        let err = measure_delay_with_process(
            "hy2://private-password@node.test:443",
            command,
            "http://example.test/generate_204",
            std::time::Duration::from_secs(3),
        )
        .await
        .unwrap_err();
        assert!(!err.contains("private-password"));
        let pid: u32 = fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancelled_delay_probe_stops_temporary_xray() {
        let dir = unique_dir("delay-probe-cancel");
        let pid_path = dir.join("pid");
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "commands::profiles::tests::fake_xray_process",
            "--nocapture",
        ]);
        command.env("NET_MANAGER_FAKE_XRAY", "hang");
        command.env("NET_MANAGER_FAKE_XRAY_PID", &pid_path);
        let task = tokio::spawn(async move {
            measure_delay_with_process(
                "hy2://private-password@node.test:443",
                command,
                "http://example.test/generate_204",
                std::time::Duration::from_secs(10),
            )
            .await
        });
        let pid = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Ok(raw) = fs::read_to_string(&pid_path) {
                    break raw.parse::<u32>().unwrap();
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while std::path::Path::new(&format!("/proc/{pid}")).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn base64_decode_returns_none_for_invalid_input() {
        assert!(base64_decode("!!!not-base64!!!").is_none());
        assert!(base64_decode("").is_none());
    }
}
