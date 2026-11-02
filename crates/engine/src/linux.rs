//! Requests to the Linux network daemon, built without any UI state: what the
//! Tauri app and the `netorch` CLI both send for "connect this profile".
//! Everything here is pure — it reads the managed config from the vault and
//! returns a typed `daemon_protocol` request or maps a daemon status; nothing
//! talks to the socket (see [`crate::linux_engine`] for that).
use base64::Engine as _;
use net_manager_core::daemon_protocol::{
    method, OpenVpnConnectParams, OpenVpnConnectRequest, OpenVpnConnectionState,
    OpenVpnCredentials, OpenVpnStatusResult, OpenVpnWarning, WireGuardConnectParams,
    WireGuardStatusResult, WireGuardWarning, XrayConnectParams, XrayStatusResult,
};
use net_manager_core::models::*;

/// Remembered OpenVPN credentials (the system keyring or, without one, the
/// process). The app and the CLI each bring their own store.
pub trait CredentialSource {
    /// Remembered credentials plus an optional user notice. `legacy` is the
    /// old plaintext file, migrated and deleted on first access.
    fn load(
        &self,
        profile_id: &str,
        legacy: &std::path::Path,
    ) -> Result<(Option<OpenVpnCredentials>, Option<&'static str>), String>;
}

/// The `wireguard.connect` request: the managed config plus the routes the
/// profile's role allows.
pub fn wireguard_connect_params(
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
) -> Result<WireGuardConnectParams, String> {
    if !vault.is_managed_profile_path(&profile.id, &profile.config_path) {
        return Err("WireGuard profile must use its own managed config on Linux".into());
    }
    if profile.config_path.to_string_lossy().ends_with(".dpapi") {
        return Err("DPAPI WireGuard configs are only supported on Windows".into());
    }
    let config = std::fs::read_to_string(&profile.config_path)
        .map_err(|_| "cannot read WireGuard profile config".to_string())?;
    Ok(WireGuardConnectParams {
        profile_id: profile.id.clone(),
        config,
        routes: profile.effective_routes(),
        interface_name: link_name_hint(profile),
        role: profile.tunnel_role,
        dns_domains: profile.tunnel_dns_domains.clone(),
    })
}

pub struct OpenVpnCredentialRequirements {
    pub user_pass: bool,
    pub key_passphrase: bool,
}

pub fn openvpn_encrypted_key(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN ENCRYPTED PRIVATE KEY-----".len())
        .any(|part| part == b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || bytes
            .windows(b"Proc-Type: 4,ENCRYPTED".len())
            .any(|part| part == b"Proc-Type: 4,ENCRYPTED")
}

pub fn openvpn_credential_requirements(
    config: &str,
    assets: &std::collections::BTreeMap<String, Vec<u8>>,
) -> OpenVpnCredentialRequirements {
    let mut user_pass = false;
    let mut askpass_prompt = false;
    let mut askpass_file = false;
    // Inline block contents are not directives; a credential line inside an
    // inline block must not be mistaken for a prompt request.
    let mut in_block = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if in_block {
            if trimmed.starts_with("</") {
                in_block = false;
            }
            continue;
        }
        if trimmed.starts_with('<') && !trimmed.starts_with("</") {
            in_block = true;
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(word) = tokens.next() else { continue };
        let word = word.trim_start_matches('-');
        if word.eq_ignore_ascii_case("auth-user-pass") {
            // `username-only` still prompts; a file argument does not.
            match tokens.next().map(|arg| arg.trim_matches('"')) {
                None | Some("username-only") => user_pass = true,
                Some(_) => {}
            }
        } else if word.eq_ignore_ascii_case("askpass") {
            if tokens.next().is_none() {
                askpass_prompt = true;
            } else {
                askpass_file = true;
            }
        }
    }
    let encrypted_key = openvpn_encrypted_key(config.as_bytes())
        || assets.values().any(|asset| openvpn_encrypted_key(asset));
    OpenVpnCredentialRequirements {
        user_pass,
        // A passphrase file supplies the answer; only a bare `askpass` or
        // an encrypted key without a file still prompts via management.
        key_passphrase: (askpass_prompt || encrypted_key) && !askpass_file,
    }
}

pub fn openvpn_credentials_path(
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
) -> Result<std::path::PathBuf, String> {
    if !vault.is_managed_profile_path(&profile.id, &profile.config_path) {
        return Err("OpenVPN credentials require an own managed profile".into());
    }
    let profile_dir = profile
        .config_path
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| "OpenVPN credentials require an own managed profile".to_string())?;
    if profile_dir != vault.root().join(&profile.id) {
        return Err("OpenVPN credentials require an own managed profile".into());
    }
    for directory in [
        vault.root(),
        profile_dir,
        profile.config_path.parent().unwrap(),
    ] {
        if !std::fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_dir())
        {
            return Err("OpenVPN credential vault directory is invalid".into());
        }
    }
    if !std::fs::symlink_metadata(&profile.config_path)
        .is_ok_and(|metadata| metadata.file_type().is_file())
    {
        return Err("managed OpenVPN config is invalid".into());
    }
    Ok(profile_dir.join("openvpn-credentials.json"))
}

pub fn prepare_linux_xray_tun_params(
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
) -> Result<XrayConnectParams, String> {
    if profile.backend != TunnelBackend::Xray || profile.xray_mode != XrayMode::Tun {
        return Err("profile is not an Xray TUN profile".into());
    }
    if !vault.is_managed_profile_path(&profile.id, &profile.config_path)
        || profile.config_path.to_string_lossy().ends_with(".dpapi")
    {
        return Err("Xray TUN requires its own managed generated config".into());
    }
    if !std::fs::symlink_metadata(&profile.config_path)
        .map_err(|_| "cannot inspect managed Xray config".to_string())?
        .file_type()
        .is_file()
    {
        return Err("managed Xray config is invalid".into());
    }
    let (Some(socks_port), Some(http_port)) = (profile.xray_socks_port, profile.xray_http_port)
    else {
        return Err("Xray TUN requires a generated share-link profile".into());
    };
    if socks_port == http_port {
        return Err("Xray generated listener ports are invalid".into());
    }
    let raw =
        net_manager_core::config_security::read_xray_config(&profile.config_path, &profile.id)
            .map_err(|_| "cannot read managed Xray config".to_string())?;
    let base: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "managed Xray config is invalid".to_string())?;
    // Subscription panels that serve whole Xray configs carry sections the
    // daemon does not run; reduce them to the server itself.
    let base = net_manager_core::xray::tun_compatible_config(&base).map_err(str::to_string)?;
    let inbounds = base["inbounds"]
        .as_array()
        .ok_or_else(|| "unsupported Xray TUN config".to_string())?;
    if inbounds.len() != 2
        || inbounds[0]["tag"] != "socks-in"
        || inbounds[0]["protocol"] != "socks"
        || inbounds[0]["listen"] != "127.0.0.1"
        || inbounds[0]["port"] != socks_port
        || inbounds[0]["settings"]["udp"] != true
        || inbounds[1]["tag"] != "http-in"
        || inbounds[1]["protocol"] != "http"
        || inbounds[1]["listen"] != "127.0.0.1"
        || inbounds[1]["port"] != http_port
    {
        return Err("unsupported Xray TUN config".into());
    }
    let config = net_manager_core::xray::apply_profile_routing(
        &base,
        &profile.domain_policies,
        &net_manager_core::xray::ProfileRoutingOptions::from(profile),
    )
    .map_err(|_| "invalid Xray routing rules".to_string())?;
    // Multinode: a subscription profile with backups or pinned routes needs
    // one outbound per candidate plus the pinned outbounds, and the daemon
    // probe/switch policy.
    let multinode = profile.subscription.as_ref().is_some_and(|subscription| {
        !subscription.backup_keys.is_empty()
            || subscription.node_pool.is_some() && !subscription.pool_keys.is_empty()
    }) || !profile.pinned_policies.is_empty()
        || profile.xray_dns.outbound_key.is_some();
    let (config, failover) = if multinode {
        build_multinode(vault, profile)?
    } else {
        (config, None)
    };

    let effective_routes = profile.effective_routes();
    let default_route = effective_routes.is_empty();
    let route = |destination: &str| PolicyRoute {
        destination: destination.parse().unwrap(),
        metric: 5,
        via: None,
    };
    let routes = if default_route {
        // Split-default installs the two def1 halves instead of one /0 —
        // same full coverage, but coexisting tunnel managers that use the
        // halves see a consistent picture.
        if profile.xray_split_default {
            vec![route("0.0.0.0/1"), route("128.0.0.0/1")]
        } else {
            vec![route("0.0.0.0/0")]
        }
    } else {
        effective_routes
    };
    let mut dns_bypass = net_manager_core::xray::dns_bypass_hosts(&profile.xray_dns);
    if default_route {
        for ip in ["1.1.1.1", "8.8.8.8", "9.9.9.9"] {
            dns_bypass.push(ip.to_string());
        }
    }
    dns_bypass.sort();
    dns_bypass.dedup();
    let params = XrayConnectParams {
        profile_id: profile.id.clone(),
        config: serde_json::to_string(&config)
            .map_err(|_| "cannot encode Xray TUN config".to_string())?,
        routes,
        dns_servers: if !profile.xray_tun_dns_servers.is_empty() {
            profile.xray_tun_dns_servers.clone()
        } else if default_route {
            vec!["1.1.1.1".parse().unwrap()]
        } else {
            Vec::new()
        },
        dns_domains: Vec::new(),
        dns_bypass,
        interface_name: link_name_hint(profile),
        geo_assets: None,
        macos_data_root: None,
        role: profile.tunnel_role,
        failover,
        reject_quic: profile.xray_quic_reject,
        probe_url: Some(
            profile
                .subscription
                .as_ref()
                .and_then(|meta| meta.probe_url.clone())
                .unwrap_or_else(|| net_manager_core::subscription::DELAY_PROBE_URL.to_string()),
        ),
        mtu: profile.xray_tun_mtu,
        service_checks: profile
            .xray_service_checks
            .iter()
            .filter(|check| check.background)
            .cloned()
            .collect(),
    };
    check_xray_frame_size(&params)?;
    Ok(params)
}
/// Build the multinode connect pieces: every failover candidate and pinned
/// endpoint is generated from its *current* share link (not `config_path`,
/// which may hold a stale selection), the routing rules land on the fresh
/// primary config, and the daemon gets its ordered probe list.
fn build_multinode(
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
) -> Result<
    (
        serde_json::Value,
        Option<net_manager_core::daemon_protocol::XrayFailoverParams>,
    ),
    String,
> {
    use net_manager_core::daemon_protocol::{XrayFailoverNode, XrayFailoverParams};
    use net_manager_core::xray::{multinode_outbound, PinnedOutbound};

    let (nodes, pinned) = net_manager_core::subscription::failover_plan(vault, profile)
        .map_err(|_| "The subscription's failover endpoints could not be resolved".to_string())?;
    let primary_url = nodes[0].url.clone();
    let primary_key = net_manager_core::subscription::endpoint_key(&primary_url);
    let mut primary_config = net_manager_core::xray::tun_compatible_config(
        &net_manager_core::xray::generate_share_link_config(&primary_url, 1)
            .map_err(|_| "The selected endpoint is invalid".to_string())?,
    )
    .map_err(str::to_string)?;
    primary_config = net_manager_core::xray::apply_profile_routing(
        &primary_config,
        &profile.domain_policies,
        &net_manager_core::xray::ProfileRoutingOptions::from(profile),
    )
    .map_err(|_| "invalid Xray routing rules".to_string())?;
    let mut backups = Vec::new();
    for node in &nodes[1..] {
        let key = net_manager_core::subscription::endpoint_key(&node.url);
        backups.push((
            key.clone(),
            multinode_outbound(&node.url, &net_manager_core::xray::node_tag(&key))
                .map_err(|_| "A backup endpoint is invalid".to_string())?,
        ));
    }
    let mut pinned_outbounds = Vec::new();
    for route in &pinned {
        let outbound = if route.missing {
            None
        } else {
            let endpoint = vault
                .read_subscription_endpoints(&profile.id)
                .ok()
                .and_then(|endpoints| {
                    net_manager_core::subscription::key_index(&endpoints, &route.endpoint_key)
                        .map(|index| endpoints[index].url.clone())
                });
            match endpoint {
                Some(url) => Some(
                    multinode_outbound(&url, &net_manager_core::xray::pin_tag(&route.endpoint_key))
                        .map_err(|_| "A pinned endpoint is invalid".to_string())?,
                ),
                // Resolution disagreed with the plan — fail closed.
                None => None,
            }
        };
        pinned_outbounds.push(PinnedOutbound {
            key: route.endpoint_key.clone(),
            outbound,
            selectors: route.selectors.clone(),
        });
    }
    if let Some(key) = &profile.xray_dns.outbound_key {
        if !pinned_outbounds.iter().any(|route| &route.key == key) {
            let endpoints = vault
                .read_subscription_endpoints(&profile.id)
                .map_err(|_| "cannot read subscription endpoints".to_string())?;
            let outbound = endpoints
                .iter()
                .find(|endpoint| {
                    net_manager_core::subscription::endpoint_key(&endpoint.url) == *key
                })
                .map(|endpoint| {
                    multinode_outbound(&endpoint.url, &net_manager_core::xray::pin_tag(key))
                })
                .transpose()
                .map_err(|_| "The DNS endpoint is invalid".to_string())?;
            pinned_outbounds.push(PinnedOutbound {
                key: key.clone(),
                outbound,
                selectors: Vec::new(),
            });
        }
    }
    let mut config = net_manager_core::xray::apply_multinode_config(
        &primary_config,
        &primary_key,
        &backups,
        &pinned_outbounds,
    )
    .map_err(|_| "cannot encode the multinode Xray config".to_string())?;
    if let Some(sockopts) = &profile.xray_sockopts {
        for outbound in config["outbounds"]
            .as_array_mut()
            .expect("generated outbounds")
        {
            if !matches!(
                outbound["protocol"].as_str(),
                Some("blackhole" | "dns" | "loopback")
            ) {
                net_manager_core::xray::apply_stream_sockopts(outbound, sockopts)
                    .map_err(|_| "Invalid Xray socket settings".to_string())?;
            }
        }
    }
    let subscription = profile.subscription.as_ref().expect("multinode checked");
    let failover = XrayFailoverParams {
        nodes: nodes
            .iter()
            .map(|node| XrayFailoverNode {
                key: net_manager_core::subscription::endpoint_key(&node.url),
            })
            .collect(),
        primary_key,
        auto_return_primary: subscription.auto_return_primary.unwrap_or(true),
        probe_url: subscription
            .probe_url
            .clone()
            .unwrap_or_else(|| net_manager_core::subscription::DELAY_PROBE_URL.to_string()),
        interval_secs: 10,
    };
    Ok((config, Some(failover)))
}

/// Rejects `xray.connect` payloads that would exceed the daemon frame cap.
/// Runs once in `prepare_linux_xray_tun_params` (config-only) and again in
/// `linux_xray_connect` after inline geo assets are attached.
pub fn check_xray_frame_size(params: &XrayConnectParams) -> Result<(), String> {
    let frame = net_manager_core::daemon_protocol::RequestFrame {
        id: 2,
        method: method::XRAY_CONNECT.into(),
        params: serde_json::to_value(params)
            .map_err(|_| "cannot encode Xray TUN config".to_string())?,
    };
    if net_manager_core::daemon_protocol::encode_line(&frame)
        .map_err(|_| "cannot encode Xray TUN config".to_string())?
        .len()
        > net_manager_core::daemon_protocol::MAX_FRAME_BYTES
    {
        return Err("Xray TUN config is too large for daemon protocol".into());
    }
    Ok(())
}

pub fn linux_xray_tunnel_status(status: XrayStatusResult, profile: &Profile) -> TunnelStatus {
    let mut notices = Vec::new();
    if status.state == TunnelState::Running && profile.routes.is_empty() {
        if !status.dns_applied {
            notices.push("Xray TUN DNS was not applied");
        }
        if !status.ipv4_covered {
            notices.push("IPv4 is not covered by this tunnel");
        }
        if !status.ipv6_covered {
            notices.push("IPv6 is not covered by this tunnel");
        }
    } else if status.state == TunnelState::Failed {
        notices.push("Xray TUN failed in network daemon");
    }
    TunnelStatus {
        profile_id: status.profile_id,
        state: status.state,
        message: (!notices.is_empty()).then(|| notices.join("; ")),
        interface_name: status.interface_name,
        failover: status.failover,
        watchdog: status.watchdog,
    }
}

/// Kernel interface-name hint for daemon-managed tunnels: an explicit
/// per-profile `interface_name` wins, otherwise the display name is offered
/// (the daemon sanitizes it and falls back to its deterministic name).
pub fn link_name_hint(profile: &Profile) -> Option<String> {
    let hint = if profile.interface_name.trim().is_empty() {
        &profile.name
    } else {
        &profile.interface_name
    };
    (!hint.trim().is_empty()).then(|| hint.trim().to_string())
}

pub fn linux_openvpn_tunnel_status(status: OpenVpnStatusResult) -> TunnelStatus {
    let state = match status.state {
        OpenVpnConnectionState::Stopped => TunnelState::Stopped,
        OpenVpnConnectionState::Connecting
        | OpenVpnConnectionState::Connected
        | OpenVpnConnectionState::Reconnecting => TunnelState::Running,
        OpenVpnConnectionState::Failed => TunnelState::Failed,
    };
    let mut notices = Vec::new();
    match status.state {
        OpenVpnConnectionState::Connecting => notices.push("OpenVPN is connecting"),
        OpenVpnConnectionState::Reconnecting => notices.push("OpenVPN is reconnecting"),
        OpenVpnConnectionState::Failed => {
            use net_manager_core::daemon_protocol::OpenVpnFailure as F;
            notices.push(match status.failure_reason {
                Some(F::AuthenticationFailure) => {
                    "OpenVPN authentication failed; check username, password, or private key passphrase"
                }
                Some(F::CredentialsRequired) => {
                    "OpenVPN server requested credentials that are not stored for this profile"
                }
                Some(F::ResolveError) => "OpenVPN could not resolve the server address",
                Some(F::ConnectError) => {
                    "OpenVPN could not reach the server (connection refused or timed out)"
                }
                Some(F::TlsError) => {
                    "OpenVPN TLS handshake failed; check CA, certificate, or tls-auth settings"
                }
                Some(F::ConnectionLost) => {
                    "OpenVPN connection was lost (timeout or connection reset)"
                }
                Some(F::ExitNotification) => {
                    "OpenVPN server asked the client to disconnect"
                }
                Some(F::Terminated) => "OpenVPN process was terminated",
                Some(F::ExitWithError) | None => {
                    if status
                        .warnings
                        .contains(&OpenVpnWarning::AuthenticationFailed)
                    {
                        "OpenVPN authentication failed; check username, password, or private key passphrase"
                    } else {
                        "OpenVPN connection failed; check credentials or server settings"
                    }
                }
            });
        }
        _ => {}
    }
    if status.warnings.contains(&OpenVpnWarning::DnsNotApplied) {
        notices.push("OpenVPN DNS was not applied");
    }
    if status.warnings.contains(&OpenVpnWarning::Ipv6NotCovered) {
        notices.push("IPv6 is not covered by this tunnel");
    }
    TunnelStatus {
        profile_id: status.profile_id,
        state,
        message: (!notices.is_empty()).then(|| notices.join("; ")),
        interface_name: status.interface_name,
        failover: None,
        watchdog: None,
    }
}

pub fn finish_openvpn_connect(status: OpenVpnStatusResult, notice: Option<&str>) -> TunnelStatus {
    let mut status = linux_openvpn_tunnel_status(status);
    if let Some(notice) = notice {
        status.message = Some(match status.message {
            Some(existing) => format!("{existing}; {notice}"),
            None => notice.to_string(),
        });
    }
    status
}

/// The managed OpenVPN config and its assets, checked to be the profile's own
/// regular files.
fn read_openvpn_inputs(
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
) -> Result<(String, std::collections::BTreeMap<String, Vec<u8>>), String> {
    if !vault.is_managed_profile_path(&profile.id, &profile.config_path) {
        return Err("OpenVPN profile must use its own managed config on Linux".into());
    }
    if !std::fs::symlink_metadata(&profile.config_path)
        .map_err(|_| "cannot inspect managed OpenVPN config".to_string())?
        .file_type()
        .is_file()
    {
        return Err("managed OpenVPN config is invalid".into());
    }
    let config = std::fs::read_to_string(&profile.config_path)
        .map_err(|_| "cannot read OpenVPN profile config".to_string())?;
    let mut raw_assets = std::collections::BTreeMap::new();
    let asset_dir = profile.config_path.parent().unwrap().join("assets");
    if asset_dir.exists() {
        if !std::fs::symlink_metadata(&asset_dir)
            .map_err(|_| "cannot inspect managed OpenVPN assets".to_string())?
            .file_type()
            .is_dir()
        {
            return Err("managed OpenVPN assets directory is invalid".into());
        }
        for entry in std::fs::read_dir(&asset_dir)
            .map_err(|_| "cannot read managed OpenVPN assets".to_string())?
        {
            let entry = entry.map_err(|_| "cannot read managed OpenVPN assets".to_string())?;
            let path = entry.path();
            if !vault.is_managed_profile_path(&profile.id, &path)
                || !entry
                    .file_type()
                    .map_err(|_| "cannot inspect managed OpenVPN asset".to_string())?
                    .is_file()
            {
                return Err("managed OpenVPN asset is invalid".into());
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "managed OpenVPN asset name is invalid".to_string())?;
            let bytes = std::fs::read(&path)
                .map_err(|_| "cannot read managed OpenVPN asset".to_string())?;
            raw_assets.insert(format!("assets/{name}"), bytes);
        }
    }
    Ok((config, raw_assets))
}

/// What the profile's OpenVPN config asks the user for.
pub fn openvpn_requirements(
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
) -> Result<OpenVpnCredentialRequirements, String> {
    let (config, assets) = read_openvpn_inputs(vault, profile)?;
    Ok(openvpn_credential_requirements(&config, &assets))
}

/// Builds the daemon request; the notice reports a credential migration.
pub fn prepare_linux_openvpn_request(
    vault: &net_manager_core::config_vault::ConfigVault,
    credential_store: &dyn CredentialSource,
    profile: &Profile,
    supplied_credentials: Option<OpenVpnCredentials>,
    routes: Vec<PolicyRoute>,
    method_name: &str,
) -> Result<(OpenVpnConnectRequest, Option<&'static str>), String> {
    let (config, raw_assets) = read_openvpn_inputs(vault, profile)?;
    let requirements = openvpn_credential_requirements(&config, &raw_assets);
    let mut notice = None;
    let credentials = if supplied_credentials.is_some() {
        supplied_credentials
    } else if requirements.user_pass || requirements.key_passphrase {
        let (remembered, load_notice) = credential_store
            .load(&profile.id, &openvpn_credentials_path(vault, profile)?)
            .map_err(|_| "OpenVPN credentials required".to_string())?;
        notice = load_notice;
        remembered
    } else {
        None
    };
    if requirements.user_pass
        && credentials
            .as_ref()
            .is_none_or(|value| value.auth_user_pass.is_none())
        || requirements.key_passphrase
            && credentials
                .as_ref()
                .is_none_or(|value| value.private_key_passphrase.is_none())
    {
        return Err("OpenVPN credentials required".into());
    }
    if let Some(credentials) = &credentials {
        if requirements.user_pass != credentials.auth_user_pass.is_some()
            || (!requirements.key_passphrase && credentials.private_key_passphrase.is_some())
            || net_manager_core::openvpn_management::validate_openvpn_credentials(credentials)
                .is_err()
        {
            return Err("OpenVPN credentials are invalid for this profile".into());
        }
    }
    let assets = raw_assets
        .into_iter()
        .map(|(name, bytes)| {
            (
                name,
                base64::engine::general_purpose::STANDARD.encode(bytes),
            )
        })
        .collect();
    let params = OpenVpnConnectParams {
        profile_id: profile.id.clone(),
        config,
        assets,
        routes,
        interface_name: link_name_hint(profile),
        role: profile.tunnel_role,
        dns_domains: profile.tunnel_dns_domains.clone(),
    };
    let request = OpenVpnConnectRequest {
        profile: params,
        credentials: credentials.clone(),
    };
    let frame = net_manager_core::daemon_protocol::RequestFrame {
        id: 2,
        method: method_name.into(),
        params: serde_json::to_value(&request)
            .map_err(|_| "cannot encode OpenVPN config for daemon".to_string())?,
    };
    if net_manager_core::daemon_protocol::encode_line(&frame)
        .map_err(|_| "cannot encode OpenVPN config for daemon".to_string())?
        .len()
        > net_manager_core::daemon_protocol::MAX_FRAME_BYTES
    {
        return Err("OpenVPN config too large for daemon protocol".into());
    }
    Ok((request, notice))
}

pub fn linux_wireguard_tunnel_status(status: WireGuardStatusResult) -> TunnelStatus {
    let mut notices = Vec::new();
    if status.warnings.contains(&WireGuardWarning::IgnoredHook) {
        notices.push("WireGuard hooks were ignored");
    }
    if status
        .warnings
        .contains(&WireGuardWarning::IgnoredSaveConfig)
    {
        notices.push("WireGuard SaveConfig was ignored");
    }
    if status.warnings.contains(&WireGuardWarning::DnsNotApplied) {
        notices.push("WireGuard DNS was not applied");
    }
    if status.warnings.contains(&WireGuardWarning::Ipv6NotCovered) {
        notices.push("IPv6 is not covered by this tunnel");
    }
    TunnelStatus {
        profile_id: status.profile_id,
        state: status.state,
        message: (!notices.is_empty()).then(|| notices.join("; ")),
        interface_name: status.interface_name,
        failover: None,
        watchdog: None,
    }
}
