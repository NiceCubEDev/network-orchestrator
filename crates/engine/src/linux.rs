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

/// Remembered OpenVPN credentials. Linux frontends share the Secret Service
/// adapter in `linux_credentials`; root callers use no remembered credentials.
pub trait CredentialSource {
    /// Remembered credentials plus an optional user notice. `legacy` is the
    /// old plaintext file, migrated and deleted on first access.
    fn load(
        &self,
        profile_id: &str,
        legacy: &std::path::Path,
    ) -> Result<(Option<OpenVpnCredentials>, Option<&'static str>), String>;
}

impl CredentialSource for () {
    fn load(
        &self,
        _: &str,
        _: &std::path::Path,
    ) -> Result<(Option<OpenVpnCredentials>, Option<&'static str>), String> {
        Ok((None, None))
    }
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
    let (mut config, failover) = if multinode {
        build_multinode(vault, profile)?
    } else {
        (config, None)
    };
    // Named `netorch proxy` exits: dedicated pin-<key> outbounds appended
    // after everything else — the default route and failover stay as built.
    net_manager_core::proxy_exits::append_named_proxy_outbounds(vault, profile, &mut config)?;
    let default_route = profile.tunnel_role == TunnelRole::Primary && profile.routes.is_empty();
    let routes = net_manager_core::connect_plan::linux_xray_tun_routes(profile);
    if profile.xray_dns.fake_dns {
        configure_linux_fake_dns(&mut config, &routes, profile.xray_dns.query_strategy)?;
    }
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
        proxy_exits: profile.xray_proxy_exits.clone(),
    };
    check_xray_frame_size(&params)?;
    Ok(params)
}

fn configure_linux_fake_dns(
    config: &mut serde_json::Value,
    routes: &[PolicyRoute],
    strategy: Option<XrayDnsQueryStrategy>,
) -> Result<(), String> {
    let destinations: Vec<_> = routes
        .iter()
        .map(|route| route.destination.trunc())
        .collect();
    let destinations = ipnet::IpNet::aggregate(&destinations);
    let captured = |pool: ipnet::IpNet| {
        destinations
            .iter()
            .any(|route| route.prefix_len() <= pool.prefix_len() && route.contains(&pool.network()))
    };
    let ipv4 = captured("198.18.0.0/16".parse().unwrap());
    let ipv6 = captured("fc00::/18".parse().unwrap());
    if !ipv4 && !ipv6 {
        return Err(
            "Xray fake DNS requires routes covering a complete synthetic address pool".into(),
        );
    }
    if strategy == Some(XrayDnsQueryStrategy::UseIpv4) && !ipv4
        || strategy == Some(XrayDnsQueryStrategy::UseIpv6) && !ipv6
    {
        return Err("Xray fake DNS query strategy requires a captured pool in that family".into());
    }
    let mut pools = Vec::with_capacity(usize::from(ipv4) + usize::from(ipv6));
    if ipv4 {
        pools.push(serde_json::json!({ "ipPool": "198.18.0.0/16", "poolSize": 65535 }));
    }
    if ipv6 {
        pools.push(serde_json::json!({ "ipPool": "fc00::/18", "poolSize": 65535 }));
    }
    config["fakedns"] = serde_json::Value::Array(pools);
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::config_vault::ConfigVault;
    use net_manager_core::profile_import::import_share_link;
    use net_manager_core::profiles::ProfileStore;

    fn generated_tun_profile() -> (tempfile::TempDir, ConfigVault, Profile) {
        let directory = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(directory.path().join("configs"));
        let store = ProfileStore::new(directory.path().join("profiles.json"));
        import_share_link(
            &vault,
            &store,
            "ipv6-tun",
            "IPv6 TUN fixture",
            "vless://synthetic-id@node.test:443?security=tls#IPv6",
            net_manager_core::models::XrayMode::platform_default(),
            |_| true,
        )
        .unwrap();
        let mut profile = store.load().unwrap().profiles.remove(0);
        profile.xray_mode = XrayMode::Tun;
        (directory, vault, profile)
    }

    fn route(destination: &str) -> PolicyRoute {
        PolicyRoute {
            destination: destination.parse().unwrap(),
            metric: 5,
            via: None,
        }
    }

    #[test]
    fn xray_tun_default_primary_captures_both_route_families() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        profile.tunnel_role = TunnelRole::Primary;
        profile.routes.clear();
        profile.xray_split_default = false;

        let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();

        assert_eq!(params.routes.len(), 2);
        for destination in ["0.0.0.0/0", "::/0"] {
            let route = params
                .routes
                .iter()
                .find(|route| route.destination == destination.parse().unwrap())
                .expect("default route must cover each address family");
            assert_eq!(route.via, None);
        }
        assert_eq!(params.role, TunnelRole::Primary);
    }

    #[test]
    fn xray_tun_split_default_captures_four_halves() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        profile.tunnel_role = TunnelRole::Primary;
        profile.routes.clear();
        profile.xray_split_default = true;

        let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();

        assert_eq!(params.routes.len(), 4);
        for destination in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
            let route = params
                .routes
                .iter()
                .find(|route| route.destination == destination.parse().unwrap())
                .expect("split-default must cover both halves of each address family");
            assert_eq!(route.via, None);
        }
    }

    #[test]
    fn xray_tun_explicit_single_family_routes_are_not_expanded() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        for (destination, via) in [
            ("0.0.0.0/0", "192.0.2.1"),
            ("::/0", "2001:db8::1"),
            ("10.20.0.0/16", "192.0.2.1"),
            ("2001:db8:20::/48", "2001:db8::1"),
        ] {
            let mut explicit = route(destination);
            explicit.metric = 37;
            explicit.via = Some(via.parse().unwrap());
            profile.routes = vec![explicit.clone()];
            for split_default in [false, true] {
                profile.xray_split_default = split_default;

                let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();

                assert_eq!(
                    params.routes,
                    vec![explicit.clone()],
                    "explicit {destination}, split-default {split_default}"
                );
                assert!(params.dns_servers.is_empty());
            }
        }
    }

    #[test]
    fn xray_tun_explicit_partial_dual_family_routes_stay_scoped() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        let expected = vec![route("10.20.0.0/16"), route("2001:db8:20::/48")];
        profile.routes = expected.clone();
        for split_default in [false, true] {
            profile.xray_split_default = split_default;

            let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();

            assert_eq!(params.routes, expected);
            assert!(params.dns_servers.is_empty());
        }
    }

    #[test]
    fn xray_tun_secondary_routes_stay_scoped_to_its_networks() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        profile.tunnel_role = TunnelRole::Secondary;
        profile.routes = vec![route("0.0.0.0/0"), route("::/0")];
        for networks in [
            vec!["10.20.0.0/16"],
            vec!["2001:db8:20::/48"],
            vec!["10.20.0.0/16", "2001:db8:20::/48"],
        ] {
            profile.tunnel_networks = networks
                .iter()
                .map(|network| network.parse().unwrap())
                .collect();
            let expected: Vec<_> = networks.iter().map(|network| route(network)).collect();
            for split_default in [false, true] {
                profile.xray_split_default = split_default;

                let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();

                assert_eq!(params.routes, expected);
                assert_eq!(params.role, TunnelRole::Secondary);
                assert!(params.dns_servers.is_empty());
            }
        }
    }

    #[test]
    fn xray_tun_empty_secondary_routes_do_not_become_full_tunnel() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        profile.tunnel_role = TunnelRole::Secondary;
        profile.routes = vec![route("0.0.0.0/0"), route("::/0")];
        profile.tunnel_networks.clear();
        for split_default in [false, true] {
            profile.xray_split_default = split_default;

            let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();

            assert!(params.routes.is_empty());
            assert!(params.dns_servers.is_empty());
        }
    }

    #[test]
    fn xray_tun_fake_dns_only_uses_captured_families() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        profile.xray_dns.fake_dns = true;
        for (destinations, ipv4, ipv6) in [
            (vec!["0.0.0.0/0"], true, false),
            (vec!["::/0"], false, true),
            (vec![], true, true),
            (
                vec![
                    "198.18.0.0/17",
                    "198.18.128.0/17",
                    "fc00::/19",
                    "fc00:2000::/19",
                ],
                true,
                true,
            ),
        ] {
            profile.routes = destinations
                .iter()
                .map(|destination| route(destination))
                .collect();
            for split_default in [false, true] {
                profile.xray_split_default = split_default;
                for (strategy, expected) in [
                    (None, None),
                    (Some(XrayDnsQueryStrategy::UseIp), Some("UseIP")),
                    (Some(XrayDnsQueryStrategy::UseIpv4), Some("UseIPv4")),
                    (Some(XrayDnsQueryStrategy::UseIpv6), Some("UseIPv6")),
                ] {
                    if strategy == Some(XrayDnsQueryStrategy::UseIpv4) && !ipv4
                        || strategy == Some(XrayDnsQueryStrategy::UseIpv6) && !ipv6
                    {
                        continue;
                    }
                    profile.xray_dns.query_strategy = strategy;
                    let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();
                    let config: serde_json::Value = serde_json::from_str(&params.config).unwrap();
                    let pools = config["fakedns"].as_array().unwrap();
                    let mut has_ipv4 = false;
                    let mut has_ipv6 = false;
                    for pool in pools {
                        let destination = route(pool["ipPool"].as_str().unwrap()).destination;
                        assert!(matches!(pool["poolSize"].as_u64(), Some(1..=65535)));
                        match destination.network() {
                            std::net::IpAddr::V4(_) => has_ipv4 = true,
                            std::net::IpAddr::V6(_) => has_ipv6 = true,
                        }
                    }
                    assert_eq!((has_ipv4, has_ipv6), (ipv4, ipv6));
                    assert_eq!(
                        config["dns"].get("queryStrategy"),
                        expected
                            .map(|strategy| serde_json::json!(strategy))
                            .as_ref()
                    );
                    if !profile.routes.is_empty() {
                        assert_eq!(params.routes, profile.routes);
                    }
                }
            }
        }
    }

    #[test]
    fn xray_tun_fake_dns_rejects_uncaptured_pools() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        profile.xray_dns.fake_dns = true;
        for destinations in [
            vec!["10.20.0.0/16", "2001:db8::/32"],
            vec!["198.18.0.0/17"],
            vec!["fc00::/19"],
        ] {
            profile.routes = destinations
                .iter()
                .map(|destination| route(destination))
                .collect();
            assert!(prepare_linux_xray_tun_params(&vault, &profile).is_err());
        }
    }

    #[test]
    fn xray_tun_fake_dns_rejects_uncaptured_query_family() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        profile.xray_dns.fake_dns = true;
        for (destination, strategy) in [
            ("0.0.0.0/0", XrayDnsQueryStrategy::UseIpv6),
            ("::/0", XrayDnsQueryStrategy::UseIpv4),
        ] {
            profile.routes = vec![route(destination)];
            profile.xray_dns.query_strategy = Some(strategy);
            assert!(prepare_linux_xray_tun_params(&vault, &profile).is_err());
        }
    }

    #[test]
    fn xray_tun_explicit_dns_query_strategy_is_preserved() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        for (strategy, expected) in [
            (XrayDnsQueryStrategy::UseIp, "UseIP"),
            (XrayDnsQueryStrategy::UseIpv4, "UseIPv4"),
            (XrayDnsQueryStrategy::UseIpv6, "UseIPv6"),
        ] {
            profile.xray_dns.query_strategy = Some(strategy);

            let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();
            let config: serde_json::Value = serde_json::from_str(&params.config).unwrap();

            assert_eq!(config["dns"]["queryStrategy"], expected);
        }
    }

    #[test]
    fn xray_tun_explicit_dual_family_dns_servers_are_captured() {
        let (_directory, vault, mut profile) = generated_tun_profile();
        profile.xray_tun_dns_servers = vec![
            "192.0.2.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ];
        for split_default in [false, true] {
            profile.xray_split_default = split_default;

            let params = prepare_linux_xray_tun_params(&vault, &profile).unwrap();

            assert_eq!(params.dns_servers, profile.xray_tun_dns_servers);
            for server in &params.dns_servers {
                assert!(
                    params
                        .routes
                        .iter()
                        .any(|route| route.destination.contains(server)),
                    "DNS server {server} must be covered, split-default {split_default}"
                );
            }
        }
    }
}
