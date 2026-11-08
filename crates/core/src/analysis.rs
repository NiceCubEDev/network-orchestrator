use crate::config_vault::{inline_tag, tokenize_line, SCRIPT_DIRECTIVES};
use crate::models::{
    AnalyzedRoute, ConfigAnalysis, ConfigField, ConfigPeer, ConflictKind, LocalListener, Profile,
    ProfileConflict, RemoteEndpoint, RouteEntry, TunnelBackend,
};
use ipnet::{IpNet, Ipv4Net};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

pub fn analyze_profile(profile: &Profile) -> io::Result<ConfigAnalysis> {
    analyze_with_xray_snapshot(profile, None)
}

/// Analyze retained Xray input without consulting a mutable managed revision.
pub fn analyze_xray_snapshot(profile: &Profile, bytes: &[u8]) -> io::Result<ConfigAnalysis> {
    if profile.backend != TunnelBackend::Xray {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot analysis requires an Xray profile",
        ));
    }
    analyze_with_xray_snapshot(profile, Some(bytes))
}

fn analyze_with_xray_snapshot(
    profile: &Profile,
    bytes: Option<&[u8]>,
) -> io::Result<ConfigAnalysis> {
    let mut analysis = ConfigAnalysis {
        profile_id: profile.id.clone(),
        os_routes: Vec::new(),
        internal_routes: Vec::new(),
        listeners: Vec::new(),
        endpoints: Vec::new(),
        domain_patterns: Vec::new(),
        warnings: Vec::new(),
        route_knowledge_complete: true,
        peers: Vec::new(),
        interface_details: Vec::new(),
    };
    for route in &profile.routes {
        analysis.os_routes.push(AnalyzedRoute {
            metric: Some(route.metric),
            destination: route.destination,
            source: "profile policy".to_string(),
        });
    }
    match profile.backend {
        TunnelBackend::None => {}
        TunnelBackend::WireGuard => analyze_wireguard(&profile.config_path, &mut analysis)?,
        TunnelBackend::OpenVpn => analyze_openvpn(&profile.config_path, &mut analysis)?,
        TunnelBackend::Xray => match bytes {
            Some(bytes) => analyze_xray_bytes(profile, bytes, &mut analysis)?,
            None => analyze_xray(profile, &mut analysis)?,
        },
    }
    if profile.tunnel_role == crate::models::TunnelRole::Secondary {
        // The privileged side installs exactly the listed networks and ignores
        // what the config would route, so that is what can conflict.
        analysis.os_routes = profile
            .secondary_routes()
            .into_iter()
            .map(|route| AnalyzedRoute {
                metric: Some(route.metric),
                destination: route.destination,
                source: "secondary tunnel".to_string(),
            })
            .collect();
    }
    for policy in &profile.domain_policies {
        analysis
            .domain_patterns
            .extend(policy.domains.iter().cloned());
    }
    dedup(&mut analysis.os_routes);
    dedup(&mut analysis.internal_routes);
    dedup(&mut analysis.listeners);
    dedup(&mut analysis.endpoints);
    dedup(&mut analysis.domain_patterns);
    Ok(analysis)
}

pub fn conflicts_between(
    candidate: &ConfigAnalysis,
    other: &ConfigAnalysis,
    blocking: bool,
) -> Vec<ProfileConflict> {
    let mut conflicts = Vec::new();
    let mut seen = HashSet::new();
    for route in &candidate.os_routes {
        for other_route in &other.os_routes {
            if !prefixes_overlap(route.destination, other_route.destination) {
                continue;
            }
            if route.destination == other_route.destination {
                let message = format!(
                    "route {} overlaps {} ({}) in profile '{}'",
                    route.destination,
                    other_route.destination,
                    other_route.source,
                    other.profile_id
                );
                if seen.insert(message.clone()) {
                    conflicts.push(ProfileConflict {
                        kind: ConflictKind::RouteOverlap,
                        message,
                        other_profile_id: Some(other.profile_id.clone()),
                        blocking,
                    });
                }
                continue;
            }
            let wg_killswitch = (route.destination.prefix_len() == 0
                && route.source == "WireGuard AllowedIPs")
                || (other_route.destination.prefix_len() == 0
                    && other_route.source == "WireGuard AllowedIPs");
            if blocking && !wg_killswitch {
                continue;
            }
            let (more, less) =
                if route.destination.prefix_len() > other_route.destination.prefix_len() {
                    (route, other_route)
                } else {
                    (other_route, route)
                };
            let message = if wg_killswitch {
                format!(
                    "WireGuard default route {} ({}) may act as a kill-switch and prevent the more-specific route {} ({}) from working in profile '{}'",
                    less.destination,
                    less.source,
                    more.destination,
                    more.source,
                    other.profile_id
                )
            } else {
                format!(
                    "route {} ({}) is more specific and takes precedence by longest-prefix match over {} ({}) in profile '{}'",
                    more.destination,
                    more.source,
                    less.destination,
                    less.source,
                    other.profile_id
                )
            };
            if seen.insert(message.clone()) {
                conflicts.push(ProfileConflict {
                    kind: ConflictKind::RouteOverlap,
                    message,
                    other_profile_id: Some(other.profile_id.clone()),
                    blocking,
                });
            }
        }
    }
    for listener in &candidate.listeners {
        for other_listener in &other.listeners {
            if listener.port == other_listener.port
                && listeners_collide(&listener.address, &other_listener.address)
            {
                let message = format!(
                    "{} listener {}:{} collides with {}:{} in profile '{}'",
                    listener.protocol,
                    listener.address,
                    listener.port,
                    other_listener.address,
                    other_listener.port,
                    other.profile_id
                );
                if seen.insert(message.clone()) {
                    conflicts.push(ProfileConflict {
                        kind: ConflictKind::ListenerCollision,
                        message,
                        other_profile_id: Some(other.profile_id.clone()),
                        blocking,
                    });
                }
            }
        }
    }
    conflicts
}

pub fn warnings_against_os_routes(
    candidate: &ConfigAnalysis,
    routes: &[RouteEntry],
) -> Vec<ProfileConflict> {
    let os_nets: Vec<(IpNet, &RouteEntry)> = routes
        .iter()
        .filter_map(|entry| {
            IpNet::new(entry.destination, entry.prefix_len)
                .ok()
                .map(|net| (net, entry))
        })
        .collect();
    let mut warnings = Vec::new();
    let mut seen = HashSet::new();
    for route in &candidate.os_routes {
        if route.destination.prefix_len() == 0 {
            let message = format!(
                "route {} adds a default route that captures all traffic",
                route.destination
            );
            if seen.insert(message.clone()) {
                warnings.push(os_warning(message));
            }
            continue;
        }
        for (net, entry) in &os_nets {
            if net.prefix_len() == 0 {
                continue;
            }
            if prefixes_overlap(route.destination, *net) {
                let message = format!(
                    "route {} overlaps existing OS route {} on '{}'",
                    route.destination, net, entry.interface_name
                );
                if seen.insert(message.clone()) {
                    warnings.push(os_warning(message));
                }
            }
        }
    }
    warnings
}

pub fn prefixes_overlap(a: IpNet, b: IpNet) -> bool {
    match (a, b) {
        (IpNet::V4(a), IpNet::V4(b)) => a.contains(&b.network()) || b.contains(&a.network()),
        (IpNet::V6(a), IpNet::V6(b)) => a.contains(&b.network()) || b.contains(&a.network()),
        _ => false,
    }
}

fn os_warning(message: String) -> ProfileConflict {
    ProfileConflict {
        kind: ConflictKind::RouteOverlap,
        message,
        other_profile_id: None,
        blocking: false,
    }
}

fn listeners_collide(a: &str, b: &str) -> bool {
    let a = a.trim();
    let b = b.trim();
    a == b || matches!(a, "" | "0.0.0.0" | "::") || matches!(b, "" | "0.0.0.0" | "::")
}

fn dedup<T: PartialEq>(items: &mut Vec<T>) {
    let mut unique = Vec::with_capacity(items.len());
    for item in items.drain(..) {
        if !unique.contains(&item) {
            unique.push(item);
        }
    }
    *items = unique;
}

fn read_config(path: &Path) -> io::Result<String> {
    fs::read_to_string(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot read config '{}': {err}", path.display()),
        )
    })
}

fn analyze_wireguard(path: &Path, analysis: &mut ConfigAnalysis) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let text = if name.ends_with(".dpapi") {
        match std::fs::read(path)
            .map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!("cannot read config '{}': {err}", path.display()),
                )
            })
            .and_then(|bytes| {
                // WireGuard `.conf.dpapi` files are encrypted with machine-scope
                // DPAPI (no entropy) by the tunnel service. Any process on the
                // machine can decrypt them via CryptUnprotectData.
                crate::config_security::unprotect_machine_data(&bytes)
            }) {
            Ok(plaintext) => String::from_utf8_lossy(&plaintext).to_string(),
            Err(_) => {
                analysis
                    .warnings
                    .push("encrypted WireGuard config cannot be statically analyzed".to_string());
                analysis.route_knowledge_complete = false;
                return Ok(());
            }
        }
    } else {
        read_config(path)?
    };
    parse_wireguard_text(&text, analysis);
    Ok(())
}

fn parse_wireguard_text(text: &str, analysis: &mut ConfigAnalysis) {
    let mut section = String::new();
    let mut table_off = false;
    let mut allowed: Vec<AnalyzedRoute> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_lowercase();
            if section == "peer" {
                analysis.peers.push(ConfigPeer {
                    endpoint: None,
                    routes: Vec::new(),
                });
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim();
        match (section.as_str(), key.as_str()) {
            ("interface", "table") => {
                if value.eq_ignore_ascii_case("off") {
                    table_off = true;
                }
            }
            ("interface", "address" | "dns") => {
                let field = if key == "dns" { "dns" } else { "address" };
                for part in value.split(',') {
                    let part = part.trim();
                    if !part.is_empty() {
                        analysis.interface_details.push(ConfigField {
                            field: field.to_string(),
                            value: part.to_string(),
                        });
                    }
                }
            }
            ("interface", "mtu" | "listenport") => {
                analysis.interface_details.push(ConfigField {
                    field: if key == "mtu" { "mtu" } else { "listenPort" }.to_string(),
                    value: value.to_string(),
                });
            }
            ("peer", "allowedips") => {
                for part in value.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    match part.parse::<IpNet>() {
                        Ok(destination) => {
                            let route = AnalyzedRoute {
                                metric: None,
                                destination,
                                source: "WireGuard AllowedIPs".to_string(),
                            };
                            if let Some(peer) = analysis.peers.last_mut() {
                                peer.routes.push(route.clone());
                            }
                            allowed.push(route);
                        }
                        Err(_) => analysis
                            .warnings
                            .push(format!("line {line_no}: invalid AllowedIPs entry")),
                    }
                }
            }
            ("peer", "endpoint") => match parse_endpoint(value) {
                Some((host, port)) => {
                    let endpoint = RemoteEndpoint {
                        address: host,
                        port: Some(port),
                        protocol: "wireguard".to_string(),
                    };
                    if let Some(peer) = analysis.peers.last_mut() {
                        peer.endpoint = Some(endpoint.clone());
                    }
                    analysis.endpoints.push(endpoint);
                }
                None => analysis
                    .warnings
                    .push(format!("line {line_no}: invalid Endpoint")),
            },
            _ => {}
        }
    }
    if !table_off {
        analysis.os_routes.extend(allowed);
    }
}

fn parse_endpoint(value: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        (host, port)
    } else {
        value.rsplit_once(':')?
    };
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.trim().parse().ok()?;
    Some((host.to_string(), port))
}

fn analyze_openvpn(path: &Path, analysis: &mut ConfigAnalysis) -> io::Result<()> {
    let text = read_config(path)?;
    let mut in_block: Option<String> = None;
    let mut push_warned = false;
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let tokens = tokenize_line(raw);
        if let Some(tag) = &in_block {
            if let Some((true, close)) = tokens.first().and_then(|t| inline_tag(t)) {
                if close.eq_ignore_ascii_case(tag) {
                    in_block = None;
                }
            }
            continue;
        }
        if tokens.is_empty() {
            continue;
        }
        if let Some((false, open)) = inline_tag(&tokens[0]) {
            in_block = Some(open.to_lowercase());
            continue;
        }
        let directive = tokens[0].trim_start_matches('-').to_lowercase();
        match directive.as_str() {
            "route" => match parse_openvpn_route(&tokens) {
                Some(destination) => analysis.os_routes.push(AnalyzedRoute {
                    metric: None,
                    destination,
                    source: "OpenVPN route".to_string(),
                }),
                None => analysis
                    .warnings
                    .push(format!("line {line_no}: invalid route directive")),
            },
            "route-ipv6" => match tokens.get(1).and_then(|t| t.parse::<IpNet>().ok()) {
                Some(destination @ IpNet::V6(_)) => analysis.os_routes.push(AnalyzedRoute {
                    metric: None,
                    destination,
                    source: "OpenVPN route".to_string(),
                }),
                _ => analysis
                    .warnings
                    .push(format!("line {line_no}: invalid route-ipv6 directive")),
            },
            "redirect-gateway" => analysis.os_routes.push(AnalyzedRoute {
                metric: None,
                destination: IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
                source: "OpenVPN route".to_string(),
            }),
            "redirect-gateway-ipv6" => analysis.os_routes.push(AnalyzedRoute {
                metric: None,
                destination: net6_any(),
                source: "OpenVPN route".to_string(),
            }),
            "remote" => {
                let Some(host) = tokens.get(1) else {
                    continue;
                };
                let port = tokens.get(2).and_then(|t| t.parse::<u16>().ok());
                let protocol = tokens
                    .get(if port.is_some() { 3 } else { 2 })
                    .cloned()
                    .unwrap_or_else(|| "openvpn".to_string());
                analysis.endpoints.push(RemoteEndpoint {
                    address: host.clone(),
                    port,
                    protocol,
                });
            }
            "proto" | "dev" | "cipher" | "port" => {
                if let Some(value) = tokens.get(1) {
                    let field = match directive.as_str() {
                        "proto" => "protocol",
                        "dev" => "device",
                        "port" => "listenPort",
                        _ => "cipher",
                    };
                    analysis.interface_details.push(ConfigField {
                        field: field.to_string(),
                        value: value.clone(),
                    });
                }
            }
            "auth-user-pass" => analysis.interface_details.push(ConfigField {
                field: "authUserPass".to_string(),
                value: "required".to_string(),
            }),
            "client" | "pull" if !push_warned => {
                push_warned = true;
                analysis.route_knowledge_complete = false;
                analysis.warnings.push(
                    "OpenVPN server-pushed routes cannot be known before connection".to_string(),
                );
            }
            name if SCRIPT_DIRECTIVES.contains(&name) => {
                let message = format!(
                    "directive '{name}' references an external or executable item that requires review"
                );
                if !analysis.warnings.contains(&message) {
                    analysis.warnings.push(message);
                }
            }
            _ => {}
        }
    }
    if in_block.is_some() {
        analysis
            .warnings
            .push("unterminated inline block".to_string());
    }
    Ok(())
}

fn net6_any() -> IpNet {
    "::/0".parse().unwrap()
}

fn parse_openvpn_route(tokens: &[String]) -> Option<IpNet> {
    let network = tokens.get(1)?;
    if let Ok(net) = network.parse::<IpNet>() {
        return Some(net);
    }
    let address = network.parse::<Ipv4Addr>().ok()?;
    match tokens.get(2) {
        None => Ipv4Net::new(address, 32).ok().map(IpNet::V4),
        Some(mask) => {
            let mask = mask.parse::<Ipv4Addr>().ok()?;
            Ipv4Net::with_netmask(address, mask).ok().map(IpNet::V4)
        }
    }
}

fn analyze_xray(profile: &Profile, analysis: &mut ConfigAnalysis) -> io::Result<()> {
    let bytes = crate::config_security::read_xray_config(&profile.config_path, &profile.id)?;
    analyze_xray_bytes(profile, &bytes, analysis)
}

fn analyze_xray_bytes(
    profile: &Profile,
    bytes: &[u8],
    analysis: &mut ConfigAnalysis,
) -> io::Result<()> {
    let root: Value = serde_json::from_slice(bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid JSON in '{}': {err}", profile.config_path.display()),
        )
    })?;

    if let Some(rules) = root
        .get("routing")
        .and_then(|r| r.get("rules"))
        .and_then(Value::as_array)
    {
        for rule in rules {
            if let Some(ips) = rule.get("ip").and_then(Value::as_array) {
                for entry in ips {
                    match entry.as_str().and_then(parse_xray_ip) {
                        Some(destination) => analysis.internal_routes.push(AnalyzedRoute {
                            metric: None,
                            destination,
                            source: "Xray routing rule".to_string(),
                        }),
                        None => {
                            let message = "unrecognized Xray routing ip entry".to_string();
                            if !analysis.warnings.contains(&message) {
                                analysis.warnings.push(message);
                            }
                        }
                    }
                }
            }
            if let Some(domains) = rule.get("domain").and_then(Value::as_array) {
                for domain in domains {
                    if let Some(pattern) = domain.as_str() {
                        analysis.domain_patterns.push(pattern.to_string());
                    }
                }
            }
        }
    }

    if let Some(inbounds) = root.get("inbounds").and_then(Value::as_array) {
        for inbound in inbounds {
            let protocol = inbound
                .get("protocol")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("xray")
                .to_string();
            // TUN inbound captures all IP traffic at the interface level,
            // making Xray a full-tunnel backend. Treat it as a 0.0.0.0/0 OS
            // route so conflict detection and route maps account for it.
            if protocol == "tun" {
                analysis.os_routes.push(AnalyzedRoute {
                    metric: None,
                    destination: IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
                    source: "Xray TUN".to_string(),
                });
                continue;
            }
            match inbound.get("port").and_then(json_port) {
                Some(port) => {
                    let address = inbound
                        .get("listen")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("0.0.0.0")
                        .to_string();
                    analysis.listeners.push(LocalListener {
                        address,
                        port,
                        protocol,
                    });
                }
                None => analysis
                    .warnings
                    .push("Xray inbound is missing a valid port".to_string()),
            }
        }
    }

    // Managed Linux capture must match the actual scoped or dual-stack request.
    // Secondary routes are assigned by analyze_profile after config analysis.
    #[cfg(target_os = "linux")]
    if profile.xray_mode == crate::models::XrayMode::Tun
        && profile.tunnel_role == crate::models::TunnelRole::Primary
    {
        analysis.os_routes.clear();
        analysis.os_routes.extend(
            crate::connect_plan::linux_xray_tun_routes(profile)
                .into_iter()
                .map(|route| AnalyzedRoute {
                    metric: Some(route.metric),
                    destination: route.destination,
                    source: "Xray TUN".to_string(),
                }),
        );
    }
    // Other platforms retain their existing capture contract.
    #[cfg(not(target_os = "linux"))]
    if profile.xray_mode == crate::models::XrayMode::Tun
        && !analysis.os_routes.iter().any(|r| r.source == "Xray TUN")
    {
        analysis.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
            source: "Xray TUN".to_string(),
        });
    }

    if let Some(outbounds) = root.get("outbounds").and_then(Value::as_array) {
        for outbound in outbounds {
            let Some(protocol) = outbound.get("protocol").and_then(Value::as_str) else {
                continue;
            };
            if !matches!(protocol, "vless" | "vmess" | "trojan" | "shadowsocks") {
                continue;
            }
            let settings = outbound.get("settings");
            let server = ["vnext", "servers"].iter().find_map(|key| {
                settings
                    .and_then(|s| s.get(*key))
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
            });
            if let Some(server) = server {
                if let Some(address) = server.get("address").and_then(Value::as_str) {
                    analysis.endpoints.push(RemoteEndpoint {
                        address: address.to_string(),
                        port: server.get("port").and_then(json_port),
                        protocol: protocol.to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn parse_xray_ip(entry: &str) -> Option<IpNet> {
    let entry = entry.trim();
    if let Ok(net) = entry.parse::<IpNet>() {
        return Some(net);
    }
    entry.parse::<std::net::IpAddr>().ok().map(|ip| match ip {
        std::net::IpAddr::V4(a) => IpNet::V4(Ipv4Net::new(a, 32).unwrap()),
        std::net::IpAddr::V6(_) => IpNet::new(ip, 128).unwrap(),
    })
}

fn json_port(value: &Value) -> Option<u16> {
    value.as_u64().and_then(|n| u16::try_from(n).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AnalyzedRoute, ConflictKind, DomainPolicy, DomainRouteTarget, LocalListener, PolicyRoute,
        TunnelBackend, XrayMode,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-analysis-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn profile(backend: TunnelBackend, path: &Path) -> Profile {
        Profile {
            id: "p1".into(),
            name: "P".into(),
            backend,
            config_path: path.to_path_buf(),
            interface_name: "tun0".into(),
            ..Default::default()
        }
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn destinations(routes: &[AnalyzedRoute]) -> Vec<IpNet> {
        routes.iter().map(|r| r.destination).collect()
    }

    fn os_route(dest: &str) -> RouteEntry {
        RouteEntry {
            destination: dest.split('/').next().unwrap().parse().unwrap(),
            prefix_len: dest.split('/').nth(1).unwrap().parse().unwrap(),
            gateway: None,
            interface_index: 5,
            interface_name: "Ethernet".into(),
            metric: 10,
        }
    }

    fn empty_analysis(id: &str) -> ConfigAnalysis {
        ConfigAnalysis {
            profile_id: id.into(),
            os_routes: vec![],
            internal_routes: vec![],
            listeners: vec![],
            endpoints: vec![],
            domain_patterns: vec![],
            warnings: vec![],
            route_knowledge_complete: true,
            peers: Vec::new(),
            interface_details: Vec::new(),
        }
    }

    fn analysis_with_route(id: &str, dest: &str, source: &str) -> ConfigAnalysis {
        let mut a = empty_analysis(id);
        a.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: net(dest),
            source: source.into(),
        });
        a
    }

    #[test]
    fn secondary_profile_reports_only_its_networks() {
        let dir = unique_dir("secondary");
        let path = dir.join("wg.conf");
        fs::write(
            &path,
            "[Interface]\nAddress=10.9.0.2/32\n[Peer]\nAllowedIPs=0.0.0.0/0\n",
        )
        .unwrap();
        let mut secondary = profile(TunnelBackend::WireGuard, &path);
        secondary.tunnel_role = crate::models::TunnelRole::Secondary;
        secondary.tunnel_networks = vec![net("10.20.0.0/16")];
        let analysis = analyze_profile(&secondary).unwrap();
        assert_eq!(destinations(&analysis.os_routes), vec![net("10.20.0.0/16")]);

        let primary = profile(TunnelBackend::WireGuard, &path);
        let analysis = analyze_profile(&primary).unwrap();
        assert!(destinations(&analysis.os_routes).contains(&net("0.0.0.0/0")));
    }

    #[test]
    fn wireguard_allowed_ips_and_endpoints() {
        let dir = unique_dir("wg-basic");
        let cfg = dir.join("w.conf");
        fs::write(
            &cfg,
            "[Interface]\nPrivateKey=S3cr3t\nAddress=10.0.0.2/32\n\n\
             [Peer]\nPublicKey=S3cr3t2\nAllowedIPs=10.0.0.0/24, 0.0.0.0/0\n\
             Endpoint=vpn.example.com:51820\n\n\
             [Peer]\nAllowedIPs=fd00::/64\nEndpoint=[2001:db8::1]:51820\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::WireGuard, &cfg)).unwrap();
        assert_eq!(
            destinations(&result.os_routes),
            vec![net("10.0.0.0/24"), net("0.0.0.0/0"), net("fd00::/64")]
        );
        assert!(result
            .os_routes
            .iter()
            .all(|r| r.source == "WireGuard AllowedIPs"));
        assert_eq!(result.endpoints.len(), 2);
        assert_eq!(result.endpoints[0].address, "vpn.example.com");
        assert_eq!(result.endpoints[0].port, Some(51820));
        assert_eq!(result.endpoints[0].protocol, "wireguard");
        assert_eq!(result.endpoints[1].address, "2001:db8::1");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_interface_details_and_peers() {
        let dir = unique_dir("wg-peers");
        let cfg = dir.join("w.conf");
        fs::write(
            &cfg,
            "[Interface]\nPrivateKey=S3cr3t\nAddress=10.0.0.2/32, fd00::2/128\n\
             DNS=10.0.0.1\nMTU=1420\nListenPort=51820\n\n\
             [Peer]\nPublicKey=S3cr3t2\nAllowedIPs=10.0.0.0/24\n\
             Endpoint=vpn.example.com:51820\n\n\
             [Peer]\nPublicKey=S3cr3t3\nAllowedIPs=fd00::/64\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::WireGuard, &cfg)).unwrap();

        let fields: Vec<(&str, &str)> = result
            .interface_details
            .iter()
            .map(|f| (f.field.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            fields,
            vec![
                ("address", "10.0.0.2/32"),
                ("address", "fd00::2/128"),
                ("dns", "10.0.0.1"),
                ("mtu", "1420"),
                ("listenPort", "51820"),
            ]
        );
        assert!(fields
            .iter()
            .all(|(_, v)| !v.contains("S3cr3t") && !v.contains("PrivateKey")));

        assert_eq!(result.peers.len(), 2);
        assert_eq!(
            result.peers[0].endpoint.as_ref().unwrap().address,
            "vpn.example.com"
        );
        assert_eq!(
            destinations(&result.peers[0].routes),
            vec![net("10.0.0.0/24")]
        );
        assert!(result.peers[1].endpoint.is_none());
        assert_eq!(
            destinations(&result.peers[1].routes),
            vec![net("fd00::/64")]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn openvpn_interface_details() {
        let dir = unique_dir("ovpn-details");
        let cfg = dir.join("client.conf");
        fs::write(
            &cfg,
            "client\nproto udp\ndev tun\nremote vpn.example.com 1194\n\
             cipher AES-256-GCM\nauth-user-pass\nroute 10.8.0.0 255.255.255.0\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::OpenVpn, &cfg)).unwrap();

        let fields: Vec<(&str, &str)> = result
            .interface_details
            .iter()
            .map(|f| (f.field.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            fields,
            vec![
                ("protocol", "udp"),
                ("device", "tun"),
                ("cipher", "AES-256-GCM"),
                ("authUserPass", "required"),
            ]
        );
        assert_eq!(result.endpoints.len(), 1);
        assert_eq!(result.endpoints[0].address, "vpn.example.com");
        assert_eq!(result.endpoints[0].port, Some(1194));
        assert_eq!(destinations(&result.os_routes), vec![net("10.8.0.0/24")]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_table_off_and_dpapi_warning() {
        let dir = unique_dir("wg-table");
        let cfg = dir.join("w.conf");
        fs::write(
            &cfg,
            "[Interface]\nTable=off\n[Peer]\nAllowedIPs=10.0.0.0/24\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::WireGuard, &cfg)).unwrap();
        assert!(result.os_routes.is_empty());
        assert!(result.warnings.is_empty());

        let enc = dir.join("w.conf.dpapi");
        fs::write(&enc, b"opaque").unwrap();
        let mut p = profile(TunnelBackend::WireGuard, &enc);
        p.routes.push(PolicyRoute {
            destination: net("192.168.7.0/24"),
            metric: 5,
            via: None,
        });
        let result = analyze_profile(&p).unwrap();
        assert_eq!(
            result.warnings,
            vec!["encrypted WireGuard config cannot be statically analyzed".to_string()]
        );
        assert_eq!(destinations(&result.os_routes), vec![net("192.168.7.0/24")]);
        assert_eq!(result.os_routes[0].source, "profile policy");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn wireguard_dpapi_config_is_decrypted_for_analysis() {
        let dir = unique_dir("wg-dpapi");
        let plaintext =
            b"[Interface]\nPrivateKey = redacted\n\n[Peer]\nAllowedIPs = 10.20.0.0/16\nEndpoint = peer.example.com:51820\n";
        let ciphertext = crate::config_security::protect_machine_data(plaintext).unwrap();
        let cfg = dir.join("wg.conf.dpapi");
        fs::write(&cfg, &ciphertext).unwrap();

        let result = analyze_profile(&profile(TunnelBackend::WireGuard, &cfg)).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert!(result.route_knowledge_complete);
        assert_eq!(destinations(&result.os_routes), vec![net("10.20.0.0/16")]);
        assert_eq!(result.os_routes[0].source, "WireGuard AllowedIPs");
        assert_eq!(result.endpoints.len(), 1);
        assert_eq!(result.endpoints[0].address, "peer.example.com");
        assert_eq!(result.endpoints[0].port, Some(51820));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn wireguard_dpapi_corrupt_falls_back_to_warning() {
        let dir = unique_dir("wg-dpapi-corrupt");
        let cfg = dir.join("wg.conf.dpapi");
        fs::write(&cfg, b"not-a-valid-dpapi-blob").unwrap();

        let result = analyze_profile(&profile(TunnelBackend::WireGuard, &cfg)).unwrap();
        assert_eq!(
            result.warnings,
            vec!["encrypted WireGuard config cannot be statically analyzed".to_string()]
        );
        assert!(!result.route_knowledge_complete);
        assert!(result.os_routes.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn route_knowledge_incomplete_for_dpapi_and_openvpn_pull() {
        let dir = unique_dir("route-knowledge");
        let enc = dir.join("w.conf.dpapi");
        fs::write(&enc, b"opaque").unwrap();
        let result = analyze_profile(&profile(TunnelBackend::WireGuard, &enc)).unwrap();
        assert!(!result.route_knowledge_complete);

        let ovpn = dir.join("c.ovpn");
        fs::write(&ovpn, "client\npull\nremote h.example.com 1194\n").unwrap();
        let p = profile(TunnelBackend::OpenVpn, &ovpn);
        let result = analyze_profile(&p).unwrap();
        assert!(!result.route_knowledge_complete);

        fs::write(&ovpn, "remote h.example.com 1194\nroute 1.2.3.4\n").unwrap();
        let result = analyze_profile(&p).unwrap();
        assert!(result.route_knowledge_complete);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_bad_values_warn_without_echo() {
        let dir = unique_dir("wg-bad");
        let cfg = dir.join("w.conf");
        fs::write(
            &cfg,
            "[Interface]\nPrivateKey=S3cr3t\n[Peer]\nAllowedIPs=not-a-cidr-XYZ\n\
             Endpoint=vpn.example.com:notaport\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::WireGuard, &cfg)).unwrap();
        assert!(result.os_routes.is_empty());
        assert!(result.endpoints.is_empty());
        assert_eq!(result.warnings.len(), 2);
        assert!(
            result.warnings[0].contains("line 4"),
            "{:?}",
            result.warnings
        );
        assert!(
            result.warnings[1].contains("line 5"),
            "{:?}",
            result.warnings
        );
        for w in &result.warnings {
            assert!(!w.contains("not-a-cidr-XYZ"), "{w}");
            assert!(!w.contains("notaport"), "{w}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn openvpn_routes_endpoints_and_push_warning() {
        let dir = unique_dir("ovpn-basic");
        let cfg = dir.join("c.ovpn");
        fs::write(
            &cfg,
            "client\ndev tun\nremote vpn.example.com 1194 udp\nremote plain.example.com\n\
             route 10.8.0.0 255.255.255.0\nroute 192.168.5.0/24\nroute 172.16.0.1\n\
             route-ipv6 fd00::/64\nredirect-gateway\nredirect-gateway-ipv6\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::OpenVpn, &cfg)).unwrap();
        let dests = destinations(&result.os_routes);
        for expected in [
            "10.8.0.0/24",
            "192.168.5.0/24",
            "172.16.0.1/32",
            "fd00::/64",
            "0.0.0.0/0",
            "::/0",
        ] {
            assert!(dests.contains(&net(expected)), "missing {expected}");
        }
        assert!(result.os_routes.iter().all(|r| r.source == "OpenVPN route"));
        assert_eq!(result.endpoints.len(), 2);
        assert_eq!(result.endpoints[0].address, "vpn.example.com");
        assert_eq!(result.endpoints[0].port, Some(1194));
        assert_eq!(result.endpoints[0].protocol, "udp");
        assert_eq!(result.endpoints[1].protocol, "openvpn");
        assert_eq!(
            result.warnings,
            vec!["OpenVPN server-pushed routes cannot be known before connection".to_string()]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn openvpn_remote_variants() {
        let dir = unique_dir("ovpn-remote");
        let cfg = dir.join("c.ovpn");
        fs::write(
            &cfg,
            "dev tun\nremote a.example.com\nremote b.example.com 1194\n\
             remote c.example.com 1194 udp\nremote d.example.com tcp\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::OpenVpn, &cfg)).unwrap();
        assert_eq!(result.endpoints.len(), 4);
        assert_eq!(result.endpoints[0].port, None);
        assert_eq!(result.endpoints[0].protocol, "openvpn");
        assert_eq!(result.endpoints[1].port, Some(1194));
        assert_eq!(result.endpoints[1].protocol, "openvpn");
        assert_eq!(result.endpoints[2].port, Some(1194));
        assert_eq!(result.endpoints[2].protocol, "udp");
        assert_eq!(result.endpoints[3].port, None);
        assert_eq!(result.endpoints[3].protocol, "tcp");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn openvpn_inline_ignored_and_bad_netmask_warns() {
        let dir = unique_dir("ovpn-inline");
        let cfg = dir.join("c.ovpn");
        fs::write(
            &cfg,
            "pull\nroute 9.9.9.9 255.0.255.0\nroute hostname.example.com\n\
             <ca>\nroute 8.8.8.8 255.255.255.255\nremote fake.example 9999\n</ca>\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::OpenVpn, &cfg)).unwrap();
        assert!(result.os_routes.is_empty(), "{:?}", result.os_routes);
        assert!(result.endpoints.is_empty());
        assert_eq!(result.warnings.len(), 3);
        assert!(result.warnings.iter().any(|w| w.contains("line 2")));
        assert!(result.warnings.iter().any(|w| w.contains("line 3")));
        assert!(result
            .warnings
            .iter()
            .any(|w| { w.contains("server-pushed") }));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_listeners_endpoints_routes_and_domains() {
        let dir = unique_dir("xray-basic");
        let cfg = dir.join("c.json");
        fs::write(
            &cfg,
            r#"{
              "inbounds": [
                {"listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
                {"port": null},
                {"port": "bad"}
              ],
              "outbounds": [
                {"protocol": "vless", "settings": {"vnext": [{"address": "vpn.example.com", "port": 443}]}},
                {"protocol": "trojan", "settings": {"servers": [{"address": "t.example.com", "port": 8443}]}},
                {"protocol": "freedom"}
              ],
              "routing": {"rules": [{"type": "field",
                "ip": ["10.0.0.0/8", "1.2.3.4"],
                "domain": ["domain:example.com"]}]}
            }"#,
        )
        .unwrap();
        let mut p = profile(TunnelBackend::Xray, &cfg);
        p.domain_policies.push(DomainPolicy {
            domains: vec!["full:api.example.com".into()],
            target: DomainRouteTarget::Proxy,
        });
        let result = analyze_profile(&p).unwrap();

        assert_eq!(result.listeners.len(), 1);
        assert_eq!(result.listeners[0].address, "127.0.0.1");
        assert_eq!(result.listeners[0].port, 10808);
        assert_eq!(result.listeners[0].protocol, "socks");
        assert_eq!(result.endpoints.len(), 2);
        assert_eq!(result.endpoints[0].protocol, "vless");
        assert_eq!(result.endpoints[0].port, Some(443));
        assert_eq!(result.endpoints[1].protocol, "trojan");
        assert_eq!(
            destinations(&result.internal_routes),
            vec![net("10.0.0.0/8"), net("1.2.3.4/32")]
        );
        assert_eq!(
            result.domain_patterns,
            vec!["domain:example.com", "full:api.example.com"]
        );
        assert_eq!(result.warnings.len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_tun_inbound_adds_default_route_to_os_routes() {
        let dir = unique_dir("xray-tun");
        let cfg = dir.join("c.json");
        fs::write(
            &cfg,
            r#"{
              "inbounds": [{"protocol": "tun", "settings": {"interfaceName": "xray-tun"}}],
              "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "vpn.example.com", "port": 443}]}}]
            }"#,
        )
        .unwrap();
        let p = profile(TunnelBackend::Xray, &cfg);
        let result = analyze_profile(&p).unwrap();
        // TUN inbound produces a 0.0.0.0/0 OS route.
        assert!(result
            .os_routes
            .iter()
            .any(|r| r.destination == net("0.0.0.0/0") && r.source == "Xray TUN"));
        // No listener — TUN has no port.
        assert!(result.listeners.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_tun_mode_adds_default_route_even_without_tun_inbound_in_config() {
        let dir = unique_dir("xray-tun-mode");
        let cfg = dir.join("c.json");
        fs::write(
            &cfg,
            r#"{
              "inbounds": [{"protocol": "socks", "port": 10808}],
              "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "vpn.example.com", "port": 443}]}}]
            }"#,
        )
        .unwrap();
        let mut p = profile(TunnelBackend::Xray, &cfg);
        p.xray_mode = XrayMode::Tun;
        let result = analyze_profile(&p).unwrap();
        // Profile is configured for TUN mode — 0.0.0.0/0 OS route is added
        // proactively even though the stored config still has a SOCKS inbound.
        assert!(result
            .os_routes
            .iter()
            .any(|r| r.destination == net("0.0.0.0/0") && r.source == "Xray TUN"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_geoip_warning_and_malformed_json() {
        let dir = unique_dir("xray-geo");
        let cfg = dir.join("c.json");
        fs::write(
            &cfg,
            r#"{"routing":{"rules":[{"ip":["geoip:cn","ext:list.dat","bogus value"]}]}}"#,
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::Xray, &cfg)).unwrap();
        assert_eq!(result.warnings.len(), 1);
        for w in &result.warnings {
            assert!(!w.contains("geoip:cn"), "{w}");
            assert!(!w.contains("ext:list.dat"), "{w}");
            assert!(!w.contains("bogus value"), "{w}");
        }

        let bad = dir.join("bad.json");
        fs::write(&bad, b"{ not json SECRET-UUID-1234").unwrap();
        let err = analyze_profile(&profile(TunnelBackend::Xray, &bad)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("bad.json"));
        assert!(!err.to_string().contains("SECRET-UUID-1234"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn xray_dpapi_config_is_decrypted_for_analysis() {
        let dir = unique_dir("xray-dpapi");
        let cfg = dir.join("c.json.dpapi");
        let plaintext = br#"{"inbounds":[{"listen":"127.0.0.1","port":10888,"protocol":"socks"}]}"#;
        let bytes = crate::config_security::protect_user_data(
            plaintext,
            &crate::config_security::xray_context("p-dpapi"),
        )
        .unwrap();
        fs::write(&cfg, &bytes).unwrap();
        let mut p = profile(TunnelBackend::Xray, &cfg);
        p.id = "p-dpapi".to_string();

        let result = analyze_profile(&p).unwrap();
        assert_eq!(result.listeners.len(), 1);
        assert_eq!(result.listeners[0].port, 10888);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn xray_dpapi_error_does_not_leak_plaintext() {
        let dir = unique_dir("xray-dpapi-bad");
        let cfg = dir.join("c.json.dpapi");
        fs::write(&cfg, b"corrupt-UUID-SENTINEL-9").unwrap();
        let p = profile(TunnelBackend::Xray, &cfg);

        let err = analyze_profile(&p).unwrap_err();
        assert!(!err.to_string().contains("UUID-SENTINEL-9"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn profile_policy_routes_included_for_each_backend() {
        let dir = unique_dir("policy");
        let wg = dir.join("w.conf.dpapi");
        fs::write(&wg, b"opaque").unwrap();
        let ovpn = dir.join("o.ovpn");
        fs::write(&ovpn, "dev tun\n").unwrap();
        let xray = dir.join("x.json");
        fs::write(&xray, b"{}").unwrap();

        for (backend, path) in [
            (TunnelBackend::WireGuard, wg),
            (TunnelBackend::OpenVpn, ovpn),
            (TunnelBackend::Xray, xray),
        ] {
            let mut p = profile(backend, &path);
            p.routes.push(PolicyRoute {
                destination: net("10.9.9.0/24"),
                metric: 1,
                via: None,
            });
            let result = analyze_profile(&p).unwrap();
            assert!(result
                .os_routes
                .iter()
                .any(|r| r.destination == net("10.9.9.0/24") && r.source == "profile policy"));
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prefixes_overlap_same_family_containment() {
        assert!(prefixes_overlap(net("10.0.0.0/8"), net("10.1.0.0/16")));
        assert!(prefixes_overlap(net("10.1.0.0/16"), net("10.0.0.0/8")));
        assert!(!prefixes_overlap(net("10.0.0.0/8"), net("11.0.0.0/8")));
        assert!(prefixes_overlap(net("fd00::/64"), net("fd00::/80")));
        assert!(!prefixes_overlap(net("10.0.0.0/8"), net("fd00::/64")));
        assert!(prefixes_overlap(net("10.0.0.0/24"), net("10.0.0.0/24")));
    }

    #[test]
    fn conflicts_detect_route_overlap_and_listener_collision() {
        let mut candidate = empty_analysis("new");
        candidate.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: net("10.0.0.0/24"),
            source: "test".into(),
        });
        candidate.listeners.push(LocalListener {
            address: "0.0.0.0".into(),
            port: 10808,
            protocol: "socks".into(),
        });
        let mut other = empty_analysis("existing");
        other.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: net("10.0.0.0/24"),
            source: "test".into(),
        });
        other.listeners.push(LocalListener {
            address: "127.0.0.1".into(),
            port: 10808,
            protocol: "socks".into(),
        });

        let conflicts = conflicts_between(&candidate, &other, true);
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts
            .iter()
            .any(|c| c.kind == ConflictKind::RouteOverlap
                && c.blocking
                && c.other_profile_id.as_deref() == Some("existing")
                && c.message.contains("10.0.0.0/24")));
        assert!(conflicts
            .iter()
            .any(|c| c.kind == ConflictKind::ListenerCollision && c.message.contains("10808")));

        let mut distinct = empty_analysis("distinct");
        distinct.listeners.push(LocalListener {
            address: "127.0.0.1".into(),
            port: 9999,
            protocol: "socks".into(),
        });
        distinct.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: net("172.16.0.0/16"),
            source: "t".into(),
        });
        assert!(conflicts_between(&distinct, &other, true).is_empty());

        let mut same_port = empty_analysis("same-port");
        same_port.listeners.push(LocalListener {
            address: "127.0.0.2".into(),
            port: 10808,
            protocol: "socks".into(),
        });
        let conflicts = conflicts_between(&same_port, &other, true);
        assert!(conflicts
            .iter()
            .all(|c| c.kind != ConflictKind::ListenerCollision));
    }

    #[test]
    fn longest_prefix_nested_routes_compose_without_blocking() {
        let cand16 = analysis_with_route("new", "10.20.0.0/16", "test");
        let other8 = analysis_with_route("existing", "10.0.0.0/8", "test");

        assert!(conflicts_between(&cand16, &other8, true)
            .iter()
            .all(|c| c.kind != ConflictKind::RouteOverlap));
        assert!(conflicts_between(&other8, &cand16, true)
            .iter()
            .all(|c| c.kind != ConflictKind::RouteOverlap));

        let info = conflicts_between(&cand16, &other8, false);
        assert_eq!(info.len(), 1);
        assert!(!info[0].blocking);
        assert!(
            info[0].message.contains("longest-prefix"),
            "{}",
            info[0].message
        );
        assert!(info[0].message.contains("/16"), "{}", info[0].message);

        let exact_other = analysis_with_route("existing", "10.20.0.0/16", "test");
        let conflicts = conflicts_between(&cand16, &exact_other, true);
        assert!(conflicts
            .iter()
            .any(|c| c.kind == ConflictKind::RouteOverlap && c.blocking));
        let info_exact = conflicts_between(&cand16, &exact_other, false);
        assert!(info_exact
            .iter()
            .any(|c| c.kind == ConflictKind::RouteOverlap));
    }

    #[test]
    fn wireguard_default_route_killswitch_stays_blocking() {
        let cand16 = analysis_with_route("new", "10.20.0.0/16", "test");
        let wg_default = analysis_with_route("existing", "0.0.0.0/0", "WireGuard AllowedIPs");

        let conflicts = conflicts_between(&cand16, &wg_default, true);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].blocking);
        assert!(
            conflicts[0].message.contains("kill-switch"),
            "{}",
            conflicts[0].message
        );

        let wg_candidate = analysis_with_route("new", "0.0.0.0/0", "WireGuard AllowedIPs");
        let other16 = analysis_with_route("existing", "10.20.0.0/16", "test");
        let conflicts = conflicts_between(&wg_candidate, &other16, true);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].blocking);

        let info = conflicts_between(&cand16, &wg_default, false);
        assert_eq!(info.len(), 1);
        assert!(!info[0].blocking);
        assert!(info[0].message.contains("kill-switch"));
    }

    #[test]
    fn non_wireguard_default_nesting_is_not_blocking() {
        let cand16 = analysis_with_route("new", "10.20.0.0/16", "test");
        let ovpn_default = analysis_with_route("existing", "0.0.0.0/0", "OpenVPN route");
        assert!(conflicts_between(&cand16, &ovpn_default, true)
            .iter()
            .all(|c| c.kind != ConflictKind::RouteOverlap));
        let info = conflicts_between(&cand16, &ovpn_default, false);
        assert_eq!(info.len(), 1);
        assert!(!info[0].blocking);
    }

    #[test]
    fn listener_collision_still_blocks_with_nested_routes() {
        let mut candidate = analysis_with_route("new", "10.20.0.0/16", "test");
        candidate.listeners.push(LocalListener {
            address: "0.0.0.0".into(),
            port: 10808,
            protocol: "socks".into(),
        });
        let mut other = analysis_with_route("existing", "10.0.0.0/8", "test");
        other.listeners.push(LocalListener {
            address: "127.0.0.1".into(),
            port: 10808,
            protocol: "socks".into(),
        });
        let conflicts = conflicts_between(&candidate, &other, true);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].kind, ConflictKind::ListenerCollision);
        assert!(conflicts[0].blocking);
    }

    #[test]
    fn xray_internal_route_alone_is_not_blocking_conflict() {
        let mut candidate = empty_analysis("new");
        candidate.internal_routes.push(AnalyzedRoute {
            metric: None,
            destination: net("10.0.0.0/8"),
            source: "Xray routing rule".into(),
        });
        let mut other = empty_analysis("existing");
        other.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: net("10.0.0.0/8"),
            source: "WireGuard AllowedIPs".into(),
        });
        assert!(conflicts_between(&candidate, &other, true).is_empty());
    }

    #[test]
    fn os_warnings_suppress_baseline_default_but_report_meaningful() {
        let os = vec![os_route("0.0.0.0/0"), os_route("10.0.0.0/8")];

        let mut overlapping = empty_analysis("c1");
        overlapping.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: net("10.1.0.0/16"),
            source: "test".into(),
        });
        let warnings = warnings_against_os_routes(&overlapping, &os);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("10.1.0.0/16"));
        assert!(!warnings[0].blocking);
        assert_eq!(warnings[0].other_profile_id, None);

        let mut only_default = empty_analysis("c2");
        only_default.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: net("192.168.0.0/24"),
            source: "test".into(),
        });
        assert!(warnings_against_os_routes(&only_default, &os).is_empty());

        let mut candidate_default = empty_analysis("c3");
        candidate_default.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: net("0.0.0.0/0"),
            source: "test".into(),
        });
        let warnings = warnings_against_os_routes(&candidate_default, &os);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("0.0.0.0/0"));
    }

    #[test]
    fn analysis_results_deduplicate_preserving_order() {
        let dir = unique_dir("dedup");
        let cfg = dir.join("w.conf");
        fs::write(
            &cfg,
            "[Peer]\nAllowedIPs=10.0.0.0/24\n[Peer]\nAllowedIPs=10.0.0.0/24\n",
        )
        .unwrap();
        let result = analyze_profile(&profile(TunnelBackend::WireGuard, &cfg)).unwrap();
        assert_eq!(destinations(&result.os_routes), vec![net("10.0.0.0/24")]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn listener_address_equality_and_wildcard_ipv6() {
        let mut a = empty_analysis("a");
        a.listeners.push(LocalListener {
            address: "::".into(),
            port: 443,
            protocol: "x".into(),
        });
        let mut b = empty_analysis("b");
        b.listeners.push(LocalListener {
            address: "2001:db8::1".into(),
            port: 443,
            protocol: "x".into(),
        });
        assert_eq!(conflicts_between(&a, &b, false).len(), 1);

        let mut c = empty_analysis("c");
        c.listeners.push(LocalListener {
            address: "192.168.1.1".into(),
            port: 443,
            protocol: "x".into(),
        });
        b.listeners.clear();
        b.listeners.push(LocalListener {
            address: "192.168.1.2".into(),
            port: 443,
            protocol: "x".into(),
        });
        assert!(conflicts_between(&c, &b, false).is_empty());
    }

    #[test]
    fn none_backend_reports_only_policy_routes() {
        let mut p = profile(TunnelBackend::None, Path::new(""));
        p.routes = vec![PolicyRoute {
            destination: "10.0.0.0/24".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        let analysis = analyze_profile(&p).unwrap();
        assert!(analysis.warnings.is_empty());
        assert!(analysis.route_knowledge_complete);
        assert_eq!(destinations(&analysis.os_routes), vec![net("10.0.0.0/24")]);
        assert_eq!(analysis.os_routes[0].source, "profile policy");
        assert!(analysis.internal_routes.is_empty());
        assert!(analysis.listeners.is_empty());
        assert!(analysis.endpoints.is_empty());
    }
}
