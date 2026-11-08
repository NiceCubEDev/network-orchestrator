//! Pure validation and planning for a Linux WireGuard client connection.
//! No filesystem, subprocess or network access happens here.

use crate::connect_plan::full_coverage;
use crate::models::PolicyRoute;
use base64::Engine;
use ipnet::IpNet;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

pub const MAX_WIREGUARD_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_WIREGUARD_PEERS: usize = 16;
const MAX_ADDRESSES: usize = 32;
const MAX_ROUTES: usize = 512;
const MAX_DNS_SERVERS: usize = 8;
const MAX_DNS_DOMAINS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardPlanWarning {
    IgnoredHook,
    IgnoredSaveConfig,
}

/// Contains a private key in `setconf`; its Debug implementation is redacted.
pub struct WireGuardPlan {
    pub setconf: String,
    pub addresses: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_domains: Vec<String>,
    pub mtu: Option<u32>,
    pub routes: Vec<PolicyRoute>,
    pub full_ipv4: bool,
    pub full_ipv6: bool,
    pub warnings: Vec<WireGuardPlanWarning>,
    /// Optional kernel interface-name hint supplied by the client (the profile
    /// name). Sanitized in `DaemonCore::connect_wireguard`; a deterministic
    /// hash name is used when this is `None` or sanitizes to nothing.
    pub interface_name: Option<String>,
}

impl fmt::Debug for WireGuardPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardPlan")
            .field("setconf", &"[REDACTED]")
            .field("address_count", &self.addresses.len())
            .field("dns_server_count", &self.dns_servers.len())
            .field("dns_domain_count", &self.dns_domains.len())
            .field("mtu", &self.mtu)
            .field("route_count", &self.routes.len())
            .field("full_ipv4", &self.full_ipv4)
            .field("full_ipv6", &self.full_ipv6)
            .field("warnings", &self.warnings)
            .field("interface_name", &self.interface_name)
            .finish()
    }
}

/// All messages are fixed strings; neither Display nor Debug includes input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireGuardPlanError(&'static str);

impl fmt::Display for WireGuardPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for WireGuardPlanError {}

#[derive(Default)]
struct Peer {
    has_public_key: bool,
    has_preshared_key: bool,
    has_endpoint: bool,
    has_keepalive: bool,
    allowed_ips: Vec<IpNet>,
    allowed_line: Option<std::ops::Range<usize>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

/// Parse only WireGuard/wg-quick fields the daemon knows how to own. The
/// returned `setconf` has wg-quick fields and executable hooks removed.
pub fn parse_wireguard_config(
    source: &str,
    policy_routes: &[PolicyRoute],
) -> Result<WireGuardPlan, WireGuardPlanError> {
    if source.len() > MAX_WIREGUARD_CONFIG_BYTES {
        return Err(WireGuardPlanError("WireGuard config is too large"));
    }
    if policy_routes.len() > MAX_ROUTES {
        return Err(WireGuardPlanError("too many policy routes"));
    }

    let mut plan = WireGuardPlan {
        setconf: String::new(),
        addresses: Vec::new(),
        dns_servers: Vec::new(),
        dns_domains: Vec::new(),
        mtu: None,
        routes: Vec::new(),
        full_ipv4: false,
        full_ipv6: false,
        warnings: Vec::new(),
        interface_name: None,
    };
    let mut section = Section::None;
    let mut seen_interface = false;
    let mut has_private_key = false;
    let mut has_listen_port = false;
    let mut peers = Vec::<Peer>::new();
    let mut table_off = false;
    let mut table_seen = false;
    let mut mtu_seen = false;

    for raw in source.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            match line.to_ascii_lowercase().as_str() {
                "[interface]" if !seen_interface && peers.is_empty() => {
                    seen_interface = true;
                    section = Section::Interface;
                    plan.setconf.push_str("[Interface]\n");
                }
                "[peer]" if seen_interface && peers.len() < MAX_WIREGUARD_PEERS => {
                    peers.push(Peer::default());
                    section = Section::Peer;
                    plan.setconf.push_str("\n[Peer]\n");
                }
                "[peer]" => return Err(WireGuardPlanError("too many or misplaced peers")),
                _ => return Err(WireGuardPlanError("invalid WireGuard section")),
            }
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(WireGuardPlanError("invalid WireGuard field"))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            return Err(WireGuardPlanError("empty WireGuard field"));
        }
        match (section, key.as_str()) {
            (Section::Interface, "privatekey") => {
                if has_private_key {
                    return Err(WireGuardPlanError("duplicate PrivateKey"));
                }
                validate_key(value, "invalid PrivateKey")?;
                has_private_key = true;
                push_setconf(&mut plan.setconf, "PrivateKey", value);
            }
            (Section::Interface, "listenport") => {
                if has_listen_port {
                    return Err(WireGuardPlanError("duplicate ListenPort"));
                }
                validate_port(value, "invalid ListenPort")?;
                has_listen_port = true;
                push_setconf(&mut plan.setconf, "ListenPort", value);
            }
            (Section::Interface, "address") => {
                for part in comma_items(value) {
                    let address = part
                        .parse::<IpNet>()
                        .map_err(|_| WireGuardPlanError("invalid Address"))?;
                    if address.addr().is_unspecified() || address.addr().is_multicast() {
                        return Err(WireGuardPlanError("invalid Address"));
                    }
                    if plan.addresses.contains(&address) {
                        continue;
                    }
                    plan.addresses.push(address);
                    if plan.addresses.len() > MAX_ADDRESSES {
                        return Err(WireGuardPlanError("too many Address entries"));
                    }
                }
            }
            (Section::Interface, "dns") => {
                for part in comma_items(value) {
                    if let Ok(server) = part.parse::<IpAddr>() {
                        if server.is_unspecified() || server.is_multicast() {
                            return Err(WireGuardPlanError("invalid DNS"));
                        }
                        plan.dns_servers.push(server);
                        if plan.dns_servers.len() > MAX_DNS_SERVERS {
                            return Err(WireGuardPlanError("too many DNS servers"));
                        }
                    } else {
                        if !valid_dns_name(part) {
                            return Err(WireGuardPlanError("invalid DNS domain"));
                        }
                        plan.dns_domains.push(part.to_ascii_lowercase());
                        if plan.dns_domains.len() > MAX_DNS_DOMAINS {
                            return Err(WireGuardPlanError("too many DNS domains"));
                        }
                    }
                }
            }
            (Section::Interface, "mtu") => {
                if mtu_seen {
                    return Err(WireGuardPlanError("duplicate MTU"));
                }
                mtu_seen = true;
                let mtu = value
                    .parse::<u32>()
                    .map_err(|_| WireGuardPlanError("invalid MTU"))?;
                if !(576..=9000).contains(&mtu) {
                    return Err(WireGuardPlanError("invalid MTU"));
                }
                plan.mtu = Some(mtu);
            }
            (Section::Interface, "table") => {
                if table_seen {
                    return Err(WireGuardPlanError("duplicate Table"));
                }
                table_seen = true;
                table_off = match value.to_ascii_lowercase().as_str() {
                    "off" => true,
                    "auto" => false,
                    _ => return Err(WireGuardPlanError("unsupported Table")),
                };
            }
            (Section::Interface, "preup" | "postup" | "predown" | "postdown") => {
                if !plan.warnings.contains(&WireGuardPlanWarning::IgnoredHook) {
                    plan.warnings.push(WireGuardPlanWarning::IgnoredHook);
                }
            }
            (Section::Interface, "saveconfig") => {
                if !plan
                    .warnings
                    .contains(&WireGuardPlanWarning::IgnoredSaveConfig)
                {
                    plan.warnings.push(WireGuardPlanWarning::IgnoredSaveConfig);
                }
            }
            (Section::Interface, "fwmark") => {
                return Err(WireGuardPlanError("unsupported FwMark"));
            }
            (Section::Peer, "publickey") => {
                let peer = peers.last_mut().expect("peer section has a peer");
                if peer.has_public_key {
                    return Err(WireGuardPlanError("duplicate PublicKey"));
                }
                validate_key(value, "invalid PublicKey")?;
                peer.has_public_key = true;
                push_setconf(&mut plan.setconf, "PublicKey", value);
            }
            (Section::Peer, "presharedkey") => {
                let peer = peers.last_mut().expect("peer section has a peer");
                if peer.has_preshared_key {
                    return Err(WireGuardPlanError("duplicate PresharedKey"));
                }
                validate_key(value, "invalid PresharedKey")?;
                peer.has_preshared_key = true;
                push_setconf(&mut plan.setconf, "PresharedKey", value);
            }
            (Section::Peer, "endpoint") => {
                let peer = peers.last_mut().expect("peer section has a peer");
                if peer.has_endpoint {
                    return Err(WireGuardPlanError("duplicate Endpoint"));
                }
                validate_endpoint(value)?;
                peer.has_endpoint = true;
                push_setconf(&mut plan.setconf, "Endpoint", value);
            }
            (Section::Peer, "allowedips") => {
                let peer = peers.last_mut().expect("peer section has a peer");
                if !peer.allowed_ips.is_empty() {
                    return Err(WireGuardPlanError("duplicate AllowedIPs"));
                }
                for part in comma_items(value) {
                    let network = part
                        .parse::<IpNet>()
                        .map_err(|_| WireGuardPlanError("invalid AllowedIPs"))?
                        .trunc();
                    peer.allowed_ips.push(network);
                    if peer.allowed_ips.len() > MAX_ROUTES {
                        return Err(WireGuardPlanError("too many AllowedIPs"));
                    }
                }
                let start = plan.setconf.len();
                push_setconf(
                    &mut plan.setconf,
                    "AllowedIPs",
                    &peer
                        .allowed_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                peer.allowed_line = Some(start..plan.setconf.len());
            }
            (Section::Peer, "persistentkeepalive") => {
                let peer = peers.last_mut().expect("peer section has a peer");
                if peer.has_keepalive {
                    return Err(WireGuardPlanError("duplicate PersistentKeepalive"));
                }
                let keepalive = value
                    .parse::<u16>()
                    .map_err(|_| WireGuardPlanError("invalid PersistentKeepalive"))?;
                peer.has_keepalive = true;
                if keepalive > 0 {
                    push_setconf(&mut plan.setconf, "PersistentKeepalive", value);
                }
            }
            _ => return Err(WireGuardPlanError("unsupported WireGuard field")),
        }
    }
    if !has_private_key || peers.is_empty() || !peers.iter().all(|p| p.has_public_key) {
        return Err(WireGuardPlanError("missing WireGuard key or peer"));
    }
    if !peers.iter().any(|p| p.has_endpoint) {
        return Err(WireGuardPlanError("missing Endpoint"));
    }
    if plan.addresses.is_empty() || peers.iter().any(|p| p.allowed_ips.is_empty()) {
        return Err(WireGuardPlanError("missing Address or AllowedIPs"));
    }
    if !plan.dns_domains.is_empty() && plan.dns_servers.is_empty() {
        return Err(WireGuardPlanError("DNS domains require a DNS server"));
    }
    let mut prior_peers = Vec::<IpNet>::new();
    for peer in &peers {
        let mut this_peer = HashSet::new();
        for allowed in &peer.allowed_ips {
            if !this_peer.insert(*allowed) || prior_peers.contains(allowed) {
                return Err(WireGuardPlanError("duplicate AllowedIPs across peers"));
            }
            if prior_peers
                .iter()
                .any(|prior| contains_net(prior, allowed) || contains_net(allowed, prior))
            {
                return Err(WireGuardPlanError("overlapping AllowedIPs across peers"));
            }
        }
        prior_peers.extend(&peer.allowed_ips);
    }

    if !policy_routes.is_empty() {
        let mut seen = HashSet::new();
        let mut expanded = false;
        for route in policy_routes {
            if route.via.is_some() || route.destination != route.destination.trunc() {
                return Err(WireGuardPlanError("invalid policy route"));
            }
            let covered = peers.iter().any(|peer| {
                peer.allowed_ips
                    .iter()
                    .any(|allowed| contains_net(allowed, &route.destination))
            });
            if !covered {
                if peers.len() != 1 {
                    return Err(WireGuardPlanError(
                        "policy route is not covered by AllowedIPs",
                    ));
                }
                peers[0].allowed_ips.push(route.destination);
                expanded = true;
            }
            if !seen.insert(route.destination) {
                return Err(WireGuardPlanError("duplicate policy route"));
            }
            plan.routes.push(route.clone());
        }
        if expanded {
            let peer = &peers[0];
            let mut line = String::new();
            push_setconf(
                &mut line,
                "AllowedIPs",
                &peer
                    .allowed_ips
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            plan.setconf
                .replace_range(peer.allowed_line.clone().unwrap(), &line);
        }
    } else if !table_off {
        for peer in &peers {
            for destination in &peer.allowed_ips {
                plan.routes.push(PolicyRoute {
                    destination: *destination,
                    metric: 5,
                    via: None,
                });
                if plan.routes.len() > MAX_ROUTES {
                    return Err(WireGuardPlanError("too many routes"));
                }
            }
        }
    }
    // def1-style halves capture everything too, so they need the same
    // marked-transport policy routing as a default route.
    let has = |network: &str| {
        plan.routes
            .iter()
            .any(|route| route.destination == network.parse::<IpNet>().unwrap())
    };
    plan.full_ipv4 = has("0.0.0.0/0") || (has("0.0.0.0/1") && has("128.0.0.0/1"));
    plan.full_ipv6 = has("::/0") || (has("::/1") && has("8000::/1"));
    let (covers_ipv4, covers_ipv6) = full_coverage(plan.routes.iter().map(|r| r.destination));
    if (covers_ipv4 && !plan.full_ipv4) || (covers_ipv6 && !plan.full_ipv6) {
        return Err(WireGuardPlanError(
            "unsupported full-tunnel route decomposition",
        ));
    }
    for server in &plan.dns_servers {
        let reachable = plan
            .routes
            .iter()
            .any(|route| route.destination.contains(server));
        if !reachable {
            return Err(WireGuardPlanError(
                "DNS server is not covered by tunnel routes",
            ));
        }
    }
    Ok(plan)
}

fn push_setconf(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push_str(" = ");
    output.push_str(value);
    output.push('\n');
}

fn comma_items(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim)
}

fn validate_key(value: &str, error: &'static str) -> Result<(), WireGuardPlanError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| WireGuardPlanError(error))?;
    if decoded.len() != 32 {
        return Err(WireGuardPlanError(error));
    }
    Ok(())
}

fn validate_port(value: &str, error: &'static str) -> Result<(), WireGuardPlanError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| WireGuardPlanError(error))?;
    if port == 0 {
        return Err(WireGuardPlanError(error));
    }
    Ok(())
}

fn validate_endpoint(value: &str) -> Result<(), WireGuardPlanError> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once("]:")
            .ok_or(WireGuardPlanError("invalid Endpoint"))?;
        if !matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            return Err(WireGuardPlanError("invalid Endpoint"));
        }
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or(WireGuardPlanError("invalid Endpoint"))?;
        if host.contains(':') {
            return Err(WireGuardPlanError("invalid Endpoint"));
        }
        (host, port)
    };
    validate_port(port, "invalid Endpoint")?;
    if host.parse::<IpAddr>().is_err() && !valid_dns_name(host) {
        return Err(WireGuardPlanError("invalid Endpoint"));
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn contains_net(outer: &IpNet, inner: &IpNet) -> bool {
    outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.network())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PolicyRoute;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn config(interface: &str, peer: &str) -> String {
        format!("[Interface]\nPrivateKey = {KEY}\n{interface}\n[Peer]\nPublicKey = {KEY}\nEndpoint = peer.example.test:51820\n{peer}\n")
    }

    fn route(destination: &str) -> PolicyRoute {
        PolicyRoute {
            destination: destination.parse().unwrap(),
            metric: 5,
            via: None,
        }
    }

    #[test]
    fn full_plan_strips_extensions_and_hooks_without_exposing_secrets() {
        let source = config(
            "Address = 10.77.0.2/32, fd77::2/128\nDNS = 10.77.0.1, corp.test\nMTU = 1380\nTable = auto\nPostUp = echo SECRET-HOOK",
            "AllowedIPs = 0.0.0.0/0, ::/0",
        );
        let plan = parse_wireguard_config(&source, &[]).unwrap();
        assert_eq!(plan.addresses.len(), 2);
        assert_eq!(
            plan.dns_servers,
            vec!["10.77.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(plan.dns_domains, vec!["corp.test"]);
        assert_eq!(plan.mtu, Some(1380));
        assert!(plan.full_ipv4 && plan.full_ipv6);
        assert_eq!(plan.routes.len(), 2);
        assert!(plan.setconf.contains("PrivateKey = "));
        for forbidden in ["Address", "DNS", "MTU", "Table", "PostUp", "SECRET-HOOK"] {
            assert!(!plan.setconf.contains(forbidden), "{forbidden}");
        }
        assert_eq!(plan.warnings, vec![WireGuardPlanWarning::IgnoredHook]);
        let debug = format!("{plan:?}");
        for private in [KEY, "corp.test", "10.77.0.2", "10.77.0.1"] {
            assert!(!debug.contains(private));
        }
    }

    #[test]
    fn split_policy_routes_replace_derived_allowed_ips() {
        let source = config("Address=10.77.0.2/32", "AllowedIPs=10.0.0.0/8");
        let plan = parse_wireguard_config(&source, &[route("10.2.0.0/16")]).unwrap();
        assert_eq!(plan.routes, vec![route("10.2.0.0/16")]);
        assert!(!plan.full_ipv4 && !plan.full_ipv6);
        assert!(plan.setconf.contains("AllowedIPs = 10.0.0.0/8"));
    }

    #[test]
    fn table_off_suppresses_only_derived_routes() {
        let source = config("Address=10.77.0.2/32\nTable=off", "AllowedIPs=10.0.0.0/8");
        assert!(parse_wireguard_config(&source, &[])
            .unwrap()
            .routes
            .is_empty());
        let plan = parse_wireguard_config(&source, &[route("10.2.0.0/16")]).unwrap();
        assert_eq!(plan.routes, vec![route("10.2.0.0/16")]);
    }

    #[test]
    fn rejects_executable_and_unknown_fields_without_echoing_values() {
        for (key, value) in [
            ("FwMark", "SECRET-MARK"),
            ("Foo", "SECRET-UNKNOWN"),
            ("Table", "SECRET-TABLE"),
        ] {
            let source = config(&format!("{key}={value}"), "AllowedIPs=10.0.0.0/8");
            let error = parse_wireguard_config(&source, &[]).unwrap_err();
            assert!(error
                .to_string()
                .contains(if key == "Foo" { "field" } else { key }));
            assert!(!error.to_string().contains(value));
            assert!(!format!("{error:?}").contains(value));
        }
    }

    #[test]
    fn rejects_invalid_key_address_dns_and_endpoint_with_redacted_errors() {
        for source in [
            config("PrivateKey=SECRET-INVALID", "AllowedIPs=10.0.0.0/8"),
            config("Address=SECRET-ADDRESS", "AllowedIPs=10.0.0.0/8"),
            config("DNS=SECRET-DNS!", "AllowedIPs=10.0.0.0/8"),
            config("", "Endpoint=SECRET-ENDPOINT!\nAllowedIPs=10.0.0.0/8"),
        ] {
            let error = parse_wireguard_config(&source, &[]).unwrap_err();
            assert!(!error.to_string().contains("SECRET-"));
            assert!(!format!("{error:?}").contains("SECRET-"));
        }
    }

    #[test]
    fn rejects_policy_route_without_unambiguous_peer() {
        let source = config("Address=10.77.0.2/32", "AllowedIPs=10.0.0.0/8");
        let source = format!("{source}[Peer]\nPublicKey={KEY}\nAllowedIPs=192.168.0.0/16\n");
        let error = parse_wireguard_config(&source, &[route("172.16.0.0/16")]).unwrap_err();
        assert!(error.to_string().contains("policy route"));
    }

    #[test]
    fn one_peer_policy_route_expands_cryptokey_allowed_ips() {
        let source = config("Address=10.77.0.2/32", "AllowedIPs=10.0.0.0/8");
        let plan = parse_wireguard_config(&source, &[route("172.16.0.0/16")]).unwrap();
        assert_eq!(plan.routes, vec![route("172.16.0.0/16")]);
        assert!(plan
            .setconf
            .contains("AllowedIPs = 10.0.0.0/8, 172.16.0.0/16"));
    }

    #[test]
    fn duplicate_peer_allowed_ips_are_rejected_even_with_policy_routes() {
        let source = config("Address=10.77.0.2/32", "AllowedIPs=10.0.0.0/8");
        let source = format!("{source}[Peer]\nPublicKey={KEY}\nAllowedIPs=10.0.0.0/8\n");
        let error = parse_wireguard_config(&source, &[route("10.2.0.0/16")]).unwrap_err();
        assert!(error.to_string().contains("duplicate AllowedIPs"));
    }

    #[test]
    fn overlapping_peer_allowed_ips_are_rejected() {
        let source = config("Address=10.77.0.2/32", "AllowedIPs=10.0.0.0/8");
        let source = format!("{source}[Peer]\nPublicKey={KEY}\nAllowedIPs=10.1.0.0/16\n");
        let error = parse_wireguard_config(&source, &[]).unwrap_err();
        assert!(error.to_string().contains("overlapping AllowedIPs"));
    }

    #[test]
    fn def1_style_halves_are_a_full_tunnel() {
        let source = config(
            "Address=10.77.0.2/32, fd77::2/128",
            "AllowedIPs=0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1",
        );
        let plan = parse_wireguard_config(&source, &[]).unwrap();
        assert!(plan.full_ipv4 && plan.full_ipv6);
        let half = config("Address=10.77.0.2/32", "AllowedIPs=0.0.0.0/1");
        assert!(!parse_wireguard_config(&half, &[]).unwrap().full_ipv4);
    }

    #[test]
    fn noncanonical_full_coverage_cannot_be_treated_as_split_tunnel() {
        let source = config(
            "Address=10.77.0.2/32",
            "AllowedIPs=0.0.0.0/2, 64.0.0.0/2, 128.0.0.0/2, 192.0.0.0/2",
        );
        assert!(parse_wireguard_config(&source, &[]).is_err());
    }

    #[test]
    fn duplicate_addresses_are_owned_once() {
        let source = config(
            "Address=10.77.0.2/32, 10.77.0.2/32\nAddress=10.77.0.2/32",
            "AllowedIPs=10.0.0.0/8",
        );
        let plan = parse_wireguard_config(&source, &[]).unwrap();
        assert_eq!(
            plan.addresses,
            vec!["10.77.0.2/32".parse::<IpNet>().unwrap()]
        );
    }

    #[test]
    fn client_config_needs_address_and_peer_allowed_ips() {
        let no_address = config("", "AllowedIPs=10.0.0.0/8");
        assert!(parse_wireguard_config(&no_address, &[]).is_err());
        let no_allowed = config("Address=10.77.0.2/32", "");
        assert!(parse_wireguard_config(&no_allowed, &[]).is_err());
    }

    #[test]
    fn rejects_split_dns_server_unreachable_through_selected_route() {
        let source = config(
            "Address=10.77.0.2/32\nDNS=192.0.2.53",
            "AllowedIPs=10.0.0.0/8",
        );
        let error = parse_wireguard_config(&source, &[]).unwrap_err();
        assert!(error.to_string().contains("DNS"));
    }

    #[test]
    fn rejects_oversized_config_and_excess_peers() {
        let source = "x".repeat(MAX_WIREGUARD_CONFIG_BYTES + 1);
        assert!(parse_wireguard_config(&source, &[]).is_err());
        let mut source = config("", "AllowedIPs=10.0.0.0/8");
        for _ in 0..MAX_WIREGUARD_PEERS {
            source.push_str(&format!(
                "[Peer]\nPublicKey={KEY}\nAllowedIPs=192.0.2.0/24\n"
            ));
        }
        assert!(parse_wireguard_config(&source, &[]).is_err());
    }

    #[test]
    fn duplicate_single_value_fields_are_rejected() {
        let cases = [
            config(
                "ListenPort=51820\nListenPort=51821",
                "AllowedIPs=10.0.0.0/8",
            ),
            config(
                "Address=10.77.0.2/32",
                &format!("PresharedKey={KEY}\nPresharedKey={KEY}\nAllowedIPs=10.0.0.0/8"),
            ),
            config(
                "Address=10.77.0.2/32",
                "PersistentKeepalive=20\nPersistentKeepalive=30\nAllowedIPs=10.0.0.0/8",
            ),
        ];
        for source in cases {
            assert!(parse_wireguard_config(&source, &[]).is_err());
        }
    }

    #[test]
    fn endpoint_requires_unambiguous_host_and_port() {
        let base = config("Address=fd77::2/128", "AllowedIPs=::/0")
            .replace("Endpoint = peer.example.test:51820\n", "");
        let good = base.replace(
            "AllowedIPs=::/0",
            "Endpoint=[2001:db8::1]:51820\nAllowedIPs=::/0",
        );
        assert!(parse_wireguard_config(&good, &[]).is_ok());
        for endpoint in [
            "2001:db8::1:51820",
            "[peer.example.test]:51820",
            "[2001:db8::1]:0",
        ] {
            let source = base.replace(
                "AllowedIPs=::/0",
                &format!("Endpoint={endpoint}\nAllowedIPs=::/0"),
            );
            assert!(parse_wireguard_config(&source, &[]).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn dns_domains_need_a_dns_server() {
        let source = config(
            "Address=10.77.0.2/32\nDNS=corp.test",
            "AllowedIPs=10.0.0.0/8",
        );
        assert!(parse_wireguard_config(&source, &[]).is_err());
    }
}
