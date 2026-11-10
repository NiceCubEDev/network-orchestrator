//! Platform-neutral decisions behind connecting a profile: conflict checks
//! against running tunnels, which routes to install, which interface to bind
//! them to and how to wait for a freshly started backend. Shared by the Tauri
//! app and (later) the Linux CLI.

use crate::analysis;
use crate::models::*;
use crate::vpn::TunnelManager;
use ipnet::IpNet;
use std::net::{Ipv4Addr, TcpStream};
use std::time::{Duration, Instant};

/// Detect a full address-family union even when no single route is `/0`.
pub fn full_coverage(routes: impl IntoIterator<Item = IpNet>) -> (bool, bool) {
    let networks: Vec<_> = routes.into_iter().collect();
    let aggregated = IpNet::aggregate(&networks);
    (
        aggregated
            .iter()
            .any(|net| matches!(net, IpNet::V4(net) if net.prefix_len() == 0)),
        aggregated
            .iter()
            .any(|net| matches!(net, IpNet::V6(net) if net.prefix_len() == 0)),
    )
}

pub fn has_target_interface(profile: &Profile, interfaces: &[NetworkInterface]) -> bool {
    #[cfg(windows)]
    let gateways = if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun {
        match windows_xray_tun_gateways(profile) {
            Ok(gateways) => Some(gateways),
            Err(_) => return false,
        }
    } else {
        None
    };
    interfaces.iter().any(|iface| {
        let ready = matches!(iface.state, InterfaceState::Up)
            && (iface.friendly_name == profile.interface_name
                || iface.name == profile.interface_name);
        #[cfg(windows)]
        let ready = ready
            && gateways.as_ref().is_none_or(|gateways| {
                gateways.iter().all(|gateway| {
                    iface.addresses.iter().any(|address| {
                        address.address == gateway.addr()
                            && address.prefix_len == gateway.prefix_len()
                    })
                })
            });
        ready
    })
}

/// Addresses assigned by Windows TUN startup after its initial route-table reset.
pub fn windows_xray_tun_gateways(profile: &Profile) -> std::io::Result<Vec<IpNet>> {
    let ipv4: ipnet::Ipv4Net = profile
        .xray_tun_ip
        .as_deref()
        .unwrap_or("172.19.0.1/30")
        .trim()
        .parse()
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid Windows TUN IPv4 address",
            )
        })?;
    if ipv4.prefix_len() == 0
        || ipv4.addr().is_unspecified()
        || ipv4.addr().is_multicast()
        || ipv4.addr().is_loopback()
        || ipv4.addr().is_broadcast()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Windows TUN IPv4 address",
        ));
    }
    let routes = xray_tun_capture_routes(profile);
    let mut gateways = Vec::new();
    if routes
        .iter()
        .any(|route| route.destination.addr().is_ipv4())
    {
        gateways.push(IpNet::V4(ipv4));
    }
    if routes
        .iter()
        .any(|route| route.destination.addr().is_ipv6())
    {
        gateways.push("fd42:6e65:746f::1/126".parse().unwrap());
    }
    Ok(gateways)
}

/// Select the physical Windows uplink from actual default routes, independently
/// of VPN adapters and Xray's automatic interface-name heuristic.
pub fn windows_xray_uplink(
    interfaces: &[NetworkInterface],
    routes: &[RouteEntry],
) -> std::io::Result<String> {
    routes
        .iter()
        .filter(|route| route.prefix_len == 0 && route.destination.is_unspecified())
        .filter_map(|route| {
            interfaces
                .iter()
                .find(|interface| {
                    interface.if_index == route.interface_index
                        && interface.if_index != 0
                        && matches!(interface.state, InterfaceState::Up)
                        && interface.physical
                        && interface.category == InterfaceCategory::Physical
                        && !matches!(
                            &interface.kind,
                            InterfaceKind::WireGuard
                                | InterfaceKind::OpenVpn
                                | InterfaceKind::Xray
                                | InterfaceKind::Loopback
                        )
                        && !interface.friendly_name.is_empty()
                        && interface.friendly_name.trim() == interface.friendly_name
                        && !interface.friendly_name.eq_ignore_ascii_case("auto")
                        && interface.friendly_name.encode_utf16().count() <= 255
                        && !interface.friendly_name.chars().any(char::is_control)
                })
                .map(|interface| (route, interface))
        })
        .min_by_key(|(route, interface)| {
            (
                route.destination.is_ipv6(),
                route.metric,
                interface.if_index,
            )
        })
        .map(|(_, interface)| interface.friendly_name.clone())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no active physical default route is available for Windows TUN",
            )
        })
}

/// Exact managed Xray TUN capture, shared by execution and route analysis.
pub fn xray_tun_capture_routes(profile: &Profile) -> Vec<PolicyRoute> {
    let routes = profile.effective_routes();
    if profile.tunnel_role != TunnelRole::Primary || !routes.is_empty() {
        return routes;
    }
    let route = |destination: &str| PolicyRoute {
        destination: destination.parse().unwrap(),
        metric: 5,
        via: None,
    };
    if cfg!(windows) || profile.xray_split_default {
        vec![
            route("0.0.0.0/1"),
            route("128.0.0.0/1"),
            route("::/1"),
            route("8000::/1"),
        ]
    } else {
        vec![route("0.0.0.0/0"), route("::/0")]
    }
}

pub use self::xray_tun_capture_routes as linux_xray_tun_routes;

pub fn unknown_route_conflicts(
    candidate: &ConfigAnalysis,
    other: &Profile,
    other_analysis: &ConfigAnalysis,
) -> Vec<ProfileConflict> {
    let mut conflicts = Vec::new();
    if !other_analysis.route_knowledge_complete
        && (!candidate.os_routes.is_empty() || !candidate.route_knowledge_complete)
    {
        conflicts.push(ProfileConflict {
            kind: ConflictKind::RouteOverlap,
            message: format!(
                "cannot verify route conflicts with active profile '{}' because its effective routes are not fully known",
                other.name
            ),
            other_profile_id: Some(other.id.clone()),
            blocking: true,
        });
    } else if !candidate.route_knowledge_complete && !other_analysis.os_routes.is_empty() {
        conflicts.push(ProfileConflict {
            kind: ConflictKind::RouteOverlap,
            message: format!(
                "candidate routes are not fully known and may conflict with routes of active profile '{}'",
                other.name
            ),
            other_profile_id: Some(other.id.clone()),
            blocking: true,
        });
    }
    conflicts
}

pub fn active_profile_conflicts(
    tunnels: &mut TunnelManager,
    candidate_id: &str,
    candidate: &ConfigAnalysis,
    profiles: &[Profile],
) -> Result<Vec<ProfileConflict>, String> {
    let mut conflicts = Vec::new();
    for other in profiles {
        if other.id == candidate_id {
            continue;
        }
        if tunnels.status(other).state != TunnelState::Running {
            continue;
        }
        let other_analysis = analysis::analyze_profile(other).map_err(|_| {
            format!(
                "cannot verify conflicts with active profile '{}'",
                other.name
            )
        })?;
        conflicts.extend(unknown_route_conflicts(candidate, other, &other_analysis));
        conflicts.extend(analysis::conflicts_between(
            candidate,
            &other_analysis,
            true,
        ));
    }
    Ok(conflicts)
}

pub async fn wait_for_tcp_listener(port: u16, timeout: Duration, interval: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(interval).await;
    }
}

/// Wait for OpenVPN to log `PUSH_REPLY` (or `Initialization Sequence Completed`)
/// after connect, then return the server-pushed routes parsed from the log.
/// Returns an empty vec if the deadline passes without a PUSH_REPLY.
pub async fn wait_for_openvpn_pushed_routes(
    tunnels: &mut TunnelManager,
    profile: &Profile,
    timeout: Duration,
    interval: Duration,
) -> Vec<AnalyzedRoute> {
    let deadline = Instant::now() + timeout;
    loop {
        let routes = tunnels.openvpn_pushed_routes(&profile.id);
        if !routes.is_empty() {
            return routes;
        }
        if Instant::now() >= deadline {
            return Vec::new();
        }
        tokio::time::sleep(interval).await;
    }
}

/// Derive the routes to install for a profile when `profile.routes` is empty.
/// The app is the sole route installer, so when the user has not specified
/// explicit policy routes, we derive them from the backend's own route
/// information:
/// - WireGuard: AllowedIPs (static, known pre-connect from analysis).
/// - OpenVPN: server-pushed routes (dynamic, read from log post-connect).
/// - Xray SOCKS: no OS routes (proxy-based, no interface routes).
/// - None: no derivation (static-routes profiles require explicit routes).
pub fn derive_installable_routes(
    analysis: &ConfigAnalysis,
    pushed: &[AnalyzedRoute],
    backend: TunnelBackend,
) -> Vec<PolicyRoute> {
    match backend {
        TunnelBackend::WireGuard => analysis
            .os_routes
            .iter()
            .filter(|r| r.source.contains("WireGuard"))
            .map(|r| PolicyRoute {
                destination: r.destination,
                metric: 5,
                via: None,
            })
            .collect(),
        TunnelBackend::OpenVpn => pushed
            .iter()
            .chain(
                analysis
                    .os_routes
                    .iter()
                    .filter(|r| r.source.contains("OpenVPN") && !r.source.contains("pushed")),
            )
            .map(|r| PolicyRoute {
                destination: r.destination,
                metric: 5,
                via: None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Resolve the interface name for route installation. For WireGuard, if the
/// profile has no explicit interface name, derive it from the config file name
/// (the tunnel service creates an interface named after the config stem).
/// Windows Xray TUN uses the adapter named by its TUN settings.
pub fn resolve_install_interface(profile: &Profile) -> Option<String> {
    #[cfg(target_os = "windows")]
    if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun {
        let name = profile
            .xray_tun_interface
            .as_deref()
            .unwrap_or("xray-tun")
            .trim();
        return (!name.is_empty()).then(|| name.to_string());
    }
    if !profile.interface_name.trim().is_empty() {
        return Some(profile.interface_name.clone());
    }
    match profile.backend {
        TunnelBackend::WireGuard => crate::vpn::wireguard_tunnel_name(&profile.config_path).ok(),
        _ => None,
    }
}

/// Profiles to start when the app launches: flagged `auto_connect`, in saved
/// order, skipping the ones a backend already reports as running.
pub fn auto_connect_candidates(
    profiles: &[Profile],
    is_running: impl Fn(&Profile) -> bool,
) -> Vec<&Profile> {
    profiles
        .iter()
        .filter(|profile| profile.auto_connect && !is_running(profile))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::path::PathBuf;

    #[test]
    fn full_coverage_detects_decomposed_ipv4_and_ipv6_unions() {
        let networks: Vec<IpNet> = [
            "0.0.0.0/2",
            "64.0.0.0/2",
            "128.0.0.0/2",
            "192.0.0.0/2",
            "::/2",
            "4000::/2",
            "8000::/2",
            "c000::/2",
        ]
        .into_iter()
        .map(|network| network.parse().unwrap())
        .collect();
        assert_eq!(full_coverage(networks.iter().copied()), (true, true));
        assert_eq!(full_coverage(networks[..3].iter().copied()), (false, false));
    }

    fn profile(interface_name: &str) -> Profile {
        Profile {
            id: "p1".into(),
            name: "P1".into(),
            backend: TunnelBackend::WireGuard,
            config_path: PathBuf::from("p1.conf"),
            interface_name: interface_name.into(),
            ..Default::default()
        }
    }

    fn candidate_profile() -> Profile {
        let mut p = profile("wg-a");
        p.id = "a".into();
        p
    }

    fn iface(name: &str, friendly_name: &str, state: InterfaceState) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            friendly_name: friendly_name.into(),
            kind: InterfaceKind::Other("test".into()),
            state,
            addresses: vec![],
            dns_servers: vec![],
            dns_suffix: None,
            mtu: None,
            if_index: 1,
            physical: true,
            mac: None,
            gateway: None,
            ipv6_gateway: None,
            rx_bytes: None,
            tx_bytes: None,
            link_speed_mbps: None,
            category: InterfaceCategory::Physical,
            description: String::new(),
            if_type: 6,
            tunnel_type: None,
        }
    }

    fn blank_analysis(id: &str) -> ConfigAnalysis {
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

    fn route(destination: &str, source: &str) -> AnalyzedRoute {
        AnalyzedRoute {
            metric: None,
            destination: destination.parse().unwrap(),
            source: source.into(),
        }
    }

    fn system_route(network: &str, index: u32, metric: u32) -> RouteEntry {
        let network: IpNet = network.parse().unwrap();
        RouteEntry {
            destination: network.network(),
            prefix_len: network.prefix_len(),
            gateway: None,
            interface_index: index,
            interface_name: "route-table-name".into(),
            metric,
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_xray_tun_defaults_use_split_capture_regardless_of_legacy_flag() {
        for split in [false, true] {
            let profile = Profile {
                xray_split_default: split,
                ..Default::default()
            };
            let routes: Vec<_> = xray_tun_capture_routes(&profile)
                .into_iter()
                .map(|route| route.destination.to_string())
                .collect();
            assert_eq!(routes, ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
        }
    }

    #[test]
    fn windows_xray_tun_gateways_match_captured_families_and_configured_host_address() {
        let mut profile = Profile::default();
        let gateways = |profile: &Profile| {
            windows_xray_tun_gateways(profile)
                .unwrap()
                .into_iter()
                .map(|gateway| gateway.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            gateways(&profile),
            ["172.19.0.1/30", "fd42:6e65:746f::1/126"]
        );
        profile.xray_tun_ip = Some("10.5.0.7/24".into());
        profile.routes = vec![PolicyRoute {
            destination: "10.20.0.0/16".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        assert_eq!(gateways(&profile), ["10.5.0.7/24"]);
        profile.routes[0].destination = "fd00:50::/64".parse().unwrap();
        assert_eq!(gateways(&profile), ["fd42:6e65:746f::1/126"]);
    }

    #[test]
    fn windows_xray_tun_gateways_reject_invalid_ipv4_addresses() {
        for address in [
            "invalid",
            "0.0.0.0/30",
            "127.0.0.1/8",
            "224.0.0.1/4",
            "10.0.0.1/0",
        ] {
            let profile = Profile {
                xray_tun_ip: Some(address.into()),
                ..Default::default()
            };
            assert!(windows_xray_tun_gateways(&profile).is_err(), "{address}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_xray_tun_readiness_waits_for_all_gateway_addresses_and_prefixes() {
        let profile = Profile {
            backend: TunnelBackend::Xray,
            xray_mode: XrayMode::Tun,
            interface_name: "xray-tun".into(),
            ..Default::default()
        };
        let mut interface = iface("adapter-id", "xray-tun", InterfaceState::Up);
        assert!(!has_target_interface(&profile, &[interface.clone()]));
        interface.addresses.push(InterfaceAddress {
            address: "172.19.0.1".parse().unwrap(),
            prefix_len: 30,
            family: AddressFamily::Ipv4,
        });
        assert!(!has_target_interface(&profile, &[interface.clone()]));
        interface.addresses.push(InterfaceAddress {
            address: "fd42:6e65:746f::1".parse().unwrap(),
            prefix_len: 126,
            family: AddressFamily::Ipv6,
        });
        assert!(has_target_interface(&profile, &[interface.clone()]));
        interface.addresses[0].prefix_len = 31;
        assert!(!has_target_interface(&profile, &[interface.clone()]));
        interface.addresses[0].prefix_len = 30;
        interface.state = InterfaceState::Down;
        assert!(!has_target_interface(&profile, &[interface]));
    }

    #[test]
    fn windows_xray_uplink_uses_physical_default_even_when_vpn_metric_is_lower() {
        let mut ethernet = iface("ethernet-id", "Проводная сеть", InterfaceState::Up);
        ethernet.if_index = 7;
        let mut netbird = iface("netbird-id", "wt0", InterfaceState::Up);
        netbird.if_index = 9;
        netbird.category = InterfaceCategory::Vpn;
        let mut tun = iface("xray-id", "xray-tun", InterfaceState::Up);
        tun.if_index = 10;
        tun.kind = InterfaceKind::Xray;
        let mut virtual_adapter = iface("virtual-id", "vEthernet", InterfaceState::Up);
        virtual_adapter.if_index = 11;
        virtual_adapter.physical = false;
        let mut wifi_without_default = iface("wifi-id", "Wi-Fi", InterfaceState::Up);
        wifi_without_default.if_index = 12;
        let interfaces = [
            ethernet,
            netbird,
            tun,
            virtual_adapter,
            wifi_without_default,
        ];
        let routes = [
            system_route("0.0.0.0/0", 9, 1),
            system_route("0.0.0.0/0", 10, 0),
            system_route("0.0.0.0/0", 11, 0),
            system_route("0.0.0.0/0", 7, 40),
        ];
        assert_eq!(
            windows_xray_uplink(&interfaces, &routes).unwrap(),
            "Проводная сеть"
        );
    }

    #[test]
    fn windows_xray_uplink_prefers_ipv4_then_lowest_route_metric() {
        let mut ethernet = iface("ethernet-id", "Ethernet", InterfaceState::Up);
        ethernet.if_index = 7;
        let mut wifi = iface("wifi-id", "Wi-Fi", InterfaceState::Up);
        wifi.if_index = 8;
        let interfaces = [ethernet, wifi];
        let mut routes = vec![
            system_route("::/0", 7, 1),
            system_route("0.0.0.0/0", 8, 900),
            system_route("0.0.0.0/0", 7, u32::MAX),
        ];
        assert_eq!(windows_xray_uplink(&interfaces, &routes).unwrap(), "Wi-Fi");
        routes.push(system_route("0.0.0.0/0", 7, 2));
        assert_eq!(
            windows_xray_uplink(&interfaces, &routes).unwrap(),
            "Ethernet"
        );
    }

    #[test]
    fn windows_xray_uplink_falls_back_to_ipv6_default() {
        let interfaces = [iface("ethernet-id", "Ethernet", InterfaceState::Up)];
        assert_eq!(
            windows_xray_uplink(&interfaces, &[system_route("::/0", 1, 10)]).unwrap(),
            "Ethernet"
        );
    }

    #[test]
    fn windows_xray_uplink_rejects_missing_or_ineligible_physical_defaults() {
        let ethernet = iface("ethernet-id", "Ethernet", InterfaceState::Up);
        for routes in [
            vec![],
            vec![system_route("192.0.2.0/24", 1, 1)],
            vec![system_route("0.0.0.0/0", 99, 1)],
        ] {
            assert!(windows_xray_uplink(std::slice::from_ref(&ethernet), &routes).is_err());
        }
        for variant in 0..7 {
            let mut interface = ethernet.clone();
            match variant {
                0 => interface.state = InterfaceState::Down,
                1 => interface.physical = false,
                2 => interface.category = InterfaceCategory::Virtual,
                3 => interface.kind = InterfaceKind::WireGuard,
                4 => interface.friendly_name = " ".into(),
                5 => interface.friendly_name = "auto".into(),
                _ => interface.friendly_name = "bad\nname".into(),
            }
            assert_eq!(
                windows_xray_uplink(&[interface], &[system_route("0.0.0.0/0", 1, 1)])
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
        }
    }

    #[test]
    fn target_interface_matches_exact_friendly_or_raw_name() {
        let p = profile("wg-work");
        let interfaces = vec![
            iface("if0", "wg-work", InterfaceState::Up),
            iface("if1", "other", InterfaceState::Up),
        ];
        assert!(has_target_interface(&p, &interfaces));

        let p_raw = profile("if1");
        assert!(has_target_interface(&p_raw, &interfaces));
    }

    #[test]
    fn target_interface_rejects_down_state() {
        let p = profile("wg-work");
        let interfaces = vec![iface("if0", "wg-work", InterfaceState::Down)];
        assert!(!has_target_interface(&p, &interfaces));
    }

    #[test]
    fn target_interface_rejects_substring_matches() {
        let p = profile("wg-work");
        let interfaces = vec![
            iface("wg-work-extra", "wg", InterfaceState::Up),
            iface("xwg-work", "my-wg-work-tunnel", InterfaceState::Up),
        ];
        assert!(!has_target_interface(&p, &interfaces));
    }

    #[test]
    fn active_profile_conflicts_skips_non_running_profiles() {
        let mut tunnels = TunnelManager::new();
        let candidate = ConfigAnalysis {
            profile_id: "a".into(),
            os_routes: vec![AnalyzedRoute {
                metric: None,
                destination: "10.0.0.0/8".parse().unwrap(),
                source: "test".into(),
            }],
            internal_routes: vec![],
            listeners: vec![],
            endpoints: vec![],
            domain_patterns: vec![],
            warnings: vec![],
            route_knowledge_complete: true,
            peers: Vec::new(),
            interface_details: Vec::new(),
        };
        let mut other = profile("wg-b");
        other.id = "b".into();
        other.config_path = std::path::PathBuf::from("nonexistent.conf");

        let conflicts = active_profile_conflicts(&mut tunnels, "a", &candidate, &[other]).unwrap();
        assert!(conflicts.is_empty());

        let same = active_profile_conflicts(&mut tunnels, "a", &candidate, &[candidate_profile()])
            .unwrap();
        assert!(same.is_empty());
    }

    #[test]
    fn unknown_route_conflicts_cover_uncertainty_both_directions() {
        let mut other = profile("ovpn-b");
        other.id = "b".into();
        other.name = "B".into();

        let mut complete_with_route = blank_analysis("a");
        complete_with_route.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        let mut incomplete_other = blank_analysis("b");
        incomplete_other.route_knowledge_complete = false;

        let conflicts = unknown_route_conflicts(&complete_with_route, &other, &incomplete_other);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].blocking);
        assert!(conflicts[0].message.contains("'B'"));
        assert!(conflicts[0]
            .message
            .contains("effective routes are not fully known"));

        let mut incomplete_candidate = blank_analysis("a");
        incomplete_candidate.route_knowledge_complete = false;
        let mut known_other = blank_analysis("b");
        known_other.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        let conflicts = unknown_route_conflicts(&incomplete_candidate, &other, &known_other);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].message.contains("not fully known"));
        assert!(conflicts[0].message.contains("'B'"));

        let mut both_incomplete_other = blank_analysis("b");
        both_incomplete_other.route_knowledge_complete = false;
        both_incomplete_other.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        let conflicts =
            unknown_route_conflicts(&incomplete_candidate, &other, &both_incomplete_other);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0]
            .message
            .contains("effective routes are not fully known"));
    }

    #[test]
    fn unknown_route_conflicts_skip_complete_candidate_without_routes() {
        let mut other = profile("ovpn-b");
        other.id = "b".into();
        other.name = "B".into();
        let candidate = blank_analysis("a");
        let mut incomplete_other = blank_analysis("b");
        incomplete_other.route_knowledge_complete = false;

        assert!(unknown_route_conflicts(&candidate, &other, &incomplete_other).is_empty());

        let mut known_other = blank_analysis("b");
        known_other.os_routes.push(AnalyzedRoute {
            metric: None,
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        assert!(unknown_route_conflicts(&candidate, &other, &known_other).is_empty());
    }

    #[tokio::test]
    async fn wait_for_tcp_listener_detects_live_and_dead_ports() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(
            wait_for_tcp_listener(port, Duration::from_millis(500), Duration::from_millis(50))
                .await
        );
        drop(listener);
        assert!(
            !wait_for_tcp_listener(port, Duration::from_millis(200), Duration::from_millis(50))
                .await
        );
    }

    #[test]
    fn wireguard_routes_come_from_allowed_ips_only() {
        let mut analysis = blank_analysis("p1");
        analysis.os_routes = vec![
            route("10.1.0.0/16", "WireGuard AllowedIPs"),
            route("192.0.2.1/32", "Xray endpoint"),
        ];
        let derived = derive_installable_routes(&analysis, &[], TunnelBackend::WireGuard);
        assert_eq!(derived.len(), 1);
        assert_eq!(derived[0].destination, "10.1.0.0/16".parse().unwrap());
        assert_eq!(derived[0].metric, 5);
        assert_eq!(derived[0].via, None);
    }

    #[test]
    fn openvpn_routes_are_pushed_plus_configured_but_not_stale_pushed() {
        let mut analysis = blank_analysis("p1");
        analysis.os_routes = vec![
            route("10.2.0.0/16", "OpenVPN route"),
            route("10.3.0.0/16", "OpenVPN pushed route"),
        ];
        let pushed = [route("10.9.0.0/16", "OpenVPN pushed route")];
        let derived = derive_installable_routes(&analysis, &pushed, TunnelBackend::OpenVpn);
        let destinations: Vec<String> = derived.iter().map(|r| r.destination.to_string()).collect();
        assert_eq!(destinations, ["10.9.0.0/16", "10.2.0.0/16"]);
    }

    #[test]
    fn proxy_and_static_backends_derive_nothing() {
        let mut analysis = blank_analysis("p1");
        analysis.os_routes = vec![route("10.1.0.0/16", "WireGuard AllowedIPs")];
        for backend in [TunnelBackend::Xray, TunnelBackend::None] {
            assert!(derive_installable_routes(&analysis, &[], backend).is_empty());
        }
    }

    #[test]
    fn install_interface_prefers_the_explicit_name_then_the_wireguard_stem() {
        assert_eq!(
            resolve_install_interface(&profile("corp0")).as_deref(),
            Some("corp0")
        );
        let mut unnamed = profile("  ");
        unnamed.config_path = PathBuf::from("/x/office.conf");
        assert_eq!(
            resolve_install_interface(&unnamed).as_deref(),
            Some("office")
        );
        unnamed.backend = TunnelBackend::OpenVpn;
        assert_eq!(resolve_install_interface(&unnamed), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_xray_tun_install_interface_matches_the_created_adapter() {
        let mut p = profile("Ethernet");
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        assert_eq!(resolve_install_interface(&p).as_deref(), Some("xray-tun"));

        p.xray_tun_interface = Some("  internet0  ".into());
        assert_eq!(resolve_install_interface(&p).as_deref(), Some("internet0"));

        p.xray_tun_interface = Some("   ".into());
        assert_eq!(resolve_install_interface(&p), None);

        p.xray_mode = XrayMode::Socks;
        assert_eq!(resolve_install_interface(&p).as_deref(), Some("Ethernet"));
    }

    #[test]
    fn auto_connect_keeps_saved_order_and_skips_running_or_unflagged() {
        let flagged = |id: &str| {
            let mut p = profile(id);
            p.id = id.into();
            p.auto_connect = true;
            p
        };
        let mut off = flagged("off");
        off.auto_connect = false;
        let profiles = [flagged("a"), off, flagged("b"), flagged("c")];
        let chosen = auto_connect_candidates(&profiles, |p| p.id == "b");
        let ids: Vec<&str> = chosen.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["a", "c"]);
    }

    #[test]
    fn auto_connect_is_empty_without_flagged_profiles() {
        assert!(auto_connect_candidates(&[profile("x")], |_| false).is_empty());
    }
}
