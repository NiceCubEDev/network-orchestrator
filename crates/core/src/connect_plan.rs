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
    interfaces.iter().any(|iface| {
        matches!(iface.state, InterfaceState::Up)
            && (iface.friendly_name == profile.interface_name
                || iface.name == profile.interface_name)
    })
}

/// Exact Linux-managed Xray TUN capture, shared by execution and route analysis.
pub fn linux_xray_tun_routes(profile: &Profile) -> Vec<PolicyRoute> {
    let routes = profile.effective_routes();
    if profile.tunnel_role != TunnelRole::Primary || !routes.is_empty() {
        return routes;
    }
    let route = |destination: &str| PolicyRoute {
        destination: destination.parse().unwrap(),
        metric: 5,
        via: None,
    };
    if profile.xray_split_default {
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
pub fn resolve_install_interface(profile: &Profile) -> Option<String> {
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
