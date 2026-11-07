use crate::analysis::analyze_profile;
use crate::models::{
    PlannedRoute, Profile, RouteEntry, RouteMap, RoutePlanDiff, RoutePlanDiffKind,
};
use ipnet::IpNet;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub fn build_route_map(profiles: &[(Profile, bool)], effective: &[RouteEntry]) -> RouteMap {
    let mut predicted = Vec::new();
    let mut warnings = Vec::new();

    for (profile, active) in profiles {
        match analyze_profile(profile) {
            Ok(analysis) => {
                let interface_name = (!profile.interface_name.trim().is_empty())
                    .then(|| profile.interface_name.clone());
                for route in analysis.os_routes {
                    predicted.push(PlannedRoute {
                        destination: route.destination,
                        owner_profile_id: profile.id.clone(),
                        owner_name: profile.name.clone(),
                        source: route.source,
                        interface_name: interface_name.clone(),
                        metric: route.metric,
                        active: *active,
                    });
                }
            }
            Err(_) => warnings.push(format!(
                "could not analyze profile '{}' ('{}') for route plan",
                profile.name, profile.id
            )),
        }
    }

    predicted.sort_by(|a, b| {
        compare_nets(a.destination, b.destination)
            .then_with(|| a.owner_profile_id.cmp(&b.owner_profile_id))
    });

    let mut effective_sorted = effective.to_vec();
    effective_sorted.sort_by(|a, b| {
        compare_nets(
            IpNet::new(a.destination, a.prefix_len)
                .unwrap_or_else(|_| IpNet::new(a.destination, 0).unwrap()),
            IpNet::new(b.destination, b.prefix_len)
                .unwrap_or_else(|_| IpNet::new(b.destination, 0).unwrap()),
        )
        .then_with(|| a.interface_name.cmp(&b.interface_name))
        .then_with(|| a.metric.cmp(&b.metric))
    });

    let diffs = build_diffs(&predicted, &effective_sorted);
    RouteMap {
        predicted,
        effective: effective_sorted,
        diffs,
        warnings,
        pushed_routes: Vec::new(),
    }
}

pub fn predicted_winner(destination: IpAddr, routes: &[PlannedRoute]) -> Option<&PlannedRoute> {
    routes
        .iter()
        .filter(|r| r.active && r.destination.contains(&destination))
        .min_by(|a, b| {
            b.destination
                .prefix_len()
                .cmp(&a.destination.prefix_len())
                .then_with(|| metric_rank(a).cmp(&metric_rank(b)))
                .then_with(|| a.owner_profile_id.cmp(&b.owner_profile_id))
        })
}

pub fn parent_prefix(index: usize, routes: &[PlannedRoute]) -> Option<usize> {
    let target = routes.get(index)?;
    (0..index).rev().find(|&i| {
        let candidate = &routes[i];
        candidate.destination.prefix_len() < target.destination.prefix_len()
            && candidate
                .destination
                .contains(&target.destination.network())
    })
}

fn metric_rank(route: &PlannedRoute) -> u32 {
    route.metric.unwrap_or(u32::MAX)
}

fn family_rank(net: IpNet) -> u8 {
    match net {
        IpNet::V4(_) => 0,
        IpNet::V6(_) => 1,
    }
}

fn compare_nets(a: IpNet, b: IpNet) -> Ordering {
    family_rank(a)
        .cmp(&family_rank(b))
        .then_with(|| a.network().cmp(&b.network()))
        .then_with(|| a.prefix_len().cmp(&b.prefix_len()))
}

fn build_diffs(predicted: &[PlannedRoute], effective: &[RouteEntry]) -> Vec<RoutePlanDiff> {
    let mut diffs = Vec::new();
    let mut claims: BTreeMap<IpNet, Vec<String>> = BTreeMap::new();

    for route in predicted.iter().filter(|r| r.active) {
        claims
            .entry(route.destination)
            .or_default()
            .push(route.owner_profile_id.clone());

        let exact: Vec<&RouteEntry> = effective
            .iter()
            .filter(|e| {
                e.destination == route.destination.network()
                    && e.prefix_len == route.destination.prefix_len()
            })
            .collect();

        if exact.is_empty() {
            diffs.push(RoutePlanDiff {
                kind: RoutePlanDiffKind::Missing,
                destination: route.destination,
                message: format!(
                    "predicted route {} for profile '{}' is not present in the effective table",
                    route.destination, route.owner_name
                ),
                profile_ids: vec![route.owner_profile_id.clone()],
            });
        } else if let Some(expected) = &route.interface_name {
            if !exact.iter().any(|e| &e.interface_name == expected) {
                diffs.push(RoutePlanDiff {
                    kind: RoutePlanDiffKind::InterfaceMismatch,
                    destination: route.destination,
                    message: format!(
                        "route {} is present on interface(s) {} instead of expected '{}'",
                        route.destination,
                        exact
                            .iter()
                            .map(|e| e.interface_name.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        expected
                    ),
                    profile_ids: vec![route.owner_profile_id.clone()],
                });
            }
        }
    }

    for (destination, owners) in claims {
        let mut unique = owners;
        unique.sort();
        unique.dedup();
        if unique.len() > 1 {
            diffs.push(RoutePlanDiff {
                kind: RoutePlanDiffKind::ExactCompetition,
                destination,
                message: format!(
                    "route {} is claimed by multiple profiles: {}",
                    destination,
                    unique.join(", ")
                ),
                profile_ids: unique,
            });
        }
    }

    diffs
}

#[cfg(test)]
mod tests {
    use crate::models::{PolicyRoute, Profile, RouteEntry, RoutePlanDiffKind, TunnelBackend};
    use crate::route_plan::{build_route_map, parent_prefix, predicted_winner};
    use ipnet::IpNet;
    use std::fs;
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-routeplan-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wg_config(dir: &Path, name: &str, allowed: &str) -> PathBuf {
        let path = dir.join(format!("{name}.conf"));
        fs::write(
            &path,
            format!(
                "[Interface]\nPrivateKey=AAAA\n[Peer]\nPublicKey=BBBB\nEndpoint=198.51.100.1:1\nAllowedIPs={allowed}\n"
            ),
        )
        .unwrap();
        path
    }

    fn profile(id: &str, config: PathBuf, iface: &str, routes: Vec<PolicyRoute>) -> Profile {
        Profile {
            id: id.into(),
            name: format!("Profile {id}"),
            backend: TunnelBackend::WireGuard,
            config_path: config,
            interface_name: iface.into(),
            routes,
            ..Default::default()
        }
    }

    fn route_entry(cidr: &str, interface: &str, metric: u32) -> RouteEntry {
        let net: IpNet = cidr.parse().unwrap();
        RouteEntry {
            destination: net.network(),
            prefix_len: net.prefix_len(),
            gateway: None,
            interface_index: 1,
            interface_name: interface.into(),
            metric,
        }
    }

    #[test]
    fn nested_prefixes_sort_parent_first_and_have_no_conflict() {
        let dir = unique_dir("nested");
        let broad = profile("wg-a", wg_config(&dir, "a", "10.0.0.0/8"), "wg-a", vec![]);
        let narrow = profile("wg-b", wg_config(&dir, "b", "10.20.0.0/16"), "wg-b", vec![]);
        let effective = vec![
            route_entry("10.0.0.0/8", "wg-a", 5),
            route_entry("10.20.0.0/16", "wg-b", 5),
        ];

        let map = build_route_map(&[(broad, true), (narrow, true)], &effective);
        assert!(map.diffs.is_empty(), "{:?}", map.diffs);
        assert_eq!(map.predicted.len(), 2);
        assert_eq!(map.predicted[0].destination, "10.0.0.0/8".parse().unwrap());
        assert_eq!(
            map.predicted[1].destination,
            "10.20.0.0/16".parse().unwrap()
        );
        assert_eq!(parent_prefix(1, &map.predicted), Some(0));
        assert_eq!(parent_prefix(0, &map.predicted), None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_and_interface_mismatch_are_reported() {
        let dir = unique_dir("diffs");
        let missing = profile("wg-m", wg_config(&dir, "m", "10.9.0.0/24"), "wg-m", vec![]);
        let mismatched = profile("wg-i", wg_config(&dir, "i", "10.8.0.0/24"), "wg-i", vec![]);
        let effective = vec![route_entry("10.8.0.0/24", "eth0", 5)];

        let map = build_route_map(&[(missing, true), (mismatched, true)], &effective);
        let missing_diff = map
            .diffs
            .iter()
            .find(|d| d.kind == RoutePlanDiffKind::Missing)
            .expect("missing diff");
        assert_eq!(missing_diff.destination, "10.9.0.0/24".parse().unwrap());
        let mismatch = map
            .diffs
            .iter()
            .find(|d| d.kind == RoutePlanDiffKind::InterfaceMismatch)
            .expect("mismatch diff");
        assert_eq!(mismatch.destination, "10.8.0.0/24".parse().unwrap());
        assert_eq!(mismatch.profile_ids, vec!["wg-i".to_string()]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn exact_competition_reported_once_per_prefix() {
        let dir = unique_dir("compete");
        let a = profile("wg-a", wg_config(&dir, "a", "10.0.0.0/8"), "wg-a", vec![]);
        let b = profile("wg-b", wg_config(&dir, "b", "10.0.0.0/8"), "wg-b", vec![]);

        let map = build_route_map(&[(a, true), (b, true)], &[]);
        let competitions: Vec<_> = map
            .diffs
            .iter()
            .filter(|d| d.kind == RoutePlanDiffKind::ExactCompetition)
            .collect();
        assert_eq!(competitions.len(), 1);
        assert_eq!(competitions[0].destination, "10.0.0.0/8".parse().unwrap());
        assert_eq!(
            competitions[0].profile_ids,
            vec!["wg-a".to_string(), "wg-b".to_string()]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn predicted_winner_prefers_lpm_then_metric_then_owner() {
        let dir = unique_dir("winner");
        let mk = |id: &str, name: &str, cidr: &str, metric: u32| {
            profile(
                id,
                wg_config(&dir, name, cidr),
                id,
                vec![PolicyRoute {
                    destination: cidr.parse().unwrap(),
                    metric,
                    via: None,
                }],
            )
        };
        let wide = mk("z-owner", "wide", "10.0.0.0/8", 100);
        let narrow_a = mk("a-owner", "na", "10.20.0.0/16", 50);
        let narrow_b = mk("b-owner", "nb", "10.20.0.0/16", 50);
        let probe: IpAddr = "10.20.1.5".parse().unwrap();

        let map = build_route_map(&[(wide, true), (narrow_a, true), (narrow_b, true)], &[]);
        let winner = predicted_winner(probe, &map.predicted).unwrap();
        assert_eq!(winner.destination, "10.20.0.0/16".parse().unwrap());
        assert_eq!(winner.owner_profile_id, "a-owner");

        let cheap = mk("cheap", "cheap", "10.30.0.0/16", 10);
        let pricey = mk("pricey", "pricey", "10.30.0.0/16", 90);
        let map2 = build_route_map(&[(pricey, true), (cheap, true)], &[]);
        let probe2: IpAddr = "10.30.1.1".parse().unwrap();
        assert_eq!(
            predicted_winner(probe2, &map2.predicted)
                .unwrap()
                .owner_profile_id,
            "cheap"
        );

        let inactive = mk("dead", "dead", "10.40.0.0/16", 1);
        let map3 = build_route_map(&[(inactive, false)], &[]);
        let probe3: IpAddr = "10.40.0.1".parse().unwrap();
        assert!(predicted_winner(probe3, &map3.predicted).is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ipv6_sorts_after_ipv4_and_parents_stay_in_family() {
        let dir = unique_dir("v6");
        let v4 = profile("wg-4", wg_config(&dir, "v4", "10.0.0.0/8"), "wg-4", vec![]);
        let v6 = profile(
            "wg-6",
            wg_config(&dir, "v6", "fd00::/8, fd00:1::/32"),
            "wg-6",
            vec![],
        );

        let map = build_route_map(&[(v4, true), (v6, true)], &[]);
        assert_eq!(map.predicted.len(), 3);
        assert!(matches!(map.predicted[0].destination, IpNet::V4(_)));
        let v6_parent = map
            .predicted
            .iter()
            .position(|r| r.destination == "fd00:1::/32".parse().unwrap())
            .unwrap();
        let parent = parent_prefix(v6_parent, &map.predicted).unwrap();
        assert_eq!(
            map.predicted[parent].destination,
            "fd00::/8".parse().unwrap()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inactive_routes_produce_no_diffs() {
        let dir = unique_dir("inactive");
        let p = profile(
            "wg-off",
            wg_config(&dir, "off", "10.50.0.0/24"),
            "wg-off",
            vec![],
        );

        let map = build_route_map(&[(p, false)], &[]);
        assert_eq!(map.predicted.len(), 1);
        assert!(!map.predicted[0].active);
        assert!(map.diffs.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn analysis_failure_produces_warning_without_config_path() {
        let dir = unique_dir("bad");
        let p = profile("wg-bad", dir.join("SECRET-NAME-77.conf"), "wg-bad", vec![]);

        let map = build_route_map(&[(p, true)], &[]);
        assert_eq!(map.warnings.len(), 1);
        assert!(map.warnings[0].contains("wg-bad"));
        assert!(!map.warnings[0].contains("SECRET-NAME-77"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_map_matches_dual_stack_split_and_explicit_capture() {
        use crate::models::XrayMode;
        use std::os::unix::fs::OpenOptionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("xray.json");
        let config = crate::xray::generate_share_link_config_with_http(
            "vless://11111111-2222-4333-8444-555555555555@192.0.2.1:443?type=raw&security=none",
            10808,
            10809,
        )
        .unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        serde_json::to_writer(file, &config).unwrap();
        let mut profile = Profile {
            id: "xray-capture".into(),
            name: "Xray capture".into(),
            backend: TunnelBackend::Xray,
            config_path: path,
            interface_name: "xray-test".into(),
            xray_mode: XrayMode::Tun,
            xray_socks_port: Some(10808),
            xray_http_port: Some(10809),
            ..Default::default()
        };
        for (split, prefixes) in [
            (false, vec!["0.0.0.0/0", "::/0"]),
            (true, vec!["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]),
        ] {
            profile.xray_split_default = split;
            let effective: Vec<_> = prefixes
                .into_iter()
                .map(|prefix| route_entry(prefix, "xray-test", 5))
                .collect();
            let map = build_route_map(&[(profile.clone(), true)], &effective);
            assert!(map.diffs.is_empty(), "{:?}", map.diffs);
            for destination in ["203.0.113.1", "2001:db8::1", "fd00::1"] {
                assert_eq!(
                    predicted_winner(destination.parse().unwrap(), &map.predicted)
                        .map(|route| route.owner_profile_id.as_str()),
                    Some(profile.id.as_str()),
                );
            }
        }
        profile.routes = vec![PolicyRoute {
            destination: "2001:db8:1234::/48".parse().unwrap(),
            metric: 17,
            via: None,
        }];
        let map = build_route_map(
            &[(profile, true)],
            &[route_entry("2001:db8:1234::/48", "xray-test", 17)],
        );
        assert!(map.diffs.is_empty(), "{:?}", map.diffs);
        assert!(predicted_winner("2001:db8:1234::1".parse().unwrap(), &map.predicted).is_some());
        for destination in ["203.0.113.1", "2001:db8:5678::1"] {
            assert!(predicted_winner(destination.parse().unwrap(), &map.predicted).is_none());
        }
    }
}
