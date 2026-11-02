use super::*;
use crate::{
    config_vault::ConfigVault,
    models::{NodePoolFilter, PinnedRoute, SubscriptionMeta, TunnelBackend},
    profiles::ProfileStore,
    subscription::{self, endpoint_key},
};
use std::collections::HashMap;

fn vless(host: &str, port: u16, name: &str) -> String {
    format!("vless://uuid@{host}:{port}?security=tls&sni=a.test&type=tcp#{name}")
}

/// Subscription profile + endpoints without touching the network: endpoints
/// go straight to the vault sidecar.
fn fixture(dir: &std::path::Path, endpoints: &[(&str, u16, &str)]) -> (ConfigVault, ProfileStore) {
    let vault = ConfigVault::new(dir.join("configs"));
    let store = ProfileStore::new(dir.join("profiles.json"));
    let stored: Vec<SubscriptionEndpoint> = endpoints
        .iter()
        .map(|(host, port, name)| SubscriptionEndpoint {
            url: vless(host, *port, name),
            name: name.to_string(),
        })
        .collect();
    vault.store_subscription_endpoints("sub", &stored).unwrap();
    let primary_key = endpoint_key(&stored[0].url);
    store
        .upsert(crate::models::Profile {
            id: "sub".into(),
            name: "Nodes".into(),
            backend: TunnelBackend::Xray,
            config_path: dir.join("config.json"),
            subscription: Some(SubscriptionMeta {
                url: "https://sub.example.test/token".into(),
                hwid: String::new(),
                endpoint_count: stored.len(),
                active_index: 0,
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
                active_key: Some(primary_key),
                backup_keys: Vec::new(),
                auto_return_primary: None,
                probe_url: None,
                node_pool: None,
                pool_keys: Vec::new(),
            }),
            ..crate::models::Profile::default()
        })
        .unwrap();
    (vault, store)
}

fn canada_pool() -> NodePoolSettings {
    NodePoolSettings {
        filters: vec![NodePoolFilter {
            name_contains: vec!["canada".into()],
            exit_country: Some("CA".into()),
        }],
        verify_exit_country: true,
    }
}

fn fake_probe<'m>(
    exits: &'m HashMap<&'static str, &'static str>,
) -> impl Fn(&SubscriptionEndpoint) -> std::future::Ready<Result<ExitCountry, String>> + 'm {
    move |endpoint| {
        std::future::ready(match exits.get(endpoint.name.as_str()) {
            Some(country) => Ok(ExitCountry {
                country: country.to_string(),
                ip: "203.0.113.9".into(),
            }),
            None => Err("unreachable".into()),
        })
    }
}

fn load_meta(store: &ProfileStore) -> SubscriptionMeta {
    store
        .load()
        .unwrap()
        .profiles
        .remove(0)
        .subscription
        .unwrap()
}
#[test]
fn disabled_pool_members_cannot_activate_failover() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, store) = fixture(
        dir.path(),
        &[
            ("primary.test", 443, "Primary"),
            ("candidate.test", 443, "Dormant pool member"),
        ],
    );
    let endpoints = vault.read_subscription_endpoints("sub").unwrap();
    store
        .update_profile("sub", |profile| {
            profile.subscription.as_mut().unwrap().pool_keys = vec![EndpointRef {
                key: endpoint_key(&endpoints[1].url),
                name: endpoints[1].name.clone(),
            }];
            Ok(())
        })
        .unwrap();
    let profile = store.load().unwrap().profiles.remove(0);
    let (nodes, _) = subscription::failover_plan(&vault, &profile).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["Primary"]
    );
}

#[test]
fn name_only_pool_can_be_rebuilt_without_network_or_country_claims() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, store) = fixture(
        dir.path(),
        &[
            ("primary.test", 443, "Primary"),
            ("candidate.test", 443, "Canada One"),
        ],
    );
    set_node_pool(
        &store,
        "sub",
        Some(NodePoolSettings {
            filters: vec![NodePoolFilter {
                name_contains: vec!["Canada".into()],
                exit_country: None,
            }],
            verify_exit_country: false,
        }),
    )
    .unwrap();
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(rebuild_node_pool_with(&vault, &store, "sub", |_| async {
            Err("offline".into())
        }))
        .unwrap();
    assert_eq!(
        report
            .members
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>(),
        ["Canada One"]
    );
    assert_eq!(report.entries[0].verdict, NodePoolVerdict::Member);
    assert_eq!(report.entries[0].exit_country, None);
}

#[test]
fn pool_requires_opt_in_and_country_when_verifying() {
    let dir = tempfile::tempdir().unwrap();
    let (_vault, store) = fixture(dir.path(), &[("ca1.test", 443, "Canada One")]);
    // Disabled by default: a rebuild without opt-in fails.
    let err = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(rebuild_node_pool_with(
            &ConfigVault::new(dir.path().join("configs")),
            &store,
            "sub",
            |_| async { Err("unreachable".to_string()) },
        ))
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    // Verification on: name-only filters are refused — a flag/name is not proof.
    let mut settings = canada_pool();
    settings.filters[0].exit_country = None;
    assert!(set_node_pool(&store, "sub", Some(settings)).is_err());
    // Verification off: a term-less match-all filter is refused.
    let settings = NodePoolSettings {
        filters: vec![NodePoolFilter {
            name_contains: vec![],
            exit_country: None,
        }],
        verify_exit_country: false,
    };
    assert!(set_node_pool(&store, "sub", Some(settings)).is_err());
}

#[test]
fn country_mismatch_rejects_healthy_node_and_explicits_never_join() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, store) = fixture(
        dir.path(),
        &[
            ("ca1.test", 443, "Canada Primary"),
            ("ca2.test", 443, "Canada Backup"),
            ("ca3.test", 443, "Canada Pool A"),
            ("ca4.test", 443, "Canada Pool B"),
            ("de1.test", 443, "Germany One"),
        ],
    );
    // Primary is endpoints[0]; pin endpoints[1] explicitly; keep 3+4 for pool.
    let endpoints = vault.read_subscription_endpoints("sub").unwrap();
    let pinned = endpoint_key(&endpoints[1].url);
    subscription::set_backup_endpoints(&vault, &store, "sub", std::slice::from_ref(&pinned))
        .unwrap();
    subscription::set_pinned_routes(
        &vault,
        &store,
        "sub",
        vec![PinnedRoute {
            selectors: vec!["domain:pinned.example".into()],
            endpoint_key: pinned.clone(),
            missing: false,
        }],
    )
    .unwrap();
    set_node_pool(&store, "sub", Some(canada_pool())).unwrap();

    let exits: HashMap<&'static str, &'static str> = HashMap::from([
        ("Canada Pool A", "CA"),
        ("Canada Pool B", "NL"), // healthy TLS, wrong exit country
    ]);
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(rebuild_node_pool_with(
            &vault,
            &store,
            "sub",
            fake_probe(&exits),
        ))
        .unwrap();

    // Only the verified CA node is a member.
    let meta = load_meta(&store);
    assert_eq!(meta.pool_keys.len(), 1);
    assert_eq!(meta.pool_keys[0].key, endpoint_key(&endpoints[2].url));
    assert!(report.pool_changed && !report.kept_previous);
    // Verdicts: primary + pinned reported Explicit, wrong country rejected.
    let verdict = |name: &str| {
        report
            .entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| (e.verdict, e.exit_country.clone()))
    };
    assert_eq!(
        verdict("Canada Primary"),
        Some((NodePoolVerdict::Explicit, None))
    );
    assert_eq!(
        verdict("Canada Backup"),
        Some((NodePoolVerdict::Explicit, None))
    );
    assert_eq!(
        verdict("Canada Pool B"),
        Some((NodePoolVerdict::WrongCountry, Some("NL".into())))
    );
    // Unmatched names never reach the report.
    assert!(verdict("Germany One").is_none());
}

#[test]
fn empty_rebuild_keeps_previous_pool_and_disable_clears() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, store) = fixture(
        dir.path(),
        &[("p.test", 443, "Primary"), ("ca1.test", 443, "Canada A")],
    );
    set_node_pool(&store, "sub", Some(canada_pool())).unwrap();
    let exits: HashMap<&'static str, &'static str> = HashMap::from([("Canada A", "CA")]);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime
        .block_on(rebuild_node_pool_with(
            &vault,
            &store,
            "sub",
            fake_probe(&exits),
        ))
        .unwrap();
    assert_eq!(load_meta(&store).pool_keys.len(), 1);

    // Second rebuild: candidate unreachable → previous pool kept.
    let report = runtime
        .block_on(rebuild_node_pool_with(
            &vault,
            &store,
            "sub",
            fake_probe(&HashMap::new()),
        ))
        .unwrap();
    assert!(report.kept_previous && !report.pool_changed);
    assert_eq!(load_meta(&store).pool_keys.len(), 1);

    // Disable: members drop with the setting.
    set_node_pool(&store, "sub", None).unwrap();
    assert!(load_meta(&store).pool_keys.is_empty());
    assert!(load_meta(&store).node_pool.is_none());
}

#[test]
fn live_country_mismatch_removes_a_previously_verified_member() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, store) = fixture(
        dir.path(),
        &[
            ("primary.test", 443, "Primary"),
            ("candidate.test", 443, "Canada A"),
        ],
    );
    set_node_pool(&store, "sub", Some(canada_pool())).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime
        .block_on(rebuild_node_pool_with(
            &vault,
            &store,
            "sub",
            fake_probe(&HashMap::from([("Canada A", "CA")])),
        ))
        .unwrap();
    assert_eq!(load_meta(&store).pool_keys.len(), 1);
    let report = runtime
        .block_on(rebuild_node_pool_with(
            &vault,
            &store,
            "sub",
            fake_probe(&HashMap::from([("Canada A", "NL")])),
        ))
        .unwrap();
    assert!(report.pool_changed && !report.kept_previous);
    assert!(report.members.is_empty());
    assert!(load_meta(&store).pool_keys.is_empty());
}

#[test]
fn retained_pool_cannot_reintroduce_new_explicit_domain_or_dns_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, store) = fixture(
        dir.path(),
        &[
            ("primary.test", 443, "Primary"),
            ("domain.test", 443, "Canada Domain"),
            ("dns.test", 443, "Canada DNS"),
            ("keep.test", 443, "Canada Keep"),
        ],
    );
    set_node_pool(&store, "sub", Some(canada_pool())).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let exits = HashMap::from([
        ("Canada Domain", "CA"),
        ("Canada DNS", "CA"),
        ("Canada Keep", "CA"),
    ]);
    runtime
        .block_on(rebuild_node_pool_with(
            &vault,
            &store,
            "sub",
            fake_probe(&exits),
        ))
        .unwrap();
    let endpoints = vault.read_subscription_endpoints("sub").unwrap();
    let keep = endpoint_key(&endpoints[3].url);
    store
        .update_profile("sub", |profile| {
            profile.pinned_policies.push(PinnedRoute {
                selectors: vec!["full:fixed.test".into()],
                endpoint_key: endpoint_key(&endpoints[1].url),
                missing: false,
            });
            profile.xray_dns.outbound_key = Some(endpoint_key(&endpoints[2].url));
            Ok(())
        })
        .unwrap();
    let profile = store.load().unwrap().profiles.remove(0);
    let (chain, _) = subscription::failover_plan(&vault, &profile).unwrap();
    assert_eq!(
        chain
            .iter()
            .skip(1)
            .map(|endpoint| endpoint_key(&endpoint.url))
            .collect::<Vec<_>>(),
        vec![keep.clone()]
    );
    let report = runtime
        .block_on(rebuild_node_pool_with(
            &vault,
            &store,
            "sub",
            fake_probe(&HashMap::new()),
        ))
        .unwrap();
    assert!(report.kept_previous && report.pool_changed);
    assert_eq!(
        report
            .members
            .iter()
            .map(|node| node.key.clone())
            .collect::<Vec<_>>(),
        vec![keep.clone()]
    );
    assert_eq!(
        load_meta(&store)
            .pool_keys
            .iter()
            .map(|node| node.key.clone())
            .collect::<Vec<_>>(),
        vec![keep]
    );
}

#[test]
fn pool_extends_failover_after_manual_backups_and_survives_reorder_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, store) = fixture(
        dir.path(),
        &[
            ("primary.test", 443, "Primary"),
            ("manual.test", 443, "Manual"),
            ("pool1.test", 443, "Canada A"),
            ("pool2.test", 443, "Canada B"),
        ],
    );
    let endpoints = vault.read_subscription_endpoints("sub").unwrap();
    let manual = endpoint_key(&endpoints[1].url);
    let pool_a = endpoint_key(&endpoints[2].url);
    let pool_b = endpoint_key(&endpoints[3].url);
    subscription::set_backup_endpoints(&vault, &store, "sub", std::slice::from_ref(&manual))
        .unwrap();
    set_node_pool(&store, "sub", Some(canada_pool())).unwrap();
    let exits: HashMap<&'static str, &'static str> =
        HashMap::from([("Canada A", "CA"), ("Canada B", "CA")]);
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(rebuild_node_pool_with(
            &vault,
            &store,
            "sub",
            fake_probe(&exits),
        ))
        .unwrap();

    // Ordered failover: primary, manual backups, then pool order.
    let profile = store.load().unwrap().profiles.remove(0);
    let (nodes, _) = subscription::failover_plan(&vault, &profile).unwrap();
    let order: Vec<String> = nodes.iter().map(|n| endpoint_key(&n.url)).collect();
    assert_eq!(
        order,
        vec![
            order[0].clone(),
            manual.clone(),
            pool_a.clone(),
            pool_b.clone()
        ]
    );

    // Subscription reorder + credential rotation preserve pool identity.
    let reordered: Vec<SubscriptionEndpoint> = endpoints
        .iter()
        .rev()
        .map(|endpoint| SubscriptionEndpoint {
            url: endpoint.url.replacen("uuid", "rotated", 1),
            name: endpoint.name.clone(),
        })
        .collect();
    vault
        .store_subscription_endpoints("sub", &reordered)
        .unwrap();
    let (nodes, _) = subscription::failover_plan(&vault, &profile).unwrap();
    let order: Vec<String> = nodes.iter().map(|n| endpoint_key(&n.url)).collect();
    assert_eq!(order[1..], [manual.clone(), pool_a.clone(), pool_b.clone()]);
    // list_endpoints flags: pool members are not manual backups.
    let rows = subscription::list_endpoints(&vault, &store, "sub").unwrap();
    let row = |key: &str| rows.iter().find(|r| r.key == key).unwrap();
    assert!(row(&pool_a).in_pool && !row(&pool_a).is_backup);
    assert!(row(&manual).is_backup && !row(&manual).in_pool);
}

#[test]
fn parse_exit_country_rejects_garbage() {
    assert_eq!(
        parse_exit_country(r#"{"country":"ca","ip":"1.2.3.4"}"#, "country", "ip")
            .unwrap()
            .country,
        "CA"
    );
    for bad in [
        r#"{"country":"USA","ip":"1.2.3.4"}"#,
        r#"{"country":"ca"}"#,
        r#"{"country":"ca","ip":"not-an-ip"}"#,
        "not json",
        r#"{"country":"<script>","ip":"1.2.3.4"}"#,
    ] {
        assert!(parse_exit_country(bad, "country", "ip").is_none(), "{bad}");
    }
}

#[test]
fn pool_cannot_overflow_failover_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let names = [
        ("p.test", 443, "Primary"),
        ("a.test", 443, "Canada A"),
        ("b.test", 443, "Canada B"),
        ("c.test", 443, "Canada C"),
        ("d.test", 443, "Canada D"),
        ("e.test", 443, "Canada E"),
        ("f.test", 443, "Canada F"),
        ("g.test", 443, "Canada G"),
        ("h.test", 443, "Canada H"),
        ("i.test", 443, "Canada I"),
    ];
    let (vault, store) = fixture(dir.path(), &names);
    set_node_pool(&store, "sub", Some(canada_pool())).unwrap();
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(rebuild_node_pool_with(&vault, &store, "sub", |_| async {
            Ok(ExitCountry {
                country: "CA".into(),
                ip: "203.0.113.9".into(),
            })
        }))
        .unwrap();
    let profile = store.load().unwrap().profiles.remove(0);
    assert_eq!(
        profile.subscription.as_ref().unwrap().pool_keys.len(),
        subscription::MAX_FAILOVER_NODES - 1
    );
    assert_eq!(
        subscription::failover_plan(&vault, &profile)
            .unwrap()
            .0
            .len(),
        subscription::MAX_FAILOVER_NODES
    );
}
