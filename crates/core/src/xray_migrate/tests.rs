use super::*;
use crate::models::Profile;
use crate::subscription::endpoint_key;

const PRIMARY_LINK: &str = "vless://u@ca1.test:443?security=tls&sni=a.test&type=tcp#Canada";
const NL_LINK: &str = "vless://u@nl1.test:443?security=tls&sni=a.test&type=tcp#Netherlands";

fn endpoints() -> Vec<SubscriptionEndpoint> {
    vec![
        SubscriptionEndpoint {
            url: PRIMARY_LINK.into(),
            name: "Canada".into(),
        },
        SubscriptionEndpoint {
            url: NL_LINK.into(),
            name: "Netherlands".into(),
        },
    ]
}

/// The outbound a link generates — identical to what a real ~/vpn-style
/// config.json carries, so the signature match is exercised end to end.
fn outbound_for(link: &str, tag: &str) -> Value {
    let config = crate::xray::generate_share_link_config(link, 1).unwrap();
    let mut outbound = config["outbounds"][0].clone();
    outbound["tag"] = json!(tag);
    outbound
}

fn resolver<'a>(
    endpoints: &'a [SubscriptionEndpoint],
    primary: &'a str,
) -> impl Fn(&Value) -> ResolvedOutbound + 'a {
    subscription_outbound_resolver(endpoints, Some(primary))
}

#[test]
fn unrepresented_selector_and_dns_scopes_are_refused() {
    for rule in [
        json!({"domain": ["1.2.3.4"], "outboundTag": "direct"}),
        json!({"ip": ["domain:example.test"], "outboundTag": "direct"}),
        json!({"domain": false, "outboundTag": "direct"}),
        json!({"domain": [], "outboundTag": "direct"}),
        json!({"port": 53, "network": "udp", "outboundTag": "dns"}),
        json!({"port": 53, "domain": ["full:example.test"], "outboundTag": "dns"}),
        json!({"domain": ["full:example.test"], "attrs": "unsupported", "outboundTag": "direct"}),
        json!({"domain": ["full:example.test"], "outboundTag": "direct", "balancerTag": "pool"}),
    ] {
        let source = json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "dns", "protocol": "dns"}],
            "dns": {"servers": ["1.1.1.1"]},
            "routing": {"rules": [rule]},
        });
        let plan = plan_xray_policy_migration(&source, None, |outbound| {
            auxiliary_outbound(outbound).unwrap_or(ResolvedOutbound::Foreign)
        })
        .unwrap();
        assert!(
            !plan.refused.is_empty(),
            "unrepresented source rule was accepted"
        );
    }
}

#[test]
fn invalid_direct_migration_does_not_mutate_profile() {
    for migration in [
        XrayPolicyMigration {
            tun_mtu: Some(1279),
            ..Default::default()
        },
        XrayPolicyMigration {
            connection_idle_secs: Some(86_401),
            ..Default::default()
        },
        XrayPolicyMigration {
            sockopts: Some(XraySockopts {
                tcp_user_timeout: Some(3_600_001),
                ..Default::default()
            }),
            ..Default::default()
        },
        XrayPolicyMigration {
            traffic_rules: vec![XrayTrafficRule {
                ips: vec!["domain:example.test".into()],
                port: 53,
                network: "udp".into(),
                target: DomainRouteTarget::Direct,
            }],
            ..Default::default()
        },
    ] {
        let mut profile = Profile::default();
        let before = serde_json::to_value(&profile).unwrap();
        assert!(apply_xray_policy_migration(&mut profile, migration).is_err());
        assert_eq!(serde_json::to_value(&profile).unwrap(), before);
    }
}

#[test]
fn outbound_signature_maps_rotated_credentials_and_rejects_transport_drift() {
    let same_key = SubscriptionEndpoint {
        url: PRIMARY_LINK.into(),
        name: "Canada".into(),
    };
    let rotated = SubscriptionEndpoint {
        url: PRIMARY_LINK.replace("u@", "rotated@"),
        name: "Canada".into(),
    };
    let rotated_out = outbound_for(&rotated.url, "proxy");
    assert_eq!(
        endpoint_key_for_outbound(&rotated_out, std::slice::from_ref(&same_key)),
        Some(endpoint_key(&same_key.url))
    );
    let mut drifted = rotated_out;
    drifted["streamSettings"]["network"] = json!("grpc");
    assert_eq!(endpoint_key_for_outbound(&drifted, &[same_key]), None);
}

#[test]
fn personal_policy_shape_preserves_dns_guards_pins_and_runtime_settings() {
    let endpoints = endpoints();
    let primary = endpoint_key(PRIMARY_LINK);
    let pinned = endpoint_key(NL_LINK);
    let mut node = outbound_for(PRIMARY_LINK, "proxy");
    node["streamSettings"]["sockopt"] = json!({
        "tcpNoDelay": true, "tcpKeepAliveIdle": 30,
        "tcpKeepAliveInterval": 10, "tcpUserTimeout": 20000,
    });
    let source = json!({
        "inbounds": [
            {"tag": "tun-in", "protocol": "tun", "settings": {"mtu": 8500, "dns": ["1.1.1.1", "8.8.8.8"]}},
            {"tag": "wrapper", "protocol": "socks", "port": 10814},
        ],
        "outbounds": [
            node, outbound_for(NL_LINK, "pinned"),
            {"tag": "direct", "protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "ForceIPv4"}}},
            {"tag": "dns", "protocol": "dns", "settings": {
                "rewriteAddress": "9.9.9.9", "rewriteNetwork": "udp", "rewritePort": 53,
                "rules": [
                    {"action": "return", "qType": "65,28", "rCode": 5},
                    {"action": "hijack", "qType": "1", "domain": ["domain:blocked.example"]},
                    {"action": "direct"},
                ]
            }, "streamSettings": {"sockopt": {"dialerProxy": "pinned"}}},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [{"tag": "pool", "selector": ["proxy"], "strategy": {"type": "leastPing"}}],
            "rules": [
                {"type": "field", "inboundTag": ["wrapper"], "balancerTag": "pool"},
                {"type": "field", "port": "53", "ip": ["1.1.1.1", "8.8.8.8"], "outboundTag": "direct"},
                {"port": "53", "network": "tcp,udp", "outboundTag": "dns"},
                {"port": "853", "network": "tcp", "ip": ["1.1.1.1", "8.8.8.8"], "outboundTag": "block"},
                {"port": "443", "network": "udp", "outboundTag": "block"},
                {"type": "field", "domain": ["domain:pinned.example"], "outboundTag": "pinned"},
                {"type": "field", "ip": ["10.7.0.0/24"], "outboundTag": "block"},
                {"ip": ["geoip:ru", "geoip:by"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "pool"},
            ],
        },
        "dns": {
            "servers": ["1.1.1.1", "8.8.8.8"],
            "hosts": {"corp.internal": ["10.1.1.1"]},
            "queryStrategy": "UseIPv4", "enableParallelQuery": false,
        },
        "policy": {"levels": {"0": {"connIdle": 120}}, "system": {"statsOutboundUplink": true}},
    });
    let migration =
        plan_xray_policy_migration(&source, Some(&primary), resolver(&endpoints, &primary))
            .unwrap();
    assert!(migration.refused.is_empty(), "{:#?}", migration.refused);
    let mut profile = Profile::default();
    apply_xray_policy_migration(&mut profile, migration).unwrap();
    assert!(profile.xray_quic_reject);
    assert_eq!(profile.pinned_policies[0].endpoint_key, pinned);
    assert_eq!(
        profile.xray_dns.outbound_key.as_deref(),
        Some(pinned.as_str())
    );
    assert_eq!(profile.xray_dns.enable_parallel_query, Some(false));
    let rewrite = profile.xray_dns.outbound.as_ref().unwrap();
    assert_eq!(rewrite.rules[0].q_type.as_deref(), Some("65,28"));
    assert_eq!(rewrite.rules[0].r_code, Some(5));
    assert_eq!(rewrite.rules[1].domain, ["domain:blocked.example"]);
    assert_eq!(rewrite.rules[2].action, "direct");
    assert_eq!(
        profile.xray_tun_dns_servers,
        [
            "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
            "8.8.8.8".parse().unwrap()
        ]
    );
    assert_eq!(profile.xray_connection_idle_secs, Some(120));
    assert_eq!(profile.xray_tun_mtu, Some(8500));
    assert_eq!(
        profile.xray_direct_domain_strategy.as_deref(),
        Some("ForceIPv4")
    );
    assert_eq!(
        profile.xray_sockopts.as_ref().unwrap().tcp_user_timeout,
        Some(20000)
    );
    assert!(profile
        .xray_traffic_rules
        .iter()
        .any(|rule| rule.port == 853
            && rule.network == "tcp"
            && rule.target == DomainRouteTarget::Block
            && rule.ips == ["1.1.1.1", "8.8.8.8"]));
    assert_eq!(profile.xray_dns.hosts["corp.internal"], ["10.1.1.1"]);
    assert!(profile
        .domain_policies
        .iter()
        .any(|rule| rule.target == DomainRouteTarget::Direct
            && rule.domains == ["geoip:ru", "geoip:by"]));
}

#[test]
fn unknown_and_nonequivalent_constructs_refuse_not_drop() {
    let source = json!({
        "outbounds": [
            {"tag": "spider", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"interface": "wg0"}}},
        ],
        "routing": {"rules": [
            // Foreign tunnel target — cannot map to direct.
            {"type": "field", "domain": ["corp.example"], "outboundTag": "spider"},
            // domain+ip AND semantics.
            {"type": "field", "domain": ["a.example"], "ip": ["1.2.3.4"], "outboundTag": "spider"},
            // Unsupported condition.
            {"type": "field", "domain": ["a.example"], "user": ["u1"], "outboundTag": "spider"},
            // Pinned outbound carrying unsupported sockopt.
            {"type": "field", "port": "853-855", "network": "tcp", "ip": ["8.8.8.8"], "outboundTag": "block"},
        ]},
    });
    let migration =
        plan_xray_policy_migration(&source, None, |_| ResolvedOutbound::Foreign).unwrap();
    let reasons: Vec<&str> = migration
        .refused
        .iter()
        .map(|r| r.reason.as_str())
        .collect();
    assert!(reasons.contains(&"unknownTarget"), "{reasons:?}");
    assert!(reasons.contains(&"compoundSelector"), "{reasons:?}");
    assert!(reasons.contains(&"unsupportedRuleCondition"), "{reasons:?}");
    assert!(reasons.contains(&"unsupportedPortRule"), "{reasons:?}");
    // Apply refuses outright — nothing silently lands.
    let mut profile = Profile::default();
    assert!(apply_xray_policy_migration(&mut profile, migration).is_err());
    assert!(profile.domain_policies.is_empty());
}

#[test]
fn explicit_primary_domain_route_stays_pinned_when_default_can_fail_over() {
    let endpoints = endpoints();
    let primary = endpoint_key(PRIMARY_LINK);
    let source = json!({
        "outbounds": [outbound_for(PRIMARY_LINK, "proxy"), {"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [
            {"type": "field", "domain": ["geosite:openai"], "outboundTag": "proxy"},
        ]},
    });
    let migration =
        plan_xray_policy_migration(&source, Some(&primary), resolver(&endpoints, &primary))
            .unwrap();
    assert!(migration.refused.is_empty(), "{:#?}", migration.refused);
    assert!(migration.domain_policies.is_empty());
    assert_eq!(migration.pinned_routes[0].endpoint_key, primary);
    assert_eq!(migration.pinned_routes[0].selectors, ["geosite:openai"]);
}

#[test]
fn dns_resolver_bypass_does_not_widen_to_other_ports() {
    let source = json!({
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "dns", "protocol": "dns"},
        ],
        "routing": {"rules": [
            {"type": "field", "port": "53", "ip": ["1.1.1.1"], "outboundTag": "direct"},
        ]},
        "dns": {"servers": ["1.1.1.1"]},
    });
    let migration =
        plan_xray_policy_migration(&source, None, subscription_outbound_resolver(&[], None))
            .unwrap();
    assert!(migration.refused.is_empty(), "{:#?}", migration.refused);
    let mut profile = Profile::default();
    apply_xray_policy_migration(&mut profile, migration).unwrap();
    let base = xray::generate_share_link_config(PRIMARY_LINK, 1080).unwrap();
    let generated = xray::apply_profile_routing(
        &base,
        &profile.domain_policies,
        &xray::ProfileRoutingOptions::from(&profile),
    )
    .unwrap();
    let rules = generated["routing"]["rules"].as_array().unwrap();
    assert!(rules
        .iter()
        .any(|rule| rule["ip"] == json!(["1.1.1.1"]) && rule["port"] == "53"));
    assert!(!rules
        .iter()
        .any(|rule| rule["ip"] == json!(["1.1.1.1"]) && rule.get("port").is_none()));
}
