//! A panel's whole-Xray config, reduced by `tun_compatible_config`, must pass
//! the daemon's own validator: the two lists of allowed fields cannot drift
//! apart unnoticed.
#![cfg(target_os = "linux")]
use net_manager_core::daemon_protocol::XrayConnectParams;
use net_manager_core::xray;
use network_orchestrator_daemon::xray::prepare_xray;
use serde_json::{json, Value};

fn params(config: &Value) -> XrayConnectParams {
    XrayConnectParams {
        profile_id: "sub1".into(),
        config: serde_json::to_string(config).unwrap(),
        routes: vec![],
        dns_servers: vec![],
        dns_domains: vec![],
        dns_bypass: vec![],
        interface_name: None,
        geo_assets: None,
        macos_data_root: None,
        role: Default::default(),
        failover: None,
        reject_quic: false,
        probe_url: None,
        mtu: None,
    }
}

fn panel(proxy: Value) -> Value {
    json!({
        "burstObservatory": {"subjectSelector": ["proxy"]},
        "policy": {"levels": {"0": {"handshake": 4}}},
        "dns": {"servers": ["1.1.1.1"]},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"udp": true}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http"}
        ],
        "outbounds": [proxy,
            {"tag": "at4pda", "protocol": "freedom"},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": []},
    })
}

#[test]
fn a_reduced_panel_vless_reality_config_passes_the_daemon_validator() {
    let config = panel(json!({
        "tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "node.test", "port": 443,
            "users": [{"id": "u", "encryption": "none", "flow": "xtls-rprx-vision", "level": 0}]}]},
        "streamSettings": {"network": "tcp", "security": "reality",
            "realitySettings": {"serverName": "s", "fingerprint": "chrome", "publicKey": "k",
                "shortId": "a", "spiderX": "/", "show": false},
            "sockopt": {"mark": 1}},
        "mux": {"enabled": false, "concurrency": -1}
    }));
    assert!(
        prepare_xray(1000, params(&config), 1).is_err(),
        "raw panel config"
    );
    let reduced = xray::tun_compatible_config(&config).unwrap();
    prepare_xray(1000, params(&reduced), 1).expect("reduced config");
}

#[test]
fn a_reduced_panel_hysteria_config_passes_the_daemon_validator() {
    let config = panel(json!({
        "tag": "proxy", "protocol": "hysteria",
        "settings": {"version": 2, "address": "h.test", "port": 443},
        "streamSettings": {"network": "hysteria", "security": "tls",
            "tlsSettings": {"serverName": "h.test", "alpn": ["h3"]},
            "hysteriaSettings": {"version": 2, "auth": "secret", "congestion": {"type": "bbr"}},
            "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "p"}}]}}
    }));
    let reduced = xray::tun_compatible_config(&config).unwrap();
    prepare_xray(1000, params(&reduced), 1).expect("reduced config");
}

#[test]
fn multinode_preserves_proxy_policies_and_accepts_missing_pinned_nodes() {
    use net_manager_core::daemon_protocol::{XrayFailoverNode, XrayFailoverParams};
    use net_manager_core::models::{DomainPolicy, DomainRouteTarget};
    let uri =
        "vless://00000000-0000-0000-0000-000000000001@primary.test:443?security=none&type=tcp";
    let key = net_manager_core::subscription::endpoint_key(uri);
    let base = xray::generate_share_link_config_with_http(uri, 10808, 10809).unwrap();
    let routed = xray::apply_profile_routing(
        &base,
        &[DomainPolicy {
            domains: vec!["domain:default.test".into()],
            target: DomainRouteTarget::Proxy,
        }],
        &Default::default(),
    )
    .unwrap();
    let config = xray::apply_multinode_config(
        &routed,
        &key,
        &[],
        &[xray::PinnedOutbound {
            key: "ffffffffffffffff".into(),
            selectors: vec!["domain:pinned.test".into()],
            outbound: None,
        }],
    )
    .unwrap();
    let mut request = params(&config);
    request.failover = Some(XrayFailoverParams {
        nodes: vec![XrayFailoverNode { key: key.clone() }],
        primary_key: key,
        auto_return_primary: true,
        probe_url: "https://example.test/check".into(),
        interval_secs: 10,
    });
    let plan = prepare_xray(1000, request, 51820).expect("valid generated multinode policy");
    let running: Value = serde_json::from_str(&plan.config).unwrap();
    assert!(running["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|outbound| outbound["tag"] == "pin-ffffffffffffffff"
            && outbound["protocol"] == "blackhole"));
}
