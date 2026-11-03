//! Daemon-owned loopback exits. Configuration never contains executable hooks.
use net_manager_core::daemon_protocol::{ProxyExitBinding, XrayFailoverNode, XrayFailoverParams};
use net_manager_core::models::{NamedProxyExit, ProxyTarget};
use serde_json::{json, Value};
use std::io;

fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid named Xray proxy exits",
    )
}

pub fn bindings(exits: &[NamedProxyExit], config: &Value) -> io::Result<Vec<ProxyExitBinding>> {
    net_manager_core::proxy_exits::validate_proxy_exits(exits)?;
    let outbounds = config["outbounds"].as_array().ok_or_else(rejected)?;
    if outbounds
        .iter()
        .filter(|outbound| {
            outbound["tag"]
                .as_str()
                .is_some_and(|tag| tag.starts_with("pin-"))
        })
        .count()
        > 33
    {
        return Err(rejected());
    }
    for exit in exits {
        for key in exit.target.endpoint_keys() {
            let tag = net_manager_core::xray::pin_tag(key);
            let outbound = outbounds
                .iter()
                .find(|outbound| outbound["tag"] == tag)
                .ok_or_else(rejected)?;
            if !matches!(
                outbound["protocol"].as_str(),
                Some("vless" | "hysteria" | "blackhole")
            ) || !outbound["proxySettings"].is_null()
                || !outbound["streamSettings"]["sockopt"]["dialerProxy"].is_null()
            {
                return Err(rejected());
            }
        }
        if exit.target == ProxyTarget::Direct {
            let direct = outbounds
                .iter()
                .find(|outbound| outbound["tag"] == "direct")
                .ok_or_else(rejected)?;
            if direct["protocol"] != "freedom"
                || !direct["proxySettings"].is_null()
                || !direct["streamSettings"]["sockopt"]["dialerProxy"].is_null()
            {
                return Err(rejected());
            }
        }
    }
    Ok(exits
        .iter()
        .map(|exit| ProxyExitBinding {
            name: exit.name.clone(),
            target: exit.target.clone(),
        })
        .collect())
}

pub fn ports(mark: u32, index: usize) -> (u16, u16) {
    // The caller validates <=16 exits; marks share the existing 128-slot allocator.
    let socks = (24_000
        + mark.saturating_sub(crate::xray::POLICY_MARK_BASE).min(127) * 32
        + index as u32 * 2) as u16;
    (socks, socks + 1)
}

pub fn balancer_tag(name: &str) -> String {
    format!("proxy-pool-{name}")
}

pub fn inject(config: &mut Value, exits: &[ProxyExitBinding], mark: u32) -> io::Result<()> {
    if exits.is_empty() {
        return Ok(());
    }
    let mut forced_rules = Vec::with_capacity(exits.len());
    let mut balancers = Vec::new();
    for (index, exit) in exits.iter().enumerate() {
        let (socks_port, http_port) = ports(mark, index);
        let socks_tag = format!("proxy-socks-{}", exit.name);
        let http_tag = format!("proxy-http-{}", exit.name);
        for (tag, protocol, port) in [
            (&socks_tag, "socks", socks_port),
            (&http_tag, "http", http_port),
        ] {
            config["inbounds"].as_array_mut().ok_or_else(rejected)?.push(json!({
                "tag": tag, "listen": "127.0.0.1", "protocol": protocol, "port": port,
                "settings": if protocol == "socks" { json!({"udp":false}) } else { json!({}) },
                "sniffing": {"enabled": true, "destOverride": ["http", "tls"], "routeOnly": true},
            }));
        }
        let mut rule = json!({"type":"field", "inboundTag":[socks_tag, http_tag]});
        match &exit.target {
            ProxyTarget::Rules => continue,
            ProxyTarget::Node { endpoint_key } => {
                rule["outboundTag"] = json!(net_manager_core::xray::pin_tag(endpoint_key))
            }
            ProxyTarget::Direct => rule["outboundTag"] = json!("direct"),
            ProxyTarget::Pool { .. } => {
                let tag = balancer_tag(&exit.name);
                rule["balancerTag"] = json!(tag);
                // No candidate is safe until its own controller successfully probes it.
                balancers
                    .push(json!({"tag":tag,"selector":[net_manager_core::xray::UNAVAILABLE_TAG]}));
            }
        }
        forced_rules.push(rule);
    }
    config["routing"]["rules"]
        .as_array_mut()
        .ok_or_else(rejected)?
        .splice(0..0, forced_rules);
    if !balancers.is_empty() {
        let routing = config["routing"].as_object_mut().ok_or_else(rejected)?;
        routing
            .entry("balancers")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(rejected)?
            .extend(balancers);
        let outbounds = config["outbounds"].as_array_mut().ok_or_else(rejected)?;
        if !outbounds
            .iter()
            .any(|outbound| outbound["tag"] == net_manager_core::xray::UNAVAILABLE_TAG)
        {
            outbounds.push(
                json!({"tag":net_manager_core::xray::UNAVAILABLE_TAG,"protocol":"blackhole"}),
            );
        }
    }
    Ok(())
}

pub fn pool_params(
    exit: &ProxyExitBinding,
    probe_url: &str,
    interval_secs: u16,
) -> Option<XrayFailoverParams> {
    let ProxyTarget::Pool { endpoint_keys } = &exit.target else {
        return None;
    };
    Some(XrayFailoverParams {
        nodes: endpoint_keys
            .iter()
            .map(|key| XrayFailoverNode { key: key.clone() })
            .collect(),
        primary_key: endpoint_keys.first()?.clone(),
        auto_return_primary: true,
        probe_url: probe_url.to_owned(),
        interval_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_alias_cannot_be_replaced_by_freedom_or_a_chained_outbound() {
        let exits: Vec<NamedProxyExit> = serde_json::from_value(json!([
            {"name":"fixed","target":{"kind":"node","endpointKey":"1111111111111111"}}
        ]))
        .unwrap();
        let mut config = json!({"outbounds":[{
            "tag":"pin-1111111111111111","protocol":"vless"
        }]});
        assert!(bindings(&exits, &config).is_ok());
        config["outbounds"][0]["protocol"] = json!("freedom");
        assert!(bindings(&exits, &config).is_err());
        config["outbounds"][0]["protocol"] = json!("blackhole");
        assert!(
            bindings(&exits, &config).is_ok(),
            "missing saved node remains a blackhole"
        );
        config["outbounds"][0]["protocol"] = json!("vless");
        config["outbounds"][0]["streamSettings"] = json!({"sockopt":{"dialerProxy":"proxy"}});
        assert!(bindings(&exits, &config).is_err());
        config["outbounds"][0]["streamSettings"] = json!({});
        config["outbounds"][0]["proxySettings"] = json!({"tag":"proxy"});
        assert!(bindings(&exits, &config).is_err());
    }

    #[test]
    fn direct_alias_rejects_a_proxy_disguised_as_the_direct_outbound() {
        let exits: Vec<NamedProxyExit> = serde_json::from_value(json!([
            {"name":"underlay","target":{"kind":"direct"}}
        ]))
        .unwrap();
        let mut config = json!({"outbounds":[{"tag":"direct","protocol":"freedom"}]});
        assert!(bindings(&exits, &config).is_ok());
        config["outbounds"][0]["streamSettings"] = json!({"sockopt":{"dialerProxy":"proxy"}});
        assert!(bindings(&exits, &config).is_err());
        config["outbounds"][0] = json!({"tag":"direct","protocol":"vless"});
        assert!(bindings(&exits, &config).is_err());
    }
}
