//! Named `netorch proxy NAME -- COMMAND` exits of an Xray TUN profile.
//!
//! Each named exit is a loopback SOCKS/HTTP listener pair the daemon binds;
//! traffic reaching it leaves through the exit's declared target: the normal
//! profile rules, one fixed subscription node, an independent ordered node
//! pool, or the marked direct outbound. The configuration is data only —
//! it never stores a command, shell string or plugin, and serde rejects
//! unknown fields so an executable spec cannot smuggle one in.
//!
//! Exits are fail-closed like pinned routes: an endpoint key that is no
//! longer in the subscription stays a valid saved choice but its pin
//! outbound is a blackhole — traffic drops, it is never retargeted to
//! another endpoint. Keys explicitly used by node/pool exits are excluded
//! from the automatic failover pool (see [`Profile::named_exit_keys`]).
use crate::config_vault::ConfigVault;
use crate::models::{NamedProxyExit, Profile, ProxyTarget, TunnelBackend};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io;

/// At most this many named exits per profile (the daemon's per-profile
/// listener slot budget).
pub const MAX_PROXY_EXITS: usize = 16;
/// Ordered, unique endpoint keys one pool exit may list.
pub const MAX_POOL_KEYS: usize = 8;
/// Most `no_proxy` entries per exit.
pub const MAX_NO_PROXY: usize = 32;
/// Longest single `no_proxy` entry (a full DNS name fits).
const MAX_NO_PROXY_LEN: usize = 253;
/// Domain pins + fixed DNS egress + named node/pool keys together stay
/// inside the daemon's pin-listener budget.
const MAX_DISTINCT_PIN_KEYS: usize = 33;
/// Reserved exit names — they collide with `netorch proxy` verbs.
const RESERVED_NAMES: [&str; 4] = ["list", "set", "remove", "help"];

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// `1-32` lowercase ASCII alnum/`-`/`_`, first character alnum; `list`,
/// `set`, `remove` and `help` are reserved command verbs. `default`,
/// `nl`, `ru`, `direct` and the like are ordinary permitted names.
pub fn valid_proxy_exit_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
        && !RESERVED_NAMES.contains(&name)
}

/// One `no_proxy` entry: a host, domain suffix, IP, CIDR or `host:port`,
/// or an explicit `*`. No whitespace, controls or URL/userinfo/query and
/// shell metacharacters — entries travel to child processes' `NO_PROXY`
/// environments verbatim.
fn valid_no_proxy_entry(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= MAX_NO_PROXY_LEN
        && entry.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']' | b'/' | b'*')
        })
}

/// Structural checks on one named-exit list — no profile context: names,
/// duplicates, per-target key shape and `no_proxy` entries. The daemon
/// calls this on connect specs before it validates the built config.
pub fn validate_proxy_exits(exits: &[NamedProxyExit]) -> io::Result<()> {
    if exits.len() > MAX_PROXY_EXITS {
        return Err(invalid("At most 16 named proxy exits are supported"));
    }
    let mut names = HashSet::with_capacity(exits.len());
    for exit in exits {
        if !valid_proxy_exit_name(&exit.name) {
            return Err(invalid("A proxy exit name is invalid or reserved"));
        }
        if !names.insert(exit.name.as_str()) {
            return Err(invalid("Duplicate proxy exit name"));
        }
        match &exit.target {
            ProxyTarget::Rules | ProxyTarget::Direct => {}
            ProxyTarget::Node { endpoint_key } => {
                if !crate::subscription::valid_endpoint_key(endpoint_key) {
                    return Err(invalid("Invalid proxy exit endpoint key"));
                }
            }
            ProxyTarget::Pool { endpoint_keys } => {
                if endpoint_keys.is_empty() || endpoint_keys.len() > MAX_POOL_KEYS {
                    return Err(invalid("A proxy exit pool needs 1-8 endpoint keys"));
                }
                let mut keys = HashSet::with_capacity(endpoint_keys.len());
                for key in endpoint_keys {
                    if !crate::subscription::valid_endpoint_key(key) {
                        return Err(invalid("Invalid proxy exit endpoint key"));
                    }
                    if !keys.insert(key.as_str()) {
                        return Err(invalid("Duplicate proxy exit pool key"));
                    }
                }
            }
        }
        if exit.no_proxy.len() > MAX_NO_PROXY {
            return Err(invalid("At most 32 no-proxy entries per exit"));
        }
        if exit
            .no_proxy
            .iter()
            .any(|entry| !valid_no_proxy_entry(entry))
        {
            return Err(invalid("A no-proxy entry is invalid"));
        }
    }
    Ok(())
}

/// Full profile checks: structural rules plus backend/subscription context
/// and the aggregate pin-listener budget. Runs on load/save/upsert.
pub fn validate_profile_proxy_exits(profile: &Profile) -> io::Result<()> {
    if profile.xray_proxy_exits.is_empty() {
        return Ok(());
    }
    if profile.backend != TunnelBackend::Xray {
        return Err(invalid("Named proxy exits require an Xray profile"));
    }
    validate_proxy_exits(&profile.xray_proxy_exits)?;
    if profile
        .xray_proxy_exits
        .iter()
        .any(|exit| !exit.target.endpoint_keys().is_empty())
        && profile.subscription.is_none()
    {
        return Err(invalid(
            "Node and pool proxy exits require subscription endpoints",
        ));
    }
    let mut distinct: HashSet<&str> = profile
        .pinned_policies
        .iter()
        .map(|route| route.endpoint_key.as_str())
        .collect();
    if let Some(key) = &profile.xray_dns.outbound_key {
        distinct.insert(key.as_str());
    }
    for exit in &profile.xray_proxy_exits {
        distinct.extend(exit.target.endpoint_keys().iter().map(String::as_str));
    }
    if distinct.len() > MAX_DISTINCT_PIN_KEYS {
        return Err(invalid(
            "Too many pinned endpoints across routes, DNS and proxy exits",
        ));
    }
    Ok(())
}

/// Append the `pin-<key>` outbounds the named exits need to an already
/// built TUN config — after normal/multinode generation, so default-route
/// behaviour, balancers and failover settings stay untouched.
///
/// For every distinct node/pool key the current subscription link (from
/// the vault sidecar, never the stale `config_path`) becomes a dedicated
/// pin outbound; a key that no longer resolves produces a blackhole
/// `pin-<key>` — fail-closed, never retargeted. A `pin-<key>` outbound the
/// profile routing already created (domain pin or DNS egress) is reused as
/// is. Outbound chaining (`proxySettings`, `dialerProxy`) is stripped so a
/// fixed alias cannot silently detour through another node, the profile
/// sockopts apply, and no profile routing touches these dedicated
/// outbounds. Rules/direct exits need no sidecar and read nothing.
pub fn append_named_proxy_outbounds(
    vault: &ConfigVault,
    profile: &Profile,
    config: &mut Value,
) -> Result<(), String> {
    let mut needed: Vec<&str> = Vec::new();
    for exit in &profile.xray_proxy_exits {
        for key in exit.target.endpoint_keys() {
            if !needed.contains(&key.as_str()) {
                needed.push(key.as_str());
            }
        }
    }
    if needed.is_empty() {
        return Ok(());
    }
    let outbounds = config
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "invalid Xray config".to_string())?;
    let mut present: HashSet<String> = outbounds
        .iter()
        .filter_map(|outbound| outbound["tag"].as_str().map(str::to_string))
        .collect();
    // One sidecar read for every missing key; an unreadable sidecar
    // resolves nothing (same fail-closed posture as a missing node).
    let endpoints = vault.read_subscription_endpoints(&profile.id).ok();
    for key in needed {
        let tag = crate::xray::pin_tag(key);
        if !present.insert(tag.clone()) {
            continue;
        }
        let url = endpoints.as_ref().and_then(|endpoints| {
            crate::subscription::key_index(endpoints, key).map(|index| endpoints[index].url.clone())
        });
        let outbound = match url {
            Some(url) => {
                let mut outbound = crate::xray::multinode_outbound(&url, &tag)
                    .map_err(|_| "A named proxy exit endpoint is invalid".to_string())?;
                // A fixed alias never chains into another outbound.
                let object = outbound
                    .as_object_mut()
                    .ok_or_else(|| "A named proxy exit endpoint is invalid".to_string())?;
                object.remove("proxySettings");
                if let Some(sockopt) = object
                    .get_mut("streamSettings")
                    .and_then(Value::as_object_mut)
                    .and_then(|stream| stream.get_mut("sockopt"))
                    .and_then(Value::as_object_mut)
                {
                    sockopt.remove("dialerProxy");
                }
                if let Some(sockopts) = &profile.xray_sockopts {
                    crate::xray::apply_stream_sockopts(&mut outbound, sockopts)
                        .map_err(|_| "Invalid Xray socket settings".to_string())?;
                }
                outbound
            }
            // Missing key: blackhole, never another endpoint.
            None => json!({"tag": tag, "protocol": "blackhole"}),
        };
        outbounds.push(outbound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_vault::SubscriptionEndpoint;

    fn endpoint(host: &str) -> SubscriptionEndpoint {
        SubscriptionEndpoint {
            url: format!("vless://uuid@{host}:443?security=tls&sni=a.test&type=tcp#{host}"),
            name: host.into(),
        }
    }

    fn node_exit(key: &str) -> NamedProxyExit {
        NamedProxyExit {
            name: "work".into(),
            target: ProxyTarget::Node {
                endpoint_key: key.into(),
            },
            no_proxy: Vec::new(),
        }
    }

    #[test]
    fn named_pins_blackhole_missing_and_never_retarget_or_touch_routing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let node = endpoint("one.test");
        vault
            .store_subscription_endpoints("p", std::slice::from_ref(&node))
            .unwrap();
        let node_key = crate::subscription::endpoint_key(&node.url);
        let gone_key = "deadbeefdeadbeef".to_string();

        let mut profile = Profile {
            id: "p".into(),
            backend: TunnelBackend::Xray,
            xray_proxy_exits: vec![
                NamedProxyExit {
                    name: "lax".into(),
                    target: ProxyTarget::Rules,
                    no_proxy: Vec::new(),
                },
                node_exit(&node_key),
                NamedProxyExit {
                    name: "pool".into(),
                    target: ProxyTarget::Pool {
                        // Same key as the node exit (deduped) plus a key
                        // that left the subscription.
                        endpoint_keys: vec![node_key.clone(), gone_key.clone()],
                    },
                    no_proxy: Vec::new(),
                },
                NamedProxyExit {
                    name: "out".into(),
                    target: ProxyTarget::Direct,
                    no_proxy: Vec::new(),
                },
            ],
            ..Profile::default()
        };

        // A pre-existing pin outbound is reused as is (domain pin / DNS
        // egress may have built it earlier).
        let mut config = json!({
            "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {}},
                {"tag": "freedom", "protocol": "freedom"},
                {"tag": format!("pin-{gone_key}"), "protocol": "vless",
                 "settings": {"existing": true}},
            ],
            "routing": {"domainStrategy": "AsIs", "rules": [
                {"type": "field", "domain": ["x.test"], "outboundTag": "proxy"}
            ]}
        });
        let routing_before = config["routing"].clone();

        append_named_proxy_outbounds(&vault, &profile, &mut config).unwrap();

        let outbounds = config["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 4, "one deduped pin appended");
        assert_eq!(config["routing"], routing_before, "routing untouched");
        let generated = &outbounds[3];
        assert_eq!(generated["tag"], crate::xray::pin_tag(&node_key));
        assert_eq!(generated["protocol"], "vless");
        // No chaining into another outbound through a fixed alias.
        assert!(generated.get("proxySettings").is_none());
        // The missing key kept its existing pin outbound untouched.
        assert_eq!(outbounds[2]["settings"]["existing"], true);

        // Without the sidecar the same key blackholes — fail closed,
        // never another endpoint.
        profile.id = "no-sidecar".into();
        let mut empty = json!({
            "outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {}}],
            "routing": {"rules": []}
        });
        append_named_proxy_outbounds(&vault, &profile, &mut empty).unwrap();
        let missing = empty["outbounds"].as_array().unwrap();
        assert_eq!(missing[1]["protocol"], "blackhole");
        assert_eq!(missing[1]["tag"], crate::xray::pin_tag(&node_key));
    }

    #[test]
    fn exits_without_keys_leave_the_config_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let profile = Profile {
            id: "p".into(),
            xray_proxy_exits: vec![
                NamedProxyExit {
                    name: "lax".into(),
                    target: ProxyTarget::Rules,
                    no_proxy: Vec::new(),
                },
                NamedProxyExit {
                    name: "out".into(),
                    target: ProxyTarget::Direct,
                    no_proxy: Vec::new(),
                },
            ],
            ..Profile::default()
        };
        let mut config = json!({"outbounds": [{"tag": "proxy"}], "routing": {}});
        let before = config.clone();
        append_named_proxy_outbounds(&vault, &profile, &mut config).unwrap();
        assert_eq!(config, before);
    }
}
