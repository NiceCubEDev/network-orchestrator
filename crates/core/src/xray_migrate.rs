//! Safe policy migration from a local Xray `config.json` into the managed
//! profile model.
//!
//! Only *policy* is imported: routing rules, `dns`, stream `sockopt`
//! keepalive/timeouts, geo-asset URLs and endpoint bypasses. Inbounds
//! (including TUN — root config), `api`, `observatory`, `log` and every
//! daemon-owned section are never imported. Nothing a rule or outbound
//! carries that has no equivalent construct here is silently dropped: it
//! lands in [`XrayPolicyMigration::refused`] and blocks
//! [`apply_xray_policy_migration`]. `skipped` entries report constructs
//! that are equivalent to an existing managed feature or explicitly out of
//! scope (e.g. wrapper `inboundTag` rules — they belong to local helper
//! inbounds, not to general domain policy).
use crate::{
    config_vault::SubscriptionEndpoint,
    models::{
        DomainPolicy, DomainRouteTarget, PinnedRoute, Profile, XrayDnsConfig,
        XrayDnsOutboundSettings, XrayDnsQueryStrategy, XrayDnsRoute, XrayDnsServer,
        XrayDomainMatcher, XrayDomainStrategy, XraySockopts, XrayTrafficRule,
    },
    subscription, xray,
};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// How a source outbound resolves under our model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedOutbound {
    /// Plain `freedom` direct egress.
    Direct,
    /// `blackhole` block.
    Block,
    /// Built-in `dns` intercept outbound.
    Dns,
    /// The primary endpoint (selected node).
    Primary,
    /// The default failover group, distinct from a fixed primary node.
    Default,
    /// A freedom outbound explicitly bound to an existing interface.
    Interface {
        name: String,
        domain_strategy: Option<String>,
    },
    /// A specific subscription endpoint; carries its
    /// [`subscription::endpoint_key`].
    Pinned(String),
    /// Anything else: unknown protocol, foreign tunnel (interface-bound
    /// freedom, dialerProxy), unparseable — unrepresentable.
    Foreign,
}

/// A construct that was examined and deliberately not imported because an
/// equivalent managed feature already covers it, or it is out of scope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationSkip {
    /// Machine-readable short reason.
    pub reason: String,
    /// What was skipped (a rule kind/section — never credentials).
    pub detail: String,
}

/// A construct that has no equivalent in the managed model. Any entry here
/// must block the apply — importing anyway would silently change traffic.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationRefusal {
    /// Machine-readable short reason.
    pub reason: String,
    /// What could not be represented (a rule kind/section — never credentials).
    pub detail: String,
}

/// Everything extracted from a source config, ready to apply to a profile.
#[derive(Debug, Clone, Default)]
pub struct XrayPolicyMigration {
    pub domain_policies: Vec<DomainPolicy>,
    pub pinned_routes: Vec<PinnedRoute>,
    pub dns: XrayDnsConfig,
    pub domain_strategy: Option<XrayDomainStrategy>,
    pub domain_matcher: Option<XrayDomainMatcher>,
    /// Endpoint hosts that must stay reachable via the physical uplink
    /// (every imported proxy node's address).
    pub endpoint_bypasses: Vec<String>,
    pub private_lan_direct: bool,
    /// Source had an unconditional UDP/443 blackhole rule → maps to the
    /// managed QUIC-reject firewall feature.
    pub quic_reject: bool,
    pub sockopts: Option<XraySockopts>,
    pub geoip_url: Option<String>,
    pub geosite_url: Option<String>,
    pub traffic_rules: Vec<XrayTrafficRule>,
    pub connection_idle_secs: Option<u32>,
    pub tun_mtu: Option<u32>,
    pub backup_keys: Option<Vec<crate::models::EndpointRef>>,
    pub interface_routes: Vec<crate::models::XrayInterfaceRoute>,
    pub tun_dns_servers: Vec<std::net::IpAddr>,
    pub direct_domain_strategy: Option<String>,
    pub skipped: Vec<MigrationSkip>,
    pub refused: Vec<MigrationRefusal>,
}

impl XrayPolicyMigration {
    fn skip(&mut self, reason: &str, detail: impl Into<String>) {
        self.skipped.push(MigrationSkip {
            reason: reason.to_string(),
            detail: detail.into(),
        });
    }
    fn refuse(&mut self, reason: &str, detail: impl Into<String>) {
        self.refused.push(MigrationRefusal {
            reason: reason.to_string(),
            detail: detail.into(),
        });
    }
}

/// Canonical form of one proxy outbound for endpoint comparison: identity-
/// relevant fields only — tag, mux and sockopt are not node identity.
fn canonical_outbound(outbound: &Value) -> Option<Value> {
    let object = outbound.as_object()?;
    let protocol = object.get("protocol")?.as_str()?;
    let mut canonical = Map::new();
    canonical.insert("protocol".into(), Value::String(protocol.to_string()));
    for key in ["settings", "streamSettings"] {
        if let Some(value) = object.get(key) {
            let mut value = value.clone();
            if key == "streamSettings" {
                if let Some(stream) = value.as_object_mut() {
                    stream.remove("sockopt");
                    if stream.get("tcpSettings").is_some_and(|settings| {
                        settings.as_object().is_some_and(Map::is_empty)
                            || *settings == json!({"header": {"type": "none"}})
                    }) {
                        stream.remove("tcpSettings");
                    }
                }
            }
            if key == "settings" {
                for servers_key in ["vnext", "servers"] {
                    if let Some(servers) = value.get_mut(servers_key).and_then(Value::as_array_mut)
                    {
                        for server in servers {
                            if let Some(users) =
                                server.get_mut("users").and_then(Value::as_array_mut)
                            {
                                for user in users {
                                    if let Some(user) = user.as_object_mut() {
                                        for secret in ["id", "password", "email", "level"] {
                                            user.remove(secret);
                                        }
                                        if user.get("flow").and_then(Value::as_str) == Some("") {
                                            user.remove("flow");
                                        }
                                    }
                                }
                            }
                            if let Some(server) = server.as_object_mut() {
                                for secret in ["password", "username"] {
                                    server.remove(secret);
                                }
                            }
                        }
                    }
                }
                if let Some(settings) = value.as_object_mut() {
                    settings.remove("password");
                }
            }
            canonical.insert(key.into(), value);
        }
    }
    Some(Value::Object(canonical))
}

/// Canonical signature of an outbound (sorted JSON).
fn outbound_signature(outbound: &Value) -> Option<String> {
    let canonical = canonical_outbound(outbound)?;
    serde_json::to_string(&canonical).ok()
}

/// True when the outbound is an auxiliary (`freedom`/`blackhole`/`dns`/`loopback`).
fn is_auxiliary(outbound: &Value) -> bool {
    matches!(
        outbound.get("protocol").and_then(Value::as_str),
        Some("freedom" | "blackhole" | "dns" | "loopback")
    )
}

/// Resolve a source outbound to a [`subscription::endpoint_key`]:
/// generate the outbound the endpoint's share link produces and compare
/// the canonical signature — host, port, transport and every transport
/// parameter must match, so a rotated-but-identical link maps while a
/// modified one is (correctly) foreign.
pub fn endpoint_key_for_outbound(
    outbound: &Value,
    endpoints: &[SubscriptionEndpoint],
) -> Option<String> {
    let signature = outbound_signature(outbound)?;
    for endpoint in endpoints {
        let Ok(generated) = xray::generate_share_link_config(&endpoint.url, 1) else {
            continue;
        };
        let Some(produced) = generated
            .get("outbounds")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
        else {
            continue;
        };
        if outbound_signature(produced).as_deref() == Some(signature.as_str()) {
            return Some(subscription::endpoint_key(&endpoint.url));
        }
    }
    None
}

/// Resolver for [`plan_xray_policy_migration`]: classify every managed
/// auxiliary itself, map subscription-matching proxy outbounds to
/// `Pinned(key)` (or `Primary` for the primary key), leave the rest
/// `Foreign`.
pub fn subscription_outbound_resolver<'a>(
    endpoints: &'a [SubscriptionEndpoint],
    primary_key: Option<&'a str>,
) -> impl Fn(&Value) -> ResolvedOutbound + 'a {
    let primary_key = primary_key.map(str::to_string);
    move |outbound| match auxiliary_outbound(outbound) {
        Some(resolved) => resolved,
        None => match endpoint_key_for_outbound(outbound, endpoints) {
            Some(key) if Some(key.as_str()) == primary_key.as_deref() => ResolvedOutbound::Primary,
            Some(key) => ResolvedOutbound::Pinned(key),
            None => ResolvedOutbound::Foreign,
        },
    }
}

/// Classify auxiliaries by protocol; non-default settings make them
/// foreign (unrepresentable, must be refused rather than dropped).
fn auxiliary_outbound(outbound: &Value) -> Option<ResolvedOutbound> {
    let protocol = outbound.get("protocol")?.as_str()?;
    let empty_settings = outbound
        .get("settings")
        .is_none_or(|v| v.as_object().is_some_and(Map::is_empty));
    let sockopt = outbound
        .get("streamSettings")
        .and_then(|v| v.get("sockopt"));
    let known_stream = |allowed: &[&str]| {
        outbound.get("streamSettings").is_none_or(|stream| {
            stream.as_object().is_some_and(|stream| {
                stream.keys().all(|key| key == "sockopt")
                    && sockopt.is_none_or(|value| {
                        value.as_object().is_some_and(|map| {
                            map.keys().all(|key| allowed.contains(&key.as_str()))
                        })
                    })
            })
        })
    };
    Some(match protocol {
        "freedom" if empty_settings && known_stream(&["domainStrategy", "interface"]) => {
            match sockopt
                .and_then(|value| value.get("interface"))
                .and_then(Value::as_str)
            {
                Some(name) => ResolvedOutbound::Interface {
                    name: name.to_string(),
                    domain_strategy: sockopt
                        .and_then(|value| value.get("domainStrategy"))
                        .and_then(Value::as_str)
                        .map(str::to_string),
                },
                None => ResolvedOutbound::Direct,
            }
        }
        "freedom" => ResolvedOutbound::Foreign,
        "blackhole" if empty_settings => ResolvedOutbound::Block,
        "blackhole" => ResolvedOutbound::Foreign,
        "dns" if known_stream(&["dialerProxy"]) => ResolvedOutbound::Dns,
        "dns" => ResolvedOutbound::Foreign,
        _ => return None,
    })
}

/// Selector normalization: every string must be a supported routing
/// selector (domain forms, geosite, geoip, literal IP/CIDR).
fn normalize_selectors(values: &[Value], expected_kind: &'static str) -> io::Result<Vec<String>> {
    if values.is_empty() || values.len() > 128 {
        return Err(invalid("selector array needs 1-128 entries"));
    }

    let mut selectors = Vec::with_capacity(values.len());
    for value in values {
        let selector = value
            .as_str()
            .map(str::trim)
            .filter(|selector| !selector.is_empty())
            .ok_or_else(|| invalid("selector must be a nonblank string"))?;

        let Some((kind, normalized)) = xray::classify_routing_selector(selector)? else {
            return Err(invalid("source selectors cannot be comments"));
        };

        if kind != expected_kind {
            return Err(invalid("selector does not match its source field"));
        }

        // The general classifier accepts plain domain text; migration must
        // not reinterpret an unknown prefixed selector as a plain domain.
        if kind == "domain" {
            match selector.split_once(':') {
                Some(("domain" | "full" | "keyword" | "regexp" | "geosite", value))
                    if !value.is_empty() => {}
                Some(_) => return Err(invalid("unsupported domain selector")),
                None if !selector.contains(['/', '\\']) => {}
                None => return Err(invalid("unsupported domain selector")),
            }
        }

        selectors.push(normalized);
    }
    Ok(selectors)
}

fn rule_selectors(
    object: &Map<String, Value>,
    field: &'static str,
) -> io::Result<Option<Vec<String>>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid("selector field must be an array"))?;
    normalize_selectors(values, if field == "ip" { "ip" } else { "domain" }).map(Some)
}

/// Rule condition buckets we can read; anything else makes the rule
/// unrepresentable.
const KNOWN_RULE_KEYS: [&str; 8] = [
    "type",
    "domain",
    "ip",
    "port",
    "network",
    "inboundTag",
    "outboundTag",
    "balancerTag",
];

/// Port list covering exactly 53, however the source spelled it.
fn ports_only(values: Option<&Value>, expected: u16) -> bool {
    let Some(value) = values else { return false };
    let mut ports = Vec::new();
    let collect = |s: &str, ports: &mut Vec<String>| {
        for part in s.split(',') {
            ports.push(part.trim().to_string());
        }
    };
    match value {
        Value::String(s) => collect(s, &mut ports),
        Value::Number(n) => ports.push(n.to_string()),
        _ => return false,
    }
    !ports.is_empty() && ports.iter().all(|p| p == &expected.to_string())
}

/// `network` field → does it cover tcp / udp.
fn rule_network(rule: &Map<String, Value>) -> (bool, bool) {
    let Some(network) = rule.get("network").and_then(Value::as_str) else {
        return (true, true);
    };
    let mut tcp = false;
    let mut udp = false;
    for part in network.split(',') {
        match part.trim() {
            "tcp" => tcp = true,
            "udp" => udp = true,
            _ => {}
        }
    }
    (tcp, udp)
}

fn validate_source_outbound(outbound: &Value) -> io::Result<()> {
    let object = outbound
        .as_object()
        .ok_or_else(|| invalid("outbound must be an object"))?;

    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "tag" | "protocol" | "settings" | "streamSettings" | "mux"
        )
    }) {
        return Err(invalid("outbound contains unrepresented behavior"));
    }

    object
        .get("protocol")
        .and_then(Value::as_str)
        .filter(|protocol| !protocol.is_empty())
        .ok_or_else(|| invalid("outbound needs a protocol"))?;

    if object
        .get("settings")
        .is_some_and(|settings| !settings.is_object())
    {
        return Err(invalid("outbound settings must be an object"));
    }

    if let Some(stream) = object.get("streamSettings") {
        let stream = stream
            .as_object()
            .ok_or_else(|| invalid("streamSettings must be an object"))?;

        if let Some(sockopt) = stream.get("sockopt") {
            let sockopt = sockopt
                .as_object()
                .ok_or_else(|| invalid("sockopt must be an object"))?;

            for key in ["interface", "domainStrategy", "dialerProxy"] {
                if sockopt
                    .get(key)
                    .is_some_and(|value| value.as_str().is_none_or(|value| value.is_empty()))
                {
                    return Err(invalid("outbound socket selector must be a string"));
                }
            }
        }
    }

    if let Some(mux) = object.get("mux") {
        let mux = mux
            .as_object()
            .ok_or_else(|| invalid("mux must be an object"))?;
        if mux.keys().any(|key| {
            !matches!(
                key.as_str(),
                "enabled" | "concurrency" | "xudpConcurrency" | "xudpProxyUDP443"
            )
        }) || mux.get("enabled").and_then(Value::as_bool) != Some(false)
        {
            return Err(invalid("enabled or unrepresented mux is unsupported"));
        }
    }

    // Canonical matching currently ignores per-user level. Only the
    // default level has a managed runtime-policy equivalent.
    if let Some(settings) = object.get("settings") {
        for key in ["vnext", "servers"] {
            for server in settings
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                for user in server
                    .get("users")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if user
                        .get("level")
                        .is_some_and(|level| level.as_u64() != Some(0))
                    {
                        return Err(invalid("nondefault user level is unsupported"));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Plan the migration of a source Xray config.
///
/// `resolve_outbound` maps source outbounds to subscription endpoints.
/// Primary-node domain rules become fixed pins, independent of failover.
/// Every routing rule is imported, explicitly identified as wrapper-only,
/// or refused when its semantics cannot be preserved.
pub fn plan_xray_policy_migration(
    source: &Value,
    primary_key: Option<&str>,
    resolve_outbound: impl Fn(&Value) -> ResolvedOutbound,
) -> io::Result<XrayPolicyMigration> {
    let root = source
        .as_object()
        .ok_or_else(|| invalid("xray config must be a JSON object"))?;
    let mut migration = XrayPolicyMigration::default();

    for key in ["outbounds", "inbounds", "fakedns"] {
        if root.get(key).is_some_and(|value| !value.is_array()) {
            migration.refuse("invalidSourceShape", "source section must be an array");
        }
    }
    for key in ["routing", "dns", "policy"] {
        if root.get(key).is_some_and(|value| !value.is_object()) {
            migration.refuse("invalidSourceShape", "source section must be an object");
        }
    }
    if let Some(routing) = root.get("routing").and_then(Value::as_object) {
        for key in ["rules", "balancers"] {
            if routing.get(key).is_some_and(|value| !value.is_array()) {
                migration.refuse("invalidSourceShape", "routing list must be an array");
            }
        }
        for key in ["domainStrategy", "domainMatcher"] {
            if routing.get(key).is_some_and(|value| !value.is_string()) {
                migration.refuse("invalidSourceShape", "routing option must be a string");
            }
        }
    }
    if !migration.refused.is_empty() {
        return Ok(migration);
    }
    // ---- outbounds: classify once, gather bypasses + sockopts ----------
    let outbounds = root
        .get("outbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut outbound_tags: BTreeMap<String, Value> = BTreeMap::new();
    let mut sockopts: Option<XraySockopts> = None;
    let mut sockopts_conflict = false;
    for (index, outbound) in outbounds.iter().enumerate() {
        let Some(object) = outbound.as_object() else {
            migration.refuse(
                "unsupportedOutbound",
                format!("outbound #{index} is not an object"),
            );
            continue;
        };
        if validate_source_outbound(outbound).is_err() {
            migration.refuse(
                "unsupportedOutbound",
                format!("outbound #{index} has unrepresented settings"),
            );
            continue;
        }

        let Some(tag) = object
            .get("tag")
            .and_then(Value::as_str)
            .filter(|tag| !tag.trim().is_empty())
        else {
            migration.refuse("invalidOutboundTag", "source outbound needs a nonblank tag");
            continue;
        };

        match outbound_tags.entry(tag.to_string()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(outbound.clone());
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                migration.refuse(
                    "duplicateOutboundTag",
                    "source outbound tags must be unique",
                );
                continue;
            }
        }
        if is_auxiliary(outbound) {
            continue;
        }
        // Endpoint bypass: the node's address must stay reachable on the
        // physical uplink when a foreign tunnel holds the default route.
        if let Some(address) = object
            .get("settings")
            .and_then(|s| s.get("vnext"))
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .and_then(|v| v.get("address"))
            .and_then(Value::as_str)
            .or_else(|| {
                object
                    .get("settings")
                    .and_then(|s| s.get("servers"))
                    .and_then(Value::as_array)
                    .and_then(|v| v.first())
                    .and_then(|v| v.get("address"))
                    .and_then(Value::as_str)
            })
        {
            let address = address.trim();
            if !address.is_empty() && !migration.endpoint_bypasses.iter().any(|b| b == address) {
                migration.endpoint_bypasses.push(address.to_string());
            }
        }
        // sockopt keepalive/timeouts: merge identical sets, refuse
        // conflicts and unsupported knobs — silent loss changes traffic.
        if let Some(sockopt) = object.get("streamSettings").and_then(|s| s.get("sockopt")) {
            match import_sockopts(sockopt) {
                Ok(value) => {
                    if value != XraySockopts::default() {
                        match &sockopts {
                            None => sockopts = Some(value),
                            Some(existing) if *existing == value => {}
                            Some(_) => sockopts_conflict = true,
                        }
                    }
                }
                Err(detail) => migration.refuse("unsupportedSockopt", detail),
            }
        }
    }
    if sockopts_conflict {
        migration.refuse(
            "conflictingSockopts",
            "node outbounds carry conflicting sockopt keepalive/timeouts",
        );
        sockopts = None;
    }
    migration.sockopts = sockopts;

    // ---- balancers: only an ordered pool of node/proxy outbounds is
    // equivalent to our ordered failover; everything else must be refused.
    let balancers = root
        .get("routing")
        .and_then(|r| r.get("balancers"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut balancer_tags: BTreeSet<String> = BTreeSet::new();
    let default_balancers: BTreeSet<&str> = root
        .get("routing")
        .and_then(|routing| routing.get("rules"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|rule| {
            ["inboundTag", "domain", "ip", "port"]
                .iter()
                .all(|key| rule.get(key).is_none())
        })
        .filter_map(|rule| rule.get("balancerTag").and_then(Value::as_str))
        .collect();
    let mut source_balancer_tags = BTreeSet::new();
    for balancer in &balancers {
        let Some(object) = balancer.as_object() else {
            migration.refuse("unsupportedBalancer", "balancer must be an object");
            continue;
        };
        let Some(tag) = object
            .get("tag")
            .and_then(Value::as_str)
            .filter(|tag| !tag.trim().is_empty())
        else {
            migration.refuse("invalidBalancerTag", "balancer needs a nonblank tag");
            continue;
        };
        if !source_balancer_tags.insert(tag) || outbound_tags.contains_key(tag) {
            migration.refuse(
                "duplicateTargetTag",
                "source target tags must be unambiguous",
            );
        }
    }
    for balancer in &balancers {
        let Some(object) = balancer.as_object() else {
            continue;
        };
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if !default_balancers.contains(tag.as_str()) {
            migration.skip("wrapperBalancer", "balancer not used by the default path");
            continue;
        }
        balancer_tags.insert(tag.clone());
        let selectors = object
            .get("selector")
            .and_then(Value::as_array)
            .filter(|selectors| !selectors.is_empty())
            .and_then(|selectors| {
                selectors
                    .iter()
                    .map(|selector| {
                        selector
                            .as_str()
                            .filter(|selector| !selector.is_empty())
                            .map(str::to_string)
                    })
                    .collect::<Option<Vec<_>>>()
            });

        let Some(selectors) = selectors else {
            migration.refuse(
                "unsupportedBalancer",
                "default balancer selectors are invalid",
            );
            continue;
        };

        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "tag" | "selector" | "strategy"))
            || object.get("strategy").is_some_and(|strategy| {
                strategy.as_object().is_none_or(|strategy| {
                    strategy.keys().any(|key| key != "type")
                        || strategy.get("type").and_then(Value::as_str) != Some("leastPing")
                })
            })
        {
            migration.refuse(
                "unsupportedBalancer",
                "default balancer settings are unrepresented",
            );
            continue;
        }
        let all_pool = !selectors.is_empty()
            && selectors.iter().all(|selector| {
                outbound_tags.values().any(|outbound| {
                    let matches_tag = outbound
                        .get("tag")
                        .and_then(Value::as_str)
                        .is_some_and(|t| t.starts_with(selector));
                    matches_tag && !is_auxiliary(outbound)
                })
            });
        let least_ping = object
            .get("strategy")
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            .is_none_or(|t| t == "leastPing");
        if all_pool && least_ping {
            let mut backups = Vec::new();
            for outbound in &outbounds {
                if !outbound["tag"]
                    .as_str()
                    .is_some_and(|tag| selectors.iter().any(|selector| tag.starts_with(selector)))
                {
                    continue;
                }
                match resolve_outbound(outbound) {
                    ResolvedOutbound::Primary => {}
                    ResolvedOutbound::Pinned(key) if Some(key.as_str()) == primary_key => {}
                    ResolvedOutbound::Pinned(key) => {
                        if !backups
                            .iter()
                            .any(|node: &crate::models::EndpointRef| node.key == key)
                        {
                            backups.push(crate::models::EndpointRef {
                                key,
                                name: "Imported backup".into(),
                            });
                        }
                    }
                    _ => migration.refuse(
                        "unmappedPoolMember",
                        "default pool contains an unmapped node",
                    ),
                }
            }
            if backups.len() >= subscription::MAX_FAILOVER_NODES {
                migration.refuse(
                    "poolCapacity",
                    "default pool exceeds eight ordered candidates",
                );
            } else {
                if migration
                    .backup_keys
                    .as_ref()
                    .is_some_and(|existing| existing != &backups)
                {
                    migration.refuse(
                        "conflictingDefaultPools",
                        "multiple default pools produce different backup chains",
                    );
                } else {
                    migration.backup_keys = Some(backups);
                }
            }
            migration.skip(
                "orderedFailover",
                format!(
                    "balancer '{tag}': pool members join ordered failover instead of leastPing"
                ),
            );
        } else {
            migration.refuse(
                "unsupportedBalancer",
                format!("balancer '{tag}' selects non-node outbounds or a non-leastPing strategy"),
            );
        }
    }

    // ---- dns: imported before routing rules so port-53 resolver pins
    // can match the imported server list.
    import_dns(root.get("dns"), &mut migration);
    import_runtime_policy(root, &mut migration);
    for outbound in &outbounds {
        if resolve_outbound(outbound) == ResolvedOutbound::Direct {
            if let Some(strategy) = outbound
                .pointer("/streamSettings/sockopt/domainStrategy")
                .and_then(Value::as_str)
            {
                if !matches!(
                    strategy,
                    "UseIP" | "UseIPv4" | "UseIPv6" | "ForceIP" | "ForceIPv4" | "ForceIPv6"
                ) {
                    migration.refuse(
                        "directDomainStrategy",
                        "unsupported direct address-family strategy",
                    );
                } else if migration
                    .direct_domain_strategy
                    .as_deref()
                    .is_some_and(|old| old != strategy)
                {
                    migration.refuse(
                        "directDomainStrategy",
                        "conflicting direct address-family strategies",
                    );
                } else {
                    migration.direct_domain_strategy = Some(strategy.to_string());
                }
            }
        }
        if outbound["protocol"] == "dns" {
            if let Some(settings) = outbound.get("settings") {
                match import_dns_outbound(settings) {
                    Ok(settings) => migration.dns.outbound = Some(settings),
                    Err(()) => {
                        migration.refuse("dnsOutboundSettings", "unsupported DNS rewrite settings")
                    }
                }
            }
            if let Some(tag) = outbound
                .pointer("/streamSettings/sockopt/dialerProxy")
                .and_then(Value::as_str)
            {
                let resolved = outbound_tags
                    .get(tag)
                    .map(&resolve_outbound)
                    .unwrap_or(ResolvedOutbound::Foreign);
                match resolved {
                    ResolvedOutbound::Pinned(key) => migration.dns.outbound_key = Some(key),
                    ResolvedOutbound::Primary if primary_key.is_some() => {
                        migration.dns.outbound_key = primary_key.map(str::to_string)
                    }
                    ResolvedOutbound::Direct => {}
                    _ => migration.refuse(
                        "dnsEgress",
                        "DNS forwarding needs a mapped subscription endpoint",
                    ),
                }
            }
        }
    }

    // ---- routing --------------------------------------------------------
    let routing = root.get("routing").and_then(Value::as_object);
    if let Some(routing) = routing {
        match routing.get("domainStrategy").and_then(Value::as_str) {
            None | Some("AsIs") => {}
            Some("IPIfNonMatch") => {
                migration.domain_strategy = Some(XrayDomainStrategy::IpIfNonMatch)
            }
            Some("IPOnDemand") => migration.domain_strategy = Some(XrayDomainStrategy::IpOnDemand),
            Some(other) => migration.refuse(
                "unsupportedDomainStrategy",
                format!("routing.domainStrategy '{other}'"),
            ),
        }
        match routing.get("domainMatcher").and_then(Value::as_str) {
            None => {}
            Some("mph") => migration.domain_matcher = Some(XrayDomainMatcher::Mph),
            Some("hybrid") => migration.domain_matcher = Some(XrayDomainMatcher::Hybrid),
            Some("linear") => migration.domain_matcher = Some(XrayDomainMatcher::Linear),
            Some(other) => migration.refuse(
                "unsupportedDomainMatcher",
                format!("routing.domainMatcher '{other}'"),
            ),
        }
        for key in routing.keys() {
            if !matches!(
                key.as_str(),
                "domainStrategy" | "domainMatcher" | "rules" | "balancers"
            ) {
                migration.skip("routingExtra", format!("routing.{key}"));
            }
        }
        let rules = routing
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for (index, rule) in rules.iter().enumerate() {
            import_rule(
                index,
                rule,
                primary_key,
                &outbound_tags,
                &balancer_tags,
                &resolve_outbound,
                &mut migration,
            );
        }
    }

    // ---- top-level fakedns --------------------------------------------------
    if let Some(fakedns) = root.get("fakedns") {
        let standard = fakedns
            .as_array()
            .map(|entries| {
                !entries.is_empty()
                    && entries.iter().all(|entry| {
                        entry.get("ipPool").and_then(Value::as_str) == Some("198.18.0.0/16")
                            && entry.get("poolSize") == Some(&json!(65535))
                    })
            })
            .unwrap_or(false);
        if standard {
            migration.dns.fake_dns = true;
        } else {
            migration.refuse(
                "unsupportedFakeDns",
                "fakedns uses a non-standard ipPool/poolSize",
            );
        }
    }

    // ---- geodata asset URLs ---------------------------------------------------
    if let Some(geodata) = root.get("geodata").and_then(Value::as_object) {
        for asset in geodata
            .get("assets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let file = asset
                .get("file")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let url = asset.get("url").and_then(Value::as_str).unwrap_or_default();
            let https = url.starts_with("https://");
            match (file, https) {
                ("geoip.dat", true) => migration.geoip_url = Some(url.to_string()),
                ("geosite.dat", true) => migration.geosite_url = Some(url.to_string()),
                (_, false) => migration.refuse(
                    "insecureGeoAsset",
                    format!("geodata asset '{file}' is not fetched over HTTPS"),
                ),
                _ => migration.skip("geoAsset", format!("geodata asset '{file}'")),
            }
        }
        for key in geodata.keys() {
            if key != "assets" {
                migration.skip("geoExtra", format!("geodata.{key}"));
            }
        }
    }

    // ---- sections we manage or never import -----------------------------------
    const MANAGED_SECTIONS: [&str; 6] = [
        "inbounds",
        "api",
        "observatory",
        "burstObservatory",
        "log",
        "policy",
    ];
    for section in MANAGED_SECTIONS {
        if let Some(value) = root.get(section) {
            let detail = if section == "inbounds" {
                let protocols: Vec<&str> = value
                    .as_array()
                    .map(|inbounds| {
                        inbounds
                            .iter()
                            .filter_map(|inbound| inbound.get("protocol").and_then(Value::as_str))
                            .collect()
                    })
                    .unwrap_or_default();
                format!("inbounds ({})", protocols.join(", "))
            } else {
                section.to_string()
            };
            migration.skip("managedSection", detail);
        }
    }
    let known: BTreeSet<&str> = [
        "outbounds",
        "routing",
        "dns",
        "fakedns",
        "geodata",
        "inbounds",
        "api",
        "observatory",
        "burstObservatory",
        "log",
        "policy",
        "remarks",
        "meta",
    ]
    .into_iter()
    .collect();
    for key in root.keys() {
        if !known.contains(key.as_str()) {
            migration.skip("unknownSection", key.clone());
        }
    }
    if let Err(error) = validate_migration_fields(&migration) {
        migration.refuse("invalidManagedPolicy", error.to_string());
    }
    Ok(migration)
}

/// One routing rule → managed construct, explicit skip, or refusal.
fn import_rule(
    index: usize,
    rule: &Value,
    primary_key: Option<&str>,
    outbound_tags: &BTreeMap<String, Value>,
    balancer_tags: &BTreeSet<String>,
    resolve_outbound: &impl Fn(&Value) -> ResolvedOutbound,
    migration: &mut XrayPolicyMigration,
) {
    let Some(object) = rule.as_object() else {
        migration.refuse("unsupportedRule", format!("rule #{index} is not an object"));
        return;
    };

    if object
        .get("type")
        .is_some_and(|value| value.as_str() != Some("field"))
    {
        migration.refuse(
            "unsupportedRule",
            format!("rule #{index} has unsupported type"),
        );
        return;
    }

    if object
        .keys()
        .any(|key| !KNOWN_RULE_KEYS.contains(&key.as_str()))
    {
        migration.refuse(
            "unsupportedRuleCondition",
            format!("rule #{index} has an unrepresented condition"),
        );
        return;
    }

    // Local inbound rules are excluded, never generalized.
    if object.contains_key("inboundTag") {
        migration.skip(
            "wrapperInbound",
            format!("rule #{index} uses local inbound selectors"),
        );
        return;
    }

    let domains = match rule_selectors(object, "domain") {
        Ok(values) => values,
        Err(_) => {
            migration.refuse(
                "unsupportedSelector",
                format!("rule #{index}: invalid domain array"),
            );
            return;
        }
    };
    let ips = match rule_selectors(object, "ip") {
        Ok(values) => values,
        Err(_) => {
            migration.refuse(
                "unsupportedSelector",
                format!("rule #{index}: invalid IP array"),
            );
            return;
        }
    };

    if domains.is_some() && ips.is_some() {
        migration.refuse(
            "compoundSelector",
            format!("rule #{index} combines domain and IP conditions"),
        );
        return;
    }

    if object
        .get("network")
        .is_some_and(|value| !matches!(value.as_str(), Some("tcp" | "udp" | "tcp,udp" | "udp,tcp")))
    {
        migration.refuse(
            "unsupportedNetwork",
            format!("rule #{index} has unsupported network selectors"),
        );
        return;
    }
    let (covers_tcp, covers_udp) = rule_network(object);
    let network = if covers_tcp && covers_udp {
        "tcp,udp"
    } else if covers_tcp {
        "tcp"
    } else {
        "udp"
    };

    let target_tag = match (object.get("outboundTag"), object.get("balancerTag")) {
        (Some(value), None) | (None, Some(value)) => {
            match value.as_str().filter(|tag| !tag.trim().is_empty()) {
                Some(tag) => tag,
                None => {
                    migration.refuse(
                        "unsupportedRule",
                        format!("rule #{index} has an invalid target"),
                    );
                    return;
                }
            }
        }
        _ => {
            migration.refuse(
                "unsupportedRule",
                format!("rule #{index} needs exactly one target"),
            );
            return;
        }
    };

    let target = if object.contains_key("outboundTag") {
        outbound_tags
            .get(target_tag)
            .map(resolve_outbound)
            .unwrap_or(ResolvedOutbound::Foreign)
    } else if balancer_tags.contains(target_tag) {
        ResolvedOutbound::Default
    } else {
        ResolvedOutbound::Foreign
    };

    let target = match target {
        ResolvedOutbound::Primary => match primary_key {
            Some(key) => ResolvedOutbound::Pinned(key.to_string()),
            None => ResolvedOutbound::Foreign,
        },
        other => other,
    };

    if let Some(value) = object.get("port") {
        let port = if ports_only(Some(value), 53) {
            Some(53)
        } else if ports_only(Some(value), 443) {
            Some(443)
        } else {
            value
                .as_u64()
                .or_else(|| value.as_str()?.parse::<u64>().ok())
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
        };

        let Some(port) = port else {
            migration.refuse(
                "unsupportedPortRule",
                format!("rule #{index} needs one representable port"),
            );
            return;
        };

        if port == 53 && target == ResolvedOutbound::Dns {
            if domains.is_some() || ips.is_some() || !covers_tcp || !covers_udp {
                migration.refuse(
                    "conditionalDnsCapture",
                    format!("rule #{index}: restricted DNS capture is not representable"),
                );
            } else if migration.dns.servers.is_empty() && migration.dns.hosts.is_empty() {
                migration.refuse(
                    "dnsIntercept",
                    format!("rule #{index}: DNS capture needs a resolver policy"),
                );
            } else {
                migration.skip(
                    "dnsIntercept",
                    format!("rule #{index}: managed DNS capture"),
                );
            }
            return;
        }

        if port == 443
            && covers_udp
            && !covers_tcp
            && domains.is_none()
            && ips.is_none()
            && target == ResolvedOutbound::Block
        {
            migration.quic_reject = true;
            migration.skip(
                "quicReject",
                format!("rule #{index}: managed QUIC rejection"),
            );
            return;
        }

        if domains.is_none() {
            let guard_target = match &target {
                ResolvedOutbound::Direct => Some(DomainRouteTarget::Direct),
                ResolvedOutbound::Block => Some(DomainRouteTarget::Block),
                _ => None,
            };
            if let (Some(ips), Some(target)) = (ips, guard_target) {
                migration.traffic_rules.push(XrayTrafficRule {
                    ips,
                    port,
                    network: network.to_string(),
                    target,
                });
                return;
            }
        }

        migration.refuse(
            "unsupportedPortRule",
            format!("rule #{index}: port policy is not representable"),
        );
        return;
    }

    if !covers_tcp || !covers_udp {
        migration.refuse(
            "networkScopedRule",
            format!("rule #{index}: protocol-scoped policy is not representable"),
        );
        return;
    }

    let (selectors, is_ip_rule) = match (domains, ips) {
        (Some(selectors), None) => (selectors, false),
        (None, Some(selectors)) => (selectors, true),
        (None, None) => {
            if target == ResolvedOutbound::Default {
                migration.skip(
                    "defaultRoute",
                    format!("rule #{index}: managed ordered default route"),
                );
            } else {
                migration.refuse(
                    "unsupportedDefaultRoute",
                    format!("rule #{index}: fixed catch-all is not the managed default"),
                );
            }
            return;
        }
        (Some(_), Some(_)) => unreachable!("compound selectors rejected above"),
    };

    match target {
        ResolvedOutbound::Default => migration.domain_policies.push(DomainPolicy {
            domains: selectors,
            target: DomainRouteTarget::Proxy,
        }),
        ResolvedOutbound::Direct => migration.domain_policies.push(DomainPolicy {
            domains: selectors,
            target: DomainRouteTarget::Direct,
        }),
        ResolvedOutbound::Block => migration.domain_policies.push(DomainPolicy {
            domains: selectors,
            target: DomainRouteTarget::Block,
        }),
        ResolvedOutbound::Pinned(key) if !is_ip_rule => {
            migration.pinned_routes.push(PinnedRoute {
                selectors,
                endpoint_key: key,
                missing: false,
            });
        }
        ResolvedOutbound::Interface {
            name,
            domain_strategy,
        } => {
            migration
                .interface_routes
                .push(crate::models::XrayInterfaceRoute {
                    selectors,
                    interface_name: name,
                    domain_strategy,
                });
        }
        ResolvedOutbound::Pinned(_) => migration.refuse(
            "pinnedIpRule",
            format!("rule #{index}: pinned IP policies are not represented"),
        ),
        ResolvedOutbound::Dns | ResolvedOutbound::Foreign | ResolvedOutbound::Primary => migration
            .refuse(
                "unknownTarget",
                format!("rule #{index}: target is not represented"),
            ),
    }
}

/// `dns` section → `XrayDnsConfig`; unknown keys refuse rather than drop.
fn import_dns(dns: Option<&Value>, migration: &mut XrayPolicyMigration) {
    let Some(dns) = dns else { return };
    let Some(object) = dns.as_object() else {
        migration.refuse("invalidDns", "dns is not an object");
        return;
    };
    const KNOWN_DNS_KEYS: [&str; 10] = [
        "servers",
        "hosts",
        "queryStrategy",
        "clientIp",
        "tag",
        "disableCache",
        "disableFallback",
        "disableFallbackIfMatch",
        "enableParallelQuery",
        "useSystemHosts",
    ];
    for (key, value) in object {
        match key.as_str() {
            "servers" => {}
            "hosts" => {}
            "queryStrategy" => match value.as_str() {
                Some("UseIP") => migration.dns.query_strategy = Some(XrayDnsQueryStrategy::UseIp),
                Some("UseIPv4") => {
                    migration.dns.query_strategy = Some(XrayDnsQueryStrategy::UseIpv4)
                }
                Some("UseIPv6") => {
                    migration.dns.query_strategy = Some(XrayDnsQueryStrategy::UseIpv6)
                }
                _ => migration.refuse(
                    "unsupportedDnsStrategy",
                    "dns.queryStrategy is not a supported value",
                ),
            },
            // The intercept tag has no meaning for the managed dns section.
            "tag" => migration.skip("dnsTag", "dns.tag (intercept naming)"),
            "enableParallelQuery" => match value.as_bool() {
                Some(value) => migration.dns.enable_parallel_query = Some(value),
                None => migration.refuse("unsupportedDnsOption", "DNS scheduling must be boolean"),
            },
            "clientIp"
            | "disableCache"
            | "disableFallback"
            | "disableFallbackIfMatch"
            | "useSystemHosts" => {
                let non_default = !value.is_null() && *value != json!(false) && *value != json!("");
                if non_default {
                    migration.refuse(
                        "unsupportedDnsOption",
                        format!("dns.{key} has no managed equivalent"),
                    );
                } else {
                    migration.skip("dnsOption", format!("dns.{key} is the xray default"));
                }
            }
            _ => {
                if !KNOWN_DNS_KEYS.contains(&key.as_str()) {
                    migration.refuse("unsupportedDnsOption", format!("dns.{key} is unknown"));
                }
            }
        }
    }
    if let Some(servers) = object.get("servers").and_then(Value::as_array) {
        for entry in servers {
            match import_dns_server(entry) {
                Ok(server) => {
                    if server.address == "fakedns" {
                        migration.dns.fake_dns = true;
                    } else {
                        migration.dns.servers.push(server);
                    }
                }
                Err(detail) => migration.refuse("unsupportedDnsServer", detail),
            }
        }
    } else if let Some(servers) = object.get("servers") {
        if !servers.is_null() {
            migration.refuse("invalidDns", "dns.servers is not an array");
        }
    }
    if let Some(hosts) = object.get("hosts").and_then(Value::as_object) {
        for (name, value) in hosts {
            let values = match value {
                Value::String(single) => Some(vec![single.clone()]),
                Value::Array(items) if !items.is_empty() => items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>(),
                _ => None,
            };
            match values {
                Some(values) => {
                    migration.dns.hosts.insert(name.clone(), values);
                }
                None => migration.refuse(
                    "invalidDns",
                    "DNS hosts values must be strings or nonempty arrays of strings",
                ),
            }
        }
    } else if let Some(hosts) = object.get("hosts") {
        if !hosts.is_null() {
            migration.refuse("invalidDns", "dns.hosts is not an object");
        }
    }
    // Let the shared validator decide whether the imported policy is legal;
    // anything it rejects is a refusal, not a silent drop.
    let validation = xray::validate_dns_config(&migration.dns);
    if let Err(error) = validation {
        migration.refuse("invalidDns", error.to_string());
    }
}

/// One `dns.servers` entry (string or object).
fn import_dns_server(entry: &Value) -> Result<XrayDnsServer, String> {
    if let Some(address) = entry.as_str() {
        return Ok(XrayDnsServer {
            address: address.to_string(),
            port: None,
            domains: Vec::new(),
            skip_fallback: false,
            route: XrayDnsRoute::None,
        });
    }

    let object = entry
        .as_object()
        .ok_or_else(|| "DNS server must be a string or object".to_string())?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "address" | "port" | "domains" | "skipFallback"
        )
    }) {
        return Err("DNS server has an unrepresented option".to_string());
    }

    let address = object
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| "DNS server needs a string address".to_string())?;

    let port = object
        .get("port")
        .map(|value| {
            value
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| "DNS server port is invalid".to_string())
        })
        .transpose()?;

    let domains = match object.get("domains") {
        None => Vec::new(),
        Some(value) => {
            let values = value
                .as_array()
                .ok_or_else(|| "DNS server domains must be an array".to_string())?;
            if values.is_empty() {
                Vec::new()
            } else {
                normalize_selectors(values, "domain")
                    .map_err(|_| "DNS server domains are invalid".to_string())?
            }
        }
    };

    let skip_fallback = object
        .get("skipFallback")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| "DNS skipFallback must be boolean".to_string())
        })
        .transpose()?
        .unwrap_or(false);

    Ok(XrayDnsServer {
        address: address.to_string(),
        port,
        domains,
        skip_fallback,
        route: XrayDnsRoute::None,
    })
}

/// `streamSettings.sockopt` → `XraySockopts`; unsupported knobs refuse.
fn import_sockopts(sockopt: &Value) -> Result<XraySockopts, String> {
    let object = sockopt
        .as_object()
        .ok_or_else(|| "sockopt must be an object".to_string())?;

    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "tcpKeepAliveIdle" | "tcpKeepAliveInterval" | "tcpUserTimeout" | "tcpNoDelay"
        )
    }) {
        return Err("unsupported sockopt field".to_string());
    }

    let integer = |key: &str| -> Result<Option<u32>, String> {
        object
            .get(key)
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| format!("sockopt.{key} must be an unsigned integer"))
            })
            .transpose()
    };

    let tcp_no_delay = object
        .get("tcpNoDelay")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| "sockopt.tcpNoDelay must be boolean".to_string())
        })
        .transpose()?
        .unwrap_or(false);

    let sockopts = XraySockopts {
        tcp_keep_alive_idle: integer("tcpKeepAliveIdle")?,
        tcp_keep_alive_interval: integer("tcpKeepAliveInterval")?,
        tcp_user_timeout: integer("tcpUserTimeout")?,
        tcp_no_delay,
    };
    xray::validate_stream_sockopts(&sockopts)
        .map_err(|_| "sockopt values exceed supported bounds".to_string())?;
    Ok(sockopts)
}

fn import_runtime_policy(root: &Map<String, Value>, migration: &mut XrayPolicyMigration) {
    if let Some(levels) = root.get("policy").and_then(|value| value.get("levels")) {
        if let Some(levels) = levels.as_object() {
            for (level, settings) in levels {
                if level != "0"
                    || settings
                        .as_object()
                        .is_none_or(|settings| settings.keys().any(|key| key != "connIdle"))
                {
                    migration.refuse(
                        "connectionPolicy",
                        "only the default-level connection idle policy is supported",
                    );
                    continue;
                }
                if let Some(idle) = settings.get("connIdle") {
                    match idle.as_u64().filter(|seconds| *seconds <= 86_400) {
                        Some(seconds) => migration.connection_idle_secs = Some(seconds as u32),
                        None => migration.refuse(
                            "connectionPolicy",
                            "connection idle timeout must be 0-86400 seconds",
                        ),
                    }
                }
            }
        } else {
            migration.refuse(
                "connectionPolicy",
                "connection policy levels must be an object",
            );
        }
    }
    let mut saw_tun = false;
    for inbound in root
        .get("inbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if inbound["protocol"] != "tun" {
            continue;
        }
        if saw_tun {
            migration.refuse(
                "multipleTunPolicies",
                "only one source TUN policy is representable",
            );
            continue;
        }
        saw_tun = true;
        if let Some(mtu) = inbound.pointer("/settings/mtu") {
            match mtu.as_u64().filter(|mtu| (1280..=9000).contains(mtu)) {
                Some(mtu) => migration.tun_mtu = Some(mtu as u32),
                None => migration.refuse("tunMtu", "TUN MTU must be 1280-9000"),
            }
        }
        if let Some(servers) = inbound.pointer("/settings/dns") {
            match servers.as_array().filter(|servers| servers.len() <= 8) {
                Some(servers) => {
                    for server in servers {
                        match server
                            .as_str()
                            .and_then(|server| server.parse::<std::net::IpAddr>().ok())
                        {
                            Some(server) if !server.is_unspecified() && !server.is_multicast() => {
                                migration.tun_dns_servers.push(server)
                            }
                            _ => migration
                                .refuse("tunDns", "TUN DNS servers must be unicast IP addresses"),
                        }
                    }
                }
                None => migration.refuse("tunDns", "TUN DNS needs at most eight IP addresses"),
            }
        }
    }
}

fn import_dns_outbound(value: &Value) -> Result<XrayDnsOutboundSettings, ()> {
    let object = value.as_object().ok_or(())?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "rewriteAddress" | "rewritePort" | "rewriteNetwork" | "rules"
        )
    }) {
        return Err(());
    }
    serde_json::from_value(value.clone()).map_err(|_| ())
}

fn validate_migration_fields(migration: &XrayPolicyMigration) -> io::Result<()> {
    xray::validate_routing_policy_selectors(&migration.domain_policies)?;
    xray::validate_dns_config(&migration.dns)?;
    xray::validate_advanced_routing_options(
        &migration.traffic_rules,
        &migration.interface_routes,
        migration.sockopts.as_ref(),
        migration.connection_idle_secs,
        migration.direct_domain_strategy.as_deref(),
    )?;
    xray::validate_tun_profile_settings(migration.tun_mtu, &migration.tun_dns_servers)?;
    xray::validate_pinned_routes(&migration.pinned_routes)?;

    if let Some(backups) = &migration.backup_keys {
        if backups.len() >= subscription::MAX_FAILOVER_NODES {
            return Err(invalid("too many imported backup endpoints"));
        }
        let mut seen = BTreeSet::new();
        for backup in backups {
            if !subscription::valid_endpoint_key(&backup.key) || !seen.insert(backup.key.as_str()) {
                return Err(invalid("invalid imported backup references"));
            }
        }
    }

    Ok(())
}

/// Apply a planned migration to a profile. Refuses (error, nothing applied)
/// while `migration.refused` is non-empty — explicit refusal, never a
/// partial import.
pub fn apply_xray_policy_migration(
    profile: &mut Profile,
    migration: XrayPolicyMigration,
) -> io::Result<()> {
    if !migration.refused.is_empty() {
        return Err(invalid(format!(
            "xray policy migration refused {} construct(s): {}",
            migration.refused.len(),
            migration
                .refused
                .iter()
                .map(|refusal| refusal.reason.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    validate_migration_fields(&migration)?;
    if migration
        .backup_keys
        .as_ref()
        .is_some_and(|backups| !backups.is_empty())
        && profile.subscription.is_none()
    {
        return Err(invalid(
            "imported default pool requires a subscription profile",
        ));
    }
    let mut pins = profile.pinned_policies.clone();
    for imported in migration.pinned_routes {
        if pins.iter().any(|existing| {
            existing.endpoint_key != imported.endpoint_key
                && existing
                    .selectors
                    .iter()
                    .any(|selector| imported.selectors.contains(selector))
        }) {
            return Err(invalid(
                "imported pinned route conflicts with an existing explicit pin",
            ));
        }
        if !pins.iter().any(|existing| {
            existing.endpoint_key == imported.endpoint_key
                && existing.selectors == imported.selectors
        }) {
            pins.push(imported);
        }
    }
    xray::validate_pinned_routes(&pins)?;
    if let (Some(subscription), Some(backups)) = (&mut profile.subscription, migration.backup_keys)
    {
        subscription.backup_keys = backups;
    }
    profile.domain_policies = migration.domain_policies;
    profile.pinned_policies = pins;
    profile.xray_dns = migration.dns;
    profile.xray_domain_strategy = migration.domain_strategy;
    profile.xray_domain_matcher = migration.domain_matcher;
    profile.endpoint_bypasses = migration.endpoint_bypasses;
    profile.private_lan_direct = migration.private_lan_direct;
    profile.xray_quic_reject = migration.quic_reject;
    profile.xray_sockopts = migration.sockopts;
    profile.xray_geoip_url = migration.geoip_url;
    profile.xray_geosite_url = migration.geosite_url;
    profile.xray_traffic_rules = migration.traffic_rules;
    profile.xray_interface_routes = migration.interface_routes;
    profile.xray_connection_idle_secs = migration.connection_idle_secs;
    profile.xray_tun_mtu = migration.tun_mtu;
    profile.xray_tun_dns_servers = migration.tun_dns_servers;
    profile.xray_direct_domain_strategy = migration.direct_domain_strategy;
    Ok(())
}

/// Serialize a migration for client display: applied construct counts plus
/// every skip/refusal. Contains no credentials by construction.
pub fn migration_summary(migration: &XrayPolicyMigration) -> serde_json::Value {
    serde_json::json!({
        "domainPolicies": migration.domain_policies.len(),
        "pinnedRoutes": migration.pinned_routes.len(),
        "backupNodes": migration.backup_keys.as_ref().map(Vec::len),
        "trafficGuards": migration.traffic_rules.len(),
        "connectionIdleSecs": migration.connection_idle_secs,
        "tunMtu": migration.tun_mtu,
        "dnsServers": migration.dns.servers.len(),
        "dnsHosts": migration.dns.hosts.len(),
        "endpointBypasses": migration.endpoint_bypasses,
        "privateLanDirect": migration.private_lan_direct,
        "quicReject": migration.quic_reject,
        "skipped": migration.skipped,
        "refused": migration.refused,
    })
}

#[cfg(test)]
mod tests;
