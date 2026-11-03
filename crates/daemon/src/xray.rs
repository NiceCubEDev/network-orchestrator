use crate::validate::{full_coverage, validate_owner};
use net_manager_core::daemon_protocol::XrayConnectParams;
use net_manager_core::models::PolicyRoute;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;

pub const MAX_XRAY_CONFIG_BYTES: usize = 512 * 1024;

pub struct XrayPlan {
    pub profile_id: String,
    pub name: String,
    pub config: String,
    pub routes: Vec<PolicyRoute>,
    pub address: ipnet::IpNet,
    pub mtu: u32,
    pub dns_servers: Vec<IpAddr>,
    pub dns_domains: Vec<String>,
    /// Additional hosts that get a physical-gateway host route when their
    /// family is fully captured (see [`dns_bypass_addrs`]): upstream DNS
    /// resolvers chosen in the profile, which may be literal IPs or names.
    pub dns_bypass: Vec<String>,
    pub full_ipv4: bool,
    pub full_ipv6: bool,
    pub mark: u32,
    /// Loopback port of the injected `api-in` StatsService listener.
    pub api_port: u16,
    /// Upstream host of every proxy outbound (`node-`/`pin-` and the
    /// primary): literal IPs or hostnames. The kernel keeps a direct route
    /// to each outside the tunnel — any node must be reachable while the
    /// tunnel captures the family, not only the currently selected one.
    pub server_hosts: Vec<String>,
    /// Node hostnames [`pin_server_addresses`] could not resolve while the
    /// uplink was intact: they resolve inside the tunnel instead.
    pub unpinned_hosts: Vec<String>,
    /// Every node host is a literal IP or was pre-resolved, so nothing has
    /// to resolve a server name once the tunnel is up.
    pub server_pinned: bool,
    /// Multinode failover the probe supervisor steers at runtime; absent on
    /// single-endpoint tunnels.
    pub failover: Option<net_manager_core::daemon_protocol::XrayFailoverParams>,
    pub reject_quic: bool,
    pub probe_url: Option<String>,
    pub pinned_keys: Vec<String>,
    pub service_checks: Vec<net_manager_core::models::ServiceCheck>,
    pub proxy_exits: Vec<net_manager_core::daemon_protocol::ProxyExitBinding>,
    /// Inline caller-provided `geoip.dat`/`geosite.dat` contents; decoded
    /// into the root-owned staging dir before spawn (the sandboxed unit
    /// cannot see caller paths).
    pub geo_assets: Option<net_manager_core::daemon_protocol::XrayGeoAssets>,
}

impl std::fmt::Debug for XrayPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XrayPlan")
            .field("profile_id", &self.profile_id)
            .field("name", &self.name)
            .field("config", &"[REDACTED]")
            .field("routes", &self.routes)
            .field("address", &self.address)
            .field("mtu", &self.mtu)
            .field("dns_servers", &self.dns_servers)
            .field("dns_domains", &self.dns_domains)
            .field("dns_bypass", &self.dns_bypass)
            .field("full_ipv4", &self.full_ipv4)
            .field("full_ipv6", &self.full_ipv6)
            .field("mark", &self.mark)
            .field("server_hosts", &self.server_hosts)
            .field("server_pinned", &self.server_pinned)
            .field("unpinned_hosts", &self.unpinned_hosts.len())
            .field("geo_assets", &self.geo_assets.is_some())
            .field("failover", &self.failover.is_some())
            .finish()
    }
}

fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "unsupported generated Xray TUN config",
    )
}

fn object<'a>(value: &'a Value, allowed: &[&str]) -> io::Result<&'a Map<String, Value>> {
    let map = value.as_object().ok_or_else(rejected)?;
    if map.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(rejected());
    }
    Ok(map)
}

fn string(value: &Value) -> io::Result<&str> {
    value
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(rejected)
}

/// Panels encode "not set" as an explicit empty string (`"shortId": ""`,
/// `"spiderX": ""`) — accept empty where a field is optional for Xray.
fn maybe_string(value: &Value) -> io::Result<()> {
    if value.as_str().is_some_and(|s| s.len() <= 256) {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn port(value: &Value) -> io::Result<()> {
    if value
        .as_u64()
        .is_some_and(|port| (1..=65535).contains(&port))
    {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn one(value: &Value) -> io::Result<&Value> {
    let array = value.as_array().ok_or_else(rejected)?;
    if array.len() != 1 {
        return Err(rejected());
    }
    Ok(&array[0])
}

fn validate_generated(config: &Value) -> io::Result<()> {
    let root = object(
        config,
        &[
            "log",
            "inbounds",
            "outbounds",
            "routing",
            "dns",
            "fakedns",
            "policy",
        ],
    )?;
    if let Some(log) = root.get("log") {
        object(log, &["loglevel"])?;
        if !matches!(log["loglevel"].as_str(), Some("warning" | "error" | "none")) {
            return Err(rejected());
        }
    }
    if let Some(dns) = root.get("dns") {
        validate_dns(dns)?;
    }
    if let Some(fakedns) = root.get("fakedns") {
        validate_fakedns(fakedns)?;
    }
    if let Some(policy) = root.get("policy") {
        object(policy, &["levels"])?;
        object(&policy["levels"], &["0"])?;
        let level = object(&policy["levels"]["0"], &["connIdle"])?;
        if !level
            .get("connIdle")
            .and_then(Value::as_u64)
            .is_some_and(|value| value <= 86_400)
        {
            return Err(rejected());
        }
    }
    let inbounds = root
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(rejected)?;
    if inbounds.is_empty() || inbounds.len() > 2 {
        return Err(rejected());
    }
    for inbound in inbounds {
        let map = object(
            inbound,
            &["tag", "listen", "port", "protocol", "settings", "sniffing"],
        )?;
        if inbound["listen"] != "127.0.0.1" {
            return Err(rejected());
        }
        port(&inbound["port"])?;
        string(&inbound["tag"])?;
        if let Some(sniffing) = map.get("sniffing") {
            validate_sniffing(sniffing)?;
        }
        match string(&inbound["protocol"])? {
            "socks" => {
                if let Some(settings) = map.get("settings") {
                    object(settings, &["udp"])?;
                    if settings["udp"] != true {
                        return Err(rejected());
                    }
                }
            }
            "http" if !map.contains_key("settings") => {}
            _ => return Err(rejected()),
        }
    }
    let outbounds = root
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(rejected)?;
    if outbounds.len() < 2 || outbounds.len() > 64 {
        return Err(rejected());
    }
    // Tags the daemon injects itself; a client-supplied one would collide
    // (or smuggle a fake API/blackhole handler).
    const RESERVED_TAGS: [&str; 4] = ["api", "api-in", "tun-in", "unavailable"];
    let mut tags = HashSet::new();
    let mut proxies = 0usize;
    let mut freedom = false;
    for outbound in outbounds.iter() {
        let map = object(
            outbound,
            &["tag", "protocol", "settings", "streamSettings", "mux"],
        )?;
        let tag = string(&outbound["tag"])?;
        if !tags.insert(tag.to_string()) {
            return Err(rejected());
        }
        if RESERVED_TAGS.contains(&tag) || tag.starts_with("probe-") {
            return Err(rejected());
        }
        // `node-`/`pin-` tags carry a stable endpoint key and only appear
        // on multinode configs; any other suffix is malformed.
        for prefix in ["node-", "pin-"] {
            if tag.starts_with(prefix) && !valid_node_key(&tag[prefix.len()..]) {
                return Err(rejected());
            }
        }
        if let Some(mux) = map.get("mux") {
            validate_mux(mux)?;
        }
        match string(&outbound["protocol"])? {
            "vless" => {
                proxies += 1;
                let settings = object(&outbound["settings"], &["vnext"])?;
                let server = one(settings.get("vnext").ok_or_else(rejected)?)?;
                object(server, &["address", "port", "users"])?;
                string(&server["address"])?;
                port(&server["port"])?;
                let user = one(&server["users"])?;
                object(user, &["id", "encryption", "flow"])?;
                string(&user["id"])?;
                if user["encryption"] != "none" {
                    return Err(rejected());
                }
                // Panels emit `"flow": ""` for non-vision endpoints; only the
                // known XTLS flow names besides empty are accepted.
                if let Some(flow) = user.get("flow") {
                    let flow = flow.as_str().ok_or_else(rejected)?;
                    if !flow.is_empty()
                        && !matches!(flow, "xtls-rprx-vision" | "xtls-rprx-vision-udp443")
                    {
                        return Err(rejected());
                    }
                }
                validate_vless_stream(&outbound["streamSettings"])?;
            }
            "hysteria" => {
                proxies += 1;
                object(&outbound["settings"], &["version", "address", "port"])?;
                if outbound["settings"]["version"] != 2 {
                    return Err(rejected());
                }
                string(&outbound["settings"]["address"])?;
                port(&outbound["settings"]["port"])?;
                validate_hysteria_stream(&outbound["streamSettings"])?;
            }
            "freedom" => {
                freedom = true;
                validate_auxiliary(outbound, map)?;
            }
            "blackhole" | "dns" => {
                validate_auxiliary(outbound, map)?;
            }
            _ => return Err(rejected()),
        }
    }
    if proxies == 0 || !freedom {
        return Err(rejected());
    }

    let routing = object(
        &config["routing"],
        &["domainStrategy", "domainMatcher", "rules", "balancers"],
    )?;
    // The only balancer this daemon runs: `failover`, initially selecting
    // nothing but the `unavailable` blackhole (the override that pins a
    // real node is installed by the probe supervisor at runtime).
    if let Some(balancers) = routing.get("balancers") {
        let balancers = balancers.as_array().ok_or_else(rejected)?;
        if balancers.len() != 1 {
            return Err(rejected());
        }
        let balancer = object(&balancers[0], &["tag", "selector"])?;
        if string(&balancer["tag"])? != "failover" {
            return Err(rejected());
        }
        let selector = balancer["selector"].as_array().ok_or_else(rejected)?;
        if selector.len() != 1 || selector[0] != "unavailable" {
            return Err(rejected());
        }
    }
    if let Some(strategy) = routing.get("domainStrategy") {
        if !matches!(
            strategy.as_str(),
            Some("AsIs" | "IPIfNonMatch" | "IPOnDemand")
        ) {
            return Err(rejected());
        }
    }
    if let Some(matcher) = routing.get("domainMatcher") {
        if !matches!(matcher.as_str(), Some("mph" | "hybrid" | "linear")) {
            return Err(rejected());
        }
    }
    let rules = config["routing"]["rules"].as_array().ok_or_else(rejected)?;
    if rules.len() > 64 {
        return Err(rejected());
    }
    for rule in rules {
        object(
            rule,
            &[
                "type",
                "domain",
                "ip",
                "port",
                "network",
                "outboundTag",
                "balancerTag",
                "inboundTag",
            ],
        )?;
        // `type` is optional in panel exports; Xray treats a missing type as
        // "field". Whatever is present must still be the field kind.
        if let Some(kind) = rule.get("type") {
            if kind != "field" {
                return Err(rejected());
            }
        }
        match (rule.get("outboundTag"), rule.get("balancerTag")) {
            (Some(outbound), None) => {
                if !tags.contains(string(outbound)?) {
                    return Err(rejected());
                }
            }
            // The only balancer a generated config may target.
            (None, Some(balancer)) => {
                if string(balancer)? != "failover" {
                    return Err(rejected());
                }
            }
            _ => return Err(rejected()),
        }
        if let Some(inbound_tag) = rule.get("inboundTag") {
            let items = inbound_tag.as_array().ok_or_else(rejected)?;
            if items.is_empty() || items.len() > 8 {
                return Err(rejected());
            }
            for item in items {
                let item = string(item)?;
                if item.len() > 64 {
                    return Err(rejected());
                }
            }
        }
        if let Some(rule_port) = rule.get("port") {
            match rule_port {
                Value::String(list) => {
                    if list.len() > 128
                        || !list.split(',').all(|item| {
                            let mut bounds = item.splitn(2, '-');
                            bounds.all(|bound| bound.parse::<u16>().is_ok() && bound.len() <= 5)
                        })
                    {
                        return Err(rejected());
                    }
                }
                Value::Number(_) => port(rule_port)?,
                _ => return Err(rejected()),
            }
        }
        if let Some(network) = rule.get("network") {
            if !matches!(network.as_str(), Some("tcp" | "udp" | "tcp,udp")) {
                return Err(rejected());
            }
        }
        for key in ["domain", "ip"] {
            if let Some(items) = rule.get(key) {
                let items = items.as_array().ok_or_else(rejected)?;
                if items.is_empty() || items.len() > 128 {
                    return Err(rejected());
                }
                for item in items {
                    routing_selector(key, string(item)?)?;
                }
            }
        }
    }
    Ok(())
}

/// `node-`/`pin-` tag suffixes are endpoint keys: exactly 16 lowercase hex.
fn valid_node_key(key: &str) -> bool {
    key.len() == 16
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Auxiliary outbounds cannot open listeners; their settings only shape
/// outbound behaviour, so validate the emitted inner shapes rather than
/// forbid them outright.
fn validate_auxiliary(outbound: &Value, map: &Map<String, Value>) -> io::Result<()> {
    if let Some(settings) = map.get("settings") {
        validate_auxiliary_settings(string(&outbound["protocol"]).unwrap_or_default(), settings)?;
    }
    if let Some(stream) = map.get("streamSettings") {
        validate_auxiliary_stream(stream)?;
    }
    Ok(())
}

/// The generated `dns` section: resolver entries may be bare address strings
/// or `{address, port, domains, skipFallback}` objects; hosts map names to
/// one or more literal addresses.
fn validate_dns(dns: &Value) -> io::Result<()> {
    let dns = object(
        dns,
        &[
            "hosts",
            "servers",
            "queryStrategy",
            "tag",
            "enableParallelQuery",
            "disableCache",
            "serveStale",
            "clientIp",
        ],
    )?;
    if let Some(query) = dns.get("queryStrategy") {
        string(query)?;
    }
    for key in ["tag", "clientIp"] {
        if let Some(value) = dns.get(key) {
            string(value)?;
        }
    }
    for key in ["enableParallelQuery", "disableCache", "serveStale"] {
        if let Some(value) = dns.get(key) {
            if !value.is_boolean() {
                return Err(rejected());
            }
        }
    }
    if let Some(hosts) = dns.get("hosts") {
        let hosts = hosts.as_object().ok_or_else(rejected)?;
        if hosts.len() > 128 {
            return Err(rejected());
        }
        for (name, value) in hosts {
            if name.is_empty() || name.len() > 253 {
                return Err(rejected());
            }
            match value {
                Value::String(entry) if !entry.is_empty() && entry.len() <= 256 => {}
                Value::Array(entries) => {
                    if entries.is_empty() || entries.len() > 8 {
                        return Err(rejected());
                    }
                    for entry in entries {
                        string(entry)?;
                    }
                }
                _ => return Err(rejected()),
            }
        }
    }
    if let Some(servers) = dns.get("servers") {
        let servers = servers.as_array().ok_or_else(rejected)?;
        if servers.is_empty() || servers.len() > 16 {
            return Err(rejected());
        }
        for server in servers {
            match server {
                Value::String(address) => {
                    if address.is_empty() || address.len() > 256 {
                        return Err(rejected());
                    }
                }
                Value::Object(_) => {
                    let entry = object(
                        server,
                        &[
                            "address",
                            "port",
                            "domains",
                            "skipFallback",
                            "queryStrategy",
                        ],
                    )?;
                    string(&entry["address"])?;
                    if let Some(server_port) = entry.get("port") {
                        port(server_port)?;
                    }
                    if let Some(domains) = entry.get("domains") {
                        let domains = domains.as_array().ok_or_else(rejected)?;
                        if domains.is_empty() || domains.len() > 64 {
                            return Err(rejected());
                        }
                        for domain in domains {
                            string(domain)?;
                        }
                    }
                    if let Some(skip) = entry.get("skipFallback") {
                        if !skip.is_boolean() {
                            return Err(rejected());
                        }
                    }
                    if let Some(query) = entry.get("queryStrategy") {
                        string(query)?;
                    }
                }
                _ => return Err(rejected()),
            }
        }
    }
    Ok(())
}

fn validate_fakedns(fakedns: &Value) -> io::Result<()> {
    let pools = fakedns.as_array().ok_or_else(rejected)?;
    if pools.is_empty() || pools.len() > 4 {
        return Err(rejected());
    }
    for pool in pools {
        let pool = object(pool, &["ipPool", "poolSize"])?;
        let cidr = string(&pool["ipPool"])?;
        if cidr.parse::<ipnet::IpNet>().is_err() {
            return Err(rejected());
        }
        if pool["poolSize"]
            .as_u64()
            .is_none_or(|size| size == 0 || size > 65535)
        {
            return Err(rejected());
        }
    }
    Ok(())
}

/// Inbound `sniffing` blocks generated or imported by the app: enable flag,
/// destOverride/metatada lists, and boolean modifiers only.
fn validate_sniffing(sniffing: &Value) -> io::Result<()> {
    let map = object(
        sniffing,
        &[
            "enabled",
            "destOverride",
            "routeOnly",
            "metadataOnly",
            "domainsExcluded",
        ],
    )?;
    for key in ["enabled", "routeOnly", "metadataOnly"] {
        if let Some(value) = map.get(key) {
            if !value.is_boolean() {
                return Err(rejected());
            }
        }
    }
    for key in ["destOverride", "domainsExcluded"] {
        if let Some(list) = map.get(key) {
            let list = list.as_array().ok_or_else(rejected)?;
            if list.len() > 8 {
                return Err(rejected());
            }
            for item in list {
                let item = string(item)?;
                if item.len() > 64 {
                    return Err(rejected());
                }
            }
        }
    }
    Ok(())
}

/// `mux` multiplexing options on a proxy outbound.
fn validate_mux(mux: &Value) -> io::Result<()> {
    let map = object(
        mux,
        &[
            "enabled",
            "concurrency",
            "xudpConcurrency",
            "xudpProxyUDP443",
        ],
    )?;
    if let Some(enabled) = map.get("enabled") {
        if !enabled.is_boolean() {
            return Err(rejected());
        }
    }
    for key in ["concurrency", "xudpConcurrency"] {
        if let Some(value) = map.get(key) {
            if !value.as_i64().is_some_and(|n| (1..=1024).contains(&n)) {
                return Err(rejected());
            }
        }
    }
    if let Some(policy) = map.get("xudpProxyUDP443") {
        let policy = string(policy)?;
        if policy.len() > 64 {
            return Err(rejected());
        }
    }
    Ok(())
}

/// `tcpSettings.header` masquerade — only the shape emitted by the generator.
fn validate_tcp_settings(tcp: &Value) -> io::Result<()> {
    let map = object(tcp, &["header"])?;
    if let Some(header) = map.get("header") {
        let header = object(header, &["type"])?;
        string(&header["type"])?;
    }
    Ok(())
}

/// `streamSettings.sockopt` — kernel knobs and dialer chaining. `mark` is
/// written by the daemon itself; callers may set the rest.
fn validate_sockopt(sockopt: &Value) -> io::Result<()> {
    let map = object(
        sockopt,
        &[
            "mark",
            "dialerProxy",
            "domainStrategy",
            "tcpFastOpen",
            "tproxy",
            "tcpKeepAliveInterval",
            "tcpKeepAliveIdle",
            "tcpUserTimeout",
            "tcpcongestion",
            "interface",
            "V6Only",
            "tcpWindowClamp",
            "tcpMptcp",
            "tcpNoDelay",
        ],
    )?;
    for (key, value) in map {
        match key.as_str() {
            "mark" | "tcpKeepAliveInterval" | "tcpKeepAliveIdle" | "tcpWindowClamp" => {
                value
                    .as_u64()
                    .filter(|n| *n <= u32::MAX as u64)
                    .ok_or_else(rejected)?;
            }
            // `TCP_USER_TIMEOUT` is milliseconds; bound it to an hour so a
            // generated config cannot stall dead-stream detection for days.
            "tcpUserTimeout" => {
                value
                    .as_u64()
                    .filter(|n| *n <= 3_600_000)
                    .ok_or_else(rejected)?;
            }
            "tcpFastOpen" | "V6Only" | "tcpMptcp" | "tcpNoDelay" => {
                value.as_bool().ok_or_else(rejected)?;
            }
            "tproxy" => {
                if !matches!(value.as_str(), Some("off" | "redirect" | "tproxy")) {
                    return Err(rejected());
                }
            }
            _ => {
                string(value)?;
            }
        }
    }
    Ok(())
}

/// `settings` on freedom/blackhole/dns outbounds — none of them can open a
/// listener, so validating the emitted key shapes keeps the allowlist honest
/// without shrinking the importer's vocabulary.
fn validate_auxiliary_settings(protocol: &str, settings: &Value) -> io::Result<()> {
    match protocol {
        "freedom" => {
            let map = object(
                settings,
                &[
                    "domainStrategy",
                    "redirect",
                    "timeout",
                    "userLevel",
                    "fragment",
                ],
            )?;
            for (key, value) in map {
                match key.as_str() {
                    "timeout" | "userLevel" => {
                        value.as_u64().ok_or_else(rejected)?;
                    }
                    "fragment" => {
                        object(value, &["packets", "length", "interval"])?;
                    }
                    _ => {
                        string(value)?;
                    }
                }
            }
        }
        "blackhole" => {
            let map = object(settings, &["response"])?;
            if let Some(response) = map.get("response") {
                let response = object(response, &["type"])?;
                string(&response["type"])?;
            }
        }
        "dns" => {
            // Covers both vanilla Xray dns fields and the panel/fork
            // rewrite table (`rewriteAddress`/`rewriteNetwork`/`rewritePort`
            // plus `rules` with action/qType/rCode filters).
            let map = object(
                settings,
                &[
                    "address",
                    "port",
                    "network",
                    "userLevel",
                    "nonIPQuery",
                    "blockTypes",
                    "skipFallback",
                    "queryStrategy",
                    "rewriteAddress",
                    "rewriteNetwork",
                    "rewritePort",
                    "rules",
                ],
            )?;
            for (key, value) in map {
                match key.as_str() {
                    "port" => port(value)?,
                    "userLevel" | "rewritePort" => {
                        value.as_u64().ok_or_else(rejected)?;
                    }
                    "skipFallback" => {
                        value.as_bool().ok_or_else(rejected)?;
                    }
                    "blockTypes" => {
                        let items = value.as_array().ok_or_else(rejected)?;
                        if items.is_empty() || items.len() > 16 {
                            return Err(rejected());
                        }
                        for item in items {
                            value_u64(item)?;
                        }
                    }
                    "rules" => {
                        let rules = value.as_array().ok_or_else(rejected)?;
                        if rules.is_empty() || rules.len() > 64 {
                            return Err(rejected());
                        }
                        for rule in rules {
                            validate_dns_rewrite_rule(rule)?;
                        }
                    }
                    _ => {
                        string(value)?;
                    }
                }
            }
        }
        _ => return Err(rejected()),
    }
    Ok(())
}

fn validate_dns_rewrite_rule(rule: &Value) -> io::Result<()> {
    let map = object(rule, &["action", "qType", "rCode", "domain", "domains"])?;
    if let Some(action) = map.get("action") {
        let action = string(action)?;
        if !matches!(action, "return" | "hijack" | "direct" | "drop") {
            return Err(rejected());
        }
    }
    if let Some(qtype) = map.get("qType") {
        let qtype = string(qtype)?;
        if qtype.len() > 128
            || !qtype
                .split(',')
                .all(|item| !item.is_empty() && item.parse::<u16>().is_ok())
        {
            return Err(rejected());
        }
    }
    if let Some(rcode) = map.get("rCode") {
        value_u64(rcode)?;
    }
    for key in ["domain", "domains"] {
        if let Some(list) = map.get(key) {
            let list = list.as_array().ok_or_else(rejected)?;
            if list.is_empty() || list.len() > 128 {
                return Err(rejected());
            }
            for item in list {
                routing_selector("domain", string(item)?)?;
            }
        }
    }
    Ok(())
}

fn value_u64(value: &Value) -> io::Result<()> {
    if value.as_u64().is_some() {
        Ok(())
    } else {
        Err(rejected())
    }
}

/// `streamSettings` on auxiliary outbounds: transport extras only — sockopt
/// for fwmark/dialer chaining, tcpSettings for masquerade headers.
fn validate_auxiliary_stream(stream: &Value) -> io::Result<()> {
    let map = object(stream, &["network", "security", "tcpSettings", "sockopt"])?;
    for key in ["network", "security"] {
        if let Some(value) = map.get(key) {
            string(value)?;
        }
    }
    if let Some(tcp) = map.get("tcpSettings") {
        validate_tcp_settings(tcp)?;
    }
    if let Some(sockopt) = map.get("sockopt") {
        validate_sockopt(sockopt)?;
    }
    Ok(())
}

/// Root Xray resolves `ext:`-style selectors to files next to its assets, so
/// accept only the selector forms the app generates.
fn routing_selector(key: &str, item: &str) -> io::Result<()> {
    let valid = if key == "ip" {
        match item.strip_prefix("geoip:") {
            // Country codes dominate, but profiles may load a custom geoip.dat
            // defining arbitrary categories (e.g. `direct`); Xray resolves the
            // code against the staged asset at start and fails loudly if absent.
            Some(code) => {
                !code.is_empty()
                    && code.len() <= 64
                    && code
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            }
            None => item.parse::<IpAddr>().is_ok() || item.parse::<ipnet::IpNet>().is_ok(),
        }
    } else {
        match item.split_once(':') {
            Some(("geosite", category)) => {
                // `geosite:category@attr` filters on asset attributes (the
                // `*` wildcard is allowed inside the attribute only).
                let mut parts = category.splitn(2, '@');
                let (name, attr) = (parts.next().unwrap_or_default(), parts.next());
                !name.is_empty()
                    && name.len() <= 64
                    && name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'!')
                    })
                    && attr.is_none_or(|attr| {
                        !attr.is_empty()
                            && attr.len() <= 64
                            && attr.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric()
                                    || byte == b'-'
                                    || byte == b'_'
                                    || byte == b'*'
                            })
                    })
            }
            Some(("domain" | "full" | "keyword" | "regexp", value)) => !value.is_empty(),
            Some(_) => false,
            None => !item.contains(['/', '\\']),
        }
    };
    if valid {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn validate_vless_stream(stream: &Value) -> io::Result<()> {
    let map = object(
        stream,
        &[
            "network",
            "security",
            "wsSettings",
            "grpcSettings",
            "xhttpSettings",
            "httpupgradeSettings",
            "tlsSettings",
            "realitySettings",
            "tcpSettings",
            "sockopt",
        ],
    )?;
    if let Some(tcp) = map.get("tcpSettings") {
        validate_tcp_settings(tcp)?;
    }
    if let Some(sockopt) = map.get("sockopt") {
        validate_sockopt(sockopt)?;
    }
    if !matches!(
        stream["network"].as_str(),
        Some("tcp" | "raw" | "ws" | "grpc" | "xhttp" | "httpupgrade")
    ) || !matches!(
        stream["security"].as_str(),
        Some("none" | "tls" | "reality")
    ) {
        return Err(rejected());
    }
    for (key, allowed) in [
        ("wsSettings", &["path", "headers"][..]),
        ("grpcSettings", &["serviceName"][..]),
        ("xhttpSettings", &["path", "host"][..]),
        ("httpupgradeSettings", &["path", "host"][..]),
        ("tlsSettings", &["serverName", "fingerprint", "alpn"][..]),
        (
            "realitySettings",
            &[
                "serverName",
                "fingerprint",
                "publicKey",
                "shortId",
                "spiderX",
            ][..],
        ),
    ] {
        if let Some(value) = stream.get(key) {
            let map = object(value, allowed)?;
            for (field, value) in map {
                if key == "wsSettings" && field == "headers" {
                    object(value, &["Host"])?;
                    string(&value["Host"])?;
                } else if key == "tlsSettings" && field == "alpn" {
                    let items = value.as_array().ok_or_else(rejected)?;
                    if items.is_empty() || items.len() > 8 {
                        return Err(rejected());
                    }
                    for item in items {
                        string(item)?;
                    }
                } else {
                    maybe_string(value)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_hysteria_stream(stream: &Value) -> io::Result<()> {
    object(
        stream,
        &[
            "network",
            "security",
            "tlsSettings",
            "hysteriaSettings",
            "finalmask",
        ],
    )?;
    if stream["network"] != "hysteria" || stream["security"] != "tls" {
        return Err(rejected());
    }
    let tls = object(
        &stream["tlsSettings"],
        &["serverName", "pinnedPeerCertSha256"],
    )?;
    for value in tls.values() {
        string(value)?;
    }
    object(&stream["hysteriaSettings"], &["version", "auth"])?;
    if stream["hysteriaSettings"]["version"] != 2 {
        return Err(rejected());
    }
    string(&stream["hysteriaSettings"]["auth"])?;
    if let Some(mask) = stream.get("finalmask") {
        object(mask, &["udp", "quicParams"])?;
        if let Some(udp) = mask.get("udp") {
            let item = one(udp)?;
            object(item, &["type", "settings"])?;
            if item["type"] != "salamander" {
                return Err(rejected());
            }
            object(&item["settings"], &["password"])?;
            string(&item["settings"]["password"])?;
        }
        if let Some(quic) = mask.get("quicParams") {
            object(quic, &["udpHop"])?;
            object(&quic["udpHop"], &["ports"])?;
            string(&quic["udpHop"]["ports"])?;
        }
    }
    Ok(())
}

pub fn prepare_xray(uid: u32, params: XrayConnectParams, mark: u32) -> io::Result<XrayPlan> {
    validate_owner(&format!("xray:{}", params.profile_id)).map_err(|_| rejected())?;
    if mark == 0
        || params.config.len() > MAX_XRAY_CONFIG_BYTES
        || params.routes.len() > 64
        || params.dns_servers.len() > 8
        || params.dns_domains.len() > 16
    {
        return Err(rejected());
    }
    net_manager_core::service_checks::validate_service_checks(&params.service_checks)?;
    let mut seen = HashSet::new();
    for route in &params.routes {
        if route.via.is_some()
            || route.destination.trunc() != route.destination
            || !seen.insert(route.destination)
        {
            return Err(rejected());
        }
    }
    if params
        .dns_servers
        .iter()
        .any(|ip| ip.is_unspecified() || ip.is_multicast())
        || (!params.dns_domains.is_empty() && params.dns_servers.is_empty())
        || params.dns_domains.iter().any(|domain| {
            domain.is_empty() || domain.len() > 253 || domain.chars().any(char::is_control)
        })
        || params.dns_bypass.len() > 16
        || params.dns_bypass.iter().any(|host| {
            host.is_empty()
                || host.len() > 253
                || host
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '@' | '%'))
        })
    {
        return Err(rejected());
    }
    // Both the single default route and its def1 halves mean the family is
    // fully captured; the halves live in the same tunnel table.
    let net = |network: &str| network.parse::<ipnet::IpNet>().unwrap();
    let full_ipv4 = seen.contains(&net("0.0.0.0/0"))
        || (seen.contains(&net("0.0.0.0/1")) && seen.contains(&net("128.0.0.0/1")));
    let full_ipv6 = seen.contains(&net("::/0"))
        || (seen.contains(&net("::/1")) && seen.contains(&net("8000::/1")));
    let (covers_ipv4, covers_ipv6) = full_coverage(params.routes.iter().map(|r| r.destination));
    if (covers_ipv4 && !full_ipv4) || (covers_ipv6 && !full_ipv6) {
        return Err(rejected());
    }
    for server in &params.dns_servers {
        if !params
            .routes
            .iter()
            .any(|route| route.destination.contains(server))
        {
            return Err(rejected());
        }
    }
    let mut config: Value = serde_json::from_str(&params.config).map_err(|_| rejected())?;
    validate_generated(&config)?;
    let proxy_exits = crate::proxy_exits::bindings(&params.proxy_exits, &config)?;
    let failover = params
        .failover
        .as_ref()
        .map(|f| validate_failover(f, &config));
    let failover = match failover {
        Some(Ok(params)) => Some(params),
        Some(Err(err)) => return Err(err),
        None => None,
    };
    // Upstream host of every proxy outbound: each candidate node needs its
    // own bypass route (the failover target changes at runtime).
    let mut server_hosts: Vec<String> = Vec::new();
    for outbound in config["outbounds"].as_array().ok_or_else(rejected)? {
        let host = match outbound["protocol"].as_str() {
            Some("vless") => outbound["settings"]["vnext"][0]["address"].as_str(),
            Some("hysteria") => outbound["settings"]["address"].as_str(),
            _ => None,
        };
        if let Some(host) = host {
            if !server_hosts.iter().any(|known| known == host) {
                server_hosts.push(host.to_owned());
            }
        }
    }
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in uid.to_le_bytes().iter().chain(params.profile_id.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let (name, _) = crate::link_names::tunnel_link_names(
        "xray-",
        uid,
        &params.profile_id,
        params.interface_name.as_deref(),
    );
    // Build an address within 198.18.0.0/15 without accepting a caller IP.
    let host = (hash as u32) & 0x1ffff;
    let address: ipnet::IpNet = format!(
        "198.{}.{}.{}/32",
        18 + (host >> 16),
        (host >> 8) & 255,
        host & 255
    )
    .parse()
    .map_err(|_| rejected())?;
    let mtu = params.mtu.unwrap_or(1500);
    if !(1280..=9000).contains(&mtu) {
        return Err(rejected());
    }
    let probe_url = params
        .probe_url
        .as_deref()
        .map(crate::watchdog::checked_probe_url)
        .transpose()?;
    if proxy_exits.iter().any(|exit| {
        matches!(
            exit.target,
            net_manager_core::models::ProxyTarget::Pool { .. }
        )
    }) && probe_url.is_none()
        && failover.is_none()
    {
        return Err(rejected());
    }
    let pinned_keys: Vec<String> = config["outbounds"]
        .as_array()
        .ok_or_else(rejected)?
        .iter()
        .filter(|outbound| matches!(outbound["protocol"].as_str(), Some("vless" | "hysteria")))
        .filter_map(|outbound| {
            outbound["tag"]
                .as_str()?
                .strip_prefix("pin-")
                .map(str::to_owned)
        })
        .collect();
    if pinned_keys.len() > 33 {
        return Err(rejected());
    }
    let mut dest_override = vec!["http", "tls", "quic"];
    // Fake-IP answers need the sniffing stage to keep the fake destination so
    // routing can match it against domain policies.
    if config["fakedns"]
        .as_array()
        .is_some_and(|pools| !pools.is_empty())
    {
        dest_override.push("fakedns");
    }
    // Caller inbounds are loopback socks/http listeners that a TUN tunnel
    // replaces wholesale. The extra `api-in` dokodemo door feeds the local
    // StatsService/RoutingService; it never leaves loopback. Each failover
    // node gets its own loopback SOCKS inbound so a probe's health path
    // really traverses that node.
    let api_port = xray_api_port(mark);
    let mut inbounds = vec![
        json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": { "name": name, "mtu": mtu },
            // TUN traffic arrives as bare IP packets; sniffing recovers the TLS
            // SNI / HTTP Host so domain and geosite routing rules can match.
            "sniffing": { "enabled": true, "destOverride": dest_override },
        }),
        json!({
            "tag": "api-in",
            "protocol": "dokodemo-door",
            "listen": "127.0.0.1",
            "port": api_port,
            "settings": { "address": "127.0.0.1" },
        }),
    ];
    if let Some(failover) = &failover {
        for (index, node) in failover.nodes.iter().enumerate() {
            inbounds.push(json!({
                "tag": format!("probe-{}", node.key),
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": xray_probe_port(mark, index),
            }));
        }
    }
    for (index, key) in pinned_keys.iter().enumerate() {
        inbounds.push(json!({
            "tag": format!("pin-probe-{key}"),
            "protocol": "socks", "listen": "127.0.0.1",
            "port": xray_pin_probe_port(mark, index),
        }));
    }
    config["inbounds"] = json!(inbounds);
    config["log"] = json!({"loglevel":"warning"});
    config["stats"] = json!({});
    if config["policy"].is_null() {
        config["policy"] = json!({});
    }
    config["policy"]["system"] = json!({
        "statsInboundUplink": true,
        "statsInboundDownlink": true,
        "statsOutboundUplink": true,
        "statsOutboundDownlink": true,
    });
    let services = if failover.is_some()
        || proxy_exits.iter().any(|exit| {
            matches!(
                exit.target,
                net_manager_core::models::ProxyTarget::Pool { .. }
            )
        }) {
        vec!["StatsService", "RoutingService"]
    } else {
        vec!["StatsService"]
    };
    config["api"] = json!({"tag": "api", "services": services});
    {
        let rules = config["routing"]["rules"]
            .as_array_mut()
            .ok_or_else(rejected)?;
        // Control and probe traffic must win over every user rule, including
        // the failover catch-all; otherwise a fresh tunnel cannot probe or
        // install its first override.
        let api_rule = json!({"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"});
        let probe_rules = failover
            .iter()
            .flat_map(|plan| plan.nodes.iter())
            .map(|node| {
                json!({
                    "type": "field",
                    "inboundTag": [format!("probe-{}", node.key)],
                    "outboundTag": net_manager_core::xray::node_tag(&node.key),
                })
            });
        let pin_rules = pinned_keys.iter().map(|key| {
            json!({
                "type":"field", "inboundTag":[format!("pin-probe-{key}")],
                "outboundTag":net_manager_core::xray::pin_tag(key),
            })
        });
        rules.splice(
            0..0,
            std::iter::once(api_rule)
                .chain(probe_rules)
                .chain(pin_rules),
        );
        if failover.is_some() {
            // Everything that matched no rule goes through the failover
            // balancer; the probe supervisor pins it to the first healthy
            // node or the `unavailable` blackhole — never direct.
            rules.push(json!({
                "type": "field",
                "network": "tcp,udp",
                "balancerTag": net_manager_core::xray::FAILOVER_BALANCER,
            }));
        }
    }
    if failover.is_some() {
        config["outbounds"]
            .as_array_mut()
            .ok_or_else(rejected)?
            .push(json!({
                "tag": net_manager_core::xray::UNAVAILABLE_TAG,
                "protocol": "blackhole",
            }));
    }
    crate::proxy_exits::inject(&mut config, &proxy_exits, mark)?;
    for outbound in config["outbounds"].as_array_mut().ok_or_else(rejected)? {
        if outbound["protocol"] != "blackhole" {
            if outbound["streamSettings"].is_null() {
                outbound["streamSettings"] = json!({});
            }
            let stream = outbound["streamSettings"]
                .as_object_mut()
                .ok_or_else(rejected)?;
            // Imported configs may already carry sockopt knobs (dialerProxy
            // chains the dns outbound through the proxy, domainStrategy
            // pins the address family) — merge the daemon mark instead of
            // replacing the object.
            match stream.entry("sockopt").or_insert_with(|| json!({})) {
                Value::Object(sockopt) => {
                    sockopt.insert("mark".into(), json!(mark));
                }
                _ => return Err(rejected()),
            }
        }
    }
    Ok(XrayPlan {
        profile_id: params.profile_id,
        name,
        config: serde_json::to_string(&config).map_err(|_| rejected())?,
        routes: params.routes,
        address,
        mtu,
        dns_servers: params.dns_servers,
        dns_domains: params.dns_domains,
        dns_bypass: params.dns_bypass,
        full_ipv4,
        full_ipv6,
        mark,
        api_port,
        server_hosts,
        unpinned_hosts: Vec::new(),
        server_pinned: false,
        failover,
        reject_quic: params.reject_quic,
        probe_url,
        pinned_keys,
        service_checks: params.service_checks,
        proxy_exits,
        geo_assets: params.geo_assets,
    })
}

/// Check the failover params against a validated config: every declared
/// candidate owns a `node-<key>` outbound, no `node-` outbound goes
/// undeclared (it would sit outside the supervisor's health tracking), and
/// the probe URL stays inside the HTTPS-probe contract.
fn validate_failover(
    failover: &net_manager_core::daemon_protocol::XrayFailoverParams,
    config: &Value,
) -> io::Result<net_manager_core::daemon_protocol::XrayFailoverParams> {
    let nodes = &failover.nodes;
    if nodes.is_empty() || nodes.len() > net_manager_core::subscription::MAX_FAILOVER_NODES {
        return Err(rejected());
    }
    let mut keys = HashSet::new();
    for node in nodes {
        if !valid_node_key(&node.key) || !keys.insert(node.key.as_str()) {
            return Err(rejected());
        }
    }
    if !valid_node_key(&failover.primary_key) || failover.primary_key != nodes[0].key {
        return Err(rejected());
    }
    let tags: HashSet<&str> = config["outbounds"]
        .as_array()
        .ok_or_else(rejected)?
        .iter()
        .filter_map(|outbound| outbound["tag"].as_str())
        .collect();
    for node in nodes {
        if !tags.contains(net_manager_core::xray::node_tag(&node.key).as_str()) {
            return Err(rejected());
        }
    }
    for tag in &tags {
        if let Some(key) = tag.strip_prefix("node-") {
            if !keys.contains(key) {
                return Err(rejected());
            }
        }
    }
    let probe = crate::watchdog::checked_probe_url(failover.probe_url.trim())?;
    if !(1..=300).contains(&failover.interval_secs) {
        return Err(rejected());
    }
    let mut checked = failover.clone();
    checked.probe_url = probe;
    Ok(checked)
}

impl XrayPlan {
    /// Resolver addresses that get a direct host route (see
    /// [`dns_bypass_addrs`]). They only exist so the system resolver can look
    /// up the server's name outside the tunnel; once the server is dialled by
    /// IP the queries belong inside the tunnel, and a bypass would send them
    /// to a resolver the uplink may not allow.
    pub fn dns_server_bypass(&self) -> Vec<IpAddr> {
        if self.server_pinned {
            return Vec::new();
        }
        dns_bypass_addrs(&self.dns_servers, self.full_ipv4, self.full_ipv6)
    }
}
/// Makes every proxy outbound dial its server by IP instead of by name.
///
/// Xray re-resolves a name through the system resolver whenever it
/// reconnects, and by then the resolver points into the tunnel that is
/// waiting for that very connection. `resolve` runs while the physical
/// uplink is still intact — once per distinct hostname, applied to every
/// `node-`/`pin-` outbound that uses it. The name stays the TLS/Reality
/// server name unless the config sets one. A name that does not resolve,
/// or a transport that derives a Host header or authority from the address
/// (ws, grpc, xhttp, ...), is left untouched and reported in
/// `unpinned_hosts`.
pub fn pin_server_addresses(plan: &mut XrayPlan, resolve: impl Fn(&str) -> Vec<IpAddr>) {
    let Ok(mut config) = serde_json::from_str::<Value>(&plan.config) else {
        return;
    };
    let Some(outbounds) = config["outbounds"].as_array_mut() else {
        return;
    };
    let mut resolved: std::collections::HashMap<String, Option<IpAddr>> = Default::default();
    let mut unpinned: Vec<String> = Vec::new();
    let mut all_pinned = true;
    for outbound in outbounds.iter_mut() {
        let host = match outbound["protocol"].as_str() {
            Some("vless") => outbound["settings"]["vnext"][0]["address"].as_str(),
            Some("hysteria") => outbound["settings"]["address"].as_str(),
            _ => None,
        };
        let Some(host) = host.map(str::to_string) else {
            continue;
        };
        if host.parse::<IpAddr>().is_ok() {
            continue;
        }
        let carries_name = matches!(
            outbound["streamSettings"]["network"].as_str(),
            None | Some("tcp" | "raw" | "hysteria" | "kcp")
        );
        let address = if carries_name {
            resolved
                .entry(host.clone())
                .or_insert_with(|| {
                    let addresses = resolve(&host);
                    addresses
                        .iter()
                        .copied()
                        .find(|ip| ip.is_ipv4())
                        .or_else(|| addresses.first().copied())
                })
                .to_owned()
        } else {
            None
        };
        let Some(address) = address else {
            all_pinned = false;
            if !unpinned.iter().any(|known| known == &host) {
                unpinned.push(host);
            }
            continue;
        };
        let slot = match outbound["protocol"].as_str() {
            Some("vless") => &mut outbound["settings"]["vnext"][0]["address"],
            Some("hysteria") => &mut outbound["settings"]["address"],
            _ => continue,
        };
        *slot = json!(address.to_string());
        for security in ["tlsSettings", "realitySettings"] {
            if let Some(settings) = outbound["streamSettings"][security].as_object_mut() {
                settings
                    .entry("serverName")
                    .or_insert_with(|| json!(host.clone()));
            }
        }
    }
    plan.server_hosts = outbounds
        .iter()
        .filter_map(|outbound| {
            match outbound["protocol"].as_str() {
                Some("vless") => outbound["settings"]["vnext"][0]["address"].as_str(),
                Some("hysteria") => outbound["settings"]["address"].as_str(),
                _ => None,
            }
            .map(str::to_owned)
        })
        .collect();
    let Ok(text) = serde_json::to_string(&config) else {
        return;
    };
    plan.config = text;
    plan.unpinned_hosts = unpinned;
    plan.server_pinned = all_pinned;
}

/// Loopback port of the `probe-<key>` SOCKS inbound for failover node
/// `index` (0-based, same order as `failover.nodes`). The range sits one
/// hundred ports above the per-slot `api-in` listener so tunnels never
/// collide; `MAX_FAILOVER_NODES` keeps it inside the slot stride.
pub fn xray_probe_port(mark: u32, index: usize) -> u16 {
    u16::try_from(
        PROBE_PORT_BASE + mark.saturating_sub(POLICY_MARK_BASE).min(127) * 8 + index.min(7) as u32,
    )
    .unwrap_or(PROBE_PORT_BASE as u16)
}

/// Per-tunnel probe listeners take an 8-port stride per policy slot, in a
/// range disjoint from `API_PORT_BASE` (api port + slot is shared across
/// tunnels by design? no — one slot per tunnel; stride keeps indexes apart).
const PROBE_PORT_BASE: u32 = 11185;

/// Loopback port of the per-tunnel `api-in` listener, derived from the
/// policy-routing slot so concurrently running tunnels never collide and a
/// reload keeps the same endpoint.
pub fn xray_api_port(mark: u32) -> u16 {
    u16::try_from(API_PORT_BASE + mark.saturating_sub(POLICY_MARK_BASE).min(127))
        .unwrap_or(API_PORT_BASE as u16)
}

pub fn xray_pin_probe_port(mark: u32, index: usize) -> u16 {
    (13_000 + mark.saturating_sub(POLICY_MARK_BASE).min(127) * 40 + index.min(32) as u32) as u16
}

/// Policy marks are allocated as `POLICY_MARK_BASE + slot` (0..128 slots); the
/// API listeners take the same slot numbering on loopback.
pub const POLICY_MARK_BASE: u32 = 51820;
const API_PORT_BASE: u32 = 10185;

/// DNS resolvers whose family is fully captured by the tunnel need a direct
/// host route through the physical gateway: without it, resolver queries
/// (e.g. systemd-resolved resolving the VPN server host) re-enter the TUN
/// and loop. Split-tunnel profiles intentionally resolve those servers
/// *inside* the tunnel, so they are bypassed only under full coverage.
pub fn dns_bypass_addrs(dns_servers: &[IpAddr], full_ipv4: bool, full_ipv6: bool) -> Vec<IpAddr> {
    dns_servers
        .iter()
        .copied()
        .filter(|ip| match ip {
            IpAddr::V4(_) => full_ipv4,
            IpAddr::V6(_) => full_ipv6,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::XrayConnectParams;
    use net_manager_core::models::PolicyRoute;
    use serde_json::{json, Value};

    fn params() -> XrayConnectParams {
        XrayConnectParams {
            profile_id: "home".into(),
            config: json!({
                "inbounds": [{"tag":"socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings":{"udp":true}}],
                "outbounds": [
                    {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address":"example.test","port":443,"users":[{"id":"SECRET-UUID","encryption":"none"}]}]}, "streamSettings":{"network":"tcp","security":"none"}},
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "blocked", "protocol": "blackhole"}
                ],
                "routing": {"rules": []}
            }).to_string(),
            routes: vec![PolicyRoute {
                destination: "10.20.0.0/16".parse().unwrap(),
                metric: 5,
                via: None,
            }],
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
            service_checks: Vec::new(),
            proxy_exits: Vec::new(),
        }
    }

    #[test]
    fn plan_replaces_user_inbounds_and_marks_every_dialling_outbound() {
        let plan = prepare_xray(1000, params(), 51820).unwrap();
        assert!(plan.name.starts_with("xray-"));
        assert!(plan.name.len() <= 15);
        // The deterministic hash name is hex-only and stable per (uid, profile).
        assert!(plan.name[5..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(plan.name, prepare_xray(1000, params(), 51820).unwrap().name);
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["protocol"], "tun");
        assert_eq!(inbounds[0]["settings"]["name"], plan.name);
        assert_eq!(inbounds[0]["settings"]["mtu"], 1500);
        assert_eq!(inbounds[1]["protocol"], "dokodemo-door");
        assert_eq!(inbounds[1]["listen"], "127.0.0.1");
        assert_eq!(inbounds[1]["port"], plan.api_port);
        for index in [0, 1] {
            assert_eq!(
                config["outbounds"][index]["streamSettings"]["sockopt"]["mark"],
                51820
            );
        }
        assert!(config["outbounds"][2]["streamSettings"].is_null());
        assert!(!plan.config.contains("\"protocol\":\"socks\""));
        assert!(!format!("{plan:?}").contains("SECRET-UUID"));
    }

    #[test]
    fn plan_extracts_server_host_for_bypass_routes() {
        let plan = prepare_xray(1000, params(), 51820).unwrap();
        assert_eq!(plan.server_hosts, ["example.test"]);

        let mut hysteria = params();
        hysteria.config = json!({
            "inbounds": [{"tag":"socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings":{"udp":true}}],
            "outbounds": [
                {"tag": "proxy", "protocol": "hysteria", "settings": {"version": 2, "address": "hy.example.test", "port": 443}, "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"hy.example.test"},"hysteriaSettings":{"version":2,"auth":"SECRET-PASS"}}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "blocked", "protocol": "blackhole"}
            ],
            "routing": {"rules": []}
        })
        .to_string();
        let plan = prepare_xray(1000, hysteria, 51820).unwrap();
        assert_eq!(plan.server_hosts, ["hy.example.test"]);
        assert!(!format!("{plan:?}").contains("SECRET-PASS"));
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn pinning_replaces_the_server_name_and_keeps_the_sni() {
        let mut plan = prepare_xray(1000, params(), 51820).unwrap();
        // The vless fixture uses plain TCP without TLS: nothing to carry over.
        pin_server_addresses(&mut plan, |_| vec![ip("203.0.113.7")]);
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(
            config["outbounds"][0]["settings"]["vnext"][0]["address"],
            "203.0.113.7"
        );
        assert_eq!(plan.server_hosts, ["203.0.113.7"]);
        assert!(plan.server_pinned);

        let mut hysteria = params();
        hysteria.config = json!({
            "inbounds": [{"tag":"socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings":{"udp":true}}],
            "outbounds": [
                {"tag": "proxy", "protocol": "hysteria", "settings": {"version": 2, "address": "hy.example.test", "port": 443}, "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{},"hysteriaSettings":{"version":2,"auth":"x"}}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "blocked", "protocol": "blackhole"}
            ],
            "routing": {"rules": []}
        })
        .to_string();
        let mut plan = prepare_xray(1000, hysteria, 51820).unwrap();
        pin_server_addresses(&mut plan, |_| vec![ip("2001:db8::1"), ip("203.0.113.9")]);
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(config["outbounds"][0]["settings"]["address"], "203.0.113.9");
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"],
            "hy.example.test"
        );
        assert!(plan.server_pinned);
    }

    #[test]
    fn pinning_never_overrides_an_explicit_server_name() {
        let mut input = params();
        input.config = json!({
            "inbounds": [{"tag":"socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings":{"udp":true}}],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address":"example.test","port":443,"users":[{"id":"u","encryption":"none"}]}]}, "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"front.test"}}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "blocked", "protocol": "blackhole"}
            ],
            "routing": {"rules": []}
        })
        .to_string();
        let mut plan = prepare_xray(1000, input, 51820).unwrap();
        pin_server_addresses(&mut plan, |_| vec![ip("203.0.113.7")]);
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"],
            "front.test"
        );
    }

    #[test]
    fn pinning_leaves_the_name_when_it_cannot_be_resolved_or_carried() {
        let mut plan = prepare_xray(1000, params(), 51820).unwrap();
        let before = plan.config.clone();
        pin_server_addresses(&mut plan, |_| Vec::new());
        assert_eq!(plan.config, before);
        assert_eq!(plan.server_hosts, ["example.test"]);
        assert!(!plan.server_pinned);

        // WebSocket derives its Host header from the address.
        let mut ws = params();
        let mut config: Value = serde_json::from_str(&ws.config).unwrap();
        config["outbounds"][0]["streamSettings"]["network"] = json!("ws");
        ws.config = config.to_string();
        let mut plan = prepare_xray(1000, ws, 51820).unwrap();
        let before = plan.config.clone();
        pin_server_addresses(&mut plan, |_| vec![ip("203.0.113.7")]);
        assert_eq!(plan.config, before);
        assert!(!plan.server_pinned);
    }

    #[test]
    fn a_literal_server_address_counts_as_pinned_without_resolving() {
        let mut input = params();
        let mut config: Value = serde_json::from_str(&input.config).unwrap();
        config["outbounds"][0]["settings"]["vnext"][0]["address"] = json!("203.0.113.7");
        input.config = config.to_string();
        let mut plan = prepare_xray(1000, input, 51820).unwrap();
        pin_server_addresses(&mut plan, |_| panic!("no lookup for a literal address"));
        assert!(plan.server_pinned);
    }

    #[test]
    fn resolvers_are_bypassed_only_while_the_server_must_be_looked_up() {
        let mut plan = prepare_xray(1000, params(), 51820).unwrap();
        plan.dns_servers = vec![ip("1.1.1.1")];
        plan.full_ipv4 = true;
        assert_eq!(plan.dns_server_bypass(), vec![ip("1.1.1.1")]);
        plan.server_pinned = true;
        assert!(plan.dns_server_bypass().is_empty());
    }

    #[test]
    fn dns_bypass_addrs_keeps_only_fully_captured_families() {
        let dns: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        assert_eq!(
            dns_bypass_addrs(&dns, true, false),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(dns_bypass_addrs(&dns, true, true).len(), 2);
        assert!(dns_bypass_addrs(&dns, false, false).is_empty());
    }

    #[test]
    fn plan_names_tun_after_sanitized_interface_hint() {
        let mut hinted = params();
        hinted.interface_name = Some("NL Home!".into());
        let plan = prepare_xray(1000, hinted, 51820).unwrap();
        assert_eq!(plan.name, "xray-nl-home");
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(config["inbounds"][0]["settings"]["name"], "xray-nl-home");
    }

    #[test]
    fn plan_enables_traffic_sniffing_on_the_tun_inbound() {
        let plan = prepare_xray(1000, params(), 51820).unwrap();
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        let sniffing = &config["inbounds"][0]["sniffing"];
        // TUN traffic arrives as bare IP packets; sniffing exposes the TLS/HTTP
        // hostname so domain/geosite routing rules can match.
        assert_eq!(sniffing["enabled"], true);
        assert_eq!(sniffing["destOverride"], json!(["http", "tls", "quic"]));
    }

    #[test]
    fn plan_rejects_untrusted_config_without_echoing_secrets() {
        let mut input = params();
        input.config = "{SECRET-CONFIG".into();
        let err = prepare_xray(1000, input, 51820).unwrap_err();
        assert!(!err.to_string().contains("SECRET-CONFIG"));

        let mut input = params();
        input.config =
            json!({"outbounds":[{"protocol":"freedom","settings":{"redirect":"127.0.0.1:22"}}]})
                .to_string();
        assert!(prepare_xray(1000, input, 51820).is_err());
    }

    #[test]
    fn real_generated_vless_and_hysteria_schemas_are_accepted() {
        for uri in [
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=ws&security=tls&sni=node.test&path=%2Fapi&host=front.test&alpn=h2%2Chttp%2F1.1",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=raw&security=reality&sni=node.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&spx=%2Fcrawl",
            "hy2://password@node.test:443,8443-8444?sni=node.test&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&obfs=salamander&obfs-password=mask",
        ] {
            let generated = net_manager_core::xray::generate_share_link_config(uri, 10808).unwrap();
            let mut input = params();
            input.config = generated.to_string();
            assert!(prepare_xray(1000, input, 51820).is_ok(), "generated schema was rejected");
        }
    }

    #[test]
    fn routing_selectors_cannot_load_arbitrary_asset_files() {
        let with_rule = |rule: Value| {
            let mut config: Value = serde_json::from_str(&params().config).unwrap();
            config["routing"]["rules"] = json!([rule]);
            let mut input = params();
            input.config = config.to_string();
            prepare_xray(1000, input, 51820)
        };
        for rule in [
            json!({"type":"field","domain":["ext:geosite.dat:cn"],"outboundTag":"proxy"}),
            json!({"type":"field","domain":["ext-domain:custom.dat:ads"],"outboundTag":"proxy"}),
            json!({"type":"field","domain":["geosite:../../etc/shadow"],"outboundTag":"proxy"}),
            json!({"type":"field","domain":["../../etc/shadow"],"outboundTag":"proxy"}),
            json!({"type":"field","ip":["ext:../../etc/shadow:tag"],"outboundTag":"direct"}),
            json!({"type":"field","ip":["ext-ip:geoip.dat:cn"],"outboundTag":"direct"}),
            json!({"type":"field","ip":["example.test"],"outboundTag":"direct"}),
        ] {
            assert!(with_rule(rule.clone()).is_err(), "{rule}");
        }
        for rule in [
            json!({"type":"field","domain":["example.com","domain:a.test","full:b.test","keyword:ads","regexp:^c\\.test$","geosite:category-ads_all","geosite:category-ai-chat-!cn"],"outboundTag":"proxy"}),
            json!({"type":"field","ip":["geoip:private","geoip:us","geoip:direct","geoip:custom_cat","10.0.0.0/8","::1/128","192.0.2.1"],"outboundTag":"direct"}),
        ] {
            assert!(with_rule(rule.clone()).is_ok(), "{rule}");
        }
    }

    #[test]
    fn def1_style_route_pair_counts_as_full_coverage() {
        // The split-default halves are full capture, applied through the
        // tunnel table and mark rules like a single default route — never
        // through the main table, where they would capture marked traffic.
        let mut input = params();
        input.routes = ["0.0.0.0/1", "128.0.0.0/1"]
            .into_iter()
            .map(|destination| PolicyRoute {
                destination: destination.parse().unwrap(),
                metric: 5,
                via: None,
            })
            .collect();
        let plan = prepare_xray(1000, input, 51820).unwrap();
        assert!(plan.full_ipv4);
        assert!(!plan.full_ipv6);
    }

    #[test]
    fn noncanonical_full_coverage_cannot_bypass_full_tunnel_marking() {
        let mut input = params();
        input.routes = ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"]
            .into_iter()
            .map(|destination| PolicyRoute {
                destination: destination.parse().unwrap(),
                metric: 5,
                via: None,
            })
            .collect();
        assert!(prepare_xray(1000, input, 51820).is_err());
    }

    #[test]
    fn a_lone_def1_half_is_a_normal_route_not_full_coverage() {
        let mut input = params();
        input.routes = vec![PolicyRoute {
            destination: "0.0.0.0/1".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        let plan = prepare_xray(1000, input, 51820).unwrap();
        assert!(!plan.full_ipv4);
    }

    #[test]
    fn plan_injects_a_loopback_stats_listener_and_api_route() {
        let plan = prepare_xray(1000, params(), 51820).unwrap();
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(plan.api_port, xray_api_port(51820));
        assert_eq!(xray_api_port(51821), plan.api_port + 1);
        assert_eq!(
            config["api"],
            json!({"tag": "api", "services": ["StatsService"]})
        );
        assert!(config["stats"].is_object());
        assert_eq!(
            config["policy"]["system"]["statsInboundUplink"],
            json!(true)
        );
        let api_in = &config["inbounds"][1];
        assert_eq!(api_in["tag"], "api-in");
        assert_eq!(api_in["listen"], "127.0.0.1");
        assert_eq!(api_in["port"], json!(xray_api_port(51820)));
        let rules = config["routing"]["rules"].as_array().unwrap();
        let rule = rules
            .iter()
            .find(|rule| rule["outboundTag"] == "api")
            .expect("api route");
        assert_eq!(rule["inboundTag"], json!(["api-in"]));
    }

    #[test]
    fn plan_accepts_generated_split_dns_and_strategy_sections() {
        // Mirror of what `apply_profile_routing` emits for a profile with
        // xrayDns + strategy overrides — the daemon must not reject it.
        let mut input = params();
        input.config = json!({
            "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true}}],
            "outbounds":[
                {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"proxy.test","port":443,"users":[{"id":"SECRET-ID","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"direct","protocol":"freedom"},
                {"tag":"blocked","protocol":"blackhole"},
                {"tag":"dns-out","protocol":"dns"}
            ],
            "dns":{
                "hosts":{"domain:ads.test":["127.0.0.1"]},
                "servers":[
                    "fakedns",
                    {"address":"https://1.1.1.1/dns-query","domains":["geosite:category-ru@attr"],"skipFallback":true},
                    "udp://9.9.9.9:53"
                ],
                "queryStrategy":"UseIPv4"
            },
            "fakedns":[{"ipPool":"198.18.0.0/16","poolSize":65535}],
            "routing":{
                "domainStrategy":"IPIfNonMatch",
                "domainMatcher":"mph",
                "rules":[
                    {"type":"field","port":"53","outboundTag":"dns-out"},
                    {"type":"field","ip":["1.1.1.1"],"outboundTag":"direct"},
                    {"type":"field","domain":["geosite:category-ru@attr"],"outboundTag":"proxy"},
                    {"type":"field","network":"udp","domain":["ntp.test"],"outboundTag":"blocked"}
                ]
            }
        })
        .to_string();
        let plan = prepare_xray(1000, input, 51820).unwrap();
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(
            config["inbounds"][0]["sniffing"]["destOverride"],
            json!(["http", "tls", "quic", "fakedns"])
        );
        assert_eq!(config["outbounds"][3]["protocol"], "dns");
        assert_eq!(
            config["outbounds"][3]["streamSettings"]["sockopt"]["mark"],
            51820
        );
    }

    #[test]
    fn plan_accepts_imported_panel_config_shape() {
        // Subscription/panel configs keep richer machinery than the narrow
        // generated schema: mux on the proxy outbound, dialerProxy on the
        // dns outbound, DNS rewrite tables, inboundTag rules without an
        // explicit type field, and dns.tag/enableParallelQuery.
        let mut input = params();
        input.config = json!({
            "inbounds": [
                {"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true},"sniffing":{"enabled":true,"destOverride":["http","tls"]}},
                {"tag":"http-in","listen":"127.0.0.1","port":1081,"protocol":"http"}
            ],
            "outbounds": [
                {"tag":"proxy","protocol":"vless","mux":{"enabled":true,"concurrency":6,"xudpConcurrency":4,"xudpProxyUDP443":"reject"},
                 "settings":{"vnext":[{"address":"nl.example.test","port":443,"users":[{"id":"SECRET-ID","encryption":"none","flow":""}]}]},
                 "streamSettings":{"network":"tcp","security":"reality","tcpSettings":{},"realitySettings":{"serverName":"www.example.test","fingerprint":"chrome","publicKey":"KEY","shortId":"","spiderX":""}}},
                {"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"domainStrategy":"ForceIPv4"}}},
                {"tag":"dns","protocol":"dns",
                 "settings":{"rewriteAddress":"8.8.8.8","rewriteNetwork":"udp","rewritePort":53,
                    "rules":[{"action":"return","qType":"65,28","rCode":5},{"action":"hijack","domain":["geosite:private"],"qType":"1"},{"action":"direct"}]},
                 "streamSettings":{"sockopt":{"dialerProxy":"proxy"}}},
                {"tag":"block","protocol":"blackhole"},
                {"tag":"block-http","protocol":"blackhole","settings":{"response":{"type":"http"}}}
            ],
            "dns":{
                "enableParallelQuery": false,
                "tag": "dns-inbound",
                "hosts": {"dot.example.test": ["77.88.8.8"]},
                "queryStrategy": "UseIPv4",
                "servers": ["https://dot.example.test/dns-query", "77.88.8.8", "194.85.254.37"]
            },
            "routing":{
                "domainStrategy":"AsIs",
                "rules":[
                    {"inboundTag":["socks-direct","dns-inbound"],"outboundTag":"direct"},
                    {"network":"tcp,udp","outboundTag":"dns","port":"53"},
                    {"inboundTag":["dns-in"],"outboundTag":"dns"},
                    {"ip":["8.8.8.8"],"network":"tcp","outboundTag":"block","port":"853"},
                    {"type":"field","ip":["geoip:private"],"outboundTag":"direct"},
                    {"type":"field","domain":["geosite:private"],"outboundTag":"direct"}
                ]
            }
        })
        .to_string();
        let plan = prepare_xray(1000, input, 51820).unwrap();
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        // dialerProxy chains the dns outbound through the proxy; the daemon
        // mark must merge into sockopt, not replace it.
        assert_eq!(
            config["outbounds"][2]["streamSettings"]["sockopt"]["dialerProxy"],
            "proxy"
        );
        assert_eq!(
            config["outbounds"][2]["streamSettings"]["sockopt"]["mark"],
            51820
        );
        assert_eq!(
            config["outbounds"][1]["streamSettings"]["sockopt"]["domainStrategy"],
            "ForceIPv4"
        );
    }

    #[test]
    fn plan_rejects_malformed_dns_sections() {
        let with_dns = |dns: Value| {
            let mut config: Value = serde_json::from_str(&params().config).unwrap();
            config["dns"] = dns;
            let mut input = params();
            input.config = config.to_string();
            prepare_xray(1000, input, 51820)
        };
        assert!(with_dns(json!({"servers": [{"address": "ok.test", "exec": "sh"}]})).is_err());
        assert!(with_dns(json!({"servers": [{"address": "ok.test", "port": 99999}]})).is_err());
        assert!(with_dns(json!({"hosts": {"x.test": 42}})).is_err());
        let mut config: Value = serde_json::from_str(&params().config).unwrap();
        config["fakedns"] = json!([{"ipPool": "not-a-cidr", "poolSize": 16}]);
        let mut input = params();
        input.config = config.to_string();
        assert!(prepare_xray(1000, input, 51820).is_err());
    }
    /// Opt-in end-to-end check against a real config and the pinned binary:
    /// `XRAY_PANEL_CONFIG=/path/config.json XRAY_TEST_BIN=/path/to/xray`
    /// runs `prepare_xray` on the file and asks `xray run -test` whether the
    /// resulting TUN plan actually loads. Skips silently without both vars.
    /// Secrets in the source config never leave the process — the assertion
    /// is the process exit status only.
    #[test]
    fn env_gated_plan_loads_in_real_xray() {
        let (Ok(config_path), Ok(binary)) = (
            std::env::var("XRAY_PANEL_CONFIG"),
            std::env::var("XRAY_TEST_BIN"),
        ) else {
            return;
        };
        let mut input = params();
        input.config = std::fs::read_to_string(&config_path).expect("read panel config");
        let plan = prepare_xray(1000, input, 51820).expect("plan");
        // XRAY_PLAN_OUT additionally keeps a copy of the plan for manual
        // `xray run` reproduction outside the test.
        if let Ok(keep) = std::env::var("XRAY_PLAN_OUT") {
            std::fs::write(&keep, &plan.config).expect("write plan copy");
        }
        let staged =
            std::env::temp_dir().join(format!("xray-plan-test-{}.json", std::process::id()));
        std::fs::write(&staged, &plan.config).expect("write staged plan");
        let assets = std::path::Path::new(&binary)
            .parent()
            .expect("binary parent dir");
        // `run -test` still instantiates the TUN device, so an unprivileged
        // run fails with EPERM after parsing. Inside a disposable user+net
        // namespace the check fully loads the config.
        let output = std::process::Command::new("unshare")
            .args(["-Urn", &binary, "run", "-test", "-config"])
            .arg(&staged)
            .env("XRAY_LOCATION_ASSET", assets)
            .output()
            .expect("spawn xray");
        let _ = std::fs::remove_file(&staged);
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Without namespace support the parse still has to succeed: xray
        // may then only fail at TUN creation with EPERM.
        let parsed =
            stdout.contains("Configuration OK") || stdout.contains("operation not permitted");
        assert!(
            parsed,
            "xray -test rejected the generated TUN plan: {stdout}"
        );
    }

    #[test]
    fn dns_bypass_hosts_are_carried_into_the_plan() {
        let mut input = params();
        input.dns_bypass = vec!["8.8.8.8".into(), "dns.example.test".into()];
        let plan = prepare_xray(1000, input, 51820).unwrap();
        assert_eq!(plan.dns_bypass, ["8.8.8.8", "dns.example.test"]);

        let mut input = params();
        input.dns_bypass = vec!["1.1.1.1".into(); 17];
        assert!(prepare_xray(1000, input, 51820).is_err());
        let mut input = params();
        input.dns_bypass = vec!["bad host/name".into()];
        assert!(prepare_xray(1000, input, 51820).is_err());
    }

    #[test]
    fn connection_idle_policy_survives_privileged_stats_injection() {
        let mut input = params();
        let mut config: Value = serde_json::from_str(&input.config).unwrap();
        config["policy"] = json!({"levels":{"0":{"connIdle":120}}});
        input.config = config.to_string();
        let plan = prepare_xray(1000, input, 51820).unwrap();
        let runtime: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(runtime["policy"]["levels"]["0"]["connIdle"], 120);
        assert_eq!(runtime["policy"]["system"]["statsInboundUplink"], true);
        config["policy"]["levels"]["0"]["bufferSize"] = json!(1024);
        let mut input = params();
        input.config = config.to_string();
        assert!(
            prepare_xray(1000, input, 51820).is_err(),
            "unapproved policy settings reached root Xray"
        );
    }
}
