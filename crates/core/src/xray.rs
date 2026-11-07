use crate::models::{
    DomainPolicy, DomainRouteTarget, XrayDnsConfig, XrayDnsRoute, XrayDnsServer, XrayDomainMatcher,
    XrayDomainStrategy, XraySockopts, XrayTrafficRule,
};
use ipnet::IpNet;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVless {
    pub name: Option<String>,
    pub id: String,
    pub address: String,
    pub port: u16,
    pub network: String,
    pub security: String,
    pub flow: Option<String>,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub spider_x: Option<String>,
}

pub fn parse_vless_url(uri: &str) -> io::Result<ParsedVless> {
    let url = Url::parse(uri.trim()).map_err(|_| invalid_input("invalid vless url"))?;
    if url.scheme() != "vless" {
        return Err(invalid_input(format!(
            "unsupported scheme '{}', expected vless",
            url.scheme()
        )));
    }
    let id = percent_decode(url.username());
    if id.trim().is_empty() {
        return Err(invalid_input("vless url must contain a nonblank user id"));
    }
    let address = url
        .host_str()
        .map(str::to_string)
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| invalid_input("vless url must contain a host"))?;

    let mut network = "tcp".to_string();
    let mut security = "none".to_string();
    let mut flow = None;
    let mut sni = None;
    let mut fingerprint = None;
    let mut public_key = None;
    let mut short_id = None;
    let mut path = None;
    let mut host = None;
    let mut service_name = None;
    let mut alpn = None;
    let mut spider_x = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "type" => network = value.into_owned(),
            "security" => security = value.into_owned(),
            "flow" => flow = Some(value.into_owned()),
            "sni" => sni = Some(value.into_owned()),
            "fp" => fingerprint = Some(value.into_owned()),
            "pbk" => public_key = Some(value.into_owned()),
            "sid" => short_id = Some(value.into_owned()),
            "path" => path = Some(value.into_owned()),
            "host" => host = Some(value.into_owned()),
            "serviceName" => service_name = Some(value.into_owned()),
            "alpn" => {
                alpn = Some(
                    value
                        .split(',')
                        .map(str::trim)
                        .map(str::to_string)
                        .collect(),
                )
            }
            "spx" => spider_x = Some(value.into_owned()),
            "allowInsecure" if value != "0" => {
                return Err(invalid_input(
                    "allowInsecure is unsupported by Xray 26.3.27",
                ))
            }
            _ => {}
        }
    }
    if !matches!(
        network.as_str(),
        "tcp" | "raw" | "ws" | "grpc" | "xhttp" | "httpupgrade"
    ) {
        return Err(invalid_input("unsupported transport type"));
    }
    if !matches!(security.as_str(), "none" | "tls" | "reality") {
        return Err(invalid_input("unsupported security"));
    }
    let port = match url.port() {
        Some(0) => return Err(invalid_input("vless url port must be nonzero")),
        Some(port) => port,
        None if security == "tls" || security == "reality" => 443,
        None => {
            return Err(invalid_input(
                "vless url requires an explicit port unless security is tls or reality",
            ))
        }
    };
    if security == "reality"
        && (sni.as_deref().map(str::trim).unwrap_or("").is_empty()
            || public_key
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty())
    {
        return Err(invalid_input(
            "reality security requires nonblank sni and pbk",
        ));
    }
    let name = url
        .fragment()
        .map(percent_decode)
        .filter(|name| !name.trim().is_empty());
    Ok(ParsedVless {
        name,
        id,
        address,
        port,
        network,
        security,
        flow,
        sni,
        fingerprint,
        public_key,
        short_id,
        path,
        host,
        service_name,
        alpn,
        spider_x,
    })
}

pub fn generate_vless_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    if socks_port == 0 {
        return Err(invalid_input("socks port must be nonzero"));
    }
    let parsed = parse_vless_url(uri)?;
    let mut user = json!({
        "id": parsed.id,
        "encryption": "none",
    });
    if let Some(flow) = &parsed.flow {
        user["flow"] = json!(flow);
    }
    let mut stream = json!({
        "network": parsed.network,
        "security": parsed.security,
    });
    match parsed.network.as_str() {
        "ws" => {
            let mut ws = Map::new();
            if let Some(path) = &parsed.path {
                ws.insert("path".into(), json!(path));
            }
            if let Some(host) = &parsed.host {
                ws.insert("headers".into(), json!({ "Host": host }));
            }
            if !ws.is_empty() {
                stream["wsSettings"] = Value::Object(ws);
            }
        }
        "grpc" => {
            if let Some(service_name) = &parsed.service_name {
                stream["grpcSettings"] = json!({ "serviceName": service_name });
            }
        }
        "xhttp" | "httpupgrade" => {
            let mut settings = Map::new();
            if let Some(path) = &parsed.path {
                settings.insert("path".into(), json!(path));
            }
            if let Some(host) = &parsed.host {
                settings.insert("host".into(), json!(host));
            }
            if !settings.is_empty() {
                let key = if parsed.network == "xhttp" {
                    "xhttpSettings"
                } else {
                    "httpupgradeSettings"
                };
                stream[key] = Value::Object(settings);
            }
        }
        _ => {}
    }
    match parsed.security.as_str() {
        "tls" => {
            let mut tls = Map::new();
            if let Some(sni) = &parsed.sni {
                tls.insert("serverName".into(), json!(sni));
            }
            if let Some(fingerprint) = &parsed.fingerprint {
                tls.insert("fingerprint".into(), json!(fingerprint));
            }
            if let Some(alpn) = &parsed.alpn {
                tls.insert("alpn".into(), json!(alpn));
            }
            stream["tlsSettings"] = Value::Object(tls);
        }
        "reality" => {
            let mut reality = Map::new();
            if let Some(sni) = &parsed.sni {
                reality.insert("serverName".into(), json!(sni));
            }
            if let Some(fingerprint) = &parsed.fingerprint {
                reality.insert("fingerprint".into(), json!(fingerprint));
            }
            if let Some(public_key) = &parsed.public_key {
                reality.insert("publicKey".into(), json!(public_key));
            }
            if let Some(short_id) = &parsed.short_id {
                reality.insert("shortId".into(), json!(short_id));
            }
            if let Some(spider_x) = &parsed.spider_x {
                reality.insert("spiderX".into(), json!(spider_x));
            }
            stream["realitySettings"] = Value::Object(reality);
        }
        _ => {}
    }
    Ok(config_with_proxy(
        json!({
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": parsed.address,
                    "port": parsed.port,
                    "users": [user],
                }],
            },
            "streamSettings": stream,
        }),
        socks_port,
    ))
}

/// Subscription entries that arrive as complete Xray JSON configs (Remnawave
/// and similar panels serve this format to v2rayN) are stored next to share
/// links as `xray-json:<base64url>` so switching, refresh and naming reuse the
/// share-link paths unchanged.
pub const XRAY_JSON_PREFIX: &str = "xray-json:";
/// Only routing-relevant sections survive; `log` (arbitrary file paths), `api`,
/// `stats`, `inbounds` and anything else from the untrusted panel is dropped.
const XRAY_JSON_KEEP: [&str; 6] = [
    "outbounds",
    "routing",
    "dns",
    "policy",
    "observatory",
    "burstObservatory",
];

pub fn xray_json_entry(config: &Value) -> io::Result<String> {
    use base64::Engine;
    let object = config
        .as_object()
        .ok_or_else(|| invalid_input("xray config must be an object"))?;
    if object
        .get("outbounds")
        .and_then(Value::as_array)
        .is_none_or(|outbounds| outbounds.is_empty())
    {
        return Err(invalid_input("xray config has no outbounds"));
    }
    let mut kept = Map::new();
    for key in XRAY_JSON_KEEP {
        if let Some(value) = object.get(key) {
            kept.insert(key.into(), value.clone());
        }
    }
    if let Some(remarks) = object.get("remarks").and_then(Value::as_str) {
        kept.insert("remarks".into(), json!(remarks));
    }
    let bytes = serde_json::to_vec(&Value::Object(kept))
        .map_err(|_| invalid_input("xray config could not be encoded"))?;
    Ok(format!(
        "{XRAY_JSON_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    ))
}

fn decode_xray_json_entry(uri: &str) -> io::Result<Map<String, Value>> {
    use base64::Engine;
    let encoded = uri
        .trim()
        .strip_prefix(XRAY_JSON_PREFIX)
        .ok_or_else(|| invalid_input("not an xray-json entry"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid_input("invalid xray-json entry"))?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(invalid_input("invalid xray-json entry")),
    }
}

/// Secret-free identity string for `xray-json:` entries (see
/// [`crate::subscription::endpoint_key`]): the transport of the first
/// outbound — `protocol|address:port|network|security`. `None` for entries
/// that cannot be decoded.
pub fn xray_json_identity(uri: &str) -> Option<String> {
    let entry = decode_xray_json_entry(uri).ok()?;
    let outbound = entry.get("outbounds")?.as_array()?.first()?;
    let text = |key: &str| outbound.get(key)?.as_str().map(str::to_string);
    let protocol = text("protocol")?;
    let (address, port) = match protocol.as_str() {
        "hysteria" | "hysteria2" => (
            outbound["settings"].get("address")?.as_str()?.to_string(),
            outbound["settings"].get("port")?.to_string(),
        ),
        _ => {
            let server = outbound["settings"].get("vnext")?.as_array()?.first()?;
            (
                server.get("address")?.as_str()?.to_string(),
                server.get("port")?.to_string(),
            )
        }
    };
    let network = outbound["streamSettings"]
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("tcp");
    let security = outbound["streamSettings"]
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("none");
    Some(format!(
        "{protocol}|{}:{port}|{network}|{security}",
        address.to_lowercase()
    ))
}

fn generate_xray_json_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    if socks_port == 0 {
        return Err(invalid_input("socks port must be nonzero"));
    }
    let entry = decode_xray_json_entry(uri)?;
    let mut config = Map::new();
    for key in XRAY_JSON_KEEP {
        if let Some(value) = entry.get(key) {
            config.insert(key.into(), value.clone());
        }
    }
    if config
        .get("outbounds")
        .and_then(Value::as_array)
        .is_none_or(|outbounds| outbounds.is_empty())
    {
        return Err(invalid_input("xray config has no outbounds"));
    }
    config.insert("log".into(), json!({ "loglevel": "warning" }));
    config.insert(
        "inbounds".into(),
        json!([{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "udp": true },
        }]),
    );
    Ok(Value::Object(config))
}

pub fn generate_share_link_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    if uri.trim().starts_with(XRAY_JSON_PREFIX) {
        return generate_xray_json_config(uri, socks_port);
    }
    match uri.trim().split_once("://").map(|(scheme, _)| scheme) {
        Some("vless") => generate_vless_config(uri, socks_port),
        Some("hysteria2" | "hy2") => generate_hysteria2_config(uri, socks_port),
        _ => Err(invalid_input("unsupported share link scheme")),
    }
}

/// Top-level sections of a config the Linux daemon runs as a system tunnel.
const TUN_TOP_LEVEL: [&str; 6] = ["log", "inbounds", "outbounds", "routing", "dns", "fakedns"];

/// A config already in the shape the daemon accepts: the generated one from
/// a share link (`proxy` first, `freedom` second, plain routing).
fn is_tun_shaped(object: &Map<String, Value>) -> bool {
    let outbounds = object.get("outbounds").and_then(Value::as_array);
    let routing = object.get("routing").and_then(Value::as_object);
    object
        .keys()
        .all(|key| TUN_TOP_LEVEL.contains(&key.as_str()))
        && outbounds.is_some_and(|list| {
            list.len() == 2 && list[0]["tag"] == "proxy" && list[1]["protocol"] == "freedom"
        })
        && routing.is_none_or(|routing| {
            routing
                .keys()
                .all(|key| matches!(key.as_str(), "domainStrategy" | "domainMatcher" | "rules"))
        })
}

/// Copies the listed keys of an object, dropping everything else.
fn keep_keys(value: &Value, keys: &[&str]) -> Value {
    let mut out = Map::new();
    if let Some(object) = value.as_object() {
        for key in keys {
            if let Some(item) = object.get(*key) {
                out.insert((*key).into(), item.clone());
            }
        }
    }
    Value::Object(out)
}

/// Hysteria2 masking reduced to Salamander obfuscation and port hopping, the
/// only parts the daemon runs; `None` when nothing of it is left.
fn tun_finalmask(mask: &Value) -> Option<Value> {
    let mut out = Map::new();
    if let Some(item) = mask["udp"].as_array().and_then(|list| list.first()) {
        if item["type"] == "salamander" {
            out.insert(
                "udp".into(),
                json!([{
                    "type": "salamander",
                    "settings": keep_keys(&item["settings"], &["password"]),
                }]),
            );
        }
    }
    if let Some(ports) = mask["quicParams"]["udpHop"]["ports"].as_str() {
        out.insert("quicParams".into(), json!({"udpHop": {"ports": ports}}));
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

/// Mux limited to the fields and ranges the daemon accepts. Panels write
/// `concurrency: -1` for "off"; out-of-range counts are dropped.
fn tun_mux(mux: &Value) -> Value {
    let mut out = keep_keys(
        mux,
        &[
            "enabled",
            "concurrency",
            "xudpConcurrency",
            "xudpProxyUDP443",
        ],
    );
    for key in ["concurrency", "xudpConcurrency"] {
        if !out[key].as_i64().is_some_and(|n| (1..=1024).contains(&n)) {
            out.as_object_mut().map(|map| map.remove(key));
        }
    }
    out
}

/// `streamSettings` reduced to the fields the daemon's validator accepts.
/// Anything else a panel adds (`sockopt`, `show`, `extra`, ...) is dropped:
/// it can only make the connection stricter or fail, never open anything up.
fn tun_stream_settings(stream: &Value, hysteria: bool) -> Value {
    if hysteria {
        let mut out = keep_keys(
            stream,
            &["network", "security", "tlsSettings", "hysteriaSettings"],
        );
        out["tlsSettings"] = keep_keys(
            &stream["tlsSettings"],
            &["serverName", "pinnedPeerCertSha256"],
        );
        out["hysteriaSettings"] = keep_keys(&stream["hysteriaSettings"], &["version", "auth"]);
        if let Some(mask) = tun_finalmask(&stream["finalmask"]) {
            out["finalmask"] = mask;
        }
        return out;
    }
    let mut out = keep_keys(
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
        ],
    );
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
        ("tcpSettings", &["header"][..]),
    ] {
        if stream.get(key).is_some() {
            out[key] = keep_keys(&stream[key], allowed);
        }
    }
    if let Some(header) = stream["tcpSettings"].get("header") {
        out["tcpSettings"]["header"] = keep_keys(header, &["type"]);
    }
    out
}

/// Turns a complete Xray config from a subscription panel (see
/// [`xray_json_entry`]) into the plain shape the Linux daemon runs as a
/// system-wide tunnel: the panel's main VLESS or Hysteria2 server, a direct
/// outbound and nothing else. The panel's own routing rules, DNS section,
/// observatory and policy are left out; the profile's routing settings are
/// applied on top afterwards. Configs already in the daemon's shape are
/// returned unchanged. When a balancer only chooses between the server and a
/// fallback relay, the server itself is used; an entry that is a pool of many
/// servers ("automatic") cannot be reduced to one and is refused.
pub fn tun_compatible_config(base: &Value) -> Result<Value, &'static str> {
    let object = base.as_object().ok_or("The Xray config is invalid")?;
    if is_tun_shaped(object) {
        return Ok(base.clone());
    }
    let outbounds = object
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or("The Xray config has no outbounds")?;
    let supported =
        |outbound: &&Value| matches!(outbound["protocol"].as_str(), Some("vless" | "hysteria"));
    // "proxy", "proxy-2", ...: several of them form a pool the panel picks
    // from with a balancer (its "automatic" entry), which has no single server.
    let pool = outbounds
        .iter()
        .filter(|outbound| {
            supported(outbound)
                && outbound["tag"]
                    .as_str()
                    .is_some_and(|tag| tag == "proxy" || tag.starts_with("proxy-"))
        })
        .count();
    if pool > 1 {
        return Err(
            "This is an automatic entry that chooses between many servers, which a system-wide \
             tunnel does not support. Choose a specific server.",
        );
    }
    let proxy = outbounds
        .iter()
        .find(|outbound| outbound["tag"] == "proxy" && supported(outbound))
        .or_else(|| outbounds.iter().find(supported))
        .ok_or("The server uses a protocol a system-wide tunnel does not support")?;
    let hysteria = proxy["protocol"] == "hysteria";
    let settings = if hysteria {
        keep_keys(&proxy["settings"], &["version", "address", "port"])
    } else {
        let server = proxy["settings"]["vnext"]
            .as_array()
            .and_then(|list| list.first())
            .ok_or("The server has no address")?;
        let user = server["users"]
            .as_array()
            .and_then(|list| list.first())
            .ok_or("The server has no user")?;
        json!({
            "vnext": [{
                "address": server["address"],
                "port": server["port"],
                "users": [keep_keys(user, &["id", "encryption", "flow"])],
            }],
        })
    };
    let mut clean = json!({
        "tag": "proxy",
        "protocol": proxy["protocol"],
        "settings": settings,
        "streamSettings": tun_stream_settings(&proxy["streamSettings"], hysteria),
    });
    if let Some(mux) = proxy.get("mux") {
        clean["mux"] = tun_mux(mux);
    }
    let mut config = config_with_proxy(clean, 1);
    config["inbounds"] = object.get("inbounds").cloned().unwrap_or(json!([]));
    Ok(config)
}

pub fn generate_share_link_config_with_http(
    uri: &str,
    socks_port: u16,
    http_port: u16,
) -> io::Result<Value> {
    if http_port == 0 || http_port == socks_port {
        return Err(invalid_input(
            "HTTP proxy port must be nonzero and differ from SOCKS port",
        ));
    }
    let mut config = generate_share_link_config(uri, socks_port)?;
    config["inbounds"].as_array_mut().unwrap().push(json!({
        "tag": "http-in",
        "listen": "127.0.0.1",
        "port": http_port,
        "protocol": "http",
    }));
    Ok(config)
}

// ---- multinode (failover + pinned routes) ----------------------------------

/// Outbound tag of a failover candidate (`node-<key>`); also the tag a
/// `xray api bo` override selects.
pub fn node_tag(key: &str) -> String {
    format!("node-{key}")
}

/// Outbound tag of a pinned-only node (`pin-<key>`) — deliberately outside
/// the balancer selector so the failover machinery can never select a node
/// the user only pinned routes to.
pub fn pin_tag(key: &str) -> String {
    format!("pin-{key}")
}

/// The tag the balancer selects while no candidate is healthy: a blackhole
/// the daemon appends. Default traffic is dropped, never sent direct.
pub const UNAVAILABLE_TAG: &str = "unavailable";
/// Tag of the single `routing.balancers` entry the daemon overrides at
/// runtime with `xray api bo`.
pub const FAILOVER_BALANCER: &str = "failover";

/// The proxy outbound of an endpoint's generated config, retagged to `tag`.
/// Panel `xray-json:` entries are reduced to their server first, the same
/// way a single-endpoint TUN connect treats them.
pub fn multinode_outbound(url: &str, tag: &str) -> io::Result<Value> {
    let config = generate_share_link_config(url, 1)?;
    let config = tun_compatible_config(&config)
        .map_err(|_| invalid_input("invalid or unsupported subscription endpoint"))?;
    let mut outbound = config["outbounds"]
        .as_array()
        .and_then(|outbounds| outbounds.first().cloned())
        .ok_or_else(|| invalid_input("endpoint produced no proxy outbound"))?;
    outbound["tag"] = json!(tag);
    Ok(outbound)
}

/// One resolved pinned route for [`apply_multinode_config`]: selectors plus
/// either a real outbound (the endpoint is in the subscription) or a
/// blackhole (it left — the pinned selectors drop, never reroute).
pub struct PinnedOutbound {
    pub key: String,
    /// `None` → the outbound for this key is a blackhole.
    pub outbound: Option<Value>,
    pub selectors: Vec<String>,
}

/// Rebuild a generated single-endpoint config for multinode operation:
///
/// - `base`'s primary outbound is retagged `node-<primary>` and the ordered
///   `backups` join it (same order → strict priority);
/// - each resolved pinned route adds a `pin-<key>` outbound and prepends a
///   domain rule pinned to it — these rules sit before every other rule so
///   a pinned name can never escape to direct or another node;
/// - a missing pinned key adds only a blackhole `pin-<key>` outbound —
///   fail-closed;
/// - routing gets `balancers: [{tag: failover, selector: [unavailable]}]`:
///   the daemon adds the `unavailable` blackhole outbound and the catch-all
///   rule, and pins the balancer to a real node only after a probe says it
///   is healthy. Before that, default traffic drops — never leaks.
///
/// `freedom`/`blackhole` auxiliaries from the base config are preserved.
pub fn apply_multinode_config(
    base: &Value,
    primary_key: &str,
    backups: &[(String, Value)],
    pinned: &[PinnedOutbound],
) -> io::Result<Value> {
    let mut config = base.clone();
    let outbounds = config["outbounds"]
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config outbounds must be an array"))?;
    if outbounds.is_empty() {
        return Err(invalid_data("xray config has no outbounds"));
    }
    let primary_tag = outbounds[0]["tag"]
        .as_str()
        .ok_or_else(|| invalid_data("xray primary outbound has no tag"))?
        .to_owned();
    outbounds[0]["tag"] = json!(node_tag(primary_key));
    for (key, outbound) in backups {
        let mut node = outbound.clone();
        node["tag"] = json!(node_tag(key));
        outbounds.push(node);
    }
    let mut pinned_outbounds = HashMap::new();
    for route in pinned {
        if let Some(previous) = pinned_outbounds.insert(route.key.as_str(), route.outbound.as_ref())
        {
            if previous != route.outbound.as_ref() {
                return Err(invalid_data("conflicting outbounds for a pinned endpoint"));
            }
            continue;
        }
        outbounds.push(match &route.outbound {
            Some(outbound) => {
                let mut pinned_node = outbound.clone();
                pinned_node["tag"] = json!(pin_tag(&route.key));
                pinned_node
            }
            None => json!({"tag": pin_tag(&route.key), "protocol": "blackhole"}),
        });
    }
    let routing = config
        .as_object_mut()
        .and_then(|root| root.get_mut("routing"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid_data("xray config routing must be an object"))?;
    let mut merged: Vec<Value> = Vec::new();
    for route in pinned {
        if route.selectors.is_empty() {
            continue;
        }
        merged.push(json!({
            "type": "field",
            "domain": route.selectors,
            "outboundTag": pin_tag(&route.key),
        }));
    }
    let rules = routing
        .entry("rules")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config routing rules must be an array"))?;
    // Existing proxy policies must follow failover, not retain a dangling
    // reference to the primary's old tag after it becomes `node-<key>`.
    for rule in rules.iter_mut() {
        if rule["outboundTag"].as_str() == Some(primary_tag.as_str()) {
            let object = rule
                .as_object_mut()
                .ok_or_else(|| invalid_data("xray routing rule must be an object"))?;
            object.remove("outboundTag");
            object.insert("balancerTag".into(), json!(FAILOVER_BALANCER));
        }
    }
    // Port-scoped transport guards and DNS capture precede domain pins.
    // Pins still precede ordinary domain/default policies.
    let guard_count = rules
        .iter()
        .take_while(|rule| rule.get("port").is_some())
        .count();
    rules.splice(guard_count..guard_count, merged);
    routing.insert(
        "balancers".into(),
        json!([{"tag": FAILOVER_BALANCER, "selector": [UNAVAILABLE_TAG]}]),
    );
    Ok(config)
}

/// Short protocol label for an endpoint, e.g. `VLESS · Reality` or
/// `Hysteria2`; for full Xray JSON entries it is read from the first outbound.
pub fn endpoint_protocol(uri: &str) -> Option<String> {
    let name = |scheme: &str| match scheme {
        "vless" => "VLESS".to_string(),
        "hy2" | "hysteria2" => "Hysteria2".to_string(),
        "trojan" => "Trojan".to_string(),
        "vmess" => "VMess".to_string(),
        "ss" | "shadowsocks" => "Shadowsocks".to_string(),
        other => other.to_uppercase(),
    };
    let mut label;
    let (security, transport) = if uri.trim().starts_with(XRAY_JSON_PREFIX) {
        let entry = decode_xray_json_entry(uri).ok()?;
        let outbound = entry.get("outbounds")?.as_array()?.first()?.clone();
        label = name(outbound.get("protocol")?.as_str()?);
        let stream = outbound
            .get("streamSettings")
            .cloned()
            .unwrap_or(Value::Null);
        (
            stream["security"].as_str().map(str::to_string),
            stream["network"].as_str().map(str::to_string),
        )
    } else {
        let url = reqwest::Url::parse(uri.trim()).ok()?;
        label = name(url.scheme());
        let query = |key: &str| {
            url.query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
        };
        (query("security"), query("type"))
    };
    match security.as_deref() {
        Some("reality") => label.push_str(" · Reality"),
        Some("tls") => label.push_str(" · TLS"),
        _ => {}
    }
    if let Some(transport) = transport.filter(|t| t != "tcp" && t != "none" && t != "raw") {
        label.push_str(&format!(" · {}", transport.to_uppercase()));
    }
    Some(label)
}

pub fn share_link_name(uri: &str) -> Option<String> {
    if uri.trim().starts_with(XRAY_JSON_PREFIX) {
        return decode_xray_json_entry(uri)
            .ok()
            .and_then(|entry| entry.get("remarks")?.as_str().map(str::to_string))
            .filter(|name| !name.trim().is_empty());
    }
    uri.rsplit_once('#')
        .map(|(_, fragment)| percent_decode(fragment))
        .filter(|name| !name.trim().is_empty())
}

fn generate_hysteria2_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    if socks_port == 0 {
        return Err(invalid_input("socks port must be nonzero"));
    }
    let uri = uri.trim();
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| invalid_input("invalid hysteria2 url"))?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .ok_or_else(|| invalid_input("hysteria2 url must contain auth"))?;
    let port_spec = if host_port.starts_with('[') {
        host_port.rsplit_once("]:").map(|(_, port)| port)
    } else {
        host_port.rsplit_once(':').map(|(_, port)| port)
    };
    let mut hop_ports = None;
    let normalized;
    if let Some(port_spec) = port_spec.filter(|port| port.contains([',', '-'])) {
        let first = validate_hysteria_ports(port_spec)?;
        let port_start = authority
            .rfind(':')
            .ok_or_else(|| invalid_input("invalid hysteria2 port"))?;
        normalized = format!(
            "{scheme}://{}:{first}{}",
            &authority[..port_start],
            &rest[authority_end..]
        );
        hop_ports = Some(port_spec);
    } else {
        normalized = uri.to_string();
    }
    let url = Url::parse(&normalized).map_err(|_| invalid_input("invalid hysteria2 url"))?;
    let auth = percent_decode(url.username());
    let auth = match url.password() {
        Some(password) => format!("{auth}:{}", percent_decode(password)),
        None => auth,
    };
    if auth.is_empty() {
        return Err(invalid_input("hysteria2 url must contain auth"));
    }
    let address = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| invalid_input("hysteria2 url must contain a host"))?;
    let port = url.port().unwrap_or(443);
    if port == 0 {
        return Err(invalid_input("hysteria2 port must be nonzero"));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(invalid_input("unsupported hysteria2 url path"));
    }
    let mut sni = None;
    let mut pin = None;
    let mut obfs = None;
    let mut obfs_password = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sni" => sni = Some(value.into_owned()),
            "pinSHA256" => {
                let normalized_pin = value.replace(':', "");
                if normalized_pin.len() != 64
                    || !normalized_pin.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(invalid_input("invalid pinSHA256"));
                }
                pin = Some(normalized_pin);
            }
            "obfs" => obfs = Some(value.into_owned()),
            "obfs-password" => obfs_password = Some(value.into_owned()),
            "insecure" | "allowInsecure" if value == "0" => {}
            "insecure" | "allowInsecure" => {
                return Err(invalid_input("insecure TLS is unsupported by Xray 26.3.27"))
            }
            _ => return Err(invalid_input("unsupported hysteria2 option")),
        }
    }
    let mut tls = Map::new();
    if let Some(sni) = sni {
        tls.insert("serverName".into(), json!(sni));
    }
    if let Some(pin) = pin {
        tls.insert("pinnedPeerCertSha256".into(), json!(pin));
    }
    let mut stream = json!({
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": Value::Object(tls),
        "hysteriaSettings": {"version": 2, "auth": auth},
    });
    let mut finalmask = Map::new();
    match (obfs.as_deref(), obfs_password) {
        (Some("salamander"), Some(password)) if !password.is_empty() => {
            finalmask.insert(
                "udp".into(),
                json!([{"type": "salamander", "settings": {"password": password}}]),
            );
        }
        (None, None) => {}
        _ => return Err(invalid_input("unsupported hysteria2 obfuscation")),
    }
    if let Some(ports) = hop_ports {
        finalmask.insert("quicParams".into(), json!({"udpHop": {"ports": ports}}));
    }
    if !finalmask.is_empty() {
        stream["finalmask"] = Value::Object(finalmask);
    }
    Ok(config_with_proxy(
        json!({
            "tag": "proxy",
            "protocol": "hysteria",
            "settings": {"version": 2, "address": address, "port": port},
            "streamSettings": stream,
        }),
        socks_port,
    ))
}

fn validate_hysteria_ports(ports: &str) -> io::Result<u16> {
    let mut first = None;
    for part in ports.split(',') {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let start = start
            .parse::<u16>()
            .map_err(|_| invalid_input("invalid hysteria2 port range"))?;
        let end = end
            .parse::<u16>()
            .map_err(|_| invalid_input("invalid hysteria2 port range"))?;
        if start == 0 || end < start {
            return Err(invalid_input("invalid hysteria2 port range"));
        }
        first.get_or_insert(start);
    }
    first.ok_or_else(|| invalid_input("invalid hysteria2 port range"))
}

fn config_with_proxy(proxy: Value, socks_port: u16) -> Value {
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "udp": true },
        }],
        "outbounds": [
            proxy,
            {
                "tag": "direct",
                "protocol": "freedom",
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [],
        },
    })
}

/// Profile-level routing/DNS options applied alongside the domain policy
/// lists: strategy, matcher, split DNS, static hosts and fake-DNS capture.
#[derive(Debug, Default)]
pub struct ProfileRoutingOptions {
    pub private_lan_direct: bool,
    /// `routing.domainStrategy` override (`None` keeps the base value).
    pub domain_strategy: Option<XrayDomainStrategy>,
    /// `routing.domainMatcher` override.
    pub domain_matcher: Option<XrayDomainMatcher>,
    /// Profile `dns` section policy.
    pub dns: XrayDnsConfig,
    /// `streamSettings.sockopt` keepalive/timeouts applied to the node and
    /// direct outbounds (`None` keeps xray defaults).
    pub sockopts: Option<XraySockopts>,
    pub traffic_rules: Vec<XrayTrafficRule>,
    pub interface_routes: Vec<crate::models::XrayInterfaceRoute>,
    pub connection_idle_secs: Option<u32>,
    pub direct_domain_strategy: Option<String>,
}

impl From<&crate::models::Profile> for ProfileRoutingOptions {
    fn from(profile: &crate::models::Profile) -> Self {
        Self {
            private_lan_direct: profile.private_lan_direct,
            domain_strategy: profile.xray_domain_strategy,
            domain_matcher: profile.xray_domain_matcher,
            dns: profile.xray_dns.clone(),
            sockopts: profile.xray_sockopts.clone(),
            traffic_rules: profile.xray_traffic_rules.clone(),
            interface_routes: profile.xray_interface_routes.clone(),
            connection_idle_secs: profile.xray_connection_idle_secs,
            direct_domain_strategy: profile.xray_direct_domain_strategy.clone(),
        }
    }
}

pub fn apply_domain_policies(base: &Value, policies: &[DomainPolicy]) -> io::Result<Value> {
    apply_profile_routing(base, policies, &ProfileRoutingOptions::default())
}

pub fn validate_routing_policy_selectors(policies: &[DomainPolicy]) -> io::Result<()> {
    for policy in policies {
        if policy.domains.is_empty() {
            return Err(invalid_input("routing rule must contain selectors"));
        }
        for selector in &policy.domains {
            classify_routing_selector(selector)?;
        }
    }
    Ok(())
}

/// Returns `Ok(None)` for comments (`# …`) and blank selectors so the UI can
/// keep annotation lines inside routing lists.
pub fn classify_routing_selector(selector: &str) -> io::Result<Option<(&'static str, String)>> {
    let selector = selector.trim();
    if selector.is_empty() || selector.starts_with('#') {
        return Ok(None);
    }
    if let Some(category) = selector.strip_prefix("geosite:") {
        // `category@attr` filters records by attribute (`@cn`, `*`
        // wildcards allowed); a single `@` separates name and attribute.
        let (name, attr) = match category.split_once('@') {
            Some((name, attr)) => (name, Some(attr)),
            None => (category, None),
        };
        let valid_name = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                // `!` is legal in compiled category names (e.g. the
                // Loyalsoldier `geolocation-!cn` lists ship a literal
                // category literally named `geolocation-!cn`).
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'!'));
        let valid_attr = attr.is_none_or(|attr| {
            !attr.is_empty()
                && attr.len() <= 32
                && attr.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*' | b'.')
                })
        });
        if !valid_name || !valid_attr {
            return Err(invalid_input("invalid geosite category"));
        }
        return Ok(Some(("domain", selector.to_string())));
    }
    if let Some(code) = selector.strip_prefix("geoip:") {
        // Countries are the common case, but profiles may ship custom
        // geoip.dat files defining arbitrary categories (e.g. `direct`) —
        // Xray resolves the code against the actually loaded asset.
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(invalid_input("invalid geoip code"));
        }
        return Ok(Some(("ip", selector.to_string())));
    }
    if let Ok(ip) = selector.parse::<IpAddr>() {
        return Ok(Some(("ip", ip.to_string())));
    }
    if let Ok(net) = IpNet::from_str(selector) {
        return Ok(Some(("ip", net.to_string())));
    }
    Ok(Some(("domain", selector.to_string())))
}

const DNS_SCHEMES: &[&str] = &["udp", "tcp", "tls", "https", "https+local", "quic+local"];

pub fn validate_dns_config(dns: &XrayDnsConfig) -> io::Result<()> {
    if dns
        .outbound_key
        .as_ref()
        .is_some_and(|key| !crate::subscription::valid_endpoint_key(key))
    {
        return Err(invalid_input("invalid DNS egress endpoint key"));
    }
    if let Some(outbound) = &dns.outbound {
        if outbound.rewrite_port == Some(0)
            || outbound
                .rewrite_network
                .as_deref()
                .is_some_and(|network| !matches!(network, "tcp" | "udp"))
            || outbound.rewrite_address.as_deref().is_some_and(|address| {
                address.parse::<IpAddr>().is_err()
                    && (address.is_empty()
                        || address.len() > 253
                        || !address.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                        }))
            })
            || outbound.rules.len() > 64
        {
            return Err(invalid_input("invalid DNS outbound rewrite settings"));
        }
        for rule in &outbound.rules {
            if !matches!(
                rule.action.as_str(),
                "direct" | "drop" | "return" | "hijack"
            ) || rule.domain.len() > 128
                || rule.q_type.as_deref().is_some_and(|types| {
                    types.len() > 128 || types.split(',').any(|value| value.parse::<u16>().is_err())
                })
            {
                return Err(invalid_input("invalid DNS outbound rewrite rule"));
            }
            for domain in &rule.domain {
                if !matches!(classify_routing_selector(domain)?, Some(("domain", _))) {
                    return Err(invalid_input("DNS rewrite rules require domain selectors"));
                }
            }
        }
    }
    for server in &dns.servers {
        let address = server.address.trim();
        if address.is_empty()
            || address.len() > 256
            || !address.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid_input("invalid dns server address"));
        }
        match address {
            "localhost" => {}
            "fakedns" if dns.fake_dns => {}
            "fakedns" => return Err(invalid_input("fakedns server requires fakeDns")),
            _ => {
                if let Some((scheme, _)) = address.split_once("://") {
                    if !DNS_SCHEMES.contains(&scheme) {
                        return Err(invalid_input("unsupported dns server scheme"));
                    }
                }
                if dns_server_host(address).is_none() {
                    return Err(invalid_input("invalid dns server address"));
                }
            }
        }
        if server.port == Some(0) {
            return Err(invalid_input("dns server port must be nonzero"));
        }
        for selector in &server.domains {
            // dns.servers `domains` takes domain matchers only — geosite
            // categories and literal domain forms, never IP selectors.
            if matches!(classify_routing_selector(selector)?, Some(("ip", _))) {
                return Err(invalid_input("dns server domains must be domain selectors"));
            }
        }
    }
    for (name, values) in &dns.hosts {
        let name = name.trim();
        if name.is_empty() || name.len() > 253 || !name.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid_input("invalid dns hosts entry"));
        }
        if values.is_empty() {
            return Err(invalid_input("dns hosts entry must map to an address"));
        }
        for value in values {
            let value = value.trim();
            let ok = value.parse::<IpAddr>().is_ok()
                || (!value.is_empty()
                    && value.len() <= 253
                    && value.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*')
                    }));
            if !ok {
                return Err(invalid_input("invalid dns hosts value"));
            }
        }
    }
    Ok(())
}

/// Host part of a DNS server entry, dropping scheme/userinfo/port/path.
/// `udp://` and bare values share the same `host[:port]` shape.
fn dns_server_host(address: &str) -> Option<&str> {
    let rest = match address.split_once("://") {
        Some((_, rest)) => rest,
        None => address,
    };
    let host = rest.split(['/', '?', '#']).next()?.trim();
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = if let Some(inner) = host.strip_prefix('[') {
        inner.split(']').next()?
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    };
    (!host.is_empty()).then_some(host)
}

/// Resolver hosts that must stay reachable through the physical uplink when
/// the tunnel fully captures their family — every configured resolver that
/// is not pinned to the proxy outbound (a `Proxy` resolver is meant to be
/// reached *inside* the tunnel, so bypassing it would defeat the point).
/// Returned as a deduped list of literal IPs or resolvable names.
pub fn dns_bypass_hosts(dns: &XrayDnsConfig) -> Vec<String> {
    let mut hosts = Vec::new();
    for server in &dns.servers {
        if matches!(server.route, crate::models::XrayDnsRoute::Proxy) {
            continue;
        }
        let Some(host) = dns_server_host(&server.address) else {
            continue;
        };
        if matches!(host, "localhost" | "fakedns") || hosts.iter().any(|item| item == host) {
            continue;
        }
        hosts.push(host.to_string());
    }
    hosts
}

/// The routable destination of a DNS server entry: `None` for
/// `localhost`/`fakedns`, which Xray handles internally.
pub(crate) fn dns_server_route_target(address: &str) -> Option<(&'static str, String)> {
    let host = dns_server_host(address)?;
    if matches!(host, "localhost" | "fakedns") {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(("ip", ip.to_string()));
    }
    Some(("domain", host.to_string()))
}

/// Block-target selectors that can also be null-routed through the DNS
/// `hosts` table — plain names and `domain:`/`full:` literals only (a
/// geosite/keyword/regexp matcher cannot be expressed as a hosts key).
fn dns_hosts_key(selector: &str) -> Option<String> {
    let selector = selector.trim();
    if selector.is_empty() || selector.starts_with('#') {
        return None;
    }
    for prefix in ["domain:", "full:"] {
        if let Some(rest) = selector.strip_prefix(prefix) {
            let rest = rest.trim();
            return (!rest.is_empty()).then(|| rest.to_string());
        }
    }
    if selector.contains(':') || selector.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(selector.to_string())
}

fn dns_server_entry(server: &XrayDnsServer, policies: &[DomainPolicy]) -> Value {
    let mut entry = Map::new();
    entry.insert("address".into(), json!(server.address.trim()));
    if let Some(port) = server.port {
        entry.insert("port".into(), json!(port));
    }
    let mut domains = server.domains.clone();
    // Split-DNS default: a resolver pinned to an outbound also answers the
    // domains routed through it — remote/proxy lists and domestic/direct
    // lists stay on their own resolver.
    if domains.is_empty() {
        let target = match server.route {
            XrayDnsRoute::Proxy => Some(DomainRouteTarget::Proxy),
            XrayDnsRoute::Direct => Some(DomainRouteTarget::Direct),
            XrayDnsRoute::None => None,
        };
        if let Some(target) = target {
            for policy in policies.iter().filter(|policy| policy.target == target) {
                for selector in &policy.domains {
                    if let Ok(Some(("domain", value))) = classify_routing_selector(selector) {
                        domains.push(value);
                    }
                }
            }
        }
    }
    if !domains.is_empty() {
        entry.insert("domains".into(), json!(domains));
    }
    if server.skip_fallback {
        entry.insert("skipFallback".into(), json!(true));
    }
    Value::Object(entry)
}

fn dns_servers_json(dns: &XrayDnsConfig, policies: &[DomainPolicy]) -> Vec<Value> {
    let mut servers = Vec::new();
    if dns.fake_dns {
        servers.push(json!("fakedns"));
    }
    for server in &dns.servers {
        servers.push(dns_server_entry(server, policies));
    }
    // Xray walks servers in order and domain-bound entries only answer
    // their own list — when nothing is left as a catch-all, mirror the
    // first proxy-routed (else first) server as a bare fallback.
    let has_catch_all = servers
        .iter()
        .any(|s| s.as_str().is_some() || s.get("domains").is_none());
    if !has_catch_all {
        let catch_all = dns
            .servers
            .iter()
            .find(|server| server.route == XrayDnsRoute::Proxy)
            .or_else(|| dns.servers.first());
        if let Some(catch_all) = catch_all {
            servers.insert(
                usize::from(dns.fake_dns),
                json!({"address": catch_all.address.trim()}),
            );
        }
    }
    servers
}

pub fn validate_stream_sockopts(sockopts: &XraySockopts) -> io::Result<()> {
    if sockopts
        .tcp_user_timeout
        .is_some_and(|milliseconds| milliseconds > 3_600_000)
    {
        return Err(invalid_input("TCP user timeout must not exceed one hour"));
    }
    Ok(())
}

fn validate_outbound_domain_strategy(strategy: Option<&str>) -> io::Result<()> {
    if strategy.is_some_and(|strategy| {
        !matches!(
            strategy,
            "UseIP" | "UseIPv4" | "UseIPv6" | "ForceIP" | "ForceIPv4" | "ForceIPv6"
        )
    }) {
        return Err(invalid_input("unsupported outbound domain strategy"));
    }
    Ok(())
}

pub fn validate_advanced_routing_options(
    traffic_rules: &[XrayTrafficRule],
    interface_routes: &[crate::models::XrayInterfaceRoute],
    sockopts: Option<&XraySockopts>,
    connection_idle_secs: Option<u32>,
    direct_domain_strategy: Option<&str>,
) -> io::Result<()> {
    if connection_idle_secs.is_some_and(|seconds| seconds > 86_400) {
        return Err(invalid_input(
            "connection idle timeout must not exceed one day",
        ));
    }

    validate_outbound_domain_strategy(direct_domain_strategy)?;

    if let Some(sockopts) = sockopts {
        validate_stream_sockopts(sockopts)?;
    }

    if interface_routes.len() > 16 {
        return Err(invalid_input(
            "at most 16 interface-bound policies are supported",
        ));
    }

    for route in interface_routes {
        let name = &route.interface_name;
        if name.is_empty()
            || name.len() > 15
            || name.starts_with('-')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || route.selectors.is_empty()
        {
            return Err(invalid_input("invalid interface-bound policy"));
        }

        validate_outbound_domain_strategy(route.domain_strategy.as_deref())?;

        let mut domains = 0;
        let mut ips = 0;
        for selector in &route.selectors {
            match classify_routing_selector(selector)? {
                Some(("domain", _)) => domains += 1,
                Some(("ip", _)) => ips += 1,
                None => {}
                _ => return Err(invalid_input("unsupported routing selector")),
            }
        }
        if domains + ips == 0 || domains > 128 || ips > 128 {
            return Err(invalid_input(
                "interface-bound policy needs 1-128 selectors per emitted rule",
            ));
        }
    }

    if traffic_rules.len() > 32 {
        return Err(invalid_input("at most 32 IP/port guards are supported"));
    }

    for rule in traffic_rules {
        if rule.port == 0
            || rule.ips.is_empty()
            || rule.ips.len() > 128
            || !matches!(rule.network.as_str(), "tcp" | "udp" | "tcp,udp")
        {
            return Err(invalid_input("invalid IP/port guard"));
        }
        for selector in &rule.ips {
            if !matches!(classify_routing_selector(selector)?, Some(("ip", _))) {
                return Err(invalid_input("IP/port guards require IP selectors"));
            }
        }
    }

    Ok(())
}

pub fn validate_tun_profile_settings(mtu: Option<u32>, dns_servers: &[IpAddr]) -> io::Result<()> {
    if mtu.is_some_and(|mtu| !(1280..=9000).contains(&mtu)) {
        return Err(invalid_input("TUN MTU must be 1280-9000"));
    }
    if dns_servers.len() > 8
        || dns_servers
            .iter()
            .any(|server| server.is_unspecified() || server.is_multicast())
    {
        return Err(invalid_input(
            "TUN DNS needs at most eight unicast IP addresses",
        ));
    }
    Ok(())
}

pub fn validate_pinned_routes(routes: &[crate::models::PinnedRoute]) -> io::Result<()> {
    if routes.len() > 32 {
        return Err(invalid_input("at most 32 pinned routes are supported"));
    }
    for route in routes {
        if !crate::subscription::valid_endpoint_key(&route.endpoint_key)
            || route.selectors.is_empty()
            || route.selectors.len() > 128
        {
            return Err(invalid_input("invalid pinned route"));
        }

        let mut has_selector = false;
        for selector in &route.selectors {
            match classify_routing_selector(selector)? {
                Some(("domain", _)) => has_selector = true,
                None => {}
                _ => {
                    return Err(invalid_input("pinned routes require domain selectors"));
                }
            }
        }
        if !has_selector {
            return Err(invalid_input("pinned route has no selectors"));
        }
    }
    Ok(())
}

pub fn apply_profile_routing(
    base: &Value,
    policies: &[DomainPolicy],
    options: &ProfileRoutingOptions,
) -> io::Result<Value> {
    let dns_active = !options.dns.is_empty();
    let rules_active = !policies.is_empty()
        || options.private_lan_direct
        || dns_active
        || !options.traffic_rules.is_empty()
        || !options.interface_routes.is_empty();
    if !rules_active
        && options.domain_strategy.is_none()
        && options.domain_matcher.is_none()
        && options.sockopts.is_none()
        && options.connection_idle_secs.is_none()
        && options.direct_domain_strategy.is_none()
    {
        return Ok(base.clone());
    }
    validate_routing_policy_selectors(policies)?;
    validate_dns_config(&options.dns)?;
    validate_advanced_routing_options(
        &options.traffic_rules,
        &options.interface_routes,
        options.sockopts.as_ref(),
        options.connection_idle_secs,
        options.direct_domain_strategy.as_deref(),
    )?;
    let mut doc = base.clone();
    let root = doc
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config root must be an object"))?;
    let outbounds = root
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_data("xray config outbounds must be an array"))?;

    let needs_proxy = policies
        .iter()
        .any(|policy| policy.target == DomainRouteTarget::Proxy)
        || options
            .dns
            .servers
            .iter()
            .any(|server| server.route == XrayDnsRoute::Proxy);
    let needs_proxy = needs_proxy
        || options
            .traffic_rules
            .iter()
            .any(|rule| rule.target == DomainRouteTarget::Proxy);
    let needs_direct = options.private_lan_direct
        || policies
            .iter()
            .any(|policy| policy.target == DomainRouteTarget::Direct)
        || options
            .dns
            .servers
            .iter()
            .any(|server| server.route == XrayDnsRoute::Direct);
    let needs_direct = needs_direct
        || options
            .traffic_rules
            .iter()
            .any(|rule| rule.target == DomainRouteTarget::Direct);
    // Any customised rule set also drops multicast, so the blackhole
    // outbound is always required once rules are emitted.
    let needs_block = rules_active;

    let mut counts: HashMap<String, usize> = HashMap::new();
    for tag in outbounds
        .iter()
        .filter_map(|outbound| outbound["tag"].as_str())
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
    {
        *counts.entry(tag.to_string()).or_default() += 1;
    }
    let mut used: HashSet<String> = counts.keys().cloned().collect();

    let proxy_tag = if needs_proxy {
        let index = outbounds
            .iter()
            .position(|outbound| match outbound["protocol"].as_str() {
                Some(protocol) => {
                    !protocol.trim().is_empty()
                        && !matches!(protocol, "freedom" | "blackhole" | "dns")
                }
                None => false,
            })
            .ok_or_else(|| invalid_data("no eligible proxy outbound for domain policy"))?;
        Some(resolve_outbound_tag(
            &mut outbounds[index],
            "network-orchestrator-proxy",
            &counts,
            &mut used,
        ))
    } else {
        None
    };

    let direct_tag = if needs_direct {
        let index = match outbounds
            .iter()
            .position(|outbound| outbound["protocol"].as_str() == Some("freedom"))
        {
            Some(index) => index,
            None => {
                outbounds.push(json!({ "protocol": "freedom" }));
                outbounds.len() - 1
            }
        };
        Some(resolve_outbound_tag(
            &mut outbounds[index],
            "network-orchestrator-direct",
            &counts,
            &mut used,
        ))
    } else {
        None
    };

    let block_tag = if needs_block {
        let index = match outbounds
            .iter()
            .position(|outbound| outbound["protocol"].as_str() == Some("blackhole"))
        {
            Some(index) => index,
            None => {
                outbounds.push(json!({ "protocol": "blackhole" }));
                outbounds.len() - 1
            }
        };
        Some(resolve_outbound_tag(
            &mut outbounds[index],
            "network-orchestrator-block",
            &counts,
            &mut used,
        ))
    } else {
        None
    };

    let dns_tag = if dns_active {
        let index = match outbounds
            .iter()
            .position(|outbound| outbound["protocol"].as_str() == Some("dns"))
        {
            Some(index) => index,
            None => {
                outbounds.push(json!({ "protocol": "dns" }));
                outbounds.len() - 1
            }
        };
        Some(resolve_outbound_tag(
            &mut outbounds[index],
            "dns-out",
            &counts,
            &mut used,
        ))
    } else {
        None
    };
    if let Some(settings) = &options.dns.outbound {
        if let Some(index) = outbounds
            .iter()
            .position(|outbound| outbound["protocol"] == "dns")
        {
            outbounds[index]["settings"] = json!(settings);
        }
    }
    if let Some(key) = &options.dns.outbound_key {
        if let Some(index) = outbounds
            .iter()
            .position(|outbound| outbound["protocol"] == "dns")
        {
            outbounds[index]["streamSettings"] = json!({"sockopt": {"dialerProxy": pin_tag(key)}});
        }
    }
    if let Some(strategy) = &options.direct_domain_strategy {
        for outbound in outbounds
            .iter_mut()
            .filter(|outbound| outbound["protocol"] == "freedom")
        {
            let object = outbound
                .as_object_mut()
                .ok_or_else(|| invalid_data("invalid direct outbound"))?;
            let stream = object
                .entry("streamSettings")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(|| invalid_data("invalid direct stream settings"))?;
            let sockopt = stream
                .entry("sockopt")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(|| invalid_data("invalid direct socket options"))?;
            sockopt.insert("domainStrategy".into(), json!(strategy));
        }
    }

    let mut interface_tags = HashMap::new();
    for route in &options.interface_routes {
        let identity = (
            route.interface_name.as_str(),
            route.domain_strategy.as_deref(),
        );
        if interface_tags.contains_key(&identity) {
            continue;
        }
        let mut outbound = json!({"protocol": "freedom", "streamSettings": {"sockopt": {"interface": route.interface_name}}});
        if let Some(strategy) = &route.domain_strategy {
            outbound["streamSettings"]["sockopt"]["domainStrategy"] = json!(strategy);
        }
        let tag = resolve_outbound_tag(
            &mut outbound,
            "network-orchestrator-interface",
            &counts,
            &mut used,
        );
        outbounds.push(outbound);
        interface_tags.insert(identity, tag);
    }
    if let Some(sockopts) = &options.sockopts {
        for outbound in outbounds.iter_mut() {
            let protocol = outbound["protocol"].as_str().unwrap_or_default();
            if matches!(protocol, "blackhole" | "dns" | "loopback" | "") {
                continue;
            }
            apply_stream_sockopts(outbound, sockopts)?;
        }
    }
    if let Some(seconds) = options.connection_idle_secs {
        root.insert(
            "policy".into(),
            json!({"levels": {"0": {"connIdle": seconds}}}),
        );
    }

    let routing = root.entry("routing").or_insert_with(|| json!({}));
    let routing = routing
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config routing must be an object"))?;
    if let Some(strategy) = options.domain_strategy {
        routing.insert("domainStrategy".into(), json!(strategy.as_xray_str()));
    }
    if let Some(matcher) = options.domain_matcher {
        routing.insert("domainMatcher".into(), json!(matcher.as_xray_str()));
    }
    let rules = routing.entry("rules").or_insert_with(|| json!([]));
    let rules = rules
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config routing.rules must be an array"))?;

    let mut merged = Vec::new();
    for guard in &options.traffic_rules {
        let tag = match guard.target {
            DomainRouteTarget::Proxy => proxy_tag.as_deref().unwrap_or_default(),
            DomainRouteTarget::Direct => direct_tag.as_deref().unwrap_or_default(),
            DomainRouteTarget::Block => block_tag.as_deref().unwrap_or_default(),
        };
        merged.push(
            json!({"type": "field", "ip": guard.ips, "port": guard.port.to_string(),
            "network": guard.network, "outboundTag": tag}),
        );
    }
    // DNS capture comes first: port-53 traffic is answered by the dns
    // outbound so static hosts / split resolvers / fake-DNS apply even to
    // plain system resolvers (TUN mode).
    if let Some(tag) = dns_tag.as_deref() {
        merged.push(json!({"type": "field", "port": "53", "outboundTag": tag}));
    }
    for route in &options.interface_routes {
        let tag = &interface_tags[&(
            route.interface_name.as_str(),
            route.domain_strategy.as_deref(),
        )];
        let mut domains = Vec::new();
        let mut ips = Vec::new();
        for selector in &route.selectors {
            if let Some((kind, value)) = classify_routing_selector(selector)? {
                if kind == "ip" {
                    ips.push(value);
                } else {
                    domains.push(value);
                }
            }
        }
        if !domains.is_empty() {
            merged.push(json!({"type": "field", "domain": domains, "outboundTag": tag}));
        }
        if !ips.is_empty() {
            merged.push(json!({"type": "field", "ip": ips, "outboundTag": tag}));
        }
    }
    for policy in policies {
        let tag = match policy.target {
            DomainRouteTarget::Proxy => proxy_tag.as_deref().unwrap_or_default(),
            DomainRouteTarget::Direct => direct_tag.as_deref().unwrap_or_default(),
            DomainRouteTarget::Block => block_tag.as_deref().unwrap_or_default(),
        };
        let mut domains = Vec::new();
        let mut ips = Vec::new();
        for selector in &policy.domains {
            let Some((kind, value)) = classify_routing_selector(selector)? else {
                continue;
            };
            if kind == "ip" {
                ips.push(value);
            } else {
                domains.push(value);
            }
        }
        if !domains.is_empty() {
            merged.push(json!({"type": "field", "domain": domains, "outboundTag": tag}));
        }
        if !ips.is_empty() {
            merged.push(json!({"type": "field", "ip": ips, "outboundTag": tag}));
        }
    }
    // Keep each resolver reachable on its own side of the tunnel: the
    // resolver pinned to `proxy` must not resolve via the local network and
    // vice versa.
    for server in &options.dns.servers {
        let tag = match server.route {
            XrayDnsRoute::Proxy => proxy_tag.as_deref().unwrap_or_default(),
            XrayDnsRoute::Direct => direct_tag.as_deref().unwrap_or_default(),
            XrayDnsRoute::None => continue,
        };
        match dns_server_route_target(&server.address) {
            Some(("ip", value)) => {
                merged.push(json!({"type": "field", "ip": [value], "outboundTag": tag}));
            }
            Some(("domain", value)) => {
                merged.push(json!({"type": "field", "domain": [value], "outboundTag": tag}));
            }
            _ => {}
        }
    }
    // Multicast is never routed through the tunnel — emit only when some
    // other rule set exists so a comment-only policy stays a no-op.
    if !merged.is_empty() || options.private_lan_direct {
        merged.push(json!({
            "type": "field",
            "ip": ["224.0.0.0/4", "ff00::/8"],
            "outboundTag": block_tag.as_deref().unwrap_or_default(),
        }));
    }
    if options.private_lan_direct {
        merged.push(json!({
            "type": "field",
            "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"],
            "outboundTag": direct_tag.as_deref().unwrap_or_default(),
        }));
    }
    merged.append(rules);
    *rules = merged;

    if dns_active {
        let mut hosts = Map::new();
        // Blocked literal domains are also null-routed at the resolver —
        // a client ignoring routing still gets a dead answer.
        for policy in policies
            .iter()
            .filter(|policy| policy.target == DomainRouteTarget::Block)
        {
            for selector in &policy.domains {
                if let Some(host) = dns_hosts_key(selector) {
                    hosts.entry(host).or_insert_with(|| json!(["127.0.0.1"]));
                }
            }
        }
        // Explicit host overrides win over the generated null routes.
        for (name, values) in &options.dns.hosts {
            hosts.insert(name.clone(), json!(values));
        }
        let mut dns_obj = Map::new();
        if !hosts.is_empty() {
            dns_obj.insert("hosts".into(), Value::Object(hosts));
        }
        let servers = dns_servers_json(&options.dns, policies);
        if !servers.is_empty() {
            dns_obj.insert("servers".into(), json!(servers));
        }
        if let Some(strategy) = options.dns.query_strategy {
            dns_obj.insert("queryStrategy".into(), json!(strategy.as_xray_str()));
        }
        if let Some(parallel) = options.dns.enable_parallel_query {
            dns_obj.insert("enableParallelQuery".into(), json!(parallel));
        }
        root.insert("dns".into(), Value::Object(dns_obj));

        if options.dns.fake_dns {
            root.insert(
                "fakedns".into(),
                json!([{ "ipPool": "198.18.0.0/16", "poolSize": 65535 }]),
            );
            // Sniffing must translate fake pool answers back to the real
            // name on every inbound that sees them.
            if let Some(inbounds) = root.get_mut("inbounds").and_then(Value::as_array_mut) {
                for inbound in inbounds.iter_mut() {
                    let sniffing = inbound
                        .as_object_mut()
                        .map(|obj| obj.entry("sniffing").or_insert_with(|| json!({})))
                        .and_then(|s| s.as_object_mut());
                    let Some(sniffing) = sniffing else { continue };
                    sniffing.insert("enabled".into(), json!(true));
                    let overrides = sniffing.entry("destOverride").or_insert_with(|| json!([]));
                    if let Some(list) = overrides.as_array_mut() {
                        if !list.iter().any(|v| v == "fakedns") {
                            list.push(json!("fakedns"));
                        }
                    }
                }
            }
        }
    }
    Ok(doc)
}

/// Merge profile `XraySockopts` into one outbound's `streamSettings.sockopt`:
/// keepalive seconds and user timeout (xray's millisecond unit) plus
/// `tcpNoDelay`. Existing sockopt keys we do not model are preserved.
pub fn apply_stream_sockopts(outbound: &mut Value, sockopts: &XraySockopts) -> io::Result<()> {
    validate_stream_sockopts(sockopts)?;

    let object = outbound
        .as_object_mut()
        .ok_or_else(|| invalid_data("outbound must be an object"))?;

    if let Some(stream) = object.get("streamSettings") {
        let stream = stream
            .as_object()
            .ok_or_else(|| invalid_data("streamSettings must be an object"))?;
        if stream
            .get("sockopt")
            .is_some_and(|value| !value.is_object())
        {
            return Err(invalid_data("sockopt must be an object"));
        }
    }

    let stream = object
        .entry("streamSettings")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid_data("streamSettings must be an object"))?;
    let sockopt = stream
        .entry("sockopt")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid_data("sockopt must be an object"))?;

    if let Some(idle) = sockopts.tcp_keep_alive_idle {
        sockopt.insert("tcpKeepAliveIdle".into(), json!(idle));
    }
    if let Some(interval) = sockopts.tcp_keep_alive_interval {
        sockopt.insert("tcpKeepAliveInterval".into(), json!(interval));
    }
    if let Some(timeout) = sockopts.tcp_user_timeout {
        sockopt.insert("tcpUserTimeout".into(), json!(timeout));
    }
    sockopt.insert("tcpNoDelay".into(), json!(sockopts.tcp_no_delay));

    Ok(())
}

/// Replace the SOCKS inbound in an Xray config with a TUN inbound (Wintun on
/// Windows). If no inbound exists, a TUN inbound is added. The TUN interface
/// captures all IP traffic at the interface level, making Xray a full-tunnel
/// backend. The `interface_name` and `ip` parameters configure the TUN
/// adapter; if `None`, sensible defaults are used.
pub fn apply_tun_inbound(
    base: &Value,
    interface_name: Option<&str>,
    ip: Option<&str>,
) -> io::Result<Value> {
    let mut doc = base.clone();
    let root = doc
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config root must be an object"))?;
    let inbounds = root
        .entry("inbounds")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config inbounds must be an array"))?;

    // Remove existing SOCKS inbound(s) — TUN mode replaces system-proxy-based
    // traffic capture with interface-level capture.
    inbounds.retain(|inbound| inbound["protocol"].as_str() != Some("socks"));

    // TUN traffic arrives as bare IP packets; sniffing recovers the TLS
    // SNI / HTTP Host so domain and geosite routing rules can match. With
    // fake-DNS enabled it also translates pool answers back to real names.
    let mut dest_override = vec!["http", "tls", "quic"];
    if base["fakedns"]
        .as_array()
        .is_some_and(|fakedns| !fakedns.is_empty())
    {
        dest_override.push("fakedns");
    }

    let tun_inbound = json!({
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {
            "interfaceName": interface_name.unwrap_or("xray-tun"),
            "ip": ip.unwrap_or("172.19.0.1/30"),
            "mtu": 1500,
        },
        "sniffing": {
            "enabled": true,
            "destOverride": dest_override,
        },
    });
    inbounds.insert(0, tun_inbound);
    Ok(doc)
}

/// Replace the SOCKS inbound in an Xray config with the TUN inbound used for
/// macOS full-tunnel operation. The privileged helper creates the `utun`
/// device and hands its fd to Xray through `XRAY_TUN_FD`, so the settings
/// carry only what Xray consumes in that mode: the stack `mtu` and
/// `autoOutboundsInterface`. The latter binds every outbound dial Xray makes
/// itself (proxy endpoint, direct/freedom, resolvers) to the physical
/// uplink via `IP_BOUND_IF` — loop prevention, since a full tunnel would
/// otherwise feed `direct` traffic straight back into the utun.
pub fn apply_macos_tun_inbound(base: &Value, mtu: u32, uplink: &str) -> io::Result<Value> {
    let uplink = uplink.trim();
    if uplink.is_empty()
        || uplink.len() > 15
        || !uplink
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return Err(invalid_input("invalid uplink interface name"));
    }
    if !(512..=9000).contains(&mtu) {
        return Err(invalid_input("invalid TUN MTU"));
    }
    let mut doc = base.clone();
    let root = doc
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config root must be an object"))?;
    let inbounds = root
        .entry("inbounds")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config inbounds must be an array"))?;

    inbounds.retain(|inbound| inbound["protocol"].as_str() != Some("socks"));

    // TUN traffic arrives as bare IP packets; sniffing recovers the TLS
    // SNI / HTTP Host so domain and geosite routing rules can match. With
    // fake-DNS enabled it also translates pool answers back to real names.
    let mut dest_override = vec!["http", "tls", "quic"];
    if base["fakedns"]
        .as_array()
        .is_some_and(|fakedns| !fakedns.is_empty())
    {
        dest_override.push("fakedns");
    }

    let tun_inbound = json!({
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {
            "mtu": mtu,
            "autoOutboundsInterface": uplink,
        },
        "sniffing": {
            "enabled": true,
            "destOverride": dest_override,
        },
    });
    inbounds.insert(0, tun_inbound);
    Ok(doc)
}

/// Resolver the tunnel's own lookups use for everything that is not pinned to
/// the local network; plain TCP-over-HTTPS so it works through any proxy.
const MACOS_REMOTE_DNS: &str = "https://1.1.1.1/dns-query";
/// Gateway of the helper-created utun; the system DNS is pointed here.
const MACOS_TUNNEL_RESOLVER: &str = "169.254.10.1";
const MACOS_REMOTE_DNS_IP: &str = "1.1.1.1";

fn outbound_tag(outbound: &Value) -> Option<&str> {
    outbound["tag"]
        .as_str()
        .filter(|tag| !tag.trim().is_empty())
}

/// Make Xray answer the system's DNS on macOS and keep domain rules working.
///
/// The helper points the uplink's service at the tunnel gateway, so every
/// lookup arrives on `tun-in` as a packet for `169.254.10.1:53`. Unless a
/// `dns` outbound answers it, routing sends it `direct` to a gateway that does
/// not exist: no name resolves and every domain rule goes quiet.
///
/// Added, never replacing what the profile defines:
/// - when the profile does not route DNS itself: a `dns` outbound, a first rule
///   sending `tun-in` traffic for the tunnel resolver to it, and `dns.servers`
///   (a remote resolver through the proxy);
/// - a `direct` rule for `local_domains` (the network's search domains), and
///   `dns.servers` entries sending those names plus the profile's direct names
///   to the local network's resolvers, which are pinned `direct`;
/// - `domainStrategy: UseIP` on `freedom`, so a direct connection to a name is
///   resolved by Xray (the OS resolver points back at this tunnel);
/// - fake-DNS for every name the profile routes `direct`/`block`, so protocols
///   without SNI (SSH) still match their rule, see
///   [`add_fake_dns_for_routed_domains`];
/// - those names in the `hijack` rules of a profile `dns` outbound that
///   forwards everything else to a fixed resolver, otherwise they would never
///   reach the fake-DNS engine.
pub fn apply_macos_dns_capture(
    base: &Value,
    local_resolvers: &[IpAddr],
    local_domains: &[String],
) -> io::Result<Value> {
    let mut doc = base.clone();
    let root = doc
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config root must be an object"))?;
    let existing_rules = root
        .get("routing")
        .and_then(|routing| routing.get("rules"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let outbounds = root
        .entry("outbounds")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config outbounds must be an array"))?;

    let dns_outbound_tags: HashSet<String> = outbounds
        .iter()
        .filter(|outbound| outbound["protocol"].as_str() == Some("dns"))
        .filter_map(|outbound| outbound_tag(outbound).map(str::to_string))
        .collect();
    let already_captured = existing_rules.iter().any(|rule| {
        rule["port"]
            .as_str()
            .or_else(|| rule["port"].as_u64().map(|_| "53"))
            == Some("53")
            && rule["outboundTag"]
                .as_str()
                .is_some_and(|tag| dns_outbound_tags.contains(tag))
    });

    let mut taken: HashSet<String> = outbounds
        .iter()
        .filter_map(|outbound| outbound_tag(outbound).map(str::to_string))
        .collect();
    let mut fresh_tag = |wanted: &str| {
        let mut tag = wanted.to_string();
        let mut n = 2;
        while taken.contains(&tag) {
            tag = format!("{wanted}-{n}");
            n += 1;
        }
        taken.insert(tag.clone());
        tag
    };

    // Outbounds: reuse what exists (naming it when it has no tag), add what is missing.
    let dns_tag = if already_captured {
        None
    } else {
        Some(
            match outbounds
                .iter()
                .position(|outbound| outbound["protocol"].as_str() == Some("dns"))
            {
                Some(index) => match outbound_tag(&outbounds[index]) {
                    Some(tag) => tag.to_string(),
                    None => {
                        let tag = fresh_tag("dns-out");
                        outbounds[index]["tag"] = json!(tag);
                        tag
                    }
                },
                None => {
                    let tag = fresh_tag("dns-out");
                    outbounds.push(json!({"protocol": "dns", "tag": tag}));
                    tag
                }
            },
        )
    };
    let direct_index = match outbounds
        .iter()
        .position(|outbound| outbound["protocol"].as_str() == Some("freedom"))
    {
        Some(index) => index,
        None => {
            let tag = fresh_tag("direct");
            outbounds.push(json!({"protocol": "freedom", "tag": tag}));
            outbounds.len() - 1
        }
    };
    let direct_tag = match outbound_tag(&outbounds[direct_index]) {
        Some(tag) => tag.to_string(),
        None => {
            let tag = fresh_tag("direct");
            outbounds[direct_index]["tag"] = json!(tag);
            tag
        }
    };
    let proxy_tag = if dns_tag.is_some() {
        outbounds
            .iter()
            .position(|outbound| {
                outbound["protocol"]
                    .as_str()
                    .is_some_and(|protocol| !matches!(protocol, "freedom" | "blackhole" | "dns"))
            })
            .map(|index| match outbound_tag(&outbounds[index]) {
                Some(tag) => tag.to_string(),
                None => {
                    let tag = fresh_tag("proxy");
                    outbounds[index]["tag"] = json!(tag);
                    tag
                }
            })
    } else {
        None
    };

    // The names that live on the local network: what the profile routes
    // direct, plus the network's own search domains.
    let search: Vec<Value> = local_domains
        .iter()
        .map(|domain| json!(format!("domain:{}", domain.trim_start_matches('.'))))
        .collect();
    let mut local_names: Vec<Value> = existing_rules
        .iter()
        .filter(|rule| rule["outboundTag"].as_str() == Some(direct_tag.as_str()))
        .filter_map(|rule| rule["domain"].as_array())
        .flatten()
        .cloned()
        .collect();
    for name in &search {
        if !local_names.contains(name) {
            local_names.push(name.clone());
        }
    }

    let mut rules: Vec<Value> = Vec::new();
    if let Some(tag) = &dns_tag {
        // Only lookups addressed to the tunnel's own resolver (the address the
        // system DNS points at) are answered here; an app asking some other
        // resolver keeps its normal routing.
        rules.push(json!({
            "type": "field",
            "inboundTag": ["tun-in"],
            "ip": [MACOS_TUNNEL_RESOLVER],
            "port": "53",
            "outboundTag": tag,
        }));
    }
    for resolver in local_resolvers {
        rules.push(
            json!({"type": "field", "ip": [resolver.to_string()], "outboundTag": direct_tag}),
        );
    }
    if !search.is_empty() {
        rules.push(json!({"type": "field", "domain": search, "outboundTag": direct_tag}));
    }
    if let (Some(tag), true) = (&proxy_tag, dns_tag.is_some()) {
        rules.push(json!({"type": "field", "ip": [MACOS_REMOTE_DNS_IP], "outboundTag": tag}));
    }

    let routing = root
        .entry("routing")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config routing must be an object"))?;
    let existing = routing
        .entry("rules")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config routing.rules must be an array"))?;
    rules.append(existing);
    *existing = rules;

    // DNS servers, in front of whatever the profile has: local resolvers for
    // the local names; the remote default only when the profile has no servers.
    let mut servers: Vec<Value> = Vec::new();
    if !local_names.is_empty() {
        for resolver in local_resolvers {
            servers.push(json!({
                "address": resolver.to_string(),
                "domains": local_names,
                "skipFallback": true,
            }));
        }
    }
    let dns = root.entry("dns").or_insert_with(|| json!({}));
    let dns = dns
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config dns must be an object"))?;
    match dns.get_mut("servers").and_then(Value::as_array_mut) {
        Some(own) => {
            let mut merged = servers;
            merged.append(own);
            *own = merged;
        }
        None => {
            servers.push(json!(MACOS_REMOTE_DNS));
            dns.insert("servers".into(), Value::Array(servers));
        }
    }

    // `freedom` resolves names through Xray's resolvers (the OS one points back
    // at this tunnel).
    if let Some(outbounds) = root.get_mut("outbounds").and_then(Value::as_array_mut) {
        for outbound in outbounds
            .iter_mut()
            .filter(|outbound| outbound["protocol"].as_str() == Some("freedom"))
        {
            if outbound["settings"]["domainStrategy"].is_null() {
                outbound["settings"]["domainStrategy"] = json!("UseIP");
            }
        }
    }
    let fake_domains = add_fake_dns_for_routed_domains(root);
    hijack_routed_domains(root, &fake_domains);
    Ok(doc)
}

/// Domain rules only see a name when the traffic carries one (TLS SNI, HTTP
/// Host, QUIC); SSH, databases and other plain protocols arrive as a bare IP
/// and fall through to the default outbound. Names the profile routes `direct`
/// or `block` therefore get fake-DNS answers: the tunnel hands out a pool
/// address for them and sniffing (`fakedns`) turns the connection back into the
/// name, whatever the protocol. Returns those names.
///
/// Xray applies the fake server to every lookup its DNS engine answers, not
/// just the listed names; the listed names are what matters for routing.
fn add_fake_dns_for_routed_domains(root: &mut Map<String, Value>) -> Vec<Value> {
    let routed: HashSet<String> = root
        .get("outbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|outbound| {
            matches!(
                outbound["protocol"].as_str(),
                Some("freedom") | Some("blackhole")
            )
        })
        .filter_map(|outbound| outbound_tag(outbound).map(str::to_string))
        .collect();
    let mut domains: Vec<Value> = Vec::new();
    for rule in root
        .get("routing")
        .and_then(|routing| routing.get("rules"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let routed_here = rule["outboundTag"]
            .as_str()
            .is_some_and(|tag| routed.contains(tag));
        if let (true, Some(list)) = (routed_here, rule["domain"].as_array()) {
            for domain in list {
                if !domains.contains(domain) {
                    domains.push(domain.clone());
                }
            }
        }
    }
    if domains.is_empty() || root.contains_key("fakedns") {
        return domains;
    }
    root.insert(
        "fakedns".into(),
        json!([{ "ipPool": "198.18.0.0/16", "poolSize": 65535 }]),
    );
    let dns = root.entry("dns").or_insert_with(|| json!({}));
    if let Some(dns) = dns.as_object_mut() {
        let fake = json!({"address": "fakedns", "domains": domains});
        match dns.get_mut("servers").and_then(Value::as_array_mut) {
            Some(servers) => servers.insert(0, fake),
            None => {
                dns.insert("servers".into(), json!([fake, MACOS_REMOTE_DNS]));
            }
        }
    }
    domains
}

/// A `dns` outbound with `rules` (newer Xray) can answer only some names
/// itself (`hijack`) and forward the rest verbatim to a fixed resolver
/// (`direct`). Those forwarded answers are real addresses, so a name that
/// needs a fake one must be hijacked: a `hijack` rule for it goes in front of
/// the first catch-all `direct` rule (after any `return` rules, which keep
/// refusing e.g. AAAA).
fn hijack_routed_domains(root: &mut Map<String, Value>, domains: &[Value]) {
    if domains.is_empty() {
        return;
    }
    let Some(outbounds) = root.get_mut("outbounds").and_then(Value::as_array_mut) else {
        return;
    };
    for outbound in outbounds
        .iter_mut()
        .filter(|outbound| outbound["protocol"].as_str() == Some("dns"))
    {
        let Some(rules) = outbound["settings"]["rules"].as_array_mut() else {
            continue;
        };
        let Some(at) = rules
            .iter()
            .position(|rule| rule["action"].as_str() == Some("direct"))
        else {
            continue;
        };
        rules.insert(
            at,
            json!({"action": "hijack", "domain": domains, "qType": "1"}),
        );
    }
}

/// Drop every TUN inbound. `xray run -test` with a tun inbound would create a
/// real device (and needs privileges), so validation must run on this form.
pub fn strip_tun_inbound(base: &Value) -> Value {
    let mut doc = base.clone();
    if let Some(inbounds) = doc.get_mut("inbounds").and_then(Value::as_array_mut) {
        inbounds.retain(|inbound| inbound["protocol"].as_str() != Some("tun"));
    }
    doc
}

/// Check whether an Xray config has a TUN inbound.
pub fn has_tun_inbound(config: &Value) -> bool {
    config["inbounds"]
        .as_array()
        .map(|inbounds| {
            inbounds
                .iter()
                .any(|inbound| inbound["protocol"].as_str() == Some("tun"))
        })
        .unwrap_or(false)
}

fn resolve_outbound_tag(
    outbound: &mut Value,
    base_tag: &str,
    counts: &HashMap<String, usize>,
    used: &mut HashSet<String>,
) -> String {
    if let Some(tag) = outbound["tag"]
        .as_str()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
    {
        if counts.get(tag) == Some(&1) {
            return tag.to_string();
        }
    }
    let mut candidate = base_tag.to_string();
    let mut suffix = 2;
    while used.contains(&candidate) {
        candidate = format!("{base_tag}-{suffix}");
        suffix += 1;
    }
    used.insert(candidate.clone());
    outbound["tag"] = json!(candidate.clone());
    candidate
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = char::from(bytes[index + 1]).to_digit(16);
            let low = char::from(bytes[index + 2]).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                decoded.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn endpoint_protocol_labels_links_and_json_entries() {
        assert_eq!(
            endpoint_protocol("vless://id@h:443?security=reality&type=grpc#A").as_deref(),
            Some("VLESS · Reality · GRPC")
        );
        assert_eq!(
            endpoint_protocol("hy2://p@h:443#B").as_deref(),
            Some("Hysteria2")
        );
        let entry = xray_json_entry(&json!({
            "remarks": "NL",
            "outbounds": [{"protocol": "vless", "streamSettings": {"network": "xhttp", "security": "reality"}}]
        }))
        .unwrap();
        assert_eq!(
            endpoint_protocol(&entry).as_deref(),
            Some("VLESS · Reality · XHTTP")
        );
    }

    /// Opt-in pipeline probe: XRAY_PANEL_CONFIG=<managed config>,
    /// XRAY_PROFILES=<profiles.json>, XRAY_PROFILE_ID=<id>, XRAY_PROC_OUT=<out>
    /// applies `apply_profile_routing` exactly like the TUN connect path and
    /// writes the wire-format config to XRAY_PROC_OUT for daemon-side tests.
    /// Skips silently unless all four vars are set.
    #[test]
    fn env_gated_apply_profile_routing_dumps_wire_config() {
        let (Ok(config_path), Ok(profiles_path), Ok(profile_id), Ok(out_path)) = (
            std::env::var("XRAY_PANEL_CONFIG"),
            std::env::var("XRAY_PROFILES"),
            std::env::var("XRAY_PROFILE_ID"),
            std::env::var("XRAY_PROC_OUT"),
        ) else {
            return;
        };
        let base: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&config_path).expect("read panel config"),
        )
        .expect("parse panel config");
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&profiles_path).expect("read profiles"))
                .expect("parse profiles");
        let profiles: Vec<crate::models::Profile> =
            serde_json::from_value(document["profiles"].clone()).expect("parse profile list");
        let profile = profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .expect("profile id");
        let processed = apply_profile_routing(
            &base,
            &profile.domain_policies,
            &ProfileRoutingOptions::from(profile),
        )
        .expect("apply_profile_routing");
        std::fs::write(
            &out_path,
            serde_json::to_string(&processed).expect("encode processed config"),
        )
        .expect("write processed config");
    }

    /// Opt-in: XRAY_TEST_BIN=/path/to/xray validates a panel-style JSON entry.
    #[test]
    fn xray_accepts_generated_panel_json_config_when_binary_supplied() {
        let Ok(binary) = std::env::var("XRAY_TEST_BIN") else {
            return;
        };
        let panel = json!({
            "remarks": "🇳🇱 Netherlands",
            "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
            "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "nl.example.test", "port": 443, "users": [{"id": "00000000-0000-4000-8000-000000000000", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                 "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "www.example.test", "fingerprint": "chrome", "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "shortId": "0123"}}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"}
            ]}
        });
        let entry = xray_json_entry(&panel).unwrap();
        let config = generate_share_link_config_with_http(&entry, 20808, 20809).unwrap();
        let mut child = std::process::Command::new(&binary)
            .args(["run", "-test", "-config", "stdin:"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(config.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    fn panel_config(name: &str) -> Value {
        json!({
            "remarks": name,
            "log": {"loglevel": "debug", "access": "/tmp/stolen.log"},
            "api": {"tag": "api", "services": ["HandlerService"]},
            "stats": {},
            "inbounds": [{"tag": "socks", "port": 10808, "listen": "0.0.0.0", "protocol": "socks"}],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": []}},
                {"tag": "direct", "protocol": "freedom"},
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]},
            "dns": {"servers": ["1.1.1.1"]},
        })
    }

    #[test]
    fn xray_json_entry_keeps_its_remarks_as_the_endpoint_name() {
        let entry = xray_json_entry(&panel_config("🇳🇱 Netherlands")).unwrap();
        assert!(entry.starts_with(XRAY_JSON_PREFIX));
        assert!(!entry.contains('#') && !entry.contains('\n'));
        assert_eq!(share_link_name(&entry).as_deref(), Some("🇳🇱 Netherlands"));
        assert!(xray_json_entry(&json!({"remarks": "x"})).is_err());
    }

    #[test]
    fn xray_json_entry_config_uses_our_listeners_and_drops_unsafe_sections() {
        let entry = xray_json_entry(&panel_config("DE")).unwrap();
        let config = generate_share_link_config_with_http(&entry, 20808, 20809).unwrap();
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["listen"], "127.0.0.1");
        assert_eq!(inbounds[0]["port"], 20808);
        assert_eq!(inbounds[1]["port"], 20809);
        assert_eq!(config["log"], json!({"loglevel": "warning"}));
        for dropped in ["api", "stats", "remarks"] {
            assert!(config.get(dropped).is_none(), "{dropped} kept");
        }
        assert_eq!(config["outbounds"][0]["tag"], "proxy");
        assert_eq!(config["routing"]["domainStrategy"], "IPIfNonMatch");
        assert_eq!(config["dns"]["servers"][0], "1.1.1.1");
    }

    use super::*;
    use crate::models::DomainRouteTarget;
    use serde_json::json;

    const WS_TLS_URL: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&sni=edge.example.com&fp=chrome&path=%2Fapi%2Fws&host=cdn.example.com#My%20Node%20%F0%9F%9A%80";

    #[test]
    fn parses_tls_websocket_url() {
        let parsed = parse_vless_url(WS_TLS_URL).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("My Node 🚀"));
        assert_eq!(parsed.id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(parsed.address, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.network, "ws");
        assert_eq!(parsed.security, "tls");
        assert_eq!(parsed.sni.as_deref(), Some("edge.example.com"));
        assert_eq!(parsed.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(parsed.path.as_deref(), Some("/api/ws"));
        assert_eq!(parsed.host.as_deref(), Some("cdn.example.com"));
        assert!(parsed.flow.is_none());
        assert!(parsed.service_name.is_none());
    }

    #[test]
    fn parses_reality_grpc_url() {
        let parsed = parse_vless_url(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@node.test:8443?type=grpc&security=reality&sni=www.microsoft.com&pbk=PUBLIC_KEY&sid=0123ab&serviceName=grpcsvc&flow=xtls-rprx-vision",
        )
        .unwrap();
        assert_eq!(parsed.network, "grpc");
        assert_eq!(parsed.security, "reality");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.service_name.as_deref(), Some("grpcsvc"));
        assert_eq!(parsed.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(parsed.public_key.as_deref(), Some("PUBLIC_KEY"));
        assert_eq!(parsed.short_id.as_deref(), Some("0123ab"));
        assert!(parsed.name.is_none());
    }

    #[test]
    fn reality_requires_sni_and_public_key() {
        for uri in [
            "vless://id@node.test:443?security=reality&pbk=KEY",
            "vless://id@node.test:443?security=reality&sni=site.com",
            "vless://id@node.test:443?security=reality&sni=%20&pbk=KEY",
            "vless://id@node.test:443?security=reality&sni=site.com&pbk=%20",
        ] {
            assert_eq!(
                parse_vless_url(uri).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{uri}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_transport_and_security() {
        for uri in [
            "vless://id@node.test:443?type=h2&security=tls&sni=x",
            "vless://id@node.test:443?type=ws&security=auto",
            "vless://id@node.test:443?type=tcp&security=xtls",
        ] {
            assert_eq!(
                parse_vless_url(uri).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{uri}"
            );
        }
    }

    #[test]
    fn rejects_missing_id_host_and_port() {
        for uri in [
            "vless://@node.test:443?security=tls&sni=x",
            "vless://id@:443?security=tls&sni=x",
            "vless://id@node.test?security=none",
            "vless://id@node.test:0?security=tls&sni=x",
            "not-a-url",
            "vmess://id@node.test:443",
        ] {
            assert_eq!(
                parse_vless_url(uri).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{uri}"
            );
        }
    }

    #[test]
    fn tls_and_reality_default_to_port_443() {
        let parsed = parse_vless_url("vless://id@node.test?security=tls&sni=x").unwrap();
        assert_eq!(parsed.port, 443);
        let parsed =
            parse_vless_url("vless://id@node.test?security=reality&sni=x&pbk=KEY").unwrap();
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn generated_config_shape_for_ws_tls() {
        let config = generate_vless_config(WS_TLS_URL, 10808).unwrap();
        assert_eq!(config["log"]["loglevel"], "warning");
        assert_eq!(config["inbounds"][0]["tag"], "socks-in");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["port"], 10808);
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
        assert_eq!(config["inbounds"][0]["settings"]["udp"], true);

        let proxy = &config["outbounds"][0];
        assert_eq!(proxy["tag"], "proxy");
        assert_eq!(proxy["protocol"], "vless");
        let vnext = &proxy["settings"]["vnext"][0];
        assert_eq!(vnext["address"], "example.com");
        assert_eq!(vnext["port"], 443);
        let user = &vnext["users"][0];
        assert_eq!(user["id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(user["encryption"], "none");
        assert!(user.get("flow").is_none());

        let stream = &proxy["streamSettings"];
        assert_eq!(stream["network"], "ws");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["wsSettings"]["path"], "/api/ws");
        assert_eq!(stream["wsSettings"]["headers"]["Host"], "cdn.example.com");
        assert_eq!(stream["tlsSettings"]["serverName"], "edge.example.com");
        assert_eq!(stream["tlsSettings"]["fingerprint"], "chrome");

        assert_eq!(config["outbounds"][1]["tag"], "direct");
        assert_eq!(config["outbounds"][1]["protocol"], "freedom");
        assert_eq!(config["routing"]["domainStrategy"], "AsIs");
        assert_eq!(config["routing"]["rules"], json!([]));
    }

    #[test]
    fn generated_share_link_has_distinct_loopback_socks_and_http_inbounds() {
        let config = generate_share_link_config_with_http(WS_TLS_URL, 10808, 10809).unwrap();
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 2);
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["port"], 10808);
        assert_eq!(config["inbounds"][1]["tag"], "http-in");
        assert_eq!(config["inbounds"][1]["protocol"], "http");
        assert_eq!(config["inbounds"][1]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][1]["port"], 10809);
    }

    #[test]
    fn generated_share_link_rejects_duplicate_or_zero_http_port() {
        for http_port in [0, 10808] {
            assert_eq!(
                generate_share_link_config_with_http(WS_TLS_URL, 10808, http_port)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn generated_config_includes_flow_only_when_present() {
        let with_flow = generate_vless_config(
            "vless://id@node.test:443?security=reality&sni=x&pbk=KEY&flow=xtls-rprx-vision",
            10808,
        )
        .unwrap();
        assert_eq!(
            with_flow["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );

        let without_flow = generate_vless_config(
            "vless://id@node.test:443?security=reality&sni=x&pbk=KEY",
            10808,
        )
        .unwrap();
        assert!(
            without_flow["outbounds"][0]["settings"]["vnext"][0]["users"][0]
                .get("flow")
                .is_none()
        );
    }

    #[test]
    fn generated_config_rejects_zero_socks_port() {
        assert_eq!(
            generate_vless_config(WS_TLS_URL, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn reality_grpc_stream_settings() {
        let config = generate_vless_config(
            "vless://id@node.test:443?type=grpc&security=reality&sni=x&pbk=KEY&sid=ff&serviceName=svc",
            10808,
        )
        .unwrap();
        let stream = &config["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "grpc");
        assert_eq!(stream["security"], "reality");
        assert_eq!(stream["grpcSettings"]["serviceName"], "svc");
        assert_eq!(stream["realitySettings"]["serverName"], "x");
        assert_eq!(stream["realitySettings"]["publicKey"], "KEY");
        assert_eq!(stream["realitySettings"]["shortId"], "ff");
    }

    #[test]
    fn vless_new_transports_keep_decoded_path_host_and_alpn() {
        for (network, settings) in [
            ("raw", None),
            ("xhttp", Some("xhttpSettings")),
            ("httpupgrade", Some("httpupgradeSettings")),
        ] {
            let uri = format!("vless://id@node.test:443?type={network}&security=tls&sni=node.test&path=%2Fhello%3Ftoken%3Da%252Fb&host=front.test&alpn=h2%2Chttp%2F1.1");
            let config = generate_vless_config(&uri, 10808).unwrap();
            let stream = &config["outbounds"][0]["streamSettings"];
            assert_eq!(stream["network"], network);
            assert_eq!(stream["tlsSettings"]["alpn"], json!(["h2", "http/1.1"]));
            if let Some(settings) = settings {
                assert_eq!(stream[settings]["path"], "/hello?token=a%2Fb");
                assert_eq!(stream[settings]["host"], "front.test");
            }
        }
    }

    #[test]
    fn vless_reality_spider_x_is_decoded() {
        let config = generate_vless_config("vless://id@node.test:443?type=raw&security=reality&sni=node.test&pbk=KEY&spx=%2Fcrawl%3Fq%3D1", 10808).unwrap();
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["realitySettings"]["spiderX"],
            "/crawl?q=1"
        );
    }

    #[test]
    fn vless_rejects_removed_insecure_setting_without_leaking_uri() {
        let uri = "vless://sensitive-id@node.test:443?security=tls&allowInsecure=1#private-name";
        let err = generate_vless_config(uri, 10808).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let message = err.to_string();
        assert!(!message.contains("sensitive-id"));
        assert!(!message.contains("private-name"));
        assert!(!message.contains(uri));
    }

    #[test]
    fn hysteria2_share_link_generates_auth_tls_obfs_and_port_hopping() {
        let uri = "hysteria2://my%40secret@node.test:443,8443-8444/?sni=front.test&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&obfs=salamander&obfs-password=mask%40secret#Private";
        let config = generate_share_link_config(uri, 10808).unwrap();
        let proxy = &config["outbounds"][0];
        assert_eq!(proxy["protocol"], "hysteria");
        assert_eq!(
            proxy["settings"],
            json!({"version": 2, "address": "node.test", "port": 443})
        );
        let stream = &proxy["streamSettings"];
        assert_eq!(stream["network"], "hysteria");
        assert_eq!(stream["security"], "tls");
        assert_eq!(
            stream["hysteriaSettings"],
            json!({"version": 2, "auth": "my@secret"})
        );
        assert_eq!(stream["tlsSettings"]["serverName"], "front.test");
        assert_eq!(
            stream["tlsSettings"]["pinnedPeerCertSha256"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            stream["finalmask"]["udp"][0],
            json!({"type": "salamander", "settings": {"password": "mask@secret"}})
        );
        assert_eq!(
            stream["finalmask"]["quicParams"]["udpHop"]["ports"],
            "443,8443-8444"
        );
    }

    #[test]
    fn hy2_alias_defaults_to_port_443() {
        let config =
            generate_share_link_config("hy2://pass%3Aword@node.test?sni=front.test", 10808)
                .unwrap();
        let proxy = &config["outbounds"][0];
        assert_eq!(proxy["settings"]["port"], 443);
        assert_eq!(
            proxy["streamSettings"]["hysteriaSettings"]["auth"],
            "pass:word"
        );
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
    }

    #[test]
    fn hysteria2_rejects_unsupported_options_without_leaking_secrets() {
        for uri in [
            "hy2://private-password@node.test?insecure=1",
            "hy2://private-password@node.test?allowInsecure=1",
            "hy2://private-password@node.test?obfs=gecko&obfs-password=secret",
            "hy2://private-password@node.test?ech=secret",
            "hy2://private-password@node.test:443,0",
        ] {
            let err = generate_share_link_config(uri, 10808).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            let message = err.to_string();
            assert!(!message.contains("private-password"));
            assert!(!message.contains("secret"));
            assert!(!message.contains(uri));
        }
    }

    #[test]
    fn generated_share_configs_pass_pinned_xray_test_when_requested() {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let Ok(binary) = std::env::var("XRAY_TEST_BINARY") else {
            return;
        };
        let uris = [
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=raw&security=tls&sni=node.test",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=raw&security=reality&sni=node.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&spx=%2Fcrawl",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=xhttp&security=tls&sni=node.test&path=%2Fapi&host=front.test",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=httpupgrade&security=tls&sni=node.test&path=%2Fapi&host=front.test",
            "hy2://password@node.test:443,8443-8444?sni=node.test&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&obfs=salamander&obfs-password=mask",
        ];
        let mut configs: Vec<_> = uris
            .iter()
            .map(|uri| generate_share_link_config_with_http(uri, 10808, 10809).unwrap())
            .collect();
        if std::env::var_os("XRAY_LOCATION_ASSET").is_some() {
            let policies = [
                DomainPolicy {
                    domains: vec!["geosite:cn".into()],
                    target: DomainRouteTarget::Direct,
                },
                DomainPolicy {
                    domains: vec!["geoip:cn".into()],
                    target: DomainRouteTarget::Block,
                },
            ];
            configs.push(
                apply_profile_routing(
                    &configs[0],
                    &policies,
                    &ProfileRoutingOptions {
                        private_lan_direct: true,
                        ..ProfileRoutingOptions::default()
                    },
                )
                .unwrap(),
            );
        }
        for (index, config) in configs.iter().enumerate() {
            let path = std::env::temp_dir().join(format!(
                "net-manager-xray-test-{}-{index}.json",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&path).unwrap();
            file.write_all(&serde_json::to_vec(&config).unwrap())
                .unwrap();
            drop(file);
            let result = std::process::Command::new(&binary)
                .args(["run", "-test", "-config"])
                .arg(&path)
                .output();
            std::fs::remove_file(&path).unwrap();
            assert!(
                result.unwrap().status.success(),
                "Xray rejected generated config {index}"
            );
        }
    }

    #[test]
    fn empty_policies_return_unchanged_clone() {
        let base = json!({"anything": [1, 2, 3]});
        let result = apply_domain_policies(&base, &[]).unwrap();
        assert_eq!(result, base);
    }

    #[test]
    fn geo_rules_precede_private_lan_preset_and_existing_rules() {
        let mut base = generate_share_link_config_with_http(WS_TLS_URL, 10808, 10809).unwrap();
        base["routing"]["rules"] =
            json!([{"type":"field","domain":["domain:existing.test"],"outboundTag":"proxy"}]);
        let policies = [
            DomainPolicy {
                domains: vec!["geosite:cn".into()],
                target: DomainRouteTarget::Direct,
            },
            DomainPolicy {
                domains: vec!["geoip:us".into()],
                target: DomainRouteTarget::Block,
            },
        ];
        let config = apply_profile_routing(
            &base,
            &policies,
            &ProfileRoutingOptions {
                private_lan_direct: true,
                ..ProfileRoutingOptions::default()
            },
        )
        .unwrap();
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[0]["domain"], json!(["geosite:cn"]));
        assert_eq!(rules[0]["outboundTag"], "direct");
        assert_eq!(rules[1]["ip"], json!(["geoip:us"]));
        assert!(rules[1].get("domain").is_none());
        let block = rules[1]["outboundTag"].as_str().unwrap();
        assert_eq!(
            config["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|outbound| outbound["tag"] == block)
                .unwrap()["protocol"],
            "blackhole"
        );
        assert_eq!(rules[2]["ip"], json!(["224.0.0.0/4", "ff00::/8"]));
        assert_eq!(rules[2]["outboundTag"], block);
        assert_eq!(rules[3]["ip"][0], "10.0.0.0/8");
        assert_eq!(rules[3]["outboundTag"], "direct");
        assert_eq!(rules[4]["domain"], json!(["domain:existing.test"]));
    }

    #[test]
    fn geosite_attribute_selectors_are_domain_rules() {
        let policies = [DomainPolicy {
            domains: vec!["geosite:category-ru@cdn".into(), "geosite:cn@*".into()],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base_config(), &policies).unwrap();
        assert_eq!(
            result["routing"]["rules"][0]["domain"],
            json!(["geosite:category-ru@cdn", "geosite:cn@*"])
        );
        for bad in ["geosite:@cn", "geosite:cat@", "geosite:a@b@c"] {
            let policies = [DomainPolicy {
                domains: vec![bad.into()],
                target: DomainRouteTarget::Direct,
            }];
            assert_eq!(
                apply_domain_policies(&base_config(), &policies)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn comments_and_blank_selectors_are_ignored() {
        let policies = [DomainPolicy {
            domains: vec![
                "# custom".into(),
                "".into(),
                "   ".into(),
                "domain:example.com".into(),
            ],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base_config(), &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["domain"], json!(["domain:example.com"]));
        assert_eq!(rules[0]["outboundTag"], "direct");
    }

    #[test]
    fn comment_only_policy_emits_no_rule() {
        let policies = [DomainPolicy {
            domains: vec!["# just a note".into()],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base_config(), &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().all(|rule| rule["domain"]
            .as_array()
            .map(|d| !d.iter().any(|v| v == "# just a note"))
            .unwrap_or(true)));
    }

    #[test]
    fn bare_ip_and_cidr_selectors_go_to_ip_rules() {
        let policies = [DomainPolicy {
            domains: vec![
                "203.0.113.10".into(),
                "198.51.100.0/24".into(),
                "2001:db8::/32".into(),
            ],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base_config(), &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        let ip_rule = rules
            .iter()
            .find(|rule| rule.get("ip").is_some())
            .expect("ip rule emitted");
        assert_eq!(
            ip_rule["ip"],
            json!(["203.0.113.10", "198.51.100.0/24", "2001:db8::/32"])
        );
        assert_eq!(ip_rule["outboundTag"], "direct");
    }

    #[test]
    fn invalid_geo_selectors_do_not_leak_input() {
        for selector in [
            "geosite:secret/../cn",
            "geoip:secret/../cn",
            "geoip:",
            "geosite:",
        ] {
            let policies = [DomainPolicy {
                domains: vec![selector.into()],
                target: DomainRouteTarget::Proxy,
            }];
            let err =
                apply_profile_routing(&base_config(), &policies, &ProfileRoutingOptions::default())
                    .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(!err.to_string().contains("secret"));
            assert!(!err.to_string().contains(selector));
        }
    }

    fn base_config() -> Value {
        generate_vless_config(WS_TLS_URL, 10808).unwrap()
    }

    #[test]
    fn policies_prepend_rules_and_map_outbound_tags() {
        let mut base = base_config();
        base["routing"]["rules"] =
            json!([{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]);
        let policies = [
            DomainPolicy {
                domains: vec![" ads.example ".into(), "tracker.io".into()],
                target: DomainRouteTarget::Direct,
            },
            DomainPolicy {
                domains: vec!["example.com".into()],
                target: DomainRouteTarget::Proxy,
            },
        ];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(
            rules[0],
            json!({"type": "field", "domain": ["ads.example", "tracker.io"], "outboundTag": "direct"})
        );
        assert_eq!(
            rules[1],
            json!({"type": "field", "domain": ["example.com"], "outboundTag": "proxy"})
        );
        assert_eq!(rules[2]["ip"], json!(["224.0.0.0/4", "ff00::/8"]));
        assert_eq!(rules[3]["ip"], json!(["geoip:private"]));
    }

    #[test]
    fn policies_do_not_mutate_input() {
        let base = base_config();
        let snapshot = base.clone();
        let policies = [DomainPolicy {
            domains: vec!["example.com".into()],
            target: DomainRouteTarget::Direct,
        }];
        apply_domain_policies(&base, &policies).unwrap();
        assert_eq!(base, snapshot);
    }

    #[test]
    fn missing_outbound_tags_are_assigned_uniquely() {
        let mut base = base_config();
        base["outbounds"][0].as_object_mut().unwrap().remove("tag");
        base["outbounds"][1].as_object_mut().unwrap().remove("tag");
        base["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tag": "network-orchestrator-proxy", "protocol": "blackhole"}));

        let policies = [
            DomainPolicy {
                domains: vec!["a.com".into()],
                target: DomainRouteTarget::Proxy,
            },
            DomainPolicy {
                domains: vec!["b.com".into()],
                target: DomainRouteTarget::Direct,
            },
        ];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "network-orchestrator-proxy-2");
        assert_eq!(rules[1]["outboundTag"], "network-orchestrator-direct");
        assert_eq!(
            result["outbounds"][0]["tag"],
            "network-orchestrator-proxy-2"
        );
        assert_eq!(result["outbounds"][1]["tag"], "network-orchestrator-direct");
    }

    #[test]
    fn direct_outbound_injected_when_absent() {
        let mut base = base_config();
        base["outbounds"]
            .as_array_mut()
            .unwrap()
            .retain(|o| o["protocol"] != "freedom");
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "network-orchestrator-direct");
        let injected = result["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "freedom")
            .unwrap();
        assert_eq!(injected["tag"], "network-orchestrator-direct");
    }

    #[test]
    fn proxy_policy_without_proxy_outbound_rejects() {
        let base = json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": []}
        });
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        assert_eq!(
            apply_domain_policies(&base, &policies).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn malformed_routing_or_rules_rejects() {
        for bad in [
            json!({"outbounds": [{"protocol": "vless"}], "routing": "nope"}),
            json!({"outbounds": [{"protocol": "vless"}], "routing": {"rules": "nope"}}),
        ] {
            let policies = [DomainPolicy {
                domains: vec!["a.com".into()],
                target: DomainRouteTarget::Proxy,
            }];
            assert_eq!(
                apply_domain_policies(&bad, &policies).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{bad}"
            );
        }
    }

    #[test]
    fn outbound_without_protocol_is_not_eligible_proxy() {
        let base = json!({
            "outbounds": [
                {"tag": "no-protocol"},
                {"tag": "null-protocol", "protocol": null},
                {"tag": "blank-protocol", "protocol": "   "},
                {"tag": "direct", "protocol": "freedom"}
            ],
            "routing": {"rules": []}
        });
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        assert_eq!(
            apply_domain_policies(&base, &policies).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn injected_direct_tag_avoids_occupied_base_tag() {
        let base = json!({
            "outbounds": [
                {"tag": "network-orchestrator-direct", "protocol": "blackhole"},
                {"tag": "p", "protocol": "vless"}
            ]
        });
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "network-orchestrator-direct-2");
        let injected = result["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "freedom")
            .unwrap();
        assert_eq!(injected["tag"], "network-orchestrator-direct-2");
        assert_eq!(result["outbounds"][0]["tag"], "network-orchestrator-direct");
    }

    #[test]
    fn duplicate_selected_tag_is_reassigned() {
        let base = json!({
            "outbounds": [
                {"tag": "dup", "protocol": "vless"},
                {"tag": "dup", "protocol": "vless"}
            ]
        });
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "network-orchestrator-proxy");
        assert_eq!(result["outbounds"][0]["tag"], "network-orchestrator-proxy");
        assert_eq!(result["outbounds"][1]["tag"], "dup");
    }

    #[test]
    fn routing_created_when_absent() {
        let base = json!({"outbounds": [{"tag": "p", "protocol": "vless"}]});
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        let result = apply_domain_policies(&base, &policies).unwrap();
        assert_eq!(
            result["routing"]["rules"][0],
            json!({"type": "field", "domain": ["a.com"], "outboundTag": "p"})
        );
    }

    #[test]
    fn apply_tun_inbound_replaces_socks_with_tun() {
        let base = json!({
            "inbounds": [{"tag": "socks-in", "protocol": "socks", "port": 10808}],
            "outbounds": [{"tag": "proxy", "protocol": "vless"}],
        });
        let result = apply_tun_inbound(&base, None, None).unwrap();
        assert_eq!(result["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(result["inbounds"][0]["protocol"], "tun");
        assert_eq!(result["inbounds"][0]["tag"], "tun-in");
        assert_eq!(
            result["inbounds"][0]["settings"]["interfaceName"],
            "xray-tun"
        );
        assert_eq!(result["inbounds"][0]["settings"]["ip"], "172.19.0.1/30");
        assert_eq!(result["inbounds"][0]["settings"]["mtu"], 1500);
        // Outbounds preserved.
        assert_eq!(result["outbounds"][0]["tag"], "proxy");
    }

    #[test]
    fn apply_tun_inbound_enables_traffic_sniffing() {
        let base = json!({"outbounds": [{"tag": "proxy", "protocol": "vless"}]});
        let result = apply_tun_inbound(&base, None, None).unwrap();
        // Without sniffing, TUN traffic only carries destination IPs and
        // domain/geosite routing rules can never match.
        assert_eq!(result["inbounds"][0]["sniffing"]["enabled"], true);
        assert_eq!(
            result["inbounds"][0]["sniffing"]["destOverride"],
            json!(["http", "tls", "quic"])
        );
    }

    #[test]
    fn apply_tun_inbound_uses_custom_interface_and_ip() {
        let base = json!({"outbounds": [{"tag": "proxy", "protocol": "vless"}]});
        let result = apply_tun_inbound(&base, Some("my-tun"), Some("10.5.0.1/24")).unwrap();
        assert_eq!(result["inbounds"][0]["settings"]["interfaceName"], "my-tun");
        assert_eq!(result["inbounds"][0]["settings"]["ip"], "10.5.0.1/24");
    }

    #[test]
    fn apply_tun_inbound_adds_inbound_when_none_exists() {
        let base = json!({"outbounds": [{"tag": "proxy", "protocol": "vless"}]});
        let result = apply_tun_inbound(&base, None, None).unwrap();
        assert_eq!(result["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(result["inbounds"][0]["protocol"], "tun");
    }

    #[test]
    fn has_tun_inbound_detects_tun_protocol() {
        let with_tun = json!({"inbounds": [{"protocol": "tun"}]});
        assert!(has_tun_inbound(&with_tun));
        let with_socks = json!({"inbounds": [{"protocol": "socks"}]});
        assert!(!has_tun_inbound(&with_socks));
        let no_inbounds = json!({"outbounds": []});
        assert!(!has_tun_inbound(&no_inbounds));
    }

    #[test]
    fn apply_macos_tun_inbound_replaces_socks_with_fd_mode_tun() {
        let base = json!({
            "inbounds": [{"tag": "socks-in", "protocol": "socks", "port": 10808}],
            "outbounds": [{"tag": "proxy", "protocol": "vless"}],
        });
        let result = apply_macos_tun_inbound(&base, 1500, "en0").unwrap();
        let inbounds = result["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0]["protocol"], "tun");
        assert_eq!(inbounds[0]["tag"], "tun-in");
        // fd-mode schema: the helper owns the device (name, address, MTU on
        // the interface itself), so Xray only needs the stack MTU and the
        // loop-prevention uplink binding.
        assert_eq!(
            inbounds[0]["settings"],
            json!({"mtu": 1500, "autoOutboundsInterface": "en0"})
        );
        assert_eq!(result["outbounds"][0]["tag"], "proxy");
    }

    #[test]
    fn apply_macos_tun_inbound_sniffs_with_fakedns_override() {
        let base = json!({
            "outbounds": [{"tag": "proxy", "protocol": "vless"}],
            "fakedns": [{"ipPool": "198.18.0.0/16", "poolSize": 65535}]
        });
        let result = apply_macos_tun_inbound(&base, 1400, "en0").unwrap();
        assert_eq!(result["inbounds"][0]["sniffing"]["enabled"], true);
        assert_eq!(
            result["inbounds"][0]["sniffing"]["destOverride"],
            json!(["http", "tls", "quic", "fakedns"])
        );
        assert_eq!(result["inbounds"][0]["settings"]["mtu"], 1400);
    }

    #[test]
    fn apply_macos_tun_inbound_rejects_bad_uplink_or_mtu() {
        let base = json!({"outbounds": [{"tag": "p", "protocol": "vless"}]});
        for uplink in ["", "   ", "en0123456789012345", "en 0"] {
            assert_eq!(
                apply_macos_tun_inbound(&base, 1500, uplink)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "{uplink:?}"
            );
        }
        for mtu in [0, 9001] {
            assert_eq!(
                apply_macos_tun_inbound(&base, mtu, "en0")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "{mtu}"
            );
        }
    }

    fn macos_dns_base() -> Value {
        json!({
            "inbounds": [{"tag": "tun-in", "protocol": "tun"}],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless"},
                {"tag": "network-orchestrator-direct", "protocol": "freedom"},
                {"tag": "network-orchestrator-block", "protocol": "blackhole"},
            ],
            "routing": {"rules": [
                {"type": "field", "domain": ["ds-mind-lab.ru", "domain:corp.example"], "outboundTag": "network-orchestrator-direct"},
                {"type": "field", "domain": ["ads.example"], "outboundTag": "network-orchestrator-block"},
            ]},
        })
    }

    #[test]
    fn macos_dns_capture_answers_port_53_and_resolves_direct_names_locally() {
        let local: Vec<IpAddr> = vec!["10.228.32.2".parse().unwrap()];
        let out = apply_macos_dns_capture(&macos_dns_base(), &local, &[]).unwrap();
        // A dns outbound exists and tun-in port-53 traffic goes to it.
        let dns_tag = out["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "dns")
            .and_then(|o| o["tag"].as_str())
            .unwrap();
        let rules = out["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["port"] == "53"
            && r["inboundTag"] == json!(["tun-in"])
            && r["ip"] == json!(["169.254.10.1"])
            && r["outboundTag"] == dns_tag));
        // It is the first rule, so nothing can pre-empt the system's lookups.
        assert_eq!(rules[0]["port"], "53");
        // Local resolver: pinned direct and answers only the direct domains.
        assert!(rules.iter().any(|r| r["ip"] == json!(["10.228.32.2"])
            && r["outboundTag"] == "network-orchestrator-direct"));
        assert_eq!(
            out["dns"]["servers"][1],
            json!({"address": "10.228.32.2", "domains": ["ds-mind-lab.ru", "domain:corp.example"], "skipFallback": true})
        );
        // Everything else resolves remotely, through the proxy.
        assert_eq!(out["dns"]["servers"][2], json!("https://1.1.1.1/dns-query"));
        assert!(rules
            .iter()
            .any(|r| r["ip"] == json!(["1.1.1.1"]) && r["outboundTag"] == "proxy"));
        // The profile's own rules survive, after ours.
        assert!(rules
            .iter()
            .any(|r| r["outboundTag"] == "network-orchestrator-block"));
        // Names routed direct/block get fake answers, so SSH and other
        // protocols without SNI still match their domain rule.
        assert_eq!(
            out["dns"]["servers"][0],
            json!({"address": "fakedns", "domains": ["ds-mind-lab.ru", "domain:corp.example", "ads.example"]})
        );
        assert_eq!(out["fakedns"][0]["ipPool"], "198.18.0.0/16");
        // Direct connections to a name resolve through Xray's resolvers.
        let freedom = out["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "freedom")
            .unwrap();
        assert_eq!(freedom["settings"]["domainStrategy"], "UseIP");
    }

    #[test]
    fn macos_dns_capture_without_direct_domains_or_resolvers_still_resolves() {
        let base = json!({"outbounds": [{"tag": "proxy", "protocol": "vless"}]});
        let out = apply_macos_dns_capture(&base, &[], &[]).unwrap();
        assert_eq!(out["dns"]["servers"], json!(["https://1.1.1.1/dns-query"]));
        let rules = out["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["port"] == "53"));
        // A freedom outbound was added for the direct side.
        assert!(out["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["protocol"] == "freedom"));
    }

    #[test]
    fn macos_dns_capture_keeps_a_profile_that_already_routes_dns() {
        let mut base = macos_dns_base();
        base["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tag": "dns-out", "protocol": "dns"}));
        base["routing"]["rules"].as_array_mut().unwrap().insert(
            0,
            json!({"type": "field", "port": "53", "outboundTag": "dns-out"}),
        );
        let out = apply_macos_dns_capture(&base, &["10.0.0.1".parse().unwrap()], &[]).unwrap();
        // Its own DNS routing stays: no second dns outbound, no second port-53 rule.
        let dns_outbounds = out["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["protocol"] == "dns")
            .count();
        assert_eq!(dns_outbounds, 1);
        let capture_rules = out["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["port"] == "53")
            .count();
        assert_eq!(capture_rules, 1);
        // Direct names still resolve on the local network and get fake answers.
        let servers = out["dns"]["servers"].as_array().unwrap();
        assert_eq!(servers[0]["address"], "fakedns");
        assert_eq!(servers[1]["address"], "10.0.0.1");
        assert_eq!(servers[1]["skipFallback"], true);
    }

    #[test]
    fn macos_dns_capture_merges_with_a_profile_dns_section_and_unique_tags() {
        let mut base = macos_dns_base();
        base["dns"] = json!({"servers": ["9.9.9.9"], "hosts": {"a.test": "1.2.3.4"}});
        base["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tag": "dns-out", "protocol": "vless"}));
        let out = apply_macos_dns_capture(&base, &["10.0.0.1".parse().unwrap()], &[]).unwrap();
        assert_eq!(out["dns"]["hosts"]["a.test"], "1.2.3.4");
        assert!(out["dns"]["servers"]
            .as_array()
            .unwrap()
            .contains(&json!("9.9.9.9")));
        let tags: Vec<&str> = out["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["tag"].as_str())
            .collect();
        let unique: HashSet<&&str> = tags.iter().collect();
        assert_eq!(tags.len(), unique.len(), "{tags:?}");
    }

    /// The shape provider configs ship: a `dns` outbound that answers a few
    /// domains itself and forwards everything else to a fixed resolver.
    fn provider_dns_base() -> Value {
        json!({
            "outbounds": [
                {"tag": "proxy", "protocol": "vless"},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "dns", "protocol": "dns", "settings": {
                    "rewriteAddress": "8.8.8.8", "rewriteNetwork": "udp", "rewritePort": 53,
                    "rules": [
                        {"action": "return", "qType": "65,28", "rCode": 5},
                        {"action": "hijack", "domain": ["geosite:yandex"], "qType": "1"},
                        {"action": "direct"}
                    ]}},
            ],
            "dns": {"servers": ["77.88.8.8"]},
            "routing": {"rules": [
                {"type": "field", "network": "tcp,udp", "port": "53", "outboundTag": "dns"},
                {"type": "field", "domain": ["ds-mind-lab.ru"], "outboundTag": "direct"},
            ]},
        })
    }

    #[test]
    fn macos_dns_capture_hijacks_routed_names_in_a_forwarding_dns_outbound() {
        let out = apply_macos_dns_capture(&provider_dns_base(), &[], &[]).unwrap();
        let rules = out["outbounds"][2]["settings"]["rules"].as_array().unwrap();
        // `return` rules stay first, ours sits before the catch-all forward.
        assert_eq!(rules[0]["action"], "return");
        assert_eq!(rules[1]["action"], "hijack");
        assert_eq!(rules[2]["action"], "hijack");
        assert_eq!(rules[2]["domain"], json!(["ds-mind-lab.ru"]));
        assert_eq!(rules[2]["qType"], "1");
        assert_eq!(rules[3]["action"], "direct");
        // The profile's own resolvers remain behind the fake server.
        assert_eq!(
            out["dns"]["servers"],
            json!([
                {"address": "fakedns", "domains": ["ds-mind-lab.ru"]},
                "77.88.8.8"
            ])
        );
    }

    #[test]
    fn macos_dns_capture_sends_search_domains_to_the_local_resolvers_direct() {
        let local: Vec<IpAddr> = vec!["10.228.32.2".parse().unwrap()];
        let out = apply_macos_dns_capture(
            &provider_dns_base(),
            &local,
            &["agtuvsn.local".to_string(), ".agni.loc".to_string()],
        )
        .unwrap();
        let servers = out["dns"]["servers"].as_array().unwrap();
        // fake first, then the local resolver for direct names + search domains.
        assert_eq!(servers[1]["address"], "10.228.32.2");
        assert_eq!(
            servers[1]["domains"],
            json!(["ds-mind-lab.ru", "domain:agtuvsn.local", "domain:agni.loc"])
        );
        let rules = out["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["domain"]
            == json!(["domain:agtuvsn.local", "domain:agni.loc"])
            && r["outboundTag"] == "direct"));
        assert!(rules
            .iter()
            .any(|r| r["ip"] == json!(["10.228.32.2"]) && r["outboundTag"] == "direct"));
        // Search domains are hijacked too, so they never leave as real forwards.
        let hijack = &out["outbounds"][2]["settings"]["rules"][2];
        assert!(hijack["domain"]
            .as_array()
            .unwrap()
            .contains(&json!("domain:agtuvsn.local")));
    }

    #[test]
    fn macos_dns_capture_rejects_non_object_configs() {
        assert!(apply_macos_dns_capture(&json!([]), &[], &[]).is_err());
    }

    #[test]
    fn strip_tun_inbound_leaves_socks_and_outbounds() {
        let base = json!({
            "inbounds": [
                {"tag": "tun-in", "protocol": "tun"},
                {"tag": "socks-in", "protocol": "socks", "port": 10808},
            ],
            "outbounds": [{"tag": "proxy", "protocol": "vless"}],
        });
        let stripped = strip_tun_inbound(&base);
        assert_eq!(stripped["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(stripped["inbounds"][0]["protocol"], "socks");
        assert!(!has_tun_inbound(&stripped));
        let untouched = strip_tun_inbound(&json!({"outbounds": []}));
        assert!(!has_tun_inbound(&untouched));
    }

    #[test]
    fn percent_decode_does_not_panic_on_non_ascii_after_percent() {
        assert_eq!(percent_decode("Speed 5%-Москва"), "Speed 5%-Москва");
        assert_eq!(percent_decode("%М"), "%М");
        assert_eq!(
            share_link_name("vless://id@example.com:443#Speed 5%-Москва").as_deref(),
            Some("Speed 5%-Москва")
        );
    }

    #[test]
    fn percent_decode_handles_trailing_and_invalid_escapes() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("a%4"), "a%4");
        assert_eq!(percent_decode("%+1"), "%+1");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("a%41"), "aA");
        assert_eq!(percent_decode("%D0%9C%D0%BE"), "Мо");
        assert_eq!(percent_decode("%FF"), "\u{FFFD}");
    }

    fn dns_options(dns: XrayDnsConfig) -> ProfileRoutingOptions {
        ProfileRoutingOptions {
            dns,
            ..ProfileRoutingOptions::default()
        }
    }

    fn dns_server(address: &str, route: XrayDnsRoute) -> XrayDnsServer {
        XrayDnsServer {
            address: address.into(),
            port: None,
            domains: Vec::new(),
            skip_fallback: false,
            route,
        }
    }

    #[test]
    fn domain_strategy_and_matcher_override_base_values() {
        let config = apply_profile_routing(
            &base_config(),
            &[],
            &ProfileRoutingOptions {
                domain_strategy: Some(XrayDomainStrategy::IpIfNonMatch),
                domain_matcher: Some(XrayDomainMatcher::Mph),
                ..ProfileRoutingOptions::default()
            },
        )
        .unwrap();
        assert_eq!(config["routing"]["domainStrategy"], "IPIfNonMatch");
        assert_eq!(config["routing"]["domainMatcher"], "mph");
        // No rule set configured → no rules, no extra outbounds.
        assert_eq!(config["routing"]["rules"], json!([]));
    }

    #[test]
    fn split_dns_emits_section_servers_and_route_rules() {
        let mut dns = XrayDnsConfig {
            servers: vec![
                dns_server("https://8.8.8.8/dns-query", XrayDnsRoute::Proxy),
                dns_server("https://77.88.8.8/dns-query", XrayDnsRoute::Direct),
            ],
            query_strategy: Some(crate::models::XrayDnsQueryStrategy::UseIpv4),
            ..XrayDnsConfig::default()
        };
        dns.hosts
            .insert("lk.nalog.ru".into(), vec!["213.24.64.1".into()]);
        let config = apply_profile_routing(&base_config(), &[], &dns_options(dns)).unwrap();

        let rules = config["routing"]["rules"].as_array().unwrap();
        // port-53 capture, remote DNS → proxy, domestic DNS → direct,
        // multicast block.
        assert_eq!(rules[0]["port"], "53");
        let dns_tag = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "dns")
            .unwrap()["tag"]
            .clone();
        assert_eq!(rules[0]["outboundTag"], dns_tag);
        assert_eq!(rules[1]["ip"], json!(["8.8.8.8"]));
        assert_eq!(rules[1]["outboundTag"], "proxy");
        assert_eq!(rules[2]["ip"], json!(["77.88.8.8"]));
        assert_eq!(rules[2]["outboundTag"], "direct");
        assert_eq!(rules[3]["ip"], json!(["224.0.0.0/4", "ff00::/8"]));

        assert_eq!(
            config["dns"]["hosts"]["lk.nalog.ru"],
            json!(["213.24.64.1"])
        );
        assert_eq!(config["dns"]["queryStrategy"], "UseIPv4");
        let servers = config["dns"]["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["address"], "https://8.8.8.8/dns-query");
        assert_eq!(servers[1]["address"], "https://77.88.8.8/dns-query");
    }

    #[test]
    fn route_bound_dns_servers_autobind_policy_domains() {
        let policies = [DomainPolicy {
            domains: vec!["geosite:youtube".into(), "domain:example.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        let dns = XrayDnsConfig {
            servers: vec![dns_server(
                "https://dns.google/dns-query",
                XrayDnsRoute::Proxy,
            )],
            ..XrayDnsConfig::default()
        };
        let config = apply_profile_routing(&base_config(), &policies, &dns_options(dns)).unwrap();
        let servers = config["dns"]["servers"].as_array().unwrap();
        // Bare catch-all comes first, then the domain-bound entry.
        assert_eq!(servers.len(), 2);
        assert_eq!(
            servers[0],
            json!({"address": "https://dns.google/dns-query"})
        );
        assert_eq!(servers[0].get("domains"), None);
        assert_eq!(
            servers[1]["domains"],
            json!(["geosite:youtube", "domain:example.com"])
        );
        // The resolver host itself is pinned to the proxy outbound.
        let rules = config["routing"]["rules"].as_array().unwrap();
        let dns_rule = rules
            .iter()
            .find(|rule| rule["domain"] == json!(["dns.google"]))
            .expect("dns server route rule");
        assert_eq!(dns_rule["outboundTag"], "proxy");
    }

    #[test]
    fn block_domains_are_null_routed_through_dns_hosts() {
        let policies = [DomainPolicy {
            domains: vec![
                "domain:ads.example".into(),
                "geosite:category-ads".into(),
                "full:telemetry.example".into(),
            ],
            target: DomainRouteTarget::Block,
        }];
        let mut dns = XrayDnsConfig {
            servers: vec![dns_server("8.8.8.8", XrayDnsRoute::None)],
            ..XrayDnsConfig::default()
        };
        // An explicit hosts entry beats the generated null route.
        dns.hosts
            .insert("telemetry.example".into(), vec!["10.0.0.7".into()]);
        let config = apply_profile_routing(&base_config(), &policies, &dns_options(dns)).unwrap();
        let hosts = &config["dns"]["hosts"];
        assert_eq!(hosts["ads.example"], json!(["127.0.0.1"]));
        assert_eq!(hosts["telemetry.example"], json!(["10.0.0.7"]));
        // geosite categories cannot be expressed as hosts keys.
        assert!(hosts.get("geosite:category-ads").is_none());
    }

    #[test]
    fn fake_dns_emits_section_and_sniffing_override() {
        let dns = XrayDnsConfig {
            fake_dns: true,
            servers: vec![dns_server("1.1.1.1", XrayDnsRoute::None)],
            ..XrayDnsConfig::default()
        };
        let config = apply_profile_routing(&base_config(), &[], &dns_options(dns)).unwrap();
        assert_eq!(config["fakedns"][0]["ipPool"], "198.18.0.0/16");
        assert_eq!(config["dns"]["servers"][0], json!("fakedns"));
        let sniffing = &config["inbounds"][0]["sniffing"];
        assert_eq!(sniffing["enabled"], true);
        assert!(sniffing["destOverride"]
            .as_array()
            .unwrap()
            .contains(&json!("fakedns")));

        // TUN inbound picks up the fakedns override too.
        let tun = apply_tun_inbound(&config, None, None).unwrap();
        let overrides = tun["inbounds"][0]["sniffing"]["destOverride"]
            .as_array()
            .unwrap();
        for expected in ["http", "tls", "quic", "fakedns"] {
            assert!(overrides.contains(&json!(expected)));
        }
    }

    #[test]
    fn dns_validation_rejects_bad_servers() {
        for bad in [
            // Unknown scheme.
            "quic://dns.example",
            // Empty host after scheme.
            "https://",
            // fakedns entry without the fakedns section enabled.
            "fakedns",
        ] {
            let dns = XrayDnsConfig {
                servers: vec![dns_server(bad, XrayDnsRoute::None)],
                ..XrayDnsConfig::default()
            };
            assert_eq!(
                apply_profile_routing(&base_config(), &[], &dns_options(dns))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "accepted {bad}"
            );
        }
        let mut server = dns_server("1.1.1.1", XrayDnsRoute::None);
        server.port = Some(0);
        let dns = XrayDnsConfig {
            servers: vec![server],
            ..XrayDnsConfig::default()
        };
        assert_eq!(
            apply_profile_routing(&base_config(), &[], &dns_options(dns))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        // IP selectors are meaningless in dns.servers `domains`.
        let mut server = dns_server("1.1.1.1", XrayDnsRoute::None);
        server.domains = vec!["geoip:cn".into()];
        let dns = XrayDnsConfig {
            servers: vec![server],
            ..XrayDnsConfig::default()
        };
        assert_eq!(
            apply_profile_routing(&base_config(), &[], &dns_options(dns))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn dns_server_host_extracts_routable_host() {
        assert_eq!(dns_server_host("8.8.8.8"), Some("8.8.8.8"));
        assert_eq!(dns_server_host("8.8.8.8:53"), Some("8.8.8.8"));
        assert_eq!(
            dns_server_host("https://dns.google/dns-query"),
            Some("dns.google")
        );
        assert_eq!(
            dns_server_host("tls://one.one.one:853"),
            Some("one.one.one")
        );
        assert_eq!(
            dns_server_host("udp://[2001:db8::1]:53"),
            Some("2001:db8::1")
        );
        assert_eq!(dns_server_host("::1"), Some("::1"));
        assert_eq!(dns_server_host("https://"), None);
        assert_eq!(dns_server_route_target("localhost"), None);
        assert_eq!(dns_server_route_target("fakedns"), None);
        assert_eq!(
            dns_server_route_target("https://1.1.1.1/dns-query"),
            Some(("ip", "1.1.1.1".to_string()))
        );
        assert_eq!(
            dns_server_route_target("dns.google"),
            Some(("domain", "dns.google".to_string()))
        );
    }

    #[test]
    fn dns_bypass_hosts_skip_proxy_routed_and_internal_resolvers() {
        use crate::models::{XrayDnsConfig, XrayDnsRoute, XrayDnsServer};
        let server = |address: &str, route: XrayDnsRoute| XrayDnsServer {
            address: address.to_string(),
            route,
            domains: Vec::new(),
            port: None,
            skip_fallback: false,
        };
        let dns = XrayDnsConfig {
            servers: vec![
                server("udp://9.9.9.9:53", XrayDnsRoute::Direct),
                server("https://dns.resolver.test/dns-query", XrayDnsRoute::Direct),
                server("udp://8.8.4.4", XrayDnsRoute::Proxy),
                server("localhost", XrayDnsRoute::Direct),
                server("fakedns", XrayDnsRoute::Direct),
                server("udp://9.9.9.9:53", XrayDnsRoute::Direct),
            ],
            ..XrayDnsConfig::default()
        };
        assert_eq!(dns_bypass_hosts(&dns), ["9.9.9.9", "dns.resolver.test"]);
        assert!(dns_bypass_hosts(&XrayDnsConfig::default()).is_empty());
    }

    fn panel_vless() -> Value {
        json!({
            "burstObservatory": {"subjectSelector": ["proxy"]},
            "dns": {"servers": ["1.1.1.1"]},
            "remarks": "x",
            "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808,
                "protocol": "socks", "settings": {"udp": true}}],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless",
                 "settings": {"vnext": [{"address": "node.test", "port": 443, "level": 0,
                    "users": [{"id": "uuid-1", "encryption": "none", "flow": "xtls-rprx-vision",
                        "level": 0}]}]},
                 "streamSettings": {"network": "tcp", "security": "reality",
                    "realitySettings": {"serverName": "sni.test", "fingerprint": "chrome",
                        "publicKey": "pk", "shortId": "ab", "show": false},
                    "sockopt": {"mark": 99}},
                 "mux": {"enabled": false, "concurrency": -1}},
                {"tag": "other", "protocol": "vless", "settings": {}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {"domainStrategy": "IPIfNonMatch",
                "rules": [{"type": "field", "outboundTag": "direct", "domain": ["geosite:ru"]}]},
        })
    }

    #[test]
    fn a_panel_vless_config_is_reduced_to_the_servers_plain_shape() {
        let config = tun_compatible_config(&panel_vless()).unwrap();
        let keys: Vec<&String> = config.as_object().unwrap().keys().collect();
        assert!(
            keys.iter().all(|key| TUN_TOP_LEVEL.contains(&key.as_str())),
            "{keys:?}"
        );
        let outbounds = config["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 2);
        assert_eq!(outbounds[0]["tag"], "proxy");
        assert_eq!(outbounds[1]["protocol"], "freedom");
        let server = &outbounds[0]["settings"]["vnext"][0];
        assert_eq!(server["address"], "node.test");
        assert!(server.get("level").is_none() && server["users"][0].get("level").is_none());
        assert_eq!(server["users"][0]["flow"], "xtls-rprx-vision");
        let stream = &outbounds[0]["streamSettings"];
        assert_eq!(stream["realitySettings"]["publicKey"], "pk");
        assert!(stream["realitySettings"].get("show").is_none());
        assert!(stream.get("sockopt").is_none());
        // The listeners the caller set up survive.
        assert_eq!(config["inbounds"], panel_vless()["inbounds"]);
        assert!(config["routing"]["rules"].as_array().unwrap().is_empty());
        assert!(config.get("dns").is_none() && config.get("burstObservatory").is_none());
    }

    #[test]
    fn a_hysteria_entry_keeps_its_auth_and_masking() {
        let mut panel = panel_vless();
        panel["outbounds"][0] = json!({
            "tag": "proxy", "protocol": "hysteria",
            "settings": {"version": 2, "address": "h.test", "port": 443},
            "streamSettings": {"network": "hysteria", "security": "tls",
                "tlsSettings": {"serverName": "h.test", "alpn": ["h3"]},
                "hysteriaSettings": {"version": 2, "auth": "secret", "udpIdleTimeout": 60},
                "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "p"}}]}}
        });
        let config = tun_compatible_config(&panel).unwrap();
        let stream = &config["outbounds"][0]["streamSettings"];
        assert_eq!(
            stream["hysteriaSettings"],
            json!({"version": 2, "auth": "secret"})
        );
        assert_eq!(stream["tlsSettings"], json!({"serverName": "h.test"}));
        assert_eq!(stream["finalmask"]["udp"][0]["type"], "salamander");
    }

    #[test]
    fn a_pool_of_servers_is_refused_with_advice() {
        let mut panel = panel_vless();
        let second = panel["outbounds"][0].clone();
        panel["outbounds"].as_array_mut().unwrap().push(second);
        panel["outbounds"][4]["tag"] = json!("proxy-2");
        let error = tun_compatible_config(&panel).unwrap_err();
        assert!(error.contains("Choose a specific server"), "{error}");
    }

    #[test]
    fn a_balancer_between_a_server_and_its_fallback_uses_the_server() {
        let mut panel = panel_vless();
        panel["routing"]["balancers"] =
            json!([{"tag": "auto", "selector": ["proxy", "bridge"], "fallbackTag": "bridge"}]);
        let config = tun_compatible_config(&panel).unwrap();
        assert_eq!(
            config["outbounds"][0]["settings"]["vnext"][0]["address"],
            "node.test"
        );
        assert!(config["routing"].get("balancers").is_none());
    }

    #[test]
    fn mux_counts_outside_the_daemons_range_are_dropped() {
        let config = tun_compatible_config(&panel_vless()).unwrap();
        assert_eq!(config["outbounds"][0]["mux"], json!({"enabled": false}));
    }

    #[test]
    fn a_share_link_config_passes_through_unchanged() {
        let config = generate_share_link_config_with_http(
            "vless://id@node.test:443?security=tls#Lab",
            10808,
            10809,
        )
        .unwrap();
        assert_eq!(tun_compatible_config(&config).unwrap(), config);
    }

    #[test]
    fn an_unsupported_protocol_is_refused() {
        let mut panel = panel_vless();
        panel["outbounds"] = json!([{"tag": "proxy", "protocol": "trojan", "settings": {}}]);
        assert!(tun_compatible_config(&panel).is_err());
    }

    #[test]
    fn fixed_domain_routes_do_not_override_port_guards_or_dns_capture() {
        let base = json!({"outbounds":[{"tag":"proxy","protocol":"vless"}],
        "routing":{"rules":[
            {"type":"field","port":853,"network":"tcp","outboundTag":"direct"},
            {"type":"field","port":53,"outboundTag":"dns"},
            {"type":"field","domain":["domain:example.test"],"outboundTag":"proxy"}
        ]}});
        let pins = [PinnedOutbound {
            key: "1111111111111111".into(),
            selectors: vec!["domain:example.test".into()],
            outbound: Some(json!({"protocol":"vless"})),
        }];
        let config = apply_multinode_config(&base, "2222222222222222", &[], &pins).unwrap();
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["port"], 853);
        assert_eq!(rules[1]["port"], 53);
        assert_eq!(rules[2]["outboundTag"], pin_tag(&pins[0].key));
        assert_eq!(rules[3]["balancerTag"], FAILOVER_BALANCER);
    }

    #[test]
    fn multiple_domain_pins_share_one_endpoint_outbound() {
        let base = json!({"outbounds":[{"tag":"proxy","protocol":"vless"}],"routing":{"rules":[]}});
        let pins = ["domain:first.test", "domain:second.test"].map(|selector| PinnedOutbound {
            key: "1111111111111111".into(),
            selectors: vec![selector.into()],
            outbound: Some(json!({"protocol":"vless"})),
        });
        let config = apply_multinode_config(&base, "2222222222222222", &[], &pins).unwrap();
        let tags: Vec<_> = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str())
            .collect();
        assert_eq!(tags, ["node-2222222222222222", "pin-1111111111111111"]);
        assert_eq!(
            config["routing"]["rules"][0]["domain"],
            json!(["domain:first.test"])
        );
        assert_eq!(
            config["routing"]["rules"][1]["domain"],
            json!(["domain:second.test"])
        );
    }
}
