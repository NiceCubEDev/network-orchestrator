//! Xray routing editor support for the native client: rule sets, split DNS,
//! domain strategy, Happ/Incy imports and the offline route checker. Pure
//! profile edits and parsing — nothing here touches the network.
use net_manager_core::happ_routing;
use net_manager_core::models::*;
use net_manager_engine::macos_services::{
    AdvancedRouting, GeoUrls, MacosServices, ProfileRouting, ProfileRoutingUpdate,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn text<'a>(args: &'a Value, key: &str) -> &'a str {
    args[key].as_str().unwrap_or_default()
}

fn lines(value: &str) -> impl Iterator<Item = &str> {
    value.lines().map(str::trim).filter(|line| !line.is_empty())
}

/// Xray matches the first rule, so blocks win over proxy over direct.
pub(crate) fn policies_from_args(args: &Value) -> Result<Vec<DomainPolicy>, String> {
    let mut policies = Vec::new();
    for (key, target) in [
        ("block", DomainRouteTarget::Block),
        ("proxy", DomainRouteTarget::Proxy),
        ("direct", DomainRouteTarget::Direct),
    ] {
        let domains: Vec<String> = lines(text(args, key)).map(str::to_string).collect();
        if !domains.is_empty() {
            policies.push(DomainPolicy { domains, target });
        }
    }
    Ok(policies)
}

fn strategy_name(value: Option<XrayDomainStrategy>) -> &'static str {
    match value {
        None => "",
        Some(XrayDomainStrategy::AsIs) => "asIs",
        Some(XrayDomainStrategy::IpIfNonMatch) => "ipIfNonMatch",
        Some(XrayDomainStrategy::IpOnDemand) => "ipOnDemand",
    }
}

fn matcher_name(value: Option<XrayDomainMatcher>) -> &'static str {
    match value {
        None => "",
        Some(XrayDomainMatcher::Mph) => "mph",
        Some(XrayDomainMatcher::Hybrid) => "hybrid",
        Some(XrayDomainMatcher::Linear) => "linear",
    }
}

fn query_strategy_name(value: Option<XrayDnsQueryStrategy>) -> &'static str {
    match value {
        None => "",
        Some(XrayDnsQueryStrategy::UseIp) => "useIp",
        Some(XrayDnsQueryStrategy::UseIpv4) => "useIpv4",
        Some(XrayDnsQueryStrategy::UseIpv6) => "useIpv6",
    }
}

fn parse_strategy(value: &str) -> Result<Option<XrayDomainStrategy>, String> {
    Ok(match value {
        "" => None,
        "asIs" => Some(XrayDomainStrategy::AsIs),
        "ipIfNonMatch" => Some(XrayDomainStrategy::IpIfNonMatch),
        "ipOnDemand" => Some(XrayDomainStrategy::IpOnDemand),
        _ => return Err("Choose a valid domain strategy".into()),
    })
}

fn parse_matcher(value: &str) -> Result<Option<XrayDomainMatcher>, String> {
    Ok(match value {
        "" => None,
        "mph" => Some(XrayDomainMatcher::Mph),
        "hybrid" => Some(XrayDomainMatcher::Hybrid),
        "linear" => Some(XrayDomainMatcher::Linear),
        _ => return Err("Choose a valid domain matcher".into()),
    })
}

fn parse_query_strategy(value: &str) -> Result<Option<XrayDnsQueryStrategy>, String> {
    Ok(match value {
        "" => None,
        "useIp" => Some(XrayDnsQueryStrategy::UseIp),
        "useIpv4" => Some(XrayDnsQueryStrategy::UseIpv4),
        "useIpv6" => Some(XrayDnsQueryStrategy::UseIpv6),
        _ => return Err("Choose a valid DNS query strategy".into()),
    })
}

/// `address | proxy|direct | domain,domain | skip` — every part after the
/// address is optional.
fn parse_dns_servers(value: &str) -> Result<Vec<XrayDnsServer>, String> {
    lines(value)
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let mut parts = line.split('|').map(str::trim);
            let address = parts.next().unwrap_or_default().to_string();
            let route = match parts.next().unwrap_or_default() {
                "" | "-" | "none" => XrayDnsRoute::None,
                "proxy" => XrayDnsRoute::Proxy,
                "direct" => XrayDnsRoute::Direct,
                _ => return Err(format!("Invalid DNS server route ({line})")),
            };
            let domains = parts
                .next()
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|domain| !domain.is_empty())
                .map(str::to_string)
                .collect();
            let skip_fallback = parts.next().is_some_and(|flag| flag == "skip");
            Ok(XrayDnsServer {
                address,
                port: None,
                domains,
                skip_fallback,
                route,
            })
        })
        .collect()
}

fn format_dns_servers(servers: &[XrayDnsServer]) -> String {
    servers
        .iter()
        .map(|server| {
            let route = match server.route {
                XrayDnsRoute::None => "-",
                XrayDnsRoute::Proxy => "proxy",
                XrayDnsRoute::Direct => "direct",
            };
            let address = match server.port {
                Some(port) if !server.address.contains("://") => {
                    format!("{}:{port}", server.address)
                }
                _ => server.address.clone(),
            };
            let mut line = format!("{address} | {route} | {}", server.domains.join(","));
            if server.skip_fallback {
                line.push_str(" | skip");
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `host = ip, ip` per line.
fn parse_dns_hosts(value: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut hosts = BTreeMap::new();
    for line in lines(value).filter(|line| !line.starts_with('#')) {
        let (host, addresses) = line
            .split_once('=')
            .ok_or_else(|| format!("Invalid DNS host entry ({line})"))?;
        let addresses: Vec<String> = addresses
            .split(',')
            .map(str::trim)
            .filter(|address| !address.is_empty())
            .map(str::to_string)
            .collect();
        if host.trim().is_empty() || addresses.is_empty() {
            return Err(format!("Invalid DNS host entry ({line})"));
        }
        hosts.insert(host.trim().to_string(), addresses);
    }
    Ok(hosts)
}

fn format_dns_hosts(hosts: &BTreeMap<String, Vec<String>>) -> String {
    hosts
        .iter()
        .map(|(host, addresses)| format!("{host} = {}", addresses.join(", ")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn advanced_from_args(args: &Value) -> Result<AdvancedRouting, String> {
    let dns = XrayDnsConfig {
        servers: parse_dns_servers(text(args, "dnsServers"))?,
        hosts: parse_dns_hosts(text(args, "dnsHosts"))?,
        fake_dns: text(args, "fakeDns") == "true",
        query_strategy: parse_query_strategy(text(args, "queryStrategy"))?,
        ..XrayDnsConfig::default()
    };
    Ok(AdvancedRouting {
        domain_strategy: parse_strategy(text(args, "domainStrategy"))?,
        domain_matcher: parse_matcher(text(args, "domainMatcher"))?,
        dns,
    })
}

/// Empty editor text clears a custom geo URL; Engine validates nonempty URLs.
fn geo_url(args: &Value, key: &str) -> Option<String> {
    let url = text(args, key).trim();
    (!url.is_empty()).then(|| url.to_string())
}

/// Decode native editor text. Omitted option groups remain omitted, rather
/// than turning an old editor's missing fields into destructive clears.
pub(crate) fn draft(args: &Value) -> Result<ProfileRoutingUpdate, String> {
    Ok(ProfileRoutingUpdate {
        policies: policies_from_args(args)?,
        private_lan_direct: text(args, "privateLanDirect") == "true",
        advanced: args
            .get("domainStrategy")
            .map(|_| advanced_from_args(args))
            .transpose()?,
        geo_urls: if args.get("geoipUrl").is_some() || args.get("geositeUrl").is_some() {
            Some(GeoUrls {
                geoip_url: geo_url(args, "geoipUrl"),
                geosite_url: geo_url(args, "geositeUrl"),
            })
        } else {
            None
        },
    })
}

fn rules_json(policies: &[DomainPolicy]) -> Value {
    let joined = |target| {
        policies
            .iter()
            .filter(|policy| policy.target == target)
            .flat_map(|policy| policy.domains.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("\n")
    };
    json!({
        "block": joined(DomainRouteTarget::Block),
        "proxy": joined(DomainRouteTarget::Proxy),
        "direct": joined(DomainRouteTarget::Direct),
    })
}

fn dns_json(value: &mut Value, dns: &XrayDnsConfig) {
    value["dnsServers"] = json!(format_dns_servers(&dns.servers));
    value["dnsHosts"] = json!(format_dns_hosts(&dns.hosts));
    value["fakeDns"] = json!(dns.fake_dns);
    value["queryStrategy"] = json!(query_strategy_name(dns.query_strategy));
}

/// The editor's initial state for a profile, as plain text fields.
pub(crate) fn options_json(profile: &ProfileRouting) -> Value {
    let mut value = rules_json(&profile.policies);
    value["privateLanDirect"] = json!(profile.private_lan_direct);
    value["domainStrategy"] = json!(strategy_name(profile.domain_strategy));
    value["domainMatcher"] = json!(matcher_name(profile.domain_matcher));
    dns_json(&mut value, &profile.dns);
    value["geoipUrl"] = json!(profile.geoip_url.clone().unwrap_or_default());
    value["geositeUrl"] = json!(profile.geosite_url.clone().unwrap_or_default());
    value
}

/// Fields recovered from a pasted Happ/Incy routing export, as editor text.
/// Fields the export does not mention are omitted so the editor keeps them.
pub(crate) fn happ_json(import: happ_routing::HappRoutingImport) -> Value {
    let mut value = rules_json(&import.domain_policies);
    if let Some(lan) = import.private_lan_direct {
        value["privateLanDirect"] = json!(lan);
    }
    if let Some(strategy) = import.domain_strategy {
        value["domainStrategy"] = json!(strategy_name(Some(strategy)));
    }
    if let Some(matcher) = import.domain_matcher {
        value["domainMatcher"] = json!(matcher_name(Some(matcher)));
    }
    if !import.dns.is_empty() {
        dns_json(&mut value, &import.dns);
    }
    value["name"] = json!(import.name);
    if let Some(url) = &import.geoip_url {
        value["geoipUrl"] = json!(url);
    }
    if let Some(url) = &import.geosite_url {
        value["geositeUrl"] = json!(url);
    }
    value["warnings"] = json!(import.warnings);
    value
}

fn route_check(root: &std::path::Path, args: &Value) -> Result<Value, String> {
    let update = draft(args)?;
    let advanced = advanced_from_args(args)?;
    let routing = ProfileRouting {
        policies: update.policies,
        private_lan_direct: update.private_lan_direct,
        domain_strategy: advanced.domain_strategy,
        domain_matcher: advanced.domain_matcher,
        dns: advanced.dns,
        ..Default::default()
    };
    serde_json::to_value(MacosServices::new(root)?.check_routing(text(args, "target"), &routing)?)
        .map_err(|_| "The route check failed".into())
}

/// Bridge methods of the routing editor, or `None` for other methods.
pub(crate) fn handle(
    root: &std::path::Path,
    profile: impl FnOnce() -> Result<ProfileRouting, String>,
    method: &str,
    args: &Value,
) -> Option<Result<Value, String>> {
    match method {
        "routing_options" => Some(profile().map(|profile| options_json(&profile))),
        "parse_happ_routing" => Some(
            MacosServices::new(root)
                .and_then(|service| service.parse_happ_routing(text(args, "payload")))
                .map(happ_json),
        ),
        "check_route" => Some(route_check(root, args)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_text_round_trips() {
        let servers = parse_dns_servers("https://dns.google/dns-query | proxy | geosite:google\n1.1.1.1 | direct | | skip\nlocalhost").unwrap();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0].route, XrayDnsRoute::Proxy);
        assert_eq!(servers[0].domains, ["geosite:google"]);
        assert!(servers[1].skip_fallback);
        assert_eq!(
            parse_dns_servers(&format_dns_servers(&servers)).unwrap(),
            servers
        );
        assert!(parse_dns_servers("1.1.1.1 | sideways").is_err());
    }

    #[test]
    fn dns_hosts_round_trip_and_reject_garbage() {
        let hosts = parse_dns_hosts("example.com = 1.2.3.4, 5.6.7.8").unwrap();
        assert_eq!(hosts["example.com"], ["1.2.3.4", "5.6.7.8"]);
        assert_eq!(parse_dns_hosts(&format_dns_hosts(&hosts)).unwrap(), hosts);
        assert!(parse_dns_hosts("no-equals").is_err());
    }

    #[test]
    fn happ_geo_urls_reach_the_editor_instead_of_a_warning() {
        let import = happ_routing::HappRoutingImport {
            geoip_url: Some("https://cdn.example/geoip.dat".into()),
            ..Default::default()
        };
        let value = happ_json(import);
        assert_eq!(value["geoipUrl"], "https://cdn.example/geoip.dat");
        assert!(value.get("geositeUrl").is_none());
        assert!(!value["warnings"].to_string().contains("geo"));
    }
}
