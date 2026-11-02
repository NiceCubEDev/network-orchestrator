//! Routing rules of Xray profiles: which domains, geosite/geoip lists and
//! addresses go direct, through the tunnel or nowhere. The rules live in the
//! profile (`domainPolicies`), so the app and the daemon see what is saved
//! here; a connected profile picks the change up when it reconnects.
use super::args::{RouteCommand, RuleArgs};
use super::commands::Output;
use super::ctx::Ctx;
use super::endpoints;
use super::library::require_user;
use net_manager_core::models::{
    DomainPolicy, DomainRouteTarget, PinnedRoute, Profile, TunnelBackend, TunnelState,
};
use net_manager_core::route_check::{check_route, GeoDbs, GeoIpDb, GeoSiteDb};
use net_manager_core::subscription;
use net_manager_core::xray::{self, ProfileRoutingOptions};
use net_manager_engine::linux_engine::LinuxEngine;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::Path;

/// Where the daemon's package keeps the pinned Xray and its geo lists.
const XRAY_DIR: &str = "/usr/lib/network-orchestrator/xray";
/// The core's `LINUX_XRAY_VERSION`, which only exists in Linux builds.
const XRAY_VERSION: &str = "v26.10.31";
const MAX_GEO_ASSET_BYTES: u64 = 64 * 1024 * 1024;

/// Xray takes the first matching rule, so blocks win over proxy over direct.
const LISTS: [(&str, DomainRouteTarget); 3] = [
    ("block", DomainRouteTarget::Block),
    ("proxy", DomainRouteTarget::Proxy),
    ("direct", DomainRouteTarget::Direct),
];

pub fn run(ctx: &Ctx, command: RouteCommand) -> Result<Output, String> {
    match command {
        RouteCommand::Show { profile } => show(ctx, profile.as_deref()),
        RouteCommand::Set {
            profile,
            rules,
            lan_direct,
        } => set(ctx, &profile, &rules, lan_direct),
        RouteCommand::Add { profile, rules } => edit(ctx, &profile, &rules, Edit::Add),
        RouteCommand::Rm { profile, rules } => edit(ctx, &profile, &rules, Edit::Remove),
        RouteCommand::Check { target, profile } => check(
            ctx,
            &target,
            &profile,
            &Path::new(XRAY_DIR).join(XRAY_VERSION),
        ),
        RouteCommand::Pin {
            profile,
            via,
            selector,
        } => pin(ctx, &profile, &via, &selector),
        RouteCommand::Unpin {
            profile,
            via,
            selector,
        } => unpin(ctx, &profile, &via, &selector),
        RouteCommand::Quic { profile, enabled } => quic(ctx, &profile, enabled),
    }
}

fn xray_profile(ctx: &Ctx, query: &str) -> Result<Profile, String> {
    let profile = ctx.find(query)?;
    if profile.backend != TunnelBackend::Xray {
        return Err("Routing rules are available for Xray profiles".into());
    }
    Ok(profile)
}

fn selectors_of(policies: &[DomainPolicy], target: DomainRouteTarget) -> Vec<String> {
    policies
        .iter()
        .filter(|policy| policy.target == target)
        .flat_map(|policy| policy.domains.iter().cloned())
        .collect()
}

fn rules_json(profile: &Profile) -> Value {
    json!({
        "id": profile.id,
        "name": profile.name,
        "block": selectors_of(&profile.domain_policies, DomainRouteTarget::Block),
        "proxy": selectors_of(&profile.domain_policies, DomainRouteTarget::Proxy),
        "direct": selectors_of(&profile.domain_policies, DomainRouteTarget::Direct),
        "privateLanDirect": profile.private_lan_direct,
        "quicReject": profile.xray_quic_reject,
        "pinned": profile.pinned_policies.iter().map(|route| {
            json!({"endpointKey": route.endpoint_key,
                "missing": route.missing, "selectors": route.selectors})
        }).collect::<Vec<_>>(),
    })
}

fn rules_text(rules: &Value) -> String {
    let mut out = format!(
        "{} ({})",
        rules["name"].as_str().unwrap_or_default(),
        rules["id"].as_str().unwrap_or_default()
    );
    for (key, _) in LISTS {
        let list: Vec<&str> = rules[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        out.push_str(&format!(
            "\n  {key:<7}{}",
            if list.is_empty() {
                "-".to_string()
            } else {
                list.join(", ")
            }
        ));
    }
    out.push_str(&format!(
        "\n  lan-direct  {}",
        rules["privateLanDirect"].as_bool().unwrap_or(false)
    ));
    out.push_str(&format!(
        "\n  quic-reject {}",
        rules["quicReject"].as_bool().unwrap_or(false)
    ));
    for pinned in rules["pinned"].as_array().into_iter().flatten() {
        let selectors: Vec<&str> = pinned["selectors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        out.push_str(&format!(
            "\n  pinned {}  {}{}",
            pinned["endpointKey"].as_str().unwrap_or_default(),
            selectors.join(", "),
            if pinned["missing"].as_bool().unwrap_or(false) {
                "  (node gone from the subscription)"
            } else {
                ""
            }
        ));
    }
    out
}

fn show(ctx: &Ctx, profile: Option<&str>) -> Result<Output, String> {
    let profiles = match profile {
        Some(query) => vec![xray_profile(ctx, query)?],
        None => ctx
            .profiles()?
            .into_iter()
            .filter(|profile| profile.backend == TunnelBackend::Xray)
            .collect(),
    };
    if profiles.is_empty() {
        return Ok((json!([]), "No Xray profiles".into()));
    }
    let rules: Vec<Value> = profiles.iter().map(rules_json).collect();
    let text = rules
        .iter()
        .map(rules_text)
        .collect::<Vec<_>>()
        .join("\n\n");
    Ok((Value::Array(rules), text))
}

/// One selector as the daemon and the app accept it; comments and blanks are
/// editor annotations that make no sense on a command line.
fn valid_selector(selector: &str) -> Result<String, String> {
    let selector = selector.trim();
    let invalid = || format!("Invalid routing selector ({selector})");
    if selector.is_empty() || selector.starts_with('#') {
        return Err(invalid());
    }
    xray::validate_routing_policy_selectors(&[DomainPolicy {
        domains: vec![selector.to_string()],
        target: DomainRouteTarget::Direct,
    }])
    .map_err(|_| invalid())?;
    Ok(selector.to_string())
}

fn is_address(selector: &str) -> bool {
    let (address, prefix) = selector.split_once('/').unwrap_or((selector, ""));
    address.parse::<IpAddr>().is_ok() && (prefix.is_empty() || prefix.parse::<u8>().is_ok())
}

/// A bare name is a substring match in Xray, so `ru` also catches `trulia.com`.
fn hints(selectors: &[String]) -> Vec<String> {
    selectors
        .iter()
        .filter(|selector| !selector.contains(':') && !is_address(selector))
        .map(|selector| {
            format!(
                "\"{selector}\" matches any name that contains it; write domain:{selector} \
                 to match only that domain and its subdomains"
            )
        })
        .collect()
}

/// A selector already pinned to one node cannot join a routing rule: both
/// decisions are first-match, and the pinned one is fail-closed.
fn check_not_pinned(profile: &Profile, selectors: &[String]) -> Result<(), String> {
    for selector in selectors {
        if let Some(route) = profile
            .pinned_policies
            .iter()
            .find(|route| route.selectors.contains(selector))
        {
            return Err(format!(
                "{selector} is pinned to {}; unpin it first (`netorch route unpin`)",
                route.endpoint_key
            ));
        }
    }
    Ok(())
}
/// The selectors of one list given on the command line, checked and unique.
struct Wanted {
    target: DomainRouteTarget,
    name: &'static str,
    selectors: Vec<String>,
}

fn wanted(rules: &RuleArgs) -> Result<Vec<Wanted>, String> {
    let mut lists = Vec::new();
    for (name, target) in LISTS {
        let given = match target {
            DomainRouteTarget::Block => &rules.block,
            DomainRouteTarget::Proxy => &rules.proxy,
            DomainRouteTarget::Direct => &rules.direct,
        };
        let mut checked = Vec::new();
        for selector in given {
            let selector = valid_selector(selector)?;
            if !checked.contains(&selector) {
                checked.push(selector);
            }
        }
        lists.push(Wanted {
            target,
            name,
            selectors: checked,
        });
    }
    Ok(lists)
}

fn save(
    ctx: &Ctx,
    mut profile: Profile,
    policies: Vec<DomainPolicy>,
    extra: Vec<String>,
) -> Result<Output, String> {
    profile.domain_policies = policies;
    ctx.store().upsert(profile.clone()).map_err(|_| {
        "The rules could not be saved. Check the selectors and file permissions.".to_string()
    })?;
    let rules = rules_json(&profile);
    let mut text = format!(
        "Rules of \"{}\" saved. They apply when the profile connects: \
         `netorch down {0:?}` and `netorch up {0:?}` if it is already up.",
        profile.name
    );
    for hint in extra {
        text.push_str(&format!("\n  note: {hint}"));
    }
    Ok((rules, text))
}

/// Replaces every list, like the macOS command and the app's editor.
fn set(ctx: &Ctx, query: &str, rules: &RuleArgs, lan_direct: bool) -> Result<Output, String> {
    require_user(ctx)?;
    let mut profile = xray_profile(ctx, query)?;
    let mut policies = Vec::new();
    let mut notes = Vec::new();
    for Wanted {
        target,
        selectors: domains,
        ..
    } in wanted(rules)?
    {
        check_not_pinned(&profile, &domains)?;
        notes.extend(hints(&domains));
        if !domains.is_empty() {
            policies.push(DomainPolicy { domains, target });
        }
    }
    profile.private_lan_direct = lan_direct;
    save(ctx, profile, policies, notes)
}

#[derive(Clone, Copy, PartialEq)]
enum Edit {
    Add,
    Remove,
}

/// Adds or removes single selectors and leaves the rest, in its order, alone.
fn edit(ctx: &Ctx, query: &str, rules: &RuleArgs, how: Edit) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let lists = wanted(rules)?;
    if lists.iter().all(|list| list.selectors.is_empty()) {
        return Err("Name at least one selector with --block, --proxy or --direct".into());
    }
    let mut policies = profile.domain_policies.clone();
    let mut notes = Vec::new();
    for Wanted {
        target,
        name,
        selectors,
    } in lists
    {
        for selector in selectors {
            let holder = LISTS.iter().find(|(_, other)| {
                *other != target && selectors_of(&policies, *other).contains(&selector)
            });
            let present = selectors_of(&policies, target).contains(&selector);
            match how {
                Edit::Add => {
                    check_not_pinned(&profile, std::slice::from_ref(&selector))?;
                    if let Some((other, _)) = holder {
                        return Err(format!(
                            "{selector} is already in the {other} list; remove it there first"
                        ));
                    }
                    if present {
                        continue;
                    }
                    notes.extend(hints(std::slice::from_ref(&selector)));
                    match policies.iter_mut().find(|policy| policy.target == target) {
                        Some(policy) => policy.domains.push(selector),
                        None => policies.push(DomainPolicy {
                            domains: vec![selector],
                            target,
                        }),
                    }
                }
                Edit::Remove => {
                    if !present {
                        return Err(format!("{selector} is not in the {name} list"));
                    }
                    for policy in policies.iter_mut().filter(|policy| policy.target == target) {
                        policy.domains.retain(|domain| *domain != selector);
                    }
                }
            }
        }
    }
    policies.retain(|policy| !policy.domains.is_empty());
    save(ctx, profile, policies, notes)
}

/// The node a pin targets: a server of the subscription (number, name part)
/// or a raw key — a node that left the list may still be pinned so its
/// selectors wake up when it comes back.
fn pin_key(ctx: &Ctx, profile: &Profile, via: &str) -> Result<(String, String), String> {
    if profile.subscription.is_none() {
        return Err("Pinned rules need a subscription profile".into());
    }
    let rows = endpoints::list_rows(ctx, profile)?;
    let key = endpoints::backup_key(&rows, via)?;
    let name = rows
        .iter()
        .find(|row| row.key == key)
        .map(|row| row.name.clone())
        .unwrap_or_else(|| key.clone());
    Ok((key, name))
}

fn save_pins(ctx: &Ctx, profile: &Profile, routes: Vec<PinnedRoute>) -> Result<(), String> {
    let candidate = if profile
        .xray_service_checks
        .iter()
        .any(|check| check.background)
    {
        let mut candidate = profile.clone();
        candidate.pinned_policies = routes.clone();
        net_manager_core::profiles::validate_profile(&candidate)
            .map_err(|_| "The pinned-route configuration is invalid".to_string())?;
        super::checks::sync_background(ctx, &candidate, &candidate.xray_service_checks)?;
        Some(candidate)
    } else {
        None
    };
    let saved = subscription::set_pinned_routes(&ctx.vault(), &ctx.store(), &profile.id, routes);
    if saved.is_err() {
        if let Some(candidate) = candidate {
            super::checks::sync_background(ctx, &candidate, &[])?;
        }
    }
    saved
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::InvalidInput => error.to_string(),
            _ => "The pinned rules could not be saved. Check file permissions.".into(),
        })
        .map(|_| ())
}

/// Whether the tunnel is up: changes are stored either way, the notice tells
/// the user a reconnect puts them into effect. A daemon error counts as
/// "unknown" → treat as running so the notice is always safe.
fn running(ctx: &Ctx, profile: &Profile) -> bool {
    !LinuxEngine::handles(profile)
        || ctx
            .engine
            .status(profile)
            .map(|status| status.state != TunnelState::Stopped)
            .unwrap_or(true)
}

/// The notice that a stored change reaches the tunnel only on reconnect.
fn apply_note(running: bool) -> &'static str {
    if running {
        "\nSaved; reconnect to apply (`netorch down` then `netorch up`)."
    } else {
        ""
    }
}

/// Pins selectors to one node: while that node is down or gone from the
/// subscription the selectors are blocked — never sent direct or through
/// another server.
fn pin(ctx: &Ctx, query: &str, via: &str, selectors: &[String]) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let (key, name) = pin_key(ctx, &profile, via)?;
    let mut checked = Vec::new();
    for selector in selectors {
        let selector = valid_selector(selector)?;
        if is_address(&selector) || selector.starts_with("geoip:") {
            return Err(format!(
                "Pinned rules take domain selectors only ({selector}); send addresses \
                 through --proxy/--direct/--block instead"
            ));
        }
        if !checked.contains(&selector) {
            checked.push(selector);
        }
    }
    let mut routes = profile.pinned_policies.clone();
    for selector in &checked {
        if let Some(other) = routes
            .iter()
            .find(|route| route.endpoint_key != key && route.selectors.contains(selector))
        {
            return Err(format!(
                "{selector} is pinned to {}; remove it there first (`netorch route unpin`)",
                other.endpoint_key
            ));
        }
        if profile
            .domain_policies
            .iter()
            .any(|policy| policy.domains.contains(selector))
        {
            return Err(format!(
                "{selector} is already a routing rule; remove it there first (`netorch route rm`)"
            ));
        }
    }
    match routes.iter_mut().find(|route| route.endpoint_key == key) {
        Some(route) => {
            for selector in &checked {
                if !route.selectors.contains(selector) {
                    route.selectors.push(selector.clone());
                }
            }
        }
        None => routes.push(PinnedRoute {
            selectors: checked.clone(),
            endpoint_key: key,
            missing: false,
        }),
    }
    let running = running(ctx, &profile);
    save_pins(ctx, &profile, routes)?;
    Ok((
        json!({"id": profile.id, "server": name, "selectors": checked,
            "requiresReconnect": running}),
        format!(
            "{} now go through {} of \"{}\", nowhere else{}",
            checked.join(", "),
            name,
            profile.name,
            apply_note(running)
        ),
    ))
}

/// Removes pinned selectors — or the whole pinned route when none are named.
fn unpin(ctx: &Ctx, query: &str, via: &str, selectors: &[String]) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let (key, name) = pin_key(ctx, &profile, via)?;
    let mut routes = profile.pinned_policies.clone();
    let Some(position) = routes.iter().position(|route| route.endpoint_key == key) else {
        return Err(format!("Nothing is pinned to {name}"));
    };
    if selectors.is_empty() {
        routes.remove(position);
    } else {
        let mut removed = Vec::new();
        for selector in selectors {
            let selector = selector.trim();
            if !routes[position].selectors.iter().any(|s| s == selector) {
                return Err(format!("{selector} is not pinned to {name}"));
            }
            removed.push(selector.to_string());
        }
        routes[position]
            .selectors
            .retain(|selector| !removed.contains(selector));
        if routes[position].selectors.is_empty() {
            routes.remove(position);
        }
    }
    let running = running(ctx, &profile);
    save_pins(ctx, &profile, routes)?;
    Ok((
        json!({"id": profile.id, "server": name, "requiresReconnect": running}),
        format!(
            "Unpinned {} of \"{}\"{}",
            name,
            profile.name,
            apply_note(running)
        ),
    ))
}

/// `route quic`: the daemon's kernel-level QUIC handling for the tunnel.
/// `on` answers outbound UDP/443 with a rejection so browsers fall back to
/// TCP at once; `off` removes this rule without changing other routing policy.
/// A profile setting, applied at connect — a running tunnel is unaffected
/// until it reconnects.
fn quic(ctx: &Ctx, query: &str, enabled: Option<super::args::BoolOnOff>) -> Result<Output, String> {
    let profile = xray_profile(ctx, query)?;
    let Some(enabled) = enabled else {
        return Ok((
            json!({"id": profile.id, "quicReject": profile.xray_quic_reject}),
            format!(
                "QUIC reject is {} for \"{}\"",
                if profile.xray_quic_reject {
                    "on"
                } else {
                    "off"
                },
                profile.name
            ),
        ));
    };
    require_user(ctx)?;
    let on = matches!(enabled, super::args::BoolOnOff::On);
    let running = running(ctx, &profile);
    ctx.store()
        .update_profile(&profile.id, |current| {
            if current.backend != TunnelBackend::Xray {
                return Err(std::io::Error::other(
                    "Profile is no longer an Xray profile",
                ));
            }
            current.xray_quic_reject = on;
            Ok(())
        })
        .map_err(|_| "The QUIC rejection setting could not be saved".to_string())?;
    Ok((
        json!({"id": profile.id, "quicReject": on, "requiresReconnect": running}),
        format!(
            "QUIC reject is {} for \"{}\"{}",
            if on { "on" } else { "off" },
            profile.name,
            apply_note(running)
        ),
    ))
}

fn load_asset<T>(dir: &Path, name: &str, parse: fn(&[u8]) -> std::io::Result<T>) -> Option<T> {
    let path = dir.join(name);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_GEO_ASSET_BYTES {
        return None;
    }
    parse(&std::fs::read(path).ok()?).ok()
}

/// Which rule of the profile decides a host or address, replayed offline.
fn check(ctx: &Ctx, target: &str, query: &str, geo_dir: &Path) -> Result<Output, String> {
    let profile = xray_profile(ctx, query)?;
    let geo_site = load_asset(geo_dir, "geosite.dat", GeoSiteDb::parse);
    let geo_ip = load_asset(geo_dir, "geoip.dat", GeoIpDb::parse);
    let geo = GeoDbs {
        geo_site: geo_site.as_ref(),
        geo_ip: geo_ip.as_ref(),
    };
    let options = ProfileRoutingOptions::from(&profile);
    let result = check_route(&profile.domain_policies, &options, target, &geo)
        .map_err(|error| error.to_string())?;
    let mut value =
        serde_json::to_value(&result).map_err(|_| "The route check failed".to_string())?;
    let mut uncertain_pin = false;
    for route in &profile.pinned_policies {
        let pinned = check_route(
            &[DomainPolicy {
                domains: route.selectors.clone(),
                target: DomainRouteTarget::Proxy,
            }],
            &ProfileRoutingOptions::default(),
            &result.target,
            &geo,
        )
        .map_err(|error| error.to_string())?;
        if pinned.matched_selector.is_some() {
            value =
                serde_json::to_value(&pinned).map_err(|_| "The route check failed".to_string())?;
            value
                .as_object_mut()
                .expect("route result")
                .remove("policyIndex");
            value["endpointKey"] = json!(route.endpoint_key);
            value["source"] = json!("pinned");
            value["outbound"] = if route.missing {
                json!("block")
            } else {
                json!(net_manager_core::xray::pin_tag(&route.endpoint_key))
            };
            break;
        }
        uncertain_pin |=
            pinned.certainty == net_manager_core::route_check::RouteCheckCertainty::Probable;
    }
    if uncertain_pin {
        value["certainty"] = json!("probable");
        value["notes"]
            .as_array_mut()
            .expect("route notes")
            .push(json!(
                "An earlier pinned selector could not be evaluated locally"
            ));
    }
    let text = describe_check(&value);
    Ok((value, text))
}

fn describe_check(result: &Value) -> String {
    let mut out = format!(
        "{} -> {} ({}{})",
        result["target"].as_str().unwrap_or_default(),
        result["outbound"].as_str().unwrap_or("?"),
        result["source"].as_str().unwrap_or("?"),
        result["matchedSelector"]
            .as_str()
            .map(|selector| format!(": {selector}"))
            .unwrap_or_default()
    );
    if result["certainty"] == "probable" {
        out.push_str("\n  probable: some selectors could not be evaluated locally");
    }
    for note in result["notes"].as_array().into_iter().flatten() {
        out.push_str(&format!("\n  note: {}", note.as_str().unwrap_or_default()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::models::XrayMode;
    use net_manager_engine::linux_engine::LinuxEngine;

    fn policy(target: DomainRouteTarget, domains: &[&str]) -> DomainPolicy {
        DomainPolicy {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            target,
        }
    }

    fn setup(policies: Vec<DomainPolicy>) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = Ctx::new(dir.path().to_path_buf(), LinuxEngine::new("test")).unwrap();
        ctx.root_user = false;
        ctx.store()
            .upsert(Profile {
                id: "x1".into(),
                name: "Work".into(),
                backend: TunnelBackend::Xray,
                xray_mode: XrayMode::Tun,
                config_path: "x1.json".into(),
                domain_policies: policies,
                ..Default::default()
            })
            .unwrap();
        ctx.store()
            .upsert(Profile {
                id: "static1".into(),
                name: "Static".into(),
                backend: TunnelBackend::None,
                ..Default::default()
            })
            .unwrap();
        (dir, ctx)
    }

    fn rules(block: &[&str], proxy: &[&str], direct: &[&str]) -> RuleArgs {
        let own = |list: &[&str]| list.iter().map(|s| s.to_string()).collect();
        RuleArgs {
            block: own(block),
            proxy: own(proxy),
            direct: own(direct),
        }
    }

    fn direct_of(ctx: &Ctx) -> Vec<String> {
        selectors_of(
            &ctx.find("x1").unwrap().domain_policies,
            DomainRouteTarget::Direct,
        )
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn the_geo_directory_follows_the_pinned_xray() {
        assert_eq!(
            XRAY_VERSION,
            net_manager_core::managed_xray::LINUX_XRAY_VERSION
        );
    }

    #[test]
    fn show_lists_every_xray_profile_and_skips_the_rest() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:a.test", "10.0.0.0/8"],
        )]);
        let (value, text) = show(&ctx, None).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(value[0]["direct"], json!(["domain:a.test", "10.0.0.0/8"]));
        assert!(text.contains("direct") && text.contains("domain:a.test, 10.0.0.0/8"));
        assert!(text.contains("block  -"));
        assert!(show(&ctx, Some("static1")).is_err());
    }

    #[test]
    fn set_replaces_all_lists_and_the_lan_flag() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:old.test"],
        )]);
        let (value, _) = set(
            &ctx,
            "x1",
            &rules(&["geosite:category-ads"], &["domain:p.test"], &[]),
            true,
        )
        .unwrap();
        assert_eq!(value["direct"], json!([]));
        assert_eq!(value["block"], json!(["geosite:category-ads"]));
        assert_eq!(value["privateLanDirect"], true);
        let saved = ctx.find("x1").unwrap();
        assert_eq!(saved.domain_policies.len(), 2);
        assert!(saved.private_lan_direct);
    }

    #[test]
    fn invalid_selectors_are_refused_and_nothing_is_saved() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:keep.test"],
        )]);
        for bad in ["", "# note", "geosite:", "geoip:no way"] {
            let error = set(&ctx, "x1", &rules(&[], &[], &[bad]), false).unwrap_err();
            assert!(error.contains("Invalid routing selector"), "{bad}: {error}");
        }
        assert_eq!(direct_of(&ctx), vec!["domain:keep.test".to_string()]);
    }

    #[test]
    fn add_appends_in_place_skips_duplicates_and_refuses_the_other_list() {
        let (_dir, ctx) = setup(vec![
            policy(DomainRouteTarget::Direct, &["domain:a.test"]),
            policy(DomainRouteTarget::Proxy, &["domain:p.test"]),
        ]);
        add_direct(&ctx, &["domain:a.test", "178.72.138.220", "178.72.138.220"]);
        assert_eq!(
            direct_of(&ctx),
            vec!["domain:a.test".to_string(), "178.72.138.220".into()]
        );
        let saved = ctx.find("x1").unwrap();
        assert_eq!(saved.domain_policies[1].target, DomainRouteTarget::Proxy);
        let error = edit(&ctx, "x1", &rules(&[], &[], &["domain:p.test"]), Edit::Add).unwrap_err();
        assert!(error.contains("already in the proxy list"), "{error}");
    }

    fn add_direct(ctx: &Ctx, selectors: &[&str]) {
        edit(ctx, "x1", &rules(&[], &[], selectors), Edit::Add).unwrap();
    }

    #[test]
    fn rm_removes_selectors_drops_empty_rules_and_names_a_missing_one() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:a.test", "domain:b.test"],
        )]);
        edit(
            &ctx,
            "x1",
            &rules(&[], &[], &["domain:a.test"]),
            Edit::Remove,
        )
        .unwrap();
        assert_eq!(direct_of(&ctx), vec!["domain:b.test".to_string()]);
        edit(
            &ctx,
            "x1",
            &rules(&[], &[], &["domain:b.test"]),
            Edit::Remove,
        )
        .unwrap();
        assert!(ctx.find("x1").unwrap().domain_policies.is_empty());
        let error = edit(
            &ctx,
            "x1",
            &rules(&[], &[], &["domain:b.test"]),
            Edit::Remove,
        )
        .unwrap_err();
        assert!(error.contains("not in the direct list"), "{error}");
        let error = edit(&ctx, "x1", &rules(&[], &[], &[]), Edit::Add).unwrap_err();
        assert!(error.contains("at least one selector"));
    }

    #[test]
    fn writes_need_a_user_and_an_xray_profile() {
        let (_dir, mut ctx) = setup(vec![]);
        assert!(edit(
            &ctx,
            "static1",
            &rules(&[], &[], &["domain:a.test"]),
            Edit::Add
        )
        .is_err());
        ctx.root_user = true;
        let error = set(&ctx, "x1", &rules(&[], &[], &["domain:a.test"]), false).unwrap_err();
        assert!(error.contains("without sudo"), "{error}");
        assert!(direct_of(&ctx).is_empty());
    }

    #[test]
    fn a_bare_name_gets_a_hint_but_prefixed_selectors_and_addresses_do_not() {
        let (_dir, ctx) = setup(vec![]);
        let (_, text) = set(
            &ctx,
            "x1",
            &rules(&[], &[], &["ru", "domain:a.test", "10.0.0.0/8", "::1"]),
            false,
        )
        .unwrap();
        assert!(
            text.contains("\"ru\" matches any name that contains it"),
            "{text}"
        );
        assert_eq!(text.matches("note:").count(), 1);
    }

    #[test]
    fn check_names_the_rule_that_decides_a_host() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:ds-mind-lab.ru", "178.72.138.220"],
        )]);
        let nowhere = Path::new("/nonexistent/geo");
        let (value, text) = check(&ctx, "git.ds-mind-lab.ru", "x1", nowhere).unwrap();
        assert_eq!(value["outbound"], "direct");
        assert!(text.contains("domain:ds-mind-lab.ru"), "{text}");
        let (value, _) = check(&ctx, "178.72.138.220", "x1", nowhere).unwrap();
        assert_eq!(value["outbound"], "direct");
        let (value, _) = check(&ctx, "example.com", "x1", nowhere).unwrap();
        assert_eq!(value["outbound"], "proxy");
    }
}
