//! Typed routing configuration, imports and native lookups.
use crate::{args::RouteCommand, ctx::Ctx, input};
use net_manager_core::models::{DomainPolicy, DomainRouteTarget, Profile, TunnelBackend, XrayMode};
use net_manager_engine::macos_services::ProfileRoutingUpdate;
use serde_json::{json, Value};
pub fn runs_locally(profile: &Profile) -> bool {
    profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Socks
}
pub fn run(ctx: &Ctx, command: RouteCommand) -> Result<(), String> {
    let services = ctx.services()?;
    match command {
        RouteCommand::Lookup { address } => ctx.output(
            &ctx.network().lookup_route(
                address
                    .parse()
                    .map_err(|_| "Enter an IPv4 or IPv6 address")?,
            )?,
        ),
        RouteCommand::Show { profile } => {
            let p = ctx.find(&profile)?;
            let routing = services.profile_routing(&p.id)?;
            // Retain the existing editor-friendly selector groups, alongside full typed options.
            let mut value =
                serde_json::to_value(&routing).map_err(|_| "Could not encode routing")?;
            for (key, target) in [
                ("block", DomainRouteTarget::Block),
                ("proxy", DomainRouteTarget::Proxy),
                ("direct", DomainRouteTarget::Direct),
            ] {
                value[key] = json!(routing
                    .policies
                    .iter()
                    .filter(|p| p.target == target)
                    .flat_map(|p| p.domains.iter().cloned())
                    .collect::<Vec<_>>()
                    .join("\n"));
            }
            ctx.output(&value)
        }
        RouteCommand::Set {
            profile,
            block,
            proxy,
            direct,
            lan_direct,
            advanced,
            geo,
        } => {
            ctx.require_user()?;
            let p = ctx.find(&profile)?;
            let policies = [
                (block, DomainRouteTarget::Block),
                (proxy, DomainRouteTarget::Proxy),
                (direct, DomainRouteTarget::Direct),
            ]
            .into_iter()
            .filter(|(v, _)| !v.is_empty())
            .map(|(domains, target)| DomainPolicy { domains, target })
            .collect();
            services.set_profile_routing(
                &p.id,
                ProfileRoutingUpdate {
                    policies,
                    private_lan_direct: lan_direct,
                    advanced: advanced
                        .as_deref()
                        .map(|p| input::json(p, false))
                        .transpose()?,
                    geo_urls: geo.as_deref().map(|p| input::json(p, false)).transpose()?,
                },
            )?;
            ctx.emit(crate::ctx::ok_json(), || {
                format!("Rules of \"{}\" saved", p.name)
            });
            Ok(())
        }
        RouteCommand::Check { target, profile } => {
            let p = ctx.find(&profile)?;
            let result = services.check_routing(&target, &services.profile_routing(&p.id)?)?;
            let value =
                serde_json::to_value(result).map_err(|_| "Could not encode route verdict")?;
            ctx.emit(value.clone(), || describe_check(&value));
            Ok(())
        }
        RouteCommand::Import { profile, file } => {
            ctx.require_user()?;
            let p = ctx.find(&profile)?;
            services.import_happ_routing(&p.id, &input::text(&file, false)?)?;
            ctx.output(&services.profile_routing(&p.id)?)
        }
    }
}
fn describe_check(result: &Value) -> String {
    let mut out = format!(
        "{} -> {} ({}{})",
        result["target"].as_str().unwrap_or_default(),
        result["outbound"].as_str().unwrap_or("?"),
        result["source"].as_str().unwrap_or("?"),
        result["matchedSelector"]
            .as_str()
            .map(|s| format!(": {s}"))
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
    #[test]
    fn verdict_names_outbound_and_rule() {
        assert_eq!(
            describe_check(
                &json!({"target":"example.com","outbound":"direct","source":"policy","matchedSelector":"domain:example.com","certainty":"certain","notes":[]})
            ),
            "example.com -> direct (policy: domain:example.com)"
        );
    }
}
