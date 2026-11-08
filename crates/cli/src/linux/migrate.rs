//! Preview or apply a standalone Xray routing policy to a saved profile.
//! Source configs and parser/validator payloads never enter error output.

use super::commands::Output;
use super::ctx::Ctx;
use super::library::require_user;
#[cfg(not(target_os = "linux"))]
use net_manager_core::config_vault::SubscriptionEndpoint;
#[cfg(not(target_os = "linux"))]
use net_manager_core::models::TunnelState;
use net_manager_core::models::{DomainRouteTarget, Profile, TunnelBackend};
#[cfg(not(target_os = "linux"))]
use net_manager_core::subscription;
#[cfg(not(target_os = "linux"))]
use net_manager_core::xray_migrate;
use net_manager_core::xray_migrate::XrayPolicyMigration;
#[cfg(not(target_os = "linux"))]
use net_manager_engine::linux_engine::LinuxEngine;
use serde_json::{json, Value};
#[cfg(not(target_os = "linux"))]
use std::io::Read;
use std::path::Path;

pub fn run(ctx: &Ctx, command: super::args::MigrateCommand) -> Result<Output, String> {
    use super::args::MigrateCommand;
    match command {
        MigrateCommand::Preview { profile, from } => preview(ctx, &profile, &from),
        MigrateCommand::Apply { profile, from } => apply(ctx, &profile, &from),
    }
}

fn xray_profile(ctx: &Ctx, query: &str) -> Result<Profile, String> {
    let profile = ctx.find(query)?;
    if profile.backend != TunnelBackend::Xray {
        return Err("Policy migration requires an Xray profile".into());
    }
    Ok(profile)
}

#[cfg(not(target_os = "linux"))]
fn read_source(path: &Path) -> Result<Value, String> {
    const LIMIT: u64 = 512 * 1024;
    let mut body = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(LIMIT + 1).read_to_end(&mut body))
        .map_err(|_| "The selected Xray policy file could not be read".to_string())?;
    if body.len() as u64 > LIMIT {
        return Err("The selected Xray policy exceeds 512 KiB".into());
    }
    serde_json::from_slice(&body)
        .map_err(|_| "The selected file is not a JSON Xray configuration".to_string())
}

#[cfg(not(target_os = "linux"))]
fn source_endpoints(ctx: &Ctx, profile: &Profile) -> Result<Vec<SubscriptionEndpoint>, String> {
    if profile.subscription.is_none() {
        return Ok(Vec::new());
    }
    ctx.vault()
        .read_subscription_endpoints(&profile.id)
        .map_err(|_| "The subscription endpoint vault could not be read".to_string())
}

#[cfg(not(target_os = "linux"))]
fn primary_key(profile: &Profile, endpoints: &[SubscriptionEndpoint]) -> Option<String> {
    let subscription = profile.subscription.as_ref()?;
    subscription.active_key.clone().or_else(|| {
        endpoints
            .get(subscription.active_index)
            .map(|endpoint| subscription::endpoint_key(&endpoint.url))
    })
}

#[cfg(not(target_os = "linux"))]
fn plan(
    profile: &Profile,
    source: &Value,
    endpoints: &[SubscriptionEndpoint],
) -> Result<XrayPolicyMigration, String> {
    let primary = primary_key(profile, endpoints);
    xray_migrate::plan_xray_policy_migration(
        source,
        primary.as_deref(),
        xray_migrate::subscription_outbound_resolver(endpoints, primary.as_deref()),
    )
    .map_err(|_| "The selected Xray policy could not be planned".to_string())
}

fn policy_counts(migration: &XrayPolicyMigration) -> Value {
    let count = |target| {
        migration
            .domain_policies
            .iter()
            .filter(|policy| policy.target == target)
            .map(|policy| policy.domains.len())
            .sum::<usize>()
    };
    json!({
        "direct": count(DomainRouteTarget::Direct),
        "proxy": count(DomainRouteTarget::Proxy),
        "block": count(DomainRouteTarget::Block),
    })
}

fn preview_value(migration: &XrayPolicyMigration) -> Value {
    json!({
        "policies": policy_counts(migration),
        "pinnedRoutes": migration.pinned_routes.len(),
        "backupNodes": migration.backup_keys.as_ref().map(Vec::len),
        "trafficRules": migration.traffic_rules.len(),
        "interfaceRoutes": migration.interface_routes.len(),
        "privateLanDirect": migration.private_lan_direct,
        "quicReject": migration.quic_reject,
        "domainStrategy": migration.domain_strategy,
        "domainMatcher": migration.domain_matcher,
        "endpointBypassCount": migration.endpoint_bypasses.len(),
        "hasGeoipOverride": migration.geoip_url.is_some(),
        "hasGeositeOverride": migration.geosite_url.is_some(),
        "hasDns": !migration.dns.is_empty(),
        "hasSockopts": migration.sockopts.is_some(),
        "connectionIdleSecs": migration.connection_idle_secs,
        "tunMtu": migration.tun_mtu,
        "tunDnsServerCount": migration.tun_dns_servers.len(),
        "hasDirectDomainStrategy": migration.direct_domain_strategy.is_some(),
        "skipped": migration.skipped.iter().map(|item| {
            json!({"reason": item.reason})
        }).collect::<Vec<_>>(),
        "refused": migration.refused.iter().map(|item| {
            json!({"reason": item.reason})
        }).collect::<Vec<_>>(),
    })
}

fn preview_text(migration: &XrayPolicyMigration) -> String {
    let counts = policy_counts(migration);
    let mut text = format!(
        "Rules: {} direct; {} proxy; {} blocked\n\
         Pins: {}; traffic guards: {}; interface routes: {}\n\
         DNS policy: {}; socket policy: {}; QUIC rejection: {}",
        counts["direct"],
        counts["proxy"],
        counts["block"],
        migration.pinned_routes.len(),
        migration.traffic_rules.len(),
        migration.interface_routes.len(),
        !migration.dns.is_empty(),
        migration.sockopts.is_some(),
        migration.quic_reject,
    );
    if let Some(backups) = &migration.backup_keys {
        text.push_str(&format!(
            "\nThe source default pool replaces the explicit backup chain with {} nodes.",
            backups.len()
        ));
    }
    if let Some(mtu) = migration.tun_mtu {
        text.push_str(&format!("\nTUN MTU: {mtu}"));
    }
    if let Some(seconds) = migration.connection_idle_secs {
        text.push_str(&format!("\nConnection idle timeout: {seconds} seconds"));
    }
    for item in &migration.skipped {
        text.push_str(&format!("\nSkipped source construct: {}", item.reason));
    }
    for item in &migration.refused {
        text.push_str(&format!("\nRefused source construct: {}", item.reason));
    }
    if migration.refused.is_empty() {
        text.push_str("\nNo constructs refused.");
    } else {
        text.push_str("\nApply is blocked; no policy has been changed.");
    }
    text
}

#[cfg(not(target_os = "linux"))]
fn preview(ctx: &Ctx, query: &str, path: &Path) -> Result<Output, String> {
    let profile = xray_profile(ctx, query)?;
    let endpoints = source_endpoints(ctx, &profile)?;
    let source = read_source(path)?;
    let migration = plan(&profile, &source, &endpoints)?;
    Ok((preview_value(&migration), preview_text(&migration)))
}

#[cfg(not(target_os = "linux"))]
fn apply(ctx: &Ctx, query: &str, path: &Path) -> Result<Output, String> {
    require_user(ctx)?;
    let expected = xray_profile(ctx, query)?;
    let expected_endpoints = source_endpoints(ctx, &expected)?;
    let source = read_source(path)?;
    let migration = plan(&expected, &source, &expected_endpoints)?;

    if !migration.refused.is_empty() {
        return Err(format!(
            "Policy migration refused {} source construct(s); \
             use migrate preview for the refusal categories. Nothing was changed.",
            migration.refused.len()
        ));
    }

    let mut value = preview_value(&migration);
    let summary = preview_text(&migration);
    if LinuxEngine::handles(&expected)
        && ctx.engine.status(&expected)?.state != TunnelState::Stopped
    {
        return Err("Disconnect the profile before applying a routing-policy migration".into());
    }
    let vault = ctx.vault();

    ctx.store()
        .update_profile(&expected.id, |current| {
            if current != &expected {
                return Err(std::io::Error::other("Profile changed during migration"));
            }
            if expected.subscription.is_some() {
                let endpoints = vault
                    .read_subscription_endpoints(&expected.id)
                    .map_err(|_| std::io::Error::other("Endpoint vault could not be read"))?;
                if endpoints != expected_endpoints {
                    return Err(std::io::Error::other(
                        "Subscription changed during migration",
                    ));
                }
            }

            xray_migrate::apply_xray_policy_migration(current, migration)
                .map_err(|_| std::io::Error::other("Policy could not be applied"))?;

            if current.subscription.is_some() {
                let live = expected_endpoints
                    .iter()
                    .map(|endpoint| subscription::endpoint_key(&endpoint.url))
                    .collect::<std::collections::HashSet<_>>();
                for pin in &mut current.pinned_policies {
                    pin.missing = !live.contains(&pin.endpoint_key);
                }
            }
            Ok(())
        })
        .map_err(|_| {
            "Policy migration was not saved. The profile or endpoint selection may \
             have changed, the policy may conflict with existing pins, or the store \
             may be unwritable. Preview again before retrying."
                .to_string()
        })?;

    value["applied"] = json!(true);
    value["requiresReconnect"] = json!(false);
    Ok((
        value,
        format!("Applied the local Xray routing policy.\n{summary}"),
    ))
}

#[cfg(target_os = "linux")]
fn preview(ctx: &Ctx, query: &str, path: &Path) -> Result<Output, String> {
    let profile = xray_profile(ctx, query)?;
    let (migration, _) = net_manager_engine::linux_profiles::ProfileService::new(
        ctx.root.clone(),
        ctx.engine.clone(),
    )
    .plan_migration(&profile.id, path)?;
    Ok((preview_value(&migration), preview_text(&migration)))
}

#[cfg(target_os = "linux")]
fn apply(ctx: &Ctx, query: &str, path: &Path) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let service = net_manager_engine::linux_profiles::ProfileService::new(
        ctx.root.clone(),
        ctx.engine.clone(),
    );
    let (migration, _) = service.plan_migration(&profile.id, path)?;
    let mut value = preview_value(&migration);
    let summary = preview_text(&migration);
    service.apply_migration(&profile.id, path)?;
    value["applied"] = json!(true);
    value["requiresReconnect"] = json!(false);
    Ok((
        value,
        format!("Applied the local Xray routing policy.\n{summary}"),
    ))
}
