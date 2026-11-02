//! Saved HTTPS diagnostics through explicit domain/DNS pins.
//!
//! These commands never create pins, select another endpoint, reconnect,
//! reload Xray, or modify routing. Destination URLs are never output.

use super::args::{BoolOnOff, ChecksCommand};
use super::commands::Output;
use super::ctx::Ctx;
use super::endpoints;
use super::library::require_user;
use net_manager_core::backend_settings::BackendSettingsStore;
use net_manager_core::config_vault::SubscriptionEndpoint;
use net_manager_core::models::{
    Profile, ServiceCheck, ServiceCheckResult, TunnelBackend, TunnelState,
};
use net_manager_core::{profiles, service_checks, subscription, vpn};
use net_manager_engine::linux_engine::LinuxEngine;
use serde_json::{json, Value};
use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;

pub fn run(ctx: &Ctx, command: ChecksCommand) -> Result<Output, String> {
    match command {
        ChecksCommand::List { profile } => {
            let profile = xray_profile(ctx, &profile)?;
            Ok(configuration_output(&profile.xray_service_checks))
        }
        ChecksCommand::Add {
            profile,
            via,
            name,
            url,
            background,
        } => {
            require_user(ctx)?;
            let profile = xray_profile(ctx, &profile)?;
            let expected_endpoints = read_endpoints(ctx, &profile)?;
            let endpoint_key = pinned_key(ctx, &profile, &via)?;
            let mut checks = profile.xray_service_checks.clone();

            // IDs are independent of destinations and remain stable while
            // the saved check exists.
            let id = (1..=service_checks::MAX_SERVICE_CHECKS + 1)
                .map(|number| format!("check-{number}"))
                .find(|id| checks.iter().all(|check| check.id != *id))
                .ok_or_else(|| "No service-check identifier is available".to_string())?;

            checks.push(ServiceCheck {
                id,
                name,
                url,
                endpoint_key,
                background,
            });
            save(ctx, &profile, &expected_endpoints, checks)
        }
        ChecksCommand::Remove { profile, id } => {
            require_user(ctx)?;
            let profile = xray_profile(ctx, &profile)?;
            let expected_endpoints = read_endpoints(ctx, &profile)?;
            let mut checks = profile.xray_service_checks.clone();
            let index = checks
                .iter()
                .position(|check| check.id == id)
                .ok_or_else(|| "No saved check has that identifier".to_string())?;
            checks.remove(index);
            save(ctx, &profile, &expected_endpoints, checks)
        }
        ChecksCommand::Background {
            profile,
            id,
            enabled,
        } => {
            require_user(ctx)?;
            let profile = xray_profile(ctx, &profile)?;
            let expected_endpoints = read_endpoints(ctx, &profile)?;
            let mut checks = profile.xray_service_checks.clone();
            let check = checks
                .iter_mut()
                .find(|check| check.id == id)
                .ok_or_else(|| "No saved check has that identifier".to_string())?;
            check.background = matches!(enabled, BoolOnOff::On);
            save(ctx, &profile, &expected_endpoints, checks)
        }
        ChecksCommand::Run { profile, ids } => execute(ctx, &profile, &ids),
    }
}

fn xray_profile(ctx: &Ctx, query: &str) -> Result<Profile, String> {
    // Ctx::find embeds the supplied query in errors; do not propagate it.
    let profile = ctx
        .find(query)
        .map_err(|_| "The requested profile could not be selected".to_string())?;
    if profile.backend != TunnelBackend::Xray {
        return Err("Service checks require an Xray profile".into());
    }
    Ok(profile)
}

fn read_endpoints(ctx: &Ctx, profile: &Profile) -> Result<Vec<SubscriptionEndpoint>, String> {
    if profile.subscription.is_none() {
        return Ok(Vec::new());
    }
    ctx.vault()
        .read_subscription_endpoints(&profile.id)
        .map_err(|_| "The saved endpoint list could not be read".to_string())
}

fn pinned_key(ctx: &Ctx, profile: &Profile, query: &str) -> Result<String, String> {
    if profile.subscription.is_none() {
        return Err("A service check requires an explicitly pinned subscription endpoint".into());
    }

    // A canonical key is resolved before numeric row selection. A key may
    // contain only decimal digits, and an explicit pin may currently be
    // missing from the subscription.
    if subscription::valid_endpoint_key(query) {
        return if service_checks::service_check_is_bound(profile, query) {
            Ok(query.to_string())
        } else {
            Err("The selected endpoint is not explicitly pinned".into())
        };
    }

    let rows = endpoints::list_rows(ctx, profile)
        .map_err(|_| "The saved endpoint list could not be read".to_string())?;
    let index = endpoints::pick(&rows, query)
        .map_err(|_| "The endpoint selection is absent or ambiguous".to_string())?;
    let row = rows
        .get(index)
        .ok_or_else(|| "The endpoint selection is not available".to_string())?;

    if !service_checks::service_check_is_bound(profile, &row.key) {
        return Err("The selected endpoint is not explicitly pinned".into());
    }
    Ok(row.key.clone())
}

fn unchanged(
    ctx: &Ctx,
    expected: &Profile,
    expected_endpoints: &[SubscriptionEndpoint],
) -> Result<(), String> {
    let current = ctx
        .find(&expected.id)
        .map_err(|_| "The profile changed during the operation".to_string())?;
    if current != *expected || read_endpoints(ctx, &current)? != expected_endpoints {
        return Err("The profile or endpoint selection changed; repeat the operation".into());
    }
    Ok(())
}

/// Runtime-only suppression: retain all canonical saved specs, but never
/// permit an old live pin listener to keep an unbound check probing.
fn runtime_checks(profile: &Profile, checks: &[ServiceCheck]) -> Vec<ServiceCheck> {
    checks
        .iter()
        .filter(|check| {
            check.background && service_checks::service_check_is_bound(profile, &check.endpoint_key)
        })
        .cloned()
        .collect()
}

/// Also called by the pin-edit integration described below.
///
/// This sends local IPC only. The daemon cancels the old worker before
/// replacing it, and enabled diagnostics wait until the scheduled round.
pub(super) fn sync_background(
    ctx: &Ctx,
    profile: &Profile,
    checks: &[ServiceCheck],
) -> Result<(), String> {
    if !LinuxEngine::handles(profile)
        || (!profile
            .xray_service_checks
            .iter()
            .any(|check| check.background)
            && !checks.iter().any(|check| check.background))
    {
        return Ok(());
    }

    if ctx
        .engine
        .set_xray_service_checks(&profile.id, runtime_checks(profile, checks))
        .is_ok()
    {
        return Ok(());
    }

    // A transient socket error is not evidence that an existing worker
    // stopped. Only authoritative disconnected status permits this fallback.
    if ctx
        .engine
        .status(profile)
        .is_ok_and(|status| status.state == TunnelState::Stopped)
    {
        Ok(())
    } else {
        Err("The daemon did not confirm the diagnostic change; configuration was not saved".into())
    }
}

fn save(
    ctx: &Ctx,
    expected: &Profile,
    expected_endpoints: &[SubscriptionEndpoint],
    checks: Vec<ServiceCheck>,
) -> Result<Output, String> {
    // Validate before touching the worker or profile document.
    service_checks::validate_service_checks(&checks)
        .map_err(|_| "The service-check configuration is invalid".to_string())?;
    let mut candidate = expected.clone();
    candidate.xray_service_checks = checks.clone();
    profiles::validate_profile(&candidate)
        .map_err(|_| "The profile cannot accept this configuration".to_string())?;

    unchanged(ctx, expected, expected_endpoints)?;
    sync_background(ctx, expected, &checks)?;

    let vault = ctx.vault();
    let saved_document = ctx.store().update_profile(&expected.id, |current| {
        if *current != *expected {
            return Err(io::Error::other("selection changed"));
        }
        if current.subscription.is_some()
            && vault.read_subscription_endpoints(&current.id)? != expected_endpoints
        {
            return Err(io::Error::other("selection changed"));
        }
        current.xray_service_checks = checks;
        Ok(())
    });
    let document = match saved_document {
        Ok(document) => document,
        Err(_) => {
            // Never leave an enabled worker backed by a failed configuration save.
            let prior = if expected
                .xray_service_checks
                .iter()
                .any(|check| check.background)
            {
                expected
            } else {
                &candidate
            };
            let stopped = sync_background(ctx, prior, &[]).is_ok();
            return Err(if stopped {
                "Checks were not saved; background diagnostics are stopped."
            } else {
                "Checks were not saved; the daemon did not confirm background cancellation."
            }
            .into());
        }
    };

    let saved = document
        .profiles
        .iter()
        .find(|profile| profile.id == expected.id)
        .ok_or_else(|| "The saved profile could not be read".to_string())?;
    let (value, text) = configuration_output(&saved.xray_service_checks);
    Ok((
        value,
        format!("Saved. No check destination was contacted.\n{text}"),
    ))
}

fn executable(ctx: &Ctx) -> Result<PathBuf, String> {
    let setting = BackendSettingsStore::new(ctx.root.join("backend-settings.json"))
        .get(TunnelBackend::Xray)
        .map_err(|_| "The backend settings could not be read".to_string())?;
    vpn::resolve_xray_executable(setting.as_ref().map(|setting| setting.path.as_path()))
        .map_err(|_| "Xray executable unavailable".to_string())
}

fn execute(ctx: &Ctx, query: &str, ids: &[String]) -> Result<Output, String> {
    // Never execute a user-configured binary as root.
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let expected_endpoints = read_endpoints(ctx, &profile)?;
    let vault = ctx.vault();
    let executable = OnceLock::<Result<PathBuf, String>>::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "The diagnostic runtime could not be started".to_string())?;

    let results = runtime
        .block_on(service_checks::check_profile_services(
            &vault,
            &profile,
            (!ids.is_empty()).then_some(ids),
            || {
                let path = executable
                    .get_or_init(|| self::executable(ctx))
                    .as_ref()
                    .map_err(Clone::clone)?;
                Ok(tokio::process::Command::new(path))
            },
        ))
        .map_err(|_| "The service checks could not be completed".to_string())?;

    // Raw endpoints are compared, not only stable keys. Credential
    // rotation can preserve a transport key.
    unchanged(ctx, &profile, &expected_endpoints)?;
    result_output(results)
}

fn safe_key(value: &str) -> &str {
    if subscription::valid_endpoint_key(value) {
        value
    } else {
        "[invalid key]"
    }
}

fn configuration_output(checks: &[ServiceCheck]) -> Output {
    let rows: Vec<Value> = checks
        .iter()
        .map(|check| {
            json!({
                "id": &check.id,
                "name": &check.name,
                "endpointKey": safe_key(&check.endpoint_key),
                "background": check.background,
            })
        })
        .collect();

    let text = if checks.is_empty() {
        "No saved service checks".to_string()
    } else {
        checks
            .iter()
            .map(|check| {
                format!(
                    "{}  {}  endpoint={}  background={}",
                    check.id,
                    check.name,
                    safe_key(&check.endpoint_key),
                    if check.background { "on" } else { "off" },
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    (Value::Array(rows), text)
}

fn result_output(results: Vec<ServiceCheckResult>) -> Result<Output, String> {
    let value = serde_json::to_value(&results)
        .map_err(|_| "The diagnostic results could not be displayed".to_string())?;
    let text = if results.is_empty() {
        "No service checks selected".to_string()
    } else {
        value
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                format!(
                    "{}  endpoint={}  outcome={}  http={}  latencyMs={}  degraded={}",
                    row["id"].as_str().unwrap_or("[redacted]"),
                    safe_key(row["endpointKey"].as_str().unwrap_or_default()),
                    row["outcome"],
                    row["httpStatus"],
                    row["latencyMs"],
                    row["degraded"],
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok((value, text))
}
