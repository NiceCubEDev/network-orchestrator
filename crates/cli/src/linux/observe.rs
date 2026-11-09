//! Read-only diagnostics and event-driven snapshots.
use super::{commands::Output, compat, ctx::Ctx};
use net_manager_core::daemon_protocol::{event, method};
use net_manager_core::models::{Profile, TunnelBackend, TunnelState};
use net_manager_engine::linux_engine::{daemon_socket, LinuxEngine};
use net_manager_engine::linux_events::{EventError, Subscription};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::time::Duration;

fn observation_engine(ctx: &Ctx) -> LinuxEngine {
    LinuxEngine::for_socket_with_timeout(
        daemon_socket(),
        "netorch-observer",
        Duration::from_secs(2),
    )
    .with_data_root(ctx.root.clone())
}

fn selected(ctx: &Ctx, id: Option<&str>) -> Result<Vec<Profile>, String> {
    let profiles = ctx.profiles()?;
    Ok(profiles
        .into_iter()
        .filter(|p| LinuxEngine::handles(p) && id.is_none_or(|id| p.id == id))
        .collect())
}

fn rows(
    ctx: &Ctx,
    engine: &LinuxEngine,
    id: Option<&str>,
    available: bool,
) -> Result<Vec<Value>, String> {
    selected(ctx, id)?
        .iter()
        .map(|profile| {
            let state = if !available && LinuxEngine::requires_daemon(profile) {
                "unknown"
            } else {
                match engine.status(profile) {
                    Ok(status) => match status.state {
                        TunnelState::Running => "running",
                        TunnelState::Stopped => "stopped",
                        TunnelState::Failed => "failed",
                    },
                    Err(_) => "unknown",
                }
            };
            Ok(json!({"id": profile.id, "name": profile.name, "state": state}))
        })
        .collect()
}

fn emit(
    output: &mut impl Write,
    json_mode: bool,
    reason: &str,
    available: bool,
    profiles: &[Value],
) -> io::Result<()> {
    if json_mode {
        writeln!(
            output,
            "{}",
            json!({"type":"snapshot", "reason":reason, "daemon":if available {"available"} else {"unavailable"}, "profiles":profiles})
        )?;
    } else {
        writeln!(
            output,
            "Snapshot ({reason}; daemon {})",
            if available {
                "available"
            } else {
                "unavailable"
            }
        )?;
        for profile in profiles {
            writeln!(
                output,
                "{}: {}",
                profile["name"].as_str().unwrap_or(""),
                profile["state"].as_str().unwrap_or("unknown")
            )?;
        }
    }
    output.flush()
}

pub(super) const WATCH_UNSUPPORTED: &str =
    "The daemon does not support event subscriptions. Update the daemon.";
pub(super) const WATCH_INCOMPATIBLE: &str =
    "The daemon event protocol is incompatible. Update the daemon or netorch.";
pub(super) const WATCH_PROTOCOL: &str =
    "The daemon sent an invalid event response. Update or repair the daemon.";

fn watch_error(error: EventError) -> String {
    match error {
        EventError::Unsupported => WATCH_UNSUPPORTED,
        EventError::Incompatible => WATCH_INCOMPATIBLE,
        EventError::Protocol => WATCH_PROTOCOL,
        EventError::Unavailable => "The daemon event connection is unavailable.",
    }
    .into()
}

pub fn watch(ctx: &Ctx, target: Option<&str>, json_mode: bool) -> Result<Output, String> {
    let id = target
        .map(|query| {
            ctx.find(query)
                .map(|p| p.id)
                .map_err(|_| "Profile not found or ambiguous; use netorch ls.".to_string())
        })
        .transpose()?;
    let socket = daemon_socket();
    let timeout = Duration::from_secs(1);
    let mut subscription = match Subscription::connect(&socket, timeout) {
        Ok(subscription) => Some(subscription),
        Err(EventError::Unavailable) => None,
        Err(error) => return Err(watch_error(error)),
    };
    let engine = observation_engine(ctx);
    let mut available = subscription.is_some();
    #[cfg(target_os = "linux")]
    if !available && !ctx.root_user {
        let _ = net_manager_engine::linux_diagnostics::try_record_log(
            &ctx.root,
            net_manager_engine::linux_diagnostics::LogLevel::Warn,
            &format!(
                "daemon event stream pid={} state=unavailable reason=initial_connect",
                std::process::id()
            ),
        );
    }
    let mut previous = rows(ctx, &engine, id.as_deref(), available)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if let Err(error) = emit(&mut output, json_mode, "initial", available, &previous) {
        return if error.kind() == io::ErrorKind::BrokenPipe {
            Ok((Value::Null, String::new()))
        } else {
            Err("Cannot write event stream".into())
        };
    }
    loop {
        let mut reason = None;
        if let Some(sub) = &mut subscription {
            match sub.next_event() {
                Ok(Some(frame)) => {
                    reason = Some(if frame.event == event::RESYNC {
                        "resync"
                    } else {
                        "change"
                    })
                }
                Ok(None) => {}
                Err(EventError::Unavailable) => {
                    subscription = None;
                    available = false;
                    reason = Some("disconnected");
                }
                Err(error) => return Err(watch_error(error)),
            }
        } else {
            std::thread::sleep(timeout);
            match Subscription::connect(&socket, timeout) {
                Ok(sub) => {
                    subscription = Some(sub);
                    available = true;
                    reason = Some("reconnected");
                }
                Err(EventError::Unavailable) => {}
                Err(error) => return Err(watch_error(error)),
            }
        }
        #[cfg(target_os = "linux")]
        if !ctx.root_user && matches!(reason, Some("disconnected" | "reconnected" | "resync")) {
            let _ = net_manager_engine::linux_diagnostics::try_record_log(
                &ctx.root,
                net_manager_engine::linux_diagnostics::LogLevel::Warn,
                &format!(
                    "daemon event stream pid={} state={}",
                    std::process::id(),
                    reason.unwrap_or("unknown")
                ),
            );
        }
        let current = rows(ctx, &engine, id.as_deref(), available)?;
        if reason.is_some() || current != previous {
            if let Err(error) = emit(
                &mut output,
                json_mode,
                reason.unwrap_or("change"),
                available,
                &current,
            ) {
                return if error.kind() == io::ErrorKind::BrokenPipe {
                    Ok((Value::Null, String::new()))
                } else {
                    Err("Cannot write event stream".into())
                };
            }
            previous = current;
        }
    }
}

pub fn diagnose(ctx: &Ctx, target: Option<&str>) -> Result<Output, String> {
    let id = target
        .map(|query| {
            ctx.find(query)
                .map(|p| p.id)
                .map_err(|_| "Profile not found or ambiguous; use netorch ls.".to_string())
        })
        .transpose()?;
    let profiles = selected(ctx, id.as_deref())?;
    let engine = observation_engine(ctx);
    let hello = engine.privileged().hello().ok();
    let available = hello.is_some();
    let mut findings = Vec::new();
    if let Some(hello) = &hello {
        let verdict = net_manager_engine::linux_compat::check(hello, compat::CLIENT_VERSION);
        if !verdict.is_usable() {
            findings.push(json!({"level":"error", "code":"daemon_incompatible", "message":"Update the daemon or netorch to compatible versions."}));
        }
        if !hello.capabilities.iter().any(|c| c == method::SUBSCRIBE) {
            findings.push(json!({"level":"warning", "code":"subscribe_unavailable", "message":"Update the daemon to enable event subscriptions."}));
        }
    } else {
        findings.push(json!({"level":"warning", "code":"daemon_unavailable", "message":"Start or install the network daemon for system connections."}));
    }
    for profile in &profiles {
        let capability = match profile.backend {
            TunnelBackend::WireGuard => method::WIREGUARD_CONNECT,
            TunnelBackend::OpenVpn => method::OPENVPN_CONNECT,
            TunnelBackend::Xray => method::XRAY_CONNECT,
            TunnelBackend::None => method::ROUTES_APPLY,
        };
        if LinuxEngine::requires_daemon(profile)
            && hello
                .as_ref()
                .is_some_and(|h| !h.capabilities.iter().any(|c| c == capability))
        {
            findings.push(json!({"level":"error", "code":"capability_missing", "profile":profile.id, "message":"Update the daemon to support this profile."}));
        }
        if net_manager_core::analysis::analyze_profile(profile).is_err() {
            findings.push(json!({"level":"error", "code":"profile_invalid", "profile":profile.id, "message":"Check the saved profile configuration."}));
        }
    }
    let states = rows(ctx, &engine, id.as_deref(), available)?;
    for state in &states {
        if state["state"] == "unknown" {
            findings.push(json!({"level":"warning", "code":"status_unavailable", "profile":state["id"], "message":"Check the daemon or local runtime and retry."}));
        } else if state["state"] == "failed" {
            findings.push(json!({"level":"error", "code":"profile_failed", "profile":state["id"], "message":"The connection failed; inspect the daemon or local runtime and reconnect after resolving the problem."}));
        }
    }
    let text = if findings.is_empty() {
        "No problems detected.".to_string()
    } else {
        findings
            .iter()
            .filter_map(|f| f["message"].as_str())
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok((
        json!({"daemon":{"available":available}, "profiles":states, "findings":findings}),
        text,
    ))
}

pub fn recover(ctx: &Ctx, cleanup: bool) -> Result<Output, String> {
    if !cleanup {
        let (mut report, mut text) = diagnose(ctx, None)?;
        let engine = observation_engine(ctx);
        let owners: Option<net_manager_core::daemon_protocol::OwnedListResult> = engine
            .privileged()
            .call(method::OWNED_LIST, Value::Null)
            .ok();
        let states = owners.as_ref().map(|list| {
            list.owners
                .iter()
                .map(|owner| json!({"owner": owner.owner, "state": owner.state}))
                .collect::<Vec<_>>()
        });
        let proxy = match net_manager_core::system_proxy::load_ownership(
            &ctx.root.join("proxy-state.json"),
        ) {
            Ok(Some(_)) => "present",
            Ok(None) => "absent",
            Err(_) => "unknown",
        };
        text.push_str(&format!(
            "\nDaemon owners: {}; saved proxy ownership: {proxy}.",
            states.as_ref().map_or_else(
                || "unavailable".to_string(),
                |owners| owners.len().to_string()
            )
        ));
        if let Some(owners) = &owners {
            for owner in &owners.owners {
                text.push_str(&format!("\n{}: {:?}", owner.owner, owner.state));
            }
        }
        report["recovery"] = json!({"daemonOwners":states, "proxyOwnership":proxy});
        return Ok((report, text));
    }
    cleanup_recovery(ctx)
}

#[cfg(target_os = "linux")]
fn cleanup_recovery(ctx: &Ctx) -> Result<Output, String> {
    use net_manager_core::daemon_protocol::CleanupResult;
    use net_manager_engine::linux_engine::daemon_error;
    let local_cleanup = ctx.engine.disconnect_local_proxies();
    let local_recovery = ctx.engine.recover_local_proxy();
    let daemon = super::auth::run(ctx.root_user, || {
        ctx.engine
            .privileged()
            .call::<_, CleanupResult>(method::RECOVERY_CLEANUP, Value::Null)
            .map_err(daemon_error)
    });
    let mut failures = Vec::new();
    if local_cleanup.is_err() || local_recovery.is_err() {
        failures.push("local cleanup or proxy restoration failed; check the user runtime");
    }
    if daemon.as_ref().is_err()
        || daemon
            .as_ref()
            .is_ok_and(|result| !result.failed.is_empty())
    {
        failures.push("daemon cleanup failed; check daemon availability and authorization");
    }
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    let count = daemon
        .map(|result| result.removed_owners.len())
        .unwrap_or_default();
    Ok((
        json!({"daemonOwnersRemoved":count, "localCleanup":"complete"}),
        "Recovery cleanup completed.".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn cleanup_recovery(_ctx: &Ctx) -> Result<Output, String> {
    Err("Recovery cleanup is only available on Linux".into())
}
