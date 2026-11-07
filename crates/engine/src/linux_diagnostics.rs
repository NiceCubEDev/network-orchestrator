//! Shared Linux inspection, diagnostics, logs and leftover-only recovery.
use crate::linux_engine::LinuxEngine;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::{
    method, IpFamily, OwnedListResult, OwnedResource, OwnedState, WireGuardFullResource,
};
pub use net_manager_core::exit_ip::ExitIpEntry;
use net_manager_core::explorer;
use net_manager_core::models::*;
use net_manager_core::profiles::ProfileStore;
use net_manager_core::system_proxy::ProxyOwnership;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
#[cfg(test)]
use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
pub struct DiagnosticsInput {
    pub profile: Profile,
    pub status: TunnelStatus,
    pub managed: bool,
    pub inspection: Option<ProfileInspection>,
    pub inspection_error: Option<String>,
    pub executable: Result<PathBuf, String>,
    pub interfaces: Result<Vec<NetworkInterface>, String>,
    pub os_routes: Result<Vec<RouteEntry>, String>,
    pub owned_routes: Option<Vec<AppliedRoute>>,
    pub protocol_health: ProtocolHealth,
    pub proxy_owner: Option<String>,
}

fn diag_check(name: &str, level: DiagnosticLevel, message: String) -> DiagnosticCheck {
    DiagnosticCheck {
        name: name.to_string(),
        level,
        message,
    }
}

pub fn applied_route_present(applied: &AppliedRoute, entry: &RouteEntry) -> bool {
    applied.interface_index == entry.interface_index
        && entry.destination == applied.destination.network()
        && entry.prefix_len == applied.destination.prefix_len()
        && applied
            .gateway
            .is_none_or(|gateway| entry.gateway == Some(gateway))
}

pub fn build_diagnostics(input: &DiagnosticsInput) -> Vec<DiagnosticCheck> {
    let mut checks = Vec::new();
    let profile = &input.profile;

    checks.push(match &input.inspection {
        None => diag_check(
            "Configuration",
            DiagnosticLevel::Error,
            format!(
                "configuration could not be read or analyzed: {}",
                input.inspection_error.as_deref().unwrap_or("unknown error")
            ),
        ),
        Some(_) if input.managed => {
            let dpapi_protected = profile
                .config_path
                .file_name()
                .map(|name| {
                    name.to_string_lossy()
                        .to_lowercase()
                        .ends_with(".json.dpapi")
                })
                .unwrap_or(false);
            diag_check(
                "Configuration",
                DiagnosticLevel::Healthy,
                if dpapi_protected {
                    "managed configuration is DPAPI protected".to_string()
                } else {
                    "configuration is stored in managed storage".to_string()
                },
            )
        }
        Some(_) => diag_check(
            "Configuration",
            DiagnosticLevel::Warning,
            "Resave this profile to import it into managed storage".to_string(),
        ),
    });

    #[cfg(target_os = "linux")]
    if matches!(
        profile.backend,
        TunnelBackend::WireGuard | TunnelBackend::OpenVpn
    ) || (profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun)
    {
        checks.push(diag_check(
            "Network daemon",
            if input.status.state == TunnelState::Failed {
                DiagnosticLevel::Error
            } else {
                DiagnosticLevel::Healthy
            },
            input
                .status
                .message
                .clone()
                .unwrap_or_else(|| "Tunnel status reported by network daemon".into()),
        ));
        if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun {
            checks.push(match &input.executable {
                Ok(_) => diag_check(
                    "Package Xray",
                    DiagnosticLevel::Healthy,
                    "verified package Xray is available".into(),
                ),
                Err(err) => diag_check("Package Xray", DiagnosticLevel::Error, err.clone()),
            });
        }
    } else {
        checks.push(match &input.executable {
            Ok(path) => diag_check(
                "Backend executable",
                DiagnosticLevel::Healthy,
                format!("found {}", path.display()),
            ),
            Err(err) => diag_check("Backend executable", DiagnosticLevel::Error, err.clone()),
        });
    }
    #[cfg(not(target_os = "linux"))]
    checks.push(match &input.executable {
        Ok(path) => diag_check(
            "Backend executable",
            DiagnosticLevel::Healthy,
            format!("found {}", path.display()),
        ),
        Err(err) => diag_check("Backend executable", DiagnosticLevel::Error, err.clone()),
    });

    const STATUS_NOTE: &str = "process/service state only, not handshake verification";
    checks.push(match input.status.state {
        TunnelState::Running => diag_check(
            "Tunnel status",
            DiagnosticLevel::Healthy,
            format!("running ({STATUS_NOTE})"),
        ),
        TunnelState::Stopped => diag_check(
            "Tunnel status",
            DiagnosticLevel::Warning,
            format!("stopped ({STATUS_NOTE})"),
        ),
        TunnelState::Failed => diag_check(
            "Tunnel status",
            DiagnosticLevel::Error,
            format!(
                "failed: {} ({STATUS_NOTE})",
                input.status.message.as_deref().unwrap_or("unknown error")
            ),
        ),
    });

    let health = &input.protocol_health;
    checks.push(diag_check(
        "Protocol health",
        match health.state {
            ProtocolHealthState::Healthy => DiagnosticLevel::Healthy,
            ProtocolHealthState::Degraded => DiagnosticLevel::Warning,
            ProtocolHealthState::Failed => DiagnosticLevel::Error,
            ProtocolHealthState::Unknown => DiagnosticLevel::Warning,
        },
        health.summary.clone(),
    ));
    if let Some(tail) = health.log_tail.as_ref().filter(|t| !t.trim().is_empty()) {
        checks.push(diag_check(
            "Runtime log",
            if matches!(
                health.state,
                ProtocolHealthState::Failed | ProtocolHealthState::Degraded
            ) {
                DiagnosticLevel::Warning
            } else {
                DiagnosticLevel::Healthy
            },
            tail.clone(),
        ));
    }

    if !health.pushed_routes.is_empty() {
        let list = health
            .pushed_routes
            .iter()
            .map(|r| r.destination.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        checks.push(diag_check(
            if cfg!(target_os = "linux") && profile.backend == TunnelBackend::OpenVpn {
                "Daemon routes"
            } else {
                "Pushed routes"
            },
            DiagnosticLevel::Healthy,
            format!("{} route(s): {list}", health.pushed_routes.len()),
        ));
    }

    // Endpoint path: a remote endpoint that resolves out a tunnel interface
    // gets its handshake swallowed (TLS timeouts). Only literal IPs are
    // checked — DNS names are resolved by the daemon at apply time.
    {
        let mut endpoints: Vec<std::net::IpAddr> = profile
            .endpoint_bypasses
            .iter()
            .filter_map(|e| e.trim().parse().ok())
            .collect();
        if let Some(inspection) = &input.inspection {
            endpoints.extend(
                inspection
                    .analysis
                    .endpoints
                    .iter()
                    .filter_map(|e| e.address.trim().parse::<std::net::IpAddr>().ok()),
            );
        }
        endpoints.sort();
        endpoints.dedup();
        if !endpoints.is_empty() {
            let routes = input.os_routes.as_deref().unwrap_or(&[]);
            let ifaces = input.interfaces.as_deref().unwrap_or(&[]);
            let swallowed: Vec<String> = endpoints
                .iter()
                .filter_map(|ip| {
                    let route = explorer::longest_prefix_match(*ip, routes)?;
                    let tunnel_ish = ifaces
                        .iter()
                        .find(|i| i.name == route.interface_name)
                        .map(|i| {
                            matches!(
                                i.category,
                                InterfaceCategory::Vpn | InterfaceCategory::Tunnel
                            )
                        })
                        .unwrap_or_else(|| {
                            let n = route.interface_name.as_str();
                            n.starts_with("tun") || n.starts_with("wg") || n.starts_with("utun")
                        });
                    tunnel_ish.then(|| format!("{ip} via {}", route.interface_name))
                })
                .collect();
            checks.push(if swallowed.is_empty() {
                diag_check(
                    "Endpoint path",
                    DiagnosticLevel::Healthy,
                    format!("{} endpoint(s) route via a physical uplink", endpoints.len()),
                )
            } else {
                diag_check(
                    "Endpoint path",
                    DiagnosticLevel::Warning,
                    format!(
                        "endpoint(s) {} route via a tunnel interface — the handshake may never reach the server; add an endpoint bypass through the physical gateway",
                        swallowed.join(", ")
                    ),
                )
            });
        }
    }

    if profile.use_system_proxy || input.proxy_owner.is_some() {
        let check = match &input.proxy_owner {
            Some(owner) if owner == &profile.id => {
                if input.status.state == TunnelState::Running {
                    diag_check(
                        "System proxy",
                        DiagnosticLevel::Healthy,
                        "system proxy is applied for this profile (127.0.0.1 SOCKS5)".to_string(),
                    )
                } else {
                    diag_check(
                        "System proxy",
                        DiagnosticLevel::Error,
                        "stale ownership: system proxy still applied while the profile is not running".to_string(),
                    )
                }
            }
            Some(owner) => diag_check(
                "System proxy",
                DiagnosticLevel::Error,
                format!("system proxy is owned by another profile '{owner}'"),
            ),
            None if profile.use_system_proxy => diag_check(
                "System proxy",
                DiagnosticLevel::Warning,
                "system proxy is configured but not currently applied".to_string(),
            ),
            None => diag_check(
                "System proxy",
                DiagnosticLevel::Warning,
                "stale system proxy record without a known owner".to_string(),
            ),
        };
        checks.push(check);
    }

    match &input.inspection {
        None => checks.push(diag_check(
            "Static analysis",
            DiagnosticLevel::Warning,
            "static analysis unavailable".to_string(),
        )),
        Some(inspection) => {
            let warning_count = inspection.analysis.warnings.len();
            let conflict_count = inspection.conflicts.len();
            let incomplete = !inspection.analysis.route_knowledge_complete;
            if warning_count + conflict_count == 0 && !incomplete {
                checks.push(diag_check(
                    "Static analysis",
                    DiagnosticLevel::Healthy,
                    "no warnings or conflicts".to_string(),
                ));
            } else {
                let mut details: Vec<String> = inspection.analysis.warnings.clone();
                details.extend(inspection.conflicts.iter().map(|c| c.message.clone()));
                if incomplete {
                    details.push("effective routes are not fully known".to_string());
                }
                checks.push(diag_check(
                    "Static analysis",
                    DiagnosticLevel::Warning,
                    format!(
                        "{warning_count} warning(s), {conflict_count} conflict(s): {}",
                        details.join("; ")
                    ),
                ));
            }
        }
    }

    if !profile.routes.is_empty()
        && !(cfg!(target_os = "linux")
            && (matches!(
                profile.backend,
                TunnelBackend::WireGuard | TunnelBackend::OpenVpn
            ) || (profile.backend == TunnelBackend::Xray
                && profile.xray_mode == XrayMode::Tun)))
    {
        let check = match &input.interfaces {
            Err(err) => diag_check(
                "Target interface",
                DiagnosticLevel::Error,
                format!("cannot list interfaces: {err}"),
            ),
            Ok(interfaces) => match interfaces.iter().find(|i| {
                i.friendly_name == profile.interface_name || i.name == profile.interface_name
            }) {
                Some(i) if matches!(i.state, InterfaceState::Up) => diag_check(
                    "Target interface",
                    DiagnosticLevel::Healthy,
                    format!("interface '{}' is up", profile.interface_name),
                ),
                Some(_) => diag_check(
                    "Target interface",
                    DiagnosticLevel::Error,
                    format!("interface '{}' is not up", profile.interface_name),
                ),
                None => diag_check(
                    "Target interface",
                    DiagnosticLevel::Error,
                    format!("interface '{}' not found", profile.interface_name),
                ),
            },
        };
        checks.push(check);
    }

    if cfg!(target_os = "linux")
        && (matches!(
            profile.backend,
            TunnelBackend::WireGuard | TunnelBackend::OpenVpn
        ) || (profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun))
    {
        checks.push(diag_check(
            "Applied routes",
            match input.status.state {
                TunnelState::Running => DiagnosticLevel::Healthy,
                TunnelState::Stopped => DiagnosticLevel::Warning,
                TunnelState::Failed => DiagnosticLevel::Error,
            },
            format!(
                "{:?} routes are managed by the network daemon",
                profile.backend
            ),
        ));
    } else if profile.routes.is_empty() {
        checks.push(diag_check(
            "Applied routes",
            DiagnosticLevel::Healthy,
            "No app-managed routes".to_string(),
        ));
    } else {
        let check = match &input.owned_routes {
            None => diag_check(
                "Applied routes",
                if input.status.state == TunnelState::Running {
                    DiagnosticLevel::Error
                } else {
                    DiagnosticLevel::Warning
                },
                "app-managed routes not applied".to_string(),
            ),
            Some(routes) => match &input.os_routes {
                Err(err) => diag_check(
                    "Applied routes",
                    DiagnosticLevel::Error,
                    format!("cannot list OS routes: {err}"),
                ),
                Ok(entries) => {
                    let missing: Vec<String> = routes
                        .iter()
                        .filter(|r| !entries.iter().any(|e| applied_route_present(r, e)))
                        .map(|r| r.destination.to_string())
                        .collect();
                    if missing.is_empty() {
                        diag_check(
                            "Applied routes",
                            DiagnosticLevel::Healthy,
                            format!("{} managed route(s) present", routes.len()),
                        )
                    } else {
                        diag_check(
                            "Applied routes",
                            DiagnosticLevel::Error,
                            format!("missing OS routes: {}", missing.join(", ")),
                        )
                    }
                }
            },
        };
        checks.push(check);
    }

    if let Some(inspection) = &input.inspection {
        if inspection.analysis.endpoints.is_empty() {
            checks.push(diag_check(
                "Endpoints",
                DiagnosticLevel::Warning,
                "no remote endpoints discovered in config".to_string(),
            ));
        } else {
            let list = inspection
                .analysis
                .endpoints
                .iter()
                .map(|e| match e.port {
                    Some(port) => format!("{}:{port}", e.address),
                    None => e.address.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            checks.push(diag_check(
                "Endpoints",
                DiagnosticLevel::Healthy,
                format!(
                    "{} endpoint(s): {list}",
                    inspection.analysis.endpoints.len()
                ),
            ));
        }
        if profile.backend == TunnelBackend::Xray {
            if inspection.analysis.listeners.is_empty() {
                checks.push(diag_check(
                    "Listeners",
                    DiagnosticLevel::Warning,
                    "no inbound listeners discovered".to_string(),
                ));
            } else {
                let list = inspection
                    .analysis
                    .listeners
                    .iter()
                    .map(|l| format!("{}:{}", l.address, l.port))
                    .collect::<Vec<_>>()
                    .join(", ");
                checks.push(diag_check(
                    "Listeners",
                    DiagnosticLevel::Healthy,
                    format!("listeners: {list}"),
                ));
            }
        }
    }

    checks
}

#[cfg(target_os = "linux")]
fn linux_daemon_tunnel(profile: &Profile) -> bool {
    matches!(
        profile.backend,
        TunnelBackend::WireGuard | TunnelBackend::OpenVpn
    ) || (profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun)
}
#[cfg(target_os = "linux")]
pub fn linux_owned_checks(
    input: &DiagnosticsInput,
    listing: Option<&OwnedListResult>,
) -> Vec<DiagnosticCheck> {
    let mut checks = Vec::new();
    let profile = &input.profile;
    let owner = match profile.backend {
        TunnelBackend::WireGuard => format!("wg:{}", profile.id),
        TunnelBackend::OpenVpn => format!("ovpn:{}", profile.id),
        TunnelBackend::Xray => format!("xray:{}", profile.id),
        TunnelBackend::None => return checks,
    };
    let Some(listing) = listing else {
        checks.push(diag_check(
            "Daemon ownership",
            DiagnosticLevel::Warning,
            "Ownership is unknown: daemon listing is unavailable".into(),
        ));
        checks.push(diag_check(
            "Applied routes",
            DiagnosticLevel::Warning,
            "Route ownership is unknown".into(),
        ));
        checks.push(diag_check(
            "Tunnel DNS",
            DiagnosticLevel::Warning,
            "DNS ownership is unknown".into(),
        ));
        return checks;
    };
    let Some(entry) = listing.owners.iter().find(|entry| entry.owner == owner) else {
        let running = input.status.state == TunnelState::Running;
        checks.push(diag_check(
            "Daemon ownership",
            if running {
                DiagnosticLevel::Error
            } else {
                DiagnosticLevel::Warning
            },
            if running {
                "Tunnel reports running, but daemon has no owner"
            } else {
                "No active daemon owner"
            }
            .into(),
        ));
        checks.push(diag_check(
            "Applied routes",
            if running {
                DiagnosticLevel::Error
            } else {
                DiagnosticLevel::Warning
            },
            "No daemon route ownership recorded".into(),
        ));
        checks.push(diag_check(
            "Tunnel DNS",
            DiagnosticLevel::Warning,
            "No daemon DNS ownership recorded".into(),
        ));
        return checks;
    };
    let marker = entry
        .resources
        .iter()
        .find_map(|resource| match (profile.backend, resource) {
            (TunnelBackend::WireGuard, OwnedResource::WireGuardLink(link)) => {
                Some((link.name.as_str(), Some(link.index), link.full.as_ref()))
            }
            (TunnelBackend::OpenVpn, OwnedResource::OpenVpnProcess(process)) => {
                Some((process.name.as_str(), None, process.full.as_ref()))
            }
            (TunnelBackend::Xray, OwnedResource::XrayProcess(process)) => Some((
                process.name.as_str(),
                Some(process.index),
                process.full.as_ref(),
            )),
            _ => None,
        });
    let ownership_level = match entry.state {
        OwnedState::Stale => DiagnosticLevel::Error,
        OwnedState::Applying => DiagnosticLevel::Warning,
        OwnedState::Applied if marker.is_none() => DiagnosticLevel::Error,
        OwnedState::Applied if input.status.state != TunnelState::Running => DiagnosticLevel::Error,
        OwnedState::Applied => DiagnosticLevel::Healthy,
    };
    checks.push(diag_check(
        "Daemon ownership",
        ownership_level,
        match entry.state {
            OwnedState::Stale => "Daemon ownership is stale and needs recovery".into(),
            OwnedState::Applying => "Daemon is still applying tunnel resources".into(),
            OwnedState::Applied if marker.is_none() => {
                "Daemon owner lacks a backend resource marker".into()
            }
            OwnedState::Applied if input.status.state != TunnelState::Running => {
                "Daemon owner remains applied while tunnel status is not running".into()
            }
            OwnedState::Applied => format!(
                "Daemon journal tracks {} resource(s)",
                entry.resources.len()
            ),
        },
    ));

    let journal_routes: Vec<&AppliedRoute> = entry
        .resources
        .iter()
        .filter_map(|resource| match resource {
            OwnedResource::Route(route) => Some(route),
            _ => None,
        })
        .collect();
    let expected = if !profile.routes.is_empty() {
        profile
            .routes
            .iter()
            .map(|route| route.destination)
            .collect::<Vec<_>>()
    } else if profile.backend == TunnelBackend::OpenVpn
        && !input.protocol_health.pushed_routes.is_empty()
    {
        input
            .protocol_health
            .pushed_routes
            .iter()
            .map(|route| route.destination)
            .collect()
    } else {
        input
            .inspection
            .as_ref()
            .map(|inspection| {
                inspection
                    .analysis
                    .os_routes
                    .iter()
                    .map(|route| route.destination)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let expected_strings: Vec<String> = expected.iter().map(ToString::to_string).collect();
    let journal_strings: Vec<String> = journal_routes
        .iter()
        .map(|route| route.destination.to_string())
        .collect();
    let journal_has = |destination: &str| journal_strings.iter().any(|route| route == destination);
    let missing_expected = expected_strings
        .iter()
        .filter(|destination| {
            !journal_has(destination)
                && !(destination.as_str() == "0.0.0.0/0"
                    && journal_has("0.0.0.0/1")
                    && journal_has("128.0.0.0/1"))
                && !(destination.as_str() == "::/0"
                    && journal_has("::/1")
                    && journal_has("8000::/1"))
        })
        .count();
    let main_routes: Vec<_> = journal_routes
        .iter()
        .filter(|route| route.table.is_none())
        .collect();
    let missing_main = match &input.os_routes {
        Ok(os_routes) => main_routes
            .iter()
            .filter(|route| {
                !os_routes
                    .iter()
                    .any(|os_route| applied_route_present(route, os_route))
            })
            .count(),
        Err(_) => 0,
    };
    checks.push(if entry.state == OwnedState::Stale || missing_expected > 0 || missing_main > 0 {
        diag_check("Applied routes", DiagnosticLevel::Error, format!(
            "Daemon route ownership is incomplete: {missing_expected} expected and {missing_main} main-table route(s) missing"
        ))
    } else if expected.is_empty() || input.os_routes.is_err() || journal_routes.iter().any(|route| route.table.is_some()) {
        diag_check("Applied routes", DiagnosticLevel::Warning, format!(
            "{} route(s) journaled; expected coverage or non-main OS table is not fully verified",
            journal_routes.len()
        ))
    } else {
        diag_check("Applied routes", DiagnosticLevel::Warning, format!(
            "{} expected route(s) journaled and matching OS routes visible; kernel ownership is not independently verified",
            expected.len()
        ))
    });

    let expected_full = expected_strings
        .iter()
        .any(|route| route == "0.0.0.0/0" || route == "::/0")
        || (["0.0.0.0/1", "128.0.0.0/1"]
            .iter()
            .all(|half| expected_strings.iter().any(|route| route == half)))
        || (["::/1", "8000::/1"]
            .iter()
            .all(|half| expected_strings.iter().any(|route| route == half)))
        || journal_has("0.0.0.0/0")
        || journal_has("::/0")
        || (journal_has("0.0.0.0/1") && journal_has("128.0.0.0/1"))
        || (journal_has("::/1") && journal_has("8000::/1"))
        || entry
            .resources
            .iter()
            .any(|resource| matches!(resource, OwnedResource::Dns(dns) if dns.full));
    let full = marker.and_then(|(_, _, full)| full);
    if expected_full || full.is_some() {
        checks.push(match full {
            None => diag_check("Policy rules", DiagnosticLevel::Error, "Expected full-tunnel policy ownership is absent".into()),
            Some(full) => {
                let missing = [IpFamily::Ipv4, IpFamily::Ipv6].into_iter()
                    .filter(|family| (*family == IpFamily::Ipv4 && full.ipv4) || (*family == IpFamily::Ipv6 && full.ipv6))
                    .flat_map(|family| [
                        !has_full_main_rule(&entry.resources, family, full),
                        !has_full_tunnel_rule(&entry.resources, family, full),
                    ])
                    .filter(|missing| *missing)
                    .count();
                if missing > 0 || (!full.ipv4 && !full.ipv6) {
                    diag_check("Policy rules", DiagnosticLevel::Error, format!("{missing} required full-tunnel rule(s) missing from daemon journal"))
                } else {
                    diag_check("Policy rules", DiagnosticLevel::Warning, "Full-tunnel rules are journaled; kernel rule presence is not independently verified".into())
                }
            }
        });
    }

    let dns: Vec<_> = entry
        .resources
        .iter()
        .filter_map(|resource| match resource {
            OwnedResource::Dns(dns) => Some(dns),
            _ => None,
        })
        .collect();
    checks.push(if dns.is_empty() {
        diag_check(
            "Tunnel DNS",
            DiagnosticLevel::Warning,
            "No DNS resource is journaled; DNS requirements are unknown".into(),
        )
    } else if dns.iter().any(|dns| {
        marker.is_none_or(|(name, index, _)| {
            dns.name != name
                || index.is_some_and(|index| index != 0 && dns.interface_index != index)
        })
    }) {
        diag_check(
            "Tunnel DNS",
            DiagnosticLevel::Error,
            "DNS resource does not match the owned tunnel link".into(),
        )
    } else if dns.iter().any(|dns| !dns.applied) {
        diag_check(
            "Tunnel DNS",
            if dns.iter().any(|dns| dns.full && !dns.applied) {
                DiagnosticLevel::Error
            } else {
                DiagnosticLevel::Warning
            },
            "Daemon reports tunnel DNS was not applied".into(),
        )
    } else {
        diag_check(
            "Tunnel DNS",
            DiagnosticLevel::Warning,
            "Daemon journal marks DNS applied; resolver state is not independently verified".into(),
        )
    });
    checks
}

#[cfg(target_os = "linux")]
fn has_full_main_rule(
    resources: &[OwnedResource],
    family: IpFamily,
    full: &WireGuardFullResource,
) -> bool {
    resources.iter().any(|resource| {
        matches!(resource, OwnedResource::Rule(rule)
        if rule.family == family && rule.priority == full.priority_main && rule.table == 254
            && rule.fwmark.is_none() && !rule.invert && rule.suppress_prefix_length == Some(0))
    })
}

#[cfg(target_os = "linux")]
fn has_full_tunnel_rule(
    resources: &[OwnedResource],
    family: IpFamily,
    full: &WireGuardFullResource,
) -> bool {
    resources.iter().any(|resource| matches!(resource, OwnedResource::Rule(rule)
        if rule.family == family && rule.priority == full.priority_tunnel && rule.table == full.table
            && rule.fwmark == Some(full.fwmark) && rule.invert && rule.suppress_prefix_length.is_none()))
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogSource {
    App,
    Daemon,
}

/// One entry in the Logs view. `tsUnix` is seconds since the epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    pub ts_unix: u64,
    pub level: LogLevel,
    pub source: LogSource,
    pub message: String,
}
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);
/// Loopback listeners above this count are a misconfigured/broken host; stop
/// early instead of probing thousands of ports.
#[cfg(target_os = "linux")]
const MAX_CANDIDATES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Socks5,
    Socks4,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProxy {
    pub address: IpAddr,
    pub port: u16,
    pub kind: ProxyKind,
}

/// One `/proc/net/tcp{,6}` row → `(ip, port)` when the socket is LISTENing on
/// loopback or the wildcard address.
#[cfg(target_os = "linux")]
fn parse_listen_line(line: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let mut f = line.split_whitespace();
    f.next()?; // sl
    let local = f.next()?;
    f.next()?; // rem_address
    if f.next()? != "0A" {
        return None; // not LISTEN
    }
    let (addr_hex, port_hex) = local.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if port == 0 {
        return None;
    }
    let ip = if v6 {
        if addr_hex.len() != 32 {
            return None;
        }
        // procfs stores each 32-bit word little-endian.
        let mut w = [0u16; 8];
        for i in 0..4 {
            let be = u32::from_str_radix(&addr_hex[i * 8..i * 8 + 8], 16)
                .ok()?
                .swap_bytes();
            w[i * 2] = (be >> 16) as u16;
            w[i * 2 + 1] = (be & 0xffff) as u16;
        }
        IpAddr::V6(Ipv6Addr::new(
            w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
        ))
    } else {
        IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(addr_hex, 16).ok()?.swap_bytes(),
        ))
    };
    if ip.is_loopback() || ip.is_unspecified() {
        Some((ip, port))
    } else {
        None
    }
}

/// Ports with a listener reachable via loopback, each mapped to a probe
/// address: 127.0.0.1 when an IPv4 loopback/any bind covers it, else ::1.
#[cfg(target_os = "linux")]
fn loopback_listen_ports() -> Vec<(IpAddr, u16)> {
    let mut v4 = std::collections::HashSet::new();
    let mut v6 = std::collections::HashSet::new();
    for (path, is_v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            if let Some((ip, port)) = parse_listen_line(line, is_v6) {
                if ip.is_ipv4() {
                    v4.insert(port);
                } else {
                    v6.insert(port);
                }
            }
        }
    }
    let mut ports: Vec<u16> = v4.union(&v6).copied().collect();
    ports.sort_unstable();
    ports.truncate(MAX_CANDIDATES);
    ports
        .into_iter()
        .map(|p| {
            (
                if v4.contains(&p) {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                },
                p,
            )
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn loopback_listen_ports() -> Vec<(IpAddr, u16)> {
    Vec::new()
}

/// `05 01 00` — offer NOAUTH. A SOCKS5 server replies `05 <method>`.
async fn probe_socks5(stream: &mut TcpStream) -> bool {
    if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return false;
    }
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.is_ok() && reply[0] == 0x05
}

/// `CONNECT` to a dead loopback port. A CONNECT-capable proxy answers with a
/// failure status it generated itself (5xx/407/403/200). A plain HTTP server
/// rejects the method outright (400/404/405/501) and is not a proxy.
async fn probe_http(stream: &mut TcpStream) -> bool {
    if stream
        .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
        .await
        .is_err()
    {
        return false;
    }
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    let Ok(Ok(n)) = timeout(PROBE_TIMEOUT, reader.read_line(&mut line)).await else {
        return false;
    };
    if n == 0 {
        return false;
    }
    let Some(rest) = line.strip_prefix("HTTP/") else {
        return false;
    };
    let Some(status) = rest
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
    else {
        return false;
    };
    !matches!(status, 400 | 404 | 405 | 501)
}

/// `04 01 00 01 7F 00 00 01 00` — CONNECT to 127.0.0.1:1. A SOCKS4 server
/// replies with 8 bytes: VN ∈ {0,4}, CD ∈ 0x5A..=0x5D.
async fn probe_socks4(stream: &mut TcpStream) -> bool {
    if stream
        .write_all(&[0x04, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00])
        .await
        .is_err()
    {
        return false;
    }
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await.is_ok()
        && (reply[0] == 0x00 || reply[0] == 0x04)
        && (0x5a..=0x5d).contains(&reply[1])
}

async fn probe(addr: IpAddr, port: u16) -> Option<ProxyKind> {
    for kind in [ProxyKind::Socks5, ProxyKind::Http, ProxyKind::Socks4] {
        let Ok(Ok(mut stream)) = timeout(PROBE_TIMEOUT, TcpStream::connect((addr, port))).await
        else {
            return None; // listener vanished — nothing more to probe
        };
        let attempt = async {
            match kind {
                ProxyKind::Socks5 => probe_socks5(&mut stream).await,
                ProxyKind::Http => probe_http(&mut stream).await,
                ProxyKind::Socks4 => probe_socks4(&mut stream).await,
            }
        };
        if timeout(PROBE_TIMEOUT, attempt).await.unwrap_or(false) {
            return Some(kind);
        }
    }
    None
}

async fn probe_targets(candidates: Vec<(IpAddr, u16)>) -> Vec<LocalProxy> {
    let mut set = tokio::task::JoinSet::new();
    for (addr, port) in candidates {
        set.spawn(async move { probe(addr, port).await.map(|k| (addr, port, k)) });
    }
    let mut found = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some((address, port, kind))) = res {
            found.push(LocalProxy {
                address,
                port,
                kind,
            });
        }
    }
    found.sort_by_key(|p| p.port);
    found
}

pub async fn run_scan() -> Vec<LocalProxy> {
    probe_targets(loopback_listen_ports()).await
}

const LOG_CAPACITY: usize = 500;
const LOG_MAX_BYTES: u64 = 2 * 1024 * 1024;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn safe_message(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if message.contains("://")
        || message.contains(['{', '}', '\n', '\r'])
        || [
            "privatekey",
            "presharedkey",
            "password",
            "passphrase",
            "authorization",
            "bearer ",
            "token",
            "secret",
            "[interface]",
            "-----begin",
            "hwid",
        ]
        .iter()
        .any(|key| lower.contains(key))
    {
        return "[redacted sensitive diagnostic]".into();
    }
    let mut sanitized = net_manager_core::vpn::redact_runtime_log(message);
    sanitized.retain(|ch| !ch.is_control());
    let end = sanitized
        .char_indices()
        .map(|(index, _)| index)
        .find(|index| *index >= 2048)
        .unwrap_or(sanitized.len());
    sanitized.truncate(end);
    sanitized
}

fn store_error() -> String {
    "Shared application logs are unavailable or not private".into()
}

fn private_file(path: &Path, create: bool) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| store_error())?;
    let metadata = file.metadata().map_err(|_| store_error())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(store_error());
    }
    Ok(file)
}

fn log_directory(root: &Path, mutate: bool) -> Result<PathBuf, String> {
    let owner = fs::symlink_metadata(root).map_err(|_| store_error())?;
    if !owner.is_dir()
        || owner.mode() & 0o022 != 0
        || (mutate && owner.uid() != unsafe { libc::geteuid() })
    {
        return Err(store_error());
    }
    let directory = root.join("app-logs");
    if mutate {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|_| store_error())?;
    }
    let metadata = fs::symlink_metadata(&directory).map_err(|_| store_error())?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(store_error());
    }
    Ok(directory)
}

fn read_events(path: &Path) -> Result<Vec<LogEvent>, String> {
    if !path.try_exists().map_err(|_| store_error())? {
        // A dangling symlink must not be treated as an absent store.
        if fs::symlink_metadata(path).is_ok() {
            return Err(store_error());
        }
        return Ok(Vec::new());
    }
    let mut bytes = Vec::new();
    private_file(path, false)?
        .take(LOG_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| store_error())?;
    if bytes.len() as u64 > LOG_MAX_BYTES {
        return Err(store_error());
    }
    let mut events: Vec<LogEvent> = serde_json::from_slice(&bytes)
        .map_err(|_| "Shared application logs are corrupt".to_string())?;
    if events.len() > LOG_CAPACITY {
        return Err("Shared application log capacity exceeded".into());
    }
    for event in &mut events {
        event.message = safe_message(&event.message);
    }
    Ok(events)
}

pub fn logs(root: &Path) -> Result<Vec<LogEvent>, String> {
    if !root
        .join("app-logs")
        .try_exists()
        .map_err(|_| store_error())?
    {
        if fs::symlink_metadata(root.join("app-logs")).is_ok() {
            return Err(store_error());
        }
        return Ok(Vec::new());
    }
    let directory = log_directory(root, false)?;
    read_events(&directory.join("events.json"))
}

fn update_logs(root: &Path, update: impl FnOnce(&mut Vec<LogEvent>)) -> Result<(), String> {
    let directory = log_directory(root, true)?;
    let lock = private_file(&directory.join("store.lock"), true)?;
    lock.lock().map_err(|_| store_error())?;
    let path = directory.join("events.json");
    let mut events = read_events(&path)?;
    update(&mut events);
    let bytes = serde_json::to_vec(&events).map_err(|_| store_error())?;
    net_manager_core::journal::write_atomic(&path, &bytes).map_err(|_| store_error())
}

pub fn record_log(root: &Path, level: LogLevel, message: &str) -> Result<(), String> {
    update_logs(root, |events| {
        if events.len() == LOG_CAPACITY {
            events.remove(0);
        }
        events.push(LogEvent {
            ts_unix: now_unix(),
            level,
            source: LogSource::App,
            message: safe_message(message),
        });
    })
}

pub fn clear_logs(root: &Path) -> Result<(), String> {
    update_logs(root, Vec::clear)
}

pub fn filtered_logs(
    root: &Path,
    level: Option<LogLevel>,
    contains: Option<&str>,
) -> Result<Vec<LogEvent>, String> {
    Ok(logs(root)?
        .into_iter()
        .filter(|event| {
            level.is_none_or(|level| event.level == level)
                && contains.is_none_or(|needle| event.message.contains(needle))
        })
        .collect())
}

pub async fn daemon_log_tail(lines: u32) -> Result<Vec<LogEvent>, String> {
    let output = tokio::process::Command::new("journalctl")
        .args([
            "-u",
            "network-orchestrator.service",
            "-b",
            "--no-pager",
            "-n",
            &lines.clamp(1, 500).to_string(),
            "-o",
            "json",
        ])
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|_| "Daemon journal is unavailable")?;
    if !output.status.success() {
        return Err("Cannot read daemon journal; journal access may be required".into());
    }
    #[derive(Deserialize)]
    struct Row {
        #[serde(rename = "__REALTIME_TIMESTAMP")]
        ts: Option<String>,
        #[serde(rename = "MESSAGE")]
        message: Option<String>,
        #[serde(rename = "PRIORITY")]
        priority: Option<String>,
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Row>(line).ok())
        .map(|row| LogEvent {
            ts_unix: row
                .ts
                .and_then(|ts| ts.parse::<u64>().ok())
                .map(|ts| ts / 1_000_000)
                .unwrap_or_default(),
            level: match row.priority.as_deref() {
                Some("0" | "1" | "2" | "3") => LogLevel::Error,
                Some("4") => LogLevel::Warn,
                _ => LogLevel::Info,
            },
            source: LogSource::Daemon,
            message: safe_message(row.message.as_deref().unwrap_or_default()),
        })
        .collect())
}

pub async fn scan_local_proxies() -> Result<Vec<LocalProxy>, String> {
    Ok(run_scan().await)
}

pub async fn check_exit_ips(on_entry: &(dyn Fn(ExitIpEntry) + Send + Sync)) -> Result<(), String> {
    use net_manager_core::exit_ip::{check_one, CHECKERS, TIMEOUT};
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|_| "Exit-IP client unavailable")?;
    let mut tasks = tokio::task::JoinSet::new();
    for &(name, urls) in CHECKERS {
        let client = client.clone();
        tasks.spawn(async move { check_one(client, name, urls).await });
    }
    while let Some(result) = tasks.join_next().await {
        let mut entry = result.map_err(|_| "Exit-IP check task failed")?;
        entry.error = entry.error.map(|_| "Exit-IP checker unavailable".into());
        on_entry(entry);
    }
    Ok(())
}

fn find_profile(store: &ProfileStore, id: &str) -> Result<Profile, String> {
    store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| "Profile not found".into())
}

fn build_profile_inspection(
    candidate: &Profile,
    others: &[Profile],
    routes: &[RouteEntry],
    vault: &ConfigVault,
) -> Result<ProfileInspection, String> {
    net_manager_core::diagnostics::build_profile_inspection(candidate, others, routes, vault)
}

pub async fn inspect(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
) -> Result<ProfileInspection, String> {
    let candidate = find_profile(store, id)?;
    let others: Vec<_> = store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles
        .into_iter()
        .filter(|p| p.id != id)
        .collect();
    let routes = explorer::list_routes()
        .await
        .map_err(|_| "Cannot enumerate OS routes")?;
    build_profile_inspection(&candidate, &others, &routes, vault)
}

pub async fn inspect_all(
    vault: &ConfigVault,
    store: &ProfileStore,
) -> Result<Vec<ProfileInspection>, String> {
    let profiles = store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles;
    let routes = explorer::list_routes()
        .await
        .map_err(|_| "Cannot enumerate OS routes")?;
    profiles
        .iter()
        .map(|profile| {
            let others: Vec<_> = profiles
                .iter()
                .filter(|p| p.id != profile.id)
                .cloned()
                .collect();
            build_profile_inspection(profile, &others, &routes, vault)
        })
        .collect()
}

pub fn stats(engine: &LinuxEngine, profile: &Profile) -> Result<ProtocolHealth, String> {
    use net_manager_core::diagnostics::{openvpn_health, wireguard_health, xray_tun_health};
    match profile.backend {
        TunnelBackend::WireGuard => engine
            .wireguard_status_result(&profile.id)
            .map(|status| wireguard_health(&status)),
        TunnelBackend::OpenVpn => engine
            .openvpn_status_result(&profile.id)
            .map(|status| openvpn_health(&status)),
        TunnelBackend::Xray if profile.xray_mode == XrayMode::Tun => engine
            .xray_status_result(&profile.id)
            .map(|status| xray_tun_health(&status)),
        _ => {
            let status = engine.status(profile)?;
            Ok(ProtocolHealth {
                state: if status.state == TunnelState::Failed {
                    ProtocolHealthState::Failed
                } else {
                    ProtocolHealthState::Unknown
                },
                summary: "Shared runtime state; protocol counters are unavailable for this backend"
                    .into(),
                last_handshake_unix: None,
                rx_bytes: None,
                tx_bytes: None,
                log_tail: None,
                pushed_routes: Vec::new(),
            })
        }
    }
    .map_err(|error| safe_message(&error))
}

fn resolve_backend_executable(root: &Path, profile: &Profile) -> Result<PathBuf, String> {
    #[cfg(target_arch = "x86_64")]
    let package_root = Path::new(net_manager_core::managed_xray::LINUX_XRAY_PACKAGE_ROOT);
    #[cfg(not(target_arch = "x86_64"))]
    let package_root = root;
    resolve_backend_executable_at(root, profile, package_root)
}

fn resolve_backend_executable_at(
    root: &Path,
    profile: &Profile,
    _package_root: &Path,
) -> Result<PathBuf, String> {
    if profile.backend != TunnelBackend::Xray {
        return Ok(PathBuf::new());
    }
    #[cfg(target_arch = "x86_64")]
    if profile.xray_mode == XrayMode::Tun {
        let executable =
            net_manager_core::managed_xray::linux_managed_version_dir(_package_root).join("xray");
        net_manager_core::managed_xray::verify_managed_linux_executable(_package_root, &executable)
            .map_err(|_| "verified package Xray is unavailable".to_string())?;
        return Ok(executable);
    }
    let settings = net_manager_core::backend_settings::BackendSettingsStore::new(
        root.join("backend-settings.json"),
    )
    .load()
    .map_err(|_| "Cannot read backend settings")?;
    net_manager_core::vpn::resolve_xray_executable(
        settings.xray.as_ref().map(|setting| setting.path.as_path()),
    )
    .map_err(|_| "Verified Xray executable is unavailable".into())
}

pub async fn diagnose(
    engine: &LinuxEngine,
    root: &Path,
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
) -> Result<ProfileDiagnostics, String> {
    let profile = find_profile(store, id)?;
    let profiles = store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles;
    let others: Vec<_> = profiles.into_iter().filter(|p| p.id != id).collect();
    let os_routes = explorer::list_routes()
        .await
        .map_err(|_| "Cannot enumerate OS routes".to_string());
    let interfaces =
        explorer::list_interfaces().map_err(|_| "Cannot enumerate interfaces".to_string());
    let (inspection, inspection_error) = match build_profile_inspection(
        &profile,
        &others,
        os_routes.as_deref().unwrap_or(&[]),
        vault,
    ) {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    let mut status = engine
        .status(&profile)
        .unwrap_or_else(|error| TunnelStatus {
            profile_id: id.into(),
            state: TunnelState::Failed,
            message: Some(safe_message(&error)),
            interface_name: None,
            failover: None,
            watchdog: None,
        });
    status.message = status.message.map(|message| safe_message(&message));
    let protocol_health = stats(engine, &profile)
        .unwrap_or_else(|error| net_manager_core::diagnostics::failed_health(&error));
    let owners: Option<OwnedListResult> =
        engine.ask(method::OWNED_LIST, serde_json::Value::Null).ok();
    let owned_routes = owners
        .as_ref()
        .and_then(|listing| listing.owners.iter().find(|entry| entry.owner == id))
        .map(|entry| {
            entry
                .resources
                .iter()
                .filter_map(|resource| {
                    if let OwnedResource::Route(route) = resource {
                        Some(route.clone())
                    } else {
                        None
                    }
                })
                .collect()
        });
    let proxy_owner =
        net_manager_core::system_proxy::load_ownership(&root.join("proxy-state.json"))
            .map_err(|_| "Cannot read system proxy ownership")?
            .map(|owner| owner.profile_id);
    let input = DiagnosticsInput {
        profile: profile.clone(),
        status: status.clone(),
        managed: vault.is_managed_profile_path(id, &profile.config_path),
        inspection: inspection.clone(),
        inspection_error,
        executable: resolve_backend_executable(root, &profile),
        interfaces,
        os_routes,
        owned_routes,
        protocol_health,
        proxy_owner,
    };
    let mut checks = build_diagnostics(&input);
    if linux_daemon_tunnel(&profile) {
        checks.retain(|check| check.name != "Applied routes");
        checks.extend(linux_owned_checks(&input, owners.as_ref()));
    }
    for check in &mut checks {
        check.message = safe_message(&check.message);
    }
    Ok(ProfileDiagnostics {
        profile_id: id.into(),
        status,
        inspection,
        checks,
    })
}

#[cfg(test)]
mod proxy_tests {
    use super::*;
    #[cfg(not(target_os = "linux"))]
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_tcp_listen_line() {
        let listen =
            "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
        assert_eq!(
            parse_listen_line(listen, false),
            Some((IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
        );
        // ESTABLISHED (st=01) is skipped; non-loopback binds are skipped.
        let estab =
            "   0: 0100007F:1F90 0100007F:0046 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 0";
        let lan =
            "   0: 0B01A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
        let any =
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
        assert_eq!(parse_listen_line(estab, false), None);
        assert_eq!(parse_listen_line(lan, false), None);
        assert_eq!(
            parse_listen_line(any, false),
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_tcp6_listen_line() {
        // ::1 (0000...0001 stored as four LE u32 words) on port 8080.
        let listen =
            "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
        assert_eq!(
            parse_listen_line(listen, true),
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 8080))
        );
    }

    /// Accept connections and serve `f` to each until the test ends.
    async fn responder<F, Fut>(f: F) -> (IpAddr, u16)
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let f = std::sync::Arc::new(f);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let f = f.clone();
                tokio::spawn(async move { f(stream).await });
            }
        });
        (IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn detects_socks5() {
        let (addr, port) = responder(|mut s| async move {
            let mut buf = [0u8; 3];
            let _ = s.read_exact(&mut buf).await;
            let _ = s.write_all(&[0x05, 0x00]).await;
        })
        .await;
        assert_eq!(probe(addr, port).await, Some(ProxyKind::Socks5));
    }

    #[tokio::test]
    async fn detects_http_connect_proxy() {
        let (addr, port) = responder(|mut s| async move {
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            if buf[0] == 0x05 {
                return; // close on the socks greeting
            }
            let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        })
        .await;
        assert_eq!(probe(addr, port).await, Some(ProxyKind::Http));
    }

    #[tokio::test]
    async fn plain_http_server_is_not_a_proxy() {
        let (addr, port) = responder(|mut s| async move {
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            if buf[0] == 0x05 {
                return;
            }
            let _ = s
                .write_all(b"HTTP/1.0 405 Method Not Allowed\r\n\r\n")
                .await;
        })
        .await;
        assert_eq!(probe(addr, port).await, None);
    }

    #[tokio::test]
    async fn detects_socks4() {
        let (addr, port) = responder(|mut s| async move {
            let mut buf = [0u8; 16];
            let _ = s.read(&mut buf).await;
            if buf[0] != 0x04 {
                return; // not a SOCKS4 greeting
            }
            let mut reply = [0u8; 8];
            reply[1] = 0x5b; // request rejected — still proves SOCKS4
            let _ = s.write_all(&reply).await;
        })
        .await;
        assert_eq!(probe(addr, port).await, Some(ProxyKind::Socks4));
    }

    #[tokio::test]
    async fn silent_listener_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await; // never speak
            }
        });
        assert_eq!(probe(IpAddr::V4(Ipv4Addr::LOCALHOST), port).await, None);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn scan_finds_real_listener() {
        let (addr, port) = responder(|mut s| async move {
            let mut buf = [0u8; 3];
            let _ = s.read_exact(&mut buf).await;
            let _ = s.write_all(&[0x05, 0x00]).await;
        })
        .await;
        // End to end: the listener surfaces in /proc enumeration, and the
        // probe classifies it. Probing is scoped to this test's own port —
        // a full host scan would consume accepts of concurrent tests'
        // listeners and flake them.
        assert!(loopback_listen_ports().contains(&(addr, port)));
        let found = probe_targets(vec![(addr, port)]).await;
        assert_eq!(
            found,
            vec![LocalProxy {
                address: addr,
                port,
                kind: ProxyKind::Socks5
            }]
        );
    }
}
#[cfg(test)]
mod safety_tests {
    use super::*;
    use net_manager_core::daemon_protocol::{OwnedEntry, OwnedState};
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn tun_diagnostics_ignore_socks_override_and_reject_unverified_package() {
        let dir = tempfile::tempdir().unwrap();
        let package_root = dir.path().join("package");
        let mut profile: Profile = serde_json::from_value(serde_json::json!({
            "id":"tun", "name":"tun", "backend":"xray", "configPath":"unused",
            "interfaceName":"", "routes":[], "autoConnect":false, "xrayMode":"socks"
        }))
        .unwrap();
        let executable = std::env::current_exe().unwrap();
        let settings = net_manager_core::backend_settings::BackendSettingsStore::new(
            dir.path().join("backend-settings.json"),
        );
        let document = net_manager_core::backend_settings::BackendSettingsDocument {
            xray: Some(BackendExecutableSetting {
                path: executable.clone(),
                source: BackendExecutableSource::Configured,
                version: None,
            }),
            ..Default::default()
        };
        settings.save(&document).unwrap();
        assert_eq!(
            resolve_backend_executable_at(dir.path(), &profile, &package_root).unwrap(),
            executable
        );
        profile.xray_mode = XrayMode::Tun;
        assert!(resolve_backend_executable_at(dir.path(), &profile, &package_root).is_err());

        let version = net_manager_core::managed_xray::linux_managed_version_dir(&package_root);
        fs::create_dir_all(&version).unwrap();
        for name in ["xray", "geoip.dat", "geosite.dat"] {
            fs::write(version.join(name), b"tampered package content").unwrap();
        }
        assert!(resolve_backend_executable_at(dir.path(), &profile, &package_root).is_err());
    }

    #[test]
    fn shared_logs_reopen_clear_and_retain_only_latest_entries() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..LOG_CAPACITY + 2 {
            record_log(dir.path(), LogLevel::Info, &format!("event {n}")).unwrap();
        }
        let entries = logs(dir.path()).unwrap();
        assert_eq!(entries.len(), LOG_CAPACITY);
        assert_eq!(entries[0].message, "event 2");
        assert_eq!(
            entries.last().unwrap().message,
            format!("event {}", LOG_CAPACITY + 1)
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("app-logs/events.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        clear_logs(dir.path()).unwrap();
        assert!(logs(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn shared_logs_redact_before_persisting() {
        let dir = tempfile::tempdir().unwrap();
        for secret in [
            "https://host.invalid/sub?token=secret-marker",
            "PrivateKey = secret-marker",
            "{\"outbounds\":[{\"password\":\"secret-marker\"}]}",
            "Authorization: Bearer secret-marker",
            "[Interface]\nsecret-marker",
        ] {
            record_log(dir.path(), LogLevel::Error, secret).unwrap();
        }
        let bytes = std::fs::read_to_string(dir.path().join("app-logs/events.json")).unwrap();
        assert!(!bytes.contains("secret-marker"));
        assert!(!bytes.contains("https://"));
    }

    #[test]
    fn shared_logs_reject_symlinks_and_corruption_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        record_log(dir.path(), LogLevel::Info, "before").unwrap();
        let path = dir.path().join("app-logs/events.json");
        std::fs::write(&path, "broken").unwrap();
        assert!(record_log(dir.path(), LogLevel::Info, "after").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "broken");
        std::fs::remove_file(&path).unwrap();
        let target = dir.path().join("foreign");
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(clear_logs(dir.path()).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "untouched");
    }

    #[test]
    fn shared_logs_concurrent_writers_do_not_lose_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for worker in 0..4 {
                let root = dir.path();
                scope.spawn(move || {
                    for n in 0..20 {
                        record_log(root, LogLevel::Info, &format!("{worker}-{n}")).unwrap();
                    }
                });
            }
        });
        assert_eq!(logs(dir.path()).unwrap().len(), 80);
    }

    #[test]
    fn recovery_preserves_unknown_foreign_and_always_on_owners() {
        let entries = [
            "manual",
            "intent:office",
            "cond:lan",
            "always-on:home",
            "wg:foreign",
            "foreign-owner",
        ]
        .map(|owner| OwnedEntry {
            owner: owner.into(),
            state: OwnedState::Stale,
            resources: vec![],
        });
        assert!(leftover_owners(&entries, &[], &[], &[], &["always-on:home".into()]).is_empty());
    }

    #[test]
    fn recovery_unknown_status_preserves_applied_saved_tunnel() {
        let profile: Profile = serde_json::from_value(serde_json::json!({"id":"home","name":"home","backend":"wireGuard","configPath":"unused","interfaceName":"","routes":[],"autoConnect":false})).unwrap();
        let entry = OwnedEntry {
            owner: "wg:home".into(),
            state: OwnedState::Applied,
            resources: vec![],
        };
        assert!(leftover_owners(
            &[entry],
            &[profile],
            &[("home".into(), Err("unavailable".into()))],
            &[],
            &[]
        )
        .is_empty());
    }

    #[test]
    fn recovery_keeps_saved_enrollment_even_when_stale() {
        let profile: Profile = serde_json::from_value(serde_json::json!({"id":"home","name":"home","backend":"wireGuard","configPath":"unused","interfaceName":"","routes":[],"autoConnect":false})).unwrap();
        let entry = OwnedEntry {
            owner: "wg:home".into(),
            state: OwnedState::Stale,
            resources: vec![],
        };
        assert!(leftover_owners(&[entry], &[profile], &[], &[], &["wg:home".into()]).is_empty());
    }

    #[test]
    fn recovery_does_not_interrupt_live_tunnel_with_stale_journal() {
        let profile: Profile = serde_json::from_value(serde_json::json!({"id":"home","name":"home","backend":"wireGuard","configPath":"unused","interfaceName":"","routes":[],"autoConnect":false})).unwrap();
        let entry = OwnedEntry {
            owner: "wg:home".into(),
            state: OwnedState::Stale,
            resources: vec![],
        };
        let status = TunnelStatus {
            profile_id: "home".into(),
            state: TunnelState::Running,
            message: None,
            interface_name: None,
            failover: None,
            watchdog: None,
        };
        assert!(leftover_owners(
            &[entry],
            &[profile],
            &[("home".into(), Ok(status))],
            &[],
            &[]
        )
        .is_empty());
    }

    #[test]
    fn recovery_cleans_recorded_tunnel_after_confirmed_stop() {
        let profile: Profile = serde_json::from_value(serde_json::json!({"id":"home","name":"home","backend":"wireGuard","configPath":"unused","interfaceName":"","routes":[],"autoConnect":false})).unwrap();
        let entry = OwnedEntry {
            owner: "wg:home".into(),
            state: OwnedState::Applied,
            resources: vec![],
        };
        let status = TunnelStatus {
            profile_id: "home".into(),
            state: TunnelState::Stopped,
            message: None,
            interface_name: None,
            failover: None,
            watchdog: None,
        };
        assert_eq!(
            leftover_owners(
                &[entry],
                &[profile],
                &[("home".into(), Ok(status))],
                &[],
                &[]
            ),
            ["wg:home"]
        );
    }

    #[test]
    fn cleanup_requires_daemon_confirmation_not_just_successful_rpc() {
        assert!(!cleanup_confirmed(
            method::WIREGUARD_DISCONNECT,
            &serde_json::json!({"stopped":false})
        ));
        assert!(cleanup_confirmed(
            method::WIREGUARD_DISCONNECT,
            &serde_json::json!({"stopped":true})
        ));
        assert!(!cleanup_confirmed(
            method::ROUTES_REMOVE,
            &serde_json::json!({})
        ));
        assert!(cleanup_confirmed(
            method::ROUTES_REMOVE,
            &serde_json::json!({"removed":0})
        ));
    }

    #[test]
    fn shared_logs_reject_replaceable_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(record_log(dir.path(), LogLevel::Info, "must not write").is_err());
        assert!(!dir.path().join("app-logs").exists());
    }

    #[tokio::test]
    async fn proxy_http_probe_terminates_headers() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut byte = [0];
                if stream.read_exact(&mut byte).await.is_err() {
                    return;
                }
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        assert!(timeout(Duration::from_secs(1), probe_http(&mut stream))
            .await
            .unwrap());
        server.await.unwrap();
    }
}

fn daemon_managed_owner(owner: &str) -> bool {
    owner == "manual"
        || ["intent:", "cond:", "always-on:", "tailscale:"]
            .iter()
            .any(|prefix| owner.starts_with(prefix))
}
const TUNNEL_OWNER_PREFIXES: [&str; 4] = ["wg:", "ovpn:", "ovpn-probe:", "xray:"];
use crate::linux_runtime::daemon_owner;
#[cfg(target_os = "linux")]
fn daemon_owned_profile(profile: &Profile) -> bool {
    matches!(
        profile.backend,
        TunnelBackend::WireGuard | TunnelBackend::OpenVpn
    ) || (profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun)
}

/// Owners that are leftovers rather than healthy state: non-applied journal
/// entries, static owners without a profile or with missing routes, and
/// daemon tunnels whose status failed. Newest first, like daemon teardown.
#[cfg(target_os = "linux")]
pub fn linux_leftover_owners(
    entries: &[net_manager_core::daemon_protocol::OwnedEntry],
    profiles: &[Profile],
    statuses: &[(String, Result<TunnelStatus, String>)],
    os_routes: &[RouteEntry],
) -> Vec<String> {
    use net_manager_core::daemon_protocol::{OwnedResource, OwnedState};

    let mut owners: Vec<String> = entries
        .iter()
        .rev()
        .filter(|entry| {
            if daemon_managed_owner(&entry.owner) {
                return false;
            }
            let tunnel = TUNNEL_OWNER_PREFIXES
                .iter()
                .any(|prefix| entry.owner.starts_with(prefix));
            entry.state != OwnedState::Applied
                || (!tunnel
                    && (!profiles.iter().any(|p| p.id == entry.owner)
                        || profiles.iter().any(|profile| {
                            profile.id == entry.owner
                                && profile.backend == TunnelBackend::Xray
                                && profile.xray_mode == XrayMode::Socks
                                && statuses.iter().any(|(id, status)| {
                                    id == &profile.id
                                        && status.as_ref().is_ok_and(|status| {
                                            status.state != TunnelState::Running
                                        })
                                })
                        })
                        || entry.resources.iter().any(|resource| {
                            matches!(resource, OwnedResource::Route(route)
                                if !os_routes.iter().any(|e| applied_route_present(route, e)))
                        })))
        })
        .map(|entry| entry.owner.clone())
        .collect();
    for (profile_id, status) in statuses {
        if !status
            .as_ref()
            .is_ok_and(|status| status.state == TunnelState::Failed)
        {
            continue;
        }
        let Some(profile) = profiles
            .iter()
            .find(|p| &p.id == profile_id && daemon_owned_profile(p))
        else {
            continue;
        };
        if let Some(owner) = daemon_owner(profile) {
            if !owners.contains(&owner) {
                owners.push(owner);
            }
        }
    }
    owners
}

/// The per-owner daemon method that removes `owner`. Probe owners have no
/// per-owner method; the daemon clears them on its own restart.
#[cfg(target_os = "linux")]
pub fn cleanup_request(owner: &str) -> Option<(&'static str, serde_json::Value)> {
    use net_manager_core::daemon_protocol::method;
    use serde_json::json;

    if owner.starts_with("ovpn-probe:") {
        return None;
    }
    for (prefix, method) in [
        ("wg:", method::WIREGUARD_DISCONNECT),
        ("ovpn:", method::OPENVPN_DISCONNECT),
        ("xray:", method::XRAY_DISCONNECT),
    ] {
        if let Some(profile_id) = owner.strip_prefix(prefix) {
            return Some((method, json!({ "profileId": profile_id })));
        }
    }
    Some((method::ROUTES_REMOVE, json!({ "owner": owner })))
}

pub fn build_recovery_report(
    profiles: &[Profile],
    statuses: &[(String, TunnelStatus)],
    ownership: &[AppliedProfileRoutes],
    os_routes: &[RouteEntry],
    proxy_ownership: Option<&ProxyOwnership>,
) -> RecoveryReport {
    let mut issues = Vec::new();
    if let Some(owner) = proxy_ownership {
        issues.push(RecoveryIssue {
            kind: RecoveryIssueKind::ProxyOwnership,
            profile_id: Some(owner.profile_id.clone()),
            message: format!(
                "system proxy settings owned by profile '{}' are still applied",
                owner.profile_id
            ),
        });
    }
    for (profile_id, status) in statuses {
        let Some(profile) = profiles.iter().find(|p| &p.id == profile_id) else {
            continue;
        };
        #[cfg(target_os = "linux")]
        if !daemon_owned_profile(profile) {
            continue;
        }
        #[cfg(not(target_os = "linux"))]
        if profile.backend != TunnelBackend::WireGuard {
            continue;
        }
        match status.state {
            TunnelState::Running => {
                #[cfg(not(target_os = "linux"))]
                issues.push(RecoveryIssue {
                    kind: RecoveryIssueKind::SurvivingWireGuardService,
                    profile_id: Some(profile_id.clone()),
                    message: format!(
                        "WireGuard tunnel service for profile '{}' ('{}') may still be installed",
                        profile.id, profile.name
                    ),
                });
            }
            TunnelState::Failed => issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::StatusCheckFailed,
                profile_id: Some(profile_id.clone()),
                message: format!(
                    "status check failed for profile '{}' ('{}'): {}",
                    profile.id,
                    profile.name,
                    status.message.as_deref().unwrap_or("unknown error")
                ),
            }),
            TunnelState::Stopped => {}
        }
    }
    for record in ownership {
        if !profiles.iter().any(|p| p.id == record.profile_id) {
            issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::OrphanRouteOwnership,
                profile_id: Some(record.profile_id.clone()),
                message: format!(
                    "route ownership is recorded for profile '{}' but the profile no longer exists",
                    record.profile_id
                ),
            });
            continue;
        }
        let missing: Vec<String> = record
            .routes
            .iter()
            .filter(|r| !os_routes.iter().any(|e| applied_route_present(r, e)))
            .map(|r| r.destination.to_string())
            .collect();
        if !record.routes.is_empty() && missing.is_empty() {
            issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::OwnedRoutes,
                profile_id: Some(record.profile_id.clone()),
                message: format!(
                    "{} route(s) owned by profile '{}' are still present in the route table",
                    record.routes.len(),
                    record.profile_id
                ),
            });
        } else {
            let detail = if missing.is_empty() {
                format!("{} route(s)", record.routes.len())
            } else {
                missing.join(", ")
            };
            issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::MissingOwnedRoutes,
                profile_id: Some(record.profile_id.clone()),
                message: format!(
                    "route(s) owned by profile '{}' are missing from the route table: {detail}",
                    record.profile_id
                ),
            });
        }
    }
    RecoveryReport {
        requires_elevation: !issues.is_empty(),
        issues,
    }
}

fn leftover_owners(
    entries: &[net_manager_core::daemon_protocol::OwnedEntry],
    profiles: &[Profile],
    statuses: &[(String, Result<TunnelStatus, String>)],
    routes: &[RouteEntry],
    protected: &[String],
) -> Vec<String> {
    let mut candidates = linux_leftover_owners(entries, profiles, statuses, routes);
    for profile in profiles {
        if let Some(owner) = daemon_owner(profile) {
            if entries.iter().any(|entry| entry.owner == owner)
                && statuses.iter().any(|(id, status)| {
                    id == &profile.id
                        && status
                            .as_ref()
                            .is_ok_and(|status| status.state == TunnelState::Stopped)
                })
                && !candidates.contains(&owner)
            {
                candidates.push(owner);
            }
        }
    }
    candidates.retain(|owner| {
        if let Some(profile) = profiles
            .iter()
            .find(|profile| profile.id == *owner || daemon_owner(profile).as_ref() == Some(owner))
        {
            if statuses.iter().any(|(id, status)| {
                id == &profile.id
                    && (status.is_err()
                        || (profile.backend != TunnelBackend::None
                            && status
                                .as_ref()
                                .is_ok_and(|status| status.state == TunnelState::Running)))
            }) {
                return false;
            }
        }
        !protected.contains(owner)
            && !daemon_managed_owner(owner)
            && (profiles.iter().any(|profile| {
                profile.id == *owner
                    || daemon_owner(profile).as_ref() == Some(owner)
                    || owner.strip_prefix("ovpn-probe:") == Some(profile.id.as_str())
            }) || entries.iter().any(|entry| {
                entry.owner == *owner
                    && !TUNNEL_OWNER_PREFIXES
                        .iter()
                        .any(|prefix| owner.starts_with(prefix))
                    && !entry.resources.is_empty()
                    && entry
                        .resources
                        .iter()
                        .all(|resource| matches!(resource, OwnedResource::Route(_)))
            }))
    });
    candidates
}

async fn collect_recovery(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
) -> Result<(RecoveryReport, Vec<String>), String> {
    let profiles = store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles;
    let routes = explorer::list_routes()
        .await
        .map_err(|_| "Cannot enumerate OS routes")?;
    let statuses: Vec<_> = profiles
        .iter()
        .map(|profile| (profile.id.clone(), engine.status(profile)))
        .collect();
    let owned: OwnedListResult = engine
        .ask(method::OWNED_LIST, serde_json::Value::Null)
        .map_err(|error| safe_message(&error))?;
    // An unavailable enrollment list must stop cleanup, not guess that no owners are protected.
    let enrollment: net_manager_core::daemon_protocol::AlwaysOnListResult = engine
        .ask(method::ALWAYS_ON_LIST, serde_json::Value::Null)
        .map_err(|error| safe_message(&error))?;
    let protected: Vec<_> = enrollment
        .profiles
        .iter()
        .map(|profile| match profile.kind {
            net_manager_core::daemon_protocol::AlwaysOnKind::WireGuard => {
                format!("wg:{}", profile.profile_id)
            }
            net_manager_core::daemon_protocol::AlwaysOnKind::StaticRoutes => {
                profile.profile_id.clone()
            }
        })
        .collect();
    let leftovers = leftover_owners(&owned.owners, &profiles, &statuses, &routes, &protected);
    let mut issues: Vec<_> = leftovers
        .iter()
        .map(|owner| RecoveryIssue {
            kind: RecoveryIssueKind::LeftoverTunnel,
            profile_id: Some(
                owner
                    .split_once(':')
                    .map_or(owner.as_str(), |(_, id)| id)
                    .into(),
            ),
            message: "Leftover application-owned resources require cleanup".into(),
        })
        .collect();
    for (id, status) in &statuses {
        if status.is_err() {
            issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::StatusCheckFailed,
                profile_id: Some(id.clone()),
                message: "Profile status is unavailable; its resources will be preserved".into(),
            });
        }
    }
    if let Some(owner) =
        net_manager_core::system_proxy::load_ownership(&root.join("proxy-state.json"))
            .map_err(|_| "Cannot read system proxy ownership")?
    {
        if statuses
            .iter()
            .find(|(id, _)| id == &owner.profile_id)
            .is_none_or(|(_, result)| {
                result
                    .as_ref()
                    .is_ok_and(|status| status.state != TunnelState::Running)
            })
        {
            issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::ProxyOwnership,
                profile_id: Some(owner.profile_id),
                message: "System proxy ownership remains after its tunnel stopped".into(),
            });
        }
    }
    Ok((
        RecoveryReport {
            requires_elevation: !leftovers.is_empty(),
            issues,
        },
        leftovers,
    ))
}

pub async fn recovery_report(
    engine: &LinuxEngine,
    root: &Path,
    _vault: &ConfigVault,
    store: &ProfileStore,
) -> Result<RecoveryReport, String> {
    collect_recovery(engine, root, store)
        .await
        .map(|(report, _)| report)
}

fn cleanup_confirmed(method_name: &str, reply: &serde_json::Value) -> bool {
    if method_name == method::ROUTES_REMOVE {
        reply
            .get("removed")
            .and_then(serde_json::Value::as_u64)
            .is_some()
    } else {
        reply.get("stopped").and_then(serde_json::Value::as_bool) == Some(true)
    }
}

pub async fn cleanup_recovery(
    engine: &LinuxEngine,
    root: &Path,
    vault: &ConfigVault,
    store: &ProfileStore,
) -> Result<RecoveryReport, String> {
    let (report, leftovers) = collect_recovery(engine, root, store).await?;
    if report
        .issues
        .iter()
        .any(|issue| issue.kind == RecoveryIssueKind::ProxyOwnership)
    {
        engine
            .recover_local_proxy()
            .map_err(|error| safe_message(&error))?;
    }
    let mut failed = 0;
    let mut removed = 0;
    let mut unsupported_probes = 0;
    for owner in leftovers {
        // Re-observe before each destructive operation; another frontend may have connected it.
        if !collect_recovery(engine, root, store)
            .await?
            .1
            .contains(&owner)
        {
            continue;
        }
        if let Some((method, params)) = cleanup_request(&owner) {
            match engine.ask::<_, serde_json::Value>(method, params) {
                Ok(reply) if cleanup_confirmed(method, &reply) => removed += 1,
                _ => failed += 1,
            }
        } else {
            unsupported_probes += 1;
        }
    }
    if removed > 0 {
        let _ = record_log(
            root,
            LogLevel::Warn,
            &format!("recovery cleanup removed {removed} leftover owner(s)"),
        );
    }
    if failed > 0 {
        return Err(format!("Daemon could not clean up {failed} owner(s)"));
    }
    if unsupported_probes > 0 {
        return Err(format!("{unsupported_probes} probe leftover(s) require a daemon restart; per-owner cleanup is unavailable"));
    }
    recovery_report(engine, root, vault, store).await
}
