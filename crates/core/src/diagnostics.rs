//! Diagnostic checks for one profile, as pure functions over data the caller
//! collected. The privileged helper's tunnels (macOS) are covered by
//! [`profile_checks`]; the checks that do not depend on the platform
//! (endpoint path, static analysis, endpoints, listeners, system proxy) are
//! public so other clients can share them.
//!
//! Message texts match the Linux/Windows client's checks where a check exists
//! on both, so the same words describe the same problem everywhere.

use crate::analysis;
use crate::config_vault::ConfigVault;
use crate::daemon_protocol::{
    OpenVpnConnectionState, OpenVpnStatusResult, WireGuardStatusResult, WireGuardWarning,
    XrayStatusResult,
};
use crate::explorer;
use crate::models::*;
use std::net::IpAddr;
use std::path::PathBuf;

fn check(name: &str, level: DiagnosticLevel, message: impl Into<String>) -> DiagnosticCheck {
    DiagnosticCheck {
        name: name.to_string(),
        level,
        message: message.into(),
    }
}

/// Whether a profile's tunnel is created and owned by the privileged helper
/// (Xray TUN, WireGuard, OpenVPN) rather than by the app itself.
pub fn runs_in_helper(profile: &Profile) -> bool {
    matches!(
        profile.backend,
        TunnelBackend::WireGuard | TunnelBackend::OpenVpn
    ) || (profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun)
}

/// What the helper said about itself, for profiles that run in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperView {
    pub reachable: bool,
    /// The helper advertises the capability this profile needs.
    pub offers_capability: bool,
    pub version: String,
}

/// Detail from the helper's status answer beyond running/stopped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelDetail {
    pub dns_applied: Option<bool>,
    pub ipv6_covered: Option<bool>,
    pub notes: Vec<String>,
}

pub struct ProfileChecksInput {
    pub profile: Profile,
    pub status: TunnelStatus,
    pub inspection: Option<ProfileInspection>,
    pub inspection_error: Option<String>,
    /// The user's managed Xray (Xray profiles only).
    pub xray: Result<PathBuf, String>,
    /// `Some` for a profile whose tunnel the helper runs, `None` for loopback
    /// Xray, which is a child of the app.
    pub helper: Option<HelperView>,
    /// Whether the helper's `owned.list` names this profile; `None` when the
    /// helper could not be asked.
    pub helper_owns: Option<bool>,
    pub detail: TunnelDetail,
    pub protocol_health: ProtocolHealth,
    pub interfaces: Result<Vec<NetworkInterface>, String>,
    pub os_routes: Result<Vec<RouteEntry>, String>,
    pub proxy_owner: Option<String>,
}

/// Static analysis of `candidate` plus its conflicts with the other profiles
/// and the OS routes; the shape the web client's profile detail also shows.
pub fn build_profile_inspection(
    candidate: &Profile,
    others: &[Profile],
    os_routes: &[RouteEntry],
    vault: &ConfigVault,
) -> Result<ProfileInspection, String> {
    // The io error text can carry the config's path, so it is not passed on.
    let mut analysis = analysis::analyze_profile(candidate)
        .map_err(|_| "it is missing, unreadable or not valid for this backend".to_string())?;
    let mut conflicts = Vec::new();
    for other in others {
        match analysis::analyze_profile(other) {
            Ok(other_analysis) => conflicts.extend(analysis::conflicts_between(
                &analysis,
                &other_analysis,
                false,
            )),
            Err(_) => analysis.warnings.push(format!(
                "could not analyze profile '{}' ('{}') for conflicts",
                other.name, other.id
            )),
        }
    }
    conflicts.extend(analysis::warnings_against_os_routes(&analysis, os_routes));
    Ok(ProfileInspection {
        analysis,
        conflicts,
        managed_config: vault.is_managed_profile_path(&candidate.id, &candidate.config_path),
    })
}

// ---- Protocol health from the helper's status answers -------------------

pub fn wireguard_health(status: &WireGuardStatusResult) -> ProtocolHealth {
    let running = status.state == TunnelState::Running;
    ProtocolHealth {
        state: if status.latest_handshake.is_some() && running {
            ProtocolHealthState::Healthy
        } else if status.state == TunnelState::Failed {
            ProtocolHealthState::Failed
        } else {
            ProtocolHealthState::Unknown
        },
        summary: if status.latest_handshake.is_some() {
            "WireGuard handshake reported by the privileged helper".into()
        } else {
            "No WireGuard handshake reported yet".into()
        },
        last_handshake_unix: status.latest_handshake,
        rx_bytes: Some(status.rx_bytes),
        tx_bytes: Some(status.tx_bytes),
        log_tail: None,
        pushed_routes: Vec::new(),
    }
}

pub fn openvpn_health(status: &OpenVpnStatusResult) -> ProtocolHealth {
    let state = match status.state {
        OpenVpnConnectionState::Connected if status.warnings.is_empty() => {
            ProtocolHealthState::Healthy
        }
        OpenVpnConnectionState::Connected
        | OpenVpnConnectionState::Connecting
        | OpenVpnConnectionState::Reconnecting => ProtocolHealthState::Degraded,
        OpenVpnConnectionState::Failed => ProtocolHealthState::Failed,
        OpenVpnConnectionState::Stopped => ProtocolHealthState::Unknown,
    };
    ProtocolHealth {
        state,
        summary: format!(
            "OpenVPN {:?} reported by the privileged helper",
            status.state
        ),
        last_handshake_unix: None,
        rx_bytes: Some(status.rx_bytes),
        tx_bytes: Some(status.tx_bytes),
        log_tail: None,
        pushed_routes: status
            .applied_routes
            .iter()
            .map(|destination| AnalyzedRoute {
                destination: *destination,
                source: "OpenVPN".into(),
                metric: None,
            })
            .collect(),
    }
}

pub fn xray_tun_health(status: &XrayStatusResult) -> ProtocolHealth {
    let (state, summary) = if status.state == TunnelState::Failed {
        (ProtocolHealthState::Failed, "Xray TUN process failed")
    } else if status.state == TunnelState::Running {
        match status.watchdog.as_ref() {
            Some(watchdog)
                if watchdog.uplink == Some(false)
                    || watchdog.https_stall_streak >= 3
                    || watchdog.dns_stall_streak >= 3
                    || !watchdog.anomalies.is_empty() =>
            {
                (
                    ProtocolHealthState::Degraded,
                    "Xray TUN watchdog reports a path or resource problem",
                )
            }
            Some(watchdog)
                if watchdog.https_latency_ms.is_some() && watchdog.https_stall_streak == 0 =>
            {
                (
                    ProtocolHealthState::Healthy,
                    "HTTPS through the owned Xray TUN was verified",
                )
            }
            _ => (
                ProtocolHealthState::Unknown,
                "Xray TUN traffic has not been verified",
            ),
        }
    } else {
        (ProtocolHealthState::Unknown, "Xray TUN is not running")
    };
    ProtocolHealth {
        state,
        summary: summary.into(),
        last_handshake_unix: None,
        rx_bytes: status.rx_bytes,
        tx_bytes: status.tx_bytes,
        log_tail: None,
        pushed_routes: Vec::new(),
    }
}

/// Health for a tunnel whose status could not be read.
pub fn failed_health(message: &str) -> ProtocolHealth {
    ProtocolHealth {
        state: ProtocolHealthState::Failed,
        summary: message.to_string(),
        last_handshake_unix: None,
        rx_bytes: None,
        tx_bytes: None,
        log_tail: None,
        pushed_routes: Vec::new(),
    }
}

pub fn wireguard_detail(status: &WireGuardStatusResult) -> TunnelDetail {
    TunnelDetail {
        dns_applied: Some(status.dns_applied),
        ipv6_covered: None,
        notes: status
            .warnings
            .iter()
            .map(|warning| match warning {
                WireGuardWarning::IgnoredHook => "a PostUp/PreDown hook in the config was ignored",
                WireGuardWarning::IgnoredSaveConfig => "SaveConfig in the config was ignored",
                WireGuardWarning::DnsNotApplied => "the tunnel's DNS settings were not applied",
                WireGuardWarning::Ipv6NotCovered => {
                    "IPv6 is not covered by the allowed addresses and keeps using the uplink"
                }
            })
            .map(String::from)
            .collect(),
    }
}

pub fn xray_tun_detail(status: &XrayStatusResult) -> TunnelDetail {
    TunnelDetail {
        dns_applied: Some(status.dns_applied),
        ipv6_covered: Some(status.ipv6_covered),
        notes: Vec::new(),
    }
}

// ---- Checks that do not depend on the platform --------------------------

/// A remote endpoint that resolves out a tunnel interface gets its handshake
/// swallowed (TLS timeouts). Only literal IPs are checked: names are resolved
/// by whoever applies the routes. `None` when there is nothing to check.
pub fn endpoint_path_check(
    profile: &Profile,
    inspection: Option<&ProfileInspection>,
    os_routes: &[RouteEntry],
    interfaces: &[NetworkInterface],
) -> Option<DiagnosticCheck> {
    let mut endpoints: Vec<IpAddr> = profile
        .endpoint_bypasses
        .iter()
        .filter_map(|e| e.trim().parse().ok())
        .collect();
    if let Some(inspection) = inspection {
        endpoints.extend(
            inspection
                .analysis
                .endpoints
                .iter()
                .filter_map(|e| e.address.trim().parse::<IpAddr>().ok()),
        );
    }
    endpoints.sort();
    endpoints.dedup();
    if endpoints.is_empty() {
        return None;
    }
    let swallowed: Vec<String> = endpoints
        .iter()
        .filter_map(|ip| {
            let route = explorer::longest_prefix_match(*ip, os_routes)?;
            let tunnel_ish = interfaces
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
    Some(if swallowed.is_empty() {
        check(
            "Endpoint path",
            DiagnosticLevel::Healthy,
            format!(
                "{} endpoint(s) route via a physical uplink",
                endpoints.len()
            ),
        )
    } else {
        check(
            "Endpoint path",
            DiagnosticLevel::Warning,
            format!(
                "endpoint(s) {} route via a tunnel interface — the handshake may never reach the server; add an endpoint bypass through the physical gateway",
                swallowed.join(", ")
            ),
        )
    })
}

pub fn static_analysis_check(inspection: Option<&ProfileInspection>) -> DiagnosticCheck {
    let Some(inspection) = inspection else {
        return check(
            "Static analysis",
            DiagnosticLevel::Warning,
            "static analysis unavailable",
        );
    };
    let warning_count = inspection.analysis.warnings.len();
    let conflict_count = inspection.conflicts.len();
    let incomplete = !inspection.analysis.route_knowledge_complete;
    if warning_count + conflict_count == 0 && !incomplete {
        return check(
            "Static analysis",
            DiagnosticLevel::Healthy,
            "no warnings or conflicts",
        );
    }
    let mut details: Vec<String> = inspection.analysis.warnings.clone();
    details.extend(inspection.conflicts.iter().map(|c| c.message.clone()));
    if incomplete {
        details.push("effective routes are not fully known".to_string());
    }
    check(
        "Static analysis",
        DiagnosticLevel::Warning,
        format!(
            "{warning_count} warning(s), {conflict_count} conflict(s): {}",
            details.join("; ")
        ),
    )
}

/// The "Endpoints" and, for Xray, "Listeners" checks.
pub fn config_facts_checks(
    profile: &Profile,
    inspection: &ProfileInspection,
) -> Vec<DiagnosticCheck> {
    let analysis = &inspection.analysis;
    let mut checks = Vec::new();
    if analysis.endpoints.is_empty() {
        checks.push(check(
            "Endpoints",
            DiagnosticLevel::Warning,
            "no remote endpoints discovered in config",
        ));
    } else {
        let list = analysis
            .endpoints
            .iter()
            .map(|e| match e.port {
                Some(port) => format!("{}:{port}", e.address),
                None => e.address.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        checks.push(check(
            "Endpoints",
            DiagnosticLevel::Healthy,
            format!("{} endpoint(s): {list}", analysis.endpoints.len()),
        ));
    }
    if profile.backend == TunnelBackend::Xray {
        if analysis.listeners.is_empty() {
            checks.push(check(
                "Listeners",
                DiagnosticLevel::Warning,
                "no inbound listeners discovered",
            ));
        } else {
            let list = analysis
                .listeners
                .iter()
                .map(|l| format!("{}:{}", l.address, l.port))
                .collect::<Vec<_>>()
                .join(", ");
            checks.push(check(
                "Listeners",
                DiagnosticLevel::Healthy,
                format!("listeners: {list}"),
            ));
        }
    }
    checks
}

/// `None` when the profile does not use the system proxy and nobody owns it.
pub fn system_proxy_check(
    profile: &Profile,
    status: &TunnelStatus,
    proxy_owner: Option<&str>,
) -> Option<DiagnosticCheck> {
    if !profile.use_system_proxy && proxy_owner.is_none() {
        return None;
    }
    Some(match proxy_owner {
        Some(owner) if owner == profile.id => {
            if status.state == TunnelState::Running {
                check(
                    "System proxy",
                    DiagnosticLevel::Healthy,
                    "system proxy is applied for this profile (127.0.0.1 SOCKS5)",
                )
            } else {
                check(
                    "System proxy",
                    DiagnosticLevel::Error,
                    "stale ownership: system proxy still applied while the profile is not running",
                )
            }
        }
        Some(owner) => check(
            "System proxy",
            DiagnosticLevel::Error,
            format!("system proxy is owned by another profile '{owner}'"),
        ),
        None if profile.use_system_proxy => check(
            "System proxy",
            DiagnosticLevel::Warning,
            "system proxy is configured but not currently applied",
        ),
        None => check(
            "System proxy",
            DiagnosticLevel::Warning,
            "stale system proxy record without a known owner",
        ),
    })
}

fn tunnel_status_check(status: &TunnelStatus) -> DiagnosticCheck {
    const NOTE: &str = "process/service state only, not handshake verification";
    match status.state {
        TunnelState::Running => check(
            "Tunnel status",
            DiagnosticLevel::Healthy,
            format!("running ({NOTE})"),
        ),
        TunnelState::Stopped => check(
            "Tunnel status",
            DiagnosticLevel::Warning,
            format!("stopped ({NOTE})"),
        ),
        TunnelState::Failed => check(
            "Tunnel status",
            DiagnosticLevel::Error,
            format!(
                "failed: {} ({NOTE})",
                status.message.as_deref().unwrap_or("unknown error")
            ),
        ),
    }
}

fn protocol_health_checks(health: &ProtocolHealth) -> Vec<DiagnosticCheck> {
    let mut checks = vec![check(
        "Protocol health",
        match health.state {
            ProtocolHealthState::Healthy => DiagnosticLevel::Healthy,
            ProtocolHealthState::Degraded | ProtocolHealthState::Unknown => {
                DiagnosticLevel::Warning
            }
            ProtocolHealthState::Failed => DiagnosticLevel::Error,
        },
        health.summary.clone(),
    )];
    if let Some(tail) = health.log_tail.as_ref().filter(|t| !t.trim().is_empty()) {
        checks.push(check(
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
        checks.push(check(
            "Helper routes",
            DiagnosticLevel::Healthy,
            format!("{} route(s): {list}", health.pushed_routes.len()),
        ));
    }
    checks
}

fn configuration_check(input: &ProfileChecksInput) -> DiagnosticCheck {
    match &input.inspection {
        None => check(
            "Configuration",
            DiagnosticLevel::Error,
            format!(
                "configuration could not be read or analyzed: {}",
                input.inspection_error.as_deref().unwrap_or("unknown error")
            ),
        ),
        Some(inspection) if inspection.managed_config => check(
            "Configuration",
            DiagnosticLevel::Healthy,
            "configuration is stored in managed storage",
        ),
        Some(_) => check(
            "Configuration",
            DiagnosticLevel::Warning,
            "Resave this profile to import it into managed storage",
        ),
    }
}

fn helper_check(profile: &Profile, helper: &HelperView) -> DiagnosticCheck {
    if !helper.reachable {
        check(
            "Privileged helper",
            DiagnosticLevel::Error,
            "the privileged helper is not running; install it in Settings",
        )
    } else if !helper.offers_capability {
        check(
            "Privileged helper",
            DiagnosticLevel::Error,
            format!(
                "the installed helper ({}) cannot run {:?} connections; update it in Settings",
                helper.version, profile.backend
            ),
        )
    } else {
        check(
            "Privileged helper",
            DiagnosticLevel::Healthy,
            format!(
                "helper {} is running and serves this connection",
                helper.version
            ),
        )
    }
}

fn ownership_check(input: &ProfileChecksInput) -> Option<DiagnosticCheck> {
    let owns = input.helper_owns?;
    Some(match (input.status.state, owns) {
        (TunnelState::Running, true) => check(
            "Helper ownership",
            DiagnosticLevel::Healthy,
            "the helper holds the routes and DNS of this running tunnel",
        ),
        (TunnelState::Running, false) => check(
            "Helper ownership",
            DiagnosticLevel::Error,
            "the tunnel runs but the helper has no record of it, so a crash could not be cleaned up",
        ),
        (_, true) => check(
            "Helper ownership",
            DiagnosticLevel::Warning,
            "the helper still records routes or DNS for this stopped tunnel; clean up leftovers when the app starts",
        ),
        (_, false) => check(
            "Helper ownership",
            DiagnosticLevel::Healthy,
            "the helper holds nothing for this connection",
        ),
    })
}

fn role_check(profile: &Profile) -> DiagnosticCheck {
    match profile.tunnel_role {
        TunnelRole::Primary => check(
            "Tunnel role",
            DiagnosticLevel::Healthy,
            "primary: carries all traffic that no routing rule sends elsewhere",
        ),
        TunnelRole::Secondary if profile.tunnel_networks.is_empty() => check(
            "Tunnel role",
            DiagnosticLevel::Error,
            "secondary without networks: nothing is routed through this tunnel",
        ),
        TunnelRole::Secondary => check(
            "Tunnel role",
            DiagnosticLevel::Healthy,
            format!(
                "secondary: carries only {}",
                profile
                    .tunnel_networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
    }
}

fn dns_and_ipv6_checks(input: &ProfileChecksInput) -> Vec<DiagnosticCheck> {
    let mut checks = Vec::new();
    if input.status.state != TunnelState::Running {
        return checks;
    }
    let secondary = input.profile.tunnel_role == TunnelRole::Secondary;
    if let Some(applied) = input.detail.dns_applied {
        checks.push(if applied {
            check(
                "Tunnel DNS",
                DiagnosticLevel::Healthy,
                if secondary {
                    "split DNS is in place for the listed domains"
                } else {
                    "the tunnel's DNS servers are applied"
                },
            )
        } else {
            check(
                "Tunnel DNS",
                DiagnosticLevel::Warning,
                "the tunnel's DNS servers are not applied; names resolve through the local network",
            )
        });
    }
    if !secondary {
        if let Some(covered) = input.detail.ipv6_covered {
            checks.push(if covered {
                check(
                    "IPv6 coverage",
                    DiagnosticLevel::Healthy,
                    "IPv6 goes through the tunnel",
                )
            } else {
                check(
                    "IPv6 coverage",
                    DiagnosticLevel::Warning,
                    "IPv6 is not covered and keeps using the uplink",
                )
            });
        }
    }
    for note in &input.detail.notes {
        checks.push(check("Helper note", DiagnosticLevel::Warning, note.clone()));
    }
    checks
}

/// Every check for one profile, in the order they are shown.
pub fn profile_checks(input: &ProfileChecksInput) -> Vec<DiagnosticCheck> {
    let profile = &input.profile;
    let mut checks = vec![configuration_check(input)];
    if let Some(helper) = &input.helper {
        checks.push(helper_check(profile, helper));
    }
    if profile.backend == TunnelBackend::Xray {
        checks.push(match &input.xray {
            Ok(path) => check(
                "Backend executable",
                DiagnosticLevel::Healthy,
                format!("verified managed Xray found at {}", path.display()),
            ),
            Err(error) => check("Backend executable", DiagnosticLevel::Error, error.clone()),
        });
    }
    checks.push(tunnel_status_check(&input.status));
    checks.extend(protocol_health_checks(&input.protocol_health));
    if input.helper.is_some() {
        checks.push(role_check(profile));
        checks.extend(dns_and_ipv6_checks(input));
        checks.extend(ownership_check(input));
    }
    if let Some(check) = endpoint_path_check(
        profile,
        input.inspection.as_ref(),
        input.os_routes.as_deref().unwrap_or(&[]),
        input.interfaces.as_deref().unwrap_or(&[]),
    ) {
        checks.push(check);
    }
    if let Some(check) = system_proxy_check(profile, &input.status, input.proxy_owner.as_deref()) {
        checks.push(check);
    }
    checks.push(static_analysis_check(input.inspection.as_ref()));
    if let Some(inspection) = &input.inspection {
        checks.extend(config_facts_checks(profile, inspection));
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wg() -> Profile {
        Profile {
            id: "wg1".into(),
            name: "Work".into(),
            backend: TunnelBackend::WireGuard,
            ..Default::default()
        }
    }

    fn xray_tun() -> Profile {
        Profile {
            id: "x1".into(),
            backend: TunnelBackend::Xray,
            xray_mode: XrayMode::Tun,
            ..Default::default()
        }
    }

    fn status(state: TunnelState, message: Option<&str>) -> TunnelStatus {
        TunnelStatus {
            profile_id: "wg1".into(),
            state,
            message: message.map(String::from),
            interface_name: None,
            failover: None,
            watchdog: None,
        }
    }

    fn analysis(endpoints: &[(&str, Option<u16>)], warnings: &[&str]) -> ConfigAnalysis {
        ConfigAnalysis {
            profile_id: "wg1".into(),
            os_routes: Vec::new(),
            internal_routes: Vec::new(),
            listeners: vec![LocalListener {
                address: "127.0.0.1".into(),
                port: 1080,
                protocol: "socks".into(),
            }],
            endpoints: endpoints
                .iter()
                .map(|(address, port)| RemoteEndpoint {
                    address: (*address).into(),
                    port: *port,
                    protocol: "udp".into(),
                })
                .collect(),
            domain_patterns: Vec::new(),
            warnings: warnings.iter().map(|w| w.to_string()).collect(),
            route_knowledge_complete: true,
            peers: Vec::new(),
            interface_details: Vec::new(),
        }
    }

    fn inspection(endpoints: &[(&str, Option<u16>)]) -> ProfileInspection {
        ProfileInspection {
            analysis: analysis(endpoints, &[]),
            conflicts: Vec::new(),
            managed_config: true,
        }
    }

    fn health(state: ProtocolHealthState, summary: &str) -> ProtocolHealth {
        ProtocolHealth {
            state,
            summary: summary.into(),
            last_handshake_unix: None,
            rx_bytes: None,
            tx_bytes: None,
            log_tail: None,
            pushed_routes: Vec::new(),
        }
    }

    fn input(profile: Profile, state: TunnelState) -> ProfileChecksInput {
        ProfileChecksInput {
            status: status(state, None),
            profile,
            inspection: Some(inspection(&[("203.0.113.9", Some(51820))])),
            inspection_error: None,
            xray: Ok(PathBuf::from("/Users/u/xray")),
            helper: Some(HelperView {
                reachable: true,
                offers_capability: true,
                version: "0.9.1".into(),
            }),
            helper_owns: Some(state == TunnelState::Running),
            detail: TunnelDetail::default(),
            protocol_health: health(ProtocolHealthState::Healthy, "ok"),
            interfaces: Ok(Vec::new()),
            os_routes: Ok(Vec::new()),
            proxy_owner: None,
        }
    }

    fn find<'a>(checks: &'a [DiagnosticCheck], name: &str) -> &'a DiagnosticCheck {
        checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no '{name}' check in {checks:?}"))
    }

    fn route(destination: &str, prefix: u8, interface: &str) -> RouteEntry {
        RouteEntry {
            destination: destination.parse().unwrap(),
            prefix_len: prefix,
            gateway: None,
            interface_index: 1,
            interface_name: interface.into(),
            metric: 0,
        }
    }

    #[test]
    fn a_healthy_running_wireguard_tunnel_has_no_warnings() {
        let checks = profile_checks(&input(wg(), TunnelState::Running));
        assert!(
            checks.iter().all(|c| c.level == DiagnosticLevel::Healthy),
            "{checks:?}"
        );
        assert!(find(&checks, "Privileged helper").message.contains("0.9.1"));
        assert_eq!(
            find(&checks, "Helper ownership").level,
            DiagnosticLevel::Healthy
        );
    }

    #[test]
    fn a_loopback_profile_gets_no_helper_checks() {
        let socks = Profile {
            id: "s1".into(),
            backend: TunnelBackend::Xray,
            xray_mode: XrayMode::Socks,
            ..Default::default()
        };
        let mut i = input(socks, TunnelState::Running);
        i.helper = None;
        i.helper_owns = None;
        let checks = profile_checks(&i);
        for name in [
            "Privileged helper",
            "Helper ownership",
            "Tunnel role",
            "Tunnel DNS",
        ] {
            assert!(
                checks.iter().all(|c| c.name != name),
                "{name} in {checks:?}"
            );
        }
        assert_eq!(
            find(&checks, "Backend executable").level,
            DiagnosticLevel::Healthy
        );
        assert_eq!(find(&checks, "Listeners").level, DiagnosticLevel::Healthy);
    }

    #[test]
    fn only_helper_run_profiles_are_recognised() {
        assert!(runs_in_helper(&wg()) && runs_in_helper(&xray_tun()));
        let socks = Profile {
            backend: TunnelBackend::Xray,
            xray_mode: XrayMode::Socks,
            ..Default::default()
        };
        assert!(!runs_in_helper(&socks));
        assert!(!runs_in_helper(&Profile::default()));
    }

    #[test]
    fn a_missing_or_old_helper_is_an_error_with_a_next_step() {
        let mut missing = input(wg(), TunnelState::Stopped);
        missing.helper.as_mut().unwrap().reachable = false;
        let check = profile_checks(&missing)
            .into_iter()
            .find(|c| c.name == "Privileged helper")
            .unwrap();
        assert_eq!(check.level, DiagnosticLevel::Error);
        assert!(check.message.contains("install it in Settings"));

        let mut old = input(wg(), TunnelState::Stopped);
        old.helper.as_mut().unwrap().offers_capability = false;
        let check = find(&profile_checks(&old), "Privileged helper").clone();
        assert_eq!(check.level, DiagnosticLevel::Error);
        assert!(check.message.contains("0.9.1") && check.message.contains("update it"));
    }

    #[test]
    fn xray_needs_its_managed_executable_and_other_backends_do_not() {
        let mut tun = input(xray_tun(), TunnelState::Stopped);
        tun.xray = Err("Install Xray to start this connection".into());
        let checks = profile_checks(&tun);
        let check = find(&checks, "Backend executable");
        assert_eq!(check.level, DiagnosticLevel::Error);
        assert!(check.message.contains("Install Xray"));
        let wg_checks = profile_checks(&input(wg(), TunnelState::Stopped));
        assert!(wg_checks.iter().all(|c| c.name != "Backend executable"));
    }

    #[test]
    fn tunnel_status_levels_follow_the_state() {
        let level = |state, message| {
            let mut i = input(wg(), state);
            i.status = status(state, message);
            find(&profile_checks(&i), "Tunnel status").clone()
        };
        assert_eq!(
            level(TunnelState::Running, None).level,
            DiagnosticLevel::Healthy
        );
        assert_eq!(
            level(TunnelState::Stopped, None).level,
            DiagnosticLevel::Warning
        );
        let failed = level(TunnelState::Failed, Some("device busy"));
        assert_eq!(failed.level, DiagnosticLevel::Error);
        assert!(failed.message.contains("device busy"));
    }

    #[test]
    fn helper_ownership_flags_a_tunnel_the_helper_cannot_clean_up() {
        let owned = |state, owns| {
            let mut i = input(wg(), state);
            i.helper_owns = owns;
            profile_checks(&i)
                .into_iter()
                .find(|c| c.name == "Helper ownership")
                .map(|c| c.level)
        };
        assert_eq!(
            owned(TunnelState::Running, Some(true)),
            Some(DiagnosticLevel::Healthy)
        );
        assert_eq!(
            owned(TunnelState::Running, Some(false)),
            Some(DiagnosticLevel::Error)
        );
        assert_eq!(
            owned(TunnelState::Stopped, Some(true)),
            Some(DiagnosticLevel::Warning)
        );
        assert_eq!(
            owned(TunnelState::Stopped, Some(false)),
            Some(DiagnosticLevel::Healthy)
        );
        assert_eq!(owned(TunnelState::Running, None), None);
    }

    #[test]
    fn roles_are_explained_and_an_empty_secondary_is_an_error() {
        let primary = profile_checks(&input(wg(), TunnelState::Running));
        assert!(find(&primary, "Tunnel role").message.starts_with("primary"));

        let mut secondary = wg();
        secondary.tunnel_role = TunnelRole::Secondary;
        let empty = profile_checks(&input(secondary.clone(), TunnelState::Running));
        assert_eq!(find(&empty, "Tunnel role").level, DiagnosticLevel::Error);

        secondary.tunnel_networks = vec!["10.7.0.0/24".parse().unwrap()];
        let ok = profile_checks(&input(secondary, TunnelState::Running));
        assert!(find(&ok, "Tunnel role").message.contains("10.7.0.0/24"));
    }

    #[test]
    fn dns_and_ipv6_are_judged_only_for_a_running_primary() {
        let mut running = input(xray_tun(), TunnelState::Running);
        running.detail = TunnelDetail {
            dns_applied: Some(false),
            ipv6_covered: Some(false),
            notes: vec!["a note".into()],
        };
        let checks = profile_checks(&running);
        assert_eq!(find(&checks, "Tunnel DNS").level, DiagnosticLevel::Warning);
        assert_eq!(
            find(&checks, "IPv6 coverage").level,
            DiagnosticLevel::Warning
        );
        assert_eq!(find(&checks, "Helper note").message, "a note");

        let mut stopped = running.clone_for_test();
        stopped.status = status(TunnelState::Stopped, None);
        let checks = profile_checks(&stopped);
        assert!(checks.iter().all(|c| !matches!(
            c.name.as_str(),
            "Tunnel DNS" | "IPv6 coverage" | "Helper note"
        )));

        let mut secondary = running.clone_for_test();
        secondary.profile.tunnel_role = TunnelRole::Secondary;
        secondary.profile.tunnel_networks = vec!["10.0.0.0/8".parse().unwrap()];
        let checks = profile_checks(&secondary);
        assert!(checks.iter().all(|c| c.name != "IPv6 coverage"));
    }

    impl ProfileChecksInput {
        fn clone_for_test(&self) -> Self {
            Self {
                profile: self.profile.clone(),
                status: self.status.clone(),
                inspection: self.inspection.clone(),
                inspection_error: self.inspection_error.clone(),
                xray: self.xray.clone(),
                helper: self.helper.clone(),
                helper_owns: self.helper_owns,
                detail: self.detail.clone(),
                protocol_health: self.protocol_health.clone(),
                interfaces: self.interfaces.clone(),
                os_routes: self.os_routes.clone(),
                proxy_owner: self.proxy_owner.clone(),
            }
        }
    }

    #[test]
    fn an_unreadable_configuration_is_the_first_error() {
        let mut broken = input(wg(), TunnelState::Stopped);
        broken.inspection = None;
        broken.inspection_error = Some("bad key".into());
        let checks = profile_checks(&broken);
        assert_eq!(checks[0].name, "Configuration");
        assert_eq!(checks[0].level, DiagnosticLevel::Error);
        assert!(checks[0].message.contains("bad key"));
        assert_eq!(
            find(&checks, "Static analysis").level,
            DiagnosticLevel::Warning
        );
        assert!(checks.iter().all(|c| c.name != "Endpoints"));
    }

    #[test]
    fn a_config_outside_managed_storage_asks_to_be_resaved() {
        let mut unmanaged = input(wg(), TunnelState::Stopped);
        unmanaged.inspection.as_mut().unwrap().managed_config = false;
        let checks = profile_checks(&unmanaged);
        assert_eq!(
            find(&checks, "Configuration").level,
            DiagnosticLevel::Warning
        );
    }

    #[test]
    fn an_endpoint_that_routes_into_a_tunnel_is_flagged() {
        let p = wg();
        let ins = inspection(&[("203.0.113.9", Some(51820))]);
        let via_tunnel = [route("0.0.0.0", 0, "utun4")];
        let flagged = endpoint_path_check(&p, Some(&ins), &via_tunnel, &[]).unwrap();
        assert_eq!(flagged.level, DiagnosticLevel::Warning);
        assert!(flagged.message.contains("203.0.113.9 via utun4"));

        let via_uplink = [route("0.0.0.0", 0, "en0")];
        let fine = endpoint_path_check(&p, Some(&ins), &via_uplink, &[]).unwrap();
        assert_eq!(fine.level, DiagnosticLevel::Healthy);

        // Host names are not resolved here, so there is nothing to check.
        let named = inspection(&[("vpn.example.com", Some(443))]);
        assert!(endpoint_path_check(&p, Some(&named), &via_tunnel, &[]).is_none());
    }

    #[test]
    fn configured_bypass_addresses_count_as_endpoints_once() {
        let mut p = wg();
        p.endpoint_bypasses = vec!["203.0.113.9".into(), " 203.0.113.9 ".into()];
        let ins = inspection(&[("203.0.113.9", None)]);
        let check =
            endpoint_path_check(&p, Some(&ins), &[route("0.0.0.0", 0, "en0")], &[]).unwrap();
        assert!(
            check.message.starts_with("1 endpoint(s)"),
            "{}",
            check.message
        );
    }

    #[test]
    fn static_analysis_counts_warnings_conflicts_and_unknown_routes() {
        assert_eq!(
            static_analysis_check(Some(&inspection(&[]))).level,
            DiagnosticLevel::Healthy
        );
        assert_eq!(static_analysis_check(None).level, DiagnosticLevel::Warning);
        let mut noisy = inspection(&[]);
        noisy.analysis.warnings = vec!["w1".into()];
        noisy.analysis.route_knowledge_complete = false;
        noisy.conflicts = vec![ProfileConflict {
            kind: ConflictKind::RouteOverlap,
            message: "overlaps other".into(),
            other_profile_id: None,
            blocking: false,
        }];
        let check = static_analysis_check(Some(&noisy));
        assert_eq!(check.level, DiagnosticLevel::Warning);
        assert!(check
            .message
            .starts_with("1 warning(s), 1 conflict(s): w1; overlaps other"));
        assert!(check
            .message
            .contains("effective routes are not fully known"));
    }

    #[test]
    fn endpoints_and_listeners_describe_the_config() {
        let ins = inspection(&[("203.0.113.9", Some(51820)), ("host", None)]);
        let xray = Profile {
            backend: TunnelBackend::Xray,
            ..Default::default()
        };
        let checks = config_facts_checks(&xray, &ins);
        assert_eq!(
            find(&checks, "Endpoints").message,
            "2 endpoint(s): 203.0.113.9:51820, host"
        );
        assert_eq!(
            find(&checks, "Listeners").message,
            "listeners: 127.0.0.1:1080"
        );
        // WireGuard has no inbound listeners to report.
        assert!(config_facts_checks(&wg(), &ins)
            .iter()
            .all(|c| c.name != "Listeners"));
        let none = inspection(&[]);
        assert_eq!(
            find(&config_facts_checks(&wg(), &none), "Endpoints").level,
            DiagnosticLevel::Warning
        );
    }

    #[test]
    fn the_system_proxy_check_distinguishes_owner_and_state() {
        let mut p = wg();
        let running = status(TunnelState::Running, None);
        let stopped = status(TunnelState::Stopped, None);
        assert!(system_proxy_check(&p, &running, None).is_none());
        assert_eq!(
            system_proxy_check(&p, &running, Some("wg1")).unwrap().level,
            DiagnosticLevel::Healthy
        );
        let stale = system_proxy_check(&p, &stopped, Some("wg1")).unwrap();
        assert_eq!(stale.level, DiagnosticLevel::Error);
        assert!(stale.message.contains("stale ownership"));
        assert!(system_proxy_check(&p, &running, Some("other"))
            .unwrap()
            .message
            .contains("'other'"));
        p.use_system_proxy = true;
        assert_eq!(
            system_proxy_check(&p, &running, None).unwrap().level,
            DiagnosticLevel::Warning
        );
        p.use_system_proxy = false;
        assert!(system_proxy_check(&p, &running, None).is_none());
    }

    fn wg_status(handshake: Option<u64>, state: TunnelState) -> WireGuardStatusResult {
        WireGuardStatusResult {
            profile_id: "wg1".into(),
            state,
            interface_name: Some("utun5".into()),
            latest_handshake: handshake,
            rx_bytes: 10,
            tx_bytes: 20,
            dns_applied: true,
            warnings: vec![WireGuardWarning::Ipv6NotCovered],
        }
    }

    #[test]
    fn wireguard_health_needs_a_handshake_on_a_running_tunnel() {
        let ok = wireguard_health(&wg_status(Some(1_700_000_000), TunnelState::Running));
        assert_eq!(ok.state, ProtocolHealthState::Healthy);
        assert_eq!((ok.rx_bytes, ok.tx_bytes), (Some(10), Some(20)));
        let waiting = wireguard_health(&wg_status(None, TunnelState::Running));
        assert_eq!(waiting.state, ProtocolHealthState::Unknown);
        assert!(waiting.summary.contains("No WireGuard handshake"));
        let stopped = wireguard_health(&wg_status(Some(5), TunnelState::Stopped));
        assert_eq!(stopped.state, ProtocolHealthState::Unknown);
        let failed = wireguard_health(&wg_status(None, TunnelState::Failed));
        assert_eq!(failed.state, ProtocolHealthState::Failed);
    }

    #[test]
    fn wireguard_warnings_become_notes() {
        let detail = wireguard_detail(&wg_status(None, TunnelState::Running));
        assert_eq!(detail.dns_applied, Some(true));
        assert_eq!(detail.notes.len(), 1);
        assert!(detail.notes[0].contains("IPv6"));
    }

    #[test]
    fn openvpn_health_maps_each_connection_state() {
        let status = |state, warnings: Vec<_>| OpenVpnStatusResult {
            profile_id: "o".into(),
            state,
            interface_name: None,
            rx_bytes: 1,
            tx_bytes: 2,
            applied_routes: vec!["10.0.0.0/8".parse().unwrap()],
            warnings,
            failure_reason: None,
        };
        use crate::daemon_protocol::OpenVpnWarning;
        let level = |s: OpenVpnStatusResult| openvpn_health(&s).state;
        assert_eq!(
            level(status(OpenVpnConnectionState::Connected, vec![])),
            ProtocolHealthState::Healthy
        );
        assert_eq!(
            level(status(
                OpenVpnConnectionState::Connected,
                vec![OpenVpnWarning::DnsNotApplied]
            )),
            ProtocolHealthState::Degraded
        );
        assert_eq!(
            level(status(OpenVpnConnectionState::Reconnecting, vec![])),
            ProtocolHealthState::Degraded
        );
        assert_eq!(
            level(status(OpenVpnConnectionState::Failed, vec![])),
            ProtocolHealthState::Failed
        );
        assert_eq!(
            level(status(OpenVpnConnectionState::Stopped, vec![])),
            ProtocolHealthState::Unknown
        );
        let health = openvpn_health(&status(OpenVpnConnectionState::Connected, vec![]));
        assert_eq!(
            health.pushed_routes[0].destination.to_string(),
            "10.0.0.0/8"
        );
    }

    #[test]
    fn xray_tun_health_tracks_verified_paths_and_stalls() {
        let status = |state| XrayStatusResult {
            profile_id: "x".into(),
            state,
            interface_name: None,
            dns_applied: true,
            ipv4_covered: true,
            ipv6_covered: false,
            rx_bytes: Some(3),
            tx_bytes: None,
            failover: None,
            watchdog: None,
            proxy_exits: Vec::new(),
        };
        assert_eq!(
            xray_tun_health(&status(TunnelState::Running)).state,
            ProtocolHealthState::Unknown
        );
        assert_eq!(
            xray_tun_health(&status(TunnelState::Failed)).state,
            ProtocolHealthState::Failed
        );
        let mut monitored = status(TunnelState::Running);
        monitored.watchdog = Some(crate::models::WatchdogStatus {
            uplink: Some(true),
            https_latency_ms: Some(42),
            ..Default::default()
        });
        assert_eq!(
            xray_tun_health(&monitored).state,
            ProtocolHealthState::Healthy
        );
        monitored.watchdog.as_mut().unwrap().https_stall_streak = 3;
        assert_eq!(
            xray_tun_health(&monitored).state,
            ProtocolHealthState::Degraded
        );
        monitored.watchdog.as_mut().unwrap().https_stall_streak = 0;
        monitored.watchdog.as_mut().unwrap().uplink = Some(false);
        assert_eq!(
            xray_tun_health(&monitored).state,
            ProtocolHealthState::Degraded
        );
        monitored.state = TunnelState::Failed;
        assert_eq!(
            xray_tun_health(&monitored).state,
            ProtocolHealthState::Failed
        );
        monitored.state = TunnelState::Stopped;
        monitored.watchdog.as_mut().unwrap().uplink = Some(true);
        assert_eq!(
            xray_tun_health(&monitored).state,
            ProtocolHealthState::Unknown
        );
        let detail = xray_tun_detail(&status(TunnelState::Running));
        assert_eq!(
            (detail.dns_applied, detail.ipv6_covered),
            (Some(true), Some(false))
        );
        assert_eq!(failed_health("boom").summary, "boom");
    }

    #[test]
    fn protocol_health_adds_the_runtime_log_and_helper_routes_when_present() {
        let mut i = input(wg(), TunnelState::Running);
        i.protocol_health = health(ProtocolHealthState::Degraded, "slow");
        i.protocol_health.log_tail = Some("last line".into());
        i.protocol_health.pushed_routes = vec![AnalyzedRoute {
            destination: "10.1.0.0/16".parse().unwrap(),
            source: "OpenVPN".into(),
            metric: None,
        }];
        let checks = profile_checks(&i);
        assert_eq!(
            find(&checks, "Protocol health").level,
            DiagnosticLevel::Warning
        );
        assert_eq!(find(&checks, "Runtime log").level, DiagnosticLevel::Warning);
        assert!(find(&checks, "Helper routes")
            .message
            .contains("10.1.0.0/16"));
    }
}
