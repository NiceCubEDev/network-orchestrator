use crate::commands::diagnostics::applied_route_present;
#[cfg(not(target_os = "linux"))]
use crate::lifecycle::cleanup_all;
use crate::state::AppState;
use net_manager_core::explorer;
use net_manager_core::models::*;
use net_manager_core::system_proxy::ProxyOwnership;
use tauri::{Emitter, State};

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
fn linux_leftover_owners(
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
            if crate::route_runtime::daemon_managed_owner(&entry.owner) {
                return false;
            }
            let tunnel = crate::route_runtime::TUNNEL_OWNER_PREFIXES
                .iter()
                .any(|prefix| entry.owner.starts_with(prefix));
            entry.state != OwnedState::Applied
                || (!tunnel
                    && (!profiles.iter().any(|p| p.id == entry.owner)
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
        if let Some(owner) = crate::auto_connect::daemon_owner(profile) {
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
fn cleanup_request(owner: &str) -> Option<(&'static str, serde_json::Value)> {
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

pub(crate) fn build_recovery_report(
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

async fn collect_report(state: &AppState) -> Result<RecoveryReport, String> {
    collect(state).await.map(|(report, _)| report)
}

/// The recovery report plus, on Linux, the daemon owners that are leftovers.
async fn collect(state: &AppState) -> Result<(RecoveryReport, Vec<String>), String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let os_routes = explorer::list_routes().await.map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    let mut statuses: Vec<(String, Result<TunnelStatus, String>)> =
        Vec::with_capacity(profiles.len());
    #[cfg(target_os = "linux")]
    let client = crate::daemon_client::DaemonClient::system();
    #[cfg(target_os = "linux")]
    for profile in &profiles {
        if daemon_owned_profile(profile) {
            let result = if profile.backend == TunnelBackend::WireGuard {
                crate::commands::tunnels::linux_wireguard_status(&client, profile).await
            } else if profile.backend == TunnelBackend::OpenVpn {
                crate::commands::tunnels::linux_openvpn_status(&client, profile).await
            } else {
                crate::commands::tunnels::linux_xray_status(&client, profile).await
            };
            statuses.push((profile.id.clone(), result));
        }
    }
    let mut runtime = state.runtime.lock().await;
    #[cfg(not(target_os = "linux"))]
    let statuses: Vec<(String, TunnelStatus)> = profiles
        .iter()
        .map(|p| (p.id.clone(), runtime.tunnels.status(p)))
        .collect();
    #[cfg(target_os = "linux")]
    statuses.extend(
        profiles
            .iter()
            .filter(|p| !daemon_owned_profile(p))
            .map(|p| (p.id.clone(), Ok(runtime.tunnels.status(p)))),
    );
    #[cfg(not(target_os = "linux"))]
    let (ownership, leftovers) = (runtime.routes.snapshot().await?, Vec::new());
    let proxy_ownership = runtime.proxy.ownership().cloned();
    drop(runtime);
    #[cfg(target_os = "linux")]
    let (ownership, leftovers) = {
        use net_manager_core::daemon_protocol::{method, OwnedListResult};

        let mut owned: OwnedListResult = client
            .request(method::OWNED_LIST, serde_json::Value::Null)
            .await
            .map_err(|e| crate::daemon_client::user_message(&e))?;
        let leftovers = linux_leftover_owners(&owned.owners, &profiles, &statuses, &os_routes);
        owned
            .owners
            .retain(|entry| leftovers.contains(&entry.owner));
        (
            crate::route_runtime::static_route_snapshot(owned),
            leftovers,
        )
    };
    #[cfg(target_os = "linux")]
    let statuses: Vec<_> = statuses
        .into_iter()
        .map(|(profile_id, result)| {
            let status = result.unwrap_or_else(|err| TunnelStatus {
                profile_id: profile_id.clone(),
                state: TunnelState::Failed,
                message: Some(err),
                interface_name: None,
                failover: None,
                watchdog: None,
            });
            (profile_id, status)
        })
        .collect();
    Ok((
        build_recovery_report(
            &profiles,
            &statuses,
            &ownership,
            &os_routes,
            proxy_ownership.as_ref(),
        ),
        leftovers,
    ))
}

#[tauri::command]
pub(crate) async fn get_recovery_report(
    state: State<'_, AppState>,
) -> Result<RecoveryReport, String> {
    collect_report(&state).await
}

#[tauri::command]
pub(crate) async fn cleanup_recovery(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<RecoveryReport, String> {
    // Linux: remove only leftover daemon owners; healthy tunnels, static
    // routes and always-on state stay untouched.
    #[cfg(target_os = "linux")]
    {
        let (_, leftovers) = collect(&state).await?;
        let client = crate::daemon_client::DaemonClient::system();
        let mut failed = 0;
        for (method, params) in leftovers.iter().filter_map(|owner| cleanup_request(owner)) {
            if client
                .request::<_, serde_json::Value>(method, params)
                .await
                .is_err()
            {
                failed += 1;
            }
        }
        let _ = app.emit("route-changed", ());
        if failed > 0 {
            return Err(format!("daemon could not clean up {failed} owner(s)"));
        }
        if !leftovers.is_empty() {
            crate::commands::logs::record_log(
                &state,
                crate::commands::logs::LogLevel::Warn,
                format!(
                    "recovery cleanup removed {} leftover owner(s)",
                    leftovers.len()
                ),
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        cleanup_all(&state).await?;
        let _ = app.emit("route-changed", ());
    }
    collect_report(&state).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    fn owned(profile_id: &str, dest: &str, if_index: u32) -> AppliedProfileRoutes {
        AppliedProfileRoutes {
            profile_id: profile_id.into(),
            routes: vec![AppliedRoute {
                destination: dest.parse().unwrap(),
                interface_index: if_index,
                metric: 10,
                gateway: None,
                table: None,
            }],
        }
    }

    fn status(profile_id: &str, state: TunnelState) -> (String, TunnelStatus) {
        (
            profile_id.to_string(),
            TunnelStatus {
                profile_id: profile_id.into(),
                state,
                message: None,
                interface_name: None,
                watchdog: None,
                failover: None,
            },
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn running_linux_wireguard_reports_active_link() {
        let profiles = vec![profile("wg-work")];
        let report = build_recovery_report(
            &profiles,
            &[status("p1", TunnelState::Running)],
            &[],
            &[],
            None,
        );
        assert!(report.issues.is_empty());
        assert!(!report.requires_elevation);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn running_linux_openvpn_is_not_a_recovery_issue() {
        let mut p = profile("ovpn-work");
        p.backend = TunnelBackend::OpenVpn;
        let report =
            build_recovery_report(&[p], &[status("p1", TunnelState::Running)], &[], &[], None);
        assert!(report.issues.is_empty());
        assert!(!report.requires_elevation);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_linux_openvpn_status_is_recovery_issue() {
        let mut p = profile("ovpn-work");
        p.backend = TunnelBackend::OpenVpn;
        let mut failed = status("p1", TunnelState::Failed);
        failed.1.message = Some("daemon unavailable".into());
        let report = build_recovery_report(&[p], &[failed], &[], &[], None);
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::StatusCheckFailed);
        assert!(report.issues[0].message.contains("daemon unavailable"));
    }

    #[test]
    fn running_wireguard_and_owned_routes_produce_two_issues() {
        let profiles = vec![profile("wg-work")];
        let statuses = vec![status("p1", TunnelState::Running)];
        let ownership = vec![owned("p1", "10.1.0.0/24", 5)];
        let os_routes = vec![route_entry("10.1.0.0", 24, 5, 99)];

        let report = build_recovery_report(&profiles, &statuses, &ownership, &os_routes, None);

        assert!(report.requires_elevation);
        #[cfg(target_os = "linux")]
        assert_eq!(report.issues.len(), 1);
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(report.issues.len(), 2);
            assert_eq!(
                report.issues[0].kind,
                RecoveryIssueKind::SurvivingWireGuardService
            );
        }
        assert_eq!(
            report.issues.last().unwrap().kind,
            RecoveryIssueKind::OwnedRoutes
        );
        assert_eq!(
            report.issues.last().unwrap().profile_id.as_deref(),
            Some("p1")
        );
    }

    #[test]
    fn missing_owned_route_produces_missing_issue() {
        let profiles = vec![profile("wg-work")];
        let statuses = vec![status("p1", TunnelState::Stopped)];
        let ownership = vec![owned("p1", "10.1.0.0/24", 5)];

        let report = build_recovery_report(&profiles, &statuses, &ownership, &[], None);

        assert!(report.requires_elevation);
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::MissingOwnedRoutes);
        assert!(report.issues[0].message.contains("10.1.0.0/24"));
    }

    #[test]
    fn ownership_without_profile_produces_orphan_issue() {
        let profiles = vec![profile("wg-work")];
        let statuses = vec![status("p1", TunnelState::Stopped)];
        let ownership = vec![owned("gone", "10.1.0.0/24", 5)];
        let os_routes = vec![route_entry("10.1.0.0", 24, 5, 10)];

        let report = build_recovery_report(&profiles, &statuses, &ownership, &os_routes, None);

        assert_eq!(report.issues.len(), 1);
        assert_eq!(
            report.issues[0].kind,
            RecoveryIssueKind::OrphanRouteOwnership
        );
        assert_eq!(report.issues[0].profile_id.as_deref(), Some("gone"));
    }

    #[test]
    fn stopped_profiles_without_ownership_produce_empty_report() {
        let profiles = vec![profile("wg-work")];
        let statuses = vec![status("p1", TunnelState::Stopped)];

        let report = build_recovery_report(&profiles, &statuses, &[], &[], None);

        assert!(report.issues.is_empty());
        assert!(!report.requires_elevation);
    }

    #[test]
    fn failed_wireguard_status_produces_status_check_failed() {
        let profiles = vec![profile("wg-work")];
        let mut failed = status("p1", TunnelState::Failed);
        failed.1.message = Some("service query failed".into());

        let report = build_recovery_report(&profiles, &[failed], &[], &[], None);

        assert!(report.requires_elevation);
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::StatusCheckFailed);
        assert!(report.issues[0].message.contains("service query failed"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_xray_tun_daemon_status_is_a_recovery_issue() {
        let mut p = profile("xray");
        p.backend = TunnelBackend::Xray;
        p.xray_mode = XrayMode::Tun;
        let mut failed = status(&p.id, TunnelState::Failed);
        failed.1.message = Some("daemon status unavailable".into());
        let report = build_recovery_report(&[p], &[failed], &[], &[], None);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.kind == RecoveryIssueKind::StatusCheckFailed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_leftovers_skip_healthy_owners() {
        use net_manager_core::daemon_protocol::{OwnedEntry, OwnedResource, OwnedState};

        let with_id = |id: &str, backend: TunnelBackend| {
            let mut p = profile("if0");
            p.id = id.into();
            p.backend = backend;
            p
        };
        let mut xray = with_id("xray-failed", TunnelBackend::Xray);
        xray.xray_mode = XrayMode::Tun;
        let profiles = vec![
            with_id("static-ok", TunnelBackend::None),
            with_id("static-stale", TunnelBackend::None),
            with_id("static-missing", TunnelBackend::None),
            with_id("wg-ok", TunnelBackend::WireGuard),
            with_id("wg-applying", TunnelBackend::WireGuard),
            with_id("ovpn-failed", TunnelBackend::OpenVpn),
            xray,
        ];
        let route = |dest: &str| {
            OwnedResource::Route(AppliedRoute {
                destination: dest.parse().unwrap(),
                interface_index: 5,
                metric: 10,
                gateway: None,
                table: None,
            })
        };
        let entry = |owner: &str, state: OwnedState, resources: Vec<OwnedResource>| OwnedEntry {
            owner: owner.into(),
            state,
            resources,
        };
        let entries = vec![
            entry("static-ok", OwnedState::Applied, vec![route("10.1.0.0/24")]),
            entry(
                "static-stale",
                OwnedState::Stale,
                vec![route("10.1.0.0/24")],
            ),
            entry("gone", OwnedState::Applied, vec![route("10.1.0.0/24")]),
            entry(
                "static-missing",
                OwnedState::Applied,
                vec![route("10.2.0.0/24")],
            ),
            entry("wg:wg-ok", OwnedState::Applied, Vec::new()),
            entry("wg:wg-applying", OwnedState::Applying, Vec::new()),
            entry("ovpn:ovpn-failed", OwnedState::Applied, Vec::new()),
            entry("ovpn-probe:ovpn-failed", OwnedState::Stale, Vec::new()),
        ];
        let statuses = vec![
            status("wg-ok", TunnelState::Running),
            status("wg-applying", TunnelState::Running),
            status("ovpn-failed", TunnelState::Failed),
            status("xray-failed", TunnelState::Failed),
        ]
        .into_iter()
        .map(|(profile_id, status)| (profile_id, Ok(status)))
        .collect::<Vec<_>>();
        let os_routes = vec![route_entry("10.1.0.0", 24, 5, 10)];

        let leftovers = linux_leftover_owners(&entries, &profiles, &statuses, &os_routes);

        assert_eq!(
            leftovers,
            [
                "ovpn-probe:ovpn-failed",
                "wg:wg-applying",
                "static-missing",
                "gone",
                "static-stale",
                "ovpn:ovpn-failed",
                "xray:xray-failed",
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_managed_owners_are_never_leftovers() {
        use net_manager_core::daemon_protocol::{OwnedEntry, OwnedResource, OwnedState};

        let route = || {
            OwnedResource::Route(AppliedRoute {
                destination: "10.99.0.0/16".parse().unwrap(),
                interface_index: 5,
                metric: 10,
                gateway: None,
                table: None,
            })
        };
        let entry = |owner: &str, state: OwnedState| OwnedEntry {
            owner: owner.into(),
            state,
            resources: vec![route()],
        };
        let entries = vec![
            // A deferred intent spec is re-armed by the daemon — it is
            // policy, not a lost profile, whatever its journal state is.
            entry("intent:office", OwnedState::Applying),
            entry("intent:active", OwnedState::Applied),
            entry("cond:lan", OwnedState::Applied),
            entry("manual", OwnedState::Applied),
        ];

        let leftovers = linux_leftover_owners(&entries, &[], &[], &[]);

        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn status_rpc_error_does_not_offer_applied_tunnel_for_cleanup() {
        use net_manager_core::daemon_protocol::{OwnedEntry, OwnedState};

        let mut p = profile("wg-work");
        p.id = "home".into();
        let entry = OwnedEntry {
            owner: "wg:home".into(),
            state: OwnedState::Applied,
            resources: Vec::new(),
        };
        let rpc_error = ("home".into(), Err("daemon response timed out".into()));

        assert!(linux_leftover_owners(&[entry], &[p], &[rpc_error], &[]).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_cleanup_uses_the_owner_specific_daemon_method() {
        use net_manager_core::daemon_protocol::method;
        use serde_json::json;

        assert_eq!(
            cleanup_request("wg:home"),
            Some((method::WIREGUARD_DISCONNECT, json!({"profileId": "home"})))
        );
        assert_eq!(
            cleanup_request("ovpn:office"),
            Some((method::OPENVPN_DISCONNECT, json!({"profileId": "office"})))
        );
        assert_eq!(
            cleanup_request("xray:proxy"),
            Some((method::XRAY_DISCONNECT, json!({"profileId": "proxy"})))
        );
        assert_eq!(
            cleanup_request("static"),
            Some((method::ROUTES_REMOVE, json!({"owner": "static"})))
        );
        assert_eq!(cleanup_request("ovpn-probe:office"), None);
    }

    #[test]
    fn proxy_ownership_produces_cleanup_issue() {
        let ownership = ProxyOwnership {
            profile_id: "stale".into(),
            snapshot: net_manager_core::system_proxy::ProxySnapshot::default(),
            applied_server: "socks=127.0.0.1:10808".into(),
            applied_override: "<local>".into(),
        };

        let report = build_recovery_report(&[], &[], &[], &[], Some(&ownership));

        assert!(report.requires_elevation);
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::ProxyOwnership);
        assert_eq!(report.issues[0].profile_id.as_deref(), Some("stale"));
        assert!(report.issues[0].message.contains("stale"));
    }
}
