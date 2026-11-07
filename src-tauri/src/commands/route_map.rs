use crate::state::AppState;
use net_manager_core::explorer;
use net_manager_core::models::{
    PlannedRoute, Profile, RouteMap, TunnelBackend, TunnelState, TunnelStatus,
};
use net_manager_core::route_plan::build_route_map;
use std::collections::HashMap;
use tauri::State;

/// Pair each profile with its live running flag, and when a daemon-managed
/// tunnel reports its real interface name, copy it onto the cloned profile so
/// planned routes match effective kernel routes by interface instead of
/// producing phantom `InterfaceMismatch` diffs.
pub(crate) fn select_route_profiles(
    profiles: &[Profile],
    statuses: &[TunnelStatus],
    include_inactive: bool,
) -> Vec<(Profile, bool)> {
    let by_id: HashMap<&str, &TunnelStatus> = statuses
        .iter()
        .map(|status| (status.profile_id.as_str(), status))
        .collect();
    profiles
        .iter()
        .map(|profile| {
            let status = by_id.get(profile.id.as_str()).copied();
            let mut profile = profile.clone();
            let active = status
                .map(|status| status.state == TunnelState::Running)
                .unwrap_or(false);
            if active {
                if let Some(name) = status
                    .and_then(|status| status.interface_name.as_deref())
                    .filter(|name| !name.is_empty())
                {
                    profile.interface_name = name.to_string();
                }
            }
            (profile, active)
        })
        .filter(|(_, active)| include_inactive || *active)
        .collect()
}

#[tauri::command]
pub(crate) async fn get_route_map(
    include_inactive: bool,
    state: State<'_, AppState>,
) -> Result<RouteMap, String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;

    let statuses = super::tunnels::collect_tunnel_statuses(state.inner(), &profiles).await?;
    let running: HashMap<String, bool> = statuses
        .iter()
        .map(|status| {
            (
                status.profile_id.clone(),
                status.state == TunnelState::Running,
            )
        })
        .collect();

    let mut pushed_routes = Vec::new();
    {
        let runtime = state.runtime.lock().await;
        for profile in &profiles {
            if running.get(&profile.id).copied().unwrap_or(false)
                && profile.backend == TunnelBackend::OpenVpn
            {
                for route in runtime.tunnels.openvpn_pushed_routes(&profile.id) {
                    pushed_routes.push(PlannedRoute {
                        destination: route.destination,
                        owner_profile_id: profile.id.clone(),
                        owner_name: profile.name.clone(),
                        source: route.source,
                        interface_name: None,
                        metric: route.metric,
                        active: true,
                    });
                }
            }
        }
    }

    let selected = select_route_profiles(&profiles, &statuses, include_inactive);
    let effective = explorer::list_routes().await.map_err(|e| e.to_string())?;
    let mut map = build_route_map(&selected, &effective);
    map.pushed_routes = pushed_routes;
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::profile;

    fn status(id: &str, state: TunnelState, interface_name: Option<&str>) -> TunnelStatus {
        TunnelStatus {
            profile_id: id.into(),
            state,
            message: None,
            interface_name: interface_name.map(Into::into),
            failover: None,
            watchdog: None,
        }
    }

    #[test]
    fn select_route_profiles_omits_stopped_unless_requested() {
        let mut a = profile("wg-a");
        a.id = "pa".into();
        let mut b = profile("wg-b");
        b.id = "pb".into();
        let profiles = vec![a.clone(), b.clone()];
        let statuses = vec![
            status("pa", TunnelState::Running, None),
            status("pb", TunnelState::Stopped, None),
        ];

        let active_only = select_route_profiles(&profiles, &statuses, false);
        assert_eq!(active_only.len(), 1);
        assert_eq!(active_only[0].0.id, a.id);
        assert!(active_only[0].1);

        let all = select_route_profiles(&profiles, &statuses, true);
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|(p, active)| p.id == b.id && !*active));
    }

    #[test]
    fn select_route_profiles_uses_daemon_interface_name() {
        let mut wg = profile("wg-kzn2");
        wg.id = "pw".into();
        wg.interface_name.clear();
        let profiles = vec![wg];
        let statuses = vec![status("pw", TunnelState::Running, Some("wg-kzn2"))];

        let selected = select_route_profiles(&profiles, &statuses, true);
        assert!(selected[0].1);
        assert_eq!(selected[0].0.interface_name, "wg-kzn2");
    }

    #[test]
    fn select_route_profiles_ignores_interface_name_when_stopped() {
        let mut wg = profile("wg-kzn2");
        wg.id = "pw".into();
        wg.interface_name.clear();
        let profiles = vec![wg];
        let statuses = vec![status("pw", TunnelState::Stopped, Some("wg-old"))];

        let selected = select_route_profiles(&profiles, &statuses, true);
        assert!(!selected[0].1);
        assert!(selected[0].0.interface_name.is_empty());
    }
}
