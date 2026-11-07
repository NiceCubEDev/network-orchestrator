use net_manager_core::models::{AppliedProfileRoutes, AppliedRoute};
#[cfg(any(not(target_os = "linux"), test))]
use net_manager_core::models::{NetworkInterface, Profile};
#[cfg(all(target_os = "linux", test))]
use net_manager_core::policy::plan_profile;
use net_manager_core::policy::PolicyManager;
use net_manager_core::route_state::AppliedRouteStore;
#[cfg(any(not(target_os = "linux"), test))]
use net_manager_core::route_state::{AppliedRouteDocument, APPLIED_ROUTE_DOCUMENT_VERSION};
use std::io;
use std::path::Path;

#[cfg(target_os = "linux")]
use crate::daemon_client::{user_message, DaemonClient};
#[cfg(target_os = "linux")]
use net_manager_core::daemon_protocol::{method, OwnedListResult, OwnedResource};
#[cfg(all(target_os = "linux", test))]
use net_manager_core::daemon_protocol::{
    AttachSpecParams, OwnerParams, RoutesApplyParams, RoutesApplyResult, RoutesRemoveResult,
};

#[allow(dead_code)]
pub(crate) enum RouteRuntime {
    Local {
        policies: PolicyManager,
        store: AppliedRouteStore,
    },
    #[cfg(target_os = "linux")]
    Daemon(DaemonClient),
}

/// Owner prefixes the daemon reserves for tunnels; they are never static routes.
#[cfg(target_os = "linux")]
pub(crate) const TUNNEL_OWNER_PREFIXES: [&str; 4] = ["wg:", "ovpn:", "ovpn-probe:", "xray:"];

/// Owner namespaces the daemon manages itself — routing intents, conditional
/// rules and manual edits are journaled policies, not profiles, so the
/// recovery report must never flag them as orphans.
#[cfg(target_os = "linux")]
pub(crate) fn daemon_managed_owner(owner: &str) -> bool {
    owner == "manual" || owner.starts_with("intent:") || owner.starts_with("cond:")
}

#[cfg(target_os = "linux")]
pub(crate) fn static_route_snapshot(result: OwnedListResult) -> Vec<AppliedProfileRoutes> {
    result
        .owners
        .into_iter()
        .filter(|entry| {
            !daemon_managed_owner(&entry.owner)
                && !TUNNEL_OWNER_PREFIXES
                    .iter()
                    .any(|prefix| entry.owner.starts_with(prefix))
                && !entry.resources.iter().any(|resource| {
                    matches!(
                        resource,
                        OwnedResource::WireGuardLink(_)
                            | OwnedResource::OpenVpnProcess(_)
                            | OwnedResource::Address(_)
                    )
                })
        })
        .map(|entry| AppliedProfileRoutes {
            profile_id: entry.owner,
            routes: entry
                .resources
                .into_iter()
                .filter_map(|resource| match resource {
                    OwnedResource::Route(route) => Some(route),
                    _ => None,
                })
                .collect(),
        })
        .collect()
}

impl RouteRuntime {
    pub(crate) fn new(data_dir: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let _ = data_dir;
            Ok(Self::Daemon(DaemonClient::system()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let store = AppliedRouteStore::new(data_dir.join("applied-routes.json"));
            let mut policies = PolicyManager::new();
            policies.restore(store.load()?.profiles)?;
            Ok(Self::Local { policies, store })
        }
    }

    #[cfg(test)]
    pub(crate) fn local_with_executor(
        data_dir: &Path,
        executor: Box<dyn net_manager_core::policy::RouteExecutor>,
    ) -> Self {
        Self::Local {
            policies: PolicyManager::with_executor(executor),
            store: AppliedRouteStore::new(data_dir.join("applied-routes.json")),
        }
    }

    #[cfg(any(not(target_os = "linux"), test))]
    fn persist(&self) -> Result<(), String> {
        match self {
            Self::Local { policies, store } => store
                .save(&AppliedRouteDocument {
                    version: APPLIED_ROUTE_DOCUMENT_VERSION,
                    profiles: policies.snapshot(),
                })
                .map_err(|e| e.to_string()),
            #[cfg(target_os = "linux")]
            Self::Daemon(_) => Ok(()),
        }
    }

    #[cfg(any(not(target_os = "linux"), test))]
    pub(crate) async fn apply_profile(
        &mut self,
        profile: &Profile,
        interfaces: &[NetworkInterface],
    ) -> Result<Vec<AppliedRoute>, String> {
        match self {
            Self::Local { policies, .. } => {
                let routes = policies
                    .apply_profile(profile, interfaces)
                    .map_err(|e| e.to_string())?;
                if let Err(err) = self.persist() {
                    let cleanup = self.remove_profile(&profile.id).await;
                    return Err(match cleanup { Ok(()) => format!("failed to persist applied routes: {err}"), Err(cleanup) => format!("failed to persist applied routes: {err}; route rollback failed: {cleanup}") });
                }
                Ok(routes)
            }
            #[cfg(target_os = "linux")]
            Self::Daemon(client) => {
                let plan = plan_profile(profile, interfaces).map_err(|e| e.to_string())?;
                let mut routes = plan.routes.clone();
                routes.extend(plan.bypasses.iter().cloned());
                // Deferred binding or endpoint bypasses arm a daemon-side
                // spec: reconcile re-derives routes from the interface name
                // and the live uplink instead of trusting one ifindex.
                let attach = ((profile.wait_for_interface && !profile.interface_name.is_empty())
                    || !profile.endpoint_bypasses.is_empty())
                .then(|| AttachSpecParams {
                    interface_name: profile.interface_name.clone(),
                    routes: profile.routes.clone(),
                    endpoint_bypasses: profile.endpoint_bypasses.clone(),
                    uplink: false,
                });
                let _: RoutesApplyResult = client
                    .request(
                        method::ROUTES_APPLY,
                        RoutesApplyParams {
                            owner: profile.id.clone(),
                            routes: routes.clone(),
                            attach,
                        },
                    )
                    .await
                    .map_err(|e| user_message(&e))?;
                Ok(routes)
            }
        }
    }

    #[cfg(any(not(target_os = "linux"), test))]
    pub(crate) async fn remove_profile(&mut self, id: &str) -> Result<(), String> {
        match self {
            Self::Local { policies, .. } => {
                policies.remove_profile(id).map_err(|e| e.to_string())?;
                self.persist()
            }
            #[cfg(target_os = "linux")]
            Self::Daemon(client) => {
                let _: RoutesRemoveResult = client
                    .request(method::ROUTES_REMOVE, OwnerParams { owner: id.into() })
                    .await
                    .map_err(|e| user_message(&e))?;
                Ok(())
            }
        }
    }

    pub(crate) async fn snapshot(&mut self) -> Result<Vec<AppliedProfileRoutes>, String> {
        match self {
            Self::Local { policies, .. } => Ok(policies.snapshot()),
            #[cfg(target_os = "linux")]
            Self::Daemon(client) => {
                let result: OwnedListResult = client
                    .request(method::OWNED_LIST, serde_json::Value::Null)
                    .await
                    .map_err(|e| user_message(&e))?;
                Ok(static_route_snapshot(result))
            }
        }
    }

    pub(crate) async fn has_applied(&mut self, id: &str) -> Result<bool, String> {
        Ok(self
            .snapshot()
            .await?
            .iter()
            .any(|item| item.profile_id == id))
    }

    pub(crate) async fn applied_for(&mut self, id: &str) -> Result<Vec<AppliedRoute>, String> {
        Ok(self
            .snapshot()
            .await?
            .into_iter()
            .find(|item| item.profile_id == id)
            .map(|item| item.routes)
            .unwrap_or_default())
    }

    #[cfg(any(not(target_os = "linux"), test))]
    pub(crate) async fn applied_profile_ids(&mut self) -> Result<Vec<String>, String> {
        Ok(self
            .snapshot()
            .await?
            .into_iter()
            .map(|item| item.profile_id)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use net_manager_core::models::{InterfaceState, PolicyRoute};

    #[cfg(target_os = "linux")]
    #[test]
    fn wireguard_owned_resources_are_not_static_route_owners() {
        use net_manager_core::daemon_protocol::{
            OwnedEntry, OwnedResource, OwnedState, WireGuardLinkResource,
        };
        let snapshot = static_route_snapshot(OwnedListResult {
            owners: vec![
                OwnedEntry {
                    owner: "wg-p1".into(),
                    state: OwnedState::Applied,
                    resources: vec![OwnedResource::WireGuardLink(WireGuardLinkResource {
                        name: "wg-p1".into(),
                        index: 5,
                        owner_marker: "fixture".into(),
                        warnings: Vec::new(),
                        full: None,
                    })],
                },
                OwnedEntry {
                    owner: "wg:p1".into(),
                    state: OwnedState::Applying,
                    resources: Vec::new(),
                },
                OwnedEntry {
                    owner: "ovpn:p1".into(),
                    state: OwnedState::Applying,
                    resources: Vec::new(),
                },
            ],
        });
        assert!(snapshot.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_tunnel_owner_prefixes_are_not_static_route_owners() {
        use net_manager_core::daemon_protocol::{OwnedEntry, OwnedResource, OwnedState};
        let route = OwnedResource::Route(AppliedRoute {
            destination: "10.9.0.0/24".parse().unwrap(),
            interface_index: 5,
            metric: 5,
            gateway: None,
            table: None,
        });
        let entry = |owner: &str| OwnedEntry {
            owner: owner.into(),
            state: OwnedState::Applied,
            resources: vec![route.clone()],
        };
        let snapshot = static_route_snapshot(OwnedListResult {
            owners: vec![
                entry("xray:p1"),
                entry("ovpn-probe:p1"),
                entry("wg:p1"),
                entry("ovpn:p1"),
                entry("static"),
            ],
        });
        let owners: Vec<_> = snapshot
            .iter()
            .map(|item| item.profile_id.as_str())
            .collect();
        assert_eq!(owners, ["static"]);
    }

    #[tokio::test]
    async fn local_runtime_persists_applied_routes() {
        let dir = unique_dir("route-runtime");
        let mut routes = RouteRuntime::local_with_executor(&dir, Box::new(NoopExecutor));
        let mut p = profile("if0");
        p.routes.push(PolicyRoute {
            destination: "10.5.0.0/24".parse().unwrap(),
            metric: 5,
            via: None,
        });
        routes
            .apply_profile(&p, &[iface("if0", "if0", InterfaceState::Up)])
            .await
            .unwrap();
        assert!(routes.has_applied(&p.id).await.unwrap());
        assert_eq!(routes.snapshot().await.unwrap()[0].routes.len(), 1);
        routes.remove_profile(&p.id).await.unwrap();
        assert!(!routes.has_applied(&p.id).await.unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
