use net_manager_core::models::{AppliedProfileRoutes, AppliedRoute};
use net_manager_core::models::{NetworkInterface, Profile};
use net_manager_core::policy::PolicyManager;
use net_manager_core::route_state::AppliedRouteStore;
use net_manager_core::route_state::{AppliedRouteDocument, APPLIED_ROUTE_DOCUMENT_VERSION};
use std::io;
use std::path::Path;

pub(crate) enum RouteRuntime {
    Local {
        policies: PolicyManager,
        store: AppliedRouteStore,
    },
}

impl RouteRuntime {
    pub(crate) fn new(data_dir: &Path) -> io::Result<Self> {
        let store = AppliedRouteStore::new(data_dir.join("applied-routes.json"));
        let mut policies = PolicyManager::new();
        policies.restore(store.load()?.profiles)?;
        Ok(Self::Local { policies, store })
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

    fn persist(&self) -> Result<(), String> {
        match self {
            Self::Local { policies, store } => store
                .save(&AppliedRouteDocument {
                    version: APPLIED_ROUTE_DOCUMENT_VERSION,
                    profiles: policies.snapshot(),
                })
                .map_err(|e| e.to_string()),
        }
    }

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
        }
    }

    pub(crate) async fn remove_profile(&mut self, id: &str) -> Result<(), String> {
        match self {
            Self::Local { policies, .. } => {
                policies.remove_profile(id).map_err(|e| e.to_string())?;
                self.persist()
            }
        }
    }

    pub(crate) async fn snapshot(&mut self) -> Result<Vec<AppliedProfileRoutes>, String> {
        match self {
            Self::Local { policies, .. } => Ok(policies.snapshot()),
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
