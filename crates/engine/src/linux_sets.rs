//! Linux connection-set reconciliation over the shared protected Core store.
use crate::{linux::CredentialSource, linux_engine::LinuxEngine, linux_runtime};
use net_manager_core::{
    connection_sets::{
        get, lock_lifecycle, put, valid_id, validate, validate_members, ConnectionSet,
        CredentialInputs,
    },
    models::*,
    profiles::{validate_profile, ProfileStore},
};
use serde::Serialize;
use std::{collections::HashSet, path::Path};

fn preflight(set: &ConnectionSet, profiles: &[Profile], starting: bool) -> Result<(), String> {
    validate(set)?;
    validate_members(set, profiles)?;
    let mut primaries = 0;
    for id in &set.profile_ids {
        let profile = profiles
            .iter()
            .find(|p| &p.id == id)
            .ok_or("Missing connection-set member")?;
        validate_profile(profile).map_err(|e| format!("Invalid member {id}: {e}"))?;
        profile
            .check_role()
            .map_err(|e| format!("Invalid member {id}: {e}"))?;
        if profile.tunnel_role == TunnelRole::Primary
            && matches!(
                profile.backend,
                TunnelBackend::WireGuard | TunnelBackend::OpenVpn
            )
            || profile.tunnel_role == TunnelRole::Primary
                && profile.backend == TunnelBackend::Xray
                && profile.xray_mode == XrayMode::Tun
        {
            primaries += 1;
        }
    }
    if starting && primaries > 1 {
        return Err("A connection set cannot start multiple primary tunnels".into());
    }
    Ok(())
}

pub fn capture(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
    id: String,
    name: String,
) -> Result<ConnectionSet, String> {
    let mut set = ConnectionSet {
        id,
        name,
        profile_ids: Vec::new(),
    };
    validate(&set)?;
    for profile in store.load().map_err(|_| "Cannot load profiles")?.profiles {
        if engine.status(&profile)?.state == TunnelState::Running {
            set.profile_ids.push(profile.id);
        }
    }
    put(root, store, set)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetApplyResult {
    pub set_id: String,
    pub outcomes: Vec<SetProfileOutcome>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetProfileOutcome {
    pub profile_id: String,
    pub action: SetAction,
    pub status: Option<TunnelStatus>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SetAction {
    Connect,
    Disconnect,
    Unchanged,
}

pub fn apply(
    context: &linux_runtime::Context<'_>,
    id: &str,
    remembered: &dyn CredentialSource,
    inputs: &CredentialInputs,
    credential_store: Option<&crate::linux_credentials::OpenVpnCredentialStore>,
) -> Result<SetApplyResult, String> {
    let set = get(context.root, id)?;
    reconcile(context, &set, remembered, inputs, credential_store, false)
}

pub fn down(context: &linux_runtime::Context<'_>, id: &str) -> Result<SetApplyResult, String> {
    let set = get(context.root, id)?;
    reconcile(context, &set, &(), &CredentialInputs::new(), None, true)
}

fn reconcile(
    context: &linux_runtime::Context<'_>,
    set: &ConnectionSet,
    remembered: &dyn CredentialSource,
    inputs: &CredentialInputs,
    credential_store: Option<&crate::linux_credentials::OpenVpnCredentialStore>,
    down: bool,
) -> Result<SetApplyResult, String> {
    let linux_runtime::Context {
        engine,
        root,
        store,
        ..
    } = *context;
    let profiles = store.load().map_err(|_| "Cannot load profiles")?.profiles;
    preflight(set, &profiles, !down)?;
    if inputs.len() > 256 {
        return Err("Too many connection-set credential inputs".into());
    }
    for (id, input) in inputs {
        if !valid_id(id)
            || !profiles
                .iter()
                .any(|profile| profile.id == *id && profile.backend == TunnelBackend::OpenVpn)
        {
            return Err("Connection-set credentials must reference saved OpenVPN profiles".into());
        }
        net_manager_core::openvpn_management::validate_openvpn_credentials(&input.credentials)
            .map_err(|_| "Invalid connection-set credentials")?;
    }
    let _operation = lock_lifecycle(root)?;
    let enrolled: HashSet<String> = if profiles
        .iter()
        .any(|p| matches!(p.backend, TunnelBackend::WireGuard | TunnelBackend::None))
    {
        crate::linux_services::always_on_list(engine)?
            .profiles
            .into_iter()
            .map(|item| item.profile_id)
            .collect()
    } else {
        HashSet::new()
    };
    let mut starts = Vec::new();
    let mut stops = Vec::new();
    let mut failed_stops = Vec::new();
    let mut result = SetApplyResult {
        set_id: set.id.clone(),
        outcomes: Vec::new(),
    };
    for profile in &profiles {
        let member = set.profile_ids.contains(&profile.id);
        if down && !member {
            continue;
        }
        let status = engine.status(profile)?;
        let running = status.state == TunnelState::Running;
        if enrolled.contains(&profile.id) {
            if member && (down || !running) {
                return Err(format!(
                    "Member {} is always-on; manage its enrollment separately",
                    profile.id
                ));
            }
            if member {
                result.outcomes.push(SetProfileOutcome {
                    profile_id: profile.id.clone(),
                    action: SetAction::Unchanged,
                    status: Some(status),
                    error: None,
                });
            }
            continue;
        }
        if status.state == TunnelState::Failed {
            failed_stops.push(profile);
            if !down && member {
                starts.push(profile);
            }
        } else if running && ((!down && !member) || (down && member)) {
            stops.push(profile);
        } else if !down && member && !running {
            starts.push(profile);
        } else if member {
            result.outcomes.push(SetProfileOutcome {
                profile_id: profile.id.clone(),
                action: SetAction::Unchanged,
                status: Some(status),
                error: None,
            });
        }
    }
    if down {
        let mut failures = Vec::new();
        for profile in stops.into_iter().chain(failed_stops) {
            let outcome = engine.disconnect(profile);
            linux_runtime::record_lifecycle(root, "disconnect", &profile.id, &outcome);
            match outcome {
                Ok(status) => result.outcomes.push(SetProfileOutcome {
                    profile_id: profile.id.clone(),
                    action: SetAction::Disconnect,
                    status: Some(status),
                    error: None,
                }),
                Err(error) => {
                    failures.push(format!("{}: {error}", profile.id));
                    result.outcomes.push(SetProfileOutcome {
                        profile_id: profile.id.clone(),
                        action: SetAction::Disconnect,
                        status: None,
                        error: Some(error),
                    });
                }
            }
        }
        if !failures.is_empty() {
            let outcomes = serde_json::to_string(&result)
                .map_err(|_| "Cannot encode connection-set outcomes")?;
            return Err(format!(
                "Connection-set teardown partially failed: {}; outcomes: {outcomes}",
                failures.join("; ")
            ));
        }
        return Ok(result);
    }
    for profile in stops.iter().chain(failed_stops.iter()).chain(starts.iter()) {
        validate_profile(profile).map_err(|e| format!("Invalid member {}: {e}", profile.id))?;
        profile.check_role()?;
    }
    starts.sort_by_key(|p| p.tunnel_role != TunnelRole::Primary);
    let prepare = |profile: &Profile, restore: bool| {
        let input = inputs.get(&profile.id);
        linux_runtime::prepare_connection(
            context,
            profile,
            input.map(|input| input.credentials.clone()),
            remembered,
            credential_store,
            input.is_some_and(|input| input.remember),
            !restore,
        )
        .and_then(|prepared| {
            prepared.validate_prepared_configuration(engine)?;
            Ok(prepared)
        })
        .map_err(|error| {
            if error == crate::linux_engine::CREDENTIALS_REQUIRED {
                format!("OpenVPN credentials required: {}", profile.id)
            } else {
                format!("Cannot prepare {}: {error}", profile.id)
            }
        })
    };
    // Snapshot every actual start and restoration request before the first teardown.
    let starts = starts
        .into_iter()
        .map(|profile| prepare(profile, false))
        .collect::<Result<Vec<_>, _>>()?;
    let restores = stops
        .into_iter()
        .map(|profile| prepare(profile, true))
        .collect::<Result<Vec<_>, _>>()?;
    let mut stopped = Vec::new();
    let mut started = Vec::new();
    let mut cleanup_unconfirmed = None;
    let attempt = (|| {
        // Failed resources are cleanup-only, never credential-bearing rollback candidates.
        for (index, profile) in failed_stops
            .into_iter()
            .map(|profile| (None, profile))
            .chain(
                restores
                    .iter()
                    .enumerate()
                    .map(|(index, prepared)| (Some(index), prepared.profile())),
            )
        {
            if let Some(index) = index {
                stopped.push(index);
            }
            let outcome = engine.disconnect(profile);
            linux_runtime::record_lifecycle(root, "disconnect", &profile.id, &outcome);
            match outcome {
                Ok(status) => result.outcomes.push(SetProfileOutcome {
                    profile_id: profile.id.clone(),
                    action: SetAction::Disconnect,
                    status: Some(status),
                    error: None,
                }),
                Err(error) => {
                    if index.is_none() {
                        cleanup_unconfirmed = Some(profile.id.as_str());
                    }
                    result.outcomes.push(SetProfileOutcome {
                        profile_id: profile.id.clone(),
                        action: SetAction::Disconnect,
                        status: None,
                        error: Some(error.clone()),
                    });
                    return Err(format!("disconnect {}: {error}", profile.id));
                }
            }
        }
        for (index, prepared) in starts.iter().enumerate() {
            let profile = prepared.profile();
            started.push(index);
            let outcome = linux_runtime::execute_prepared(context, prepared, credential_store);
            linux_runtime::record_lifecycle(root, "connect", &profile.id, &outcome);
            match outcome {
                Ok(status) => result.outcomes.push(SetProfileOutcome {
                    profile_id: profile.id.clone(),
                    action: SetAction::Connect,
                    status: Some(status),
                    error: None,
                }),
                Err(error) => {
                    result.outcomes.push(SetProfileOutcome {
                        profile_id: profile.id.clone(),
                        action: SetAction::Connect,
                        status: None,
                        error: Some(error.clone()),
                    });
                    return Err(format!("connect {}: {error}", profile.id));
                }
            }
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = attempt {
        let mut rollback = Vec::new();
        if let Some(profile_id) = cleanup_unconfirmed {
            rollback.push(format!(
                "teardown {profile_id} unconfirmed; failed resources were not restarted"
            ));
        }
        for index in started.into_iter().rev() {
            let profile = starts[index].profile();
            match engine.status(profile) {
                Ok(status) if status.state == TunnelState::Stopped => (),
                Ok(_) => {
                    let outcome = engine.disconnect(profile);
                    linux_runtime::record_lifecycle(root, "disconnect", &profile.id, &outcome);
                    if let Err(error) = outcome {
                        rollback.push(format!("stop {}: {error}", profile.id));
                    }
                }
                Err(error) => {
                    rollback.push(format!("inspect {} before rollback: {error}", profile.id))
                }
            }
        }
        for index in stopped {
            let prepared = &restores[index];
            let profile = prepared.profile();
            match engine.status(profile) {
                Ok(status) if status.state == TunnelState::Running => (),
                Ok(_) => {
                    let outcome =
                        linux_runtime::execute_prepared(context, prepared, credential_store);
                    linux_runtime::record_lifecycle(root, "connect", &profile.id, &outcome);
                    if let Err(error) = outcome {
                        rollback.push(format!("restore {}: {error}", profile.id));
                    }
                }
                Err(error) => rollback.push(format!(
                    "inspect {} before restoration: {error}",
                    profile.id
                )),
            }
        }
        let outcomes =
            serde_json::to_string(&result).map_err(|_| "Cannot encode connection-set outcomes")?;
        return Err(if rollback.is_empty() {
            format!("Connection-set operation failed: {error}; previous connections restored; outcomes: {outcomes}")
        } else {
            format!("Connection-set operation partially failed: {error}; rollback failed: {}; outcomes: {outcomes}", rollback.join("; "))
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::config_vault::ConfigVault;
    use net_manager_core::connection_sets::ConnectionSetCredentialInput;
    use std::fs;

    #[test]
    fn missing_references_and_invalid_secondary_are_preflight_errors() {
        let set = ConnectionSet {
            id: "set".into(),
            name: "Set".into(),
            profile_ids: vec!["member".into()],
        };
        assert!(preflight(&set, &[], true).unwrap_err().contains("member"));
        let profile = Profile {
            id: "member".into(),
            name: "Member".into(),
            tunnel_role: TunnelRole::Secondary,
            ..Profile::default()
        };
        assert!(preflight(&set, &[profile], true).is_err());
    }

    struct CredentialPreflightDaemon {
        running: std::sync::Mutex<HashSet<String>>,
        mutations: std::sync::Mutex<Vec<String>>,
        fail_start: Option<String>,
    }

    impl CredentialPreflightDaemon {
        fn status(&self, id: &str) -> serde_json::Value {
            serde_json::json!({
                "profileId": id,
                "state": if self.running.lock().unwrap().contains(id) { "connected" } else { "stopped" },
                "interfaceName": "test-ovpn", "rxBytes": 0, "txBytes": 0,
                "appliedRoutes": [], "warnings": [], "failureReason": null
            })
        }
    }

    impl crate::Privileged for CredentialPreflightDaemon {
        fn hello(
            &self,
        ) -> Result<
            net_manager_core::daemon_protocol::HelloResult,
            net_manager_core::helper_client::HelperError,
        > {
            use net_manager_core::daemon_protocol::{method, HelloResult, PROTOCOL_VERSION};
            Ok(HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: "test".into(),
                uid: 1001,
                capabilities: vec![
                    method::OPENVPN_CONNECT.into(),
                    method::OPENVPN_DISCONNECT.into(),
                    method::OPENVPN_PLAN.into(),
                ],
                tools: Default::default(),
            })
        }

        fn call_raw(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, net_manager_core::helper_client::HelperError> {
            use net_manager_core::daemon_protocol::method;
            match method {
                method::OPENVPN_PLAN => {
                    let id = params["profileId"]
                        .as_str()
                        .expect("flat OpenVPN plan request");
                    Ok(serde_json::json!({
                        "profileId":id,"owner":format!("ovpn:{id}"),"interfaceName":"test-ovpn",
                        "fallbackInterfaceName":"test-ovpn","stagingDir":"/run/network-orchestrator/1001/test-ovpn",
                        "configPath":"/run/network-orchestrator/1001/test-ovpn/client.ovpn",
                        "managementSocket":"/run/network-orchestrator/1001/test-ovpn/management.sock","conflicts":[]
                    }))
                }
                method::OPENVPN_STATUS => Ok(self.status(params["profileId"].as_str().unwrap())),
                method::OPENVPN_DISCONNECT => {
                    let id = params["profileId"].as_str().unwrap();
                    self.mutations
                        .lock()
                        .unwrap()
                        .push(format!("disconnect {id}"));
                    self.running.lock().unwrap().remove(id);
                    Ok(serde_json::json!({"stopped": true}))
                }
                method::OPENVPN_CONNECT => {
                    let request: net_manager_core::daemon_protocol::OpenVpnConnectRequest =
                        serde_json::from_value(params).map_err(|_| {
                            net_manager_core::helper_client::HelperError::Protocol(
                                "invalid OpenVPN test request".into(),
                            )
                        })?;
                    let id = &request.profile.profile_id;
                    self.mutations.lock().unwrap().push(format!("connect {id}"));
                    self.running.lock().unwrap().insert(id.clone());
                    if self.fail_start.as_deref() == Some(id.as_str()) {
                        return Err(net_manager_core::helper_client::HelperError::Protocol(
                            "synthetic startup failure".into(),
                        ));
                    }
                    Ok(serde_json::json!({"status": self.status(id)}))
                }
                _ => Err(net_manager_core::helper_client::HelperError::Protocol(
                    format!("unexpected method {method}"),
                )),
            }
        }

        fn log_dir(&self) -> std::path::PathBuf {
            std::path::PathBuf::new()
        }
    }

    fn assert_credential_preflight_preserves_running_nonmember(start_needs_credentials: bool) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("data");
        let vault = ConfigVault::new(root.join("configs"));
        let store = ProfileStore::new(root.join("profiles.json"));
        for (id, needs_credentials) in [("running-a", true), ("target-b", start_needs_credentials)]
        {
            let source = directory.path().join(format!("{id}.ovpn"));
            fs::write(
                &source,
                format!(
                    "client\ndev tun\nremote vpn.test 1194\n{}\n",
                    if needs_credentials {
                        "auth-user-pass"
                    } else {
                        ""
                    }
                ),
            )
            .unwrap();
            let config = vault.import(id, TunnelBackend::OpenVpn, &source).unwrap();
            store
                .upsert(Profile {
                    id: id.into(),
                    name: id.into(),
                    backend: TunnelBackend::OpenVpn,
                    config_path: config.config_path,
                    ..Profile::default()
                })
                .unwrap();
        }
        put(
            &root,
            &store,
            ConnectionSet {
                id: "target".into(),
                name: "Target".into(),
                profile_ids: vec!["target-b".into()],
            },
        )
        .unwrap();
        let daemon = std::sync::Arc::new(CredentialPreflightDaemon {
            running: std::sync::Mutex::new(HashSet::from(["running-a".into()])),
            mutations: std::sync::Mutex::new(Vec::new()),
            fail_start: None,
        });
        let engine = LinuxEngine::with_privileged(daemon.clone());
        let result = apply(
            &linux_runtime::Context {
                engine: &engine,
                root: &root,
                vault: &vault,
                store: &store,
            },
            "target",
            &(),
            &CredentialInputs::new(),
            None,
        );
        assert!(
            result.is_err(),
            "a predictable start/rollback credential requirement must reject the entire apply"
        );
        assert!(
            daemon.mutations.lock().unwrap().is_empty(),
            "credential preflight must finish before any daemon mutation"
        );
        assert_eq!(
            *daemon.running.lock().unwrap(),
            HashSet::from(["running-a".into()])
        );
    }

    #[test]
    fn missing_start_credentials_preserve_running_nonmember() {
        assert_credential_preflight_preserves_running_nonmember(true);
    }

    #[test]
    fn missing_rollback_credentials_preserve_running_nonmember() {
        assert_credential_preflight_preserves_running_nonmember(false);
    }

    #[test]
    fn intentional_down_does_not_require_reconnect_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("data");
        let vault = ConfigVault::new(root.join("configs"));
        let source = directory.path().join("running-a.ovpn");
        fs::write(
            &source,
            "client\ndev tun\nremote vpn.test 1194\nauth-user-pass\n",
        )
        .unwrap();
        let config = vault
            .import("running-a", TunnelBackend::OpenVpn, &source)
            .unwrap();
        let store = ProfileStore::new(root.join("profiles.json"));
        store
            .upsert(Profile {
                id: "running-a".into(),
                name: "Running".into(),
                backend: TunnelBackend::OpenVpn,
                config_path: config.config_path,
                ..Profile::default()
            })
            .unwrap();
        put(
            &root,
            &store,
            ConnectionSet {
                id: "target".into(),
                name: "Target".into(),
                profile_ids: vec!["running-a".into()],
            },
        )
        .unwrap();
        let daemon = std::sync::Arc::new(CredentialPreflightDaemon {
            running: std::sync::Mutex::new(HashSet::from(["running-a".into()])),
            mutations: std::sync::Mutex::new(Vec::new()),
            fail_start: None,
        });
        let engine = LinuxEngine::with_privileged(daemon.clone());
        down(
            &linux_runtime::Context {
                engine: &engine,
                root: &root,
                vault: &vault,
                store: &store,
            },
            "target",
        )
        .unwrap();
        assert!(daemon.running.lock().unwrap().is_empty());
        assert_eq!(
            *daemon.mutations.lock().unwrap(),
            vec!["disconnect running-a"]
        );
    }

    struct OneUseCredentials {
        daemon: std::sync::Arc<CredentialPreflightDaemon>,
        loads: std::sync::atomic::AtomicUsize,
    }

    impl CredentialSource for OneUseCredentials {
        fn load(
            &self,
            profile_id: &str,
            _: &Path,
        ) -> Result<
            (
                Option<net_manager_core::daemon_protocol::OpenVpnCredentials>,
                Option<&'static str>,
            ),
            String,
        > {
            assert_eq!(profile_id, "running-a");
            assert!(
                self.daemon.running.lock().unwrap().contains(profile_id),
                "rollback credentials must be captured while the old connection is still running"
            );
            assert_eq!(
                self.loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                0,
                "prepared credentials must not be reloaded at execution"
            );
            Ok((Some(test_credentials()), None))
        }
    }

    fn test_credentials() -> net_manager_core::daemon_protocol::OpenVpnCredentials {
        net_manager_core::daemon_protocol::OpenVpnCredentials {
            auth_user_pass: Some(net_manager_core::daemon_protocol::OpenVpnUserPass {
                username: "synthetic-user".into(),
                password: "synthetic-password".into(),
            }),
            private_key_passphrase: None,
        }
    }

    fn openvpn_fixture(
        root: &Path,
        vault: &ConfigVault,
        store: &ProfileStore,
        id: &str,
        auth: bool,
    ) {
        let source = root.join(format!("{id}.ovpn"));
        fs::write(
            &source,
            format!(
                "client\ndev tun\nremote vpn.test 1194\n{}\n",
                if auth { "auth-user-pass" } else { "" }
            ),
        )
        .unwrap();
        let config = vault.import(id, TunnelBackend::OpenVpn, &source).unwrap();
        store
            .upsert(Profile {
                id: id.into(),
                name: id.into(),
                backend: TunnelBackend::OpenVpn,
                config_path: config.config_path,
                ..Profile::default()
            })
            .unwrap();
    }

    #[test]
    fn failed_start_restores_previous_connection_with_prepared_one_use_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("data");
        let vault = ConfigVault::new(root.join("configs"));
        let store = ProfileStore::new(root.join("profiles.json"));
        openvpn_fixture(directory.path(), &vault, &store, "running-a", true);
        openvpn_fixture(directory.path(), &vault, &store, "target-b", false);
        put(
            &root,
            &store,
            ConnectionSet {
                id: "target".into(),
                name: "Target".into(),
                profile_ids: vec!["target-b".into()],
            },
        )
        .unwrap();
        let daemon = std::sync::Arc::new(CredentialPreflightDaemon {
            running: std::sync::Mutex::new(HashSet::from(["running-a".into()])),
            mutations: std::sync::Mutex::new(Vec::new()),
            fail_start: Some("target-b".into()),
        });
        let credentials = OneUseCredentials {
            daemon: daemon.clone(),
            loads: std::sync::atomic::AtomicUsize::new(0),
        };
        let engine = LinuxEngine::with_privileged(daemon.clone());
        let error = apply(
            &linux_runtime::Context {
                engine: &engine,
                root: &root,
                vault: &vault,
                store: &store,
            },
            "target",
            &credentials,
            &CredentialInputs::new(),
            None,
        )
        .unwrap_err();
        assert!(error.contains("previous connections restored"), "{error}");
        assert!(!error.contains("synthetic-password"));
        assert_eq!(
            *daemon.running.lock().unwrap(),
            HashSet::from(["running-a".into()])
        );
        assert_eq!(
            *daemon.mutations.lock().unwrap(),
            vec![
                "disconnect running-a",
                "connect target-b",
                "disconnect target-b",
                "connect running-a"
            ]
        );
        assert_eq!(
            credentials.loads.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn manual_credential_inputs_apply_and_healthy_members_are_not_reconnected() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("data");
        let vault = ConfigVault::new(root.join("configs"));
        let store = ProfileStore::new(root.join("profiles.json"));
        openvpn_fixture(directory.path(), &vault, &store, "running-a", true);
        openvpn_fixture(directory.path(), &vault, &store, "target-b", true);
        put(
            &root,
            &store,
            ConnectionSet {
                id: "target".into(),
                name: "Target".into(),
                profile_ids: vec!["target-b".into()],
            },
        )
        .unwrap();
        let daemon = std::sync::Arc::new(CredentialPreflightDaemon {
            running: std::sync::Mutex::new(HashSet::from(["running-a".into()])),
            mutations: std::sync::Mutex::new(Vec::new()),
            fail_start: None,
        });
        let engine = LinuxEngine::with_privileged(daemon.clone());
        let inputs = ["running-a", "target-b"]
            .into_iter()
            .map(|id| {
                (
                    id.into(),
                    ConnectionSetCredentialInput {
                        credentials: test_credentials(),
                        remember: false,
                    },
                )
            })
            .collect();
        let applied = apply(
            &linux_runtime::Context {
                engine: &engine,
                root: &root,
                vault: &vault,
                store: &store,
            },
            "target",
            &(),
            &inputs,
            None,
        )
        .unwrap();
        assert_eq!(
            *daemon.running.lock().unwrap(),
            HashSet::from(["target-b".into()])
        );
        assert!(!serde_json::to_string(&applied)
            .unwrap()
            .contains("synthetic-password"));
        let unchanged = apply(
            &linux_runtime::Context {
                engine: &engine,
                root: &root,
                vault: &vault,
                store: &store,
            },
            "target",
            &(),
            &CredentialInputs::new(),
            None,
        )
        .unwrap();
        assert_eq!(unchanged.outcomes.len(), 1);
        assert!(matches!(unchanged.outcomes[0].action, SetAction::Unchanged));
        assert_eq!(
            *daemon.mutations.lock().unwrap(),
            vec!["disconnect running-a", "connect target-b"]
        );
    }

    struct RejectingConfigurationDaemon {
        inner: CredentialPreflightDaemon,
        backend: TunnelBackend,
    }

    impl crate::Privileged for RejectingConfigurationDaemon {
        fn hello(
            &self,
        ) -> Result<
            net_manager_core::daemon_protocol::HelloResult,
            net_manager_core::helper_client::HelperError,
        > {
            crate::Privileged::hello(&self.inner)
        }

        fn call_raw(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, net_manager_core::helper_client::HelperError> {
            use net_manager_core::daemon_protocol::method;
            match method {
                method::ALWAYS_ON_LIST => {
                    Ok(serde_json::json!({"profiles":[],"paused":false,"supportedKinds":[]}))
                }
                method::WIREGUARD_STATUS => Ok(serde_json::json!({
                    "profileId":"target-b","state":"stopped","interfaceName":null,
                    "latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[]
                })),
                method::WIREGUARD_CONNECT => {
                    self.inner
                        .mutations
                        .lock()
                        .unwrap()
                        .push("connect target-b".into());
                    Err(net_manager_core::helper_client::HelperError::Protocol(
                        "invalid WireGuard PrivateKey".into(),
                    ))
                }
                method::OPENVPN_PLAN => {
                    let id = params["profileId"]
                        .as_str()
                        .expect("flat OpenVPN request profileId");
                    if id == "target-b" && self.backend == TunnelBackend::OpenVpn {
                        return Err(net_manager_core::helper_client::HelperError::Protocol(
                            "invalid OpenVPN config".into(),
                        ));
                    }
                    Ok(serde_json::json!({
                        "profileId":id,"owner":format!("ovpn:{id}"),"interfaceName":"test-ovpn",
                        "fallbackInterfaceName":"test-ovpn","stagingDir":"/run/network-orchestrator/1001/test-ovpn",
                        "configPath":"/run/network-orchestrator/1001/test-ovpn/client.ovpn",
                        "managementSocket":"/run/network-orchestrator/1001/test-ovpn/management.sock","conflicts":[]
                    }))
                }
                _ => crate::Privileged::call_raw(&self.inner, method, params),
            }
        }

        fn log_dir(&self) -> std::path::PathBuf {
            std::path::PathBuf::new()
        }
    }

    fn assert_invalid_backend_config_preserves_running_nonmember(backend: TunnelBackend) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("data");
        let vault = ConfigVault::new(root.join("configs"));
        let store = ProfileStore::new(root.join("profiles.json"));
        openvpn_fixture(directory.path(), &vault, &store, "running-a", false);
        let config = if backend == TunnelBackend::WireGuard {
            vault.store_wireguard_config("target-b", b"[Interface]\nPrivateKey=not-a-base64-key\nAddress=10.9.0.2/32\n[Peer]\nPublicKey=ERERERERERERERERERERERERERERERERERERERERERE=\nAllowedIPs=0.0.0.0/0\nEndpoint=192.0.2.1:51820\n").unwrap()
        } else {
            let source = directory.path().join("bad.ovpn");
            fs::write(&source, "client\ndev tun\nremote vpn.test 1194\ndaemon\n").unwrap();
            vault
                .import("target-b", TunnelBackend::OpenVpn, &source)
                .unwrap()
        };
        store
            .upsert(Profile {
                id: "target-b".into(),
                name: "Invalid target".into(),
                backend,
                config_path: config.config_path,
                ..Profile::default()
            })
            .unwrap();
        put(
            &root,
            &store,
            ConnectionSet {
                id: "target".into(),
                name: "Target".into(),
                profile_ids: vec!["target-b".into()],
            },
        )
        .unwrap();
        let daemon = std::sync::Arc::new(RejectingConfigurationDaemon {
            inner: CredentialPreflightDaemon {
                running: std::sync::Mutex::new(HashSet::from(["running-a".into()])),
                mutations: std::sync::Mutex::new(Vec::new()),
                fail_start: Some("target-b".into()),
            },
            backend,
        });
        let engine = LinuxEngine::with_privileged(daemon.clone());
        let result = apply(
            &linux_runtime::Context {
                engine: &engine,
                root: &root,
                vault: &vault,
                store: &store,
            },
            "target",
            &(),
            &CredentialInputs::new(),
            None,
        );
        assert!(
            result.is_err(),
            "invalid backend configuration must reject the set"
        );
        assert!(
            daemon.inner.mutations.lock().unwrap().is_empty(),
            "actual backend validation must precede every daemon mutation"
        );
        assert_eq!(
            *daemon.inner.running.lock().unwrap(),
            HashSet::from(["running-a".into()])
        );
    }

    #[test]
    fn invalid_wireguard_key_preserves_running_nonmember_before_daemon_mutation() {
        assert_invalid_backend_config_preserves_running_nonmember(TunnelBackend::WireGuard);
    }

    #[test]
    fn unsupported_openvpn_directive_preserves_running_nonmember_before_daemon_mutation() {
        assert_invalid_backend_config_preserves_running_nonmember(TunnelBackend::OpenVpn);
    }

    struct FailedOwnedDaemon {
        inner: CredentialPreflightDaemon,
        resources: std::sync::Mutex<HashSet<&'static str>>,
        status_unavailable: bool,
        enrolled: bool,
    }

    impl crate::Privileged for FailedOwnedDaemon {
        fn hello(
            &self,
        ) -> Result<
            net_manager_core::daemon_protocol::HelloResult,
            net_manager_core::helper_client::HelperError,
        > {
            use net_manager_core::daemon_protocol::method;
            let mut hello = crate::Privileged::hello(&self.inner)?;
            hello.capabilities.extend(
                [
                    method::WIREGUARD_STATUS,
                    method::WIREGUARD_DISCONNECT,
                    method::WIREGUARD_CONNECT,
                    method::ALWAYS_ON_LIST,
                ]
                .map(String::from),
            );
            Ok(hello)
        }

        fn call_raw(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, net_manager_core::helper_client::HelperError> {
            use net_manager_core::daemon_protocol::method;
            use net_manager_core::helper_client::HelperError;
            match method {
                method::ALWAYS_ON_LIST => Ok(serde_json::json!({
                    "profiles": if self.enrolled {
                        vec![serde_json::json!({
                            "kind": "wireGuard", "profileId": "failed-wg", "enabled": true
                        })]
                    } else {
                        Vec::new()
                    },
                    "paused": false, "supportedKinds": ["wireGuard"]
                })),
                method::WIREGUARD_STATUS | method::WIREGUARD_DISCONNECT => {
                    assert_eq!(params["profileId"].as_str(), Some("failed-wg"));
                    if method == method::WIREGUARD_STATUS {
                        if self.status_unavailable {
                            return Err(HelperError::Protocol("status unavailable".into()));
                        }
                        let resources = self.resources.lock().unwrap();
                        Ok(serde_json::json!({
                            "profileId": "failed-wg",
                            "state": if resources.is_empty() { "stopped" } else { "failed" },
                            "interfaceName": "wg-fixture", "latestHandshake": null,
                            "rxBytes": 0, "txBytes": 0, "dnsApplied": resources.contains("dns"),
                            "warnings": []
                        }))
                    } else {
                        self.inner
                            .mutations
                            .lock()
                            .unwrap()
                            .push("disconnect failed-wg".into());
                        self.resources.lock().unwrap().clear();
                        Ok(serde_json::json!({"stopped": true}))
                    }
                }
                method::WIREGUARD_CONNECT => {
                    self.inner
                        .mutations
                        .lock()
                        .unwrap()
                        .push("connect failed-wg".into());
                    Err(HelperError::Protocol(
                        "failed resources must not be restored".into(),
                    ))
                }
                _ => crate::Privileged::call_raw(&self.inner, method, params),
            }
        }

        fn log_dir(&self) -> std::path::PathBuf {
            std::path::PathBuf::new()
        }
    }

    struct FailedOwnedFixture {
        directory: tempfile::TempDir,
        root: std::path::PathBuf,
        vault: ConfigVault,
        store: ProfileStore,
        daemon: std::sync::Arc<FailedOwnedDaemon>,
        engine: LinuxEngine,
    }

    impl FailedOwnedFixture {
        fn new(status_unavailable: bool, enrolled: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("data");
            let vault = ConfigVault::new(root.join("configs"));
            let store = ProfileStore::new(root.join("profiles.json"));
            store
                .upsert(Profile {
                    id: "failed-wg".into(),
                    name: "Failed WireGuard".into(),
                    backend: TunnelBackend::WireGuard,
                    // Teardown must not depend on a reconnectable configuration.
                    config_path: root.join("deleted-wg.conf"),
                    ..Profile::default()
                })
                .unwrap();
            let daemon = std::sync::Arc::new(FailedOwnedDaemon {
                inner: CredentialPreflightDaemon {
                    running: std::sync::Mutex::new(HashSet::new()),
                    mutations: std::sync::Mutex::new(Vec::new()),
                    fail_start: Some("target-b".into()),
                },
                resources: std::sync::Mutex::new(HashSet::from(["interface", "route", "dns"])),
                status_unavailable,
                enrolled,
            });
            let engine = LinuxEngine::with_privileged(daemon.clone());
            Self {
                directory,
                root,
                vault,
                store,
                daemon,
                engine,
            }
        }

        fn context(&self) -> linux_runtime::Context<'_> {
            linux_runtime::Context {
                engine: &self.engine,
                root: &self.root,
                vault: &self.vault,
                store: &self.store,
            }
        }

        fn save_set(&self, profile_ids: &[&str]) {
            put(
                &self.root,
                &self.store,
                ConnectionSet {
                    id: "resource-set".into(),
                    name: "Resource set".into(),
                    profile_ids: profile_ids.iter().map(|id| (*id).into()).collect(),
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn failed_owned_resources_are_removed_by_down_without_reconnect_preparation() {
        let fixture = FailedOwnedFixture::new(false, false);
        fixture.save_set(&["failed-wg"]);
        let outcome = down(&fixture.context(), "resource-set").unwrap();
        assert!(
            fixture.daemon.resources.lock().unwrap().is_empty(),
            "successful down must remove the failed interface, routes, and DNS"
        );
        assert_eq!(
            *fixture.daemon.inner.mutations.lock().unwrap(),
            ["disconnect failed-wg"]
        );
        assert_eq!(outcome.outcomes.len(), 1);
        assert!(matches!(outcome.outcomes[0].action, SetAction::Disconnect));
        assert_eq!(
            outcome.outcomes[0].status.as_ref().unwrap().state,
            TunnelState::Stopped
        );
    }

    #[test]
    fn failed_owned_resources_of_nonmembers_are_removed_by_apply() {
        let fixture = FailedOwnedFixture::new(false, false);
        fixture.save_set(&[]);
        let outcome = apply(
            &fixture.context(),
            "resource-set",
            &(),
            &CredentialInputs::new(),
            None,
        )
        .unwrap();
        assert!(
            fixture.daemon.resources.lock().unwrap().is_empty(),
            "successful apply must remove failed nonmember resources"
        );
        assert_eq!(
            *fixture.daemon.inner.mutations.lock().unwrap(),
            ["disconnect failed-wg"]
        );
        assert_eq!(outcome.outcomes.len(), 1);
        assert!(matches!(outcome.outcomes[0].action, SetAction::Disconnect));
    }

    #[test]
    fn failed_owned_resources_are_not_restored_after_another_member_fails() {
        let fixture = FailedOwnedFixture::new(false, false);
        openvpn_fixture(
            fixture.directory.path(),
            &fixture.vault,
            &fixture.store,
            "target-b",
            false,
        );
        fixture.save_set(&["target-b"]);
        let error = apply(
            &fixture.context(),
            "resource-set",
            &(),
            &CredentialInputs::new(),
            None,
        )
        .unwrap_err();
        assert!(error.contains("synthetic startup failure"));
        assert!(
            fixture.daemon.resources.lock().unwrap().is_empty(),
            "rollback must not resurrect failed resources as healthy connections"
        );
        assert_eq!(
            *fixture.daemon.inner.mutations.lock().unwrap(),
            [
                "disconnect failed-wg",
                "connect target-b",
                "disconnect target-b"
            ]
        );
        assert!(fixture.daemon.inner.running.lock().unwrap().is_empty());
    }

    #[test]
    fn failed_owned_resources_remain_protected_by_unknown_status_and_always_on() {
        for (status_unavailable, enrolled) in [(true, false), (false, true)] {
            let fixture = FailedOwnedFixture::new(status_unavailable, enrolled);
            fixture.save_set(&["failed-wg"]);
            assert!(down(&fixture.context(), "resource-set").is_err());
            assert_eq!(
                *fixture.daemon.resources.lock().unwrap(),
                HashSet::from(["interface", "route", "dns"])
            );
            assert!(fixture.daemon.inner.mutations.lock().unwrap().is_empty());
            fixture.save_set(&[]);
            let applied = apply(
                &fixture.context(),
                "resource-set",
                &(),
                &CredentialInputs::new(),
                None,
            );
            if status_unavailable {
                assert!(
                    applied.is_err(),
                    "an unknown nonmember status must fail closed"
                );
            } else {
                assert!(
                    applied.is_ok(),
                    "unrelated always-on resources must be left alone"
                );
            }
            assert_eq!(
                *fixture.daemon.resources.lock().unwrap(),
                HashSet::from(["interface", "route", "dns"])
            );
            assert!(fixture.daemon.inner.mutations.lock().unwrap().is_empty());
        }
    }
}
