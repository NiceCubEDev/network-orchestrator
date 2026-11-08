use super::*;

#[derive(Default)]
struct ProxyProbe {
    applied: usize,
    restored: usize,
    fail_apply: bool,
    fail_restore: bool,
}
struct TestProxy(Arc<Mutex<ProxyProbe>>);
impl net_manager_core::system_proxy::ProxyAdapter for TestProxy {
    fn snapshot(&mut self) -> std::io::Result<net_manager_core::system_proxy::ProxySnapshot> {
        Ok(Default::default())
    }
    fn apply(&mut self, _server: &str, _bypass: &str) -> std::io::Result<()> {
        let mut probe = self.0.lock().unwrap();
        probe.applied += 1;
        if probe.fail_apply {
            return Err(std::io::Error::other("injected proxy apply failure"));
        }
        Ok(())
    }
    fn restore(
        &mut self,
        _snapshot: &net_manager_core::system_proxy::ProxySnapshot,
    ) -> std::io::Result<()> {
        let mut probe = self.0.lock().unwrap();
        if probe.fail_restore {
            return Err(std::io::Error::other("injected restore failure"));
        }
        probe.restored += 1;
        Ok(())
    }
}

fn shared_fixture(root: &Path) -> (Engine, Profile, ProfileStore, Arc<Mutex<ProxyProbe>>) {
    use std::os::unix::fs::PermissionsExt;
    let executable = root.join("synthetic-xray");
    std::fs::write(&executable,
        "#!/bin/sh\ncase \"$*\" in *-test*) cat >/dev/null; exit 0;; esac\ncat >/dev/null\nexec /bin/sleep 60\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let imported = ConfigVault::new(root.join("configs")).store_generated_xray("local",
        br#"{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":10808}],"outbounds":[{"protocol":"freedom"}]}"#).unwrap();
    let profile = Profile {
        id: "local".into(),
        name: "Synthetic local".into(),
        backend: TunnelBackend::Xray,
        xray_mode: XrayMode::Socks,
        config_path: imported.config_path,
        xray_socks_port: Some(10808),
        ..Default::default()
    };
    let store = ProfileStore::new(root.join("profiles.json"));
    store
        .save(&net_manager_core::profiles::ProfileDocument {
            version: 1,
            profiles: vec![profile.clone()],
        })
        .unwrap();
    let probe = Arc::new(Mutex::new(ProxyProbe::default()));
    let mut engine = Engine::with_privileged(
        root,
        Arc::new(HelperClient::new(root.join("absent-helper.sock"))),
    );
    engine.owner = true;
    engine.test_executable = Some(executable);
    *engine.session_slot().unwrap().lock().unwrap() = Some(Session {
        tunnels: TunnelManager::with_log_dir(root.join("runtime/logs")),
        proxy: SystemProxyManager::with_adapter(
            root.join("runtime/system-proxy.json"),
            Box::new(TestProxy(probe.clone())),
        )
        .unwrap(),
        proxy_guard: None,
        profiles: HashMap::new(),
        recovery_error: None,
    });
    (engine, profile, store, probe)
}

fn shared_client(root: &Path, server: &macos_session::TestServer) -> Engine {
    let mut engine = Engine::new(root);
    engine.client = Some(server.client());
    engine
}

#[test]
fn real_backend_two_frontends_share_child_proxy_and_detach_only_shutdown() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, probe) = shared_fixture(temp.path());
    let inspect = owner.clone();
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let first = shared_client(temp.path(), &server);
    let second = shared_client(temp.path(), &server);
    first.connect(&store, &profile, None).unwrap();
    assert!(first.local.is_none());
    assert!(second.is_running(&profile).unwrap());
    let pid = with_session(&inspect, |s| {
        Ok(s.tunnels.xray_child_pid(&profile.id).unwrap())
    })
    .unwrap();
    second
        .set_system_proxy(&profile, std::slice::from_ref(&profile), true)
        .unwrap();
    assert_eq!(
        first.system_proxy_owner().unwrap().as_deref(),
        Some("local")
    );
    first.shutdown(std::slice::from_ref(&profile)).unwrap();
    drop(first);
    assert!(second.is_running(&profile).unwrap());
    assert_eq!(
        with_session(&inspect, |s| Ok(s.tunnels.xray_child_pid(&profile.id))).unwrap(),
        Some(pid)
    );
    second
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
    assert!(!second.is_running(&profile).unwrap());
    assert_eq!(probe.lock().unwrap().applied, 1);
    assert_eq!(probe.lock().unwrap().restored, 1);
}

#[test]
fn failed_proxy_restore_retains_owner_and_child_until_successful_down() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, probe) = shared_fixture(temp.path());
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let client = shared_client(temp.path(), &server);
    client.connect(&store, &profile, None).unwrap();
    client
        .set_system_proxy(&profile, std::slice::from_ref(&profile), true)
        .unwrap();
    probe.lock().unwrap().fail_restore = true;
    assert!(client
        .disconnect(&profile, std::slice::from_ref(&profile))
        .is_err());
    assert!(client.is_running(&profile).unwrap());
    assert_eq!(
        client.system_proxy_owner().unwrap().as_deref(),
        Some("local")
    );
    assert!(net_manager_core::system_proxy::load_ownership(
        &temp.path().join("runtime/system-proxy.json")
    )
    .unwrap()
    .is_some());
    probe.lock().unwrap().fail_restore = false;
    client
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
    assert!(client.system_proxy_owner().unwrap().is_none());
}

#[test]
fn restart_closure_runs_client_side_with_root_guard_and_no_server_reentrancy() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, _) = shared_fixture(temp.path());
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let client = shared_client(temp.path(), &server);
    client.connect(&store, &profile, None).unwrap();
    let returned = client
        .restart_around(&store, &profile.id, || {
            assert!(macos_transaction::try_root_lock(temp.path())
                .unwrap()
                .is_none());
            assert!(!client.is_running(&profile).unwrap());
            Ok(37)
        })
        .unwrap();
    assert_eq!(returned, 37);
    assert!(client.is_running(&profile).unwrap());
    client
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
}

#[test]
fn abrupt_foreground_exit_and_stale_foreground_cleanup_are_generation_bound() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, _) = shared_fixture(temp.path());
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let client = shared_client(temp.path(), &server);
    let lease = client.connect_foreground(&store, &profile, None).unwrap();
    assert!(lease.is_running().unwrap());
    client
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
    client.connect(&store, &profile, None).unwrap();
    lease.disconnect().unwrap();
    assert!(client.is_running(&profile).unwrap());
    drop(lease);
    client
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
    let lease = client.connect_foreground(&store, &profile, None).unwrap();
    drop(lease);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while client.is_running(&profile).unwrap() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!client.is_running(&profile).unwrap());
}

#[test]
fn unexpected_child_exit_restores_proxy_without_frontend_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, probe) = shared_fixture(temp.path());
    let inspect = owner.clone();
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let client = shared_client(temp.path(), &server);
    client.connect(&store, &profile, None).unwrap();
    client
        .set_system_proxy(&profile, std::slice::from_ref(&profile), true)
        .unwrap();
    let pid = with_session(&inspect, |s| {
        Ok(s.tunnels.xray_child_pid(&profile.id).unwrap())
    })
    .unwrap();
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) }, 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while client.system_proxy_owner().unwrap().is_some() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(client.system_proxy_owner().unwrap().is_none());
    assert_eq!(probe.lock().unwrap().restored, 1);
}

#[test]
fn helper_transport_activation_survives_frontend_and_user_owner_exit() {
    use net_manager_core::daemon_protocol::{
        encode_line, HelloResult, RequestFrame, ResponseFrame, PROTOCOL_VERSION,
    };
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, _, store, _) = shared_fixture(temp.path());
    let helper_path = temp.path().join("fake-helper.sock");
    let listener = UnixListener::bind(&helper_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let live = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let (helper_live, helper_stop) = (live.clone(), stop.clone());
    let helper = std::thread::spawn(move || {
        while !helper_stop.load(Ordering::Acquire) {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                continue;
            }
            let hello: RequestFrame = serde_json::from_str(&line).unwrap();
            let hello_result = HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: "test".into(),
                uid: unsafe { libc::geteuid() },
                capabilities: vec![method::WIREGUARD_CONNECT.into()],
                tools: Default::default(),
            };
            stream
                .write_all(
                    &encode_line(&ResponseFrame::ok(
                        hello.id,
                        serde_json::to_value(hello_result).unwrap(),
                    ))
                    .unwrap(),
                )
                .unwrap();
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 {
                continue;
            }
            let request: RequestFrame = serde_json::from_str(&line).unwrap();
            let state = || {
                serde_json::json!({ "profileId":"wg", "state":if helper_live.load(Ordering::Acquire) { "running" } else { "stopped" },
                "interfaceName":"utun-test", "latestHandshake":null, "rxBytes":0, "txBytes":0, "dnsApplied":false, "warnings":[] })
            };
            let value = match request.method.as_str() {
                method::WIREGUARD_STATUS => state(),
                method::WIREGUARD_CONNECT => {
                    helper_live.store(true, Ordering::Release);
                    serde_json::json!({"status":state()})
                }
                method::WIREGUARD_DISCONNECT => {
                    helper_live.store(false, Ordering::Release);
                    serde_json::json!({"stopped":true})
                }
                other => panic!("unexpected helper method: {other}"),
            };
            stream
                .write_all(&encode_line(&ResponseFrame::ok(request.id, value)).unwrap())
                .unwrap();
        }
    });
    owner.privileged = Arc::new(HelperClient::new(helper_path));
    let imported = ConfigVault::new(temp.path().join("configs"))
        .store_wireguard_config("wg", b"[Interface]\nPrivateKey = x\n")
        .unwrap();
    let profile = Profile {
        id: "wg".into(),
        name: "Synthetic helper tunnel".into(),
        backend: TunnelBackend::WireGuard,
        config_path: imported.config_path,
        ..Default::default()
    };
    store
        .save(&net_manager_core::profiles::ProfileDocument {
            version: 1,
            profiles: vec![profile.clone()],
        })
        .unwrap();
    let replacement = owner.clone();
    let first = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let frontend = shared_client(temp.path(), &first);
    frontend.connect(&store, &profile, None).unwrap();
    drop(frontend);
    assert!(live.load(Ordering::Acquire));
    drop(first);
    assert!(live.load(Ordering::Acquire));
    let second = macos_session::TestServer::start(
        temp.path(),
        OwnerBackend {
            engine: replacement,
        },
    );
    let frontend = shared_client(temp.path(), &second);
    assert!(frontend.is_running(&profile).unwrap());
    frontend.disconnect_remote(&profile).unwrap();
    assert!(!live.load(Ordering::Acquire));
    drop(second);
    stop.store(true, Ordering::Release);
    helper.join().unwrap();
}

#[test]
fn provisional_foreground_generation_promotes_only_after_proxy_success() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, probe) = shared_fixture(temp.path());
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let frontend = shared_client(temp.path(), &server);
    let lease = frontend.connect_foreground(&store, &profile, None).unwrap();
    let snapshot = lease.set_system_proxy(true).unwrap();
    assert_eq!(snapshot.system_proxy_owner.as_deref(), Some("local"));
    lease.detach().unwrap();
    drop(frontend);
    let observer = shared_client(temp.path(), &server);
    assert!(observer.is_running(&profile).unwrap());
    observer
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
    assert_eq!(probe.lock().unwrap().restored, 1);
}

#[test]
fn stale_provisional_lease_cannot_proxy_or_promote_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, _) = shared_fixture(temp.path());
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let frontend = shared_client(temp.path(), &server);
    let stale = frontend.connect_foreground(&store, &profile, None).unwrap();
    frontend
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
    frontend.connect(&store, &profile, None).unwrap();
    assert!(stale.set_system_proxy(true).is_err());
    assert!(stale.detach().is_err());
    assert!(frontend.is_running(&profile).unwrap());
    assert!(frontend.system_proxy_owner().unwrap().is_none());
    frontend
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
}

#[test]
fn failed_proxy_stage_cleans_its_provisional_activation_without_background_leak() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, probe) = shared_fixture(temp.path());
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let frontend = shared_client(temp.path(), &server);
    let lease = frontend.connect_foreground(&store, &profile, None).unwrap();
    probe.lock().unwrap().fail_apply = true;
    assert!(lease.set_system_proxy(true).is_err());
    lease.disconnect().unwrap();
    assert!(!frontend.is_running(&profile).unwrap());
    assert!(frontend.system_proxy_owner().unwrap().is_none());
    assert_eq!(probe.lock().unwrap().restored, 1);
}

#[test]
fn failed_proxy_stage_retains_failed_restore_and_can_be_cleaned_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, probe) = shared_fixture(temp.path());
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let frontend = shared_client(temp.path(), &server);
    let lease = frontend.connect_foreground(&store, &profile, None).unwrap();
    {
        let mut fault = probe.lock().unwrap();
        fault.fail_apply = true;
        fault.fail_restore = true;
    }
    assert!(lease.set_system_proxy(true).is_err());
    assert!(lease.disconnect().is_err());
    assert!(frontend.is_running(&profile).unwrap());
    assert_eq!(
        frontend.system_proxy_owner().unwrap().as_deref(),
        Some("local")
    );
    probe.lock().unwrap().fail_restore = false;
    lease.disconnect().unwrap();
    assert!(!frontend.is_running(&profile).unwrap());
    assert!(frontend.system_proxy_owner().unwrap().is_none());
}

#[test]
fn login_openvpn_restart_rejects_before_helper_stop_or_client_store_change() {
    use net_manager_core::daemon_protocol::{HelloResult, PROTOCOL_VERSION};
    use net_manager_core::helper_client::HelperError;
    use std::sync::atomic::{AtomicBool, Ordering};
    struct LiveVpn(Mutex<Vec<String>>);
    impl Privileged for LiveVpn {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            Ok(HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: "test".into(),
                uid: 1000,
                capabilities: vec![method::OPENVPN_CONNECT.into()],
                tools: Default::default(),
            })
        }
        fn call_raw(
            &self,
            operation: &str,
            _: serde_json::Value,
        ) -> Result<serde_json::Value, HelperError> {
            self.0.lock().unwrap().push(operation.into());
            Ok(
                serde_json::json!({"profileId":"ovpn","state":"connected","interfaceName":"utun-test",
                "rxBytes":0,"txBytes":0,"appliedRoutes":[],"warnings":[],"failureReason":null}),
            )
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, _, store, _) = shared_fixture(temp.path());
    let config = temp.path().join("configs/ovpn/rev-1/client.ovpn");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    net_manager_core::config_security::protect_path(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "client\ndev tun\nremote example.invalid 1194\nauth-user-pass\n",
    )
    .unwrap();
    net_manager_core::config_security::protect_path(&config).unwrap();
    let profile = Profile {
        id: "ovpn".into(),
        name: "Login VPN".into(),
        backend: TunnelBackend::OpenVpn,
        config_path: config,
        ..Default::default()
    };
    store
        .save(&net_manager_core::profiles::ProfileDocument {
            version: 1,
            profiles: vec![profile.clone()],
        })
        .unwrap();
    let helper = Arc::new(LiveVpn(Mutex::new(Vec::new())));
    owner.privileged = helper.clone();
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let frontend = shared_client(temp.path(), &server);
    assert!(
        frontend
            .credential_requirements(&profile)
            .unwrap()
            .user_pass
    );
    let changed = AtomicBool::new(false);
    let result = frontend.restart_around(&store, &profile.id, || {
        changed.store(true, Ordering::Release);
        Ok(())
    });
    assert!(result.is_err());
    assert!(!changed.load(Ordering::Acquire));
    assert!(!helper
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|operation| operation == method::OPENVPN_DISCONNECT));
    assert!(frontend.is_running(&profile).unwrap());
}

#[derive(Default)]
struct RuntimeHelperProbe {
    live: std::sync::atomic::AtomicBool,
    reject_stop: std::sync::atomic::AtomicBool,
    intents: Mutex<Vec<serde_json::Value>>,
}

impl Privileged for RuntimeHelperProbe {
    fn hello(
        &self,
    ) -> Result<
        net_manager_core::daemon_protocol::HelloResult,
        net_manager_core::helper_client::HelperError,
    > {
        Ok(net_manager_core::daemon_protocol::HelloResult {
            protocol: net_manager_core::daemon_protocol::PROTOCOL_VERSION,
            daemon_version: "injected".into(),
            uid: unsafe { libc::geteuid() },
            capabilities: vec![
                method::WIREGUARD_CONNECT.into(),
                method::NET_INTENT_SET.into(),
            ],
            tools: Default::default(),
        })
    }
    fn call_raw(
        &self,
        name: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, net_manager_core::helper_client::HelperError> {
        use net_manager_core::helper_client::HelperError;
        use std::sync::atomic::Ordering;
        match name {
            method::WIREGUARD_STATUS => Ok(json!({
                "profileId":params["profileId"], "state":if self.live.load(Ordering::Acquire) { "running" } else { "stopped" },
                "interfaceName":"utun-injected", "latestHandshake":null, "rxBytes":0,
                "txBytes":0, "dnsApplied":false, "warnings":[]
            })),
            method::WIREGUARD_DISCONNECT => {
                if self.reject_stop.load(Ordering::Acquire) {
                    return Err(HelperError::Rejected(
                        net_manager_core::daemon_protocol::ErrorBody {
                            code: net_manager_core::daemon_protocol::ErrorCode::Busy,
                            message: "injected stop failure".into(),
                        },
                    ));
                }
                self.live.store(false, Ordering::Release);
                Ok(json!({"stopped":true}))
            }
            method::NET_INTENT_LIST => Ok(json!({"intents":self.intents.lock().unwrap().clone()})),
            method::NET_INTENT_SET => {
                let id = params["id"].as_str().unwrap();
                let mut intents = self.intents.lock().unwrap();
                intents.retain(|intent| intent["id"] != id);
                intents.push(json!({
                    "id":id, "destinations":params["destinations"], "path":params["path"],
                    "metric":5, "enabled":true, "status":"effective",
                    "detail":"1 route(s) in place", "installed":1, "wanted":1
                }));
                Ok(json!({"id":id}))
            }
            method::NET_INTENT_DEL => {
                let id = params["id"].as_str().unwrap();
                self.intents
                    .lock()
                    .unwrap()
                    .retain(|intent| intent["id"] != id);
                Ok(json!({"id":id}))
            }
            _ => Err(HelperError::Protocol(
                "unexpected injected helper operation".into(),
            )),
        }
    }
    fn log_dir(&self) -> PathBuf {
        PathBuf::new()
    }
}

#[test]
fn static_profile_without_config_uses_real_owner_and_helper_intents() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, _, store, _) = shared_fixture(temp.path());
    let helper = Arc::new(RuntimeHelperProbe::default());
    owner.privileged = helper.clone();
    let profile = Profile {
        id: "static".into(),
        name: "Saved static routes".into(),
        backend: TunnelBackend::None,
        interface_name: "en97".into(),
        wait_for_interface: true,
        routes: vec![net_manager_core::models::PolicyRoute {
            destination: "192.0.2.0/24".parse().unwrap(),
            metric: 5,
            via: None,
        }],
        ..Default::default()
    };
    assert!(profile.config_path.as_os_str().is_empty());
    store
        .save(&net_manager_core::profiles::ProfileDocument {
            version: 1,
            profiles: vec![profile.clone()],
        })
        .unwrap();
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let first = shared_client(temp.path(), &server);
    let second = shared_client(temp.path(), &server);
    first.connect(&store, &profile, None).unwrap();
    assert!(second.is_running(&profile).unwrap());
    first.shutdown(std::slice::from_ref(&profile)).unwrap();
    drop(first);
    assert!(second.is_running(&profile).unwrap());
    second
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
    assert!(helper.intents.lock().unwrap().is_empty());
    assert!(!second.is_running(&profile).unwrap());
}

#[test]
fn root_executor_disconnect_returns_snapshot_without_creating_user_session_or_root() {
    use std::sync::atomic::Ordering;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("must-remain-absent");
    let helper = Arc::new(RuntimeHelperProbe::default());
    helper.live.store(true, Ordering::Release);
    let mut engine = Engine::with_privileged(&root, helper.clone());
    engine.test_root_executor = true;
    let profile = Profile {
        id: "root-vpn".into(),
        backend: TunnelBackend::WireGuard,
        ..Default::default()
    };
    let snapshot = engine
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
    assert_eq!(snapshot.statuses[0].state, TunnelState::Stopped);
    assert!(snapshot.system_proxy_owner.is_none());
    assert!(engine.session_slot().unwrap().lock().unwrap().is_none());
    assert!(!root.exists());
    assert!(!helper.live.load(Ordering::Acquire));
}

#[test]
fn restart_stop_failure_never_runs_client_mutation_or_loses_live_helper_activation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, _, store, _) = shared_fixture(temp.path());
    let helper = Arc::new(RuntimeHelperProbe::default());
    helper.live.store(true, Ordering::Release);
    helper.reject_stop.store(true, Ordering::Release);
    owner.privileged = helper.clone();
    let config = ConfigVault::new(temp.path().join("configs"))
        .store_wireguard_config("wg", b"[Interface]\nPrivateKey = injected\n")
        .unwrap();
    let profile = Profile {
        id: "wg".into(),
        backend: TunnelBackend::WireGuard,
        config_path: config.config_path,
        ..Default::default()
    };
    store
        .save(&net_manager_core::profiles::ProfileDocument {
            version: 1,
            profiles: vec![profile.clone()],
        })
        .unwrap();
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let client = shared_client(temp.path(), &server);
    let changed = AtomicBool::new(false);
    let error = client
        .restart_around(&store, &profile.id, || {
            changed.store(true, Ordering::Release);
            Ok(())
        })
        .unwrap_err();
    assert!(error.contains("injected stop failure"));
    assert!(!changed.load(Ordering::Acquire));
    assert!(client.is_running(&profile).unwrap());
}

#[test]
fn failed_client_change_restarts_saved_connection_and_preserves_original_error_and_proxy() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, profile, store, probe) = shared_fixture(temp.path());
    let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
    let client = shared_client(temp.path(), &server);
    client.connect(&store, &profile, None).unwrap();
    client
        .set_system_proxy(&profile, std::slice::from_ref(&profile), true)
        .unwrap();
    let error = client
        .restart_around(&store, &profile.id, || {
            Err::<(), _>("injected client mutation failure".into())
        })
        .unwrap_err();
    assert_eq!(error, "injected client mutation failure");
    assert!(client.is_running(&profile).unwrap());
    assert_eq!(
        client.system_proxy_owner().unwrap().as_deref(),
        Some(profile.id.as_str())
    );
    assert_eq!(probe.lock().unwrap().restored, 0);
    client
        .disconnect(&profile, std::slice::from_ref(&profile))
        .unwrap();
}

#[test]
fn reconnect_failure_restores_proxy_or_retains_failed_restore_for_explicit_cleanup() {
    for fail_restore in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (owner, profile, store, probe) = shared_fixture(temp.path());
        let executable = owner.test_executable.clone().unwrap();
        let server = macos_session::TestServer::start(temp.path(), OwnerBackend { engine: owner });
        let client = shared_client(temp.path(), &server);
        client.connect(&store, &profile, None).unwrap();
        client
            .set_system_proxy(&profile, std::slice::from_ref(&profile), true)
            .unwrap();
        let error = client
            .restart_around(&store, &profile.id, || {
                probe.lock().unwrap().fail_restore = fail_restore;
                std::fs::write(&executable, "#!/bin/sh\nexit 42\n").unwrap();
                Err::<(), _>("injected change failure".into())
            })
            .unwrap_err();
        assert!(error.contains("injected change failure"));
        assert!(!client.is_running(&profile).unwrap());
        assert_eq!(client.system_proxy_owner().unwrap().is_some(), fail_restore);
        let retained = net_manager_core::system_proxy::load_ownership(
            &temp.path().join("runtime/system-proxy.json"),
        )
        .unwrap();
        assert_eq!(retained.is_some(), fail_restore);
        if fail_restore {
            probe.lock().unwrap().fail_restore = false;
            client
                .disconnect(&profile, std::slice::from_ref(&profile))
                .unwrap();
        }
        assert!(client.system_proxy_owner().unwrap().is_none());
        assert!(probe.lock().unwrap().restored >= 1);
    }
}
