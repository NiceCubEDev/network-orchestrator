use super::*;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Runtime {
    events: Arc<Mutex<Vec<String>>>,
    running: Arc<Mutex<Vec<String>>>,
    needs: crate::macos_credentials::CredentialRequirements,
}
impl BusinessRuntime for Runtime {
    fn is_running(&self, _root: &Path, profile: &Profile) -> Result<bool, String> {
        Ok(self.running.lock().unwrap().contains(&profile.id))
    }
    fn restart_around<T>(
        &self,
        root: &Path,
        _store: &ProfileStore,
        id: &str,
        change: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        crate::macos_transaction::with_root_lock(root, || {
            self.events.lock().unwrap().push(format!("stop:{id}"));
            let result = change();
            self.events.lock().unwrap().push(format!("restart:{id}"));
            result
        })
    }
    fn connect(
        &self,
        _root: &Path,
        _store: &ProfileStore,
        profile: &Profile,
        _credentials: Option<OpenVpnCredentials>,
    ) -> Result<(), String> {
        self.events
            .lock()
            .unwrap()
            .push(format!("connect:{}", profile.id));
        if profile.id == "fail" {
            return Err("Connection failed".into());
        }
        self.running.lock().unwrap().push(profile.id.clone());
        Ok(())
    }
    fn disconnect(&self, _root: &Path, profile: &Profile, _all: &[Profile]) -> Result<(), String> {
        self.events
            .lock()
            .unwrap()
            .push(format!("disconnect:{}", profile.id));
        self.running.lock().unwrap().retain(|id| id != &profile.id);
        Ok(())
    }
    fn credential_requirements(
        &self,
        _: &Path,
        _: &Profile,
    ) -> Result<crate::macos_credentials::CredentialRequirements, String> {
        Ok(self.needs)
    }
    fn intents(&self, _: &Path) -> Result<Vec<NetIntentView>, String> {
        Ok(vec![])
    }
    fn set_intent(&self, _: &Path, params: NetIntentSetParams) -> Result<(), String> {
        self.events
            .lock()
            .unwrap()
            .push(format!("intent:{}", params.id));
        if params.id == "bad" {
            Err("Intent failed".into())
        } else {
            Ok(())
        }
    }
}
fn service(root: &Path) -> MacosServices<Runtime> {
    MacosServices::with_runtime(root, Runtime::default()).unwrap()
}
fn share(s: &MacosServices<Runtime>, id: &str) {
    s.import_share_link(ShareLinkImport {
        id: id.into(),
        name: id.into(),
        link: "vless://private-token@example.test:443?security=tls#Node".into(),
    })
    .unwrap();
}
fn server(bodies: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/secret-path", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        bodies.into_iter().map(|body| {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = [0;4096];
        let size = stream.read(&mut bytes).unwrap();
        write!(stream, "HTTP/1.1 200 OK\r\nprofile-title: Private Panel\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        String::from_utf8_lossy(&bytes[..size]).to_lowercase()
    }).collect()
    });
    (url, worker)
}
#[test]
fn public_profiles_imports_validation_and_order_are_real_portable_logic() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    share(&s, "a");
    share(&s, "b");
    assert!(s
        .public_profiles()
        .unwrap()
        .iter()
        .all(|p| p.xray_mode == XrayMode::Socks));
    let public = serde_json::to_string(&s.public_profiles().unwrap()).unwrap();
    assert!(
        !public.contains("private-token")
            && !public.contains("configs/")
            && !public.contains("vless://")
    );
    assert_eq!(
        s.reorder_profiles(TunnelBackend::Xray, &["b".into(), "a".into()])
            .unwrap()[0]
            .id,
        "b"
    );
    assert!(s
        .reorder_profiles(TunnelBackend::Xray, &["b".into()])
        .is_err());
    assert!(s.rename_profile("a", "  ").is_err());
    assert_eq!(s.rename_profile("a", " New ").unwrap().name, "New");
    assert!(s
        .import_share_link(ShareLinkImport {
            id: "bad".into(),
            name: "bad".into(),
            link: "vless://secret-path".into()
        })
        .unwrap_err()
        .contains("Invalid or unsupported"));
    assert!(!dir.path().join("configs/bad").exists());
    s.delete_profile("a").unwrap();
    assert!(!dir.path().join("configs/a").exists());
}
#[test]
fn typed_mutations_restart_inside_one_transaction_and_preserve_other_fields() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    share(&s, "p");
    s.set_auto_connect("p", true).unwrap();
    s.set_wait_for_interface("p", true).unwrap();
    s.set_xray_mode("p", XrayMode::Tun).unwrap();
    s.set_tunnel_role("p", TunnelRole::Secondary).unwrap();
    s.set_tunnel_networks(
        "p",
        vec!["10.0.0.0/8".parse().unwrap()],
        vec!["corp.test".into()],
    )
    .unwrap();
    let p = s.profile("p").unwrap();
    assert!(p.auto_connect && p.wait_for_interface);
    assert_eq!(p.xray_mode, XrayMode::Tun);
    assert_eq!(p.tunnel_role, TunnelRole::Secondary);
    assert_eq!(p.tunnel_dns_domains, ["corp.test"]);
    assert_eq!(
        *s.runtime.events.lock().unwrap(),
        [
            "stop:p",
            "restart:p",
            "stop:p",
            "restart:p",
            "stop:p",
            "restart:p"
        ]
    );
    assert!(s
        .set_tunnel_networks("p", vec![], vec!["bad..test".into()])
        .is_err());
    assert_eq!(s.profile("p").unwrap().tunnel_dns_domains, ["corp.test"]);
}
#[test]
fn failed_config_analysis_preserves_existing_profile_and_managed_config() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    share(&s, "retained");
    let retained = s.profile("retained").unwrap();
    let retained_config = std::fs::read(&retained.config_path).unwrap();
    let path = dir.path().join("source.json");
    std::fs::write(&path, "not JSON: private-token").unwrap();
    assert!(s
        .import_config(ConfigImport {
            id: "bad".into(),
            name: "Bad".into(),
            backend: TunnelBackend::Xray,
            path
        })
        .is_err());
    assert_eq!(
        s.public_profiles()
            .unwrap()
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        ["retained"]
    );
    assert_eq!(
        s.profile("retained").unwrap().config_path,
        retained.config_path
    );
    assert_eq!(
        std::fs::read(&retained.config_path).unwrap(),
        retained_config
    );
}
#[test]
fn subscriptions_refetch_hwid_record_failures_redact_and_validate_probes() {
    let body = "vless://private-token@a.test:443?security=tls#A";
    let (url, worker) = server(vec![
        body.into(),
        format!("{body}\nvless://other-token@b.test:443?security=tls#B"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    s.import_subscription(SubscriptionImportRequest {
        id: "sub".into(),
        name: "Mine".into(),
        url,
        hwid: "private-hwid".into(),
    })
    .unwrap();
    assert_eq!(s.profile("sub").unwrap().xray_mode, XrayMode::Socks);
    assert_eq!(s.refresh_subscription("sub").unwrap().endpoint_count, 2);
    let requests = worker.join().unwrap();
    assert!(requests.iter().all(|r| r.contains("x-hwid: private-hwid")));
    let endpoints = s.subscription_endpoints("sub").unwrap();
    assert_eq!(endpoints.len(), 2);
    assert!(endpoints[0].active);
    assert!(!endpoints[0].in_pool);
    assert_eq!(
        s.measure_subscription_delay("sub", 9).unwrap_err(),
        "Invalid endpoint index"
    );
    assert_eq!(
        s.measure_subscription_delay("sub", 0).unwrap_err(),
        "Install Xray to start this connection"
    );
    s.switch_subscription_endpoint("sub", 1).unwrap();
    assert!(s.subscription_endpoints("sub").unwrap()[1].active);
    assert!(s.switch_subscription_endpoint("sub", 9).is_err());
    assert!(s.subscription_endpoints("sub").unwrap()[1].active);
    s.set_subscription_refresh_interval("sub", Some(60))
        .unwrap();
    assert!(s.set_subscription_refresh_interval("sub", Some(5)).is_err());
    assert!(s.refresh_subscription("sub").is_err());
    let public = serde_json::to_string(&s.public_profiles().unwrap()).unwrap();
    for secret in [
        "private-token",
        "other-token",
        "private-hwid",
        "secret-path",
    ] {
        assert!(!public.contains(secret));
        assert!(!s.subscription_import_log().contains(secret));
    }
    assert_eq!(
        s.profile("sub")
            .unwrap()
            .subscription
            .unwrap()
            .last_refresh_error
            .as_deref(),
        Some("Refresh failed")
    );
    assert!(s.subscription_import_log().contains("profile-title"));
    assert!(!s.subscription_import_log().contains("Private Panel"));
}
#[test]
fn routing_preserves_omitted_options_and_replays_actual_policy() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    share(&s, "p");
    let policies = vec![DomainPolicy {
        domains: vec!["domain:blocked.test".into()],
        target: DomainRouteTarget::Block,
    }];
    s.set_profile_routing(
        "p",
        ProfileRoutingUpdate {
            policies: policies.clone(),
            private_lan_direct: true,
            advanced: Some(AdvancedRouting {
                domain_strategy: Some(XrayDomainStrategy::AsIs),
                domain_matcher: Some(XrayDomainMatcher::Hybrid),
                dns: XrayDnsConfig::default(),
            }),
            geo_urls: Some(GeoUrls {
                geoip_url: Some("https://example.test/geoip.dat".into()),
                geosite_url: None,
            }),
        },
    )
    .unwrap();
    s.set_profile_routing(
        "p",
        ProfileRoutingUpdate {
            policies,
            private_lan_direct: false,
            ..Default::default()
        },
    )
    .unwrap();
    let routing = s.profile_routing("p").unwrap();
    assert_eq!(routing.domain_matcher, Some(XrayDomainMatcher::Hybrid));
    assert_eq!(
        routing.geoip_url.as_deref(),
        Some("https://example.test/geoip.dat")
    );
    let verdict = s.check_routing("blocked.test", &routing).unwrap();
    assert!(serde_json::to_string(&verdict).unwrap().contains("block"));
    assert!(s
        .set_profile_routing(
            "p",
            ProfileRoutingUpdate {
                geo_urls: Some(GeoUrls {
                    geoip_url: Some("http://bad.test/secret".into()),
                    geosite_url: None
                }),
                ..Default::default()
            }
        )
        .is_err());
    assert_eq!(s.profile_routing("p").unwrap().geoip_url, routing.geoip_url);
    assert!(s.parse_happ_routing("garbage").is_err());
}
#[test]
fn static_routes_validate_before_persistence_and_preserve_gateways() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    assert!(s
        .create_static(StaticProfileCreate {
            id: "st".into(),
            name: "Static".into(),
            interface_name: "en0".into(),
            routes: vec![],
            endpoint_bypasses: vec![]
        })
        .is_err());
    let p = s
        .create_static(StaticProfileCreate {
            id: "st".into(),
            name: "Static".into(),
            interface_name: "en0".into(),
            routes: vec![PolicyRoute {
                destination: "192.0.2.0/24".parse().unwrap(),
                via: Some("192.0.2.1".parse().unwrap()),
                metric: 5,
            }],
            endpoint_bypasses: vec![],
        })
        .unwrap();
    assert_eq!(p.routes[0].via.unwrap().to_string(), "192.0.2.1");
    assert!(s.set_tunnel_role("st", TunnelRole::Primary).is_err());
}
#[test]
fn parallel_metadata_edits_do_not_lose_each_others_writes() {
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(service(dir.path()));
    share(&s, "p");
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let a = {
        let s = s.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            s.set_auto_connect("p", true).unwrap();
        })
    };
    let b = {
        let s = s.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            s.set_wait_for_interface("p", true).unwrap();
        })
    };
    barrier.wait();
    a.join().unwrap();
    b.join().unwrap();
    let p = s.profile("p").unwrap();
    assert!(p.auto_connect && p.wait_for_interface);
}

#[derive(Default)]
struct Secrets;
impl crate::macos_credentials::SecretStore for Secrets {
    fn load(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<u8>>, crate::macos_credentials::CredentialStoreError> {
        Ok(None)
    }
    fn save(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
    ) -> Result<(), crate::macos_credentials::CredentialStoreError> {
        Ok(())
    }
    fn delete(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), crate::macos_credentials::CredentialStoreError> {
        Ok(())
    }
}
#[test]
fn saved_sets_preserve_duplicate_content_missing_ids_order_and_continue_after_failure() {
    use net_manager_core::connection_sets::ConnectionSet;
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    for id in ["stop", "fail", "start"] {
        share(&s, id);
    }
    s.runtime.running.lock().unwrap().push("stop".into());
    let first = s.capture_set("one", " One ").unwrap();
    let second = s.capture_set("two", "Two").unwrap();
    assert_eq!(first.profile_ids, second.profile_ids);
    assert_eq!(
        net_manager_core::connection_sets::list(dir.path())
            .unwrap()
            .len(),
        2
    );
    let credentials = crate::macos_credentials::OpenVpnCredentialStore::new(
        dir.path(),
        dir.path(),
        Arc::new(Secrets),
    )
    .unwrap();
    let wanted = ConnectionSet {
        id: "wanted".into(),
        name: "Wanted".into(),
        profile_ids: vec!["missing".into(), "fail".into(), "start".into()],
    };
    let policy = StartPolicy {
        proxy_connections: true,
        helper_capabilities: vec![],
    };
    let outcome = s
        .apply_set(&wanted, &policy, &Default::default(), &credentials)
        .unwrap();
    assert_eq!(
        *s.runtime.events.lock().unwrap(),
        ["disconnect:stop", "connect:fail", "connect:start"]
    );
    assert_eq!(outcome.items.len(), 3);
    assert_eq!(outcome.items[1].outcome, BatchItemOutcome::Failed);
    assert_eq!(outcome.items[2].outcome, BatchItemOutcome::Succeeded);
    assert_eq!(wanted.profile_ids, ["missing", "fail", "start"]);
}
#[test]
fn auto_connect_is_explicit_and_continues_with_unavailable_and_running_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    for id in ["skip", "running", "fail", "ok"] {
        share(&s, id);
    }
    for id in ["running", "fail", "ok"] {
        s.set_auto_connect(id, true).unwrap();
    }
    s.runtime.running.lock().unwrap().push("running".into());
    let credentials = crate::macos_credentials::OpenVpnCredentialStore::new(
        dir.path(),
        dir.path(),
        Arc::new(Secrets),
    )
    .unwrap();
    let outcome = s
        .auto_connect(
            &StartPolicy {
                proxy_connections: true,
                helper_capabilities: vec![],
            },
            &Default::default(),
            &credentials,
        )
        .unwrap();
    assert_eq!(outcome.items.len(), 3);
    assert_eq!(outcome.items[0].outcome, BatchItemOutcome::SkippedRunning);
    assert_eq!(
        *s.runtime.events.lock().unwrap(),
        ["connect:fail", "connect:ok"]
    );
    assert!(s
        .disconnect_all()
        .unwrap()
        .items
        .iter()
        .all(|i| i.outcome == BatchItemOutcome::Succeeded));
}

#[test]
fn happ_import_merges_only_fields_present_in_the_export() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    share(&s, "p");
    s.set_profile_routing(
        "p",
        ProfileRoutingUpdate {
            policies: vec![],
            private_lan_direct: true,
            advanced: Some(AdvancedRouting {
                domain_strategy: Some(XrayDomainStrategy::AsIs),
                domain_matcher: Some(XrayDomainMatcher::Hybrid),
                dns: XrayDnsConfig::default(),
            }),
            geo_urls: Some(GeoUrls {
                geoip_url: Some("https://example.test/ip.dat".into()),
                geosite_url: None,
            }),
        },
    )
    .unwrap();
    s.import_happ_routing(
        "p",
        r#"{"Name":"Test","ProxySites":["domain:example.test"]}"#,
    )
    .unwrap();
    let routing = s.profile_routing("p").unwrap();
    assert!(routing.private_lan_direct);
    assert_eq!(routing.domain_matcher, Some(XrayDomainMatcher::Hybrid));
    assert_eq!(
        routing.geoip_url.as_deref(),
        Some("https://example.test/ip.dat")
    );
}

#[test]
fn eligibility_uses_shared_mode_but_running_profiles_remain_stoppable() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    share(&s, "p");
    crate::macos_state::SettingsStore::new(dir.path())
        .set_app_mode(crate::macos_state::AppMode::Orchestrator)
        .unwrap();
    let policy = StartPolicy {
        proxy_connections: true,
        helper_capabilities: vec![],
    };
    let stopped = s.start_eligibilities_with_policy(&policy).unwrap();
    assert!(stopped[0].mode_blocked);
    assert!(!stopped[0].can_start);
    s.runtime.running.lock().unwrap().push("p".into());
    let running = s.start_eligibilities_with_policy(&policy).unwrap();
    assert!(!running[0].mode_blocked);
    assert!(running[0].can_start);
}
#[test]
fn disconnect_set_leaves_unrelated_running_profiles_alone() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    for id in ["one", "other"] {
        share(&s, id);
        s.runtime.running.lock().unwrap().push(id.into());
    }
    let set = net_manager_core::connection_sets::ConnectionSet {
        id: "set".into(),
        name: "Set".into(),
        profile_ids: vec!["missing".into(), "one".into()],
    };
    s.disconnect_set(&set).unwrap();
    assert_eq!(*s.runtime.events.lock().unwrap(), ["disconnect:one"]);
    assert_eq!(*s.runtime.running.lock().unwrap(), ["other"]);
}

#[test]
fn openvpn_import_preserves_routes_and_reports_only_safe_asset_errors() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    let path = dir.path().join("client.ovpn");
    std::fs::write(
        &path,
        "client\nremote vpn.example\nroute 10.20.0.0 255.255.0.0\n",
    )
    .unwrap();
    let imported = s
        .import_config(ConfigImport {
            id: "ovpn".into(),
            name: "VPN".into(),
            backend: TunnelBackend::OpenVpn,
            path: path.clone(),
        })
        .unwrap();
    assert_eq!(imported.routes[0].destination.to_string(), "10.20.0.0/16");
    assert!(imported.config_path.as_os_str().is_empty());
    let retained_path = s.profile("ovpn").unwrap().config_path;
    for (body, expected) in [
        (
            "client\nremote vpn.example\nroute 10.0.0.0 255.0.0.0 net_gateway\n",
            "unsupported OpenVPN route directive",
        ),
        (
            "client\nremote vpn.example\npkcs12 missing-private-secret.p12\n",
            "OpenVPN referenced asset is missing",
        ),
    ] {
        std::fs::write(&path, body).unwrap();
        assert_eq!(
            s.import_config(ConfigImport {
                id: "bad".into(),
                name: "Bad".into(),
                backend: TunnelBackend::OpenVpn,
                path: path.clone()
            })
            .unwrap_err(),
            expected
        );
        assert_eq!(
            s.public_profiles()
                .unwrap()
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>(),
            ["ovpn"]
        );
        assert_eq!(s.profile("ovpn").unwrap().config_path, retained_path);
        assert_eq!(
            s.inspect_profile("ovpn").unwrap().os_routes[0]
                .destination
                .to_string(),
            "10.20.0.0/16"
        );
    }
}
#[test]
fn hwid_is_stable_and_proxy_exports_never_expose_connection_input() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    assert_eq!(
        s.generate_subscription_hwid().unwrap(),
        s.generate_subscription_hwid().unwrap()
    );
    assert_eq!(s.generate_subscription_hwid().unwrap().len(), 36);
    share(&s, "p");
    let exports = s.proxy_exports("p").unwrap();
    assert!(exports.shell.contains("ALL_PROXY=socks5h://127.0.0.1:"));
    assert!(!serde_json::to_string(&exports)
        .unwrap()
        .contains("private-token"));
    assert_eq!(
        s.measure_subscription_delays("p").unwrap_err(),
        "Delay checks are available for subscriptions"
    );
    assert_eq!(
        s.check_exit_ip(ExitIpVia::Profile("p".into())).unwrap_err(),
        "Start the connection first"
    );
}
#[test]
fn known_endpoints_are_literal_only_and_inspection_is_typed() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    share(&s, "named");
    s.import_share_link(ShareLinkImport {
        id: "literal".into(),
        name: "Literal".into(),
        link: "vless://private-token@203.0.113.7:443?security=tls#Literal".into(),
    })
    .unwrap();
    let mut profiles = s.store().load().unwrap().profiles;
    profiles[0].endpoint_bypasses = vec!["198.51.100.9".into(), "name.example".into()];
    let ips = known_endpoints(&profiles)
        .into_iter()
        .map(|e| e.ip.to_string())
        .collect::<Vec<_>>();
    assert_eq!(ips, ["198.51.100.9", "203.0.113.7"]);
    let inspection = s.inspect_profile("named").unwrap();
    assert_eq!(inspection.listeners.len(), 2);
    assert!(inspection
        .listeners
        .iter()
        .all(|l| l.address == "127.0.0.1"));
    assert!(s.inspect_profile("missing").is_err());
}

#[derive(Default)]
struct MemorySecrets {
    writes: Mutex<Vec<Vec<u8>>>,
}
impl crate::macos_credentials::SecretStore for MemorySecrets {
    fn load(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<u8>>, crate::macos_credentials::CredentialStoreError> {
        Ok(None)
    }
    fn save(
        &self,
        _: &str,
        _: &str,
        secret: &[u8],
    ) -> Result<(), crate::macos_credentials::CredentialStoreError> {
        self.writes.lock().unwrap().push(secret.to_vec());
        Ok(())
    }
    fn delete(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), crate::macos_credentials::CredentialStoreError> {
        Ok(())
    }
}
#[test]
fn connect_orchestration_remembers_only_after_success_and_never_serializes_secrets() {
    use crate::macos_credentials::CredentialRequirements;
    let dir = tempfile::tempdir().unwrap();
    let s = MacosServices::with_runtime(
        dir.path(),
        Runtime {
            needs: CredentialRequirements {
                user_pass: true,
                key_passphrase: false,
            },
            ..Default::default()
        },
    )
    .unwrap();
    share(&s, "ok");
    share(&s, "fail");
    let backend = Arc::new(MemorySecrets::default());
    let credentials = crate::macos_credentials::OpenVpnCredentialStore::new(
        dir.path(),
        dir.path(),
        backend.clone(),
    )
    .unwrap();
    let input = || {
        Some(OpenVpnCredentials {
            auth_user_pass: Some(net_manager_core::daemon_protocol::OpenVpnUserPass {
                username: "private-user".into(),
                password: "private-password".into(),
            }),
            private_key_passphrase: None,
        })
    };
    assert!(matches!(
        s.connect_profile("ok", None, false, &credentials).unwrap(),
        ConnectProfileOutcome::CredentialsRequired { .. }
    ));
    assert!(s
        .connect_profile("fail", input(), true, &credentials)
        .is_err());
    assert!(backend.writes.lock().unwrap().is_empty());
    let outcome = s
        .connect_profile("ok", input(), true, &credentials)
        .unwrap();
    assert_eq!(backend.writes.lock().unwrap().len(), 1);
    let public = serde_json::to_string(&outcome).unwrap();
    assert!(!public.contains("private-user") && !public.contains("private-password"));
    assert!(public.contains("\"remembered\":true"));
}
struct Network;
impl crate::macos_network::NetworkBackend for Network {
    fn interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        Ok(vec![])
    }
    fn routes(&self) -> Result<Vec<RouteEntry>, String> {
        Ok(vec![RouteEntry {
            destination: "0.0.0.0".parse().unwrap(),
            prefix_len: 0,
            gateway: None,
            interface_index: 1,
            interface_name: "utun5".into(),
            metric: 0,
        }])
    }
}
#[test]
fn snapshot_and_intent_doctor_use_injected_network_with_real_profile_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let s = MacosServices::with_network(
        dir.path(),
        Runtime::default(),
        crate::macos_network::MacNetwork::with_backend(dir.path(), Arc::new(Network)),
    )
    .unwrap();
    s.import_share_link(ShareLinkImport {
        id: "literal".into(),
        name: "Literal".into(),
        link: "vless://private-token@203.0.113.7:443?security=tls#Literal".into(),
    })
    .unwrap();
    let snapshot = s.network_snapshot().unwrap();
    assert!(snapshot.network_error.is_none());
    assert_eq!(snapshot.routes[0].interface_name, "utun5");
    assert!(!serde_json::to_string(&snapshot)
        .unwrap()
        .contains("private-token"));
    let suggestions = s.intent_suggestions().unwrap();
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].endpoints, ["203.0.113.7"]);
    let mut fixes = suggestions[0].fixes.clone();
    let mut bad = fixes[0].clone();
    bad.id = "bad".into();
    fixes.push(bad);
    let mut unattempted = fixes[0].clone();
    unattempted.id = "never".into();
    fixes.push(unattempted);
    let applied = s.apply_intent_fixes(&fixes).unwrap();
    assert_eq!(applied.applied, 1);
    assert_eq!(applied.error.as_deref(), Some("Intent failed"));
    assert!(!s
        .runtime
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event == "intent:never"));
}

#[test]
fn due_refresh_skips_running_but_explicit_refresh_visits_all_and_continues() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    for id in ["one", "two"] {
        let (url, worker) = server(vec![
            "vless://private-token@example.test:443?security=tls#Node".into(),
        ]);
        s.import_subscription(SubscriptionImportRequest {
            id: id.into(),
            name: id.into(),
            url,
            hwid: String::new(),
        })
        .unwrap();
        worker.join().unwrap();
        s.set_subscription_refresh_interval(id, Some(60)).unwrap();
        s.runtime.running.lock().unwrap().push(id.into());
    }
    let due = s.refresh_subscriptions(true, u64::MAX).unwrap();
    assert_eq!(due.items.len(), 2);
    assert!(due
        .items
        .iter()
        .all(|i| i.outcome == BatchItemOutcome::SkippedRunning));
    let explicit = s.refresh_subscriptions(false, u64::MAX).unwrap();
    assert_eq!(
        explicit
            .items
            .iter()
            .map(|i| i.profile_id.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
    assert!(explicit
        .items
        .iter()
        .all(|i| i.outcome == BatchItemOutcome::Failed));
    for id in ["one", "two"] {
        assert_eq!(
            s.profile(id)
                .unwrap()
                .subscription
                .unwrap()
                .last_refresh_error
                .as_deref(),
            Some("Refresh failed")
        );
    }
}

/// Opt-in managed native probe, preserved from the bridge business tests.
#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn live_delay_probe_measures_reachable_and_unreachable_servers() {
    let Ok(archive) = std::env::var("NETORCH_XRAY_ARCHIVE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let engine = crate::Engine::new(root);
    engine.install_xray(Some(&archive)).unwrap();
    let server_binary = root.join("xray-server");
    std::fs::copy(engine.managed_executable().unwrap(), &server_binary).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let uuid = "6f1d1b8e-3c2a-4d5e-9f00-112233445566";
    std::fs::write(root.join("server.json"),format!(r#"{{"inbounds":[{{"listen":"127.0.0.1","port":{port},"protocol":"vless","settings":{{"clients":[{{"id":"{uuid}"}}],"decryption":"none"}},"streamSettings":{{"network":"tcp","security":"none"}}}}],"outbounds":[{{"protocol":"freedom"}}]}}"#)).unwrap();
    let mut process = std::process::Command::new(&server_binary)
        .args(["run", "-c"])
        .arg(root.join("server.json"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let (url,worker)=server(vec![format!("vless://{uuid}@127.0.0.1:{port}?security=none&type=tcp#Loopback\nvless://{uuid}@127.0.0.1:1?security=none&type=tcp#Closed")]);
    let s = MacosServices::new(root).unwrap();
    s.import_subscription(SubscriptionImportRequest {
        id: "sub".into(),
        name: String::new(),
        url,
        hwid: String::new(),
    })
    .unwrap();
    worker.join().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let delays = s.measure_subscription_delays("sub");
    process.kill().unwrap();
    process.wait().unwrap();
    let delays = delays.unwrap();
    assert!(delays[0].delay_ms.is_some());
    assert!(delays[1].delay_ms.is_none());
}

#[test]
fn batch_credentials_required_preserves_safe_prompt_for_frontend_presentation() {
    let dir = tempfile::tempdir().unwrap();
    let s = MacosServices::with_runtime(
        dir.path(),
        Runtime {
            needs: crate::macos_credentials::CredentialRequirements {
                user_pass: true,
                key_passphrase: true,
            },
            ..Default::default()
        },
    )
    .unwrap();
    share(&s, "p");
    s.set_auto_connect("p", true).unwrap();
    let credentials = crate::macos_credentials::OpenVpnCredentialStore::new(
        dir.path(),
        dir.path(),
        Arc::new(Secrets),
    )
    .unwrap();
    let policy = StartPolicy {
        proxy_connections: true,
        helper_capabilities: vec![],
    };
    let set = net_manager_core::connection_sets::ConnectionSet {
        id: "set".into(),
        name: "Set".into(),
        profile_ids: vec!["p".into()],
    };
    for outcome in [
        s.apply_set(&set, &policy, &Default::default(), &credentials)
            .unwrap(),
        s.auto_connect(&policy, &Default::default(), &credentials)
            .unwrap(),
    ] {
        assert_eq!(
            outcome.items[0].outcome,
            BatchItemOutcome::CredentialsRequired
        );
        let prompt = outcome.items[0].credential_prompt.as_ref().unwrap();
        assert!(prompt.needs.user_pass && prompt.needs.key_passphrase);
        assert!(!prompt.rejected);
        let public = serde_json::to_value(&outcome).unwrap();
        assert_eq!(
            public["items"][0]["credentialPrompt"]["needs"]["userPass"],
            true
        );
        assert!(public["items"][0].get("username").is_none());
    }
    assert!(s.runtime.events.lock().unwrap().is_empty());
}

#[test]
fn constructors_normalize_missing_roots_without_creating_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("missing/data");
    let expected = crate::macos_transaction::normalized_root_path(&root, None).unwrap();
    let s = MacosServices::new(&root).unwrap();
    assert_eq!(s.root(), expected);
    assert!(s.public_profiles().unwrap().is_empty());
    assert!(!root.exists());
    let injected = MacosServices::with_runtime(&root, Runtime::default()).unwrap();
    assert_eq!(injected.root(), expected);
    let network = crate::macos_network::MacNetwork::with_backend(&root, Arc::new(Network));
    assert_eq!(
        MacosServices::with_network(&root, Runtime::default(), network)
            .unwrap()
            .root(),
        expected
    );
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    assert!(MacosServices::new(Path::new("relative")).is_err());
}
#[test]
fn constructors_and_profile_parent_normalization_reject_user_directory_links() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let alias = dir.path().join("alias");
    symlink(&real, &alias).unwrap();
    assert!(MacosServices::new(&alias).is_err());
    assert!(MacosServices::new(alias.join("missing")).is_err());
    assert!(MacosServices::with_runtime(&alias, Runtime::default()).is_err());
    let network = crate::macos_network::MacNetwork::with_backend(&alias, Arc::new(Network));
    assert!(MacosServices::with_network(&alias, Runtime::default(), network).is_err());
    let mut profile = Profile {
        id: "p".into(),
        backend: TunnelBackend::Xray,
        config_path: alias.join("config.json"),
        ..Default::default()
    };
    assert!(normalize_profile_path(&mut profile, None).is_err());
    let mut empty = Profile::default();
    normalize_profile_path(&mut empty, None).unwrap();
    assert!(empty.config_path.as_os_str().is_empty());
}
#[test]
fn normalized_profile_path_never_follows_configuration_leaf_links() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    share(&s, "p");
    let mut profile = s.profile("p").unwrap();
    let leaf = profile.config_path.clone();
    let target = dir.path().join("private-input.json");
    std::fs::write(&target, r#"{"outbounds":[]}"#).unwrap();
    std::fs::remove_file(&leaf).unwrap();
    symlink(&target, &leaf).unwrap();
    assert!(normalize_profile_path(&mut profile, None).is_err());
    assert_eq!(profile.config_path, leaf);
    assert!(s.inspect_profile("p").is_err());
    assert!(std::fs::symlink_metadata(leaf)
        .unwrap()
        .file_type()
        .is_symlink());
}
#[test]
#[cfg(target_os = "macos")]
fn trusted_macos_root_aliases_normalize_profiles_without_touching_leaf_names() {
    let dir = tempfile::Builder::new()
        .prefix("netorch-alias-")
        .tempdir_in("/tmp")
        .unwrap();
    let s = service(dir.path());
    share(&s, "p");
    let mut profile = s.profile("p").unwrap();
    let normalized = profile.config_path.clone();
    let alias = PathBuf::from("/tmp").join(normalized.strip_prefix("/private/tmp").unwrap());
    profile.config_path = alias;
    s.store().upsert(profile.clone()).unwrap();
    normalize_profile_path(&mut profile, None).unwrap();
    assert_eq!(profile.config_path, normalized);
    assert_eq!(s.profile("p").unwrap().config_path, normalized);
    assert!(s.inspect_profile("p").is_ok());
}

#[test]
fn macos_file_import_defaults_to_loopback_on_every_build_host() {
    let dir = tempfile::tempdir().unwrap();
    let s = service(dir.path());
    let path = dir.path().join("source.json");
    std::fs::write(&path, r#"{"outbounds":[{"protocol":"freedom"}]}"#).unwrap();
    let profile = s
        .import_config(ConfigImport {
            id: "file".into(),
            name: "File".into(),
            backend: TunnelBackend::Xray,
            path,
        })
        .unwrap();
    assert_eq!(profile.xray_mode, XrayMode::Socks);
    assert_eq!(s.profile("file").unwrap().xray_mode, XrayMode::Socks);
}
