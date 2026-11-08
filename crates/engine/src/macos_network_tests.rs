use super::*;
use std::sync::Mutex;

#[derive(Default)]
struct FakeNetwork {
    calls: Mutex<Vec<String>>,
    services: Vec<ExternalVpn>,
    list_error: bool,
}
impl NetworkBackend for FakeNetwork {
    fn external_vpns(&self) -> Result<Vec<ExternalVpn>, String> {
        if self.list_error {
            return Err("VPN services could not be listed".into());
        }
        Ok(self.services.clone())
    }
    fn set_external_vpn(&self, id: &str, connect: bool) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("native:{id}:{connect}"));
        Ok(())
    }
    fn tailscale_status(&self) -> Result<TailscaleState, String> {
        Ok(serde_json::from_str(r#"{"installed":true,"state":"connected"}"#).unwrap())
    }
    fn tailscale_control(&self, connect: bool) -> Result<TailscaleState, String> {
        self.calls.lock().unwrap().push(format!("cli:{connect}"));
        self.tailscale_status()
    }
    fn dns_config(&self) -> Result<DnsConfig, String> {
        Ok(net_manager_core::dns_diag::parse_scutil_dns("DNS configuration\nresolver #1\n nameserver[0] : 192.0.2.53\nresolver #2\n domain : corp.example\n nameserver[0] : 10.0.0.53\n port : 5353\n"))
    }
    fn dns_query(
        &self,
        hostname: &str,
        target: SocketAddr,
        family: DnsFamily,
    ) -> Result<DnsProbeResult, String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("dns:{hostname}:{target}:{family:?}"));
        Ok(DnsProbeResult {
            server: target.ip(),
            port: target.port(),
            status: "NOERROR".into(),
            answers: vec!["192.0.2.1".into()],
            truncated: false,
            fake_pool: false,
            rtt_ms: 2,
        })
    }
    fn routes(&self) -> Result<Vec<RouteEntry>, String> {
        Ok(vec![RouteEntry {
            destination: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
            gateway: None,
            interface_index: 7,
            interface_name: "utun7".into(),
            metric: 0,
        }])
    }
    fn primary_interface(&self) -> Result<Option<String>, String> {
        Ok(Some("utun7".into()))
    }
}

#[test]
fn native_tailscale_service_is_preferred_for_both_directions() {
    let backend = Arc::new(FakeNetwork {
        services: vec![ExternalVpn {
            id: "11111111-2222-3333-4444-555555555555".into(),
            name: "Tailscale".into(),
            state: "disconnected".into(),
            provider: Some("io.tailscale.ipn.macsys".into()),
            enabled: true,
        }],
        ..Default::default()
    });
    let network = MacNetwork::with_backend("/unused", backend.clone());
    assert_eq!(
        network.tailscale_up().unwrap().control,
        TailscaleControl::NativeService
    );
    assert_eq!(
        network.tailscale_down().unwrap().control,
        TailscaleControl::NativeService
    );
    assert_eq!(
        *backend.calls.lock().unwrap(),
        vec![
            "native:11111111-2222-3333-4444-555555555555:true",
            "native:11111111-2222-3333-4444-555555555555:false"
        ]
    );
}

#[test]
fn missing_native_service_uses_cli_and_invalid_id_never_reaches_io() {
    let backend = Arc::new(FakeNetwork::default());
    let network = MacNetwork::with_backend("/unused", backend.clone());
    assert_eq!(
        network.tailscale_up().unwrap().control,
        TailscaleControl::Cli
    );
    assert!(network.set_external_vpn("--evil", true).is_err());
    assert_eq!(*backend.calls.lock().unwrap(), vec!["cli:true"]);
}

#[test]
fn dns_probe_selects_system_suffix_and_reports_route_without_host_io() {
    let backend = Arc::new(FakeNetwork::default());
    let network = MacNetwork::with_backend("/unused", backend.clone());
    let answer = network
        .dns_probe(&DnsProbeRequest {
            hostname: "app.corp.example".into(),
            server: None,
            family: DnsFamily::Aaaa,
        })
        .unwrap();
    assert_eq!(answer.resolver_index, Some(2));
    assert_eq!(answer.resolver_domain.as_deref(), Some("corp.example"));
    assert_eq!(answer.path.unwrap().interface_name, "utun7");
    assert_eq!(
        *backend.calls.lock().unwrap(),
        vec!["dns:app.corp.example:10.0.0.53:5353:Aaaa"]
    );
}

#[test]
fn dns_explicit_server_bypasses_system_selection_and_invalid_name_never_queries() {
    let backend = Arc::new(FakeNetwork::default());
    let network = MacNetwork::with_backend("/unused", backend.clone());
    let mut request = DnsProbeRequest {
        hostname: "app.corp.example".into(),
        server: Some("2001:db8::53".parse().unwrap()),
        family: DnsFamily::A,
    };
    let answer = network.dns_probe(&request).unwrap();
    assert_eq!(answer.resolver_index, None);
    assert_eq!(answer.probe.port, 53);
    request.hostname = "invalid name".into();
    assert!(network.dns_probe(&request).is_err());
    assert_eq!(backend.calls.lock().unwrap().len(), 1);
}

#[test]
fn primary_proxy_explanation_excludes_managed_tunnels() {
    let network = MacNetwork::with_backend("/unused", Arc::new(FakeNetwork::default()));
    assert!(network.proxy_override(&[]).unwrap().overridden);
    assert!(
        !network
            .proxy_override(&["utun7".into()])
            .unwrap()
            .overridden
    );
    assert_eq!(
        parse_primary_interface("<dictionary> {\n PrimaryInterface : en7\n Router : 192.0.2.1\n}"),
        Some("en7".into())
    );
}

#[test]
fn provider_status_is_typed_and_does_not_reexport_raw_secrets() {
    let state = decode_netbird(serde_json::json!({"installed":true,"state":"connected","managementUrl":"https://user:pass@vpn.example/path?token=secret#private","setupKey":"PRIVATE","peersConnected":3})).unwrap();
    let json = serde_json::to_string(&state).unwrap();
    assert!(json.contains("https://vpn.example/path"));
    for secret in ["pass", "secret", "PRIVATE", "setupKey"] {
        assert!(!json.contains(secret));
    }
    let options = NetBirdConnectOptions {
        management_url: None,
        setup_key: Some("PRIVATE".into()),
    };
    assert!(!format!("{options:?}").contains("PRIVATE"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn native_network_api_never_operates_on_non_macos_hosts() {
    let network = MacNetwork::new("/unused");
    assert!(network.interfaces().unwrap_err().contains("macOS"));
    assert!(network
        .user_network_settings()
        .unwrap_err()
        .contains("macOS"));
    assert!(network
        .netbird_up(&NetBirdConnectOptions::default())
        .unwrap_err()
        .contains("macOS"));
    assert!(network.tailscale_down().unwrap_err().contains("macOS"));
}

#[test]
fn provider_rpc_contract_preserves_types_and_redacts_debug_secrets() {
    let request = ProviderRequest::NetBirdUp {
        options: NetBirdConnectOptions {
            management_url: None,
            setup_key: Some("PRIVATE".into()),
        },
    };
    assert!(request.is_mutation());
    assert!(!format!("{request:?}").contains("PRIVATE"));
    let wire = serde_json::to_vec(&request).unwrap();
    let decoded: ProviderRequest = serde_json::from_slice(&wire).unwrap();
    assert!(decoded.is_mutation());
    assert!(!ProviderRequest::TailscaleStatus.is_mutation());
    let network = MacNetwork::with_backend("/unused", Arc::new(FakeNetwork::default()));
    let response = network
        .provider_request(ProviderRequest::TailscaleControl { connect: false })
        .unwrap();
    assert!(matches!(
        response,
        ProviderResponse::TailscaleControl(TailscaleControlOutcome {
            control: TailscaleControl::Cli,
            ..
        })
    ));
    assert!(
        serde_json::from_slice::<ProviderResponse>(&serde_json::to_vec(&response).unwrap()).is_ok()
    );
}

#[test]
fn provider_logs_hide_auth_urls_setup_keys_and_credentials() {
    let text = redact_provider_log("Login: https://login.example/secret-capability?token=PRIVATE\nsetup-key PRIVATE\npassword: PRIVATE\nConnected via 8.8.8.8");
    assert!(!text.contains("PRIVATE"));
    assert!(!text.contains("secret-capability"));
    assert!(!text.contains("8.8.8.8"));
}

#[test]
fn missing_or_wrong_family_routes_are_honest_lookup_failures() {
    let network = MacNetwork::with_backend("/unused", Arc::new(FakeNetwork::default()));
    assert_eq!(
        network
            .lookup_route("10.1.2.3".parse().unwrap())
            .unwrap()
            .interface_name,
        "utun7"
    );
    assert!(network
        .lookup_route("2001:db8::1".parse().unwrap())
        .is_err());
}

#[test]
fn unreadable_native_service_inventory_never_falls_back_to_cli_mutation() {
    let backend = Arc::new(FakeNetwork {
        list_error: true,
        ..Default::default()
    });
    let network = MacNetwork::with_backend("/unused", backend.clone());
    assert!(network.tailscale_up().is_err());
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[test]
fn tailscale_login_capability_is_available_for_sign_in_but_not_debug_output() {
    let state: TailscaleState = serde_json::from_str(
        r#"{"installed":true,"state":"needsLogin","authUrl":"https://login.example/PRIVATE"}"#,
    )
    .unwrap();
    assert_eq!(
        state.auth_url.as_deref(),
        Some("https://login.example/PRIVATE")
    );
    assert!(!format!("{state:?}").contains("PRIVATE"));
}
