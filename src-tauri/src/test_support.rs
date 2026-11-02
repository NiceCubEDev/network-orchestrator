use crate::commands::diagnostics::DiagnosticsInput;
use crate::state::{AppState, RuntimeState};
use net_manager_core::backend_settings::BackendSettingsStore;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::models::*;
use net_manager_core::profiles::ProfileStore;
use net_manager_core::system_proxy::{ProxyAdapter, ProxySnapshot, SystemProxyManager};
use net_manager_core::vpn::TunnelManager;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn unique_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "netmgr-app-{}-{}-{}",
        std::process::id(),
        name,
        DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

pub(crate) fn iface(name: &str, friendly_name: &str, state: InterfaceState) -> NetworkInterface {
    NetworkInterface {
        name: name.into(),
        friendly_name: friendly_name.into(),
        kind: InterfaceKind::Other("test".into()),
        state,
        addresses: vec![],
        dns_servers: vec![],
        dns_suffix: None,
        mtu: None,
        if_index: 1,
        physical: true,
        mac: None,
        gateway: None,
        ipv6_gateway: None,
        rx_bytes: None,
        tx_bytes: None,
        link_speed_mbps: None,
        category: InterfaceCategory::Physical,
        description: String::new(),
        if_type: 6,
        tunnel_type: None,
    }
}

pub(crate) fn profile(interface_name: &str) -> Profile {
    Profile {
        id: "p1".into(),
        name: "P1".into(),
        backend: TunnelBackend::WireGuard,
        config_path: PathBuf::from(r"C:\configs\p1.conf"),
        interface_name: interface_name.into(),
        ..Default::default()
    }
}

pub(crate) fn os_route(dest: &str, prefix_len: u8) -> RouteEntry {
    RouteEntry {
        destination: dest.parse().unwrap(),
        prefix_len,
        gateway: None,
        interface_index: 5,
        interface_name: "Ethernet".into(),
        metric: 10,
    }
}

pub(crate) struct NoopExecutor;

impl net_manager_core::policy::RouteExecutor for NoopExecutor {
    fn add_route(&mut self, _route: &AppliedRoute) -> std::io::Result<()> {
        Ok(())
    }

    fn remove_route(&mut self, _route: &AppliedRoute) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) struct NoopProxyAdapter;

impl ProxyAdapter for NoopProxyAdapter {
    fn snapshot(&mut self) -> std::io::Result<ProxySnapshot> {
        Ok(ProxySnapshot::default())
    }
    fn apply(&mut self, _server: &str, _bypass: &str) -> std::io::Result<()> {
        Ok(())
    }
    fn restore(&mut self, _snapshot: &ProxySnapshot) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn app_state(dir: &Path) -> AppState {
    AppState {
        profiles: ProfileStore::new(dir.join("profiles.json")),
        config_vault: ConfigVault::new(dir.join("configs")),
        backend_settings: BackendSettingsStore::new(dir.join("backend-settings.json")),
        managed_xray_root: dir.join("backends").join("xray"),
        #[cfg(target_os = "linux")]
        geo_assets_root: dir.join("geoassets"),
        backend_install_lock: tokio::sync::Mutex::new(()),
        backend_install_cancel: AtomicBool::new(false),
        shutting_down: AtomicBool::new(false),
        cleanup_complete: AtomicBool::new(false),
        runtime: tokio::sync::Mutex::new(RuntimeState {
            tunnels: TunnelManager::new(),
            routes: crate::route_runtime::RouteRuntime::local_with_executor(
                dir,
                Box::new(NoopExecutor),
            ),
            proxy: SystemProxyManager::with_adapter(
                dir.join("proxy-state.json"),
                Box::new(NoopProxyAdapter),
            )
            .unwrap(),
        }),
        log: std::sync::Mutex::new(std::collections::VecDeque::new()),
        #[cfg(target_os = "linux")]
        openvpn_credentials: crate::openvpn_credentials::OpenVpnCredentialStore::new(Box::new(
            crate::openvpn_credentials::tests::FakeKeyring::default(),
        )),
    }
}

pub(crate) fn route_entry(dest: &str, prefix: u8, if_index: u32, metric: u32) -> RouteEntry {
    RouteEntry {
        destination: dest.parse().unwrap(),
        prefix_len: prefix,
        gateway: None,
        interface_index: if_index,
        interface_name: "if0".into(),
        metric,
    }
}

pub(crate) fn inspection_for(p: &Profile, managed: bool) -> ProfileInspection {
    ProfileInspection {
        analysis: ConfigAnalysis {
            profile_id: p.id.clone(),
            os_routes: vec![],
            internal_routes: vec![],
            listeners: vec![],
            endpoints: vec![],
            domain_patterns: vec![],
            warnings: vec![],
            route_knowledge_complete: true,
            peers: Vec::new(),
            interface_details: Vec::new(),
        },
        conflicts: vec![],
        managed_config: managed,
    }
}

pub(crate) fn diag_input(p: &Profile) -> DiagnosticsInput {
    DiagnosticsInput {
        profile: p.clone(),
        status: TunnelStatus {
            profile_id: p.id.clone(),
            state: TunnelState::Running,
            message: None,
            interface_name: None,
            failover: None,
            watchdog: None,
        },
        managed: true,
        inspection: Some(inspection_for(p, true)),
        inspection_error: None,
        executable: Ok(PathBuf::from(r"C:\tools\wg.exe")),
        interfaces: Ok(vec![iface("if0", "if0", InterfaceState::Up)]),
        os_routes: Ok(vec![]),
        owned_routes: None,
        protocol_health: ProtocolHealth {
            state: ProtocolHealthState::Unknown,
            summary: "not checked".into(),
            last_handshake_unix: None,
            rx_bytes: None,
            tx_bytes: None,
            log_tail: None,
            pushed_routes: Vec::new(),
        },
        proxy_owner: None,
    }
}

pub(crate) fn check_named<'a>(checks: &'a [DiagnosticCheck], name: &str) -> &'a DiagnosticCheck {
    checks.iter().find(|c| c.name == name).unwrap()
}
