//! Unprivileged runtime: Xray in loopback SOCKS/HTTP mode plus the per-user
//! macOS system proxy. Routes, interfaces and DNS stay out of this crate; they
//! belong to the privileged launchd helper (plan 14). Xray TUN, WireGuard and
//! OpenVPN profiles are delegated to that helper over `daemon_protocol`; this
//! crate only asks.
use crate::macos_session::{self, Client, Operation, Outcome};
use crate::macos_transaction;
use crate::privileged::Privileged;
use crate::recovery;
use crate::static_routes;
use crate::tailscale::{self, Tailscale};
use crate::vpn_backends;
use crate::{helper_error, helper_socket};
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::{
    method, CondRulesListResult, CondRulesPutParams, CondRulesPutResult, CondRulesRemoveParams,
    CondRulesRemoveResult, ConditionalRouteRule, ConditionalRuleEntry, ConditionalRuleStatus,
    NetIntentDelParams, NetIntentListResult, NetIntentResult, NetIntentSetParams, NetIntentView,
    OpenVpnCredentials, XrayConnectParams, XrayConnectResult, XrayDisconnectResult,
    XrayProfileParams, XrayStatusResult,
};
use net_manager_core::helper_client::HelperClient;
use net_manager_core::managed_xray;
use net_manager_core::models::{
    Profile, ProtocolHealth, RecoveryReport, TunnelBackend, TunnelRole, TunnelState, TunnelStatus,
    XrayMode,
};
use net_manager_core::openvpn_config::CredentialRequirements;
use net_manager_core::profile_import;
use net_manager_core::profiles::ProfileStore;
use net_manager_core::system_proxy::SystemProxyManager;
use net_manager_core::vpn::TunnelManager;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const HELPER_REQUIRED: &str =
    "This connection type needs the macOS privileged helper, which is not available yet";
const LOG_TAIL_BYTES: usize = 16 * 1024;
const MAX_BYPASS_RESOLVERS: usize = 8;

struct Session {
    tunnels: TunnelManager,
    proxy: SystemProxyManager,
    proxy_guard: Option<macos_transaction::FileLock>,
    profiles: HashMap<String, Profile>,
    recovery_error: Option<String>,
}
static DOWNLOAD_RUNTIME: OnceLock<Result<tokio::runtime::Runtime, std::io::Error>> =
    OnceLock::new();

/// What the client shows about the runtime after every operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub xray_installed: bool,
    pub xray_version: String,
    pub statuses: Vec<TunnelStatus>,
    pub system_proxy_owner: Option<String>,
}

/// Connection engine bound to one app data root and one privileged side.
#[derive(Clone)]
pub struct Engine {
    root: PathBuf,
    privileged: Arc<dyn Privileged>,
    /// The user's Tailscale, kept reachable next to a primary tunnel. Only
    /// the engine that talks to the real helper owns one.
    tailscale: Option<Arc<Tailscale>>,
    client: Option<Client>,
    local: Option<Arc<Mutex<Option<Session>>>>,
    owner: bool,
    #[cfg(test)]
    test_executable: Option<PathBuf>,
    #[cfg(test)]
    test_root_executor: bool,
}

fn xray_root(root: &Path) -> PathBuf {
    root.join("backends").join("xray")
}

/// Owner-only recovery. Failed restore remains recorded by SystemProxyManager.
fn recover(root: &Path, proxy: &mut SystemProxyManager) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let executable = managed_xray::macos_managed_version_dir(&xray_root(root)).join("xray");
        let migration = root.join("runtime/.shared-owner-migrated");
        macos_session::processes::validate(root)?;
        let migrated = match std::fs::symlink_metadata(&migration) {
            Ok(_) => {
                let _marker = macos_transaction::lock_file(&migration, false)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err("The legacy recovery marker could not be inspected".into()),
        };
        if !migrated && executable.is_file() {
            let status = std::process::Command::new("/usr/bin/pkill")
                .arg("-f")
                .arg(stale_xray_pattern(&executable))
                .status()
                .map_err(|_| "Stale Xray cleanup could not run")?;
            if !status.success() && status.code() != Some(1) {
                return Err("Stale Xray cleanup failed".into());
            }
        }
        macos_session::processes::recover(root, &executable)?;
        let _marker = macos_transaction::lock_file(&migration, false)?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = root;
    proxy
        .restore_any()
        .map_err(|_| "The previous system proxy could not be restored".into())
}

#[cfg(any(target_os = "macos", test))]
/// Matches exactly the command line `TunnelManager` uses for our managed Xray,
/// so unrelated processes that merely mention the path are never signalled.
fn stale_xray_pattern(executable: &Path) -> String {
    let escaped: String = executable
        .to_string_lossy()
        .chars()
        .flat_map(|c| {
            let special = "\\^$.|?*+()[]{}".contains(c);
            special
                .then_some('\\')
                .into_iter()
                .chain(std::iter::once(c))
        })
        .collect();
    format!("^{escaped} run -config stdin:$")
}

fn with_session<T>(
    engine: &Engine,
    action: impl FnOnce(&mut Session) -> Result<T, String>,
) -> Result<T, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("The user Xray/proxy runtime cannot run as root".into());
    }
    let mut local = engine
        .session_slot()?
        .lock()
        .map_err(|_| "Connection owner is unavailable")?;
    if local.is_none() {
        if engine.client.is_some() {
            return Err("A client cannot own a local connection session".into());
        }
        #[cfg(not(target_os = "macos"))]
        return Err("The macOS local runtime is unsupported on this platform".into());
        #[cfg(target_os = "macos")]
        {
            let runtime = engine.root.join("runtime");
            macos_transaction::canonical_root(&runtime, true)?;
            persisted_proxy_owner(&engine.root)?;
            *local = Some(Session {
                tunnels: TunnelManager::with_log_dir(runtime.join("logs")),
                proxy: SystemProxyManager::new(runtime.join("system-proxy.json"))
                    .map_err(|_| "System proxy state could not be read")?,
                proxy_guard: None,
                profiles: HashMap::new(),
                recovery_error: None,
            });
        }
    }
    action(local.as_mut().ok_or("Connection owner has no session")?)
}

/// The profile with this id, or the error the client shows.
pub fn find_profile(profiles: &[Profile], id: &str) -> Result<Profile, String> {
    profiles
        .iter()
        .find(|profile| profile.id == id)
        .cloned()
        .ok_or_else(|| "Profile not found".into())
}

fn is_tun(profile: &Profile) -> bool {
    profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun
}

fn socket_client() -> HelperClient {
    HelperClient::new(helper_socket()).with_timeout(Duration::from_secs(20))
}

/// The privileged side owns the tunnel's Xray, which logs next to its socket.
fn tun_log_tail(privileged: &dyn Privileged) -> Option<String> {
    tail_of(&privileged.log_dir().join("xray-tun.log"))
}

/// OpenVPN (run by the privileged side) logs in the same directory.
fn openvpn_log_tail(privileged: &dyn Privileged) -> Option<String> {
    tail_of(&privileged.log_dir().join("openvpn.log"))
}

/// WireGuard runs inside the helper, which writes its events here.
fn wireguard_log_tail(privileged: &dyn Privileged) -> Option<String> {
    tail_of(&privileged.log_dir().join("wireguard.log"))
}

/// The helper's own log with public addresses masked; empty when the file is
/// missing or unreadable.
pub fn helper_log_text(path: &Path) -> String {
    tail_of(path)
        .map(|text| net_manager_core::log_sanitize::sanitize_log_text(&text))
        .unwrap_or_default()
}

fn tail_of(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(LOG_TAIL_BYTES as u64)))
        .ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn last_log_line(log: &str) -> Option<String> {
    log.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
}

/// Live state of a TUN profile, from the helper. An unreachable helper owns
/// nothing, so the profile reads as stopped.
fn tun_status(client: &dyn Privileged, profile: &Profile) -> TunnelStatus {
    let stopped = TunnelStatus {
        profile_id: profile.id.clone(),
        state: TunnelState::Stopped,
        message: None,
        interface_name: None,
        failover: None,
        watchdog: None,
    };
    match client.call::<_, XrayStatusResult>(
        method::XRAY_STATUS,
        XrayProfileParams {
            profile_id: profile.id.clone(),
        },
    ) {
        Ok(status) => TunnelStatus {
            message: (status.state == TunnelState::Failed)
                .then(|| tun_log_tail(client).and_then(|log| last_log_line(&log)))
                .flatten()
                .map(|line| format!("Xray stopped: {line}")),
            state: status.state,
            interface_name: status.interface_name,
            failover: status.failover,
            ..stopped
        },
        Err(_) => stopped,
    }
}

/// Whether the privileged side, not this process, runs the profile.
fn is_remote(profile: &Profile) -> bool {
    is_tun(profile)
        || vpn_backends::is_wireguard(profile)
        || vpn_backends::is_openvpn(profile)
        || static_routes::is_static(profile)
}

/// State of a profile the privileged side runs; `None` for loopback Xray,
/// which is a child of this process.
fn remote_status(privileged: &dyn Privileged, profile: &Profile) -> Option<TunnelStatus> {
    if is_tun(profile) {
        Some(tun_status(privileged, profile))
    } else if vpn_backends::is_wireguard(profile) {
        Some(vpn_backends::wireguard_status(privileged, profile))
    } else if vpn_backends::is_openvpn(profile) {
        Some(vpn_backends::openvpn_status(privileged, profile))
    } else if static_routes::is_static(profile) {
        Some(static_routes::status(privileged, profile))
    } else {
        None
    }
}

fn status_of(
    session: &mut Session,
    privileged: &dyn Privileged,
    profile: &Profile,
) -> TunnelStatus {
    remote_status(privileged, profile).unwrap_or_else(|| session.tunnels.status(profile))
}

fn running(session: &mut Session, privileged: &dyn Privileged, profile: &Profile) -> bool {
    status_of(session, privileged, profile).state == TunnelState::Running
}

/// Stop a profile the privileged side runs.
fn stop_remote(privileged: &dyn Privileged, profile: &Profile) -> Result<(), String> {
    if static_routes::is_static(profile) {
        return static_routes::stop(privileged, profile);
    }
    if vpn_backends::is_wireguard(profile) || vpn_backends::is_openvpn(profile) {
        return vpn_backends::stop(privileged, profile, helper_error);
    }
    let result: XrayDisconnectResult = privileged
        .call(
            method::XRAY_DISCONNECT,
            XrayProfileParams {
                profile_id: profile.id.clone(),
            },
        )
        .map_err(helper_error)?;
    result
        .stopped
        .then_some(())
        .ok_or_else(|| "The connection is not running".into())
}

fn stop(
    session: &mut Session,
    privileged: &dyn Privileged,
    profile: &Profile,
) -> Result<(), String> {
    if is_remote(profile) {
        return stop_remote(privileged, profile);
    }
    session
        .tunnels
        .disconnect(profile)
        .map(|_| ())
        .map_err(|_| "The connection is not running".to_string())
}

fn statuses(
    session: &mut Session,
    privileged: &dyn Privileged,
    profiles: &[Profile],
) -> Vec<TunnelStatus> {
    profiles
        .iter()
        .map(|profile| status_of(session, privileged, profile))
        .collect()
}

/// IPv4 resolvers the machine currently uses; they keep a direct route
/// around the tunnel so name resolution survives while it captures traffic.
fn resolver_bypass() -> Vec<String> {
    let mut resolvers: Vec<String> = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("nameserver "))
        .filter_map(|ip| ip.trim().parse::<std::net::Ipv4Addr>().ok())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| ip.to_string())
        .collect();
    resolvers.dedup();
    resolvers.truncate(MAX_BYPASS_RESOLVERS);
    resolvers
}

/// Start a full-tunnel Xray through the privileged helper.
fn start_tun(engine: &Engine, profile: &Profile) -> Result<(), String> {
    vpn_backends::check_role(profile)?;
    let client = engine.privileged.as_ref();
    let hello = client.hello().map_err(helper_error)?;
    if !hello
        .capabilities
        .iter()
        .any(|name| name == method::XRAY_CONNECT)
    {
        return Err(HELPER_REQUIRED.into());
    }
    let executable = engine
        .managed_executable()
        .ok_or("Install Xray to start this connection")?;
    let config = net_manager_core::vpn::prepare_xray_config_base(profile)
        .map_err(|_| "The Xray configuration could not be prepared".to_string())?;
    let root_executor = unsafe { libc::geteuid() } == 0;
    if root_executor && client.validates_locally() {
        return Err(
            "Sudo execution must use an executor that never validates user binaries as root".into(),
        );
    }
    let geo = if root_executor {
        None
    } else {
        crate::geo::prepare(&engine.root, &executable, profile)?
    };
    // Validated here, as the user: a tun inbound would need privileges, and
    // the helper adds it only after this passes.
    if client.validates_locally() {
        net_manager_core::vpn::run_xray_validation_with_assets(
            &executable,
            &config,
            geo.as_ref().map(|geo| geo.dir.as_path()),
        )
        .map_err(|_| "The Xray configuration is invalid".to_string())?;
    }
    let inline_geo = if root_executor {
        let uid = macos_session::console_user_uid()?;
        net_manager_core::geo_assets::cached_protocol_geo_assets(
            &engine.root.join("geoassets"),
            profile,
            uid,
        )?
    } else {
        geo.map(|geo| geo.inline)
    };
    request_tunnel(
        client,
        &engine.root,
        profile,
        config,
        resolver_bypass(),
        inline_geo,
    )
}

/// The `xray.connect` request. The config carries no tun inbound: the helper
/// picks the uplink and adds it, so no caller can steer the binding.
fn request_tunnel(
    client: &dyn Privileged,
    root: &Path,
    profile: &Profile,
    config: Vec<u8>,
    dns_bypass: Vec<String>,
    geo_assets: Option<net_manager_core::daemon_protocol::XrayGeoAssets>,
) -> Result<(), String> {
    require_supported_profile(profile)?;
    let params = XrayConnectParams {
        profile_id: profile.id.clone(),
        config: String::from_utf8(config)
            .map_err(|_| "The Xray configuration could not be prepared".to_string())?,
        // A secondary connection carries only its own networks and leaves the
        // default route, the system DNS and the resolver bypasses to the primary.
        routes: if profile.tunnel_role == TunnelRole::Secondary {
            profile.secondary_routes()
        } else {
            Vec::new()
        },
        dns_servers: Vec::new(),
        dns_domains: Vec::new(),
        dns_bypass: if profile.tunnel_role == TunnelRole::Secondary {
            Vec::new()
        } else {
            dns_bypass
        },
        interface_name: None,
        geo_assets,
        macos_data_root: Some(root.to_string_lossy().into_owned()),
        role: profile.tunnel_role,
        failover: None,
        reject_quic: false,
        probe_url: None,
        mtu: None,
        service_checks: Vec::new(),
        proxy_exits: Vec::new(),
    };
    client
        .call::<_, XrayConnectResult>(method::XRAY_CONNECT, params)
        .map(|_| ())
        .map_err(helper_error)
}

/// The profile owning the system proxy when that connection is not running.
fn stale_proxy_owner(
    session: &mut Session,
    privileged: &dyn Privileged,
    profiles: &[Profile],
) -> Option<String> {
    let owner = session.proxy.ownership()?.profile_id.clone();
    let live = profiles
        .iter()
        .find(|profile| profile.id == owner)
        .is_some_and(|profile| running(session, privileged, profile));
    (!live).then_some(owner)
}

fn snapshot_of(engine: &Engine, session: &mut Session, profiles: &[Profile]) -> Snapshot {
    Snapshot {
        xray_installed: engine.managed_executable().is_some(),
        xray_version: managed_xray::MACOS_XRAY_VERSION.into(),
        statuses: statuses(session, engine.privileged.as_ref(), profiles),
        system_proxy_owner: session
            .proxy
            .ownership()
            .map(|owner| owner.profile_id.clone()),
    }
}

/// Local DNS search domains (e.g. corporate `*.corp.lan`) always bypass the
/// proxy so intranet names keep resolving through the local network.
fn search_domain_bypass() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("search "))
        .flat_map(str::split_whitespace)
        .filter(|domain| {
            domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        })
        .map(|domain| format!("*.{domain}"))
        .collect()
}

fn failure_message(session: &TunnelManager, profile: &Profile) -> String {
    let tail = session
        .log_tail(&profile.id, LOG_TAIL_BYTES)
        .ok()
        .flatten()
        .and_then(|log| {
            log.lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(str::to_string)
        });
    match tail {
        Some(line) => format!("Xray stopped: {}", line.trim()),
        None => "Xray could not start".into(),
    }
}

/// Move the profile off listener ports another process already holds; the
/// new ports are persisted so the system proxy and the UI follow them.
fn free_listener_ports(root: &Path, store: &ProfileStore, profile: &mut Profile) {
    let Ok(mut profiles) = store.load().map(|document| document.profiles) else {
        return;
    };
    let vault = ConfigVault::new(root.join("configs"));
    let _ = profile_import::prepare_connect_ports(&vault, store, profile, &mut profiles, |port| {
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
    });
}

fn restore_proxy(
    engine: &Engine,
    session: &mut Session,
    profile: Option<&str>,
) -> Result<(), String> {
    if let Some(owner) = session.proxy.ownership() {
        if profile.is_some_and(|id| id != owner.profile_id) {
            return Ok(());
        }
        session
            .proxy
            .restore_any()
            .map_err(|_| "The previous system proxy could not be restored".to_string())?;
    }
    if session.proxy_guard.is_some() {
        engine.release_proxy_guard()?;
    }
    session.proxy_guard = None;
    Ok(())
}

pub(crate) fn persisted_proxy_owner(root: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let Some(runtime) = macos_transaction::canonical_root(&root.join("runtime"), false)? else {
        return Ok(None);
    };
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(runtime.join("system-proxy.json"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("System proxy state could not be read".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "System proxy state could not be inspected")?;
    if !metadata.is_file()
        || metadata.uid() != macos_transaction::user_uid()?
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 1024 * 1024
    {
        return Err("System proxy state is unsafe".into());
    }
    crate::macos_state::reject_writable_acl(&file)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "System proxy state could not be read")?;
    if bytes.len() > 1024 * 1024 {
        return Err("System proxy state is too large".into());
    }
    let state: net_manager_core::system_proxy::ProxyStateDocument =
        serde_json::from_slice(&bytes).map_err(|_| "System proxy state is invalid")?;
    if state.version != net_manager_core::system_proxy::PROXY_STATE_DOCUMENT_VERSION {
        return Err("Unsupported system proxy state version".into());
    }
    Ok(state.ownership.map(|owner| owner.profile_id))
}
fn stopped_status(profile: &Profile) -> TunnelStatus {
    TunnelStatus {
        profile_id: profile.id.clone(),
        state: TunnelState::Stopped,
        message: None,
        interface_name: None,
        failover: None,
        watchdog: None,
    }
}

fn require_supported_profile(profile: &Profile) -> Result<(), String> {
    if !profile.xray_proxy_exits.is_empty() {
        return Err("Named proxy exits are not supported by the macOS runtime".into());
    }
    Ok(())
}

fn stopped_health() -> ProtocolHealth {
    ProtocolHealth {
        state: net_manager_core::models::ProtocolHealthState::Unknown,
        summary: "Not running".into(),
        last_handshake_unix: None,
        rx_bytes: None,
        tx_bytes: None,
        log_tail: None,
        pushed_routes: Vec::new(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleGuard {
    pub state: TailscaleGuardState,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub pinned: Vec<String>,
    #[serde(default)]
    pub bypassed: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TailscaleGuardState {
    Protected,
    Idle,
    Off,
    Unsupported,
    Unavailable,
}

impl Engine {
    /// Engine that talks to the launchd helper over its socket.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root: PathBuf = root.into();
        Self {
            client: Some(Client::new(root.clone(), helper_socket())),
            root,
            privileged: Arc::new(socket_client()),
            tailscale: None,
            local: None,
            owner: false,
            #[cfg(test)]
            test_executable: None,
            #[cfg(test)]
            test_root_executor: false,
        }
    }

    /// Engine with another privileged side (executors in the CLI process,
    /// or a fake in tests).
    pub fn with_privileged(root: impl Into<PathBuf>, privileged: Arc<dyn Privileged>) -> Self {
        Self {
            root: root.into(),
            privileged,
            tailscale: None,
            client: None,
            local: Some(Arc::new(Mutex::new(None))),
            owner: false,
            #[cfg(test)]
            test_executable: None,
            #[cfg(test)]
            test_root_executor: false,
        }
    }

    fn session_slot(&self) -> Result<&Mutex<Option<Session>>, String> {
        self.local
            .as_deref()
            .ok_or_else(|| "A client cannot own a local connection session".into())
    }

    fn in_process_root(&self) -> bool {
        if self.client.is_some() {
            return false;
        }
        #[cfg(test)]
        if self.test_root_executor {
            return true;
        }
        unsafe { libc::geteuid() == 0 }
    }

    fn normalized_profile(&self, profile: &Profile) -> Result<Profile, String> {
        let mut profile = profile.clone();
        let uid = if self.in_process_root() {
            Some(macos_session::console_user_uid()?)
        } else {
            None
        };
        crate::macos_services::normalize_profile_path(&mut profile, uid)?;
        Ok(profile)
    }

    fn operation<T>(&self, action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        if self.owner || self.in_process_root() {
            action()
        } else {
            macos_transaction::with_root_lock(&self.root, action)
        }
    }

    fn rpc(&self, operation: Operation, start: bool) -> Result<Option<Outcome>, String> {
        self.client
            .as_ref()
            .ok_or("This Engine is not a runtime client")?
            .call(operation, start)
    }

    fn rpc_snapshot(&self, operation: Operation, profiles: &[Profile]) -> Result<Snapshot, String> {
        match self.rpc(operation, true)? {
            Some(Outcome::Snapshot(mut snapshot)) => {
                snapshot
                    .statuses
                    .retain(|status| profiles.iter().any(|p| p.id == status.profile_id));
                Ok(snapshot)
            }
            _ => Err("Invalid runtime mutation snapshot".into()),
        }
    }

    fn ensure_restartable(&self, profile: &Profile) -> Result<(), String> {
        if vpn_backends::is_openvpn(profile) {
            let required = self.credential_requirements(profile)?;
            if required.user_pass || required.key_passphrase {
                return Err("This OpenVPN connection needs credentials to restart. Disconnect it before changing its settings, then reconnect.".into());
            }
        }
        Ok(())
    }

    fn acquire_proxy_guard(&self) -> Result<macos_transaction::FileLock, String> {
        #[cfg(test)]
        if self.test_executable.is_some() {
            return macos_session::proxy::acquire_at(
                &self.root,
                &self.root.join("runtime/test-proxy-owner"),
            );
        }
        macos_session::proxy::acquire(&self.root)
    }

    fn release_proxy_guard(&self) -> Result<(), String> {
        #[cfg(test)]
        if self.test_executable.is_some() {
            return macos_session::proxy::release_at(
                &self.root,
                &self.root.join("runtime/test-proxy-owner"),
            );
        }
        macos_session::proxy::release(&self.root)
    }

    #[cfg(target_os = "macos")]
    fn journal_processes(&self) -> bool {
        #[cfg(test)]
        if self.test_executable.is_some() {
            return false;
        }
        self.owner
    }

    pub fn connect_foreground(
        &self,
        _store: &ProfileStore,
        profile: &Profile,
        credentials: Option<OpenVpnCredentials>,
    ) -> Result<macos_session::ForegroundLease, String> {
        require_supported_profile(profile)?;
        let client = self
            .client
            .as_ref()
            .ok_or("Foreground service leases require an unprivileged user Engine")?;
        self.operation(|| client.foreground(&profile.id, credentials))
    }

    /// Explicitly synchronize the helper's Tailscale protection.
    pub fn sync_tailscale(&self) -> Result<TailscaleGuard, String> {
        self.operation(|| {
            let guard = if self.client.is_some() {
                match self.rpc(Operation::SyncTailscale, true)? {
                    Some(Outcome::TailscaleGuard(Some(guard))) => guard,
                    _ => return Err("The Tailscale guard is unavailable".into()),
                }
            } else {
                serde_json::from_value(
                    self.sync_tailscale_unlocked()
                        .ok_or("This executor does not manage Tailscale")?,
                )
                .map_err(|_| "Invalid Tailscale guard response")?
            };
            match guard.state {
                TailscaleGuardState::Unsupported => {
                    Err("The installed helper does not support Tailscale protection".into())
                }
                TailscaleGuardState::Unavailable => {
                    Err("The Tailscale protection helper is unavailable".into())
                }
                _ => Ok(guard),
            }
        })
    }

    fn sync_tailscale_unlocked(&self) -> Option<serde_json::Value> {
        let tailscale = self.tailscale.as_ref()?;
        Some(tailscale::sync(self.privileged(), tailscale))
    }

    pub(crate) fn provider_rpc(
        &self,
        request: crate::macos_network::ProviderRequest,
    ) -> Result<crate::macos_network::ProviderResponse, String> {
        if self.client.is_none() {
            if unsafe { libc::geteuid() } == 0 {
                return Err("Control user VPN providers as your own user".into());
            }
            return self.operation(|| {
                crate::macos_network::MacNetwork::new(&self.root).provider_request(request)
            });
        }
        let mutation = request.is_mutation();
        let execute = || match self.rpc(
            Operation::Provider {
                request: request.clone(),
            },
            mutation,
        )? {
            Some(Outcome::Provider(response)) => Ok(response),
            None if !mutation => {
                crate::macos_network::MacNetwork::new(&self.root).provider_request(request)
            }
            _ => Err("Invalid user VPN provider response".into()),
        };
        if mutation {
            self.operation(execute)
        } else {
            execute()
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn privileged(&self) -> &dyn Privileged {
        self.privileged.as_ref()
    }

    /// The verified managed Xray, when one is installed.
    pub fn managed_executable(&self) -> Option<PathBuf> {
        #[cfg(test)]
        if let Some(executable) = &self.test_executable {
            return Some(executable.clone());
        }
        let xray = xray_root(&self.root);
        let executable = managed_xray::macos_managed_version_dir(&xray).join("xray");
        managed_xray::verify_managed_macos_executable(&xray, &executable)
            .ok()
            .map(|_| executable)
    }

    pub fn is_running(&self, profile: &Profile) -> Result<bool, String> {
        if self.client.is_some() {
            return match self.rpc(
                Operation::Running {
                    id: profile.id.clone(),
                },
                false,
            )? {
                Some(Outcome::Running(running)) => Ok(running),
                None => Ok(remote_status(self.privileged(), profile)
                    .is_some_and(|status| status.state == TunnelState::Running)),
                _ => Err("Invalid running status response".into()),
            };
        }
        if let Some(status) = remote_status(self.privileged(), profile) {
            return Ok(status.state == TunnelState::Running);
        }
        with_session(self, |session| {
            Ok(running(session, self.privileged(), profile))
        })
    }

    /// State of a profile the privileged side runs, read without touching
    /// this process's own sessions; `None` for loopback Xray profiles.
    pub fn remote_status(&self, profile: &Profile) -> Option<TunnelStatus> {
        remote_status(self.privileged(), profile)
    }

    pub fn snapshot(&self, profiles: &[Profile]) -> Result<Snapshot, String> {
        if self.client.is_some() {
            return match self.rpc(
                Operation::Snapshot {
                    ids: profiles.iter().map(|p| p.id.clone()).collect(),
                },
                false,
            )? {
                Some(Outcome::Snapshot(snapshot)) => Ok(snapshot),
                None => Ok(Snapshot {
                    xray_installed: self.managed_executable().is_some(),
                    xray_version: managed_xray::MACOS_XRAY_VERSION.into(),
                    statuses: profiles
                        .iter()
                        .map(|p| {
                            remote_status(self.privileged(), p).unwrap_or_else(|| stopped_status(p))
                        })
                        .collect(),
                    system_proxy_owner: self.system_proxy_owner()?,
                }),
                _ => Err("Invalid runtime snapshot response".into()),
            };
        }
        with_session(self, |session| Ok(snapshot_of(self, session, profiles)))
    }

    /// What the profile needs from the user before it can connect.
    pub fn credential_requirements(
        &self,
        profile: &Profile,
    ) -> Result<CredentialRequirements, String> {
        vpn_backends::requirements(&self.root, &self.normalized_profile(profile)?)
    }

    /// Start a connection and confirm it survived startup. Profiles the
    /// privileged side runs never touch this process's sessions.
    pub fn connect(
        &self,
        store: &ProfileStore,
        profile: &Profile,
        credentials: Option<OpenVpnCredentials>,
    ) -> Result<(), String> {
        self.operation(|| self.connect_unlocked(store, profile, credentials))
    }

    fn connect_unlocked(
        &self,
        store: &ProfileStore,
        profile: &Profile,
        credentials: Option<OpenVpnCredentials>,
    ) -> Result<(), String> {
        require_supported_profile(profile)?;
        if self.client.is_some() {
            return self
                .rpc(
                    Operation::Connect {
                        id: profile.id.clone(),
                        credentials,
                    },
                    true,
                )
                .map(|_| ());
        }
        if self.owner {
            with_session(self, |session| match &session.recovery_error {
                Some(error) => Err(format!(
                    "Connection recovery must be completed first: {error}"
                )),
                None => Ok(()),
            })?;
        }
        if !self.in_process_root() {
            crate::macos_state::ensure_start_allowed(&self.root, profile.backend)?;
        } else {
            if !is_remote(profile) || static_routes::is_static(profile) {
                return Err("Root may start only saved helper-backed VPN profiles".into());
            }
            crate::macos_state::ensure_start_allowed_for_user(
                &self.root,
                profile.backend,
                macos_session::console_user_uid()?,
            )?;
        }
        let root = self.root.as_path();
        let privileged = self.privileged();
        let mut profile = self.normalized_profile(profile)?;
        if is_remote(&profile) {
            if is_tun(&profile) && unsafe { libc::geteuid() } != 0 {
                with_session(self, |session| {
                    restore_proxy(self, session, Some(&profile.id))
                })?;
            }
            if remote_status(privileged, &profile)
                .is_some_and(|status| status.state == TunnelState::Running)
            {
                return Err("The connection is already running".into());
            }
            let started = if is_tun(&profile) {
                start_tun(self, &profile)
            } else if static_routes::is_static(&profile) {
                static_routes::start(privileged, &profile)
            } else if vpn_backends::is_wireguard(&profile) {
                vpn_backends::start_wireguard(root, privileged, &profile)
            } else {
                vpn_backends::start_openvpn(root, privileged, &profile, credentials)
            };
            if started.is_ok() {
                // The tailnet must survive the new tunnel; never a reason to fail it.
                let _ = self.sync_tailscale_unlocked();
            }
            return started;
        }
        if profile.backend != TunnelBackend::Xray {
            return Err(HELPER_REQUIRED.into());
        }
        let executable = self
            .managed_executable()
            .ok_or("Install Xray to start this connection")?;
        free_listener_ports(root, store, &mut profile);
        let profile = &profile;
        let geo = crate::geo::prepare(root, &executable, profile)?;
        with_session(self, |session| {
            session
                .tunnels
                .set_executable(TunnelBackend::Xray, Some(executable.clone()));
            session
                .tunnels
                .set_xray_asset_dir(&profile.id, geo.map(|geo| geo.dir));
            session.tunnels.connect(profile).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    "The connection is already running".to_string()
                } else {
                    failure_message(&session.tunnels, profile)
                }
            })?;
            #[cfg(target_os = "macos")]
            if self.journal_processes() {
                let pid = session
                    .tunnels
                    .xray_child_pid(&profile.id)
                    .ok_or("Xray did not start")?;
                if let Err(error) =
                    macos_session::processes::record(root, &profile.id, pid, &executable)
                {
                    let _ = session.tunnels.disconnect(profile);
                    return Err(error);
                }
            }
            // Xray exits immediately on a bad config or a busy port.
            std::thread::sleep(Duration::from_millis(600));
            if session.tunnels.status(profile).state != TunnelState::Running {
                return Err(failure_message(&session.tunnels, profile));
            }
            session.profiles.insert(profile.id.clone(), profile.clone());
            Ok(())
        })
    }

    /// Stop a profile the privileged side runs, without starting a session
    /// of this process.
    pub fn disconnect_remote(&self, profile: &Profile) -> Result<(), String> {
        self.operation(|| {
            if !is_remote(profile) {
                return Err("This is a local proxy connection; use disconnect".into());
            }
            if self.client.is_some() {
                return self
                    .rpc(
                        Operation::Disconnect {
                            id: profile.id.clone(),
                        },
                        true,
                    )
                    .map(|_| ());
            }
            let stopped = stop_remote(self.privileged(), profile);
            let _ = self.sync_tailscale_unlocked();
            stopped
        })
    }

    /// Stop a connection, handing back a system proxy it owned.
    pub fn disconnect(&self, profile: &Profile, profiles: &[Profile]) -> Result<Snapshot, String> {
        self.operation(|| self.disconnect_unlocked(profile, profiles))
    }

    fn disconnect_unlocked(
        &self,
        profile: &Profile,
        profiles: &[Profile],
    ) -> Result<Snapshot, String> {
        if self.client.is_some() {
            return self.rpc_snapshot(
                Operation::Disconnect {
                    id: profile.id.clone(),
                },
                profiles,
            );
        }
        if self.in_process_root() {
            if !is_remote(profile) {
                return Err("Root may stop only helper-backed connections".into());
            }
            stop_remote(self.privileged(), profile)?;
            return Ok(Snapshot {
                xray_installed: self.managed_executable().is_some(),
                xray_version: managed_xray::MACOS_XRAY_VERSION.into(),
                statuses: profiles
                    .iter()
                    .map(|profile| {
                        remote_status(self.privileged(), profile)
                            .unwrap_or_else(|| stopped_status(profile))
                    })
                    .collect(),
                system_proxy_owner: None,
            });
        }
        with_session(self, |session| {
            restore_proxy(self, session, Some(&profile.id))?;
            if is_remote(profile) || session.tunnels.status(profile).state == TunnelState::Running {
                stop(session, self.privileged(), profile)?;
            }
            #[cfg(target_os = "macos")]
            if self.owner && !is_remote(profile) {
                macos_session::processes::forget(&self.root, &profile.id)?;
            }
            session.profiles.remove(&profile.id);
            let _ = self.sync_tailscale_unlocked();
            Ok(snapshot_of(self, session, profiles))
        })
    }

    /// Point the system proxy at a running connection, or give it back.
    pub fn set_system_proxy(
        &self,
        profile: &Profile,
        profiles: &[Profile],
        enable: bool,
    ) -> Result<Snapshot, String> {
        self.operation(|| self.set_system_proxy_unlocked(profile, profiles, enable))
    }

    fn set_system_proxy_unlocked(
        &self,
        profile: &Profile,
        profiles: &[Profile],
        enable: bool,
    ) -> Result<Snapshot, String> {
        if self.client.is_some() {
            return self.rpc_snapshot(
                Operation::SetProxy {
                    id: profile.id.clone(),
                    enable,
                },
                profiles,
            );
        }
        with_session(self, |session| {
            if enable {
                if is_tun(profile) {
                    return Err("The system proxy is not used in tunnel mode".into());
                }
                if session.tunnels.status(profile).state != TunnelState::Running {
                    return Err("Start the connection first".into());
                }
                let socks = profile
                    .xray_socks_port
                    .ok_or("This connection has no local proxy port")?;
                if session.proxy_guard.is_none() {
                    session.proxy_guard = Some(self.acquire_proxy_guard()?);
                }
                let applied = session.proxy.apply_with_http(
                    &profile.id,
                    socks,
                    profile.xray_http_port,
                    &search_domain_bypass(),
                );
                if applied.is_err() && session.proxy.ownership().is_none() {
                    self.release_proxy_guard()?;
                    session.proxy_guard = None;
                }
                applied.map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        "Another connection already owns the system proxy".to_string()
                    } else {
                        "The system proxy could not be changed".to_string()
                    }
                })?;
            } else {
                restore_proxy(self, session, Some(&profile.id))?;
            }
            Ok(snapshot_of(self, session, profiles))
        })
    }

    /// The profile that owns the per-user system proxy, if any.
    pub fn system_proxy_owner(&self) -> Result<Option<String>, String> {
        if self.client.is_some() {
            return match self.rpc(Operation::ProxyOwner, false)? {
                Some(Outcome::ProxyOwner(owner)) => Ok(owner),
                None => persisted_proxy_owner(&self.root),
                _ => Err("Invalid system proxy response".into()),
            };
        }
        if self.in_process_root() {
            return Ok(None);
        }
        let local = self
            .session_slot()?
            .lock()
            .map_err(|_| "Connection owner is unavailable")?;
        match local.as_ref() {
            Some(session) => Ok(session
                .proxy
                .ownership()
                .map(|owner| owner.profile_id.clone())),
            None => persisted_proxy_owner(&self.root),
        }
    }

    /// Status, protocol health and system-proxy owner of a profile this
    /// process runs itself (loopback Xray), for diagnostics.
    pub fn loopback_state(
        &self,
        profile: &Profile,
    ) -> Result<(TunnelStatus, ProtocolHealth, Option<String>), String> {
        if self.client.is_some() {
            return match self.rpc(
                Operation::Loopback {
                    id: profile.id.clone(),
                },
                false,
            )? {
                Some(Outcome::Loopback(status, health, owner)) => Ok((*status, health, owner)),
                None => Ok((
                    stopped_status(profile),
                    stopped_health(),
                    self.system_proxy_owner()?,
                )),
                _ => Err("Invalid loopback response".into()),
            };
        }
        with_session(self, |session| {
            Ok((
                session.tunnels.status(profile),
                session.tunnels.protocol_health(profile),
                session
                    .proxy
                    .ownership()
                    .map(|owner| owner.profile_id.clone()),
            ))
        })
    }

    /// Turn a network interface on or off through the helper. The helper
    /// refuses loopback and the devices of the connections it runs.
    pub fn set_interface_state(&self, name: &str, up: bool) -> Result<(), String> {
        self.operation(|| self.set_interface_state_unlocked(name, up))
    }

    fn set_interface_state_unlocked(&self, name: &str, up: bool) -> Result<(), String> {
        use net_manager_core::daemon_protocol::{ErrorCode, LinkSetStateParams};
        use net_manager_core::helper_client::HelperError;
        self.privileged()
            .call::<_, serde_json::Value>(
                method::LINK_SET_STATE,
                LinkSetStateParams {
                    name: name.to_string(),
                    up,
                },
            )
            .map(|_| ())
            .map_err(|error| match error {
                HelperError::Rejected(body) if body.code == ErrorCode::UnsupportedMethod => {
                    "The installed helper is too old to turn interfaces on or off. Update it in Settings."
                        .to_string()
                }
                other => helper_error(other),
            })
    }

    /// The user's routing intents with their live status.
    pub fn intents(&self) -> Result<Vec<NetIntentView>, String> {
        self.intent_call::<_, NetIntentListResult>(method::NET_INTENT_LIST, json!({}))
            .map(|list| list.intents)
    }

    /// Adds or replaces an intent; the helper applies it at once.
    pub fn set_intent(&self, params: NetIntentSetParams) -> Result<(), String> {
        self.intent_call::<_, NetIntentResult>(method::NET_INTENT_SET, params)
            .map(|_| ())
    }

    pub fn delete_intent(&self, id: &str) -> Result<(), String> {
        self.intent_call::<_, NetIntentResult>(
            method::NET_INTENT_DEL,
            NetIntentDelParams { id: id.to_string() },
        )
        .map(|_| ())
    }

    /// The user's conditional rules with their live status.
    pub fn cond_rules(&self) -> Result<Vec<ConditionalRuleEntry>, String> {
        self.intent_call::<_, CondRulesListResult>(method::COND_RULES_LIST, json!({}))
            .map(|list| list.rules)
    }

    /// Adds or replaces a rule; the helper evaluates it at once.
    pub fn put_cond_rule(
        &self,
        rule: ConditionalRouteRule,
    ) -> Result<ConditionalRuleStatus, String> {
        self.intent_call::<_, CondRulesPutResult>(
            method::COND_RULES_PUT,
            CondRulesPutParams { rule },
        )
        .map(|result| result.status)
    }

    pub fn remove_cond_rule(&self, id: &str) -> Result<bool, String> {
        self.intent_call::<_, CondRulesRemoveResult>(
            method::COND_RULES_REMOVE,
            CondRulesRemoveParams {
                rule_id: id.to_string(),
            },
        )
        .map(|result| result.removed)
    }

    fn intent_call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        name: &str,
        params: P,
    ) -> Result<R, String> {
        if name != method::NET_INTENT_LIST && name != method::COND_RULES_LIST {
            return self.operation(|| self.intent_call_unlocked(name, params));
        }
        self.intent_call_unlocked(name, params)
    }

    fn intent_call_unlocked<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        name: &str,
        params: P,
    ) -> Result<R, String> {
        use net_manager_core::daemon_protocol::ErrorCode;
        use net_manager_core::helper_client::HelperError;
        self.privileged()
            .call::<_, R>(name, params)
            .map_err(|error| match error {
                HelperError::Rejected(body) if body.code == ErrorCode::UnsupportedMethod => {
                    "The installed helper is too old for routing intents. Update it in Settings."
                        .to_string()
                }
                other => helper_error(other),
            })
    }

    /// What a crashed session left behind: tunnels the helper still records
    /// that no longer run, and a system proxy for a connection that is gone.
    pub fn recovery_report(&self, profiles: &[Profile]) -> Result<RecoveryReport, String> {
        if self.client.is_some() {
            return match self.rpc(Operation::RecoveryReport, false)? {
                Some(Outcome::Recovery(report)) => Ok(report),
                None => Ok(recovery::report(
                    self.privileged(),
                    self.system_proxy_owner()?.as_deref(),
                )),
                _ => Err("Invalid recovery response".into()),
            };
        }
        with_session(self, |session| {
            let stale = stale_proxy_owner(session, self.privileged(), profiles);
            let mut report = recovery::report(self.privileged(), stale.as_deref());
            if let Some(error) = &session.recovery_error {
                report.issues.push(net_manager_core::models::RecoveryIssue {
                    kind: net_manager_core::models::RecoveryIssueKind::LeftoverTunnel,
                    profile_id: None,
                    message: error.clone(),
                });
            }
            Ok(report)
        })
    }

    /// Undo what [`Engine::recovery_report`] lists and report what remains.
    /// Running connections are never touched.
    pub fn recovery_cleanup(&self, profiles: &[Profile]) -> Result<RecoveryReport, String> {
        self.operation(|| self.recovery_cleanup_unlocked(profiles))
    }

    fn recovery_cleanup_unlocked(&self, profiles: &[Profile]) -> Result<RecoveryReport, String> {
        if self.client.is_some() {
            return match self.rpc(Operation::RecoveryCleanup, true)? {
                Some(Outcome::Recovery(report)) => Ok(report),
                _ => Err("Invalid recovery response".into()),
            };
        }
        with_session(self, |session| {
            if session.recovery_error.is_some() {
                let locals: Vec<_> = session.profiles.values().cloned().collect();
                if locals
                    .iter()
                    .any(|profile| session.tunnels.status(profile).state == TunnelState::Running)
                {
                    return Err(
                        "Stop active local connections before retrying failed startup recovery"
                            .into(),
                    );
                }
                recover(&self.root, &mut session.proxy)?;
                session.recovery_error = None;
                if session.proxy.ownership().is_none() && session.proxy_guard.is_some() {
                    self.release_proxy_guard()?;
                    session.proxy_guard = None;
                }
            }
            let helper = recovery::cleanup(self.privileged());
            if let Some(owner) = stale_proxy_owner(session, self.privileged(), profiles) {
                restore_proxy(self, session, Some(&owner))?;
            }
            helper?;
            let stale = stale_proxy_owner(session, self.privileged(), profiles);
            Ok(recovery::report(self.privileged(), stale.as_deref()))
        })
    }

    /// Frontend shutdown is detach-only. Explicit disconnect is authoritative.
    /// An explicit in-process privileged executor retains its own cleanup.
    pub fn shutdown(&self, profiles: &[Profile]) -> Result<(), String> {
        if self.client.is_some() {
            return Ok(());
        }
        if self
            .session_slot()?
            .lock()
            .map_err(|_| "Connection owner is unavailable")?
            .is_none()
        {
            return self.operation(|| {
                for profile in profiles {
                    if is_remote(profile) && self.is_running(profile)? {
                        stop_remote(self.privileged(), profile)?;
                    }
                }
                Ok(())
            });
        }
        self.operation(|| {
            with_session(self, |session| {
                let mut failure = restore_proxy(self, session, None).err();
                let locals: Vec<_> = session.profiles.values().cloned().collect();
                for profile in locals {
                    if session.tunnels.disconnect(&profile).is_err() {
                        failure.get_or_insert_with(|| {
                            "The owned Xray process could not be stopped".into()
                        });
                        continue;
                    }
                    #[cfg(target_os = "macos")]
                    if self.owner {
                        if let Err(error) =
                            macos_session::processes::forget(&self.root, &profile.id)
                        {
                            failure.get_or_insert(error);
                            continue;
                        }
                    }
                    session.profiles.remove(&profile.id);
                }
                failure.map_or(Ok(()), Err)
            })
        })
    }

    /// Tail of the connection's log, empty when it has none.
    pub fn log(&self, profile: &Profile) -> Result<String, String> {
        if self.client.is_some() && !is_remote(profile) {
            return match self.rpc(
                Operation::Log {
                    id: profile.id.clone(),
                },
                false,
            )? {
                Some(Outcome::Log(log)) => Ok(log),
                None => Ok(String::new()),
                _ => Err("Invalid connection log response".into()),
            };
        }
        if is_tun(profile) {
            return Ok(tun_log_tail(self.privileged()).unwrap_or_default());
        }
        if vpn_backends::is_openvpn(profile) {
            return Ok(openvpn_log_tail(self.privileged()).unwrap_or_default());
        }
        if vpn_backends::is_wireguard(profile) {
            return Ok(wireguard_log_tail(self.privileged()).unwrap_or_default());
        }
        with_session(self, |session| {
            Ok(session
                .tunnels
                .log_tail(&profile.id, LOG_TAIL_BYTES)
                .ok()
                .flatten()
                .unwrap_or_default())
        })
    }

    /// Run a change to a profile's configuration (endpoint switch, refresh)
    /// and, when the connection was running, restart it on the new
    /// configuration. The system proxy ownership is kept across the restart.
    pub fn restart_around<T>(
        &self,
        store: &ProfileStore,
        id: &str,
        change: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        self.operation(|| self.restart_around_unlocked(store, id, change))
    }

    fn restart_around_unlocked<T>(
        &self,
        store: &ProfileStore,
        id: &str,
        change: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let load = || {
            store
                .load()
                .map(|document| document.profiles)
                .map_err(|_| "Profiles could not be loaded".to_string())
        };
        let before = find_profile(&load()?, id)?;
        let was_running = self.is_running(&before)?;
        if was_running {
            if self.client.is_none() {
                self.ensure_restartable(&before)?;
            }
            if self.client.is_some() {
                self.rpc(Operation::StopForRestart { id: id.into() }, false)?
                    .ok_or("The connection owner stopped during the restart")?;
            } else if is_remote(&before) {
                stop_remote(self.privileged(), &before)?;
            } else {
                with_session(self, |session| stop(session, self.privileged(), &before))?;
            }
        }
        let result = change();
        if was_running {
            let after = load()
                .and_then(|profiles| find_profile(&profiles, id))
                .or_else(|error| {
                    if result.is_err() {
                        Ok(before.clone())
                    } else {
                        Err(error)
                    }
                });
            let restarted = after.and_then(|profile| self.connect_unlocked(store, &profile, None));
            if let Err(error) = restarted {
                let error = match &result {
                    Ok(_) => error,
                    Err(change_error) => format!("{change_error}; reconnect failed: {error}"),
                };
                let restored = if self.client.is_some() {
                    self.rpc(Operation::RestoreAfterRestart { id: id.into() }, false)
                        .and_then(|outcome| {
                            outcome
                                .map(|_| ())
                                .ok_or_else(|| "The connection owner is unavailable".to_string())
                        })
                } else if self.in_process_root() {
                    Ok(())
                } else {
                    with_session(self, |session| restore_proxy(self, session, Some(id)))
                };
                return Err(match restored {
                    Ok(()) => error,
                    Err(restore_error) => {
                        format!("{error}; restart cleanup failed: {restore_error}")
                    }
                });
            }
        }
        result
    }

    /// Installs the pinned Xray either by download or, for closed networks,
    /// from a user-supplied copy of the same official zip; both paths are
    /// hash-checked.
    pub fn install_xray(&self, archive_path: Option<&str>) -> Result<(), String> {
        self.operation(|| self.install_xray_unlocked(archive_path))
    }

    fn install_xray_unlocked(&self, archive_path: Option<&str>) -> Result<(), String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Install Xray as your own user, never root".into());
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = archive_path;
            Err("Installing macOS Xray is unsupported on this platform".into())
        }
        #[cfg(target_os = "macos")]
        {
            if self.managed_executable().is_some() {
                return Ok(());
            }
            let archive = match archive_path.filter(|path| !path.is_empty()) {
                Some(path) => {
                    let metadata = std::fs::metadata(path)
                        .map_err(|_| "The selected Xray archive could not be read".to_string())?;
                    if metadata.len() > managed_xray::MAX_XRAY_ARCHIVE_BYTES as u64 {
                        return Err("The downloaded Xray package failed verification".into());
                    }
                    std::fs::read(path)
                        .map_err(|_| "The selected Xray archive could not be read".to_string())?
                }
                None => download_runtime()?
                    .block_on(managed_xray::download_archive(managed_xray::MACOS_XRAY_URL))
                    .map_err(|_| {
                        "Xray could not be downloaded. Check the network connection.".to_string()
                    })?,
            };
            let installed =
                managed_xray::install_verified_macos_archive(&xray_root(&self.root), &archive)
                    .map_err(|_| "The downloaded Xray package failed verification".to_string())?;
            let version = std::process::Command::new(&installed.executable)
                .arg("version")
                .output()
                .map_err(|_| "The installed Xray could not run".to_string())?;
            if !version.status.success() {
                return Err("The installed Xray could not run".into());
            }
            Ok(())
        }
    }
}

#[cfg(any(target_os = "macos", test))]
/// The service alone constructs this backend under the lifetime/cutover locks.
pub(crate) struct OwnerBackend {
    engine: Engine,
}

#[cfg(any(target_os = "macos", test))]
impl OwnerBackend {
    #[cfg(target_os = "macos")]
    pub(crate) fn new(root: &Path, helper: &Path) -> Result<Self, String> {
        let runtime = root.join("runtime");
        macos_transaction::canonical_root(&runtime, true)?;
        persisted_proxy_owner(root)?;
        let mut proxy = SystemProxyManager::new(runtime.join("system-proxy.json"))
            .map_err(|_| "System proxy state could not be read")?;
        let proxy_guard = if proxy.ownership().is_some() {
            Some(macos_session::proxy::acquire(root)?)
        } else {
            None
        };
        let mut recovery_error = recover(root, &mut proxy).err();
        let proxy_guard = if proxy.ownership().is_none() && proxy_guard.is_some() {
            match macos_session::proxy::release(root) {
                Ok(()) => None,
                Err(error) => {
                    recovery_error = Some(error);
                    proxy_guard
                }
            }
        } else {
            proxy_guard
        };
        let mut engine = Engine::with_privileged(
            root,
            Arc::new(HelperClient::new(helper).with_timeout(Duration::from_secs(20))),
        );
        engine.owner = true;
        engine.tailscale = Some(Arc::new(Tailscale::detect()));
        *engine
            .session_slot()?
            .lock()
            .map_err(|_| "Connection owner is unavailable")? = Some(Session {
            tunnels: TunnelManager::with_log_dir(runtime.join("logs")),
            proxy,
            proxy_guard,
            profiles: HashMap::new(),
            recovery_error,
        });
        Ok(Self { engine })
    }

    fn profiles(&self) -> Result<Vec<Profile>, String> {
        let mut profiles = ProfileStore::new(self.engine.root.join("profiles.json"))
            .load()
            .map(|document| document.profiles)
            .map_err(|_| "Profiles could not be loaded".to_string())?;
        for profile in &mut profiles {
            crate::macos_services::normalize_profile_path(profile, None)?;
        }
        Ok(profiles)
    }

    fn profile(&self, id: &str, profiles: &[Profile]) -> Result<Profile, String> {
        if let Ok(profile) = find_profile(profiles, id) {
            return Ok(profile);
        }
        self.engine
            .session_slot()?
            .lock()
            .map_err(|_| "Connection owner is unavailable")?
            .as_ref()
            .and_then(|session| session.profiles.get(id))
            .cloned()
            .ok_or_else(|| "Profile not found".into())
    }
}

#[cfg(any(target_os = "macos", test))]
impl macos_session::Backend for OwnerBackend {
    fn execute(&mut self, operation: Operation) -> Result<Outcome, String> {
        let profiles = match &operation {
            Operation::Provider { .. }
            | Operation::SyncTailscale
            | Operation::ProxyOwner
            | Operation::RestoreAfterRestart { .. } => Vec::new(),
            _ => self.profiles()?,
        };
        match operation {
            Operation::Provider { request } => {
                let sync = matches!(
                    &request,
                    crate::macos_network::ProviderRequest::TailscaleControl { .. }
                );
                let result = crate::macos_network::MacNetwork::new(&self.engine.root)
                    .provider_request(request)?;
                if sync {
                    let _ = self.engine.sync_tailscale_unlocked();
                }
                Ok(Outcome::Provider(result))
            }
            Operation::SyncTailscale => Ok(Outcome::TailscaleGuard(
                self.engine
                    .sync_tailscale_unlocked()
                    .and_then(|value| serde_json::from_value(value).ok()),
            )),
            Operation::Snapshot { ids } => {
                let selected: Vec<_> = profiles
                    .into_iter()
                    .filter(|p| ids.contains(&p.id))
                    .collect();
                self.engine.snapshot(&selected).map(Outcome::Snapshot)
            }
            Operation::Running { id } => self
                .engine
                .is_running(&self.profile(&id, &profiles)?)
                .map(Outcome::Running),
            Operation::Connect { id, credentials } => {
                // Never accept caller-supplied configurations, executable paths or profile snapshots.
                let profile = find_profile(&profiles, &id)?;
                let vault = ConfigVault::new(self.engine.root.join("configs"));
                if profile.backend != TunnelBackend::None
                    && !vault.is_managed_profile_path(&profile.id, &profile.config_path)
                {
                    return Err("Connections must use their own saved managed configuration".into());
                }
                self.engine.connect_unlocked(
                    &ProfileStore::new(self.engine.root.join("profiles.json")),
                    &profile,
                    credentials,
                )?;
                Ok(Outcome::Unit)
            }
            Operation::Disconnect { id } => {
                let profile = self.profile(&id, &profiles)?;
                self.engine
                    .disconnect_unlocked(&profile, &profiles)
                    .map(Outcome::Snapshot)
            }
            Operation::StopForRestart { id } => {
                let profile = self.profile(&id, &profiles)?;
                self.engine.ensure_restartable(&profile)?;
                with_session(&self.engine, |session| {
                    stop(session, self.engine.privileged(), &profile)
                })?;
                #[cfg(target_os = "macos")]
                if !is_remote(&profile) {
                    macos_session::processes::forget(&self.engine.root, &profile.id)?;
                }
                Ok(Outcome::Unit)
            }
            Operation::RestoreAfterRestart { id } => {
                with_session(&self.engine, |session| {
                    restore_proxy(&self.engine, session, Some(&id))?;
                    if let Some(profile) = session.profiles.get(&id).cloned() {
                        if session.tunnels.status(&profile).state == TunnelState::Running {
                            stop(session, self.engine.privileged(), &profile)?;
                        }
                        session.profiles.remove(&id);
                        #[cfg(target_os = "macos")]
                        macos_session::processes::forget(&self.engine.root, &id)?;
                    }
                    Ok(())
                })?;
                Ok(Outcome::Unit)
            }
            Operation::SetProxy { id, enable } => {
                let profile = self.profile(&id, &profiles)?;
                self.engine
                    .set_system_proxy_unlocked(&profile, &profiles, enable)
                    .map(Outcome::Snapshot)
            }
            Operation::ProxyOwner => self.engine.system_proxy_owner().map(Outcome::ProxyOwner),
            Operation::Loopback { id } => {
                let (status, health, owner) =
                    self.engine.loopback_state(&self.profile(&id, &profiles)?)?;
                Ok(Outcome::Loopback(Box::new(status), health, owner))
            }
            Operation::RecoveryReport => self
                .engine
                .recovery_report(&profiles)
                .map(Outcome::Recovery),
            Operation::RecoveryCleanup => self
                .engine
                .recovery_cleanup_unlocked(&profiles)
                .map(Outcome::Recovery),
            Operation::Log { id } => self
                .engine
                .log(&self.profile(&id, &profiles)?)
                .map(Outcome::Log),
            Operation::GenerationRunning { .. }
            | Operation::DisconnectGeneration { .. }
            | Operation::DetachGeneration { .. }
            | Operation::SetProxyGeneration { .. } => {
                Err("Generation operations belong to the shared owner".into())
            }
        }
    }

    fn reap(&mut self) -> Result<(), String> {
        with_session(&self.engine, |session| {
            let profiles: Vec<_> = session.profiles.values().cloned().collect();
            for profile in profiles {
                if session.tunnels.status(&profile).state != TunnelState::Running {
                    #[cfg(target_os = "macos")]
                    macos_session::processes::forget(&self.engine.root, &profile.id)?;
                    if let Err(error) = restore_proxy(&self.engine, session, Some(&profile.id)) {
                        session.recovery_error = Some(error);
                    } else {
                        session.profiles.remove(&profile.id);
                    }
                }
            }
            Ok(())
        })
    }

    fn shutdown(&mut self) -> Result<(), String> {
        // The user service must not stop helper-owned background connections.
        self.engine.shutdown(&[])
    }
}

pub(crate) fn download_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    DOWNLOAD_RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|_| "Network reader could not start".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{
        encode_line, ErrorCode, HelloResult, RequestFrame, ResponseFrame, PROTOCOL_VERSION,
    };
    use net_manager_core::helper_client::HelperClient;
    use net_manager_core::helper_client::HelperError;
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    #[test]
    fn stale_pattern_is_anchored_and_escaped() {
        let pattern = stale_xray_pattern(Path::new("/data/x.y/backends/xray/v26.7.28/xray"));
        assert_eq!(
            pattern,
            "^/data/x\\.y/backends/xray/v26\\.7\\.28/xray run -config stdin:$"
        );
    }

    fn tun_profile() -> Profile {
        Profile {
            id: "tun1".into(),
            name: "Tun".into(),
            backend: TunnelBackend::Xray,
            xray_mode: XrayMode::Tun,
            ..Default::default()
        }
    }

    /// Serves hello plus one request; reports the request it saw.
    fn fake_helper(
        dir: &Path,
        reply: impl FnOnce(&RequestFrame) -> ResponseFrame + Send + 'static,
    ) -> (HelperClient, mpsc::Receiver<RequestFrame>) {
        let socket = dir.join("h.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let hello: RequestFrame = serde_json::from_str(&line).unwrap();
            let result = HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: "t".into(),
                uid: 501,
                capabilities: vec![method::XRAY_CONNECT.into()],
                tools: Default::default(),
            };
            let ok = ResponseFrame::ok(hello.id, serde_json::to_value(result).unwrap());
            stream.write_all(&encode_line(&ok).unwrap()).unwrap();
            line.clear();
            if reader.read_line(&mut line).unwrap() > 0 {
                let request: RequestFrame = serde_json::from_str(&line).unwrap();
                let response = reply(&request);
                let _ = tx.send(request);
                stream.write_all(&encode_line(&response).unwrap()).unwrap();
            }
        });
        (HelperClient::new(socket), rx)
    }

    fn status_json(state: &str) -> Value {
        json!({"profileId":"tun1","state":state,"interfaceName":"utun10",
               "dnsApplied":true,"ipv4Covered":true,"ipv6Covered":true})
    }

    #[test]
    fn tunnel_request_carries_config_and_data_root_but_no_uplink_or_tun_inbound() {
        let dir = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(dir.path(), |request| {
            ResponseFrame::ok(request.id, json!({"status": status_json("running")}))
        });
        let config = br#"{"inbounds":[{"protocol":"socks"}],"outbounds":[]}"#.to_vec();
        request_tunnel(
            &client,
            Path::new("/data/root"),
            &tun_profile(),
            config,
            vec!["192.168.1.1".into()],
            None,
        )
        .unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.method, method::XRAY_CONNECT);
        assert_eq!(request.params["profileId"], "tun1");
        assert_eq!(request.params["macosDataRoot"], "/data/root");
        assert_eq!(request.params["dnsBypass"], json!(["192.168.1.1"]));
        let text = request.params["config"].as_str().unwrap();
        let sent: Value = serde_json::from_str(text).unwrap();
        assert!(!net_manager_core::xray::has_tun_inbound(&sent));
        assert!(!text.contains("autoOutboundsInterface"));
    }

    #[test]
    fn custom_geo_data_travels_with_the_tunnel_request_and_is_otherwise_absent() {
        let dir = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(dir.path(), |request| {
            ResponseFrame::ok(request.id, json!({"status": status_json("running")}))
        });
        let geo = net_manager_core::daemon_protocol::XrayGeoAssets {
            geoip_dat_b64: Some("Y3VzdG9t".into()),
            geosite_dat_b64: None,
        };
        request_tunnel(
            &client,
            Path::new("/d"),
            &tun_profile(),
            b"{}".to_vec(),
            vec![],
            Some(geo),
        )
        .unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.params["geoAssets"]["geoipDatB64"], "Y3VzdG9t");
        assert!(request.params["geoAssets"].get("geositeDatB64").is_none());
    }

    #[test]
    fn helper_refusals_reach_the_user_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let (client, _) = fake_helper(dir.path(), |request| {
            ResponseFrame::error(
                request.id,
                ErrorCode::Conflict,
                "another VPN already owns the default route",
            )
        });
        let error = request_tunnel(
            &client,
            Path::new("/d"),
            &tun_profile(),
            b"{}".to_vec(),
            vec![],
            None,
        )
        .unwrap_err();
        assert_eq!(error, "another VPN already owns the default route");
    }

    #[test]
    fn tun_status_maps_the_helper_state_and_an_absent_helper_reads_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let (client, _) = fake_helper(dir.path(), |request| {
            ResponseFrame::ok(request.id, status_json("running"))
        });
        let status = tun_status(&client, &tun_profile());
        assert_eq!(status.state, TunnelState::Running);
        assert_eq!(status.interface_name.as_deref(), Some("utun10"));
        let missing = HelperClient::new(dir.path().join("none.sock"));
        assert_eq!(
            tun_status(&missing, &tun_profile()).state,
            TunnelState::Stopped
        );
    }

    #[test]
    fn the_wireguard_log_is_read_from_the_helpers_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("wireguard.log"),
            "2026/10/23 12:00:00 [Info] connected on utun5\n",
        )
        .unwrap();
        let client = HelperClient::new(dir.path().join("h.sock"));
        assert_eq!(
            wireguard_log_tail(&client).as_deref(),
            Some("2026/10/23 12:00:00 [Info] connected on utun5\n")
        );
        let empty = tempfile::tempdir().unwrap();
        let none = HelperClient::new(empty.path().join("h.sock"));
        assert!(wireguard_log_tail(&none).is_none());
    }

    #[test]
    fn the_helper_log_masks_public_addresses_and_may_be_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.log");
        std::fs::write(&path, "dial 203.0.113.7:443 failed\nlocal 192.168.1.5 ok\n").unwrap();
        let text = helper_log_text(&path);
        assert!(
            text.contains("203.0.x.x:443") && !text.contains("203.0.113.7"),
            "{text}"
        );
        assert!(text.contains("192.168.1.5"));
        assert_eq!(helper_log_text(&dir.path().join("missing.log")), "");
    }

    #[test]
    fn switching_an_interface_sends_the_request_and_explains_an_old_helper() {
        use net_manager_core::daemon_protocol::ErrorCode;
        let dir = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(dir.path(), |request| {
            ResponseFrame::ok(request.id, Value::Null)
        });
        let engine = Engine::with_privileged(dir.path(), Arc::new(client));
        engine.set_interface_state("en7", false).unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.method, method::LINK_SET_STATE);
        assert_eq!(request.params, json!({"name": "en7", "up": false}));

        let other = tempfile::tempdir().unwrap();
        let (old, _) = fake_helper(other.path(), |request| {
            ResponseFrame::error(request.id, ErrorCode::UnsupportedMethod, "unsupported")
        });
        let engine = Engine::with_privileged(other.path(), Arc::new(old));
        let error = engine.set_interface_state("en7", true).unwrap_err();
        assert!(
            error.contains("too old") && error.contains("Settings"),
            "{error}"
        );

        let third = tempfile::tempdir().unwrap();
        let (refusing, _) = fake_helper(third.path(), |request| {
            ResponseFrame::error(request.id, ErrorCode::Conflict, "disconnect it instead")
        });
        let engine = Engine::with_privileged(third.path(), Arc::new(refusing));
        assert_eq!(
            engine.set_interface_state("utun9", false).unwrap_err(),
            "disconnect it instead"
        );
    }

    #[test]
    fn intents_are_listed_set_and_deleted_through_the_helper() {
        use net_manager_core::daemon_protocol::{ErrorCode, NetIntentPath};
        let dir = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(dir.path(), |request| {
            ResponseFrame::ok(
                request.id,
                json!({"intents": [{
                    "id": "office", "destinations": ["10.0.0.0/8"],
                    "path": {"kind": "direct"}, "metric": 100, "enabled": true,
                    "status": "effective", "detail": "1 route(s) in place",
                    "installed": 1, "wanted": 1
                }]}),
            )
        });
        let engine = Engine::with_privileged(dir.path(), Arc::new(client));
        let list = engine.intents().unwrap();
        assert_eq!(seen.recv().unwrap().method, method::NET_INTENT_LIST);
        assert_eq!(list[0].id, "office");
        assert_eq!((list[0].installed, list[0].wanted), (1, 1));

        let other = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(other.path(), |request| {
            ResponseFrame::ok(request.id, json!({"id": "office"}))
        });
        let engine = Engine::with_privileged(other.path(), Arc::new(client));
        engine
            .set_intent(NetIntentSetParams {
                id: "office".into(),
                destinations: vec!["10.0.0.0/8".into()],
                path: NetIntentPath {
                    gateway: None,
                    kind: "interface".into(),
                    interface: Some("utun5".into()),
                },
                metric: None,
                enabled: None,
            })
            .unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.method, method::NET_INTENT_SET);
        assert_eq!(request.params["id"], "office");
        assert_eq!(request.params["path"]["interface"], "utun5");

        let third = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(third.path(), |request| {
            ResponseFrame::ok(request.id, json!({"id": "office"}))
        });
        Engine::with_privileged(third.path(), Arc::new(client))
            .delete_intent("office")
            .unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.method, method::NET_INTENT_DEL);
        assert_eq!(request.params, json!({"id": "office"}));

        let old = tempfile::tempdir().unwrap();
        let (client, _) = fake_helper(old.path(), |request| {
            ResponseFrame::error(request.id, ErrorCode::UnsupportedMethod, "unsupported")
        });
        let error = Engine::with_privileged(old.path(), Arc::new(client))
            .intents()
            .unwrap_err();
        assert!(
            error.contains("too old") && error.contains("Settings"),
            "{error}"
        );
        let refused = tempfile::tempdir().unwrap();
        let (client, _) = fake_helper(refused.path(), |request| {
            ResponseFrame::error(
                request.id,
                ErrorCode::InvalidParams,
                "Choose a network interface for this intent",
            )
        });
        assert_eq!(
            Engine::with_privileged(refused.path(), Arc::new(client))
                .delete_intent("x")
                .unwrap_err(),
            "Choose a network interface for this intent"
        );
    }

    #[test]
    fn conditional_rules_go_through_the_helper_and_their_status_comes_back() {
        use net_manager_core::daemon_protocol::{ConditionalRuleState, RouteCondition};
        use net_manager_core::models::PolicyRoute;
        let rule = ConditionalRouteRule {
            id: "office".into(),
            name: "Office".into(),
            enabled: true,
            condition: RouteCondition::InterfaceAddressIn {
                prefix: "10.228.32.0/21".parse().unwrap(),
            },
            routes: vec![PolicyRoute {
                destination: "10.99.0.0/24".parse().unwrap(),
                metric: 5,
                via: None,
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(dir.path(), |request| {
            ResponseFrame::ok(
                request.id,
                json!({"stored": true, "status": {"state": "active", "matchedInterface": "en7", "appliedRoutes": 1}}),
            )
        });
        let status = Engine::with_privileged(dir.path(), Arc::new(client))
            .put_cond_rule(rule)
            .unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.method, method::COND_RULES_PUT);
        assert_eq!(request.params["rule"]["id"], "office");
        assert_eq!(status.state, ConditionalRuleState::Active);
        assert_eq!(status.matched_interface.as_deref(), Some("en7"));

        let other = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(other.path(), |request| {
            ResponseFrame::ok(request.id, json!({"rules": []}))
        });
        assert!(Engine::with_privileged(other.path(), Arc::new(client))
            .cond_rules()
            .unwrap()
            .is_empty());
        assert_eq!(seen.recv().unwrap().method, method::COND_RULES_LIST);

        let third = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(third.path(), |request| {
            ResponseFrame::ok(request.id, json!({"removed": true}))
        });
        assert!(Engine::with_privileged(third.path(), Arc::new(client))
            .remove_cond_rule("office")
            .unwrap());
        assert_eq!(seen.recv().unwrap().params, json!({"ruleId": "office"}));
    }

    #[test]
    fn only_xray_tun_profiles_are_delegated() {
        assert!(is_tun(&tun_profile()));
        let mut socks = tun_profile();
        socks.xray_mode = XrayMode::Socks;
        assert!(!is_tun(&socks));
        let mut other = tun_profile();
        other.backend = TunnelBackend::WireGuard;
        assert!(!is_tun(&other));
    }

    #[test]
    fn unreachable_helper_gets_an_actionable_message() {
        let error = helper_error(HelperError::Unreachable(std::io::Error::other("x")));
        assert!(error.contains("Install it in Settings"));
    }

    /// In-memory privileged side: records requests, answers from a script.
    struct Scripted {
        seen: Mutex<Vec<String>>,
        capabilities: Vec<String>,
    }

    impl Privileged for Scripted {
        fn hello(&self) -> Result<net_manager_core::daemon_protocol::HelloResult, HelperError> {
            Ok(net_manager_core::daemon_protocol::HelloResult {
                protocol: net_manager_core::daemon_protocol::PROTOCOL_VERSION,
                daemon_version: "t".into(),
                uid: 0,
                capabilities: self.capabilities.clone(),
                tools: Default::default(),
            })
        }

        fn call_raw(&self, method: &str, _params: Value) -> Result<Value, HelperError> {
            self.seen.lock().unwrap().push(method.to_string());
            Ok(match method {
                m if m == method::WIREGUARD_STATUS => json!({
                    "profileId":"wg-1","state":"stopped","interfaceName":null,
                    "latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[]}),
                _ => {
                    json!({"status": {"profileId":"wg-1","state":"running","interfaceName":"utun9",
                    "latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[]}})
                }
            })
        }

        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    #[test]
    fn a_profile_the_privileged_side_runs_never_starts_a_local_session() {
        let dir = tempfile::tempdir().unwrap();
        let revision = dir.path().join("configs/wg-1/rev-1");
        std::fs::create_dir_all(&revision).unwrap();
        std::fs::write(revision.join("wg-1.conf"), "[Interface]\nPrivateKey = x\n").unwrap();
        let profile = Profile {
            id: "wg-1".into(),
            name: "Home".into(),
            backend: TunnelBackend::WireGuard,
            config_path: revision.join("wg-1.conf"),
            ..Default::default()
        };
        let privileged = Arc::new(Scripted {
            seen: Mutex::new(Vec::new()),
            capabilities: vec![method::WIREGUARD_CONNECT.into()],
        });
        let engine = Engine::with_privileged(dir.path(), privileged.clone());
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        engine.connect(&store, &profile, None).unwrap();
        assert_eq!(
            privileged.seen.lock().unwrap().as_slice(),
            [method::WIREGUARD_STATUS, method::WIREGUARD_CONNECT]
        );
        assert!(engine.session_slot().unwrap().lock().unwrap().is_none());
        assert!(engine.is_running(&profile).is_ok());
    }
    #[test]
    fn named_proxy_exits_are_rejected_before_any_connection_or_helper_call() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = tun_profile();
        profile
            .xray_proxy_exits
            .push(net_manager_core::models::NamedProxyExit {
                name: "direct".into(),
                target: net_manager_core::models::ProxyTarget::Direct,
                no_proxy: Vec::new(),
            });
        let helper = Arc::new(Scripted {
            seen: Mutex::new(Vec::new()),
            capabilities: vec![method::XRAY_CONNECT.into()],
        });
        let engine = Engine::with_privileged(dir.path(), helper.clone());
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        assert!(engine
            .connect(&store, &profile, None)
            .unwrap_err()
            .contains("Named proxy exits"));
        assert!(request_tunnel(
            helper.as_ref(),
            dir.path(),
            &profile,
            b"{}".to_vec(),
            Vec::new(),
            None
        )
        .unwrap_err()
        .contains("Named proxy exits"));
        assert!(Engine::new(dir.path())
            .connect_foreground(&store, &profile, None)
            .err()
            .unwrap()
            .contains("Named proxy exits"));
        assert!(helper.seen.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
#[path = "macos_session_engine_tests.rs"]
mod shared_tests;
