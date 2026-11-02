//! Unprivileged runtime: Xray in loopback SOCKS/HTTP mode plus the per-user
//! macOS system proxy. Routes, interfaces and DNS stay out of this crate; they
//! belong to the privileged launchd helper (plan 14). Xray TUN, WireGuard and
//! OpenVPN profiles are delegated to that helper over `daemon_protocol`; this
//! crate only asks.
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
use serde::Serialize;
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
}

/// One session per data root, so isolated QA directories never share state.
static SESSIONS: Mutex<Option<HashMap<PathBuf, Session>>> = Mutex::new(None);
static DOWNLOAD_RUNTIME: OnceLock<Result<tokio::runtime::Runtime, std::io::Error>> =
    OnceLock::new();

/// What the client shows about the runtime after every operation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub xray_installed: bool,
    pub xray_version: &'static str,
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
}

fn xray_root(root: &Path) -> PathBuf {
    root.join("backends").join("xray")
}

/// After a crash nothing we spawned can still be owned, so stale Xray
/// processes from our managed path are stopped and a proxy left pointing at
/// them is rolled back before anything else runs.
fn recover(root: &Path, proxy: &mut SystemProxyManager) {
    let executable = managed_xray::macos_managed_version_dir(&xray_root(root)).join("xray");
    if executable.is_file() {
        let _ = std::process::Command::new("/usr/bin/pkill")
            .arg("-f")
            .arg(stale_xray_pattern(&executable))
            .status();
    }
    let _ = proxy.restore_any();
}

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
    root: &Path,
    action: impl FnOnce(&mut Session) -> Result<T, String>,
) -> Result<T, String> {
    let mut sessions = SESSIONS
        .lock()
        .map_err(|_| "Connection service is unavailable".to_string())?;
    let sessions = sessions.get_or_insert_with(HashMap::new);
    if !sessions.contains_key(root) {
        let runtime = root.join("runtime");
        let mut proxy = SystemProxyManager::new(runtime.join("system-proxy.json"))
            .map_err(|_| "System proxy state could not be read".to_string())?;
        recover(root, &mut proxy);
        let session = Session {
            tunnels: TunnelManager::with_log_dir(runtime.join("logs")),
            proxy,
        };
        sessions.insert(root.to_path_buf(), session);
    }
    action(sessions.get_mut(root).expect("session inserted above"))
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

/// Where launchd collects the helper's own stderr.
const HELPER_LOG: &str = "/var/log/network-orchestrator-helper.log";

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
    let geo = crate::geo::prepare(&engine.root, &executable, profile)?;
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
    request_tunnel(
        client,
        &engine.root,
        profile,
        config,
        resolver_bypass(),
        geo.map(|geo| geo.inline),
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
        xray_version: managed_xray::MACOS_XRAY_VERSION,
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

/// Hands back a per-app system proxy this profile left behind, without
/// starting a session (which would also run crash recovery).
fn release_own_proxy(root: &Path, profile_id: &str) -> Result<(), String> {
    let mut proxy = SystemProxyManager::new(root.join("runtime").join("system-proxy.json"))
        .map_err(|_| "System proxy state could not be read".to_string())?;
    if proxy
        .ownership()
        .is_some_and(|owner| owner.profile_id == profile_id)
    {
        proxy
            .restore(profile_id)
            .map_err(|_| "The previous system proxy could not be restored".to_string())?;
    }
    Ok(())
}

impl Engine {
    /// Engine that talks to the launchd helper over its socket.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let mut engine = Self::with_privileged(root, Arc::new(socket_client()));
        engine.tailscale = Some(Arc::new(Tailscale::detect()));
        engine
    }

    /// Engine with another privileged side (executors in the CLI process,
    /// or a fake in tests).
    pub fn with_privileged(root: impl Into<PathBuf>, privileged: Arc<dyn Privileged>) -> Self {
        Self {
            root: root.into(),
            privileged,
            tailscale: None,
        }
    }

    /// Bring the helper's Tailscale guard in line with the running tunnels
    /// and Tailscale itself (see [`tailscale::sync`]). `None` for engines
    /// that do not guard Tailscale.
    pub fn sync_tailscale(&self) -> Option<serde_json::Value> {
        let tailscale = self.tailscale.as_ref()?;
        Some(tailscale::sync(self.privileged(), tailscale))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn privileged(&self) -> &dyn Privileged {
        self.privileged.as_ref()
    }

    /// The verified managed Xray, when one is installed.
    pub fn managed_executable(&self) -> Option<PathBuf> {
        let xray = xray_root(&self.root);
        let executable = managed_xray::macos_managed_version_dir(&xray).join("xray");
        managed_xray::verify_managed_macos_executable(&xray, &executable)
            .ok()
            .map(|_| executable)
    }

    pub fn is_running(&self, profile: &Profile) -> Result<bool, String> {
        if let Some(status) = remote_status(self.privileged(), profile) {
            return Ok(status.state == TunnelState::Running);
        }
        with_session(&self.root, |session| {
            Ok(running(session, self.privileged(), profile))
        })
    }

    /// State of a profile the privileged side runs, read without touching
    /// this process's own sessions; `None` for loopback Xray profiles.
    pub fn remote_status(&self, profile: &Profile) -> Option<TunnelStatus> {
        remote_status(self.privileged(), profile)
    }

    pub fn snapshot(&self, profiles: &[Profile]) -> Result<Snapshot, String> {
        with_session(&self.root, |session| {
            Ok(snapshot_of(self, session, profiles))
        })
    }

    /// What the profile needs from the user before it can connect.
    pub fn credential_requirements(
        &self,
        profile: &Profile,
    ) -> Result<CredentialRequirements, String> {
        vpn_backends::requirements(&self.root, profile)
    }

    /// Start a connection and confirm it survived startup. Profiles the
    /// privileged side runs never touch this process's sessions.
    pub fn connect(
        &self,
        store: &ProfileStore,
        profile: &Profile,
        credentials: Option<OpenVpnCredentials>,
    ) -> Result<(), String> {
        let root = self.root.as_path();
        let privileged = self.privileged();
        let mut profile = profile.clone();
        if is_remote(&profile) {
            if is_tun(&profile) {
                // The tunnel captures everything; a leftover per-app proxy for
                // this profile would point at a listener that no longer runs.
                release_own_proxy(root, &profile.id)?;
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
                let _ = self.sync_tailscale();
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
        with_session(root, |session| {
            session
                .tunnels
                .set_executable(TunnelBackend::Xray, Some(executable));
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
            // Xray exits immediately on a bad config or a busy port.
            std::thread::sleep(Duration::from_millis(600));
            if session.tunnels.status(profile).state != TunnelState::Running {
                return Err(failure_message(&session.tunnels, profile));
            }
            Ok(())
        })
    }

    /// Stop a profile the privileged side runs, without starting a session
    /// of this process.
    pub fn disconnect_remote(&self, profile: &Profile) -> Result<(), String> {
        if !is_remote(profile) {
            return Err("This connection runs inside the app that started it".into());
        }
        let stopped = stop_remote(self.privileged(), profile);
        let _ = self.sync_tailscale();
        stopped
    }

    /// Stop a connection, handing back a system proxy it owned.
    pub fn disconnect(&self, profile: &Profile, profiles: &[Profile]) -> Result<Snapshot, String> {
        with_session(&self.root, |session| {
            if session
                .proxy
                .ownership()
                .is_some_and(|owner| owner.profile_id == profile.id)
            {
                session
                    .proxy
                    .restore(&profile.id)
                    .map_err(|_| "The previous system proxy could not be restored".to_string())?;
            }
            stop(session, self.privileged(), profile)?;
            let _ = self.sync_tailscale();
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
        with_session(&self.root, |session| {
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
                session
                    .proxy
                    .apply_with_http(
                        &profile.id,
                        socks,
                        profile.xray_http_port,
                        &search_domain_bypass(),
                    )
                    .map_err(|error| {
                        if error.kind() == std::io::ErrorKind::AlreadyExists {
                            "Another connection already owns the system proxy".to_string()
                        } else {
                            "The system proxy could not be changed".to_string()
                        }
                    })?;
            } else if session.proxy.ownership().is_some() {
                session
                    .proxy
                    .restore(&profile.id)
                    .map_err(|_| "The previous system proxy could not be restored".to_string())?;
            }
            Ok(snapshot_of(self, session, profiles))
        })
    }

    /// The profile that owns the per-user system proxy, if any.
    pub fn system_proxy_owner(&self) -> Result<Option<String>, String> {
        with_session(&self.root, |session| {
            Ok(session
                .proxy
                .ownership()
                .map(|owner| owner.profile_id.clone()))
        })
    }

    /// Status, protocol health and system-proxy owner of a profile this
    /// process runs itself (loopback Xray), for diagnostics.
    pub fn loopback_state(
        &self,
        profile: &Profile,
    ) -> Result<(TunnelStatus, ProtocolHealth, Option<String>), String> {
        with_session(&self.root, |session| {
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
        with_session(&self.root, |session| {
            let stale = stale_proxy_owner(session, self.privileged(), profiles);
            Ok(recovery::report(self.privileged(), stale.as_deref()))
        })
    }

    /// Undo what [`Engine::recovery_report`] lists and report what remains.
    /// Running connections are never touched.
    pub fn recovery_cleanup(&self, profiles: &[Profile]) -> Result<RecoveryReport, String> {
        with_session(&self.root, |session| {
            let helper = recovery::cleanup(self.privileged());
            if let Some(owner) = stale_proxy_owner(session, self.privileged(), profiles) {
                session
                    .proxy
                    .restore(&owner)
                    .map_err(|_| "The previous system proxy could not be restored".to_string())?;
            }
            helper?;
            let stale = stale_proxy_owner(session, self.privileged(), profiles);
            Ok(recovery::report(self.privileged(), stale.as_deref()))
        })
    }

    /// Give the system proxy back and stop everything this app started.
    pub fn shutdown(&self, profiles: &[Profile]) -> Result<(), String> {
        with_session(&self.root, |session| {
            let restored = session.proxy.restore_any();
            for profile in profiles {
                if running(session, self.privileged(), profile) {
                    let _ = stop(session, self.privileged(), profile);
                }
            }
            let _ = self.sync_tailscale();
            restored.map_err(|_| "The previous system proxy could not be restored".to_string())
        })
    }

    /// Tail of the privileged helper's own log (start-up recovery, device and
    /// route errors).
    pub fn helper_log(&self) -> String {
        helper_log_text(Path::new(HELPER_LOG))
    }

    /// Tail of the connection's log, empty when it has none.
    pub fn log(&self, profile: &Profile) -> Result<String, String> {
        if is_tun(profile) {
            return Ok(tun_log_tail(self.privileged()).unwrap_or_default());
        }
        if vpn_backends::is_openvpn(profile) {
            return Ok(openvpn_log_tail(self.privileged()).unwrap_or_default());
        }
        if vpn_backends::is_wireguard(profile) {
            return Ok(wireguard_log_tail(self.privileged()).unwrap_or_default());
        }
        with_session(&self.root, |session| {
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
        let load = || {
            store
                .load()
                .map(|document| document.profiles)
                .map_err(|_| "Profiles could not be loaded".to_string())
        };
        let before = find_profile(&load()?, id)?;
        let was_running = self.is_running(&before)?;
        if was_running {
            with_session(&self.root, |session| {
                stop(session, self.privileged(), &before)
                    .map_err(|_| "The connection could not be restarted".to_string())
            })?;
        }
        let result = change();
        if was_running {
            let after = find_profile(&load()?, id)?;
            self.connect(store, &after, None)?;
        }
        result
    }

    /// Installs the pinned Xray either by download or, for closed networks,
    /// from a user-supplied copy of the same official zip; both paths are
    /// hash-checked.
    pub fn install_xray(&self, archive_path: Option<&str>) -> Result<(), String> {
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
        // A session would have run crash recovery, which stops Xray children
        // and the proxy of another process using the same data directory.
        let sessions = SESSIONS.lock().unwrap();
        assert!(sessions
            .as_ref()
            .is_none_or(|sessions| !sessions.contains_key(dir.path())));
        assert!(engine.is_running(&profile).is_ok());
    }
}
