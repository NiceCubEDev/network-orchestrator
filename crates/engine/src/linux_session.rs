//! One user-owned local Xray runtime per data directory and daemon endpoint.
//! GUI and CLI exchange IDs or bounded prepared snapshots over authenticated IPC.
//! Privileged route requests remain in the calling frontend's LinuxEngine so
//! polkit authenticates the actual interactive client, not a user service.
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::models::{Profile, TunnelBackend, TunnelState, TunnelStatus, XrayMode};
use net_manager_core::profiles::ProfileStore;
use net_manager_core::system_proxy::SystemProxyManager;
use net_manager_core::vpn::TunnelManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_FRAME: u64 = 1024 * 1024;
const PREPARED_CONNECTIONS_VERSION: u32 = 1;
static STOP: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Request {
    Capabilities,
    ConnectPrepared {
        connection: Box<PreparedLocalConnection>,
    },
    Disconnect {
        id: String,
    },
    Status {
        id: String,
    },
    Cleanup,
    RecoverProxy,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    prepared_connections_version: u32,
}

/// Flattening preserves the original status/down wire fields without allocating
/// a box for every ordinary status response.
#[derive(Serialize, Deserialize)]
struct Response {
    #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
    status: Option<TunnelStatus>,
    #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
    capabilities: Option<Capabilities>,
}

impl Response {
    fn status(status: TunnelStatus) -> Self {
        Self {
            status: Some(status),
            capabilities: None,
        }
    }

    fn capabilities(capabilities: Capabilities) -> Self {
        Self {
            status: None,
            capabilities: Some(capabilities),
        }
    }

    fn into_status(self) -> Result<TunnelStatus, String> {
        match (self.status, self.capabilities) {
            (Some(status), None) => Ok(status),
            _ => Err("Unexpected local runtime response".into()),
        }
    }
}

pub(crate) fn ensure_prepared_support(root: &Path, daemon: &Path) -> Result<(), String> {
    let restart = "Install a matching netorch version and restart its user runtime before connecting or applying connection sets";
    match send_request(root, daemon, Some(&Request::Capabilities), None) {
        Ok(Response {
            status: None,
            capabilities: Some(capabilities),
        }) if capabilities.prepared_connections_version == PREPARED_CONNECTIONS_VERSION => Ok(()),
        Ok(_) => Err(format!(
            "{restart}: prepared connection protocol is not supported"
        )),
        Err(error) => Err(format!("{restart}: {error}")),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedLocalConnection {
    profile: Profile,
    xray: net_manager_core::vpn::PreparedXrayConnection,
    assets: Option<PathBuf>,
    notices: Vec<String>,
}

/// Encoded once during preflight; input-only and never persisted or logged.
pub(crate) struct PreparedLocalRequest {
    bytes: Vec<u8>,
}

fn validate_local_profile(root: &Path, profile: &Profile) -> Result<(), String> {
    if uid() == 0 {
        return Err("Run the local Xray runtime as your own user, never root".into());
    }
    if profile.backend != TunnelBackend::Xray || profile.xray_mode != XrayMode::Socks {
        return Err("The user runtime only runs local Xray proxy profiles".into());
    }
    net_manager_core::profiles::validate_profile(profile)
        .map_err(|_| "Invalid local Xray profile")?;
    profile.check_role()?;
    if !ConfigVault::new(root.join("configs"))
        .is_managed_profile_path(&profile.id, &profile.config_path)
    {
        return Err("Local Xray profiles must use their own managed config".into());
    }
    Ok(())
}

pub(crate) fn prepare_connection(
    root: &Path,
    candidate: &Profile,
    prepare_ports: bool,
) -> Result<PreparedLocalRequest, String> {
    validate_local_profile(root, candidate)?;
    let mut profile = candidate.clone();
    let notice = if prepare_ports {
        let vault = ConfigVault::new(root.join("configs"));
        let store = ProfileStore::new(root.join("profiles.json"));
        let mut profiles = store.load().map_err(|_| "Cannot read profiles")?.profiles;
        net_manager_core::profile_import::prepare_connect_ports(
            &vault,
            &store,
            &mut profile,
            &mut profiles,
            |port| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok(),
        )
        .map_err(|_| "Cannot prepare local Xray listeners")?
    } else {
        None
    };
    let executable = crate::linux_system::backend_executable(root, TunnelBackend::Xray)?;
    let (assets, mut notices) =
        crate::linux_geo_assets::prepare_blocking(&root.join("geoassets"), &profile)?;
    if let Some(notice) = notice {
        notices.insert(0, notice);
    }
    let mut manager = TunnelManager::new();
    manager.set_executable(TunnelBackend::Xray, Some(executable));
    manager.set_xray_asset_dir(&profile.id, assets.clone());
    let xray = manager
        .prepare_xray_connection(&profile)
        .map_err(|_| "Local Xray configuration validation failed")?;
    listener_targets(&profile, &xray)?;
    let request = Request::ConnectPrepared {
        connection: Box::new(PreparedLocalConnection {
            profile,
            xray,
            assets,
            notices,
        }),
    };
    let bytes = serde_json::to_vec(&request).map_err(|_| "Cannot encode local runtime request")?;
    if bytes.len() as u64 + 1 > MAX_FRAME {
        return Err("Local runtime request is too large".into());
    }
    Ok(PreparedLocalRequest { bytes })
}

pub(crate) fn execute_prepared(
    root: &Path,
    daemon: &Path,
    prepared: &PreparedLocalRequest,
) -> Result<TunnelStatus, String> {
    send_request(root, daemon, None, Some(&prepared.bytes)).and_then(Response::into_status)
}

fn error(message: &str) -> io::Error {
    io::Error::other(message)
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn private_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != uid() || metadata.mode() & 0o077 != 0 {
        return Err(error("Local runtime directory is not private"));
    }
    Ok(())
}
pub(crate) fn lock_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(error("Local runtime lock is not private"));
    }
    Ok(file)
}
fn runtime_root() -> io::Result<PathBuf> {
    let path = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", uid())));
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.uid() != uid() || metadata.mode() & 0o077 != 0 {
        return Err(error("A private user runtime directory is required"));
    }
    Ok(path.join("netorch"))
}
fn proxy_state_root(xdg_state: Option<&Path>, home: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = xdg_state.filter(|path| path.is_absolute()) {
        return Ok(path.join("netorch"));
    }
    home.filter(|path| path.is_absolute())
        .map(|path| path.join(".local/state/netorch"))
        .ok_or_else(|| error("An absolute user state directory is required"))
}

fn session_directory(root: &Path, daemon: &Path) -> io::Result<PathBuf> {
    if uid() == 0 {
        return Err(error(
            "Run the local Xray runtime as your own user, never root",
        ));
    }
    if !root.is_absolute() {
        return Err(error("The data directory must be absolute"));
    }
    let canonical = match root.canonicalize() {
        Ok(path) => path,
        Err(cause) if cause.kind() == io::ErrorKind::NotFound => root.to_path_buf(),
        Err(_) => return Err(error("The application data directory is unavailable")),
    };
    let mut hash = Sha256::new();
    hash.update(canonical.as_os_str().as_encoded_bytes());
    hash.update(b"\0");
    hash.update(daemon.as_os_str().as_encoded_bytes());
    let key = format!("{:x}", hash.finalize());
    Ok(runtime_root()?.join(format!("session-{}", &key[..24])))
}

pub(crate) fn coordination_directory(root: &Path) -> io::Result<PathBuf> {
    let directory = session_directory(root, &crate::linux_engine::daemon_socket())?;
    private_directory(&runtime_root()?)?;
    private_directory(&directory)?;
    Ok(directory)
}
fn peer_is_user(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: the kernel fills a correctly sized ucred for this Unix socket.
    let valid = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        ) == 0
    };
    valid && credentials.uid == uid()
}
fn read_line(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    BufReader::new(stream)
        .take(MAX_FRAME + 1)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > MAX_FRAME || bytes.last() != Some(&b'\n') {
        return Err(error("Invalid local runtime frame"));
    }
    Ok(bytes)
}
fn stopped(id: &str) -> TunnelStatus {
    TunnelStatus {
        profile_id: id.into(),
        state: TunnelState::Stopped,
        message: None,
        interface_name: None,
        failover: None,
        watchdog: None,
    }
}

fn start_service(root: &Path, daemon: &Path, directory: &Path) -> io::Result<()> {
    let executable = std::env::current_exe()?.with_file_name("netorch");
    if !executable.is_file() {
        return Err(error(
            "Install netorch alongside the GUI to run local proxies",
        ));
    }
    let key = directory
        .file_name()
        .ok_or_else(|| error("Invalid local runtime directory"))?;
    let status = Command::new("systemd-run")
        .args(["--user", "--quiet", "--collect", "--service-type=exec"])
        .arg(format!("--unit=netorch-{}", key.to_string_lossy()))
        .arg("--property=KillMode=control-group")
        .arg("--property=Restart=on-failure")
        .arg(format!(
            "--setenv={}={}",
            net_manager_core::daemon_protocol::SOCKET_ENV,
            daemon.display()
        ))
        .arg("--")
        .arg(executable)
        .arg("--data-dir")
        .arg(root)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(error("Cannot start the netorch user service; check systemd --user, or run netorch serve in another terminal"));
    }
    Ok(())
}

pub(crate) fn request(
    root: &Path,
    daemon: &Path,
    request: Request,
) -> Result<TunnelStatus, String> {
    send_request(root, daemon, Some(&request), None).and_then(Response::into_status)
}

fn send_request(
    root: &Path,
    daemon: &Path,
    request: Option<&Request>,
    encoded: Option<&[u8]>,
) -> Result<Response, String> {
    let operation = || -> io::Result<Response> {
        let directory = session_directory(root, daemon)?;
        let socket = directory.join("runtime.sock");
        let mut stream = match UnixStream::connect(&socket) {
            Ok(stream) => stream,
            Err(cause)
                if matches!(
                    cause.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                let ownership =
                    net_manager_core::system_proxy::load_ownership(&root.join("proxy-state.json"))?;
                match request {
                    Some(Request::Status { id }) => return Ok(Response::status(stopped(id))),
                    Some(Request::Disconnect { id })
                        if !ownership
                            .as_ref()
                            .is_some_and(|owner| owner.profile_id == *id) =>
                    {
                        return Ok(Response::status(stopped(id)))
                    }
                    Some(Request::Cleanup | Request::RecoverProxy) if ownership.is_none() => {
                        return Ok(Response::status(stopped("")))
                    }
                    _ => {}
                }
                private_directory(&runtime_root()?)?;
                private_directory(&directory)?;
                let startup = lock_file(&directory.join("startup.lock"))?;
                startup.lock()?;
                match UnixStream::connect(&socket) {
                    Ok(stream) => stream,
                    Err(_) => {
                        start_service(root, daemon, &directory)?;
                        let deadline = Instant::now() + Duration::from_secs(10);
                        loop {
                            if let Ok(stream) = UnixStream::connect(&socket) {
                                break stream;
                            }
                            if Instant::now() >= deadline {
                                return Err(error("The netorch user service did not become ready"));
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            }
            Err(_) => return Err(error("Cannot reach the local Xray runtime")),
        };
        if !peer_is_user(&stream) {
            return Err(error("Local runtime peer ownership mismatch"));
        }
        let timeout = if matches!(request, Some(Request::Status { .. })) {
            2
        } else {
            330
        };
        stream.set_read_timeout(Some(Duration::from_secs(timeout)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        if let Some(encoded) = encoded {
            stream.write_all(encoded)?;
        } else {
            serde_json::to_writer(
                &mut stream,
                request.ok_or_else(|| error("Missing local runtime request"))?,
            )
            .map_err(|_| error("Cannot encode local runtime request"))?;
        }
        stream.write_all(b"\n")?;
        let result: Result<Response, String> = serde_json::from_slice(&read_line(&mut stream)?)
            .map_err(|_| error("Invalid local runtime response"))?;
        result.map_err(|message| error(&message))
    };
    operation().map_err(|cause| match cause.kind() {
        io::ErrorKind::Other => cause.to_string(),
        _ => "Local Xray runtime operation failed".into(),
    })
}

enum ListenerTarget {
    Literal(SocketAddr),
    Resolved(Vec<SocketAddr>),
}

impl ListenerTarget {
    fn ready(&self) -> bool {
        let addresses = match self {
            Self::Literal(address) => std::slice::from_ref(address),
            Self::Resolved(addresses) => addresses.as_slice(),
        };
        addresses
            .iter()
            .any(|address| TcpStream::connect_timeout(address, Duration::from_millis(100)).is_ok())
    }
}

fn listener_targets(
    profile: &Profile,
    prepared: &net_manager_core::vpn::PreparedXrayConnection,
) -> Result<Vec<ListenerTarget>, String> {
    let listeners = prepared
        .analyze(profile)
        .map_err(|_| "Cannot inspect local Xray listeners")?
        .listeners;
    if listeners.is_empty() {
        return Err("Local Xray config has no proxy listener".into());
    }
    listeners
        .into_iter()
        .map(|listener| {
            let host = match listener.address.as_str() {
                "" | "0.0.0.0" => "127.0.0.1",
                "::" => "::1",
                address => address,
            };
            match host.parse::<IpAddr>() {
                Ok(address) => Ok(ListenerTarget::Literal(SocketAddr::new(
                    address,
                    listener.port,
                ))),
                Err(_) => {
                    let addresses: Vec<_> = (host, listener.port)
                        .to_socket_addrs()
                        .map_err(|_| "Cannot resolve local Xray listener")?
                        .collect();
                    if addresses.is_empty() {
                        return Err("Local Xray listener has no address".into());
                    }
                    Ok(ListenerTarget::Resolved(addresses))
                }
            }
        })
        .collect()
}

struct ProxyLock(File);

impl Drop for ProxyLock {
    fn drop(&mut self) {
        // A forked child can retain the descriptor until exec; close alone is not an unlock.
        let _ = self.0.unlock();
    }
}

struct Runtime {
    root: PathBuf,
    tunnels: TunnelManager,
    active: HashMap<String, Profile>,
    proxy: SystemProxyManager,
    proxy_lock: Option<ProxyLock>,
    proxy_lock_root: PathBuf,
    proxy_cleanup_failed: bool,
}
impl Runtime {
    fn new(root: PathBuf, proxy: SystemProxyManager, proxy_lock_root: PathBuf) -> io::Result<Self> {
        let mut runtime = Self {
            tunnels: TunnelManager::with_log_dir(root.join("logs")),
            root,
            active: HashMap::new(),
            proxy,
            proxy_lock: None,
            proxy_lock_root,
            proxy_cleanup_failed: false,
        };
        if let Err(cause) = runtime.proxy_guard() {
            if cause.kind() != io::ErrorKind::WouldBlock || runtime.proxy.ownership().is_some() {
                return Err(cause);
            }
            return Ok(runtime);
        }
        runtime.restore_proxy()?;
        Ok(runtime)
    }

    fn proxy_guard(&mut self) -> io::Result<()> {
        if self.proxy_lock.is_none() {
            private_directory(&self.proxy_lock_root)?;
            let lock = ProxyLock(lock_file(&self.proxy_lock_root.join("system-proxy.lock"))?);
            lock.0.try_lock().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "System proxy is owned by another netorch data directory",
                )
            })?;
            let root = self
                .root
                .canonicalize()
                .unwrap_or_else(|_| self.root.clone());
            let owner = format!("{:x}", Sha256::digest(root.as_os_str().as_encoded_bytes()));
            let marker = self.proxy_lock_root.join("system-proxy.owner");
            match fs::read_to_string(&marker) {
                Ok(existing) if existing != owner => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "System proxy is owned by another netorch data directory",
                    ));
                }
                Ok(_) => {}
                Err(cause) if cause.kind() == io::ErrorKind::NotFound => {
                    let temporary = self.proxy_lock_root.join("system-proxy.owner.tmp");
                    let mut file = lock_file(&temporary)?;
                    file.set_len(0)?;
                    file.write_all(owner.as_bytes())?;
                    file.sync_all()?;
                    fs::rename(temporary, marker)?;
                }
                Err(cause) => return Err(cause),
            }
            self.proxy.reload_ownership()?;
            self.proxy_lock = Some(lock);
        }
        Ok(())
    }
    fn restore_proxy(&mut self) -> io::Result<()> {
        if self.proxy.ownership().is_some() {
            self.proxy_guard()?;
            self.proxy.restore_any()?;
        }
        if self.proxy_lock.is_some() {
            match fs::remove_file(self.proxy_lock_root.join("system-proxy.owner")) {
                Ok(()) => {}
                Err(cause) if cause.kind() == io::ErrorKind::NotFound => {}
                Err(cause) => return Err(cause),
            }
            self.proxy_lock = None;
        }
        self.proxy_cleanup_failed = false;
        Ok(())
    }
    fn disconnect(&mut self, id: &str) -> Result<TunnelStatus, String> {
        if self
            .proxy
            .ownership()
            .is_some_and(|owner| owner.profile_id == id)
        {
            self.restore_proxy()
                .map_err(|_| "Cannot restore the previous system proxy".to_string())?;
        }
        if let Some(profile) = self.active.get(id) {
            let status = self
                .tunnels
                .disconnect(profile)
                .map_err(|_| "Cannot stop local Xray".to_string())?;
            self.active.remove(id);
            Ok(status)
        } else {
            Ok(stopped(id))
        }
    }
    fn connect(&mut self, connection: PreparedLocalConnection) -> Result<TunnelStatus, String> {
        let PreparedLocalConnection {
            profile,
            xray,
            assets,
            notices,
        } = connection;
        let profile_id = profile.id.clone();
        let id = profile_id.as_str();
        validate_local_profile(&self.root, &profile)?;
        if self
            .active
            .get(id)
            .is_some_and(|profile| self.tunnels.status(profile).state == TunnelState::Running)
        {
            return Err("This local Xray profile is already running".into());
        }
        let executable = crate::linux_system::backend_executable(&self.root, TunnelBackend::Xray)?;
        self.tunnels
            .set_executable(TunnelBackend::Xray, Some(executable));
        if let Some(directory) = &assets {
            let geoip = profile
                .xray_geoip_url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty());
            let geosite = profile
                .xray_geosite_url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty());
            let expected = crate::linux_geo_assets::profile_asset_dir(
                &self.root.join("geoassets"),
                geoip,
                geosite,
            );
            if (geoip.is_none() && geosite.is_none())
                || *directory != expected
                || !fs::symlink_metadata(directory)
                    .is_ok_and(|metadata| metadata.is_dir() && metadata.uid() == uid())
            {
                return Err("Prepared local Xray asset directory is invalid".into());
            }
        }
        self.tunnels.set_xray_asset_dir(id, assets);
        if profile.use_system_proxy {
            self.proxy_guard().map_err(|cause| cause.to_string())?;
            if self.proxy.ownership().is_some() {
                if self.active.values().any(|running| {
                    running.use_system_proxy
                        && self.tunnels.status(running).state == TunnelState::Running
                }) {
                    return Err("System proxy is already owned by a running profile".into());
                }
                self.proxy
                    .restore_any()
                    .map_err(|_| "Cannot restore previous system proxy")?;
            }
        }
        let listeners = listener_targets(&profile, &xray)?;
        let mut status = self
            .tunnels
            .connect_prepared_xray(&profile, &xray)
            .map_err(|_| "Local Xray configuration validation or process startup failed")?;
        self.active.insert(id.into(), profile);
        let deadline = Instant::now() + Duration::from_secs(10);
        for listener in listeners {
            while !listener.ready() {
                let profile = self.active.get(id).expect("connected profile is recorded");
                if self.tunnels.status(profile).state != TunnelState::Running
                    || Instant::now() >= deadline
                {
                    self.disconnect(id)?;
                    return Err("Xray did not make its configured proxy listeners ready".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let profile = self.active.get(id).expect("connected profile is recorded");
        if profile.use_system_proxy {
            let port = profile.xray_socks_port.ok_or("SOCKS listener is missing")?;
            if self
                .proxy
                .apply_with_http(id, port, profile.xray_http_port, &profile.proxy_bypass)
                .is_err()
            {
                self.disconnect(id)?;
                return Err("Cannot apply the system proxy".into());
            }
        }
        for notice in notices {
            status.message = Some(match status.message.take() {
                Some(message) => format!("{message}; {notice}"),
                None => notice,
            });
        }
        Ok(status)
    }
    fn handle(&mut self, request: Request) -> Result<Response, String> {
        let status = match request {
            Request::Capabilities => {
                return Ok(Response::capabilities(Capabilities {
                    prepared_connections_version: PREPARED_CONNECTIONS_VERSION,
                }))
            }
            Request::ConnectPrepared { connection } => {
                let result = self.connect(*connection);
                if let Err(message) = &result {
                    if self.proxy.ownership().is_none()
                        && self.proxy_lock.is_some()
                        && self.restore_proxy().is_err()
                    {
                        return Err(format!("{message}; cannot release system proxy ownership"));
                    }
                }
                result
            }
            Request::Disconnect { id } => self.disconnect(&id),
            Request::Status { id } => Ok(self
                .active
                .get(&id)
                .map(|profile| self.tunnels.status(profile))
                .unwrap_or_else(|| stopped(&id))),
            Request::Cleanup => {
                let mut errors = Vec::new();
                for id in self.active.keys().cloned().collect::<Vec<_>>() {
                    if let Err(error) = self.disconnect(&id) {
                        errors.push(error);
                    }
                }
                if self.active.is_empty() && self.restore_proxy().is_err() {
                    errors.push("Cannot restore the previous system proxy".into());
                }
                if errors.is_empty() {
                    Ok(stopped(""))
                } else {
                    Err(errors.join("; "))
                }
            }
            Request::RecoverProxy => {
                let healthy = self
                    .proxy
                    .ownership()
                    .and_then(|owner| self.active.get(&owner.profile_id))
                    .is_some_and(|profile| {
                        self.tunnels.status(profile).state == TunnelState::Running
                    });
                if !healthy {
                    self.restore_proxy()
                        .map_err(|_| "Cannot restore the previous system proxy")?;
                }
                Ok(stopped(""))
            }
        }?;
        Ok(Response::status(status))
    }
    fn check_child_health(&mut self) {
        let restore = self.active.iter().any(|(id, profile)| {
            self.tunnels.status(profile).state != TunnelState::Running
                && self
                    .proxy
                    .ownership()
                    .is_some_and(|owner| owner.profile_id == *id)
        });
        if restore && !self.proxy_cleanup_failed && self.restore_proxy().is_err() {
            self.proxy_cleanup_failed = true;
            eprintln!("netorch: system proxy cleanup failed; ownership kept for recovery");
        }
    }
}
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// The long-lived, unprivileged backend used by both frontends. It never
/// writes routes/interfaces/DNS or executes configuration-supplied commands.
pub fn serve(root: PathBuf, daemon: PathBuf) -> Result<(), String> {
    let run = || -> io::Result<()> {
        let directory = session_directory(&root, &daemon)?;
        private_directory(&runtime_root()?)?;
        private_directory(&directory)?;
        let lifetime = lock_file(&directory.join("server.lock"))?;
        lifetime
            .try_lock()
            .map_err(|_| error("The user runtime is already running"))?;
        let socket = directory.join("runtime.sock");
        match fs::remove_file(&socket) {
            Ok(()) => {}
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => {}
            Err(cause) => return Err(cause),
        }
        let proxy = SystemProxyManager::new(root.join("proxy-state.json"))?;
        let state = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from);
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let proxy_root = proxy_state_root(state.as_deref(), home.as_deref())?;
        let mut runtime = Runtime::new(root, proxy, proxy_root)?;
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        // SAFETY: handlers only set an atomic; teardown happens in this loop.
        unsafe {
            libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        }
        let mut idle_since = Instant::now();
        let mut health_check = Instant::now();
        while !STOP.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if !peer_is_user(&stream) {
                        continue;
                    }
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                    let response = read_line(&mut stream)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<Request>(&bytes).ok())
                        .ok_or_else(|| "Invalid local runtime request".to_string())
                        .and_then(|request| runtime.handle(request));
                    let _ = serde_json::to_writer(&mut stream, &response);
                    let _ = stream.write_all(b"\n");
                    idle_since = Instant::now();
                }
                Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(cause) => return Err(cause),
            }
            if health_check.elapsed() >= Duration::from_secs(1) {
                runtime.check_child_health();
                // Retain failed status until explicit disconnect, just like a
                // live profile; only an empty runtime expires.
                if !runtime.active.is_empty() {
                    idle_since = Instant::now();
                }
                health_check = Instant::now();
            }
            if idle_since.elapsed() >= Duration::from_secs(30) {
                break;
            }
        }
        let cleanup = runtime
            .handle(Request::Cleanup)
            .map_err(|message| error(&message));
        let _ = fs::remove_file(socket);
        cleanup.map(|_| ())
    };
    run().map_err(|cause| {
        if cause.kind() == io::ErrorKind::Other {
            cause.to_string()
        } else {
            "Local Xray runtime failed".into()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::backend_settings::BackendSettingsStore;
    use net_manager_core::models::{BackendExecutableSetting, BackendExecutableSource};
    use net_manager_core::system_proxy::{ProxyAdapter, ProxySnapshot};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn proxy_ownership_path_uses_persistent_user_state() {
        assert_eq!(
            proxy_state_root(
                Some(Path::new("/custom/state")),
                Some(Path::new("/home/user"))
            )
            .unwrap(),
            PathBuf::from("/custom/state/netorch")
        );
        assert_eq!(
            proxy_state_root(Some(Path::new("relative")), Some(Path::new("/home/user"))).unwrap(),
            PathBuf::from("/home/user/.local/state/netorch")
        );
        assert!(proxy_state_root(None, Some(Path::new("relative"))).is_err());
        assert!(proxy_state_root(None, None).is_err());
    }

    #[derive(Default)]
    struct FakeProxy {
        restored: Vec<ProxySnapshot>,
        fail_restore: bool,
    }

    struct Adapter(Arc<Mutex<FakeProxy>>);
    impl ProxyAdapter for Adapter {
        fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
            Ok(ProxySnapshot {
                proxy_server: Some("original".into()),
                ..Default::default()
            })
        }
        fn apply(&mut self, _: &str, _: &str) -> io::Result<()> {
            Ok(())
        }
        fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.fail_restore {
                return Err(error("restore failed"));
            }
            state.restored.push(snapshot.clone());
            Ok(())
        }
    }

    fn manager(root: &Path, state: &Arc<Mutex<FakeProxy>>) -> SystemProxyManager {
        SystemProxyManager::with_adapter(
            root.join("proxy-state.json"),
            Box::new(Adapter(state.clone())),
        )
        .unwrap()
    }

    #[test]
    fn startup_recovers_persisted_proxy_before_commands() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let locks = dir.path().join("runtime");
        let state = Arc::new(Mutex::new(FakeProxy::default()));
        let mut previous = manager(&root, &state);
        previous.apply("stale", 10808, &[]).unwrap();
        drop(previous);

        let runtime = Runtime::new(root.clone(), manager(&root, &state), locks).unwrap();
        assert!(runtime.proxy.ownership().is_none());
        assert_eq!(
            state.lock().unwrap().restored[0].proxy_server.as_deref(),
            Some("original")
        );
        assert!(
            net_manager_core::system_proxy::load_ownership(&root.join("proxy-state.json"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn startup_restore_failure_preserves_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let state = Arc::new(Mutex::new(FakeProxy::default()));
        let mut previous = manager(&root, &state);
        previous.apply("stale", 10808, &[]).unwrap();
        drop(previous);
        state.lock().unwrap().fail_restore = true;
        assert!(Runtime::new(
            root.clone(),
            manager(&root, &state),
            dir.path().join("runtime")
        )
        .is_err());
        assert!(
            net_manager_core::system_proxy::load_ownership(&root.join("proxy-state.json"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn failed_proxy_restore_retains_live_lock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let locks = dir.path().join("runtime");
        let state = Arc::new(Mutex::new(FakeProxy::default()));
        let mut runtime =
            Runtime::new(root.clone(), manager(&root, &state), locks.clone()).unwrap();
        runtime.proxy_guard().unwrap();
        runtime.proxy.apply("live", 10808, &[]).unwrap();
        state.lock().unwrap().fail_restore = true;
        assert!(runtime.restore_proxy().is_err());
        assert!(runtime.proxy.ownership().is_some());
        assert!(lock_file(&locks.join("system-proxy.lock"))
            .unwrap()
            .try_lock()
            .is_err());
    }

    #[test]
    fn failed_child_restores_proxy_and_keeps_failed_profile() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let state = Arc::new(Mutex::new(FakeProxy::default()));
        let mut runtime = Runtime::new(
            root.clone(),
            manager(&root, &state),
            dir.path().join("runtime"),
        )
        .unwrap();
        runtime.proxy_guard().unwrap();
        runtime.proxy.apply("failed", 10808, &[]).unwrap();
        let profile = Profile {
            id: "failed".into(),
            backend: TunnelBackend::Xray,
            ..Default::default()
        };
        runtime.active.insert(profile.id.clone(), profile);
        runtime.check_child_health();
        assert!(runtime.proxy.ownership().is_none());
        assert_eq!(state.lock().unwrap().restored.len(), 1);
        assert!(runtime.active.contains_key("failed"));
    }

    #[test]
    fn live_proxy_owner_cannot_be_recovered_by_another_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let locks = dir.path().join("runtime");
        let state = Arc::new(Mutex::new(FakeProxy::default()));
        let mut runtime =
            Runtime::new(root.clone(), manager(&root, &state), locks.clone()).unwrap();
        runtime.proxy_guard().unwrap();
        runtime.proxy.apply("live", 10808, &[]).unwrap();
        assert!(Runtime::new(root.clone(), manager(&root, &state), locks).is_err());
        assert!(state.lock().unwrap().restored.is_empty());
    }

    #[test]
    fn crashed_other_data_directory_cannot_become_proxy_owner() {
        let dir = tempfile::tempdir().unwrap();
        let locks = dir.path().join("runtime");
        let state = Arc::new(Mutex::new(FakeProxy::default()));
        let first = dir.path().join("first");
        let mut runtime =
            Runtime::new(first.clone(), manager(&first, &state), locks.clone()).unwrap();
        runtime.proxy_guard().unwrap();
        runtime.proxy.apply("live", 10808, &[]).unwrap();
        drop(runtime);

        let second = dir.path().join("second");
        let mut other =
            Runtime::new(second.clone(), manager(&second, &state), locks.clone()).unwrap();
        assert!(other.proxy_guard().is_err());
        assert!(
            net_manager_core::system_proxy::load_ownership(&first.join("proxy-state.json"))
                .unwrap()
                .is_some()
        );
        let recovered = Runtime::new(first.clone(), manager(&first, &state), locks).unwrap();
        assert!(recovered.proxy.ownership().is_none());
        assert_eq!(state.lock().unwrap().restored.len(), 1);
        other.proxy_guard().unwrap();
    }

    #[test]
    fn proxy_lock_is_released_while_a_forked_child_waits_to_exec() {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let locks = dir.path().join("runtime");
        let state = Arc::new(Mutex::new(FakeProxy::default()));
        let mut runtime =
            Runtime::new(root.clone(), manager(&root, &state), locks.clone()).unwrap();
        runtime.proxy_guard().unwrap();
        runtime.proxy.apply("live", 10808, &[]).unwrap();

        let (mut ready, notify) = UnixStream::pair().unwrap();
        ready
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (resume, mut release) = UnixStream::pair().unwrap();
        let notify_fd = notify.as_raw_fd();
        let resume_fd = resume.as_raw_fd();
        let ready_fd = ready.as_raw_fd();
        let release_fd = release.as_raw_fd();
        let child = std::thread::spawn(move || {
            let mut command = Command::new("/bin/true");
            // SAFETY: the child only uses async-signal-safe syscalls before exec.
            // The streams stay open in this thread until spawn completes.
            unsafe {
                command.pre_exec(move || {
                    // Let parent failure close the channel instead of orphaning this child.
                    libc::close(ready_fd);
                    libc::close(release_fd);
                    if libc::write(notify_fd, b"x".as_ptr().cast(), 1) != 1 {
                        return Err(io::Error::last_os_error());
                    }
                    let mut byte = 0u8;
                    if libc::read(resume_fd, (&mut byte as *mut u8).cast(), 1) != 1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let spawned = command.spawn();
            drop(notify);
            drop(resume);
            spawned?.wait()
        });

        ready.read_exact(&mut [0]).unwrap();
        drop(runtime);
        let recovered = Runtime::new(root.clone(), manager(&root, &state), locks);
        release.write_all(b"x").unwrap();
        assert!(child.join().unwrap().unwrap().success());
        let recovered =
            recovered.expect("an inherited pre-exec descriptor must not retain proxy ownership");
        assert!(recovered.proxy.ownership().is_none());
    }

    #[test]
    fn response_envelope_preserves_legacy_wire_fields_and_rejects_mixed_payloads() {
        let legacy: Result<Response, String> = serde_json::from_str(
            r#"{"Ok":{"profileId":"legacy","state":"running","message":null}}"#,
        )
        .unwrap();
        let status = legacy.unwrap().into_status().unwrap();
        assert_eq!(status.profile_id, "legacy");
        assert_eq!(status.state, TunnelState::Running);
        let encoded =
            serde_json::to_value(Ok::<_, String>(Response::status(stopped("legacy")))).unwrap();
        assert_eq!(encoded["Ok"]["profileId"], "legacy");
        assert_eq!(encoded["Ok"]["state"], "stopped");
        assert!(encoded["Ok"].get("status").is_none());
        assert!(encoded["Ok"].get("capabilities").is_none());

        let capabilities: Result<Response, String> =
            serde_json::from_str(r#"{"Ok":{"preparedConnectionsVersion":1}}"#).unwrap();
        let capabilities = capabilities.unwrap();
        assert!(capabilities.status.is_none());
        assert_eq!(
            capabilities
                .capabilities
                .unwrap()
                .prepared_connections_version,
            1
        );
        let encoded = serde_json::to_value(Response::capabilities(Capabilities {
            prepared_connections_version: 1,
        }))
        .unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({"preparedConnectionsVersion": 1})
        );

        for invalid in [
            r#"{"profileId":"legacy","state":"running","message":null,"preparedConnectionsVersion":1}"#,
            r#"{"profileId":"legacy","message":null}"#,
            r#"{}"#,
        ] {
            let rejected = match serde_json::from_str::<Response>(invalid) {
                Ok(response) => response.into_status().is_err(),
                Err(_) => true,
            };
            assert!(
                rejected,
                "mixed or incomplete metadata must not invent a tunnel status"
            );
        }
    }

    fn local_snapshot_fixture() -> (tempfile::TempDir, PathBuf, Profile, TcpListener) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("data");
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let executable = directory.path().join("xray");
        let captured = directory.path().join("captured.json");
        fs::write(&executable, format!("#!/bin/sh\ncase \" $* \" in *\" -test \"*) /bin/cat >/dev/null; exit 0;; esac\n/bin/cat >'{}'\nexec /bin/sleep 30\n", captured.display())).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let vault = ConfigVault::new(root.join("configs"));
        let config = serde_json::json!({
            "inbounds": [{"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":port,"settings":{"udp":true}}],
            "outbounds": [{"tag":"direct","protocol":"freedom"}]
        });
        let stored = vault
            .store_generated_xray("local-fixture", &serde_json::to_vec(&config).unwrap())
            .unwrap();
        let profile = Profile {
            id: "local-fixture".into(),
            name: "Local fixture".into(),
            backend: TunnelBackend::Xray,
            config_path: stored.config_path,
            xray_socks_port: Some(port),
            ..Profile::default()
        };
        ProfileStore::new(root.join("profiles.json"))
            .upsert(profile.clone())
            .unwrap();
        BackendSettingsStore::new(root.join("backend-settings.json"))
            .set(
                TunnelBackend::Xray,
                Some(BackendExecutableSetting {
                    path: executable,
                    source: BackendExecutableSource::Configured,
                    version: None,
                }),
            )
            .unwrap();
        (directory, root, profile, listener)
    }

    fn isolated_runtime(test_name: &str, run: impl FnOnce()) {
        const CHILD: &str = "NETORCH_LOCAL_PREFLIGHT_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            run();
            return;
        }
        let runtime = tempfile::tempdir().unwrap();
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD, "1")
            .env("XDG_RUNTIME_DIR", runtime.path())
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "isolated local-runtime behavioral regression failed: {status}"
        );
    }

    fn legacy_runtime(
        root: &Path,
        daemon: &Path,
    ) -> (
        Arc<AtomicBool>,
        Arc<Mutex<Vec<String>>>,
        std::thread::JoinHandle<()>,
    ) {
        let directory = session_directory(root, daemon).unwrap();
        private_directory(&directory).unwrap();
        let listener = UnixListener::bind(directory.join("runtime.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = done.clone();
        let observed = requests.clone();
        let thread = std::thread::spawn(move || {
            let mut running = true;
            while !stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("legacy fixture socket failed: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let value: serde_json::Value =
                    serde_json::from_slice(&read_line(&mut stream).unwrap()).unwrap();
                let operation = value["operation"]
                    .as_str()
                    .expect("runtime request operation");
                observed.lock().unwrap().push(operation.into());
                let response: Result<TunnelStatus, String> = match operation {
                    "status" => {
                        let mut status = stopped(value["id"].as_str().unwrap());
                        if running {
                            status.state = TunnelState::Running;
                        }
                        Ok(status)
                    }
                    "disconnect" => {
                        running = false;
                        Ok(stopped(value["id"].as_str().unwrap()))
                    }
                    _ => Err("Invalid local runtime request".into()),
                };
                serde_json::to_writer(&mut stream, &response).unwrap();
                stream.write_all(b"\n").unwrap();
            }
        });
        (done, requests, thread)
    }

    #[test]
    fn prepared_local_preflight_rejects_legacy_runtime_before_mutation() {
        isolated_runtime(
            "linux_session::tests::prepared_local_preflight_rejects_legacy_runtime_before_mutation",
            || {
                let (directory, root, profile, _listener) = local_snapshot_fixture();
                let daemon = directory.path().join("daemon.sock");
                let (done, requests, thread) = legacy_runtime(&root, &daemon);
                let vault = ConfigVault::new(root.join("configs"));
                let engine = crate::linux_engine::LinuxEngine::for_socket(daemon, "preflight-test")
                    .with_data_root(root);
                let result = engine.prepare_connection(&vault, &profile, None, &(), false);
                done.store(true, Ordering::SeqCst);
                thread.join().unwrap();
                assert!(
                    result.is_err(),
                    "legacy runtime must be rejected during preparation, before any set teardown"
                );
                let error = result.err().unwrap();
                assert!(error.to_ascii_lowercase().contains("restart"), "compatibility failure must explain that a matching runtime restart is needed: {error}");
                assert!(!requests
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|operation| operation == "connect"
                        || operation == "connectPrepared"
                        || operation == "disconnect"));
            },
        );
    }

    #[test]
    fn legacy_runtime_status_and_down_remain_usable() {
        isolated_runtime(
            "linux_session::tests::legacy_runtime_status_and_down_remain_usable",
            || {
                let (directory, root, _profile, _listener) = local_snapshot_fixture();
                let daemon = directory.path().join("daemon.sock");
                let (done, _requests, thread) = legacy_runtime(&root, &daemon);
                let status = request(
                    &root,
                    &daemon,
                    Request::Status {
                        id: "local-fixture".into(),
                    },
                )
                .unwrap();
                let down = request(
                    &root,
                    &daemon,
                    Request::Disconnect {
                        id: "local-fixture".into(),
                    },
                )
                .unwrap();
                done.store(true, Ordering::SeqCst);
                thread.join().unwrap();
                assert_eq!(status.state, TunnelState::Running);
                assert_eq!(down.state, TunnelState::Stopped);
            },
        );
    }

    #[test]
    fn retained_local_snapshot_starts_after_its_source_revision_is_deleted() {
        let (directory, root, profile, _listener) = local_snapshot_fixture();
        let executable =
            crate::linux_system::backend_executable(&root, TunnelBackend::Xray).unwrap();
        let mut manager = TunnelManager::new();
        manager.set_executable(TunnelBackend::Xray, Some(executable));
        let xray = manager.prepare_xray_connection(&profile).unwrap();
        fs::remove_file(&profile.config_path).unwrap();
        let mut runtime = Runtime {
            tunnels: manager,
            proxy: SystemProxyManager::new(root.join("proxy-state.json")).unwrap(),
            root,
            active: HashMap::new(),
            proxy_lock: None,
            proxy_cleanup_failed: false,
            proxy_lock_root: directory.path().join("runtime"),
        };
        let id = profile.id.clone();
        let result = runtime.connect(PreparedLocalConnection {
            profile,
            xray,
            assets: None,
            notices: Vec::new(),
        });
        assert!(result.is_ok(), "runtime must execute retained validated bytes without requiring the deleted revision: {result:?}");
        assert_eq!(result.unwrap().state, TunnelState::Running);
        runtime.disconnect(&id).unwrap();
    }
}
