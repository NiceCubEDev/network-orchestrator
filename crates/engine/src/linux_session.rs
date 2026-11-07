//! One user-owned local Xray runtime per data directory and daemon endpoint.
//! GUI and CLI exchange profile IDs, never commands, executables or configs.
//! Privileged route requests remain in the calling frontend's LinuxEngine so
//! polkit authenticates the actual interactive client, not a user service.
use net_manager_core::backend_settings::BackendSettingsStore;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::models::{
    BackendExecutableSource, Profile, TunnelBackend, TunnelState, TunnelStatus, XrayMode,
};
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

const MAX_FRAME: u64 = 64 * 1024;
static STOP: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Request {
    Connect { id: String },
    Disconnect { id: String },
    Status { id: String },
    Cleanup,
    RecoverProxy,
    ObserveDaemon,
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
fn lock_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid() || metadata.mode() & 0o077 != 0 {
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
    let operation = || -> io::Result<TunnelStatus> {
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
                match &request {
                    Request::Status { id } => return Ok(stopped(id)),
                    Request::Disconnect { id }
                        if !ownership
                            .as_ref()
                            .is_some_and(|owner| owner.profile_id == *id) =>
                    {
                        return Ok(stopped(id))
                    }
                    Request::Cleanup | Request::RecoverProxy if ownership.is_none() => {
                        return Ok(stopped(""))
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
        stream.set_read_timeout(Some(Duration::from_secs(330)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        serde_json::to_writer(&mut stream, &request)
            .map_err(|_| error("Cannot encode local runtime request"))?;
        stream.write_all(b"\n")?;
        let result: Result<TunnelStatus, String> = serde_json::from_slice(&read_line(&mut stream)?)
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

fn listener_targets(profile: &Profile) -> Result<Vec<ListenerTarget>, String> {
    let listeners = net_manager_core::analysis::analyze_profile(profile)
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

struct Runtime {
    root: PathBuf,
    daemon: net_manager_core::helper_client::HelperClient,
    tunnels: TunnelManager,
    active: HashMap<String, Profile>,
    proxy: SystemProxyManager,
    proxy_lock: Option<File>,
    proxy_cleanup_failed: bool,
    observe_daemon: bool,
    daemon_unreachable: bool,
}
impl Runtime {
    fn proxy_guard(&mut self) -> io::Result<()> {
        if self.proxy_lock.is_none() {
            let root = runtime_root()?;
            private_directory(&root)?;
            let lock = lock_file(&root.join("system-proxy.lock"))?;
            lock.try_lock()
                .map_err(|_| error("System proxy is owned by another netorch data directory"))?;
            self.proxy_lock = Some(lock);
        }
        Ok(())
    }
    fn restore_proxy(&mut self) -> io::Result<()> {
        if self.proxy.ownership().is_some() {
            self.proxy_guard()?;
            self.proxy.restore_any()?;
        }
        self.proxy_lock = None;
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
    fn connect(&mut self, id: &str) -> Result<TunnelStatus, String> {
        if self
            .active
            .get(id)
            .is_some_and(|profile| self.tunnels.status(profile).state == TunnelState::Running)
        {
            return Err("This local Xray profile is already running".into());
        }
        let store = ProfileStore::new(self.root.join("profiles.json"));
        let mut profiles = store.load().map_err(|_| "Cannot read profiles")?.profiles;
        let index = profiles
            .iter()
            .position(|profile| profile.id == id)
            .ok_or("Profile not found")?;
        let mut profile = profiles.remove(index);
        if profile.backend != TunnelBackend::Xray || profile.xray_mode != XrayMode::Socks {
            return Err("The user runtime only runs local Xray proxy profiles".into());
        }
        net_manager_core::profiles::validate_profile(&profile)
            .map_err(|_| "Invalid local Xray profile")?;
        profile.check_role()?;
        let vault = ConfigVault::new(self.root.join("configs"));
        if !vault.is_managed_profile_path(&profile.id, &profile.config_path) {
            return Err("Local Xray profiles must use their own managed config".into());
        }
        let notice = net_manager_core::profile_import::prepare_connect_ports(
            &vault,
            &store,
            &mut profile,
            &mut profiles,
            |port| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok(),
        )
        .map_err(|_| "Cannot prepare local Xray listeners")?;
        let setting = BackendSettingsStore::new(self.root.join("backend-settings.json"))
            .get(TunnelBackend::Xray)
            .map_err(|_| "Cannot read Xray executable settings")?;
        if let Some(setting) = &setting {
            if setting.source == BackendExecutableSource::Managed {
                net_manager_core::managed_xray::verify_managed_linux_executable(
                    Path::new(net_manager_core::managed_xray::LINUX_XRAY_PACKAGE_ROOT),
                    &setting.path,
                )
                .map_err(|_| "Managed Xray verification failed")?;
            }
        }
        self.tunnels
            .set_executable(TunnelBackend::Xray, setting.map(|setting| setting.path));
        let (assets, warnings) =
            crate::linux_geo_assets::prepare_blocking(&self.root.join("geoassets"), &profile)?;
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
        // A hello registers this long-lived process with the privileged daemon
        // when the profile also owns routes. It requires no authorization.
        if !profile.routes.is_empty() || !profile.endpoint_bypasses.is_empty() {
            self.daemon
                .hello()
                .map_err(|_| "The network daemon is unavailable")?;
        }
        let listeners = listener_targets(&profile)?;
        let mut status = self
            .tunnels
            .connect(&profile)
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
        for notice in notice.into_iter().chain(warnings) {
            status.message = Some(match status.message.take() {
                Some(message) => format!("{message}; {notice}"),
                None => notice,
            });
        }
        Ok(status)
    }
    fn handle(&mut self, request: Request) -> Result<TunnelStatus, String> {
        match request {
            Request::ObserveDaemon => {
                let _: net_manager_core::daemon_protocol::OwnedListResult = self
                    .daemon
                    .call(
                        net_manager_core::daemon_protocol::method::OWNED_LIST,
                        serde_json::Value::Null,
                    )
                    .map_err(crate::linux_engine::daemon_error)?;
                self.observe_daemon = true;
                Ok(stopped(""))
            }
            Request::Connect { id } => {
                let result = self.connect(&id);
                if result.is_err() && self.proxy.ownership().is_none() {
                    self.proxy_lock = None;
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
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let mut runtime = Runtime {
            tunnels: TunnelManager::with_log_dir(root.join("logs")),
            proxy: SystemProxyManager::new(root.join("proxy-state.json"))?,
            root,
            daemon: net_manager_core::helper_client::HelperClient::new(daemon),
            active: HashMap::new(),
            proxy_lock: None,
            proxy_cleanup_failed: false,
            observe_daemon: false,
            daemon_unreachable: false,
        };
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
                if runtime.observe_daemon {
                    let owned = runtime
                        .daemon
                        .call::<_, net_manager_core::daemon_protocol::OwnedListResult>(
                            net_manager_core::daemon_protocol::method::OWNED_LIST,
                            serde_json::Value::Null,
                        );
                    match owned {
                        Ok(owned) => {
                            runtime.observe_daemon = !owned.owners.is_empty();
                            runtime.daemon_unreachable = false;
                        }
                        Err(_) => {
                            if !runtime.daemon_unreachable {
                                eprintln!(
                                    "netorch: daemon unavailable; keeping the session for recovery"
                                );
                            }
                            runtime.daemon_unreachable = true;
                        }
                    }
                }
                let mut restore_proxy = false;
                for (id, profile) in &runtime.active {
                    let live = runtime.tunnels.status(profile).state == TunnelState::Running;
                    restore_proxy |= !live
                        && runtime
                            .proxy
                            .ownership()
                            .is_some_and(|owner| owner.profile_id == *id);
                }
                if restore_proxy
                    && !runtime.proxy_cleanup_failed
                    && runtime.restore_proxy().is_err()
                {
                    runtime.proxy_cleanup_failed = true;
                    eprintln!("netorch: system proxy cleanup failed; ownership kept for recovery");
                }
                // Retain failed status until explicit disconnect, just like a
                // live profile; only an empty runtime expires.
                if !runtime.active.is_empty() || runtime.observe_daemon {
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
