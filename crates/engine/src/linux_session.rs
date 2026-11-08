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
        let timeout = if matches!(&request, Request::Status { .. }) {
            2
        } else {
            330
        };
        stream.set_read_timeout(Some(Duration::from_secs(timeout)))?;
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
    tunnels: TunnelManager,
    active: HashMap<String, Profile>,
    proxy: SystemProxyManager,
    proxy_lock: Option<File>,
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
            let lock = lock_file(&self.proxy_lock_root.join("system-proxy.lock"))?;
            lock.try_lock().map_err(|_| {
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
            Request::Connect { id } => {
                let result = self.connect(&id);
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
        }
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
    use net_manager_core::system_proxy::{ProxyAdapter, ProxySnapshot};
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
}
