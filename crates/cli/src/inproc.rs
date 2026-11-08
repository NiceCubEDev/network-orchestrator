//! `sudo netorch up`: the helper's executors run inside this process, so no
//! launchd helper is needed. They are the same executors, with the same rules
//! (Xray as the console user only, the pinned OpenVPN copy, WireGuard
//! in-process), and they use the helper's own journal for crash recovery.
//! The tunnel lives as long as this process; `Ctrl+C` tears it down.
use net_manager_core::daemon_protocol::{HelloResult, RequestFrame, PROTOCOL_VERSION};
use net_manager_core::helper_client::{HelperClient, HelperError};
use net_manager_engine::Privileged;
use network_orchestrator_macos_helper::journal::Journal;
use network_orchestrator_macos_helper::openvpn::OpenVpnExecutor;
use network_orchestrator_macos_helper::peer::{console_uid, Peer};
use network_orchestrator_macos_helper::platform::{RealOvpnPlatform, RealPlatform, RealWgPlatform};
use network_orchestrator_macos_helper::server::Handler;
use network_orchestrator_macos_helper::service::HelperService;
use network_orchestrator_macos_helper::sysexec::SystemRunner;
use network_orchestrator_macos_helper::wireguard::WireGuardExecutor;
use network_orchestrator_macos_helper::xray::XrayExecutor;
use network_orchestrator_macos_helper::{resolver, SOCKET_DIR, STATE_DIR};
use serde_json::Value;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct InProcess {
    service: HelperService,
    xray: Arc<XrayExecutor>,
    wireguard: Arc<WireGuardExecutor>,
    openvpn: Arc<OpenVpnExecutor>,
    uid: u32,
    log_dir: PathBuf,
    _lock: File,
}

/// Who the executors act for: the console user, like the helper's peer
/// policy. `sudo` from anybody else is refused.
fn invoking_uid(console: Option<u32>, sudo_uid: Option<u32>) -> Result<u32, String> {
    let console = console.ok_or("Nobody is logged in at the console")?;
    match sudo_uid {
        Some(sudo) if sudo != console => Err(
            "netorch runs tunnels only for the user logged in at the console; \
             run sudo from that account"
                .into(),
        ),
        _ => Ok(console),
    }
}

fn private_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|_| "A system directory could not be created".to_string())?;
    use std::os::unix::fs::MetadataExt;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "A system directory could not be inspected")?;
    if !metadata.is_dir() || metadata.uid() != 0 {
        return Err("A system directory is not a root-owned directory".into());
    }
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .map_err(|_| "A system directory could not be secured".to_string())
}

impl InProcess {
    /// Refuses when the launchd helper is up (two owners of the same tunnels
    /// would tear each other down) or another sudo netorch holds the lock.
    pub fn start(helper_socket: &Path) -> Result<Self, String> {
        // SAFETY: geteuid never fails.
        if unsafe { libc::geteuid() } != 0 {
            return Err("This mode needs root: run it with sudo".into());
        }
        if !matches!(
            HelperClient::new(helper_socket).hello(),
            Err(HelperError::Unreachable(_))
        ) {
            return Err(
                "The Network Orchestrator helper is running; use netorch without sudo".into(),
            );
        }
        let sudo_uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|uid| uid.parse().ok());
        let uid = invoking_uid(console_uid(), sudo_uid)?;
        let socket_dir = Path::new(SOCKET_DIR);
        private_dir(socket_dir)?;
        private_dir(Path::new(STATE_DIR))?;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(socket_dir.join("netorch-inproc.lock"))
            .map_err(|_| "The tunnel lock could not be opened".to_string())?;
        let metadata = lock
            .metadata()
            .map_err(|_| "The tunnel lock could not be inspected")?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
            return Err("Unsafe sudo tunnel lock".into());
        }
        // SAFETY: flock on a descriptor owned by `lock`.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Another sudo netorch already runs the tunnels".into());
        }
        if !matches!(
            HelperClient::new(helper_socket).hello(),
            Err(HelperError::Unreachable(_))
        ) {
            return Err(
                "The Network Orchestrator helper is running; use netorch without sudo".into(),
            );
        }
        let state_dir = Path::new(STATE_DIR);
        let xray = Arc::new(XrayExecutor::new(
            Box::new(RealPlatform),
            Box::new(SystemRunner),
            Journal::new(state_dir),
            socket_dir.join("xray-tun.log"),
        ));
        let wireguard = Arc::new(WireGuardExecutor::new(
            Box::new(RealWgPlatform),
            Box::new(SystemRunner),
            Journal::named(state_dir, "wireguard.json"),
            PathBuf::from(resolver::DIR),
        ));
        let openvpn = Arc::new(OpenVpnExecutor::new(
            Box::new(RealOvpnPlatform {
                stage_dir: state_dir.join("backends"),
                log: socket_dir.join("openvpn.log"),
                bundle: None,
            }),
            Box::new(SystemRunner),
            Journal::named(state_dir, "openvpn.json"),
            PathBuf::from(network_orchestrator_macos_helper::openvpn::RUNTIME_ROOT),
            PathBuf::from(resolver::DIR),
        ));
        // What a crashed earlier run left behind must not outlive its owner.
        for (name, result) in [
            ("xray", xray.recover()),
            ("wireguard", wireguard.recover()),
            ("openvpn", openvpn.recover()),
        ] {
            if let Err(error) = result {
                eprintln!("netorch: {name} recovery failed: {error}");
            }
        }
        let watch = (xray.clone(), wireguard.clone(), openvpn.clone());
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            watch.0.reap();
            watch.1.reap();
            watch.2.reap();
        });
        Ok(Self {
            service: HelperService::new(xray.clone(), wireguard.clone(), openvpn.clone()),
            xray,
            wireguard,
            openvpn,
            uid,
            log_dir: socket_dir.to_path_buf(),
            _lock: lock,
        })
    }

    /// Tears every tunnel of this process down.
    pub fn shutdown(&self) {
        self.xray.shutdown();
        self.wireguard.shutdown();
        self.openvpn.shutdown();
    }
}

impl Privileged for InProcess {
    fn hello(&self) -> Result<HelloResult, HelperError> {
        Ok(HelloResult {
            protocol: PROTOCOL_VERSION,
            daemon_version: env!("NETORCH_VERSION").into(),
            uid: self.uid,
            capabilities: self.service.capabilities(),
            tools: self.service.tools(),
        })
    }

    fn call_raw(&self, method: &str, params: Value) -> Result<Value, HelperError> {
        let peer = Peer {
            uid: self.uid,
            pid: std::process::id(),
        };
        let response = self.service.handle(
            &peer,
            RequestFrame {
                id: 2,
                method: method.into(),
                params,
            },
        );
        response.outcome.map_err(HelperError::Rejected)
    }

    fn validates_locally(&self) -> bool {
        false
    }

    fn log_dir(&self) -> PathBuf {
        self.log_dir.clone()
    }
}

impl Drop for InProcess {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A root-owned control connection replaces unsafe PID-based sudo shutdown.
/// Its accepted stream belongs to this exact executor lifetime.
pub struct RunControl {
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
    profile_id: String,
    pending: Option<std::os::unix::net::UnixStream>,
}

impl RunControl {
    pub fn new(profile_id: &str) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt;
        let path = Path::new(SOCKET_DIR).join("netorch-inproc-control.sock");
        // InProcess's exclusive system lifetime lock is held before this call.
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                use std::os::unix::fs::{FileTypeExt, MetadataExt};
                if !metadata.file_type().is_socket() || metadata.uid() != 0 {
                    return Err("Unsafe sudo control endpoint".into());
                }
                std::fs::remove_file(&path)
                    .map_err(|_| "Could not replace stale sudo control endpoint")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("Could not inspect sudo control endpoint".into()),
        }
        let listener = std::os::unix::net::UnixListener::bind(&path)
            .map_err(|_| "Could not bind sudo control endpoint")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "Could not protect sudo control endpoint")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "Could not configure sudo control endpoint")?;
        Ok(Self {
            listener,
            path,
            profile_id: profile_id.into(),
            pending: None,
        })
    }

    pub fn stop_requested(&mut self) -> Result<bool, String> {
        use std::io::{BufRead, Write};
        let (mut stream, _) = match self.listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err("Could not accept sudo control request".into()),
        };
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: getpeereid fills two valid scalars for this accepted socket.
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 || uid != 0 {
            return Ok(false);
        }
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .map_err(|_| "Could not configure sudo control request")?;
        let mut request = String::new();
        std::io::BufReader::new(std::io::Read::take(&mut stream, 1024))
            .read_line(&mut request)
            .map_err(|_| "Could not read sudo control request")?;
        if request.trim_end() != self.profile_id && request.trim_end() != "*" {
            let _ = stream.write_all(b"wrong-profile\n");
            return Ok(false);
        }
        self.pending = Some(stream);
        Ok(true)
    }

    pub fn complete(&mut self) {
        use std::io::Write;
        if let Some(mut stream) = self.pending.take() {
            let _ = stream.write_all(b"stopped\n");
        }
    }
}

impl Drop for RunControl {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn stop(profile_id: Option<&str>) -> Result<(), String> {
    use std::io::{BufRead, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(
        Path::new(SOCKET_DIR).join("netorch-inproc-control.sock"),
    )
    .map_err(|_| "No sudo foreground connection is running")?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|_| "Could not configure sudo control connection")?;
    writeln!(stream, "{}", profile_id.unwrap_or("*"))
        .map_err(|_| "Could not send sudo stop request")?;
    let mut response = String::new();
    std::io::BufReader::new(std::io::Read::take(stream, 1024))
        .read_line(&mut response)
        .map_err(|_| "Sudo connection did not stop in time")?;
    if response == "stopped\n" {
        Ok(())
    } else {
        Err("That sudo foreground connection is not running".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_directories_never_follow_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let actual = dir.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&actual, &link).unwrap();
        assert!(private_dir(&link).is_err());
    }

    #[test]
    fn tunnels_run_only_for_the_console_user() {
        assert_eq!(invoking_uid(Some(501), Some(501)), Ok(501));
        assert_eq!(invoking_uid(Some(501), None), Ok(501));
        assert!(invoking_uid(Some(501), Some(502)).is_err());
        assert!(invoking_uid(None, Some(501)).is_err());
    }

    #[test]
    fn without_root_it_refuses_to_start() {
        // SAFETY: getuid never fails.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let error = InProcess::start(Path::new("/nonexistent.sock"))
            .err()
            .unwrap();
        assert!(error.contains("needs root"));
    }
}
