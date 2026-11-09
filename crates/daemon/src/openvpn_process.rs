use net_manager_core::daemon_protocol::OpenVpnCredentials;
use net_manager_core::openvpn_config::{SanitizedOpenVpnConfig, MAX_ASSET_BYTES, MAX_CONFIG_BYTES};
use net_manager_core::openvpn_management::{
    management_password_reply, parse_management_line, state_failure_detail, ManagementEvent,
    PasswordPrompt, MAX_MANAGEMENT_LINE_BYTES,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::openvpn::{runtime_root, stage_dir};
const MAX_POLL_BYTES: usize = 64 * 1024;
const MANAGEMENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

pub trait OpenVpnProcessRunner: Send {
    fn verify_binary(&self) -> io::Result<()>;
    fn link_index(&self, name: &str) -> io::Result<Option<u32>>;
    /// Whether a staging directory already exists for (uid, name) — an
    /// untracked leftover would make `start` fail inside stage_config_at.
    fn staging_exists(&self, uid: u32, name: &str) -> io::Result<bool>;
    fn start(
        &mut self,
        uid: u32,
        name: &str,
        config: &SanitizedOpenVpnConfig,
        credentials: Option<OpenVpnCredentials>,
        mark: u32,
    ) -> io::Result<()>;
    fn poll(&mut self, name: &str) -> io::Result<Vec<ManagementEvent>>;
    fn stop(&mut self, name: &str) -> io::Result<()>;
    fn cleanup(&mut self, uid: u32, name: &str) -> io::Result<()>;
}

struct ManagedProcess {
    uid: u32,
    child: Child,
    management: UnixStream,
    pending: Vec<u8>,
    credentials: Option<OpenVpnCredentials>,
}

pub struct TrustedOpenVpnProcess {
    children: HashMap<String, ManagedProcess>,
}

impl TrustedOpenVpnProcess {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }
}

impl Default for TrustedOpenVpnProcess {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenVpnProcessRunner for TrustedOpenVpnProcess {
    fn verify_binary(&self) -> io::Result<()> {
        trusted_binary().map(|_| ())
    }

    fn link_index(&self, name: &str) -> io::Result<Option<u32>> {
        if !valid_tun_name(name) {
            return Err(invalid_input("invalid OpenVPN link name"));
        }
        let name = CString::new(name).map_err(|_| invalid_input("invalid OpenVPN link name"))?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        Ok((index != 0).then_some(index))
    }

    fn staging_exists(&self, uid: u32, name: &str) -> io::Result<bool> {
        if !valid_tun_name(name) {
            return Err(invalid_input("invalid OpenVPN link name"));
        }
        match std::fs::symlink_metadata(stage_dir(uid, name)) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn start(
        &mut self,
        uid: u32,
        name: &str,
        config: &SanitizedOpenVpnConfig,
        credentials: Option<OpenVpnCredentials>,
        mark: u32,
    ) -> io::Result<()> {
        if !valid_tun_name(name) || mark == 0 {
            return Err(invalid_input("invalid OpenVPN link name"));
        }
        if self.children.contains_key(name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenVPN child already exists",
            ));
        }
        let binary = trusted_binary()?;
        ensure_runtime_root()?;
        let directory = stage_config_at(runtime_root().as_path(), uid, name, config)?;
        let socket = directory.join("management.sock");
        let args = openvpn_args(&directory.join("config.ovpn"), name, &socket, mark);
        let mut child = match Command::new(binary)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(&directory)
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                eprintln!("network-orchestrator-daemon: openvpn spawn failed uid={uid} kind={:?} os_code={:?}", err.kind(), err.raw_os_error());
                let _ = cleanup_stage_at(runtime_root().as_path(), uid, name);
                return Err(io::Error::other("failed to start OpenVPN"));
            }
        };
        eprintln!(
            "network-orchestrator-daemon: openvpn spawned uid={uid} pid={}",
            child.id()
        );
        let deadline = Instant::now() + MANAGEMENT_CONNECT_TIMEOUT;
        let management = loop {
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    if let Some(status) = child
                        .try_wait()
                        .map_err(|_| io::Error::other("OpenVPN child check failed"))?
                    {
                        eprintln!("network-orchestrator-daemon: openvpn unexpected exit phase=start uid={uid} pid={} code={:?} signal={:?}", child.id(), status.code(), status.signal());
                        let _ = cleanup_stage_at(runtime_root().as_path(), uid, name);
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "OpenVPN exited before management connection",
                        ));
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => {
                    eprintln!("network-orchestrator-daemon: openvpn terminating uid={uid} pid={} cause=management_timeout", child.id());
                    terminate_child(&mut child)?;
                    let _ = cleanup_stage_at(runtime_root().as_path(), uid, name);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "OpenVPN management connection timed out",
                    ));
                }
            }
        };
        if management
            .set_write_timeout(Some(Duration::from_secs(1)))
            .is_err()
        {
            terminate_child(&mut child)?;
            let _ = cleanup_stage_at(runtime_root().as_path(), uid, name);
            return Err(io::Error::other("OpenVPN management setup failed"));
        }
        let mut management = management;
        if management
            .write_all(b"state on\nbytecount 1\nlog on all\nhold release\n")
            .is_err()
            || management.set_nonblocking(true).is_err()
        {
            terminate_child(&mut child)?;
            let _ = cleanup_stage_at(runtime_root().as_path(), uid, name);
            return Err(io::Error::other("OpenVPN management setup failed"));
        }
        self.children.insert(
            name.to_owned(),
            ManagedProcess {
                uid,
                child,
                management,
                pending: Vec::new(),
                credentials,
            },
        );
        Ok(())
    }

    fn poll(&mut self, name: &str) -> io::Result<Vec<ManagementEvent>> {
        let process = self
            .children
            .get_mut(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OpenVPN child not found"))?;
        let status = process.child.try_wait().map_err(|err| {
            eprintln!("network-orchestrator-daemon: openvpn child check failed uid={} pid={} kind={:?} os_code={:?}", process.uid, process.child.id(), err.kind(), err.raw_os_error());
            io::Error::other("OpenVPN child check failed")
        })?;
        let exited = status.is_some();
        if let Some(status) = status {
            eprintln!("network-orchestrator-daemon: openvpn unexpected exit uid={} pid={} code={:?} signal={:?}", process.uid, process.child.id(), status.code(), status.signal());
        }
        let mut events = Vec::new();
        let mut total = 0;
        let mut disconnected = false;
        let mut prompt_error = None;
        let mut chunk = [0u8; 4096];
        loop {
            match process.management.read(&mut chunk) {
                Ok(0) => {
                    disconnected = true;
                    break;
                }
                Ok(count) => {
                    total += count;
                    for event in drain_management(&mut process.pending, &chunk[..count])? {
                        match event {
                            ManagementEvent::PasswordPrompt(prompt) if !exited => {
                                if let Err(error) = respond_to_password_prompt(
                                    &mut process.management,
                                    prompt,
                                    process.credentials.as_ref(),
                                ) {
                                    prompt_error = Some(error);
                                }
                            }
                            ManagementEvent::PasswordPrompt(_) => {}
                            other => events.push(other),
                        }
                    }
                    if total >= MAX_POLL_BYTES {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(io::Error::other("OpenVPN management read failed")),
            }
        }
        if exited || disconnected || prompt_error.is_some() {
            if disconnected && !exited {
                eprintln!(
                    "network-orchestrator-daemon: openvpn management disconnected uid={} pid={}",
                    process.uid,
                    process.child.id()
                );
            }
            if events
                .iter()
                .any(|event| matches!(event, ManagementEvent::AuthenticationFailed))
            {
                return Ok(vec![ManagementEvent::AuthenticationFailed]);
            }
            if prompt_error.is_some() {
                // The server asked for credentials the profile cannot
                // supply — surface a typed event instead of a bare error so
                // the failure reason reaches the status.
                events.push(ManagementEvent::FailureDetail(
                    net_manager_core::daemon_protocol::OpenVpnFailure::CredentialsRequired,
                ));
                return Ok(events);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                if exited {
                    "OpenVPN child exited"
                } else {
                    "OpenVPN management disconnected"
                },
            ));
        }
        Ok(events)
    }

    fn stop(&mut self, name: &str) -> io::Result<()> {
        let process = self
            .children
            .get_mut(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OpenVPN child not found"))?;
        eprintln!(
            "network-orchestrator-daemon: openvpn terminating uid={} pid={} cause=teardown",
            process.uid,
            process.child.id()
        );
        terminate_child(&mut process.child)?;
        self.children.remove(name);
        Ok(())
    }

    fn cleanup(&mut self, uid: u32, name: &str) -> io::Result<()> {
        if let Some(process) = self.children.get(name) {
            if process.uid != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "OpenVPN child ownership mismatch",
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "OpenVPN child is still tracked",
            ));
        }
        ensure_runtime_root()?;
        cleanup_stage_at(runtime_root().as_path(), uid, name)
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn valid_tun_name(name: &str) -> bool {
    name.starts_with("ovpn-")
        && (6..=15).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub(crate) fn trusted_binary() -> io::Result<&'static str> {
    for path in ["/usr/sbin/openvpn", "/usr/bin/openvpn"] {
        if safe_trusted_path(Path::new(path), 0, Path::new("/")) {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "trusted OpenVPN binary is unavailable",
    ))
}

fn safe_trusted_path(path: &Path, owner_uid: u32, root: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return false;
    }
    let mut directory = path.parent();
    while let Some(parent) = directory {
        let Ok(metadata) = fs::symlink_metadata(parent) else {
            return false;
        };
        if !metadata.is_dir() || metadata.uid() != owner_uid || metadata.mode() & 0o022 != 0 {
            return false;
        }
        if parent == root {
            return true;
        }
        directory = parent.parent();
    }
    false
}

fn ensure_runtime_root() -> io::Result<()> {
    let root = runtime_root();
    if !root.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|_| io::Error::other("OpenVPN runtime directory is unavailable"))?;
    }
    let metadata = fs::symlink_metadata(&root)
        .map_err(|_| io::Error::other("OpenVPN runtime directory is unavailable"))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OpenVPN runtime directory is unsafe",
        ));
    }
    Ok(())
}

fn openvpn_args(config: &Path, name: &str, socket: &Path, mark: u32) -> Vec<String> {
    [
        "--config",
        config.to_str().expect("fixed runtime config path"),
        "--dev",
        name,
        "--dev-type",
        "tun",
        "--disable-dco",
        "--route-nopull",
        "--route-noexec",
        "--script-security",
        "1",
        "--ignore-unknown-option",
        "dns-updown",
        "--dns-updown",
        "disable",
        "--management",
        socket.to_str().expect("fixed management socket path"),
        "unix",
        "--management-client-user",
        "root",
        "--management-query-passwords",
        "--management-hold",
        "--auth-nocache",
        "--verb",
        "3",
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .chain(["--mark".to_owned(), mark.to_string()])
    .collect()
}

fn stage_config_at(
    root: &Path,
    uid: u32,
    name: &str,
    config: &SanitizedOpenVpnConfig,
) -> io::Result<PathBuf> {
    if !valid_tun_name(name) || config.config.len() > MAX_CONFIG_BYTES || config.assets.len() > 32 {
        return Err(invalid_input("invalid OpenVPN staging input"));
    }
    let user_dir = root.join(uid.to_string());
    if !user_dir.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(&user_dir)
            .map_err(|_| io::Error::other("OpenVPN staging failed"))?;
    }
    let metadata =
        fs::symlink_metadata(&user_dir).map_err(|_| io::Error::other("OpenVPN staging failed"))?;
    let root_uid = fs::symlink_metadata(root)
        .map_err(|_| io::Error::other("OpenVPN staging failed"))?
        .uid();
    if !metadata.is_dir() || metadata.uid() != root_uid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OpenVPN staging directory is unsafe",
        ));
    }
    let directory = user_dir.join(name);
    DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenVPN staging directory already exists",
            )
        })?;
    let result = (|| {
        write_private_file(&directory.join("config.ovpn"), config.config.as_bytes())?;
        for (index, asset) in config.assets.iter().enumerate() {
            if asset.name != format!("asset-{index}")
                || asset.bytes.is_empty()
                || asset.bytes.len() > MAX_ASSET_BYTES
            {
                return Err(invalid_input("invalid OpenVPN asset"));
            }
            write_private_file(&directory.join(&asset.name), &asset.bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = cleanup_stage_at(root, uid, name);
        return Err(error);
    }
    Ok(directory)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| io::Error::other("OpenVPN staging file creation failed"))?;
    file.write_all(bytes)
        .map_err(|_| io::Error::other("OpenVPN staging file write failed"))?;
    file.sync_all()
        .map_err(|_| io::Error::other("OpenVPN staging file sync failed"))
}

fn cleanup_stage_at(root: &Path, uid: u32, name: &str) -> io::Result<()> {
    if !valid_tun_name(name) {
        return Err(invalid_input("invalid OpenVPN link name"));
    }
    let user_dir = root.join(uid.to_string());
    let user_metadata = match fs::symlink_metadata(&user_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("OpenVPN staging cleanup failed")),
    };
    let root_uid = fs::symlink_metadata(root)
        .map_err(|_| io::Error::other("OpenVPN staging cleanup failed"))?
        .uid();
    if !user_metadata.is_dir()
        || user_metadata.uid() != root_uid
        || user_metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OpenVPN staging directory is unsafe",
        ));
    }
    let directory = user_dir.join(name);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("OpenVPN staging cleanup failed")),
    };
    if !metadata.is_dir() || metadata.uid() != root_uid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OpenVPN staging directory is unsafe",
        ));
    }
    let entries =
        fs::read_dir(&directory).map_err(|_| io::Error::other("OpenVPN staging cleanup failed"))?;
    for entry in entries {
        let entry = entry.map_err(|_| io::Error::other("OpenVPN staging cleanup failed"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| io::Error::other("OpenVPN staging cleanup failed"))?;
        if name != "config.ovpn"
            && name != "management.sock"
            && name
                .strip_prefix("asset-")
                .is_none_or(|suffix| suffix.parse::<usize>().is_err())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "OpenVPN staging contains unknown file",
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| io::Error::other("OpenVPN staging cleanup failed"))?;
        if !(metadata.is_file() || name == "management.sock" && metadata.file_type().is_socket()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "OpenVPN staging contains unsafe file",
            ));
        }
        fs::remove_file(entry.path())
            .map_err(|_| io::Error::other("OpenVPN staging cleanup failed"))?;
    }
    fs::remove_dir(&directory).map_err(|_| io::Error::other("OpenVPN staging cleanup failed"))?;
    let _ = fs::remove_dir(&user_dir);
    Ok(())
}

fn drain_management(pending: &mut Vec<u8>, input: &[u8]) -> io::Result<Vec<ManagementEvent>> {
    pending.extend_from_slice(input);
    let mut events = Vec::new();
    while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
        if end > MAX_MANAGEMENT_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OpenVPN management line too large",
            ));
        }
        let line = pending.drain(..=end).collect::<Vec<_>>();
        let text = std::str::from_utf8(&line[..end]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OpenVPN management line is invalid",
            )
        })?;
        if let Some(event) = parse_management_line(text).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OpenVPN management event is invalid",
            )
        })? {
            if let Some(failure) = state_failure_detail(text) {
                events.push(ManagementEvent::FailureDetail(failure));
            }
            events.push(event);
        }
    }
    if pending.len() > MAX_MANAGEMENT_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OpenVPN management line too large",
        ));
    }
    Ok(events)
}

fn respond_to_password_prompt(
    management: &mut UnixStream,
    prompt: PasswordPrompt,
    credentials: Option<&OpenVpnCredentials>,
) -> io::Result<()> {
    let reply = management_password_reply(prompt, credentials).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OpenVPN credentials are unavailable or invalid",
        )
    })?;
    management
        .set_nonblocking(false)
        .map_err(|_| io::Error::other("OpenVPN management write failed"))?;
    let result = management.write_all(reply.as_bytes());
    let restored = management.set_nonblocking(true);
    if result.is_err() || restored.is_err() {
        return Err(io::Error::other("OpenVPN management write failed"));
    }
    Ok(())
}

fn terminate_child(child: &mut Child) -> io::Result<()> {
    if child
        .try_wait()
        .map_err(|_| io::Error::other("OpenVPN child check failed"))?
        .is_some()
    {
        return Ok(());
    }
    // An unreaped child keeps its PID reserved while pidfd_open binds the
    // handle. Signals through the pidfd cannot hit a later PID reuse.
    let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
    if raw_fd < 0 {
        eprintln!(
            "network-orchestrator-daemon: openvpn pidfd open failed pid={} os_code={:?}",
            child.id(),
            io::Error::last_os_error().raw_os_error()
        );
        return if child.try_wait()?.is_some() {
            Ok(())
        } else {
            Err(io::Error::other("OpenVPN child tracking failed"))
        };
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };
    send_child_signal(&pidfd, child, libc::SIGTERM)?;
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|_| io::Error::other("OpenVPN child check failed"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    eprintln!(
        "network-orchestrator-daemon: openvpn termination escalating pid={} signal=SIGKILL",
        child.id()
    );
    send_child_signal(&pidfd, child, libc::SIGKILL)?;
    // A child wedged in an uninterruptible syscall survives SIGKILL; bound
    // the final reap so `stop` cannot block a core task forever.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child
            .try_wait()
            .map_err(|_| io::Error::other("OpenVPN child wait failed"))?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "OpenVPN child did not exit",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn send_child_signal(pidfd: &OwnedFd, child: &mut Child, signal: i32) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    let signal_error = (result < 0).then(io::Error::last_os_error);
    if result < 0 && child.try_wait()?.is_none() {
        eprintln!("network-orchestrator-daemon: openvpn signal failed pid={} signal={signal} os_code={:?}", child.id(), signal_error.and_then(|err| err.raw_os_error()));
        return Err(io::Error::other("OpenVPN child signal failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{OpenVpnCredentials, OpenVpnUserPass};
    use net_manager_core::openvpn_config::SanitizedOpenVpnAsset;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temporary_path() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "openvpn-process-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn validates_deterministic_tun_name_before_using_paths() {
        assert!(valid_tun_name("ovpn-a123456789"));
        for name in [
            "",
            "tun0",
            "ovpn-../bad",
            "ovpn-has.dot",
            "ovpn-1234567890a",
        ] {
            assert!(!valid_tun_name(name), "{name}");
        }
    }

    #[test]
    fn stages_private_config_and_assets_without_replacing_existing_files() {
        let root = temporary_path();
        let config = SanitizedOpenVpnConfig {
            config: "client\nremote vpn.example\n<key>\nPRIVATE-SECRET\n</key>\n".into(),
            assets: vec![SanitizedOpenVpnAsset {
                name: "asset-0".into(),
                bytes: b"PRIVATE-ASSET".to_vec(),
            }],
        };
        let directory = stage_config_at(&root, 1000, "ovpn-abcd", &config).unwrap();
        let metadata = std::fs::metadata(&directory).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        for name in ["config.ovpn", "asset-0"] {
            let metadata = std::fs::metadata(directory.join(name)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        assert!(stage_config_at(&root, 1000, "ovpn-abcd", &config).is_err());
        assert_eq!(
            std::fs::read(directory.join("asset-0")).unwrap(),
            b"PRIVATE-ASSET"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_symlinked_staging_parent() {
        let root = temporary_path();
        let target = temporary_path();
        symlink(&target, root.join("1000")).unwrap();
        let config = SanitizedOpenVpnConfig {
            config: "client\nremote vpn.example\n".into(),
            assets: vec![],
        };
        assert!(stage_config_at(&root, 1000, "ovpn-abcd", &config).is_err());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn cleanup_does_not_follow_symlinked_user_directory() {
        let root = temporary_path();
        let target = temporary_path();
        let directory = target.join("ovpn-abcd");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(directory.join("config.ovpn"), b"PRIVATE-SECRET").unwrap();
        symlink(&target, root.join("1000")).unwrap();
        assert!(cleanup_stage_at(&root, 1000, "ovpn-abcd").is_err());
        assert_eq!(
            std::fs::read(directory.join("config.ovpn")).unwrap(),
            b"PRIVATE-SECRET"
        );
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn fixed_flags_follow_config_and_override_untrusted_options() {
        let args = openvpn_args(
            std::path::Path::new("/run/network-orchestrator/1000/ovpn-abcd/config.ovpn"),
            "ovpn-abcd",
            std::path::Path::new("/run/network-orchestrator/1000/ovpn-abcd/management.sock"),
            51820,
        );
        assert_eq!(
            &args[..2],
            [
                "--config",
                "/run/network-orchestrator/1000/ovpn-abcd/config.ovpn"
            ]
        );
        assert_eq!(&args[2..6], ["--dev", "ovpn-abcd", "--dev-type", "tun"]);
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--script-security", "1"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--route-nopull", "--route-noexec"]));
        assert!(args.iter().any(|arg| arg == "--disable-dco"));
        assert!(args.windows(2).any(|pair| pair == ["--mark", "51820"]));
        assert!(args.iter().any(|arg| arg == "--management-query-passwords"));
        assert!(!args.iter().any(|arg| arg.contains("PRIVATE-SECRET")));
    }

    #[test]
    fn management_socket_answers_auth_key_and_reconnect_prompts() {
        let (management, mut peer) = UnixStream::pair().unwrap();
        management.set_nonblocking(true).unwrap();
        management
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let credentials = OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "alice".into(),
                password: "p\\\"word".into(),
            }),
            private_key_passphrase: Some("key pass".into()),
        };
        let auth_reply =
            management_password_reply(PasswordPrompt::Auth, Some(&credentials)).unwrap();
        let key_reply =
            management_password_reply(PasswordPrompt::PrivateKey, Some(&credentials)).unwrap();
        let mut runner = TrustedOpenVpnProcess::new();
        runner.children.insert(
            "ovpn-abcd".into(),
            ManagedProcess {
                uid: 1000,
                child: Command::new("sleep").arg("30").spawn().unwrap(),
                management,
                pending: Vec::new(),
                credentials: Some(credentials),
            },
        );
        peer.write_all(b">PASSWORD:Need 'Auth' username/password\n")
            .unwrap();
        assert!(runner.poll("ovpn-abcd").unwrap().is_empty());
        let mut received = vec![0; auth_reply.len()];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, auth_reply.as_bytes());

        peer.write_all(b">STATE:1720000001,RECONNECTING,connection-reset\n>PASSWORD:Need 'Auth' username/password\n>PASSWORD:Need 'Private Key' password\n")
            .unwrap();
        let events = runner.poll("ovpn-abcd").unwrap();
        assert!(matches!(
            events.as_slice(),
            [
                ManagementEvent::FailureDetail(
                    net_manager_core::daemon_protocol::OpenVpnFailure::ConnectionLost
                ),
                ManagementEvent::State(
                    net_manager_core::openvpn_management::OpenVpnState::Reconnecting
                )
            ]
        ));
        let expected = format!("{auth_reply}{key_reply}");
        let mut received = vec![0; expected.len()];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, expected.as_bytes());

        peer.write_all(b">PASSWORD:Verification Failed: 'Auth'\n")
            .unwrap();
        assert!(matches!(
            runner.poll("ovpn-abcd").unwrap().as_slice(),
            [ManagementEvent::AuthenticationFailed]
        ));
        runner.stop("ovpn-abcd").unwrap();
    }

    #[test]
    fn missing_management_credentials_fail_without_echoing_prompt() {
        let (management, mut peer) = UnixStream::pair().unwrap();
        management.set_nonblocking(true).unwrap();
        let mut runner = TrustedOpenVpnProcess::new();
        runner.children.insert(
            "ovpn-abcd".into(),
            ManagedProcess {
                uid: 1000,
                child: Command::new("sleep").arg("30").spawn().unwrap(),
                management,
                pending: Vec::new(),
                credentials: None,
            },
        );
        peer.write_all(b">PASSWORD:Need 'Private Key' password\n")
            .unwrap();
        let events = runner.poll("ovpn-abcd").unwrap();
        assert!(matches!(
            events.as_slice(),
            [ManagementEvent::FailureDetail(
                net_manager_core::daemon_protocol::OpenVpnFailure::CredentialsRequired
            )]
        ));
        assert!(!format!("{events:?}").contains("Private Key"));
        runner.stop("ovpn-abcd").unwrap();
    }

    #[test]
    fn exited_child_still_delivers_queued_auth_failure_without_reason_text() {
        let (management, mut peer) = UnixStream::pair().unwrap();
        management.set_nonblocking(true).unwrap();
        peer.write_all(b">PASSWORD:Verification Failed: 'SECRET-REASON'\n")
            .unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let mut child = Command::new("true").spawn().unwrap();
        child.wait().unwrap();
        let mut runner = TrustedOpenVpnProcess::new();
        runner.children.insert(
            "ovpn-abcd".into(),
            ManagedProcess {
                uid: 1000,
                child,
                management,
                pending: Vec::new(),
                credentials: None,
            },
        );
        let events = runner.poll("ovpn-abcd").unwrap();
        assert!(matches!(
            events.as_slice(),
            [ManagementEvent::AuthenticationFailed]
        ));
        assert!(!format!("{events:?}").contains("SECRET-REASON"));
        runner.stop("ovpn-abcd").unwrap();
    }

    #[test]
    fn management_input_is_bounded_across_partial_reads() {
        let mut pending = Vec::new();
        let events = drain_management(&mut pending, b">STATE:123,CONNECTED,SUCCESS\n").unwrap();
        assert_eq!(events.len(), 1);
        assert!(drain_management(&mut pending, b">BYTECOUNT:5,")
            .unwrap()
            .is_empty());
        assert_eq!(drain_management(&mut pending, b"7\n").unwrap().len(), 1);
        assert!(drain_management(&mut pending, &vec![b'X'; 16 * 1024 + 1]).is_err());
    }

    #[test]
    fn state_lines_emit_sanitized_failure_details_before_the_state() {
        let mut pending = Vec::new();
        let events = drain_management(
            &mut pending,
            b">STATE:1,RECONNECTING,tls-error\n>STATE:2,EXITING,exit-with-error\n>STATE:3,CONNECTED,SUCCESS\n",
        )
        .unwrap();
        assert!(matches!(
            events.as_slice(),
            [
                ManagementEvent::FailureDetail(
                    net_manager_core::daemon_protocol::OpenVpnFailure::TlsError
                ),
                ManagementEvent::State(
                    net_manager_core::openvpn_management::OpenVpnState::Reconnecting
                ),
                ManagementEvent::FailureDetail(
                    net_manager_core::daemon_protocol::OpenVpnFailure::ExitWithError
                ),
                ManagementEvent::State(net_manager_core::openvpn_management::OpenVpnState::Exiting),
                ManagementEvent::State(
                    net_manager_core::openvpn_management::OpenVpnState::Connected
                )
            ]
        ));
    }

    #[test]
    fn trusted_binary_rejects_symlink_and_writable_parent() {
        let root = temporary_path();
        let parent = root.join("bin");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let binary = parent.join("openvpn");
        std::fs::write(&binary, b"test").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&root).unwrap());
        assert!(safe_trusted_path(&binary, uid, &root));
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!safe_trusted_path(&binary, uid, &root));
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = parent.join("linked-openvpn");
        symlink(&binary, &link).unwrap();
        assert!(!safe_trusted_path(&link, uid, &root));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn termination_reaps_only_the_saved_child() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        terminate_child(&mut child).unwrap();
        assert!(child.try_wait().unwrap().is_some());
    }
}
