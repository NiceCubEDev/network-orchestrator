//! NetBird: the app drives the user's own NetBird daemon through its CLI,
//! exactly as `netbird up` / `down` / `status` in a terminal would. The daemon
//! (a system service, root) creates its interface, routes and DNS itself, so
//! nothing here is privileged and no second daemon is started. NetBird routes
//! only its own networks, which win over a primary tunnel's capture because
//! they are more specific.
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_SOCKET: &str = "/var/run/netbird.sock";
/// Where the CLI lives when NetBird was installed by Homebrew or the package.
#[cfg(target_os = "macos")]
const CLI_CANDIDATES: [&str; 4] = [
    "/opt/homebrew/bin/netbird",
    "/usr/local/bin/netbird",
    "/usr/local/sbin/netbird",
    "/Applications/NetBird.app/Contents/MacOS/netbird",
];
/// The distribution packages put it in `/usr/bin`; a manual install script in
/// `/usr/local/bin`.
#[cfg(not(target_os = "macos"))]
const CLI_CANDIDATES: [&str; 3] = [
    "/usr/bin/netbird",
    "/usr/local/bin/netbird",
    "/usr/local/sbin/netbird",
];
const STATUS_TIMEOUT: Duration = Duration::from_secs(6);
const DOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// A `netbird up` that is still waiting (typically for the browser login).
struct Pending {
    child: Child,
    key_file: Option<PathBuf>,
    socket: PathBuf,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

pub struct NetBird {
    pub cli: Option<PathBuf>,
    pub socket: PathBuf,
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn default_socket(legacy: &Path) -> PathBuf {
    if !legacy.exists() {
        // Profile-based installs keep the default daemon in netbird/default.sock.
        let profile = legacy.with_extension("").join("default.sock");
        if profile.exists() {
            return profile;
        }
    }
    legacy.to_path_buf()
}

impl NetBird {
    /// The installed CLI and the daemon socket; both can be pointed elsewhere
    /// for tests and unusual installs.
    pub fn detect() -> Self {
        let cli = std::env::var_os("NETORCH_NETBIRD_CLI")
            .map(PathBuf::from)
            .into_iter()
            .chain(CLI_CANDIDATES.iter().map(PathBuf::from))
            .find(|path| executable(path));
        let socket = std::env::var_os("NETORCH_NETBIRD_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| default_socket(Path::new(DEFAULT_SOCKET)));
        Self { cli, socket }
    }

    fn command(&self, cli: &Path) -> Command {
        let mut command = Command::new(cli);
        command
            .arg("--daemon-addr")
            .arg(format!("unix://{}", self.socket.display()))
            .stdin(Stdio::null());
        command
    }
}

/// Runs `command`, killing it after `limit`. Output is capped.
fn run_with_timeout(mut command: Command, limit: Duration) -> Result<(bool, String), String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "NetBird could not be started".to_string())?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    // Read on a thread and collect through a channel: a grandchild that keeps
    // the pipe open must not be able to hold this call hostage.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stdout)
            .take(2 * 1024 * 1024)
            .read_to_string(&mut text);
        let _ = sender.send(text);
    });
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(40));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    match status {
        Some(status) => {
            let text = receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default();
            Ok((status.success(), text))
        }
        None => Err("NetBird did not answer in time".into()),
    }
}

fn first_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str().filter(|text| !text.is_empty())
}

/// The compact, UI-facing view of `netbird status --json`. No keys, no event
/// log, no peer details beyond counts and the networks they route.
pub fn summarize(raw: &Value, pending: bool) -> Value {
    let daemon = raw["daemonStatus"].as_str().unwrap_or("");
    let state = match daemon {
        "Connected" => "connected",
        "Connecting" => "connecting",
        "NeedsLogin" | "LoginFailed" | "SessionExpired" => "needsLogin",
        "Idle" | "Disconnected" | "" => "disconnected",
        _ => "disconnected",
    };
    // A browser login in flight is "connecting", not "disconnected".
    let state = if pending && matches!(state, "disconnected" | "needsLogin") {
        "connecting"
    } else {
        state
    };
    let mut networks: Vec<String> = Vec::new();
    for peer in raw["peers"]["details"].as_array().into_iter().flatten() {
        for network in peer["networks"].as_array().into_iter().flatten() {
            if let Some(network) = network.as_str() {
                if !networks.iter().any(|known| known == network) && networks.len() < 64 {
                    networks.push(network.to_string());
                }
            }
        }
    }
    json!({
        "installed": true,
        "state": state,
        "daemonStatus": daemon,
        "ip": first_str(raw, &["netbirdIp"]),
        "fqdn": first_str(raw, &["fqdn"]),
        "version": first_str(raw, &["daemonVersion"]),
        "profile": first_str(raw, &["profileName"]),
        "managementUrl": first_str(raw, &["management", "url"]),
        "managementConnected": raw["management"]["connected"].as_bool().unwrap_or(false),
        "peersConnected": raw["peers"]["connected"].as_u64().unwrap_or(0),
        "peersTotal": raw["peers"]["total"].as_u64().unwrap_or(0),
        "sessionExpiresAt": first_str(raw, &["sessionExpiresAt"]),
        "networks": networks,
    })
}

fn pending_alive() -> bool {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(pending) = guard.as_mut() else {
        return false;
    };
    match pending.child.try_wait() {
        Ok(None) => true,
        _ => {
            if let Some(file) = pending.key_file.take() {
                let _ = std::fs::remove_file(file);
            }
            *guard = None;
            false
        }
    }
}

fn cancel_pending_for(socket: Option<&Path>) {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    if socket.is_some_and(|socket| {
        guard
            .as_ref()
            .is_some_and(|pending| pending.socket != socket)
    }) {
        return;
    }
    let taken = guard.take();
    drop(guard);
    if let Some(mut pending) = taken {
        let _ = pending.child.kill();
        let _ = pending.child.wait();
        if let Some(file) = pending.key_file {
            let _ = std::fs::remove_file(file);
        }
    }
}

#[cfg(test)]
fn cancel_pending() {
    cancel_pending_for(None);
}

fn pending_for(socket: &Path) -> bool {
    let matches = PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|pending| pending.socket == socket);
    matches && pending_alive()
}

impl NetBird {
    pub fn status(&self) -> Value {
        let Some(cli) = &self.cli else {
            return json!({"installed": false, "state": "notInstalled"});
        };
        if !self.socket.exists() {
            // The CLI would wait ten seconds for a daemon that is not there.
            return json!({"installed": true, "state": "daemonStopped"});
        }
        let mut command = self.command(cli);
        command.args(["status", "--json"]);
        match run_with_timeout(command, STATUS_TIMEOUT) {
            Ok((true, text)) => match serde_json::from_str::<Value>(&text) {
                Ok(raw) => summarize(&raw, pending_for(&self.socket)),
                Err(_) => json!({"installed": true, "state": "unavailable"}),
            },
            _ => json!({"installed": true, "state": "unavailable"}),
        }
    }

    /// Starts `netbird up` and returns at once; the status shows how it goes.
    /// A browser login (SSO) is handled by the CLI itself.
    pub fn up(
        &self,
        runtime: &Path,
        management_url: Option<&str>,
        setup_key: Option<&str>,
    ) -> Result<Value, String> {
        let cli = self.cli.clone().ok_or("NetBird is not installed")?;
        if !self.socket.exists() {
            return Err("The NetBird service is not running".into());
        }
        if let Some(url) = management_url {
            validate_url(url)?;
        }
        if let Some(key) = setup_key {
            validate_setup_key(key)?;
        }
        let dir = secure_runtime(runtime)
            .map_err(|_| "NetBird state could not be prepared".to_string())?;
        let _lock =
            control_lock(&dir).map_err(|_| "NetBird state could not be locked".to_string())?;
        #[cfg(target_os = "linux")]
        {
            if read_pending(runtime).is_some_and(|saved| {
                saved.socket != self.socket
                    && process_identity(saved.identity.pid)
                        .is_some_and(|live| live == saved.identity)
            }) {
                return Err(
                    "Another NetBird provider has a pending login in this data directory".into(),
                );
            }
            cancel_pending_in(runtime, &self.socket)?;
        }
        cancel_pending_for(Some(&self.socket));
        #[cfg(not(target_os = "linux"))]
        let mut key_file = None;
        #[cfg(target_os = "linux")]
        let key_file = None;
        #[cfg(target_os = "linux")]
        let mut key_handle = None;
        let mut command = self.command(&cli);
        if let Some(url) = management_url {
            command.arg("--management-url").arg(url);
        }
        if let Some(key) = setup_key {
            #[cfg(target_os = "linux")]
            {
                key_handle = Some(attach_setup_key(&mut command, key)?);
            }
            #[cfg(not(target_os = "linux"))]
            {
                let path = dir.join("setup-key");
                write_private(&path, key.as_bytes())
                    .map_err(|_| "The setup key could not be prepared".to_string())?;
                command.arg("--setup-key-file").arg(&path);
                key_file = Some(path);
            }
        }
        let log = private_file(&dir.join("up.log"), true)
            .map_err(|_| "NetBird state could not be prepared".to_string())?;
        command
            .arg("up")
            .stdout(Stdio::from(
                log.try_clone()
                    .map_err(|_| "NetBird could not be started".to_string())?,
            ))
            .stderr(Stdio::from(log));
        let mut child = command.spawn().map_err(|_| {
            if let Some(file) = &key_file {
                let _ = std::fs::remove_file(file);
            }
            "NetBird could not be started".to_string()
        })?;
        #[cfg(target_os = "linux")]
        {
            drop(key_handle);
            if let Some(identity) = process_identity(child.id()) {
                if write_pending(runtime, &identity, &self.socket).is_err() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("NetBird pending state could not be saved".into());
                }
            }
        }
        *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some(Pending {
            child,
            key_file,
            socket: self.socket.clone(),
        });
        Ok(self.status_in(runtime))
    }

    pub fn down(&self) -> Result<Value, String> {
        let cli = self.cli.clone().ok_or("NetBird is not installed")?;
        cancel_pending_for(Some(&self.socket));
        if !self.socket.exists() {
            return Ok(self.status());
        }
        let mut command = self.command(&cli);
        command.arg("down");
        let (success, _) = run_with_timeout(command, DOWN_TIMEOUT)
            .map_err(|_| "NetBird could not be disconnected".to_string())?;
        if !success {
            return Err("NetBird could not be disconnected".into());
        }
        Ok(self.status())
    }

    pub fn status_in(&self, runtime: &Path) -> Value {
        let mut status = self.status();
        #[cfg(target_os = "linux")]
        if pending_in(runtime, &self.socket)
            && matches!(
                status["state"].as_str(),
                Some("needsLogin" | "disconnected")
            )
        {
            status["state"] = json!("connecting");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = runtime;
        status
    }

    pub fn down_in(&self, runtime: &Path) -> Result<Value, String> {
        let dir = secure_runtime(runtime)
            .map_err(|_| "NetBird state could not be prepared".to_string())?;
        let _lock =
            control_lock(&dir).map_err(|_| "NetBird state could not be locked".to_string())?;
        #[cfg(target_os = "linux")]
        cancel_pending_in(runtime, &self.socket)?;
        self.down()
    }
}

fn validate_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("The NetBird server address must start with https://")?;
    let host = rest.split('/').next().unwrap_or("");
    if url.len() > 200
        || host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
        || rest
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("The NetBird server address is not valid".into());
    }
    Ok(())
}

fn validate_setup_key(key: &str) -> Result<(), String> {
    if (8..=200).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'='))
    {
        Ok(())
    } else {
        Err("The setup key is not valid".into())
    }
}

fn secure_runtime(runtime: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let invalid = || std::io::Error::other("invalid NetBird runtime");
    #[cfg(target_os = "linux")]
    for path in runtime.ancestors() {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_dir() => return Err(invalid()),
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    for path in [runtime.to_path_buf(), runtime.join("netbird")] {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                // Legacy callers pass an application runtime parent; only the
                // netbird child contains private state, but neither may be writable by others.
                let forbidden = if path.as_path() == runtime {
                    0o022
                } else {
                    0o077
                };
                if !metadata.file_type().is_dir()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.permissions().mode() & forbidden != 0
                {
                    return Err(invalid());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&path)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(runtime.join("netbird"))
}

fn private_file(path: &Path, truncate: bool) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(std::io::Error::other("invalid NetBird file"));
    }
    if truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

fn control_lock(dir: &Path) -> std::io::Result<std::fs::File> {
    let file = private_file(&dir.join("control.lock"), false)?;
    file.lock()?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn attach_setup_key(command: &mut Command, key: &str) -> Result<std::fs::File, String> {
    use std::io::{Seek, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    // An inherited anonymous file disappears when the provider exits, even if
    // the initiating CLI is already gone; no plaintext pathname needs cleanup.
    let fd = unsafe { libc::memfd_create(c"netorch-netbird-key".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err("The setup key could not be prepared".into());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    if unsafe { libc::fchmod(fd, 0o600) } < 0 {
        return Err("The setup key could not be protected".into());
    }
    file.write_all(key.as_bytes())
        .and_then(|_| file.rewind())
        .map_err(|_| "The setup key could not be prepared")?;
    let raw = file.as_raw_fd();
    command
        .arg("--setup-key-file")
        .arg(format!("/proc/self/fd/{raw}"));
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(raw, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct PendingIdentity {
    pid: u32,
    start: u64,
    executable_device: u64,
    executable_inode: u64,
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
struct PendingRecord {
    identity: PendingIdentity,
    socket: PathBuf,
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> Option<PendingIdentity> {
    use std::os::unix::fs::MetadataExt;
    let dir = PathBuf::from(format!("/proc/{pid}"));
    if std::fs::metadata(&dir).ok()?.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    if matches!(fields.next(), Some("Z" | "X")) {
        return None;
    }
    let start = fields.nth(18)?.parse().ok()?;
    let executable = std::fs::metadata(dir.join("exe")).ok()?;
    Some(PendingIdentity {
        pid,
        start,
        executable_device: executable.dev(),
        executable_inode: executable.ino(),
    })
}

#[cfg(target_os = "linux")]
fn write_pending(runtime: &Path, identity: &PendingIdentity, socket: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let dir = secure_runtime(runtime)?;
    let temporary = dir.join(format!("pending-{}.tmp", std::process::id()));
    let mut file = private_file(&temporary, true)?;
    let record = PendingRecord {
        identity: *identity,
        socket: socket.to_path_buf(),
    };
    let bytes = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, dir.join("pending.json"))
}

#[cfg(target_os = "linux")]
fn read_pending(runtime: &Path) -> Option<PendingRecord> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    // Querying status must remain read-only, including when invoked by root.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(runtime.join("netbird/pending.json"))
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 1024
    {
        return None;
    }
    serde_json::from_reader(file.take(1025)).ok()
}

#[cfg(target_os = "linux")]
fn pending_in(runtime: &Path, socket: &Path) -> bool {
    read_pending(runtime).is_some_and(|saved| {
        saved.socket == socket
            && process_identity(saved.identity.pid).is_some_and(|live| live == saved.identity)
    })
}

#[cfg(target_os = "linux")]
fn cancel_pending_in(runtime: &Path, socket: &Path) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if let Some(saved) = read_pending(runtime) {
        if saved.socket != socket {
            return Ok(());
        }
        // Pin the task before checking its birth time; PID reuse cannot target
        // an unrelated process between validation and signaling.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, saved.identity.pid, 0) } as i32;
        if raw >= 0 {
            let pidfd = unsafe { std::fs::File::from_raw_fd(raw) };
            if process_identity(saved.identity.pid).is_some_and(|live| live == saved.identity)
                && unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                } < 0
            {
                return Err("NetBird login could not be cancelled".into());
            }
        } else if process_identity(saved.identity.pid).is_some_and(|live| live == saved.identity) {
            return Err("NetBird login cancellation is unavailable on this kernel".into());
        }
    }
    match std::fs::remove_file(runtime.join("netbird/pending.json")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("NetBird pending state could not be removed".into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

/// The tail of what `netbird up` printed (a login URL, an error).
pub fn log_tail(runtime: &Path) -> String {
    let text = std::fs::read_to_string(runtime.join("netbird/up.log")).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex as StdMutex;

    /// The pending-`up` slot is process-global; tests that touch it take turns.
    static SERIAL: StdMutex<()> = StdMutex::new(());

    const STATUS: &str = r#"{"peers":{"total":2,"connected":1,"details":[
        {"fqdn":"a","netbirdIp":"10.85.1.1","publicKey":"SECRETKEYMATERIAL","status":"Connected","networks":["10.10.40.0/24","10.10.30.155/32"]},
        {"fqdn":"b","netbirdIp":"10.85.1.2","publicKey":"SECRETKEYMATERIAL2","status":"Idle","networks":["10.10.40.0/24"]}]},
        "daemonVersion":"0.80.0","daemonStatus":"Connected",
        "management":{"url":"https://nb.example:443","connected":true,"error":""},
        "netbirdIp":"10.85.18.199/16","fqdn":"mac.netbird.selfhosted","profileName":"default",
        "sessionExpiresAt":"2026-10-15T09:10:41Z","events":[{"message":"private event text"}]}"#;

    /// A stand-in CLI: prints canned status and records what it was asked to do.
    fn fake_cli(dir: &Path, status: &str, up_sleep: &str) -> NetBird {
        let cli = dir.join("netbird");
        let log = dir.join("calls.log");
        std::fs::write(dir.join("status.json"), status).unwrap();
        std::fs::write(
            &cli,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$*\" in\n  *status*) cat '{status}' ;;\n  *' up'*) for f in \"$@\"; do case \"$prev\" in --setup-key-file) cat \"$f\" > '{dir}/key-seen' ;; esac; prev=\"$f\"; done; sleep {up_sleep} ;;\n  *down*) : ;;\nesac\n",
                log = log.display(),
                status = dir.join("status.json").display(),
                dir = dir.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        let socket = dir.join("nb.sock");
        std::fs::write(&socket, b"").unwrap();
        NetBird {
            cli: Some(cli),
            socket,
        }
    }

    fn calls(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default()
    }

    #[test]
    fn status_is_a_compact_summary_without_keys_or_events() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        let status = nb.status();
        assert_eq!(status["state"], "connected");
        assert_eq!(status["ip"], "10.85.18.199/16");
        assert_eq!(status["peersConnected"], 1);
        assert_eq!(status["peersTotal"], 2);
        assert_eq!(status["managementUrl"], "https://nb.example:443");
        assert_eq!(
            status["networks"],
            json!(["10.10.40.0/24", "10.10.30.155/32"])
        );
        let text = status.to_string();
        assert!(!text.contains("SECRETKEYMATERIAL") && !text.contains("private event"));
        assert!(calls(dir.path()).contains("--daemon-addr unix://"));
        assert!(calls(dir.path()).contains("status --json"));
    }

    #[test]
    fn profile_socket_is_used_when_the_legacy_socket_is_absent() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let mut nb = fake_cli(dir.path(), STATUS, "0");
        std::fs::remove_file(&nb.socket).unwrap();
        let legacy = dir.path().join("run/netbird.sock");
        let profile = dir.path().join("run/netbird/default.sock");
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        std::fs::write(&profile, b"").unwrap();
        nb.socket = default_socket(&legacy);
        assert_eq!(nb.status()["state"], "connected");
        assert_eq!(nb.socket, profile);

        std::fs::write(&legacy, b"").unwrap();
        assert_eq!(default_socket(&legacy), legacy);
        std::fs::remove_file(&legacy).unwrap();
        std::fs::remove_file(&profile).unwrap();
        nb.socket = default_socket(&legacy);
        assert_eq!(nb.status()["state"], "daemonStopped");
    }

    #[test]
    fn daemon_states_map_to_the_ui_states() {
        for (daemon, expected) in [
            ("Connected", "connected"),
            ("Connecting", "connecting"),
            ("NeedsLogin", "needsLogin"),
            ("LoginFailed", "needsLogin"),
            ("SessionExpired", "needsLogin"),
            ("Idle", "disconnected"),
            ("", "disconnected"),
            ("Weird", "disconnected"),
        ] {
            let raw = json!({"daemonStatus": daemon});
            assert_eq!(summarize(&raw, false)["state"], expected, "{daemon}");
        }
        // A login in progress is not "disconnected".
        assert_eq!(
            summarize(&json!({"daemonStatus": "NeedsLogin"}), true)["state"],
            "connecting"
        );
        assert_eq!(
            summarize(&json!({"daemonStatus": "Connected"}), true)["state"],
            "connected"
        );
    }

    #[test]
    fn missing_cli_or_daemon_is_reported_without_running_anything() {
        let dir = tempfile::tempdir().unwrap();
        let none = NetBird {
            cli: None,
            socket: dir.path().join("nb.sock"),
        };
        assert_eq!(none.status()["state"], "notInstalled");
        assert!(none.up(dir.path(), None, None).is_err());
        let stopped = {
            let mut nb = fake_cli(dir.path(), STATUS, "0");
            std::fs::remove_file(&nb.socket).unwrap();
            nb.socket = dir.path().join("nb.sock");
            nb
        };
        assert_eq!(stopped.status()["state"], "daemonStopped");
        assert!(calls(dir.path()).is_empty());
        assert!(stopped
            .up(dir.path(), None, None)
            .unwrap_err()
            .contains("not running"));
    }

    #[test]
    fn up_passes_the_setup_key_by_file_and_removes_it_afterwards() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        let runtime = dir.path().join("runtime");
        nb.up(&runtime, Some("https://nb.example"), Some("ABCD-1234-EFGH"))
            .unwrap();
        for _ in 0..100 {
            if !pending_alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let log = calls(dir.path());
        assert!(log.contains("--management-url https://nb.example"), "{log}");
        assert!(log.contains("--setup-key-file"), "{log}");
        // The secret is never on a command line…
        assert!(!log.contains("ABCD-1234-EFGH"), "{log}");
        // …it reached the CLI through the file, which is gone now.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("key-seen")).unwrap(),
            "ABCD-1234-EFGH"
        );
        assert!(!runtime.join("netbird/setup-key").exists());
    }

    #[test]
    fn a_login_in_flight_reads_as_connecting_and_down_cancels_it() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), r#"{"daemonStatus":"NeedsLogin"}"#, "30");
        nb.up(&dir.path().join("rt"), None, None).unwrap();
        assert!(pending_alive());
        assert_eq!(nb.status()["state"], "connecting");
        nb.down().unwrap();
        assert!(!pending_alive());
        assert!(calls(dir.path()).contains(" down"));
        assert_eq!(nb.status()["state"], "needsLogin");
    }

    #[test]
    fn server_addresses_and_keys_are_validated() {
        for ok in [
            "https://nb.example",
            "https://nb.example:443/",
            "http://10.0.0.5:33073",
        ] {
            assert!(validate_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "nb.example",
            "ftp://x",
            "https://",
            "https://a b",
            "https://a;b",
            "https://x/\n",
        ] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
        assert!(validate_setup_key("ABCD-1234-EFGH").is_ok());
        for bad in ["short", "has space 1234", "semi;colon1234", ""] {
            assert!(validate_setup_key(bad).is_err(), "{bad}");
        }
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        assert!(nb.up(dir.path(), Some("javascript:x"), None).is_err());
        assert!(nb.up(dir.path(), None, Some("bad key!")).is_err());
        assert!(calls(dir.path()).is_empty());
    }

    #[test]
    fn down_rejects_unsuccessful_provider_exit_without_exposing_output() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        std::fs::write(
            nb.cli.as_ref().unwrap(),
            "#!/bin/sh\necho secret-provider-body\nexit 7\n",
        )
        .unwrap();
        let error = nb.down().unwrap_err();
        assert!(!error.contains("secret-provider-body"));
    }

    #[test]
    fn up_rejects_symlinked_runtime_and_log_without_touching_targets() {
        use std::os::unix::fs::symlink;
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&outside, runtime.join("netbird")).unwrap();
        assert!(nb.up(&runtime, None, Some("ABCD-1234-EFGH")).is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        std::fs::remove_file(runtime.join("netbird")).unwrap();
        std::fs::create_dir(runtime.join("netbird")).unwrap();
        std::fs::set_permissions(
            runtime.join("netbird"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let target = outside.join("unchanged");
        std::fs::write(&target, "unchanged").unwrap();
        symlink(&target, runtime.join("netbird/up.log")).unwrap();
        assert!(nb.up(&runtime, None, None).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
    }

    #[test]
    fn existing_nonwritable_runtime_parent_keeps_legacy_provider_compatibility() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        let runtime = dir.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
        nb.up(&runtime, None, None).unwrap();
        assert_eq!(
            std::fs::metadata(runtime.join("netbird"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        nb.down_in(&runtime).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn setup_key_has_no_persistent_path_while_login_remains_pending() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "30");
        let runtime = dir.path().join("runtime");
        nb.up(&runtime, None, Some("ABCD-1234-EFGH")).unwrap();
        assert!(!runtime.join("netbird/setup-key").exists());
        nb.down().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_pending_identity_rejects_reused_or_foreign_pids() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        let current = process_identity(std::process::id()).unwrap();
        let forged = PendingIdentity {
            start: current.start + 1,
            ..current
        };
        let socket = Path::new("/test/netbird.sock");
        write_pending(&runtime, &forged, socket).unwrap();
        assert!(!pending_in(&runtime, socket));
        cancel_pending_in(&runtime, socket).unwrap();
        assert!(!runtime.join("netbird/pending.json").exists());
        assert!(process_identity(std::process::id()).is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn down_does_not_cancel_pending_login_for_a_different_provider_socket() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let owner = fake_cli(first.path(), r#"{"daemonStatus":"NeedsLogin"}"#, "2");
        let foreign = fake_cli(second.path(), STATUS, "0");
        let runtime = first.path().join("runtime");
        owner.up(&runtime, None, None).unwrap();
        let identity = read_pending(&runtime).unwrap();
        foreign.down_in(&runtime).unwrap();
        assert!(process_identity(identity.identity.pid).is_some());
        assert_eq!(owner.status_in(&runtime)["state"], "connecting");
        owner.down_in(&runtime).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pending_login_survives_initiator_exit_and_is_cancelled_by_next_process() {
        const CHILD_ROOT: &str = "NETORCH_TEST_NETBIRD_CROSSPROCESS";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let nb = NetBird {
                cli: Some(root.join("netbird")),
                socket: root.join("nb.sock"),
            };
            assert_eq!(
                nb.up(&root.join("runtime"), None, Some("ABCD-1234-EFGH"))
                    .unwrap()["state"],
                "connecting"
            );
            return;
        }
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), r#"{"daemonStatus":"NeedsLogin"}"#, "2");
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "netbird::tests::pending_login_survives_initiator_exit_and_is_cancelled_by_next_process", "--nocapture"])
            .env(CHILD_ROOT, dir.path()).status().unwrap();
        assert!(result.success());
        let runtime = dir.path().join("runtime");
        let identity =
            read_pending(&runtime).expect("pending login must survive the initiating process");
        assert_eq!(nb.status_in(&runtime)["state"], "connecting");
        assert!(!runtime.join("netbird/setup-key").exists());
        nb.down_in(&runtime).unwrap();
        for _ in 0..100 {
            if process_identity(identity.identity.pid).is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(process_identity(identity.identity.pid).is_none());
        assert!(!runtime.join("netbird/pending.json").exists());
        assert!(!calls(dir.path()).contains("ABCD-1234-EFGH"));
    }

    #[test]
    fn a_hanging_cli_is_cut_off() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("slow");
        std::fs::write(&script, "#!/bin/sh\nsleep 20\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let started = Instant::now();
        let result = run_with_timeout(Command::new(&script), Duration::from_millis(300));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
