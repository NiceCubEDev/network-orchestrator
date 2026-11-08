//! Authenticated per-user shared macOS connection owner and bounded transport.
#[cfg(any(target_os = "macos", test))]
#[path = "macos_session_generation.rs"]
mod generations;
#[cfg(any(target_os = "macos", test))]
#[path = "macos_session_launchd.rs"]
mod launchd;
#[cfg(any(target_os = "macos", test))]
#[path = "macos_session_process.rs"]
pub(crate) mod processes;
#[path = "macos_session_proxy.rs"]
pub(crate) mod proxy;
#[path = "macos_session_transport.rs"]
mod transport;
#[cfg(any(target_os = "macos", test))]
#[path = "macos_session_worker.rs"]
mod worker;
use crate::macos_transaction;
use crate::macos_transaction::FileLock;
use net_manager_core::daemon_protocol::OpenVpnCredentials;
use net_manager_core::models::{ProtocolHealth, RecoveryReport, TunnelStatus};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "macos", test))]
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
#[cfg(any(target_os = "macos", test))]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", test))]
use std::process::{Command, Stdio};
#[cfg(any(target_os = "macos", test))]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(target_os = "macos", test))]
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const VERSION: u32 = 1;
const MAX_FRAME: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(target_os = "macos", test))]
const MAX_PEERS: usize = 32;
#[cfg(any(target_os = "macos", test))]
const MAX_FOREGROUND: usize = MAX_PEERS / 2;
static STOP: AtomicBool = AtomicBool::new(false);
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Operation {
    Snapshot {
        ids: Vec<String>,
    },
    Running {
        id: String,
    },
    Connect {
        id: String,
        credentials: Option<OpenVpnCredentials>,
    },
    Disconnect {
        id: String,
    },
    StopForRestart {
        id: String,
    },
    SetProxy {
        id: String,
        enable: bool,
    },
    RestoreAfterRestart {
        id: String,
    },
    ProxyOwner,
    Loopback {
        id: String,
    },
    RecoveryReport,
    Provider {
        request: crate::macos_network::ProviderRequest,
    },
    SyncTailscale,
    RecoveryCleanup,
    Log {
        id: String,
    },
    GenerationRunning {
        id: String,
        generation: u64,
    },
    DisconnectGeneration {
        id: String,
        generation: u64,
    },
    DetachGeneration {
        id: String,
        generation: u64,
    },
    SetProxyGeneration {
        id: String,
        generation: u64,
        enable: bool,
    },
}

impl Operation {
    fn mutates(&self) -> bool {
        match self {
            Self::Connect { .. }
            | Self::Disconnect { .. }
            | Self::StopForRestart { .. }
            | Self::SetProxy { .. }
            | Self::RestoreAfterRestart { .. }
            | Self::RecoveryCleanup
            | Self::SyncTailscale
            | Self::DisconnectGeneration { .. }
            | Self::DetachGeneration { .. }
            | Self::SetProxyGeneration { .. } => true,
            Self::Provider { request } => request.is_mutation(),
            _ => false,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", content = "value", rename_all = "camelCase")]
pub(crate) enum Outcome {
    Unit,
    Running(bool),
    Snapshot(crate::Snapshot),
    ProxyOwner(Option<String>),
    Loopback(Box<TunnelStatus>, ProtocolHealth, Option<String>),
    Provider(crate::macos_network::ProviderResponse),
    TailscaleGuard(Option<crate::runtime::TailscaleGuard>),
    Recovery(RecoveryReport),
    Log(String),
    Activated(u64),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u32,
    root: PathBuf,
    helper: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    id: u64,
    foreground: bool,
    operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u32,
    id: u64,
    outcome: Result<Outcome, String>,
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|_| "Invalid user runtime frame".into())
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "Cannot encode user runtime frame")?;
    if bytes.len() > MAX_FRAME {
        return Err("User runtime frame is too large".into());
    }
    let deadline = Instant::now() + TIMEOUT;
    let header = (bytes.len() as u32).to_be_bytes();
    write_all_until(stream, &header, deadline)?;
    write_all_until(stream, &bytes, deadline)
}

fn write_all_until(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("User runtime write timed out")?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| "Cannot configure runtime timeout")?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err("The user runtime connection closed".into()),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("The user runtime connection closed or timed out".into()),
        }
    }
    Ok(())
}

fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, String> {
    read_frame_until(stream, Instant::now() + TIMEOUT)
}

fn read_exact_until_owner<G>(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    owner: Option<&Mutex<G>>,
) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = transport::read_plain_until(stream, &mut bytes[offset..], deadline, owner)?;
        if count == 0 {
            return Err("Truncated user runtime frame".into());
        }
        offset += count;
    }
    Ok(())
}

fn read_frame_until<T: DeserializeOwned>(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<T, String> {
    read_frame_until_owner(stream, deadline, None::<&Mutex<()>>)
}

fn read_frame_until_owner<T: DeserializeOwned, G>(
    stream: &mut UnixStream,
    deadline: Instant,
    owner: Option<&Mutex<G>>,
) -> Result<T, String> {
    let mut header = [0; 4];
    read_exact_until_owner(stream, &mut header, deadline, owner)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("Invalid user runtime frame size".into());
    }
    let mut bytes = vec![0; size];
    read_exact_until_owner(stream, &mut bytes, deadline, owner)?;
    decode(&bytes)
}

fn digest(root: &Path) -> String {
    use std::fmt::Write;
    let hash = Sha256::digest(root.as_os_str().as_encoded_bytes());
    let mut text = String::with_capacity(24);
    for byte in &hash[..12] {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn coordination_base(create: bool) -> Result<Option<PathBuf>, String> {
    let uid = macos_transaction::user_uid()?;
    #[cfg(target_os = "macos")]
    let tmp = Path::new("/private/tmp");
    #[cfg(not(target_os = "macos"))]
    let tmp = Path::new("/tmp");
    let metadata = fs::symlink_metadata(tmp).map_err(|_| "Cannot inspect runtime parent")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o1000 == 0 {
        return Err("Unsafe user runtime parent directory".into());
    }
    let path = tmp.join(format!("netorch-{uid}"));
    private_directory(&path, create)
}

fn private_directory(path: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    if create {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("Cannot create the user runtime directory".into()),
        }
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Cannot inspect the user runtime directory".into()),
    };
    if !metadata.is_dir()
        || metadata.uid() != macos_transaction::user_uid()?
        || metadata.mode() & 0o077 != 0
    {
        return Err("The user runtime directory has unsafe ownership or permissions".into());
    }
    macos_transaction::canonical_root(path, false)?;
    Ok(Some(path.to_path_buf()))
}

fn socket_path(root: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    let Some(base) = coordination_base(create)? else {
        return Ok(None);
    };
    let Some(directory) = private_directory(&base.join(digest(root)), create)? else {
        return Ok(None);
    };
    Ok(Some(directory.join("owner.sock")))
}

fn validate_socket(socket: &Path) -> Result<bool, String> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = match fs::symlink_metadata(socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("Cannot inspect the user runtime socket".into()),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != macos_transaction::user_uid()?
        || metadata.mode() & 0o077 != 0
    {
        return Err("The user runtime socket is unsafe".into());
    }
    Ok(true)
}

fn owner_locks(root: &Path) -> Result<(FileLock, FileLock), String> {
    let lifetime = macos_transaction::lock_file(&root.join(".runtime-owner.lock"), true)?
        .ok_or("The connection service is already running")?;
    // Keep the old inode: an older frontend may still hold its flock.
    use std::os::unix::fs::OpenOptionsExt;
    let legacy_path = root.join(".instance.lock");
    if legacy_path.exists() {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&legacy_path)
            .map_err(|_| "Unsafe legacy instance lock")?;
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect legacy instance lock")?;
        if !metadata.is_file()
            || metadata.uid() != macos_transaction::user_uid()?
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err("Unsafe legacy instance lock".into());
        }
        crate::macos_state::reject_writable_acl(&file)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "Cannot protect legacy instance lock")?;
    }
    let legacy = macos_transaction::lock_file(&root.join(".instance.lock"), true)?
        .ok_or("An older app or netorch owns this data directory. Quit it before starting the shared runtime.")?;
    Ok((lifetime, legacy))
}

#[cfg(target_os = "macos")]
fn peer(stream: &UnixStream) -> Result<(u32, PathBuf), String> {
    use std::os::raw::{c_int, c_void};
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, size: u32) -> c_int;
    }
    let mut uid = 0;
    let mut gid = 0;
    let mut pid: libc::pid_t = 0;
    let mut size = std::mem::size_of_val(&pid) as libc::socklen_t;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0
        || unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut size,
            )
        } != 0
    {
        return Err("Cannot authenticate the user runtime peer".into());
    }
    let mut path = [0u8; 4096];
    let length = unsafe { proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if length <= 0 {
        return Err("Cannot identify the user runtime peer".into());
    }
    let end = path.iter().position(|b| *b == 0).unwrap_or(length as usize);
    use std::os::unix::ffi::OsStrExt;
    Ok((
        uid,
        PathBuf::from(std::ffi::OsStr::from_bytes(&path[..end])),
    ))
}

#[cfg(target_os = "linux")]
fn peer(stream: &UnixStream) -> Result<(u32, PathBuf), String> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
    {
        return Err("Cannot authenticate the user runtime peer".into());
    }
    let path = fs::read_link(format!("/proc/{}/exe", credentials.pid))
        .map_err(|_| "Cannot identify the user runtime peer")?;
    Ok((credentials.uid, path))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer(_stream: &UnixStream) -> Result<(u32, PathBuf), String> {
    Err("User runtime peer authentication is unsupported on this platform".into())
}

fn authenticate(stream: &UnixStream, allowed: &[PathBuf]) -> Result<(), String> {
    let (uid, executable) = peer(stream)?;
    authorize_peer(uid, &executable, macos_transaction::user_uid()?, allowed)
}

fn authorize_peer(
    uid: u32,
    executable: &Path,
    expected: u32,
    allowed: &[PathBuf],
) -> Result<(), String> {
    if uid == 0 || uid != expected || !allowed.iter().any(|path| path == executable) {
        return Err("The user runtime peer is not authorized".into());
    }
    Ok(())
}

fn bundled_executable() -> Result<PathBuf, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let current = std::env::current_exe().map_err(|_| "Cannot locate bundled netorch")?;
    let directory = current.parent().ok_or("Cannot locate bundled netorch")?;
    macos_transaction::trusted_directory(directory)?;
    let executable = if current.file_name().is_some_and(|name| name == "netorch") {
        current
    } else {
        directory.join("netorch")
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&executable)
        .map_err(|_| "Install the bundled netorch executable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "The bundled netorch executable could not be inspected")?;
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != macos_transaction::user_uid()?)
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err("The bundled netorch executable has unsafe permissions".into());
    }
    crate::macos_state::reject_writable_acl(&file)?;
    Ok(executable)
}

#[cfg(test)]
type TestLauncher = dyn Fn(&Path, &Path, &Path) -> Result<(), String> + Send + Sync;

#[derive(Clone)]
pub(crate) struct Client {
    root: PathBuf,
    helper: PathBuf,
    #[cfg(test)]
    executable: Option<PathBuf>,
    #[cfg(test)]
    launcher: Option<Arc<TestLauncher>>,
}

impl Client {
    pub(crate) fn new(root: PathBuf, helper: PathBuf) -> Self {
        Self {
            root,
            helper,
            #[cfg(test)]
            executable: None,
            #[cfg(test)]
            launcher: None,
        }
    }

    fn executable(&self) -> Result<PathBuf, String> {
        #[cfg(test)]
        if let Some(executable) = &self.executable {
            return Ok(executable.clone());
        }
        bundled_executable()
    }

    fn launch(&self, root: &Path) -> Result<(), String> {
        let executable = self.executable()?;
        #[cfg(test)]
        if let Some(launcher) = &self.launcher {
            return launcher(root, &self.helper, &executable);
        }
        launch(root, &self.helper, &executable)
    }

    fn attach(&self, create: bool) -> Result<Option<(UnixStream, PathBuf)>, String> {
        if !self.helper.is_absolute() {
            return Err("The helper endpoint must be an absolute path".into());
        }
        let Some(root) = macos_transaction::canonical_root(&self.root, create)? else {
            return Ok(None);
        };
        let Some(socket) = socket_path(&root, create)? else {
            return Ok(None);
        };
        if !validate_socket(&socket)? {
            return Ok(None);
        }
        let mut stream = match UnixStream::connect(&socket) {
            Ok(stream) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(None)
            }
            Err(_) => return Err("Cannot connect to the user runtime".into()),
        };
        authenticate(&stream, &[self.executable()?])?;
        write_frame(
            &mut stream,
            &Hello {
                version: VERSION,
                root: root.clone(),
                helper: self.helper.clone(),
            },
        )?;
        let hello: Hello = read_frame(&mut stream)?;
        if hello.version != VERSION || hello.root != root || hello.helper != self.helper {
            return Err("The running connection service uses a different version, data root or helper endpoint".into());
        }
        Ok(Some((stream, root)))
    }

    fn connection(&self, start: bool) -> Result<Option<UnixStream>, String> {
        if let Some((stream, _)) = self.attach(false)? {
            return Ok(Some(stream));
        }
        if !start {
            return Ok(None);
        }
        let root =
            macos_transaction::canonical_root(&self.root, true)?.ok_or("Missing data directory")?;
        let _startup = macos_transaction::lock_file(&root.join(".runtime-start.lock"), false)?;
        if let Some((stream, _)) = self.attach(false)? {
            return Ok(Some(stream));
        }
        // Refuse legacy/competing owners before launchd or recovery can do anything.
        drop(owner_locks(&root)?);
        self.launch(&root)?;
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            if let Some((stream, _)) = self.attach(false)? {
                return Ok(Some(stream));
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        Err("The connection service did not become ready. Check its launchd user job.".into())
    }

    pub(crate) fn call(
        &self,
        operation: Operation,
        start: bool,
    ) -> Result<Option<Outcome>, String> {
        let Some(mut stream) = self.connection(start)? else {
            return Ok(None);
        };
        self.exchange(&mut stream, operation, false).map(Some)
    }

    fn exchange(
        &self,
        stream: &mut UnixStream,
        operation: Operation,
        foreground: bool,
    ) -> Result<Outcome, String> {
        let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let fd = if operation.mutates() {
            macos_transaction::operation_fd(&self.root)?
        } else {
            None
        };
        transport::send(
            stream,
            &Request {
                version: VERSION,
                id,
                foreground,
                operation,
            },
            fd,
        )?;
        let response: Response = read_frame(stream)?;
        if response.version != VERSION || response.id != id {
            return Err("The user runtime answered with a mismatched version or request ID".into());
        }
        response.outcome
    }

    pub(crate) fn foreground(
        &self,
        id: &str,
        credentials: Option<OpenVpnCredentials>,
    ) -> Result<ForegroundLease, String> {
        let mut stream = self
            .connection(true)?
            .ok_or("The connection service is unavailable")?;
        let outcome = self.exchange(
            &mut stream,
            Operation::Connect {
                id: id.into(),
                credentials,
            },
            true,
        )?;
        let Outcome::Activated(generation) = outcome else {
            return Err("Invalid foreground activation response".into());
        };
        Ok(ForegroundLease {
            client: self.clone(),
            stream: Some(stream),
            id: id.into(),
            generation,
        })
    }
}

/// A foreground control lifetime for exactly one successful activation.
/// Dropping a normal Engine or a short request connection never disconnects.
pub struct ForegroundLease {
    client: Client,
    stream: Option<UnixStream>,
    id: String,
    generation: u64,
}

impl ForegroundLease {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_running(&self) -> Result<bool, String> {
        match self.client.call(
            Operation::GenerationRunning {
                id: self.id.clone(),
                generation: self.generation,
            },
            false,
        )? {
            Some(Outcome::Running(running)) => Ok(running),
            None => Ok(false),
            _ => Err("Invalid foreground status response".into()),
        }
    }

    pub fn disconnect(&self) -> Result<(), String> {
        macos_transaction::with_root_lock(&self.client.root, || {
            match self.client.call(Operation::DisconnectGeneration { id: self.id.clone(), generation: self.generation }, false)? {
                Some(Outcome::Unit) => Ok(()),
                None => Err("The activation owner is unavailable; generation-safe cleanup could not be confirmed".into()),
                _ => Err("Invalid generation cleanup response".into()),
            }
        })
    }

    pub fn set_system_proxy(&self, enabled: bool) -> Result<crate::Snapshot, String> {
        macos_transaction::with_root_lock(&self.client.root, || {
            match self.client.call(
                Operation::SetProxyGeneration {
                    id: self.id.clone(),
                    generation: self.generation,
                    enable: enabled,
                },
                false,
            )? {
                Some(Outcome::Snapshot(snapshot)) => Ok(snapshot),
                None => Err("The activation owner is unavailable".into()),
                _ => Err("Invalid generation proxy response".into()),
            }
        })
    }

    pub fn detach(mut self) -> Result<(), String> {
        let result = macos_transaction::with_root_lock(&self.client.root, || {
            match self.client.call(
                Operation::DetachGeneration {
                    id: self.id.clone(),
                    generation: self.generation,
                },
                false,
            )? {
                Some(Outcome::Unit) => Ok(()),
                None => Err("The activation owner is unavailable".into()),
                _ => Err("Invalid foreground promotion response".into()),
            }
        });
        if let Err(error) = result {
            return match self.disconnect() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!(
                    "{error}; activation cleanup also failed: {cleanup}"
                )),
            };
        }
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        Ok(())
    }
}

impl Drop for ForegroundLease {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) trait Backend: Send {
    fn execute(&mut self, operation: Operation) -> Result<Outcome, String>;
    fn reap(&mut self) -> Result<(), String>;
    fn shutdown(&mut self) -> Result<(), String>;
}

#[cfg(any(target_os = "macos", test))]
struct Owner {
    backend: Box<dyn Backend>,
    generations: HashMap<String, u64>,
    next_generation: u64,
    detached: std::collections::HashSet<u64>,
    foregrounds: std::collections::HashSet<u64>,
    root: PathBuf,
}

#[cfg(any(target_os = "macos", test))]
impl Owner {
    fn execute(&mut self, operation: Operation) -> Result<Outcome, String> {
        match operation {
            Operation::DetachGeneration { id, generation } => {
                if self.generations.get(&id) != Some(&generation) {
                    return Err("This activation has been replaced".into());
                }
                if !self.foregrounds.contains(&generation) {
                    return Err("This activation has no foreground control lease".into());
                }
                if !matches!(
                    self.backend.execute(Operation::Running { id })?,
                    Outcome::Running(true)
                ) {
                    return Err("This activation stopped before it could be detached".into());
                }
                self.detached.insert(generation);
                Ok(Outcome::Unit)
            }
            Operation::SetProxyGeneration {
                id,
                generation,
                enable,
            } => {
                if self.generations.get(&id) != Some(&generation) {
                    return Err("This activation has been replaced".into());
                }
                self.backend.execute(Operation::SetProxy { id, enable })
            }
            Operation::GenerationRunning { id, generation } => {
                if self.generations.get(&id) != Some(&generation) {
                    return Ok(Outcome::Running(false));
                }
                self.backend.execute(Operation::Running { id })
            }
            Operation::RestoreAfterRestart { id } => {
                self.backend
                    .execute(Operation::RestoreAfterRestart { id: id.clone() })?;
                self.generations.remove(&id);
                Ok(Outcome::Unit)
            }
            Operation::DisconnectGeneration { id, generation } => {
                if self.generations.get(&id) != Some(&generation) {
                    return Ok(Outcome::Unit);
                }
                self.backend
                    .execute(Operation::Disconnect { id: id.clone() })?;
                self.generations.remove(&id);
                Ok(Outcome::Unit)
            }
            Operation::Connect { id, credentials } => {
                self.next_generation = generations::reserve(&self.root, self.next_generation)?;
                self.backend.execute(Operation::Connect {
                    id: id.clone(),
                    credentials,
                })?;
                self.generations.insert(id, self.next_generation);
                Ok(Outcome::Activated(self.next_generation))
            }
            Operation::Disconnect { ref id } | Operation::StopForRestart { ref id } => {
                let id = id.clone();
                let outcome = self.backend.execute(operation)?;
                self.generations.remove(&id);
                Ok(outcome)
            }
            operation => self.backend.execute(operation),
        }
    }

    fn close_lease(&mut self, id: String, generation: u64) -> Result<(), String> {
        self.foregrounds.remove(&generation);
        if self.detached.remove(&generation) {
            return Ok(());
        }
        self.execute(Operation::DisconnectGeneration { id, generation })
            .map(|_| ())
    }
}

#[cfg(any(target_os = "macos", test))]
fn connection(
    mut stream: UnixStream,
    root: PathBuf,
    helper: PathBuf,
    allowed: Arc<Vec<PathBuf>>,
    owner: Arc<Mutex<Owner>>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    authenticate(&stream, &allowed)?;
    let hello: Hello = read_frame_until_owner(&mut stream, Instant::now() + TIMEOUT, Some(&owner))?;
    if hello.version != VERSION || hello.root != root || hello.helper != helper {
        return Err("User runtime identity mismatch".into());
    }
    write_frame(
        &mut stream,
        &Hello {
            version: VERSION,
            root: root.clone(),
            helper,
        },
    )?;
    let (request, transferred) = transport::receive(&mut stream, &owner)?;
    if request.version != VERSION
        || (request.foreground && !matches!(request.operation, Operation::Connect { .. }))
    {
        return Err("Unsupported user runtime request".into());
    }
    let foreground_id = if request.foreground {
        match &request.operation {
            Operation::Connect { id, .. } => Some(id.clone()),
            _ => None,
        }
    } else {
        None
    };
    let outcome = {
        let _operation = if request.operation.mutates() {
            Some(match transferred {
                Some(file) => macos_transaction::adopt_operation_lock(&root, file)?,
                None => macos_transaction::root_lock(&root, false)?
                    .ok_or("The operation lock is busy")?,
            })
        } else {
            if transferred.is_some() {
                return Err("Read-only requests must not transfer file descriptors".into());
            }
            None
        };
        let mut owner = owner
            .lock()
            .map_err(|_| "Connection owner is unavailable")?;
        if request.foreground && owner.foregrounds.len() >= MAX_FOREGROUND {
            Err(
                "Too many foreground connections; detach or close an existing foreground client"
                    .into(),
            )
        } else {
            let outcome = owner.execute(request.operation);
            if request.foreground {
                if let Ok(Outcome::Activated(generation)) = &outcome {
                    owner.foregrounds.insert(*generation);
                }
            }
            outcome
        }
    };
    let generation = match &outcome {
        Ok(Outcome::Activated(generation)) => Some(*generation),
        _ => None,
    };
    let response = write_frame(
        &mut stream,
        &Response {
            version: VERSION,
            id: request.id,
            outcome,
        },
    );
    if let (Some(id), Some(generation)) = (foreground_id, generation) {
        if response.is_ok() {
            while !stop.load(Ordering::Acquire) {
                match transport::lease_open(&stream, &owner) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }
        // A client-side restart transaction may be in progress; wait outside the owner mutex.
        macos_transaction::with_root_lock(&root, || {
            owner
                .lock()
                .map_err(|_| "Connection owner is unavailable")?
                .close_lease(id, generation)
        })?;
    }
    response
}

#[cfg(test)]
fn run(
    root: &Path,
    helper: &Path,
    backend: Box<dyn Backend>,
    allowed: Vec<PathBuf>,
    stop: Arc<AtomicBool>,
    ready: impl FnOnce(),
) -> Result<(), String> {
    let root = macos_transaction::canonical_root(root, true)?.ok_or("Missing data directory")?;
    let _ownership = owner_locks(&root)?;
    run_owned(root, helper, backend, allowed, stop, ready)
}

#[cfg(any(target_os = "macos", test))]
fn run_owned(
    root: PathBuf,
    helper: &Path,
    backend: Box<dyn Backend>,
    allowed: Vec<PathBuf>,
    stop: Arc<AtomicBool>,
    ready: impl FnOnce(),
) -> Result<(), String> {
    let next_generation = generations::load(&root)?;
    let socket = socket_path(&root, true)?.ok_or("Missing runtime socket directory")?;
    if validate_socket(&socket)? {
        fs::remove_file(&socket).map_err(|_| "Cannot remove stale runtime socket")?;
    }
    let listener =
        UnixListener::bind(&socket).map_err(|_| "Cannot bind the user runtime socket")?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| "Cannot protect the user runtime socket")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "Cannot configure user runtime listener")?;
    let owner = Arc::new(Mutex::new(Owner {
        backend: Box::new(worker::Worker::start(backend)?),
        generations: HashMap::new(),
        next_generation,
        detached: std::collections::HashSet::new(),
        foregrounds: std::collections::HashSet::new(),
        root: root.clone(),
    }));
    let allowed = Arc::new(allowed);
    let peers = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    ready();
    while !stop.load(Ordering::Acquire) && !STOP.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) if peers.load(Ordering::Acquire) < MAX_PEERS => {
                peers.fetch_add(1, Ordering::AcqRel);
                let (root, helper, allowed, owner, stop, peers) = (
                    root.clone(),
                    helper.to_path_buf(),
                    allowed.clone(),
                    owner.clone(),
                    stop.clone(),
                    peers.clone(),
                );
                workers.push(std::thread::spawn(move || {
                    let _ = connection(stream, root, helper, allowed, owner, stop);
                    peers.fetch_sub(1, Ordering::AcqRel);
                }));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if let Ok(Some(_operation)) = macos_transaction::try_root_lock(&root) {
                    let _ = owner
                        .lock()
                        .map_err(|_| "Connection owner is unavailable")?
                        .backend
                        .reap();
                }
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(_) => break,
        }
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                let _ = workers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
    }
    stop.store(true, Ordering::Release);
    drop(listener);
    for worker in workers {
        let _ = worker.join();
    }
    let result = owner
        .lock()
        .map_err(|_| "Connection owner is unavailable")?
        .backend
        .shutdown();
    let _ = fs::remove_file(&socket);
    result
}

/// Async-signal-safe request; the serve loop performs actual teardown.
pub fn request_stop() {
    STOP.store(true, Ordering::Release);
}

/// The same admitted desktop identity used by the privileged helper.
pub fn console_user_uid() -> Result<u32, String> {
    #[cfg(target_os = "macos")]
    {
        let uid = std::fs::metadata("/dev/console")
            .map_err(|_| "The macOS console user could not be identified")?
            .uid();
        if uid == 0 {
            Err("Log in to the macOS desktop before starting a VPN with sudo".into())
        } else {
            Ok(uid)
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("The macOS console identity is unsupported on this platform".into())
    }
}

/// Serve as the one unprivileged owner. Never called by read-only clients.
pub fn serve(root: &Path, helper: &Path) -> Result<(), String> {
    macos_transaction::user_uid()?;
    if !helper.is_absolute() {
        return Err("The helper endpoint must be an absolute path".into());
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (root, helper);
        Err("The macOS user runtime is unsupported on this platform".into())
    }
    #[cfg(target_os = "macos")]
    {
        let root =
            macos_transaction::canonical_root(root, true)?.ok_or("Missing data directory")?;
        let _ownership = owner_locks(&root)?;
        let executable = bundled_executable()?;
        let gui = executable
            .parent()
            .ok_or("Invalid bundled netorch path")?
            .join("NetworkOrchestrator");
        let socket = socket_path(&root, true)?.ok_or("Missing runtime socket directory")?;
        validate_socket(&socket)?;
        generations::load(&root)?;
        // Recovery happens only here, after both lifetime/cutover locks.
        let backend = crate::runtime::OwnerBackend::new(&root, helper)?;
        run_owned(
            root,
            helper,
            Box::new(backend),
            vec![executable, gui],
            Arc::new(AtomicBool::new(false)),
            || {},
        )
    }
}

#[cfg(not(target_os = "macos"))]
fn launch(_root: &Path, _helper: &Path, _executable: &Path) -> Result<(), String> {
    Err("The macOS launchd user runtime is unsupported on this platform".into())
}

#[cfg(target_os = "macos")]
fn launch(root: &Path, helper: &Path, executable: &Path) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    fn escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\"', "&quot;")
            .replace('\'', "&apos;")
    }
    let uid = macos_transaction::user_uid()?;
    let socket = socket_path(root, true)?.ok_or("Missing runtime directory")?;
    let plist = socket
        .parent()
        .ok_or("Missing runtime directory")?
        .join("launchd.plist");
    let label = format!("io.github.network-orchestrator.user.{}", digest(root));
    let arguments = [
        executable.as_os_str(),
        std::ffi::OsStr::new("serve"),
        std::ffi::OsStr::new("--data-dir"),
        root.as_os_str(),
    ];
    let mut xml = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array>");
    for argument in arguments {
        let text = argument
            .to_str()
            .ok_or("Runtime paths must be valid UTF-8")?;
        xml.push_str(&format!("<string>{}</string>", escape(text)));
    }
    xml.push_str(&format!("</array><key>EnvironmentVariables</key><dict><key>NETORCH_HELPER_SOCKET</key><string>{}</string></dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer></dict></plist>", escape(helper.to_str().ok_or("Helper path must be valid UTF-8")?)));
    let domain = format!("gui/{uid}");
    let target = format!("{domain}/{label}");
    launchd::register(
        &Client::new(root.to_path_buf(), helper.to_path_buf()),
        root,
        || {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&plist)
                .map_err(|_| "Cannot write the launchd user job")?;
            let metadata = file
                .metadata()
                .map_err(|_| "Cannot inspect the launchd user job")?;
            if !metadata.is_file()
                || metadata.uid() != uid
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0
            {
                return Err("Unsafe launchd user job file".into());
            }
            crate::macos_state::reject_writable_acl(&file)?;
            file.set_len(0)
                .map_err(|_| "Cannot update the launchd user job")?;
            file.write_all(xml.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| "Cannot save the launchd user job".to_string())
        },
        |action| {
            let mut command = Command::new("/bin/launchctl");
            match action {
                launchd::Action::Inspect => {
                    command.args(["print", &target]);
                }
                launchd::Action::Bootout => {
                    command.args(["bootout", &target]);
                }
                launchd::Action::Bootstrap => {
                    command.arg("bootstrap").arg(&domain).arg(&plist);
                }
            }
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .map_err(|_| "Cannot control launchd user service".to_string())
        },
    )
}

#[cfg(test)]
pub(crate) struct TestServer {
    root: PathBuf,
    helper: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

#[cfg(test)]
impl TestServer {
    pub(crate) fn start(root: &Path, backend: impl Backend + 'static) -> Self {
        let root = root.to_path_buf();
        let helper = root.join("helper.sock");
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = std::sync::mpsc::channel();
        let (server_root, server_helper, server_stop) =
            (root.clone(), helper.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            run(
                &server_root,
                &server_helper,
                Box::new(backend),
                vec![std::env::current_exe().unwrap()],
                server_stop,
                || {
                    sender.send(()).unwrap();
                },
            )
        });
        receiver.recv_timeout(Duration::from_secs(3)).unwrap();
        Self {
            root,
            helper,
            stop,
            thread: Some(thread),
        }
    }
    pub(crate) fn client(&self) -> Client {
        let mut client = Client::new(self.root.clone(), self.helper.clone());
        client.executable = Some(std::env::current_exe().unwrap());
        client
    }
}

#[cfg(test)]
impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ProcessBackend {
        child: Option<std::process::Child>,
        starts: Arc<AtomicUsize>,
        restores: Arc<AtomicUsize>,
    }
    impl Backend for ProcessBackend {
        fn execute(&mut self, operation: Operation) -> Result<Outcome, String> {
            match operation {
                Operation::Connect { .. } => {
                    if self.child.is_some() {
                        return Err("already running".into());
                    }
                    self.child = Some(
                        Command::new("/bin/sh")
                            .args(["-c", "exec sleep 60"])
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn()
                            .map_err(|e| e.to_string())?,
                    );
                    self.starts.fetch_add(1, Ordering::SeqCst);
                    Ok(Outcome::Unit)
                }
                Operation::Disconnect { .. } | Operation::StopForRestart { .. } => {
                    if let Some(mut child) = self.child.take() {
                        child.kill().map_err(|e| e.to_string())?;
                        child.wait().map_err(|e| e.to_string())?;
                        self.restores.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(Outcome::Unit)
                }
                Operation::Running { .. } => Ok(Outcome::Running(
                    self.child
                        .as_mut()
                        .is_some_and(|child| child.try_wait().unwrap().is_none()),
                )),
                _ => Err("unexpected smoke operation".into()),
            }
        }
        fn reap(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn shutdown(&mut self) -> Result<(), String> {
            self.execute(Operation::Disconnect { id: "p".into() })
                .map(|_| ())
        }
    }

    #[test]
    fn executable_smoke_two_clients_background_and_generation_scoped_foreground() {
        let temp = tempfile::tempdir().unwrap();
        let starts = Arc::new(AtomicUsize::new(0));
        let restores = Arc::new(AtomicUsize::new(0));
        let server = TestServer::start(
            temp.path(),
            ProcessBackend {
                child: None,
                starts: starts.clone(),
                restores: restores.clone(),
            },
        );
        let first = server.client();
        let second = server.client();
        first
            .call(
                Operation::Connect {
                    id: "p".into(),
                    credentials: None,
                },
                true,
            )
            .unwrap();
        drop(first);
        assert!(matches!(
            second
                .call(Operation::Running { id: "p".into() }, false)
                .unwrap(),
            Some(Outcome::Running(true))
        ));
        second
            .call(Operation::Disconnect { id: "p".into() }, false)
            .unwrap();
        let lease = second.foreground("p", None).unwrap();
        second
            .call(Operation::Disconnect { id: "p".into() }, false)
            .unwrap();
        second
            .call(
                Operation::Connect {
                    id: "p".into(),
                    credentials: None,
                },
                false,
            )
            .unwrap();
        drop(lease);
        assert!(matches!(
            second
                .call(Operation::Running { id: "p".into() }, false)
                .unwrap(),
            Some(Outcome::Running(true))
        ));
        assert_eq!(starts.load(Ordering::SeqCst), 3);
        second
            .call(Operation::Disconnect { id: "p".into() }, false)
            .unwrap();
        assert_eq!(restores.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn absent_runtime_read_does_not_create_any_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent");
        let client = Client::new(root.clone(), temp.path().join("helper"));
        assert!(client
            .call(Operation::Running { id: "p".into() }, false)
            .unwrap()
            .is_none());
        assert!(!root.exists());
    }

    #[test]
    fn frame_limit_truncation_and_unknown_operations_are_rejected() {
        assert!(decode::<Request>(&[0, 0, 0]).is_err());
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender
            .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(read_frame::<Request>(&mut receiver).is_err());
        assert!(
            decode::<Operation>(br#"{"operation":"arbitraryExecutable","path":"/bin/sh"}"#)
                .is_err()
        );
    }

    #[test]
    fn helper_identity_mismatch_and_second_owner_are_rejected_before_execution() {
        let temp = tempfile::tempdir().unwrap();
        let server = TestServer::start(
            temp.path(),
            ProcessBackend {
                child: None,
                starts: Arc::new(AtomicUsize::new(0)),
                restores: Arc::new(AtomicUsize::new(0)),
            },
        );
        let mut conflicting = server.client();
        conflicting.helper = PathBuf::from("/different-helper");
        assert!(conflicting
            .call(Operation::Running { id: "p".into() }, false)
            .is_err());
        assert!(owner_locks(temp.path()).is_err());
    }
    #[test]
    fn racing_startup_uses_one_launcher_and_one_owner() {
        let temp = tempfile::tempdir().unwrap();
        let launched = Arc::new(AtomicUsize::new(0));
        let retained = Arc::new(Mutex::new(None));
        let mut client = Client::new(temp.path().into(), temp.path().join("helper.sock"));
        client.executable = Some(std::env::current_exe().unwrap());
        let (count, owner) = (launched.clone(), retained.clone());
        client.launcher = Some(Arc::new(move |root, _, _| {
            count.fetch_add(1, Ordering::SeqCst);
            *owner.lock().unwrap() = Some(TestServer::start(
                root,
                ProcessBackend {
                    child: None,
                    starts: Arc::new(AtomicUsize::new(0)),
                    restores: Arc::new(AtomicUsize::new(0)),
                },
            ));
            Ok(())
        }));
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let (client, barrier) = (client.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    client
                        .call(Operation::Running { id: "p".into() }, true)
                        .unwrap()
                })
            })
            .collect();
        barrier.wait();
        for thread in threads {
            assert!(matches!(
                thread.join().unwrap(),
                Some(Outcome::Running(false))
            ));
        }
        assert_eq!(launched.load(Ordering::SeqCst), 1);
        drop(client);
        drop(retained.lock().unwrap().take());
    }

    #[test]
    fn legacy_owner_blocks_launch_and_unsafe_socket_is_never_followed() {
        let temp = tempfile::tempdir().unwrap();
        let held = macos_transaction::lock_file(&temp.path().join(".instance.lock"), false)
            .unwrap()
            .unwrap();
        let mut client = Client::new(temp.path().into(), temp.path().join("helper.sock"));
        client.executable = Some(std::env::current_exe().unwrap());
        client.launcher = Some(Arc::new(|_, _, _| {
            panic!("must not launch through legacy owner")
        }));
        let error = client
            .call(
                Operation::Connect {
                    id: "p".into(),
                    credentials: None,
                },
                true,
            )
            .err()
            .unwrap();
        assert!(error.contains("older app"));
        drop(held);
        let socket = socket_path(temp.path(), true).unwrap().unwrap();
        std::os::unix::fs::symlink(temp.path().join("unrelated"), &socket).unwrap();
        assert!(client
            .call(Operation::Running { id: "p".into() }, false)
            .is_err());
        assert!(!temp.path().join("unrelated").exists());
        fs::remove_file(socket).unwrap();
    }
    #[test]
    fn stale_foreground_cannot_stop_activation_after_owner_restart() {
        let temp = tempfile::tempdir().unwrap();
        let make = || ProcessBackend {
            child: None,
            starts: Arc::new(AtomicUsize::new(0)),
            restores: Arc::new(AtomicUsize::new(0)),
        };
        let first = TestServer::start(temp.path(), make());
        let stale = first.client().foreground("p", None).unwrap();
        let generation = stale.generation();
        drop(first);
        let second = TestServer::start(temp.path(), make());
        let current = second.client().foreground("p", None).unwrap();
        assert!(current.generation() > generation);
        stale.disconnect().unwrap();
        assert!(current.is_running().unwrap());
        current.disconnect().unwrap();
    }

    #[test]
    fn kernel_peer_policy_rejects_other_uid_root_and_wrong_executable() {
        let allowed = vec![PathBuf::from("/approved/netorch")];
        assert!(authorize_peer(0, Path::new("/approved/netorch"), 1000, &allowed).is_err());
        assert!(authorize_peer(1001, Path::new("/approved/netorch"), 1000, &allowed).is_err());
        assert!(authorize_peer(1000, Path::new("/unapproved/netorch"), 1000, &allowed).is_err());
        assert!(authorize_peer(1000, Path::new("/approved/netorch"), 1000, &allowed).is_ok());
    }
    #[test]
    fn portable_subprocess_worker() {
        let Some(root) = std::env::var_os("NETORCH_RUNTIME_SMOKE_ROOT").map(PathBuf::from) else {
            return;
        };
        let role = std::env::var("NETORCH_RUNTIME_SMOKE_ROLE").unwrap();
        if role == "serve" {
            let _server = TestServer::start(
                &root,
                ProcessBackend {
                    child: None,
                    starts: Arc::new(AtomicUsize::new(0)),
                    restores: Arc::new(AtomicUsize::new(0)),
                },
            );
            fs::write(root.join("ready"), "").unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while !root.join("stop").exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                root.join("stop").exists(),
                "subprocess smoke service timed out"
            );
            return;
        }
        let mut client = Client::new(root.clone(), root.join("helper.sock"));
        client.executable = Some(std::env::current_exe().unwrap());
        let operation = match role.as_str() {
            "up" => Operation::Connect {
                id: "p".into(),
                credentials: None,
            },
            "down" => Operation::Disconnect { id: "p".into() },
            _ => panic!("invalid smoke role"),
        };
        assert!(client.call(operation, false).unwrap().is_some());
    }

    #[test]
    fn executable_subprocess_clients_exit_without_stopping_background_owner() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let child = |role: &str| {
            Command::new(&executable)
                .args([
                    "--exact",
                    "macos_session::tests::portable_subprocess_worker",
                ])
                .env("NETORCH_RUNTIME_SMOKE_ROOT", temp.path())
                .env("NETORCH_RUNTIME_SMOKE_ROLE", role)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut service = ChildGuard(child("serve"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !temp.path().join("ready").exists() && Instant::now() < deadline {
            assert!(
                service.0.try_wait().unwrap().is_none(),
                "subprocess service failed before readiness"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(temp.path().join("ready").exists());
        assert!(ChildGuard(child("up")).0.wait().unwrap().success());
        let mut observer = Client::new(temp.path().into(), temp.path().join("helper.sock"));
        observer.executable = Some(executable.clone());
        assert!(matches!(
            observer
                .call(Operation::Running { id: "p".into() }, false)
                .unwrap(),
            Some(Outcome::Running(true))
        ));
        assert!(ChildGuard(child("down")).0.wait().unwrap().success());
        assert!(matches!(
            observer
                .call(Operation::Running { id: "p".into() }, false)
                .unwrap(),
            Some(Outcome::Running(false))
        ));
        fs::write(temp.path().join("stop"), "").unwrap();
        assert!(service.0.wait().unwrap().success());
    }
    #[test]
    fn client_death_does_not_release_operation_while_backend_is_mutating() {
        struct Blocking {
            started: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl Backend for Blocking {
            fn execute(&mut self, operation: Operation) -> Result<Outcome, String> {
                if matches!(operation, Operation::Connect { .. }) {
                    self.started.send(()).unwrap();
                    self.release.recv_timeout(Duration::from_secs(3)).unwrap();
                }
                Ok(Outcome::Unit)
            }
            fn reap(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn shutdown(&mut self) -> Result<(), String> {
                Ok(())
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let (started, observed) = std::sync::mpsc::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let server = TestServer::start(
            temp.path(),
            Blocking {
                started,
                release: blocked,
            },
        );
        let client = server.client();
        macos_transaction::with_root_lock(temp.path(), || {
            let mut stream = client.connection(false)?.ok_or("Missing runtime")?;
            transport::send(
                &mut stream,
                &Request {
                    version: VERSION,
                    id: 42,
                    foreground: false,
                    operation: Operation::Connect {
                        id: "p".into(),
                        credentials: None,
                    },
                },
                macos_transaction::operation_fd(temp.path())?,
            )?;
            observed.recv_timeout(Duration::from_secs(3)).unwrap();
            // Close the frontend socket and its transaction scope before the
            // backend completes, exactly as client exit/timeout would.
            Ok(())
        })
        .unwrap();
        assert!(macos_transaction::try_root_lock(temp.path())
            .unwrap()
            .is_none());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if macos_transaction::try_root_lock(temp.path())
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "backend retained operation after completion"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn frame_deadline_and_response_identity_are_enforced() {
        let (_sender, mut receiver) = UnixStream::pair().unwrap();
        assert!(read_frame_until::<Request>(
            &mut receiver,
            Instant::now() + Duration::from_millis(5)
        )
        .is_err());
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let reply = std::thread::spawn(move || {
            let request: Request = read_frame(&mut receiver).unwrap();
            write_frame(
                &mut receiver,
                &Response {
                    version: VERSION,
                    id: request.id + 1,
                    outcome: Ok(Outcome::Running(false)),
                },
            )
            .unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let client = Client::new(temp.path().into(), temp.path().join("helper.sock"));
        assert!(client
            .exchange(&mut sender, Operation::Running { id: "p".into() }, false)
            .is_err());
        reply.join().unwrap();
    }

    #[test]
    fn long_data_roots_produce_short_private_socket_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("long-data-root-".repeat(15));
        macos_transaction::canonical_root(&root, true).unwrap();
        let socket = socket_path(&root, true).unwrap().unwrap();
        assert!(socket.as_os_str().as_encoded_bytes().len() < 104);
        let alias = macos_transaction::canonical_root(&root.join("."), false)
            .unwrap()
            .unwrap();
        assert_eq!(socket_path(&alias, false).unwrap(), Some(socket));
    }
}
