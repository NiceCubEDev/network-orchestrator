//! Linux system settings and caller-authorized managed backend installation.
use crate::linux_engine::LinuxEngine;
use crate::linux_session::{coordination_directory, lock_file};
use net_manager_core::backend_settings::{BackendSettingsDocument, BackendSettingsStore};
use net_manager_core::daemon_protocol::{self as protocol, method, VpnAuthMode};
use net_manager_core::helper_client::HelperError;
use net_manager_core::managed_xray;
use net_manager_core::models::{
    BackendAvailability, BackendExecutableSetting, BackendExecutableSource, TunnelBackend,
    TunnelState,
};
use net_manager_core::profiles::ProfileStore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DaemonState {
    NotRequired,
    NotInstalled,
    NotRunning,
    Incompatible,
    Ready,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonStatus {
    pub state: DaemonState,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxyStatus {
    pub owner_profile_id: Option<String>,
    pub owner_name: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedXrayOffer {
    pub version: String,
    pub source_url: String,
    pub sha256: String,
    pub max_download_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCapabilities {
    pub os: &'static str,
    pub system_proxy: bool,
    pub wireguard_standard_import: bool,
    pub managed_xray_install: bool,
    pub elevation_relaunch: bool,
    pub app_updates: bool,
    pub executable_extensions: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendInstallProgress {
    pub backend: TunnelBackend,
    pub stage: String,
    pub downloaded: u64,
    pub total: Option<u64>,
}

pub fn is_elevated() -> bool {
    false
}

fn user_only() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        Err("Run user settings and backend installation as your own user, never root".into())
    } else {
        Ok(())
    }
}

pub fn daemon_status(engine: &LinuxEngine) -> Result<DaemonStatus, String> {
    let status = match engine.privileged().hello() {
        Ok(_) => DaemonStatus {
            state: DaemonState::Ready,
            message: "Network daemon is ready.".into(),
        },
        Err(HelperError::Rejected(body)) if body.code == protocol::ErrorCode::ProtocolMismatch => {
            DaemonStatus {
                state: DaemonState::Incompatible,
                message: "Network daemon protocol is incompatible. Update the daemon.".into(),
            }
        }
        Err(HelperError::Protocol(_)) => DaemonStatus {
            state: DaemonState::Incompatible,
            message: "Network daemon protocol is incompatible. Update the daemon.".into(),
        },
        Err(_) => {
            let socket = engine.socket_path();
            let installed = [
                "/etc/systemd/system/network-orchestrator.service",
                "/usr/lib/systemd/system/network-orchestrator.service",
                "/lib/systemd/system/network-orchestrator.service",
            ]
            .iter()
            .any(|p| Path::new(p).exists());
            if socket.is_none_or(|path| path.exists()) {
                DaemonStatus {
                    state: DaemonState::Error,
                    message: "Network daemon socket is present but cannot be reached.".into(),
                }
            } else if installed {
                DaemonStatus {
                    state: DaemonState::NotRunning,
                    message: "Network daemon is not running. Start network-orchestrator.service."
                        .into(),
                }
            } else {
                DaemonStatus {
                    state: DaemonState::NotInstalled,
                    message:
                        "Network daemon is not installed. Install the network-orchestrator package."
                            .into(),
                }
            }
        }
    };
    Ok(status)
}

pub fn system_proxy_status(
    _engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
) -> Result<SystemProxyStatus, String> {
    let owner_profile_id =
        net_manager_core::system_proxy::load_ownership(&root.join("proxy-state.json"))
            .map_err(|_| "Cannot read system proxy ownership")?
            .map(|owner| owner.profile_id);
    let owner_name = if let Some(id) = &owner_profile_id {
        store
            .load()
            .map_err(|_| "Cannot read profiles")?
            .profiles
            .into_iter()
            .find(|p| p.id == *id)
            .map(|p| p.name)
    } else {
        None
    };
    Ok(SystemProxyStatus {
        owner_profile_id,
        owner_name,
    })
}

pub fn system_proxy_supported() -> bool {
    static AVAILABLE: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(net_manager_core::system_proxy::linux::available);
    *AVAILABLE
}

pub fn platform_capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        os: "linux",
        system_proxy: system_proxy_supported(),
        wireguard_standard_import: false,
        managed_xray_install: cfg!(target_arch = "x86_64"),
        elevation_relaunch: false,
        app_updates: false,
        executable_extensions: Vec::new(),
    }
}

pub fn vpn_auth_mode(engine: &LinuxEngine) -> Result<Option<VpnAuthMode>, String> {
    let result: protocol::SettingsResult =
        engine.ask(method::SETTINGS_GET, serde_json::Value::Null)?;
    Ok(Some(result.vpn_auth_mode))
}
pub fn logging_settings(engine: &LinuxEngine) -> Result<protocol::LoggingSettings, String> {
    engine.ask(method::LOGGING_GET, serde_json::Value::Null)
}

pub fn set_logging_verbosity(
    engine: &LinuxEngine,
    verbosity: protocol::LoggingVerbosity,
) -> Result<protocol::LoggingSettings, String> {
    engine.ask(method::LOGGING_SET, protocol::LoggingSettings { verbosity })
}

pub fn set_vpn_auth_mode(engine: &LinuxEngine, mode: VpnAuthMode) -> Result<(), String> {
    let _: protocol::SettingsResult = engine.ask(
        method::SETTINGS_SET,
        protocol::SettingsSetParams {
            vpn_auth_mode: mode,
        },
    )?;
    Ok(())
}

fn resolve(backend: TunnelBackend, configured: Option<&Path>) -> Result<PathBuf, String> {
    use net_manager_core::vpn;
    match backend {
        TunnelBackend::Xray => vpn::resolve_xray_executable(configured),
        TunnelBackend::WireGuard => vpn::resolve_wireguard_executable(configured),
        TunnelBackend::OpenVpn => vpn::resolve_openvpn_executable(configured),
        TunnelBackend::None => return Err("Static routes have no executable".into()),
    }
    .map_err(|_| "Backend executable is unavailable or invalid".into())
}

fn settings(root: &Path) -> BackendSettingsStore {
    BackendSettingsStore::new(root.join("backend-settings.json"))
}

fn managed_path() -> Result<PathBuf, String> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(managed_xray::linux_managed_version_dir(Path::new(
            managed_xray::LINUX_XRAY_PACKAGE_ROOT,
        ))
        .join("xray"))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err("Managed Xray installation requires Linux x86_64".into())
    }
}

fn verified_managed(setting: &BackendExecutableSetting) -> Result<(), String> {
    #[cfg(target_arch = "x86_64")]
    {
        if setting.version.as_deref() != Some(managed_xray::LINUX_XRAY_VERSION)
            || setting.path != managed_path()?
        {
            return Err("Managed Xray setting does not match the pinned installation".into());
        }
        managed_xray::verify_managed_linux_executable(
            Path::new(managed_xray::LINUX_XRAY_PACKAGE_ROOT),
            &setting.path,
        )
        .map_err(|_| "Managed Xray verification failed".into())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = setting;
        Err("Managed Xray installation requires Linux x86_64".into())
    }
}

fn resolve_setting(
    backend: TunnelBackend,
    setting: Option<&BackendExecutableSetting>,
) -> Result<PathBuf, String> {
    match setting {
        Some(setting) if setting.source == BackendExecutableSource::Managed => {
            if backend != TunnelBackend::Xray {
                return Err("Managed executables are only supported for Xray".into());
            }
            verified_managed(setting)?;
            Ok(setting.path.clone())
        }
        Some(setting) => resolve(backend, Some(&setting.path)),
        None => resolve(backend, None),
    }
}

/// Resolve the selected backend without executing it or mutating user storage.
pub fn backend_executable(root: &Path, backend: TunnelBackend) -> Result<PathBuf, String> {
    let setting = settings(root)
        .get(backend)
        .map_err(|_| "Cannot read backend settings")?;
    resolve_setting(backend, setting.as_ref())
}

pub fn backend_availability(
    engine: &LinuxEngine,
    root: &Path,
) -> Result<Vec<BackendAvailability>, String> {
    let hello = engine.privileged().hello();
    let status = daemon_status(engine)?;
    let store = settings(root);
    let mut entries = Vec::new();
    for backend in [
        TunnelBackend::WireGuard,
        TunnelBackend::OpenVpn,
        TunnelBackend::Xray,
    ] {
        if backend != TunnelBackend::Xray {
            let (methods, tool, name) = if backend == TunnelBackend::WireGuard {
                (
                    [
                        method::WIREGUARD_CONNECT,
                        method::WIREGUARD_DISCONNECT,
                        method::WIREGUARD_STATUS,
                    ],
                    protocol::tool::WIREGUARD,
                    "WireGuard",
                )
            } else {
                (
                    [
                        method::OPENVPN_CONNECT,
                        method::OPENVPN_DISCONNECT,
                        method::OPENVPN_STATUS,
                    ],
                    protocol::tool::OPENVPN,
                    "OpenVPN",
                )
            };
            let supported = hello.as_ref().is_ok_and(|h| {
                methods
                    .iter()
                    .all(|m| h.capabilities.iter().any(|c| c == m))
            });
            let usable = hello.as_ref().ok().and_then(|h| h.tools.get(tool)).copied();
            entries.push(BackendAvailability {
                backend,
                available: supported && usable != Some(false),
                path: None,
                source: None,
                version: None,
                message: if usable == Some(false) {
                    format!("{name} tools are missing or unsafe; install the system package.")
                } else if status.state == DaemonState::Ready && !supported {
                    format!("Network daemon does not support {name}. Update the daemon.")
                } else {
                    status.message.clone()
                },
            });
            continue;
        }
        let persisted = store
            .get(backend)
            .map_err(|_| "Cannot read backend settings")?;
        let resolved = resolve_setting(backend, persisted.as_ref());
        let socks = resolved.is_ok();
        let tun = hello.as_ref().is_ok_and(|h| {
            [
                method::XRAY_CONNECT,
                method::XRAY_DISCONNECT,
                method::XRAY_STATUS,
            ]
            .iter()
            .all(|m| h.capabilities.iter().any(|c| c == m))
        }) && managed_path().is_ok_and(|path| {
            verified_managed(&BackendExecutableSetting {
                path,
                source: BackendExecutableSource::Managed,
                version: Some(managed_xray_offer().version),
            })
            .is_ok()
        });
        entries.push(BackendAvailability { backend, available: socks || tun,
            path: resolved.ok().or_else(|| persisted.as_ref().map(|s| s.path.clone())),
            source: persisted.as_ref().map(|s| s.source).or(socks.then_some(BackendExecutableSource::AutoDetected)),
            version: persisted.and_then(|s| s.version),
            message: match (socks, tun) {
                (true, true) => "Xray SOCKS5/HTTP and TUN available.",
                (false, true) => "Xray TUN available; SOCKS5/HTTP executable setting is unavailable.",
                (true, false) => "Xray SOCKS5/HTTP available; TUN requires verified package Xray and network daemon.",
                (false, false) => "Xray unavailable; TUN requires verified package Xray and network daemon.",
            }.into() });
    }
    Ok(entries)
}

fn ensure_stopped(
    engine: &LinuxEngine,
    store: &ProfileStore,
    backend: TunnelBackend,
) -> Result<(), String> {
    for profile in store
        .load()
        .map_err(|_| "Cannot read profiles")?
        .profiles
        .iter()
        .filter(|p| p.backend == backend)
    {
        // Unknown status is not permission to replace a running executable.
        if engine.status(profile)?.state == TunnelState::Running {
            return Err("Cannot change a backend executable while a profile is running".into());
        }
    }
    Ok(())
}

fn write_settings(
    root: &Path,
    backend: TunnelBackend,
    setting: Option<BackendExecutableSetting>,
) -> Result<(), String> {
    let mut doc: BackendSettingsDocument = settings(root)
        .load()
        .map_err(|_| "Cannot read backend settings")?;
    match backend {
        TunnelBackend::Xray => doc.xray = setting,
        TunnelBackend::WireGuard => doc.wire_guard = setting,
        TunnelBackend::OpenVpn => doc.open_vpn = setting,
        TunnelBackend::None => return Err("Static routes have no executable".into()),
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .map_err(|_| "Cannot prepare settings directory")?;
    let metadata = fs::symlink_metadata(root).map_err(|_| "Cannot inspect settings directory")?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("Settings directory is not private and user-owned".into());
    }
    let path = root.join("backend-settings.json");
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } {
            return Err("Backend settings ownership is invalid".into());
        }
    }
    let temp = root.join(format!(".backend-settings-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|_| "Cannot create private backend settings file")?;
    let result = (|| {
        serde_json::to_writer_pretty(&mut file, &doc).map_err(std::io::Error::other)?;
        file.sync_all()?;
        fs::rename(&temp, &path)?;
        File::open(root)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|_| "Cannot atomically save backend settings".into())
}

fn mutation_lock(directory: &Path) -> Result<File, String> {
    let file = lock_file(&directory.join("backend-mutation.lock"))
        .map_err(|_| "Cannot open backend mutation lock")?;
    file.try_lock()
        .map_err(|_| "Another backend operation is in progress")?;
    Ok(file)
}

pub fn set_backend_executable(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
    backend: TunnelBackend,
    path: &Path,
) -> Result<(), String> {
    user_only()?;
    let directory = coordination_directory(root).map_err(|_| "Cannot access user runtime")?;
    let _lock = mutation_lock(&directory)?;
    if settings(root)
        .get(backend)
        .map_err(|_| "Cannot read backend settings")?
        .is_some_and(|s| s.source == BackendExecutableSource::Managed)
    {
        return Err(
            "Remove the managed Xray installation before choosing another executable".into(),
        );
    }
    let path = resolve(backend, Some(path))?;
    ensure_stopped(engine, store, backend)?;
    write_settings(
        root,
        backend,
        Some(BackendExecutableSetting {
            path,
            source: BackendExecutableSource::Configured,
            version: None,
        }),
    )
}

pub fn reset_backend_executable(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
    backend: TunnelBackend,
) -> Result<(), String> {
    user_only()?;
    let directory = coordination_directory(root).map_err(|_| "Cannot access user runtime")?;
    let _lock = mutation_lock(&directory)?;
    if settings(root)
        .get(backend)
        .map_err(|_| "Cannot read backend settings")?
        .is_some_and(|s| s.source == BackendExecutableSource::Managed)
    {
        return Err("Remove the managed Xray installation instead of resetting it".into());
    }
    ensure_stopped(engine, store, backend)?;
    write_settings(root, backend, None)
}

fn control(directory: &Path) -> Result<File, String> {
    let file = lock_file(&directory.join("backend-control.lock"))
        .map_err(|_| "Invalid installer control file")?;
    file.lock().map_err(|_| "Cannot lock installer control")?;
    Ok(file)
}
fn set_phase(file: &mut File, phase: &str) -> Result<(), String> {
    file.set_len(0)
        .and_then(|_| file.seek(SeekFrom::Start(0)))
        .and_then(|_| file.write_all(phase.as_bytes()))
        .and_then(|_| file.sync_all())
        .map_err(|_| "Cannot save installer state".into())
}
fn phase(file: &mut File) -> Result<String, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "Cannot read installer state")?;
    let mut state = String::new();
    file.take(32)
        .read_to_string(&mut state)
        .map_err(|_| "Cannot read installer state")?;
    Ok(state)
}
struct InstallGuard {
    directory: PathBuf,
    _mutation: File,
    _active: File,
}
impl InstallGuard {
    fn begin(directory: &Path) -> Result<Self, String> {
        let mutation = mutation_lock(directory)?;
        let mut state = control(directory)?;
        let active = lock_file(&directory.join("backend-install.lock"))
            .map_err(|_| "Invalid installer lock")?;
        active
            .try_lock()
            .map_err(|_| "An Xray installation is already active")?;
        set_phase(&mut state, "active")?;
        Ok(Self {
            directory: directory.to_path_buf(),
            _mutation: mutation,
            _active: active,
        })
    }
    fn check_cancelled(&self) -> Result<(), String> {
        if phase(&mut control(&self.directory)?)? == "cancelled" {
            Err("Managed Xray install cancelled".into())
        } else {
            Ok(())
        }
    }
    fn commit(&self, select: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
        let mut state = control(&self.directory)?;
        if phase(&mut state)? != "active" {
            return Err("Managed Xray install cancelled".into());
        }
        set_phase(&mut state, "committed")?;
        select()
    }
}
fn cancel_in(directory: &Path) -> Result<(), String> {
    let mut state = control(directory)?;
    let active =
        lock_file(&directory.join("backend-install.lock")).map_err(|_| "Invalid installer lock")?;
    match active.try_lock() {
        Ok(()) => return Err("No cancellable managed Xray installation is active".into()),
        Err(std::fs::TryLockError::WouldBlock) => {}
        Err(_) => return Err("Cannot inspect active installer ownership".into()),
    }
    if phase(&mut state)? != "active" {
        return Err("No cancellable managed Xray installation is active".into());
    }
    set_phase(&mut state, "cancelled")
}
pub fn cancel_managed_xray_install(root: &Path) -> Result<(), String> {
    user_only()?;
    if !cfg!(target_arch = "x86_64") {
        return Err("Managed Xray installation requires Linux x86_64".into());
    }
    cancel_in(&coordination_directory(root).map_err(|_| "Cannot access user runtime")?)
}

pub fn managed_xray_offer() -> ManagedXrayOffer {
    #[cfg(target_arch = "x86_64")]
    let (version, url, hash) = (
        managed_xray::LINUX_XRAY_VERSION,
        managed_xray::LINUX_XRAY_URL,
        managed_xray::LINUX_XRAY_SHA256,
    );
    #[cfg(not(target_arch = "x86_64"))]
    let (version, url, hash) = ("unavailable", "", "");
    ManagedXrayOffer {
        version: version.into(),
        source_url: url.into(),
        sha256: hash.into(),
        max_download_bytes: managed_xray::MAX_XRAY_ARCHIVE_BYTES as u64,
    }
}

fn remove_via_daemon(engine: &LinuxEngine) -> Result<(), String> {
    let _: protocol::XrayRemoveResult = engine.ask(method::XRAY_REMOVE, serde_json::Value::Null)?;
    Ok(())
}

async fn cancellable_download<T>(
    guard: &InstallGuard,
    future: impl Future<Output = Result<T, reqwest::Error>>,
) -> Result<T, String> {
    let mut future = std::pin::pin!(future);
    loop {
        guard.check_cancelled()?;
        match tokio::time::timeout(Duration::from_millis(200), future.as_mut()).await {
            Err(_) => continue,
            Ok(result) => return result.map_err(|_| "Managed Xray download failed".into()),
        }
    }
}

pub async fn install_managed_xray(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
    progress: &(dyn Fn(BackendInstallProgress) + Send + Sync),
) -> Result<(), String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    user_only()?;
    let executable = managed_path()?;
    let directory = coordination_directory(root).map_err(|_| "Cannot access user runtime")?;
    let guard = InstallGuard::begin(&directory)?;
    ensure_stopped(engine, store, TunnelBackend::Xray)?;
    let emit = |stage: &str, downloaded, total| {
        progress(BackendInstallProgress {
            backend: TunnelBackend::Xray,
            stage: stage.into(),
            downloaded,
            total,
        })
    };
    let offer = managed_xray_offer();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("Network-Orchestrator/0.1.0")
        .build()
        .map_err(|_| "Cannot build download client")?;
    emit("downloading", 0, None);
    let mut response = cancellable_download(&guard, client.get(&offer.source_url).send())
        .await?
        .error_for_status()
        .map_err(|_| "Managed Xray download failed")?;
    let total = response.content_length();
    if total.is_some_and(|n| n > offer.max_download_bytes) {
        return Err("Managed Xray archive exceeds the maximum size".into());
    }
    let mut archive = Vec::new();
    loop {
        guard
            .check_cancelled()
            .inspect_err(|_| emit("cancelled", archive.len() as u64, total))?;
        let Some(chunk) = cancellable_download(&guard, response.chunk()).await? else {
            break;
        };
        let length = archive
            .len()
            .checked_add(chunk.len())
            .filter(|n| *n <= managed_xray::MAX_XRAY_ARCHIVE_BYTES)
            .ok_or("Managed Xray archive exceeds the maximum size")?;
        archive.extend_from_slice(&chunk);
        emit("downloading", length as u64, total);
    }
    let downloaded = archive.len() as u64;
    if total.is_some_and(|n| n != downloaded) {
        return Err("Managed Xray download length did not match Content-Length".into());
    }
    emit("verifying", downloaded, total);
    if format!("{:x}", Sha256::digest(&archive)) != offer.sha256 {
        return Err("Managed Xray archive hash did not match the pinned release".into());
    }
    guard.check_cancelled()?;
    ensure_stopped(engine, store, TunnelBackend::Xray)?;
    emit("installing", downloaded, total);
    let archive_b64 = base64::engine::general_purpose::STANDARD.encode(&archive);
    drop(archive);
    // This synchronous daemon call deliberately runs in the initiating frontend:
    // polkit must authorize that caller, not an unprivileged user-service deputy.
    let installed: protocol::XrayInstallResult = engine.ask(
        method::XRAY_INSTALL,
        protocol::XrayInstallParams { archive_b64 },
    )?;
    let selection = guard.commit(|| {
        ensure_stopped(engine, store, TunnelBackend::Xray)?;
        let setting = BackendExecutableSetting {
            path: executable,
            source: BackendExecutableSource::Managed,
            version: Some(installed.version.clone()),
        };
        verified_managed(&setting)?;
        write_settings(root, TunnelBackend::Xray, Some(setting))
    });
    if let Err(error) = selection {
        emit(
            if error == "Managed Xray install cancelled" {
                "cancelled"
            } else {
                "failed"
            },
            downloaded,
            total,
        );
        if installed.created {
            // A rename may have succeeded even if the final durability sync failed.
            // Never remove a package that the settings now select.
            match settings(root).get(TunnelBackend::Xray) {
                Ok(Some(setting))
                    if setting.source == BackendExecutableSource::Managed
                        && setting.path == managed_path()? =>
                {
                    return Err(format!("{error}; managed package remains selected"))
                }
                Err(_) => {
                    return Err(format!(
                        "{error}; cannot confirm selection; managed package retained"
                    ))
                }
                _ => remove_via_daemon(engine).map_err(|_| {
                    format!("{error}; rollback failed; managed package remains installed")
                })?,
            }
        }
        return Err(error);
    }
    emit("ready", downloaded, total);
    Ok(())
}

pub fn remove_managed_xray(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
) -> Result<(), String> {
    user_only()?;
    let expected = managed_path()?;
    let directory = coordination_directory(root).map_err(|_| "Cannot access user runtime")?;
    let _lock = mutation_lock(&directory)?;
    ensure_stopped(engine, store, TunnelBackend::Xray)?;
    let selected = settings(root)
        .get(TunnelBackend::Xray)
        .map_err(|_| "Cannot read backend settings")?
        .ok_or("No managed Xray installation is selected")?;
    if selected.source != BackendExecutableSource::Managed
        || selected.path != expected
        || selected.version.as_deref() != Some(managed_xray_offer().version.as_str())
    {
        return Err("The selected Xray backend is not the pinned managed installation".into());
    }
    write_settings(root, TunnelBackend::Xray, None)?;
    if let Err(error) = remove_via_daemon(engine) {
        write_settings(root, TunnelBackend::Xray, Some(selected))
            .map_err(|_| format!("{error}; restoring the managed selection failed"))?;
        return Err(error);
    }
    Ok(())
}

// Tauri package_info().name uses tauri.conf.json's productName.
const AUTOSTART_NAME: &str = "Network Orchestrator";
fn autostart_path() -> Result<PathBuf, String> {
    user_only()?;
    // auto-launch 0.5 uses HOME/.config, including when XDG_CONFIG_HOME is set.
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or("A user home directory is required")?;
    Ok(home
        .join(".config/autostart")
        .join(format!("{AUTOSTART_NAME}.desktop")))
}
pub fn login_autostart() -> Result<bool, String> {
    let path = autostart_path()?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && meta.uid() == unsafe { libc::geteuid() } => Ok(true),
        Ok(_) => Err("Autostart entry is not a user-owned regular file".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("Cannot inspect login autostart".into()),
    }
}
fn desktop_entry(executable: &Path) -> Result<String, String> {
    let path = executable
        .to_str()
        .ok_or("GUI executable path is not valid UTF-8")?;
    if !executable.is_absolute() || path.contains(['\n', '\r', '\0']) {
        return Err("GUI executable path is invalid".into());
    }
    let mut escaped = String::new();
    for c in path.chars() {
        match c {
            '\\' => escaped.push_str("\\\\\\\\"),
            '"' | '`' | '$' => {
                escaped.push_str("\\\\");
                escaped.push(c);
            }
            '%' => escaped.push_str("%%"),
            _ => escaped.push(c),
        }
    }
    Ok(format!("[Desktop Entry]\nType=Application\nVersion=1.0\nName={AUTOSTART_NAME}\nComment={AUTOSTART_NAME} startup script\nExec=\"{escaped}\"\nStartupNotify=false\nTerminal=false\n"))
}
pub fn set_login_autostart(enabled: bool) -> Result<bool, String> {
    let path = autostart_path()?;
    if !enabled {
        if login_autostart()? {
            fs::remove_file(path).map_err(|_| "Cannot disable login autostart")?;
        }
        return Ok(false);
    }
    let current = std::env::current_exe().map_err(|_| "Cannot locate GUI executable")?;
    let executable = std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| current.with_file_name("net-manager-app"));
    if !executable.is_file() {
        return Err("Install the GUI alongside netorch before enabling login autostart".into());
    }
    let body = desktop_entry(&executable)?;
    let directory = path.parent().ok_or("Invalid autostart directory")?;
    fs::create_dir_all(directory).map_err(|_| "Cannot create autostart directory")?;
    let metadata =
        fs::symlink_metadata(directory).map_err(|_| "Cannot inspect autostart directory")?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err("Autostart directory ownership is invalid".into());
    }
    let temp = directory.join(format!(".{AUTOSTART_NAME}-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|_| "Cannot create private autostart entry")?;
    let result = (|| {
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, &path)?;
        File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result.map_err(|_| "Cannot atomically save login autostart")?;
    login_autostart()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn shared_install_cancel_reaches_another_coordinator() {
        let directory = directory();
        let install = InstallGuard::begin(directory.path()).unwrap();
        assert!(InstallGuard::begin(directory.path()).is_err());
        cancel_in(directory.path()).unwrap();
        assert!(install.check_cancelled().is_err());
        assert!(install
            .commit(|| panic!("cancelled install must not select executable"))
            .is_err());
    }

    #[test]
    fn idle_cancel_does_not_cancel_the_next_install() {
        let directory = directory();
        assert!(cancel_in(directory.path()).is_err());
        {
            let install = InstallGuard::begin(directory.path()).unwrap();
            cancel_in(directory.path()).unwrap();
            assert!(install.check_cancelled().is_err());
        }
        let next = InstallGuard::begin(directory.path()).unwrap();
        next.check_cancelled().unwrap();
        next.commit(|| Ok(())).unwrap();
        assert!(cancel_in(directory.path()).is_err());
    }

    #[test]
    fn installer_rejects_symlinked_control_files() {
        let directory = directory();
        let target = directory.path().join("target");
        std::fs::write(&target, "untouched").unwrap();
        symlink(&target, directory.path().join("backend-control.lock")).unwrap();
        assert!(InstallGuard::begin(directory.path()).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "untouched");
    }

    #[test]
    fn successful_install_cannot_be_cancelled_after_selection() {
        let directory = directory();
        let install = InstallGuard::begin(directory.path()).unwrap();
        let selected = std::cell::Cell::new(false);
        install
            .commit(|| {
                selected.set(true);
                Ok(())
            })
            .unwrap();
        assert!(selected.get());
        assert!(cancel_in(directory.path()).is_err());
    }

    #[test]
    fn shared_install_cancel_crosses_process_boundary() {
        let directory = directory();
        let install = InstallGuard::begin(directory.path()).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "linux_system::tests::cancel_child_process",
                "--nocapture",
            ])
            .env("NETORCH_TEST_CANCEL_DIRECTORY", directory.path())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(install.check_cancelled().is_err());
    }

    #[test]
    fn cancel_child_process() {
        if let Some(directory) = std::env::var_os("NETORCH_TEST_CANCEL_DIRECTORY") {
            cancel_in(Path::new(&directory)).unwrap();
        }
    }

    #[test]
    fn autostart_exec_rejects_line_injection_and_escapes_field_codes() {
        assert!(desktop_entry(Path::new("/opt/gui\nHidden=true")).is_err());
        let entry = desktop_entry(Path::new("/opt/My GUI%/app")).unwrap();
        assert!(entry.contains("Exec=\"/opt/My GUI%%/app\""));
        assert!(entry.contains("Name=Network Orchestrator"));
    }

    #[test]
    fn installer_rejects_shared_or_public_control_files() {
        let directory = directory();
        let control_path = directory.path().join("backend-control.lock");
        std::fs::write(&control_path, "untouched").unwrap();
        std::fs::set_permissions(&control_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(InstallGuard::begin(directory.path()).is_err());
        std::fs::set_permissions(&control_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&control_path, directory.path().join("alias")).unwrap();
        assert!(InstallGuard::begin(directory.path()).is_err());
        assert_eq!(std::fs::read_to_string(control_path).unwrap(), "untouched");
    }

    struct InventoryDaemon {
        capabilities: Vec<String>,
        tools: std::collections::BTreeMap<String, bool>,
    }

    impl crate::privileged::Privileged for InventoryDaemon {
        fn hello(&self) -> Result<protocol::HelloResult, HelperError> {
            Ok(protocol::HelloResult {
                protocol: protocol::PROTOCOL_VERSION,
                daemon_version: "test".into(),
                uid: 1000,
                capabilities: self.capabilities.clone(),
                tools: self.tools.clone(),
            })
        }
        fn call_raw(
            &self,
            _: &str,
            _: serde_json::Value,
        ) -> Result<serde_json::Value, HelperError> {
            panic!("backend inventory must not mutate the daemon")
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    #[test]
    fn vpn_backend_availability_requires_methods_and_usable_system_tools() {
        let directory = directory();
        let methods = [
            method::WIREGUARD_CONNECT,
            method::WIREGUARD_DISCONNECT,
            method::WIREGUARD_STATUS,
            method::OPENVPN_CONNECT,
            method::OPENVPN_DISCONNECT,
            method::OPENVPN_STATUS,
        ];
        for usable in [Some(true), Some(false), None] {
            let tools = [protocol::tool::WIREGUARD, protocol::tool::OPENVPN]
                .into_iter()
                .filter_map(|tool| usable.map(|value| (tool.to_string(), value)))
                .collect();
            let engine = LinuxEngine::with_privileged(std::sync::Arc::new(InventoryDaemon {
                capabilities: methods.iter().map(|m| m.to_string()).collect(),
                tools,
            }));
            let entries = backend_availability(&engine, directory.path()).unwrap();
            for entry in entries.iter().filter(|e| e.backend != TunnelBackend::Xray) {
                assert_eq!(entry.available, usable != Some(false));
                assert!(entry.path.is_none());
                assert!(entry.source.is_none());
            }
        }
        let engine = LinuxEngine::with_privileged(std::sync::Arc::new(InventoryDaemon {
            capabilities: vec![
                method::WIREGUARD_CONNECT.into(),
                method::OPENVPN_CONNECT.into(),
            ],
            tools: Default::default(),
        }));
        let entries = backend_availability(&engine, directory.path()).unwrap();
        assert!(entries
            .iter()
            .filter(|e| e.backend != TunnelBackend::Xray)
            .all(|e| !e.available));
    }

    #[test]
    fn linux_capabilities_hide_windows_only_features() {
        let caps = platform_capabilities();
        assert_eq!(caps.os, "linux");
        assert_eq!(
            caps.system_proxy,
            net_manager_core::system_proxy::linux::available()
        );
        assert!(!caps.wireguard_standard_import);
        assert_eq!(caps.managed_xray_install, cfg!(target_arch = "x86_64"));
        assert!(!caps.elevation_relaunch);
        assert!(!caps.app_updates);
        assert!(caps.executable_extensions.is_empty());
    }

    #[test]
    fn managed_offer_matches_pinned_linux_release() {
        let offer = managed_xray_offer();
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(offer.version, managed_xray::LINUX_XRAY_VERSION);
            assert_eq!(offer.source_url, managed_xray::LINUX_XRAY_URL);
            assert_eq!(offer.sha256, managed_xray::LINUX_XRAY_SHA256);
        }
        assert_eq!(
            offer.max_download_bytes,
            managed_xray::MAX_XRAY_ARCHIVE_BYTES as u64
        );
    }

    #[test]
    fn daemon_status_uses_the_explicit_engine_endpoint() {
        let directory = directory();
        let socket = directory.path().join("daemon.sock");
        std::fs::write(&socket, b"not a socket").unwrap();
        let engine = LinuxEngine::for_socket(socket, "system-status-test");
        assert_eq!(daemon_status(&engine).unwrap().state, DaemonState::Error);
    }

    struct FailedHandshake {
        mismatch: bool,
    }

    impl crate::privileged::Privileged for FailedHandshake {
        fn hello(&self) -> Result<protocol::HelloResult, HelperError> {
            if self.mismatch {
                Err(HelperError::Rejected(protocol::ErrorBody {
                    code: protocol::ErrorCode::ProtocolMismatch,
                    message: "private handshake details".into(),
                }))
            } else {
                Err(HelperError::Protocol("private handshake details".into()))
            }
        }

        fn call_raw(
            &self,
            _: &str,
            _: serde_json::Value,
        ) -> Result<serde_json::Value, HelperError> {
            panic!("daemon status must only perform a handshake")
        }

        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    #[test]
    fn daemon_status_classifies_rejected_protocol_mismatch_as_incompatible() {
        let engine =
            LinuxEngine::with_privileged(std::sync::Arc::new(FailedHandshake { mismatch: true }));
        let status = daemon_status(&engine).unwrap();
        assert_eq!(status.state, DaemonState::Incompatible);
        assert!(!status.message.contains("private handshake details"));
        assert_eq!(
            serde_json::to_value(status).unwrap()["state"],
            "incompatible"
        );
    }

    #[test]
    fn daemon_status_classifies_protocol_errors_as_incompatible() {
        let engine =
            LinuxEngine::with_privileged(std::sync::Arc::new(FailedHandshake { mismatch: false }));
        let status = daemon_status(&engine).unwrap();
        assert_eq!(status.state, DaemonState::Incompatible);
        assert!(!status.message.contains("private handshake details"));
        assert_eq!(
            serde_json::to_value(status).unwrap()["state"],
            "incompatible"
        );
    }

    #[test]
    fn backend_settings_reject_symlinks_and_preserve_other_backends() {
        let directory = directory();
        let target = directory.path().join("target.json");
        let body = serde_json::to_vec(&BackendSettingsDocument::default()).unwrap();
        std::fs::write(&target, &body).unwrap();
        let path = directory.path().join("backend-settings.json");
        symlink(&target, &path).unwrap();
        let setting = BackendExecutableSetting {
            path: PathBuf::from("/usr/bin/xray"),
            source: BackendExecutableSource::Configured,
            version: None,
        };
        assert!(
            write_settings(directory.path(), TunnelBackend::Xray, Some(setting.clone())).is_err()
        );
        assert_eq!(std::fs::read(&target).unwrap(), body);
        std::fs::remove_file(&path).unwrap();
        write_settings(
            directory.path(),
            TunnelBackend::WireGuard,
            Some(BackendExecutableSetting {
                path: PathBuf::from("/usr/bin/wg"),
                source: BackendExecutableSource::Configured,
                version: None,
            }),
        )
        .unwrap();
        write_settings(directory.path(), TunnelBackend::Xray, Some(setting)).unwrap();
        let document = settings(directory.path()).load().unwrap();
        assert_eq!(
            document.wire_guard.unwrap().path,
            PathBuf::from("/usr/bin/wg")
        );
        assert_eq!(document.xray.unwrap().path, PathBuf::from("/usr/bin/xray"));
        assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn shared_backend_resolver_preserves_configured_paths_and_rejects_invalid_managed_identity() {
        let directory = directory();
        let executable = std::env::current_exe().unwrap();
        write_settings(
            directory.path(),
            TunnelBackend::Xray,
            Some(BackendExecutableSetting {
                path: executable.clone(),
                source: BackendExecutableSource::Configured,
                version: None,
            }),
        )
        .unwrap();
        assert_eq!(
            backend_executable(directory.path(), TunnelBackend::Xray).unwrap(),
            executable
        );
        write_settings(
            directory.path(),
            TunnelBackend::WireGuard,
            Some(BackendExecutableSetting {
                path: executable,
                source: BackendExecutableSource::Managed,
                version: Some("untrusted".into()),
            }),
        )
        .unwrap();
        assert!(backend_executable(directory.path(), TunnelBackend::WireGuard).is_err());
        assert!(backend_executable(directory.path(), TunnelBackend::None).is_err());
        write_settings(
            directory.path(),
            TunnelBackend::Xray,
            Some(BackendExecutableSetting {
                path: PathBuf::from("/tmp/not-the-managed-package"),
                source: BackendExecutableSource::Managed,
                version: Some("untrusted".into()),
            }),
        )
        .unwrap();
        assert!(backend_executable(directory.path(), TunnelBackend::Xray).is_err());
    }
}
