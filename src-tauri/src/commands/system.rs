use crate::elevation;
use crate::state::AppState;
#[cfg(not(target_os = "linux"))]
use crate::state::{resolve_backend_path, ResolvedBackendExecutable, RuntimeState};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use net_manager_core::managed_xray::ManagedXrayInstallation;
#[cfg(not(target_os = "linux"))]
use net_manager_core::managed_xray::{self, MAX_XRAY_ARCHIVE_BYTES};
#[cfg(not(target_os = "linux"))]
use net_manager_core::managed_xray::{MANAGED_XRAY_URL, MANAGED_XRAY_VERSION};
use net_manager_core::models::{BackendAvailability, TunnelBackend};
#[cfg(not(target_os = "linux"))]
use net_manager_core::models::{
    BackendExecutableSetting, BackendExecutableSource, Profile, TunnelState,
};
#[cfg(not(target_os = "linux"))]
use net_manager_core::vpn::TunnelManager;
#[cfg(not(target_os = "linux"))]
use serde::Serialize;
#[cfg(not(target_os = "linux"))]
use std::io;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use tauri::Emitter;
use tauri::State;

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn is_elevated() -> Result<bool, String> {
    elevation::is_elevated().map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn daemon_status() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({"state":"notRequired","message":""}))
}

/// Administrator-chosen VPN password mode; `None` where no daemon exists.
#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn get_vpn_auth_mode(
) -> Result<Option<net_manager_core::daemon_protocol::VpnAuthMode>, String> {
    Ok(None)
}

/// Changing the mode asks the daemon, which requires an administrator.
#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn set_vpn_auth_mode(
    mode: net_manager_core::daemon_protocol::VpnAuthMode,
) -> Result<(), String> {
    let _ = mode;
    Err("VPN password mode is managed by the Linux daemon".into())
}

/// Discover WireGuard configs in the standard Windows service location
/// `C:\Program Files\WireGuard\Data\Configurations\`. Requires elevation to
/// read the ACL-protected directory. Returns sorted absolute paths to
/// `.conf.dpapi` (and `.conf`) files.
#[tauri::command]
pub(crate) async fn discover_wireguard_configs() -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        let dir = PathBuf::from(r"C:\Program Files\WireGuard\Data\Configurations");
        let mut paths = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(err) => {
                return Err(format!(
                    "cannot read WireGuard configs directory '{}': {err}. Run as administrator.",
                    dir.display()
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".conf") || name.ends_with(".conf.dpapi") {
                paths.push(entry.path().to_string_lossy().to_string());
            }
        }
        paths.sort();
        Ok(paths)
    }
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

#[cfg(not(target_os = "linux"))]
fn backend_entry(
    backend: TunnelBackend,
    resolved: Result<ResolvedBackendExecutable, io::Error>,
    persisted: io::Result<Option<BackendExecutableSetting>>,
) -> BackendAvailability {
    let persisted = persisted.ok().flatten();
    match resolved {
        Ok(resolved) => BackendAvailability {
            backend,
            available: true,
            path: Some(resolved.path),
            source: Some(resolved.source),
            version: resolved.version,
            message: "executable found".to_string(),
        },
        Err(err) => BackendAvailability {
            backend,
            available: false,
            path: persisted.as_ref().map(|s| s.path.clone()),
            source: persisted.as_ref().map(|s| s.source),
            version: persisted.and_then(|s| s.version),
            message: format!("executable unavailable: {err}"),
        },
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn collect_backend_availability(state: &AppState) -> Vec<BackendAvailability> {
    [
        TunnelBackend::WireGuard,
        TunnelBackend::OpenVpn,
        TunnelBackend::Xray,
    ]
    .into_iter()
    .map(|backend| {
        backend_entry(
            backend,
            state.resolve_backend_executable(backend),
            state.backend_settings.get(backend),
        )
    })
    .collect()
}

/// System proxy ownership for the status bar: which profile applied it.
#[cfg(not(target_os = "linux"))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemProxyStatus {
    pub owner_profile_id: Option<String>,
    pub owner_name: Option<String>,
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn system_proxy_status(
    state: State<'_, AppState>,
) -> Result<SystemProxyStatus, String> {
    let owner_profile_id = state
        .proxy_ownership()
        .await
        .map_err(|error| error.to_string())?
        .map(|ownership| ownership.profile_id);
    let owner_name = match &owner_profile_id {
        Some(id) => state.profiles.load().ok().and_then(|doc| {
            doc.profiles
                .iter()
                .find(|p| p.id == *id)
                .map(|p| p.name.clone())
        }),
        None => None,
    };
    Ok(SystemProxyStatus {
        owner_profile_id,
        owner_name,
    })
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn get_backend_availability(
    state: State<'_, AppState>,
) -> Result<Vec<BackendAvailability>, String> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut availability = collect_backend_availability(&state);
    Ok(availability)
}

#[cfg(not(target_os = "linux"))]
fn backend_running_error(
    tunnels: &mut TunnelManager,
    profiles: &[Profile],
    backend: TunnelBackend,
) -> Result<(), String> {
    for profile in profiles.iter().filter(|p| p.backend == backend) {
        if tunnels.status(profile).state == TunnelState::Running {
            return Err(format!(
                "cannot change {backend:?} executable while profile '{}' is running",
                profile.name
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_managed_replacement(
    current: Option<&BackendExecutableSetting>,
    managed_replacement_error: Option<&str>,
) -> Result<(), String> {
    if let Some(message) = managed_replacement_error {
        guard_managed_selection(current, message)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn select_backend_executable(
    runtime: &mut RuntimeState,
    state: &AppState,
    backend: TunnelBackend,
    setting: Option<BackendExecutableSetting>,
    managed_replacement_error: Option<&str>,
) -> Result<(), String> {
    let current = state
        .backend_settings
        .get(backend)
        .map_err(|e| e.to_string())?;
    check_managed_replacement(current.as_ref(), managed_replacement_error)?;
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    backend_running_error(&mut runtime.tunnels, &profiles, backend)?;
    let executable = setting.as_ref().map(|s| s.path.clone());
    state
        .backend_settings
        .set(backend, setting)
        .map_err(|e| e.to_string())?;
    runtime.tunnels.set_executable(backend, executable);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn guard_managed_selection(
    setting: Option<&BackendExecutableSetting>,
    message: &str,
) -> Result<(), String> {
    if setting.is_some_and(|s| s.source == BackendExecutableSource::Managed) {
        return Err(message.to_string());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn set_backend_executable(
    backend: TunnelBackend,
    path: PathBuf,
    state: State<'_, AppState>,
) -> Result<(), String> {
    resolve_backend_path(backend, Some(&path)).map_err(|e| e.to_string())?;
    let _install_guard = if backend == TunnelBackend::Xray {
        Some(state.backend_install_lock.lock().await)
    } else {
        None
    };
    let mut runtime = state.runtime.lock().await;
    select_backend_executable(
        &mut runtime,
        &state,
        backend,
        Some(BackendExecutableSetting {
            path,
            source: BackendExecutableSource::Configured,
            version: None,
        }),
        Some("remove the managed Xray installation before choosing another executable"),
    )
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn reset_backend_executable(
    backend: TunnelBackend,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let _install_guard = if backend == TunnelBackend::Xray {
        Some(state.backend_install_lock.lock().await)
    } else {
        None
    };
    let mut runtime = state.runtime.lock().await;
    select_backend_executable(
        &mut runtime,
        &state,
        backend,
        None,
        Some("remove the managed Xray installation instead of resetting it"),
    )
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ManagedXrayOffer {
    version: String,
    source_url: String,
    sha256: String,
    max_download_bytes: u64,
}

#[cfg(not(target_os = "linux"))]
fn managed_xray_offer() -> ManagedXrayOffer {
    {
        ManagedXrayOffer {
            version: MANAGED_XRAY_VERSION.to_string(),
            source_url: MANAGED_XRAY_URL.to_string(),
            sha256: managed_xray::MANAGED_XRAY_SHA256.to_string(),
            max_download_bytes: MAX_XRAY_ARCHIVE_BYTES as u64,
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) fn get_managed_xray_offer() -> ManagedXrayOffer {
    managed_xray_offer()
}

/// Which OS-specific features the frontend may offer on this platform.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlatformCapabilities {
    os: &'static str,
    system_proxy: bool,
    wireguard_standard_import: bool,
    managed_xray_install: bool,
    elevation_relaunch: bool,
    /// In-app updater remains hidden on Linux while no signed endpoint exists;
    /// `.deb` and other Linux installs update through their package manager.
    app_updates: bool,
    /// File-picker extensions for backend executables; empty means no filter.
    executable_extensions: Vec<String>,
}

#[cfg(not(target_os = "linux"))]
fn app_updates_available(windows: bool, _bundle: Option<tauri::utils::config::BundleType>) -> bool {
    windows
}

/// Windows has a system proxy; other non-Linux platforms do not.
#[cfg(not(target_os = "linux"))]
pub(crate) fn system_proxy_supported() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

#[cfg(not(target_os = "linux"))]
fn platform_capabilities() -> PlatformCapabilities {
    let windows = cfg!(windows);
    PlatformCapabilities {
        os: std::env::consts::OS,
        system_proxy: system_proxy_supported(),
        wireguard_standard_import: windows,
        managed_xray_install: cfg!(all(
            any(target_os = "windows", target_os = "linux"),
            target_arch = "x86_64"
        )),
        elevation_relaunch: windows,
        app_updates: app_updates_available(windows, tauri::utils::platform::bundle_type()),
        executable_extensions: if windows {
            vec!["exe".to_string()]
        } else {
            Vec::new()
        },
    }
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) fn get_platform_capabilities() -> PlatformCapabilities {
    platform_capabilities()
}

#[cfg(not(target_os = "linux"))]
#[cfg(all(
    any(target_os = "windows", target_os = "linux"),
    target_arch = "x86_64"
))]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendInstallProgress {
    backend: TunnelBackend,
    stage: String,
    downloaded: u64,
    total: Option<u64>,
}

// Used by `install_managed_xray_inner` on 64-bit Windows/Linux and directly
// by unit tests on every platform; never used by the plain (non-test,
// non-managed) lib build, hence `any(test, ...)`.
#[cfg(not(target_os = "linux"))]
#[cfg(any(
    test,
    all(
        any(target_os = "windows", target_os = "linux"),
        target_arch = "x86_64"
    )
))]
fn checked_download_len(current: usize, chunk_len: usize) -> io::Result<usize> {
    match current.checked_add(chunk_len) {
        Some(total) if total <= MAX_XRAY_ARCHIVE_BYTES => Ok(total),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed Xray download exceeds the maximum archive size",
        )),
    }
}

#[cfg(not(target_os = "linux"))]
#[cfg(any(
    test,
    all(
        any(target_os = "windows", target_os = "linux"),
        target_arch = "x86_64"
    )
))]
fn append_download_chunk(buffer: &mut Vec<u8>, chunk: &[u8], cancelled: bool) -> io::Result<()> {
    if cancelled {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "managed Xray install cancelled",
        ));
    }
    checked_download_len(buffer.len(), chunk.len())?;
    buffer.extend_from_slice(chunk);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[cfg(any(
    test,
    all(
        any(target_os = "windows", target_os = "linux"),
        target_arch = "x86_64"
    )
))]
fn validate_download_length(actual: usize, declared: Option<u64>) -> io::Result<()> {
    if let Some(declared) = declared {
        if declared != actual as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed Xray download length did not match Content-Length",
            ));
        }
    }
    Ok(())
}

/// The pinned managed Xray release for non-Linux frontends.
#[cfg(not(target_os = "linux"))]
fn managed_xray_version() -> &'static str {
    {
        MANAGED_XRAY_VERSION
    }
}

#[cfg(not(target_os = "linux"))]
fn require_managed_xray_setting(
    setting: Option<BackendExecutableSetting>,
) -> Result<BackendExecutableSetting, String> {
    match setting {
        Some(setting)
            if setting.source == BackendExecutableSource::Managed
                && setting.version.as_deref() == Some(managed_xray_version()) =>
        {
            Ok(setting)
        }
        Some(_) => Err("the selected Xray backend is not the managed installation".to_string()),
        None => Err("no managed Xray installation is selected".to_string()),
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn cleanup_created_installation(installation: &ManagedXrayInstallation) -> io::Result<()> {
    if installation.created {
        std::fs::remove_dir_all(&installation.version_dir)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
fn install_failure_message(primary: String, cleanup: io::Result<()>) -> String {
    match cleanup {
        Ok(()) => primary,
        Err(err) => format!(
            "{primary}; cleanup of the created installation failed and files remain that require manual removal: {err}"
        ),
    }
}

#[cfg(not(target_os = "linux"))]
#[cfg(all(
    any(target_os = "windows", target_os = "linux"),
    target_arch = "x86_64"
))]
fn emit_install_progress(app: &tauri::AppHandle, stage: &str, downloaded: u64, total: Option<u64>) {
    let _ = app.emit(
        "backend-install-progress",
        BackendInstallProgress {
            backend: TunnelBackend::Xray,
            stage: stage.to_string(),
            downloaded,
            total,
        },
    );
}

/// Windows downloads are verified and installed app-side.
#[cfg(not(target_os = "linux"))]
#[cfg(all(
    any(target_os = "windows", target_os = "linux"),
    target_arch = "x86_64"
))]
async fn download_managed_xray_archive(
    app: &tauri::AppHandle,
    url: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<(Vec<u8>, Option<u64>), String> {
    use futures_util::StreamExt;
    use std::time::Duration;

    emit_install_progress(app, "downloading", 0, None);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("Network-Orchestrator/0.1.0")
        .build()
        .map_err(|e| format!("cannot build download client: {e}"))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("managed Xray download failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("managed Xray download failed: {e}"))?;
    let total = response.content_length();
    if total.is_some_and(|len| len > MAX_XRAY_ARCHIVE_BYTES as u64) {
        return Err("managed Xray archive is larger than the allowed maximum".to_string());
    }
    let mut buffer = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("managed Xray download failed: {e}"))?;
        match append_download_chunk(&mut buffer, &chunk, cancel.load(Ordering::SeqCst)) {
            Ok(()) => emit_install_progress(app, "downloading", buffer.len() as u64, total),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                emit_install_progress(app, "cancelled", buffer.len() as u64, total);
                return Err(err.to_string());
            }
            Err(err) => return Err(err.to_string()),
        }
    }
    validate_download_length(buffer.len(), total).map_err(|e| e.to_string())?;
    Ok((buffer, total))
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn install_managed_xray(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    install_managed_xray_inner(app, state.inner()).await
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
async fn install_managed_xray_inner(app: tauri::AppHandle, state: &AppState) -> Result<(), String> {
    let _install_guard = state.backend_install_lock.lock().await;
    state.backend_install_cancel.store(false, Ordering::SeqCst);

    {
        let mut runtime = state.runtime.lock().await;
        let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
        backend_running_error(&mut runtime.tunnels, &profiles, TunnelBackend::Xray)?;
    }

    let (buffer, total) =
        download_managed_xray_archive(&app, MANAGED_XRAY_URL, &state.backend_install_cancel)
            .await?;

    let downloaded = buffer.len() as u64;
    emit_install_progress(&app, "verifying", downloaded, total);
    emit_install_progress(&app, "installing", downloaded, total);
    let root = state.managed_xray_root.clone();
    let installation =
        tokio::task::spawn_blocking(move || managed_xray::install_verified_archive(&root, &buffer))
            .await
            .map_err(|e| format!("managed Xray install task failed: {e}"))?
            .map_err(|e| format!("managed Xray install failed: {e}"))?;

    emit_install_progress(&app, "validating", downloaded, total);
    let validation = async {
        let output = tokio::process::Command::new(&installation.executable)
            .arg("version")
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| format!("cannot run managed Xray: {e}"))?;
        if !output.status.success() {
            return Err("managed Xray version check exited unsuccessfully".to_string());
        }
        let mut head = output.stdout;
        head.truncate(512);
        let text = String::from_utf8_lossy(&head);
        let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        if !first.to_lowercase().contains("xray") {
            return Err("installed binary did not report an Xray version".to_string());
        }
        Ok::<(), String>(())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(10), validation).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            return Err(install_failure_message(
                err,
                cleanup_created_installation(&installation),
            ));
        }
        Err(_) => {
            return Err(install_failure_message(
                "managed Xray version check timed out".to_string(),
                cleanup_created_installation(&installation),
            ));
        }
    }

    if state.backend_install_cancel.load(Ordering::SeqCst) {
        emit_install_progress(&app, "cancelled", downloaded, total);
        return Err(install_failure_message(
            "managed Xray install cancelled".to_string(),
            cleanup_created_installation(&installation),
        ));
    }

    let mut runtime = state.runtime.lock().await;
    let selection = select_backend_executable(
        &mut runtime,
        state,
        TunnelBackend::Xray,
        Some(BackendExecutableSetting {
            path: installation.executable.clone(),
            source: BackendExecutableSource::Managed,
            version: Some(managed_xray_version().to_string()),
        }),
        None,
    );
    if let Err(err) = selection {
        drop(runtime);
        return Err(install_failure_message(
            err,
            cleanup_created_installation(&installation),
        ));
    }
    drop(runtime);
    emit_install_progress(&app, "ready", downloaded, total);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[cfg(not(all(
    any(target_os = "windows", target_os = "linux"),
    target_arch = "x86_64"
)))]
async fn install_managed_xray_inner(
    _app: tauri::AppHandle,
    _state: &AppState,
) -> Result<(), String> {
    Err("managed Xray installation is only supported on 64-bit Windows or Linux".to_string())
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn cancel_managed_xray_install(state: State<'_, AppState>) -> Result<(), String> {
    state.backend_install_cancel.store(true, Ordering::SeqCst);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn remove_managed_xray(state: State<'_, AppState>) -> Result<(), String> {
    remove_managed_xray_inner(state.inner()).await
}

#[cfg(not(target_os = "linux"))]
async fn remove_managed_xray_inner(state: &AppState) -> Result<(), String> {
    let _install_guard = state.backend_install_lock.lock().await;
    let mut runtime = state.runtime.lock().await;
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    backend_running_error(&mut runtime.tunnels, &profiles, TunnelBackend::Xray)?;
    let setting = require_managed_xray_setting(
        state
            .backend_settings
            .get(TunnelBackend::Xray)
            .map_err(|e| e.to_string())?,
    )?;
    let managed =
        managed_xray::is_managed_executable_location(&state.managed_xray_root, &setting.path)
            .map_err(|e| format!("cannot verify managed Xray path: {e}"))?;
    if !managed {
        return Err("selected Xray executable is not inside the managed installation".to_string());
    }
    let version_dir = managed_xray::managed_version_dir(&state.managed_xray_root);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let quarantine = state.managed_xray_root.join(format!(
        "{MANAGED_XRAY_VERSION}.remove-{}-{nanos}",
        std::process::id()
    ));
    std::fs::rename(&version_dir, &quarantine)
        .map_err(|e| format!("cannot quarantine managed Xray: {e}"))?;
    if let Err(err) = state.backend_settings.set(TunnelBackend::Xray, None) {
        return Err(match std::fs::rename(&quarantine, &version_dir) {
            Ok(()) => format!("cannot clear managed Xray setting: {err}"),
            Err(rollback) => format!(
                "cannot clear managed Xray setting: {err}; rollback failed, quarantined files remain at '{}': {rollback}",
                quarantine.display()
            ),
        });
    }
    runtime.tunnels.set_executable(TunnelBackend::Xray, None);
    if let Err(err) = std::fs::remove_dir_all(&quarantine) {
        return Err(format!(
            "managed Xray backend was unselected, but quarantined files could not be removed: {err}"
        ));
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn restart_elevated(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if elevation::is_elevated().map_err(|e| e.to_string())? {
        return Ok(());
    }
    elevation::restart_elevated().map_err(|e| e.to_string())?;
    state.cleanup_complete.store(true, Ordering::SeqCst);
    app.exit(0);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{app_state, unique_dir};
    use std::io;

    #[test]
    fn capabilities_serialize_with_frontend_field_names() {
        let value = serde_json::to_value(platform_capabilities()).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "appUpdates",
                "elevationRelaunch",
                "executableExtensions",
                "managedXrayInstall",
                "os",
                "systemProxy",
                "wireguardStandardImport",
            ]
        );
    }

    #[test]
    fn deb_does_not_offer_updater_without_an_endpoint() {
        use tauri::utils::config::BundleType;

        assert!(app_updates_available(true, None));
        assert!(app_updates_available(true, Some(BundleType::Nsis)));
        assert!(!app_updates_available(false, Some(BundleType::Deb)));
        assert!(!app_updates_available(false, None));
        assert!(!app_updates_available(false, Some(BundleType::AppImage)));
        assert!(!app_updates_available(false, Some(BundleType::Rpm)));
    }

    #[cfg(windows)]
    #[test]
    fn windows_capabilities_expose_windows_features() {
        let caps = platform_capabilities();
        assert_eq!(caps.os, "windows");
        assert!(caps.system_proxy);
        assert!(caps.wireguard_standard_import);
        assert!(caps.elevation_relaunch);
        assert!(caps.app_updates);
        assert_eq!(caps.executable_extensions, vec!["exe".to_string()]);
    }

    #[test]
    fn backend_entry_maps_found_and_missing() {
        let found = backend_entry(
            TunnelBackend::WireGuard,
            Ok(ResolvedBackendExecutable {
                path: PathBuf::from(r"C:\tools\wireguard.exe"),
                source: BackendExecutableSource::AutoDetected,
                version: None,
            }),
            Ok(None),
        );
        assert!(found.available);
        assert_eq!(
            found.path.unwrap(),
            PathBuf::from(r"C:\tools\wireguard.exe")
        );

        let missing = backend_entry(
            TunnelBackend::Xray,
            Err(io::Error::new(io::ErrorKind::NotFound, "xray.exe missing")),
            Ok(None),
        );
        assert!(!missing.available);
        assert!(missing.path.is_none());
        assert!(missing.message.contains("xray.exe missing"));
    }

    #[test]
    fn availability_preserves_missing_configured_source() {
        let dir = unique_dir("avail-missing-cfg");
        let state = app_state(&dir);
        state
            .backend_settings
            .set(
                TunnelBackend::Xray,
                Some(BackendExecutableSetting {
                    path: PathBuf::from(r"C:\missing\xray.exe"),
                    source: BackendExecutableSource::Configured,
                    version: None,
                }),
            )
            .unwrap();

        let items = collect_backend_availability(&state);
        assert_eq!(
            items.iter().map(|i| i.backend).collect::<Vec<_>>(),
            vec![
                TunnelBackend::WireGuard,
                TunnelBackend::OpenVpn,
                TunnelBackend::Xray
            ]
        );

        let xray = items
            .iter()
            .find(|i| i.backend == TunnelBackend::Xray)
            .unwrap();
        assert!(!xray.available);
        assert_eq!(xray.path, Some(PathBuf::from(r"C:\missing\xray.exe")));
        assert_eq!(xray.source, Some(BackendExecutableSource::Configured));
        assert_eq!(xray.version, None);
        assert!(!xray.message.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn configured_selection_rejects_selected_managed_source() {
        let managed = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\managed\v26.7.28\xray.exe"),
            source: BackendExecutableSource::Managed,
            version: Some(net_manager_core::managed_xray::MANAGED_XRAY_VERSION.to_string()),
        });
        let err = guard_managed_selection(
            managed.as_ref(),
            "remove the managed Xray installation before choosing another executable",
        )
        .unwrap_err();
        assert_eq!(
            err,
            "remove the managed Xray installation before choosing another executable"
        );

        let configured = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\tools\xray.exe"),
            source: BackendExecutableSource::Configured,
            version: None,
        });
        assert!(guard_managed_selection(configured.as_ref(), "unused").is_ok());
        assert!(guard_managed_selection(None, "unused").is_ok());
    }

    #[test]
    fn reset_rejects_selected_managed_source() {
        let managed = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\managed\v26.7.28\xray.exe"),
            source: BackendExecutableSource::Managed,
            version: Some(net_manager_core::managed_xray::MANAGED_XRAY_VERSION.to_string()),
        });
        let err = guard_managed_selection(
            managed.as_ref(),
            "remove the managed Xray installation instead of resetting it",
        )
        .unwrap_err();
        assert_eq!(
            err,
            "remove the managed Xray installation instead of resetting it"
        );
    }

    #[test]
    fn managed_install_is_the_only_allowed_managed_replacement() {
        let managed = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\managed\v26.7.28\xray.exe"),
            source: BackendExecutableSource::Managed,
            version: Some(net_manager_core::managed_xray::MANAGED_XRAY_VERSION.to_string()),
        });
        assert!(
            check_managed_replacement(managed.as_ref(), None).is_ok(),
            "managed installer selection must be allowed to replace a managed setting"
        );
        assert!(check_managed_replacement(
            managed.as_ref(),
            Some("remove the managed Xray installation before choosing another executable")
        )
        .is_err());
        let configured = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\tools\xray.exe"),
            source: BackendExecutableSource::Configured,
            version: None,
        });
        assert!(check_managed_replacement(configured.as_ref(), Some("any")).is_ok());
        assert!(check_managed_replacement(None, Some("any")).is_ok());
    }

    #[test]
    fn managed_offer_matches_pinned_core_constants() {
        let offer = managed_xray_offer();
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            assert_eq!(
                offer.version,
                net_manager_core::managed_xray::LINUX_XRAY_VERSION
            );
            assert_eq!(
                offer.source_url,
                net_manager_core::managed_xray::LINUX_XRAY_URL
            );
            assert_eq!(
                offer.sha256,
                net_manager_core::managed_xray::LINUX_XRAY_SHA256
            );
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            assert_eq!(
                offer.version,
                net_manager_core::managed_xray::MANAGED_XRAY_VERSION
            );
            assert_eq!(
                offer.source_url,
                net_manager_core::managed_xray::MANAGED_XRAY_URL
            );
            assert_eq!(
                offer.sha256,
                net_manager_core::managed_xray::MANAGED_XRAY_SHA256
            );
        }
        assert_eq!(
            offer.max_download_bytes,
            net_manager_core::managed_xray::MAX_XRAY_ARCHIVE_BYTES as u64
        );
    }

    #[test]
    fn append_download_chunk_honors_cancel() {
        let mut buffer = Vec::new();
        let err = append_download_chunk(&mut buffer, b"chunk", true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(buffer.is_empty());
    }

    #[test]
    fn append_download_chunk_enforces_limit() {
        let mut buffer = vec![0u8; net_manager_core::managed_xray::MAX_XRAY_ARCHIVE_BYTES];
        let err = append_download_chunk(&mut buffer, b"x", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            buffer.len(),
            net_manager_core::managed_xray::MAX_XRAY_ARCHIVE_BYTES
        );

        let mut buffer = Vec::new();
        append_download_chunk(&mut buffer, b"abc", false).unwrap();
        assert_eq!(buffer, b"abc");
    }

    #[test]
    fn append_download_chunk_rejects_size_overflow() {
        let err = checked_download_len(usize::MAX, 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(checked_download_len(usize::MAX, 0).is_err());
        assert!(checked_download_len(0, 3).is_ok());
    }

    #[test]
    fn download_length_must_match_when_declared() {
        validate_download_length(10, None).unwrap();
        validate_download_length(10, Some(10)).unwrap();
        let err = validate_download_length(10, Some(20)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn cleanup_failure_is_reported_with_primary_error() {
        let message = install_failure_message(
            "primary failure".to_string(),
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
        );
        assert!(message.contains("primary failure"));
        assert!(message.contains("denied"));
        assert!(message.contains("manual"));

        let clean = install_failure_message("primary failure".to_string(), Ok(()));
        assert_eq!(clean, "primary failure");
    }

    #[test]
    fn managed_remove_rejects_configured_source() {
        let err = require_managed_xray_setting(Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\tools\xray.exe"),
            source: BackendExecutableSource::Configured,
            version: None,
        }))
        .unwrap_err();
        assert!(err.contains("managed"));

        assert!(require_managed_xray_setting(None).is_err());
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{ManagedXrayOffer, PlatformCapabilities, SystemProxyStatus};
#[cfg(target_os = "linux")]
use net_manager_engine::linux_system as linux;

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn is_elevated() -> Result<bool, String> {
    Ok(linux::is_elevated())
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn daemon_status() -> Result<serde_json::Value, String> {
    let status = crate::daemon_client::DaemonClient::system()
        .engine_request(|engine| linux::daemon_status(&engine))
        .await?;
    serde_json::to_value(status).map_err(|_| "Cannot encode daemon status".into())
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn get_vpn_auth_mode(
) -> Result<Option<net_manager_core::daemon_protocol::VpnAuthMode>, String> {
    crate::daemon_client::DaemonClient::system()
        .engine_request(|engine| linux::vpn_auth_mode(&engine))
        .await
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn set_vpn_auth_mode(
    mode: net_manager_core::daemon_protocol::VpnAuthMode,
) -> Result<(), String> {
    crate::daemon_client::DaemonClient::system()
        .engine_request(move |engine| linux::set_vpn_auth_mode(&engine, mode))
        .await
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn system_proxy_status(
    state: State<'_, AppState>,
) -> Result<SystemProxyStatus, String> {
    let root = state.data_dir().to_path_buf();
    crate::daemon_client::DaemonClient::system()
        .engine_request(move |engine| {
            let store = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"));
            linux::system_proxy_status(&engine, &root, &store)
        })
        .await
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn get_backend_availability(
    state: State<'_, AppState>,
) -> Result<Vec<BackendAvailability>, String> {
    let root = state.data_dir().to_path_buf();
    crate::daemon_client::DaemonClient::system()
        .engine_request(move |engine| {
            linux::backend_availability(&engine.with_data_root(root.clone()), &root)
        })
        .await
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn set_backend_executable(
    backend: TunnelBackend,
    path: PathBuf,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let root = state.data_dir().to_path_buf();
    crate::daemon_client::DaemonClient::system()
        .engine_request(move |engine| {
            let store = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"));
            linux::set_backend_executable(
                &engine.with_data_root(root.clone()),
                &root,
                &store,
                backend,
                &path,
            )
        })
        .await
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn reset_backend_executable(
    backend: TunnelBackend,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let root = state.data_dir().to_path_buf();
    crate::daemon_client::DaemonClient::system()
        .engine_request(move |engine| {
            let store = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"));
            linux::reset_backend_executable(
                &engine.with_data_root(root.clone()),
                &root,
                &store,
                backend,
            )
        })
        .await
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) fn get_managed_xray_offer() -> ManagedXrayOffer {
    linux::managed_xray_offer()
}
#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) fn get_platform_capabilities() -> PlatformCapabilities {
    linux::platform_capabilities()
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn install_managed_xray(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let root = state.data_dir().to_path_buf();
    crate::daemon_client::DaemonClient::system()
        .engine_request(move |engine| {
            let store = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"));
            let runtime =
                tokio::runtime::Runtime::new().map_err(|_| "Cannot start download runtime")?;
            runtime.block_on(linux::install_managed_xray(
                &engine.with_data_root(root.clone()),
                &root,
                &store,
                &move |progress| {
                    use tauri::Emitter;
                    let _ = app.emit("backend-install-progress", progress);
                },
            ))
        })
        .await
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn cancel_managed_xray_install(state: State<'_, AppState>) -> Result<(), String> {
    linux::cancel_managed_xray_install(state.data_dir())
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn remove_managed_xray(state: State<'_, AppState>) -> Result<(), String> {
    let root = state.data_dir().to_path_buf();
    crate::daemon_client::DaemonClient::system()
        .engine_request(move |engine| {
            let store = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"));
            linux::remove_managed_xray(&engine.with_data_root(root.clone()), &root, &store)
        })
        .await
}
