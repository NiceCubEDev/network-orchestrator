//! Shared, root-scoped macOS application policy. Reads never create state.
use net_manager_core::models::{TunnelBackend, XrayMode};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const SETTINGS_FILE: &str = "macos-settings.json";
const MAX_SETTINGS_BYTES: u64 = 4096;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AppMode {
    #[default]
    Combined,
    Orchestrator,
    Manager,
}

impl AppMode {
    pub fn allows_start(self, backend: TunnelBackend) -> bool {
        self != Self::Orchestrator || backend == TunnelBackend::None
    }

    fn legacy(value: Option<&str>) -> Self {
        match value {
            Some("orchestrator") => Self::Orchestrator,
            Some("manager") => Self::Manager,
            _ => Self::Combined,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub app_mode: AppMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyImportOutcome {
    pub settings: AppSettings,
    pub imported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartAvailability {
    pub proxy_connections: bool,
    pub helper_serves: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartEligibility {
    pub can_start: bool,
    pub can_try_start: bool,
    pub mode_blocked: bool,
}

/// Running profiles must remain stoppable; this function evaluates starts only.
pub fn start_eligibility(
    mode: AppMode,
    backend: TunnelBackend,
    xray_mode: XrayMode,
    availability: StartAvailability,
) -> StartEligibility {
    let mode_blocked = !mode.allows_start(backend);
    let loopback = backend == TunnelBackend::Xray && xray_mode == XrayMode::Socks;
    let can_try_start = !mode_blocked && availability.proxy_connections;
    StartEligibility {
        can_start: can_try_start && (loopback || availability.helper_serves),
        can_try_start,
        mode_blocked,
    }
}

/// Call while holding the runtime operation guard, before starting a backend.
/// This is intentionally read-only: acquiring another root lock would deadlock.
pub fn ensure_start_allowed(root: &Path, backend: TunnelBackend) -> Result<(), String> {
    check_start_mode(SettingsStore::new(root).load()?.app_mode, backend)
}

/// Read-only policy check for an already-admitted console user during sudo
/// saved-profile execution. `expected_uid` must come from admission (/dev/console),
/// never from the caller-selected data directory's ownership.
pub fn ensure_start_allowed_for_user(
    root: &Path,
    backend: TunnelBackend,
    expected_uid: u32,
) -> Result<(), String> {
    check_start_mode(
        SettingsStore::new(root)
            .load_for_user(expected_uid)?
            .app_mode,
        backend,
    )
}

fn check_start_mode(mode: AppMode, backend: TunnelBackend) -> Result<(), String> {
    if mode.allows_start(backend) {
        Ok(())
    } else {
        Err(
            "Orchestrator mode allows static routes only; change app mode to start managed tunnels"
                .into(),
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsDocument {
    version: u32,
    app_mode: AppMode,
    #[serde(default)]
    legacy_imported: bool,
}

impl SettingsDocument {
    fn settings(&self) -> AppSettings {
        AppSettings {
            app_mode: self.app_mode,
        }
    }
}

pub struct SettingsStore {
    root: PathBuf,
}

impl SettingsStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<AppSettings, String> {
        let Some(root) = crate::macos_transaction::canonical_root(&self.root, false)? else {
            return Ok(AppSettings::default());
        };
        read_document(&root).map(|doc| doc.map(|doc| doc.settings()).unwrap_or_default())
    }

    /// Ownership-aware read for admitted sudo execution. This never creates a
    /// root, operation lock, migration marker, or file and cannot repair modes.
    pub fn load_for_user(&self, expected_uid: u32) -> Result<AppSettings, String> {
        let Some(root) =
            crate::macos_transaction::canonical_root_for_user(&self.root, expected_uid)?
        else {
            return Ok(AppSettings::default());
        };
        read_document_for_user(&root, expected_uid)
            .map(|doc| doc.map(|doc| doc.settings()).unwrap_or_default())
    }

    pub fn set_app_mode(&self, mode: AppMode) -> Result<AppSettings, String> {
        crate::macos_transaction::with_root_lock(&self.root, || {
            let root = writable_root(&self.root)?;
            let previous = read_document(&root)?;
            let document = SettingsDocument {
                version: 1,
                app_mode: mode,
                legacy_imported: previous.is_some_and(|doc| doc.legacy_imported),
            };
            write_document(&root, &document)?;
            Ok(document.settings())
        })
    }

    /// Insert-only import of UserDefaults `appMode`, not UI-only preferences.
    /// Existence of any valid shared document wins, even before its import marker.
    pub fn import_legacy_app_mode(
        &self,
        production_root: &Path,
        value: Option<&str>,
    ) -> Result<LegacyImportOutcome, String> {
        let root = crate::macos_transaction::canonical_root(&self.root, false)?;
        let production = crate::macos_transaction::canonical_root(production_root, false)?;
        let is_production = match (&root, &production) {
            (Some(root), Some(production)) => root == production,
            (None, None) => self.root == production_root,
            _ => false,
        };
        if !is_production {
            return Ok(LegacyImportOutcome {
                settings: self.load()?,
                imported: false,
            });
        }
        crate::macos_transaction::with_root_lock(&self.root, || {
            let root = writable_root(&self.root)?;
            let previous = read_document(&root)?;
            let imported = previous.is_none();
            let mut document = previous.unwrap_or_else(|| SettingsDocument {
                version: 1,
                app_mode: AppMode::legacy(value),
                legacy_imported: false,
            });
            if !document.legacy_imported {
                document.legacy_imported = true;
                write_document(&root, &document)?;
            }
            Ok(LegacyImportOutcome {
                settings: document.settings(),
                imported,
            })
        })
    }
}

fn writable_root(root: &Path) -> Result<PathBuf, String> {
    crate::macos_transaction::canonical_root(root, false)?
        .ok_or_else(|| "Shared settings root is unavailable".into())
}

fn invalid_settings() -> String {
    "Shared macOS settings are invalid or not private; restore a valid owner-only settings file before starting connections".into()
}

fn read_document(root: &Path) -> Result<Option<SettingsDocument>, String> {
    read_document_for_user(root, unsafe { libc::geteuid() })
}

fn read_document_for_user(
    root: &Path,
    expected_uid: u32,
) -> Result<Option<SettingsDocument>, String> {
    let directory = File::open(root).map_err(|_| invalid_settings())?;
    reject_writable_acl(&directory)?;
    let path = root.join(SETTINGS_FILE);
    let before = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_settings()),
    };
    let private = |metadata: &fs::Metadata| {
        metadata.is_file()
            && metadata.uid() == expected_uid
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.len() <= MAX_SETTINGS_BYTES
    };
    if !before.file_type().is_file() || !private(&before) {
        return Err(invalid_settings());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| invalid_settings())?;
    let opened = file.metadata().map_err(|_| invalid_settings())?;
    if !private(&opened) || before.ino() != opened.ino() || before.dev() != opened.dev() {
        return Err(invalid_settings());
    }
    check_acl(&file)?;
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_SETTINGS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_settings())?;
    if bytes.len() as u64 > MAX_SETTINGS_BYTES {
        return Err(invalid_settings());
    }
    let document: SettingsDocument =
        serde_json::from_slice(&bytes).map_err(|_| invalid_settings())?;
    if document.version != 1 {
        return Err(invalid_settings());
    }
    Ok(Some(document))
}

fn write_document(root: &Path, document: &SettingsDocument) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(document).map_err(|_| invalid_settings())?;
    let temporary = root.join(format!(
        ".macos-settings-{}-{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| "Cannot create private shared settings".to_string())?;
    let result = (|| {
        clear_inherited_acl(&file)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "Cannot protect shared settings".to_string())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "Cannot write shared settings".to_string())?;
        fs::rename(&temporary, root.join(SETTINGS_FILE))
            .map_err(|_| "Cannot replace shared settings".to_string())?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "Shared settings were replaced but directory sync failed".to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(target_os = "macos")]
mod acl {
    use std::ffi::c_void;
    unsafe extern "C" {
        pub fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
        pub fn acl_get_entry(
            acl: *mut c_void,
            entry_id: libc::c_int,
            entry: *mut *mut c_void,
        ) -> libc::c_int;
        pub fn acl_free(object: *mut c_void) -> libc::c_int;
        pub fn acl_init(count: libc::c_int) -> *mut c_void;
        pub fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, kind: libc::c_int) -> libc::c_int;
        pub fn acl_valid(acl: *mut c_void) -> libc::c_int;
        pub fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
        pub fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> libc::c_int;
    }
    pub const EXTENDED: libc::c_int = 0x100;
}

#[cfg(any(target_os = "macos", test))]
fn acl_entry_allows_mutation(tag: i32, permissions: u64) -> bool {
    // Darwin sys/acl.h: data/add-file, delete, append/add-directory,
    // delete-child, write attributes/xattrs/security, and change-owner.
    const MUTATION: u64 =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);
    tag == 1 && permissions & MUTATION != 0
}

/// Coordination paths may have harmless deny-delete/read-only ACL entries.
/// Reject every allow-mutation ACE (conservatively, regardless of qualifier).
/// Linux POSIX ACL effective grants are already bounded by checked mode bits.
pub(crate) fn reject_writable_acl(file: &File) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    unsafe {
        let list = acl::acl_get_fd_np(file.as_raw_fd(), acl::EXTENDED);
        if list.is_null() {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOENT | libc::ENOTSUP) => Ok(()),
                _ => Err("Cannot inspect data-directory access permissions".into()),
            };
        }
        let result = (|| {
            if acl::acl_valid(list) != 0 {
                return Err("Invalid data-directory access permissions".into());
            }
            for index in 0..=128 {
                let mut entry = std::ptr::null_mut();
                if acl::acl_get_entry(list, index, &mut entry) != 0 {
                    return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                        Ok(())
                    } else {
                        Err("Cannot inspect data-directory access permissions".into())
                    };
                }
                let mut tag = 0;
                let mut permissions = 0;
                if index == 128
                    || acl::acl_get_tag_type(entry, &mut tag) != 0
                    || acl::acl_get_permset_mask_np(entry, &mut permissions) != 0
                    || !matches!(tag, 1 | 2)
                {
                    return Err("Invalid data-directory access permissions".into());
                }
                if acl_entry_allows_mutation(tag, permissions) {
                    return Err("The data directory or coordination file has unsafe writable access permissions".into());
                }
            }
            Err("Too many data-directory access permissions".into())
        })();
        acl::acl_free(list);
        result
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = file;
        Ok(())
    }
}

fn check_acl(file: &File) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    unsafe {
        let list = acl::acl_get_fd_np(file.as_raw_fd(), acl::EXTENDED);
        if list.is_null() {
            // With a valid open descriptor ENOENT means no ACL property;
            // unsupported filesystems enforce the checked POSIX mode instead.
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOENT | libc::ENOTSUP) => Ok(()),
                _ => Err(invalid_settings()),
            };
        }
        let mut entry = std::ptr::null_mut();
        let has_entry = acl::acl_get_entry(list, 0, &mut entry) == 0;
        acl::acl_free(list);
        if has_entry {
            return Err(invalid_settings());
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = file;
    Ok(())
}

fn clear_inherited_acl(file: &File) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    unsafe {
        // Darwin's acl_delete_fd_np is an ENOTSUP stub; install an empty ACL.
        let empty = acl::acl_init(0);
        if empty.is_null() {
            return Err("Cannot allocate protected settings access permissions".into());
        }
        let result = acl::acl_set_fd_np(file.as_raw_fd(), empty, acl::EXTENDED);
        let error = std::io::Error::last_os_error();
        acl::acl_free(empty);
        if result != 0 && error.raw_os_error() != Some(libc::ENOTSUP) {
            return Err("Cannot remove inherited access permissions from shared settings".into());
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = file;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn legacy_import_is_once_insert_only_and_root_scoped() {
        let a = root();
        let b = root();
        let first = SettingsStore::new(a.path());
        let second = SettingsStore::new(b.path());
        assert_eq!(first.load().unwrap().app_mode, AppMode::Combined);
        assert!(!a.path().join(SETTINGS_FILE).exists());
        assert!(
            first
                .import_legacy_app_mode(a.path(), Some("orchestrator"))
                .unwrap()
                .imported
        );
        assert_eq!(first.load().unwrap().app_mode, AppMode::Orchestrator);
        first.set_app_mode(AppMode::Manager).unwrap();
        let again = first
            .import_legacy_app_mode(a.path(), Some("orchestrator"))
            .unwrap();
        assert!(!again.imported);
        assert_eq!(again.settings.app_mode, AppMode::Manager);
        assert_eq!(second.load().unwrap().app_mode, AppMode::Combined);
        second.set_app_mode(AppMode::Orchestrator).unwrap();
        assert!(
            !second
                .import_legacy_app_mode(b.path(), Some("manager"))
                .unwrap()
                .imported
        );
        assert_eq!(second.load().unwrap().app_mode, AppMode::Orchestrator);
    }

    #[test]
    fn unknown_legacy_mode_defaults_combined() {
        let dir = root();
        let store = SettingsStore::new(dir.path());
        assert_eq!(
            store
                .import_legacy_app_mode(dir.path(), Some("future-mode"))
                .unwrap()
                .settings
                .app_mode,
            AppMode::Combined
        );
        assert!(
            !store
                .import_legacy_app_mode(dir.path(), Some("orchestrator"))
                .unwrap()
                .imported
        );
    }

    #[test]
    fn custom_root_never_imports_production_preferences_or_creates_state() {
        let production = root();
        let custom = root();
        let store = SettingsStore::new(custom.path());
        let outcome = store
            .import_legacy_app_mode(production.path(), Some("orchestrator"))
            .unwrap();
        assert!(!outcome.imported);
        assert_eq!(outcome.settings.app_mode, AppMode::Combined);
        assert!(!custom.path().join(SETTINGS_FILE).exists());
        assert!(!custom.path().join(".operation.lock").exists());
        assert!(!production.path().join(SETTINGS_FILE).exists());
    }

    #[test]
    fn corrupt_oversized_or_unprotected_settings_never_unlock_mode() {
        let dir = root();
        let store = SettingsStore::new(dir.path());
        store.set_app_mode(AppMode::Orchestrator).unwrap();
        let path = dir.path().join(SETTINGS_FILE);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for body in [
            b"not-json".to_vec(),
            vec![b' '; MAX_SETTINGS_BYTES as usize + 1],
            br#"{"version":9,"appMode":"combined"}"#.to_vec(),
            br#"{"version":1,"appMode":"unknown"}"#.to_vec(),
        ] {
            std::fs::write(&path, body).unwrap();
            assert!(store.load().is_err());
            assert!(ensure_start_allowed(dir.path(), TunnelBackend::Xray).is_err());
            assert!(store.set_app_mode(AppMode::Combined).is_err());
        }
        std::fs::remove_file(&path).unwrap();
        symlink(dir.path().join("elsewhere"), &path).unwrap();
        assert!(store.load().is_err());
        assert!(store.set_app_mode(AppMode::Combined).is_err());
    }

    #[test]
    fn broad_permissions_hardlinks_and_unsafe_roots_are_rejected() {
        let dir = root();
        let store = SettingsStore::new(dir.path());
        store.set_app_mode(AppMode::Orchestrator).unwrap();
        let path = dir.path().join(SETTINGS_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, dir.path().join("alias")).unwrap();
        assert!(store.load().is_err());
        let alias = dir.path().join("linked-root");
        symlink(dir.path(), &alias).unwrap();
        assert!(SettingsStore::new(alias).load().is_err());
        assert!(SettingsStore::new(dir.path().join("../escape"))
            .load()
            .is_err());
    }

    #[test]
    fn policy_preserves_helper_gates_and_blocks_only_managed_starts() {
        let available = StartAvailability {
            proxy_connections: true,
            helper_serves: true,
        };
        for mode in [AppMode::Combined, AppMode::Manager] {
            for backend in [
                TunnelBackend::Xray,
                TunnelBackend::WireGuard,
                TunnelBackend::OpenVpn,
                TunnelBackend::None,
            ] {
                assert!(start_eligibility(mode, backend, XrayMode::Socks, available).can_start);
            }
        }
        for backend in [
            TunnelBackend::Xray,
            TunnelBackend::WireGuard,
            TunnelBackend::OpenVpn,
        ] {
            let result =
                start_eligibility(AppMode::Orchestrator, backend, XrayMode::Socks, available);
            assert!(result.mode_blocked);
            assert!(!result.can_start && !result.can_try_start);
        }
        assert!(
            start_eligibility(
                AppMode::Orchestrator,
                TunnelBackend::None,
                XrayMode::Socks,
                available
            )
            .can_start
        );
        let no_helper = StartAvailability {
            helper_serves: false,
            ..available
        };
        assert!(
            start_eligibility(
                AppMode::Combined,
                TunnelBackend::Xray,
                XrayMode::Socks,
                no_helper
            )
            .can_start
        );
        let tun = start_eligibility(
            AppMode::Combined,
            TunnelBackend::Xray,
            XrayMode::Tun,
            no_helper,
        );
        assert!(!tun.can_start && tun.can_try_start);
        let unavailable = StartAvailability {
            proxy_connections: false,
            ..available
        };
        assert!(
            !start_eligibility(
                AppMode::Combined,
                TunnelBackend::None,
                XrayMode::Socks,
                unavailable
            )
            .can_try_start
        );
    }

    #[test]
    fn darwin_acl_policy_accepts_deny_and_read_only_but_rejects_mutation_grants() {
        assert!(!acl_entry_allows_mutation(2, u64::MAX));
        for permission in [1 << 1, 1 << 3, 1 << 7, 1 << 9, 1 << 11, 1 << 20] {
            assert!(!acl_entry_allows_mutation(1, permission));
        }
        for permission in [
            1 << 2,
            1 << 4,
            1 << 5,
            1 << 6,
            1 << 8,
            1 << 10,
            1 << 12,
            1 << 13,
        ] {
            assert!(acl_entry_allows_mutation(1, permission));
        }
    }

    #[test]
    fn admitted_user_policy_read_enforces_mode_without_writing_or_repairing() {
        let dir = root();
        let uid = unsafe { libc::getuid() };
        let path = dir.path().join(SETTINGS_FILE);
        std::fs::write(&path, br#"{"version":1,"appMode":"orchestrator"}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::read(&path).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let store = SettingsStore::new(dir.path());
        assert_eq!(
            store.load_for_user(uid).unwrap().app_mode,
            AppMode::Orchestrator
        );
        assert!(ensure_start_allowed_for_user(dir.path(), TunnelBackend::Xray, uid).is_err());
        assert!(ensure_start_allowed_for_user(dir.path(), TunnelBackend::None, uid).is_ok());
        assert!(store.load_for_user(0).is_err());
        assert!(store.load_for_user(uid.wrapping_add(1)).is_err());
        assert!(read_document_for_user(dir.path(), uid.wrapping_add(1)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), metadata.ino());
        assert_eq!(std::fs::metadata(&path).unwrap().mode(), metadata.mode());
        assert!(!dir.path().join(".operation.lock").exists());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load_for_user(uid).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn admitted_user_missing_policy_read_never_creates_state() {
        let dir = root();
        let uid = unsafe { libc::getuid() };
        let missing = dir.path().join("not-created");
        assert_eq!(
            SettingsStore::new(&missing).load_for_user(uid).unwrap(),
            AppSettings::default()
        );
        ensure_start_allowed_for_user(&missing, TunnelBackend::Xray, uid).unwrap();
        assert!(!missing.exists());
        assert!(!dir.path().join(".operation.lock").exists());
    }
}
