//! Remembered OpenVPN credentials: the desktop Secret Service (GNOME
//! Keyring / KWallet) keyed by profile id, or process memory when no keyring
//! is available. Never plaintext on disk; older plaintext files are migrated.

use net_manager_core::daemon_protocol::OpenVpnCredentials;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Mutex;

/// Minimal keyring backend. `ErrorKind::NotConnected` means "no keyring".
pub trait SecretStore: Send + Sync {
    fn load(&self, profile_id: &str) -> io::Result<Option<Vec<u8>>>;
    fn save(&self, profile_id: &str, secret: &[u8]) -> io::Result<()>;
    fn delete(&self, profile_id: &str) -> io::Result<()>;
}

pub const SESSION_ONLY_NOTICE: &str =
    "System keyring is unavailable; OpenVPN credentials are remembered only until the app exits";
pub const MIGRATED_SESSION_ONLY_NOTICE: &str =
    "Old plaintext OpenVPN credentials were removed; the system keyring is unavailable, so they are kept only until the app exits";

pub struct OpenVpnCredentialStore {
    keyring: Box<dyn SecretStore>,
    session: Mutex<HashMap<String, OpenVpnCredentials>>,
}

impl OpenVpnCredentialStore {
    pub fn new(keyring: Box<dyn SecretStore>) -> Self {
        Self {
            keyring,
            session: Mutex::new(HashMap::new()),
        }
    }

    /// Remembered credentials plus an optional user notice. `legacy` is the
    /// old plaintext file, migrated and deleted on first access.
    pub fn load(
        &self,
        profile_id: &str,
        legacy: &Path,
    ) -> Result<(Option<OpenVpnCredentials>, Option<&'static str>), String> {
        if let Some(credentials) = self.session.lock().unwrap().get(profile_id) {
            return Ok((Some(credentials.clone()), None));
        }
        let keyring = self.keyring.load(profile_id);
        if let Ok(Some(bytes)) = keyring {
            let _ = remove_legacy_file(legacy);
            return decode(&bytes)
                .map(|credentials| (Some(credentials), None))
                .ok_or_else(|| "remembered OpenVPN credentials unavailable".to_string());
        }
        // Read the old plaintext file once, then delete it whatever its state.
        let migrated = read_legacy_file(legacy).ok().flatten();
        remove_legacy_file(legacy)
            .map_err(|_| "cannot remove plaintext OpenVPN credentials".to_string())?;
        let Some(credentials) = migrated else {
            return Ok((None, None));
        };
        let saved = keyring.is_ok()
            && serde_json::to_vec(&credentials)
                .is_ok_and(|bytes| self.keyring.save(profile_id, &bytes).is_ok());
        if saved {
            return Ok((Some(credentials), None));
        }
        self.session
            .lock()
            .unwrap()
            .insert(profile_id.to_string(), credentials.clone());
        Ok((Some(credentials), Some(MIGRATED_SESSION_ONLY_NOTICE)))
    }

    /// Stores credentials in the keyring, or for this session only.
    pub fn remember(
        &self,
        profile_id: &str,
        credentials: &OpenVpnCredentials,
    ) -> Option<&'static str> {
        let saved = serde_json::to_vec(credentials)
            .is_ok_and(|bytes| self.keyring.save(profile_id, &bytes).is_ok());
        let mut session = self.session.lock().unwrap();
        if saved {
            session.remove(profile_id);
            None
        } else {
            session.insert(profile_id.to_string(), credentials.clone());
            Some(SESSION_ONLY_NOTICE)
        }
    }

    /// Clears local credentials, then confirms keyring deletion or reports failure.
    pub fn forget(&self, profile_id: &str, legacy: Option<&Path>) -> Result<(), String> {
        self.session.lock().unwrap().remove(profile_id);
        let failed = |_| "cannot remove remembered OpenVPN credentials".to_string();
        if let Some(legacy) = legacy {
            remove_legacy_file(legacy).map_err(failed)?;
        }
        match self.keyring.delete(profile_id) {
            Err(err) if err.kind() == io::ErrorKind::NotConnected => Err(
                "cannot remove remembered OpenVPN credentials: secret service unavailable".into(),
            ),
            Err(err) => Err(failed(err)),
            Ok(()) => Ok(()),
        }
    }
}

fn decode(bytes: &[u8]) -> Option<OpenVpnCredentials> {
    let credentials: OpenVpnCredentials = serde_json::from_slice(bytes).ok()?;
    net_manager_core::openvpn_management::validate_openvpn_credentials(&credentials).ok()?;
    Some(credentials)
}

fn remove_legacy_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Reads the pre-keyring plaintext file only if it is a private regular
/// file owned by this user.
fn read_legacy_file(path: &Path) -> io::Result<Option<OpenVpnCredentials>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    const MAX_BYTES: u64 = 16 * 1024;
    let invalid = || io::Error::from(io::ErrorKind::InvalidData);
    let private = |metadata: &std::fs::Metadata| {
        metadata.file_type().is_file()
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.len() <= MAX_BYTES
    };
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if !private(&metadata) {
        return Err(invalid());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    if !private(&opened) || opened.ino() != metadata.ino() || opened.dev() != metadata.dev() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid());
    }
    decode(&bytes).map(Some).ok_or_else(invalid)
}

/// Freedesktop Secret Service over the session D-Bus, with an encrypted
/// (Diffie-Hellman) transfer session. Calls block; unlock prompts time out.
pub struct SecretServiceStore;

impl SecretServiceStore {
    const PROMPT_TIMEOUT_SECS: u64 = 60;

    fn connect() -> io::Result<dbus_secret_service::SecretService> {
        dbus_secret_service::SecretService::connect_with_max_prompt_timeout(
            dbus_secret_service::EncryptionType::Dh,
            Self::PROMPT_TIMEOUT_SECS,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "secret service unavailable"))
    }

    fn attributes(profile_id: &str) -> HashMap<&str, &str> {
        HashMap::from([
            ("application", "network-orchestrator"),
            ("kind", "openvpn-credentials"),
            ("profile-id", profile_id),
        ])
    }
}

fn keyring_error(_: dbus_secret_service::Error) -> io::Error {
    io::Error::other("secret service request failed")
}

/// Secret Service calls block on D-Bus, up to a minute while an unlock prompt
/// is open; keep other async tasks running on the multi-thread runtime.
fn blocking<T>(call: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(call)
        }
        _ => call(),
    }
}

impl SecretStore for SecretServiceStore {
    fn load(&self, profile_id: &str) -> io::Result<Option<Vec<u8>>> {
        blocking(|| Self::load_blocking(profile_id))
    }

    fn save(&self, profile_id: &str, secret: &[u8]) -> io::Result<()> {
        blocking(|| Self::save_blocking(profile_id, secret))
    }

    fn delete(&self, profile_id: &str) -> io::Result<()> {
        blocking(|| Self::delete_blocking(profile_id))
    }
}

impl SecretServiceStore {
    fn load_blocking(profile_id: &str) -> io::Result<Option<Vec<u8>>> {
        let service = Self::connect()?;
        let found = service
            .search_items(Self::attributes(profile_id))
            .map_err(keyring_error)?;
        let Some(item) = found.unlocked.first().or(found.locked.first()) else {
            return Ok(None);
        };
        item.ensure_unlocked().map_err(keyring_error)?;
        item.get_secret().map(Some).map_err(keyring_error)
    }

    fn save_blocking(profile_id: &str, secret: &[u8]) -> io::Result<()> {
        let service = Self::connect()?;
        let collection = service.get_default_collection().map_err(keyring_error)?;
        collection.ensure_unlocked().map_err(keyring_error)?;
        collection
            .create_item(
                &format!("Network Orchestrator OpenVPN credentials ({profile_id})"),
                Self::attributes(profile_id),
                secret,
                true,
                "application/json",
            )
            .map(|_| ())
            .map_err(keyring_error)
    }

    fn delete_blocking(profile_id: &str) -> io::Result<()> {
        let service = Self::connect()?;
        let found = service
            .search_items(Self::attributes(profile_id))
            .map_err(keyring_error)?;
        for item in found.unlocked.iter().chain(found.locked.iter()) {
            item.ensure_unlocked().map_err(keyring_error)?;
            item.delete().map_err(keyring_error)?;
        }
        Ok(())
    }
}

impl crate::linux::CredentialSource for OpenVpnCredentialStore {
    fn load(
        &self,
        profile_id: &str,
        legacy: &Path,
    ) -> Result<(Option<OpenVpnCredentials>, Option<&'static str>), String> {
        OpenVpnCredentialStore::load(self, profile_id, legacy)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn unique_dir(name: &str) -> std::path::PathBuf {
        let directory = tempfile::Builder::new().prefix(name).tempdir().unwrap();
        directory.keep()
    }
    use net_manager_core::daemon_protocol::OpenVpnUserPass;
    use std::os::unix::fs::OpenOptionsExt;

    /// In-memory keyring; `unavailable` behaves like no Secret Service.
    #[derive(Default)]
    pub(crate) struct FakeKeyring {
        pub(crate) unavailable: bool,
        pub(crate) entries: std::sync::Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl SecretStore for FakeKeyring {
        fn load(&self, profile_id: &str) -> io::Result<Option<Vec<u8>>> {
            if self.unavailable {
                return Err(io::ErrorKind::NotConnected.into());
            }
            Ok(self.entries.lock().unwrap().get(profile_id).cloned())
        }
        fn save(&self, profile_id: &str, secret: &[u8]) -> io::Result<()> {
            if self.unavailable {
                return Err(io::ErrorKind::NotConnected.into());
            }
            self.entries
                .lock()
                .unwrap()
                .insert(profile_id.into(), secret.to_vec());
            Ok(())
        }
        fn delete(&self, profile_id: &str) -> io::Result<()> {
            if self.unavailable {
                return Err(io::ErrorKind::NotConnected.into());
            }
            self.entries.lock().unwrap().remove(profile_id);
            Ok(())
        }
    }

    fn credentials() -> OpenVpnCredentials {
        OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "private-user".into(),
                password: "private-password".into(),
            }),
            private_key_passphrase: None,
        }
    }

    fn write_legacy(path: &Path, credentials: &OpenVpnCredentials) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&serde_json::to_vec(credentials).unwrap())
            .unwrap();
    }

    fn store(keyring: FakeKeyring) -> OpenVpnCredentialStore {
        OpenVpnCredentialStore::new(Box::new(keyring))
    }

    #[test]
    fn remember_writes_keyring_only_and_load_reads_it() {
        let dir = unique_dir("ovpn-keyring");
        let legacy = dir.join("openvpn-credentials.json");
        let keyring = FakeKeyring::default();
        let entries = keyring.entries.clone();
        let credentials = credentials();

        assert_eq!(store(keyring).remember("p1", &credentials), None);
        assert!(entries.lock().unwrap().contains_key("p1"));
        assert!(!legacy.exists());

        // A fresh store (app restart) still finds the keyring entry.
        let restarted = store(FakeKeyring {
            unavailable: false,
            entries: entries.clone(),
        });
        assert_eq!(
            restarted.load("p1", &legacy).unwrap(),
            (Some(credentials), None)
        );
        assert_eq!(restarted.load("p2", &legacy).unwrap(), (None, None));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn remember_without_keyring_is_session_only_and_never_touches_disk() {
        let dir = unique_dir("ovpn-session-only");
        let legacy = dir.join("openvpn-credentials.json");
        let session = store(FakeKeyring {
            unavailable: true,
            ..Default::default()
        });
        let credentials = credentials();

        let notice = session.remember("p1", &credentials).unwrap();
        assert_eq!(notice, SESSION_ONLY_NOTICE);
        assert!(!notice.contains("private"));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(
            session.load("p1", &legacy).unwrap(),
            (Some(credentials), None)
        );

        let restarted = store(FakeKeyring {
            unavailable: true,
            ..Default::default()
        });
        assert_eq!(restarted.load("p1", &legacy).unwrap(), (None, None));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_plaintext_file_moves_into_keyring_and_is_deleted() {
        let dir = unique_dir("ovpn-migrate");
        let legacy = dir.join("openvpn-credentials.json");
        let credentials = credentials();
        write_legacy(&legacy, &credentials);
        let keyring = FakeKeyring::default();
        let entries = keyring.entries.clone();

        let loaded = store(keyring).load("p1", &legacy).unwrap();

        assert_eq!(loaded, (Some(credentials.clone()), None));
        assert!(!legacy.exists());
        let saved: OpenVpnCredentials =
            serde_json::from_slice(&entries.lock().unwrap()["p1"]).unwrap();
        assert_eq!(saved, credentials);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_plaintext_file_is_deleted_when_keyring_is_unavailable() {
        let dir = unique_dir("ovpn-migrate-no-keyring");
        let legacy = dir.join("openvpn-credentials.json");
        let credentials = credentials();
        write_legacy(&legacy, &credentials);
        let session = store(FakeKeyring {
            unavailable: true,
            ..Default::default()
        });

        let loaded = session.load("p1", &legacy).unwrap();

        assert_eq!(
            loaded,
            (
                Some(credentials.clone()),
                Some(MIGRATED_SESSION_ONLY_NOTICE)
            )
        );
        assert!(!legacy.exists());
        assert_eq!(
            session.load("p1", &legacy).unwrap(),
            (Some(credentials), None)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn insecure_legacy_file_is_deleted_without_being_used() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("ovpn-legacy-insecure");
        let legacy = dir.join("openvpn-credentials.json");
        write_legacy(&legacy, &credentials());
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o644)).unwrap();
        let keyring = FakeKeyring::default();
        let entries = keyring.entries.clone();

        assert_eq!(store(keyring).load("p1", &legacy).unwrap(), (None, None));
        assert!(!legacy.exists());
        assert!(entries.lock().unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keyring_entry_wins_and_removes_stale_legacy_file() {
        let dir = unique_dir("ovpn-keyring-wins");
        let legacy = dir.join("openvpn-credentials.json");
        let mut old = credentials();
        old.auth_user_pass.as_mut().unwrap().password = "old-password".into();
        write_legacy(&legacy, &old);
        let keyring = FakeKeyring::default();
        let credentials = credentials();
        keyring
            .entries
            .lock()
            .unwrap()
            .insert("p1".into(), serde_json::to_vec(&credentials).unwrap());

        assert_eq!(
            store(keyring).load("p1", &legacy).unwrap(),
            (Some(credentials), None)
        );
        assert!(!legacy.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_keyring_entry_is_a_generic_error() {
        let dir = unique_dir("ovpn-keyring-corrupt");
        let keyring = FakeKeyring::default();
        keyring
            .entries
            .lock()
            .unwrap()
            .insert("p1".into(), b"{\"private-password\"".to_vec());

        let error = store(keyring)
            .load("p1", &dir.join("openvpn-credentials.json"))
            .unwrap_err();

        assert_eq!(error, "remembered OpenVPN credentials unavailable");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn forget_unavailable_keyring_reports_failure_after_local_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("openvpn-credentials.json");
        let keyring = FakeKeyring {
            unavailable: true,
            ..Default::default()
        };
        let entries = keyring.entries.clone();
        let persistent = serde_json::to_vec(&credentials()).unwrap();
        entries
            .lock()
            .unwrap()
            .insert("p1".into(), persistent.clone());
        let credentials_store = store(keyring);
        assert_eq!(
            credentials_store.remember("p1", &credentials()),
            Some(SESSION_ONLY_NOTICE)
        );
        write_legacy(&legacy, &credentials());

        let result = credentials_store.forget("p1", Some(&legacy));

        assert!(
            !legacy.exists(),
            "plaintext cleanup must not depend on keyring availability"
        );
        assert_eq!(
            credentials_store.load("p1", &legacy).unwrap(),
            (None, None),
            "a failed persistent deletion must still clear session credentials"
        );
        assert_eq!(
            entries.lock().unwrap().get("p1"),
            Some(&persistent),
            "the inaccessible persistent secret has not been confirmed deleted"
        );
        let error = result.expect_err("unavailable keyring cannot confirm persistent deletion");
        assert!(error.contains("unavailable"), "{error}");
        assert!(!error.contains("private-user"));
        assert!(!error.contains("private-password"));
        assert!(!error.contains(&legacy.to_string_lossy().to_string()));
    }

    #[test]
    fn forget_clears_session_keyring_and_legacy_file() {
        let dir = unique_dir("ovpn-forget");
        let legacy = dir.join("openvpn-credentials.json");
        let keyring = FakeKeyring::default();
        let entries = keyring.entries.clone();
        let credentials_store = store(keyring);
        credentials_store.remember("p1", &credentials());
        credentials_store
            .session
            .lock()
            .unwrap()
            .insert("p1".into(), credentials());
        write_legacy(&legacy, &credentials());

        credentials_store.forget("p1", Some(&legacy)).unwrap();

        assert!(entries.lock().unwrap().is_empty());
        assert!(!legacy.exists());
        assert_eq!(credentials_store.load("p1", &legacy).unwrap(), (None, None));

        std::fs::remove_dir_all(dir).unwrap();
    }
}
