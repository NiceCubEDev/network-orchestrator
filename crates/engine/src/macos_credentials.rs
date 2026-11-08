//! OpenVPN credential policy, independent of either frontend.
//!
//! The default data root keeps the original Swift Keychain identity and payload;
//! no migration copy or second permanent store exists. Custom canonical roots
//! get a distinct service and never consult production credentials. Moving a
//! custom root deliberately requires entering credentials again.
use net_manager_core::daemon_protocol::{OpenVpnCredentials, OpenVpnUserPass};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

pub const KEYCHAIN_SERVICE: &str = "com.netmanager.app.macos.openvpn";
const MAX_SECRET_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequirements {
    pub user_pass: bool,
    pub key_passphrase: bool,
}

impl CredentialRequirements {
    pub fn any(self) -> bool {
        self.user_pass || self.key_passphrase
    }
}

pub fn requirements(config: &str, assets: &BTreeMap<String, Vec<u8>>) -> CredentialRequirements {
    let needs = net_manager_core::openvpn_config::credential_requirements(config, assets);
    CredentialRequirements {
        user_pass: needs.user_pass,
        key_passphrase: needs.key_passphrase,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStoreError {
    Locked,
    AccessDenied,
    Unavailable,
    InvalidData,
    OperationFailed,
}

/// Bytes cross only the OS secret-store boundary, never an app-data file.
pub trait SecretStore: Send + Sync {
    fn load(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, CredentialStoreError>;
    fn save(&self, service: &str, account: &str, secret: &[u8])
        -> Result<(), CredentialStoreError>;
    fn delete(&self, service: &str, account: &str) -> Result<(), CredentialStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialNotice {
    KeychainUnavailable,
    StoredCredentialsInvalid,
    RememberFailed,
    ForgetFailed,
}

impl CredentialNotice {
    pub fn message(self) -> &'static str {
        match self {
            Self::KeychainUnavailable => "Cannot read OpenVPN credentials from Keychain. Unlock the login Keychain or enter credentials for this connection.",
            Self::StoredCredentialsInvalid => "Remembered OpenVPN credentials are invalid. Enter credentials again or explicitly forget the saved item.",
            Self::RememberFailed => "Connected, but credentials were not remembered. Unlock the login Keychain and choose Remember on the next successful connection.",
            Self::ForgetFailed => "Cannot remove remembered OpenVPN credentials. Unlock the login Keychain and explicitly forget them again; rejected saved credentials will not be used for this attempt.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPrompt {
    pub needs: CredentialRequirements,
    pub rejected: bool,
    pub notice: Option<CredentialNotice>,
}

#[derive(Debug)]
pub enum CredentialResolution {
    Ready(CredentialAttempt),
    Required(CredentialPrompt),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    ConfirmedSuccess,
    AuthenticationRejected,
    Failed,
}

/// Safe public outcome: it cannot serialize credentials or account values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOutcome {
    pub remembered: bool,
    pub forgotten: bool,
    pub notice: Option<CredentialNotice>,
}

pub struct OpenVpnCredentialStore {
    backend: Arc<dyn SecretStore>,
    service: String,
}

impl OpenVpnCredentialStore {
    pub fn new(
        root: &Path,
        production_root: &Path,
        backend: Arc<dyn SecretStore>,
    ) -> Result<Self, String> {
        let root = crate::macos_transaction::canonical_root(root, false)?
            .ok_or_else(|| "OpenVPN credential data root does not exist".to_string())?;
        let production = crate::macos_transaction::canonical_root(production_root, false)?;
        let service = if production.as_deref() == Some(root.as_path()) {
            KEYCHAIN_SERVICE.into()
        } else {
            let hash = Sha256::digest(root.as_os_str().as_bytes());
            format!("{KEYCHAIN_SERVICE}.root.{hash:x}")
        };
        Ok(Self { backend, service })
    }

    pub fn native(root: &Path, production_root: &Path) -> Result<Self, String> {
        Self::new(root, production_root, Arc::new(NativeKeychain))
    }

    /// A rejected saved value is never retried, even when its deletion fails.
    /// Explicit user input takes precedence; only requested fields are retained.
    pub fn resolve(
        &self,
        profile_id: &str,
        needs: CredentialRequirements,
        supplied: Option<OpenVpnCredentials>,
        remember: bool,
        rejected: bool,
    ) -> Result<CredentialResolution, String> {
        validate_account(profile_id)?;
        let mut notice = None;
        if rejected && self.backend.delete(&self.service, profile_id).is_err() {
            notice = Some(CredentialNotice::ForgetFailed);
        }
        if !needs.any() {
            return Ok(CredentialResolution::Ready(
                self.attempt(profile_id, None, false, notice),
            ));
        }
        let supplied_input = supplied.is_some();
        let credentials = if supplied_input {
            supplied
        } else if rejected {
            None
        } else {
            match self.backend.load(&self.service, profile_id) {
                Ok(Some(bytes)) => match decode(&bytes) {
                    Ok(credentials) => Some(credentials),
                    Err(_) => {
                        notice = Some(CredentialNotice::StoredCredentialsInvalid);
                        None
                    }
                },
                Ok(None) => None,
                Err(_) => {
                    notice = Some(CredentialNotice::KeychainUnavailable);
                    None
                }
            }
        };
        let Some(credentials) = credentials.and_then(|credentials| select(credentials, needs))
        else {
            return Ok(CredentialResolution::Required(CredentialPrompt {
                needs,
                rejected,
                notice,
            }));
        };
        if net_manager_core::openvpn_management::validate_openvpn_credentials(&credentials).is_err()
        {
            if supplied_input {
                return Err("OpenVPN credentials contain invalid values; remove control characters and check field lengths".into());
            }
            return Ok(CredentialResolution::Required(CredentialPrompt {
                needs,
                rejected,
                notice: Some(CredentialNotice::StoredCredentialsInvalid),
            }));
        }
        Ok(CredentialResolution::Ready(self.attempt(
            profile_id,
            Some(credentials),
            supplied_input && remember,
            notice,
        )))
    }

    fn attempt(
        &self,
        account: &str,
        credentials: Option<OpenVpnCredentials>,
        remember: bool,
        notice: Option<CredentialNotice>,
    ) -> CredentialAttempt {
        CredentialAttempt {
            backend: self.backend.clone(),
            service: self.service.clone(),
            account: account.into(),
            credentials,
            remember,
            notice,
        }
    }

    /// Only explicit forget and authentication rejection delete credentials.
    /// Profile deletion deliberately does not invoke this method.
    pub fn forget(&self, profile_id: &str) -> Result<CredentialOutcome, String> {
        validate_account(profile_id)?;
        self.backend
            .delete(&self.service, profile_id)
            .map_err(|_| CredentialNotice::ForgetFailed.message().to_string())?;
        Ok(CredentialOutcome {
            forgotten: true,
            ..CredentialOutcome::default()
        })
    }
}

fn validate_account(account: &str) -> Result<(), String> {
    if account.is_empty() || account.len() > 256 || account.chars().any(char::is_control) {
        Err("Invalid OpenVPN credential profile identity".into())
    } else {
        Ok(())
    }
}

/// In-memory connection input, deliberately not Serialize or Clone. Dropping an
/// unconfirmed attempt cannot remember anything. Never put this in public DTOs.
#[must_use]
pub struct CredentialAttempt {
    backend: Arc<dyn SecretStore>,
    service: String,
    account: String,
    credentials: Option<OpenVpnCredentials>,
    remember: bool,
    notice: Option<CredentialNotice>,
}

impl fmt::Debug for CredentialAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialAttempt")
            .field("credentials", &"[REDACTED]")
            .field("remember", &self.remember)
            .field("notice", &self.notice)
            .finish()
    }
}

impl CredentialAttempt {
    pub fn credentials(&self) -> Option<&OpenVpnCredentials> {
        self.credentials.as_ref()
    }

    pub fn notice(&self) -> Option<CredentialNotice> {
        self.notice
    }

    /// The caller must confirm a running tunnel, not merely an accepted start
    /// request. No background task or Drop implementation can persist secrets.
    pub fn complete(self, completion: ConnectOutcome) -> CredentialOutcome {
        let mut outcome = CredentialOutcome {
            notice: self.notice,
            ..CredentialOutcome::default()
        };
        match completion {
            ConnectOutcome::AuthenticationRejected => {
                match self.backend.delete(&self.service, &self.account) {
                    Ok(()) => outcome.forgotten = true,
                    Err(_) => outcome.notice = Some(CredentialNotice::ForgetFailed),
                }
            }
            ConnectOutcome::ConfirmedSuccess if self.remember => {
                if let Some(credentials) = self.credentials.as_ref() {
                    let saved = encode(credentials)
                        .and_then(|bytes| self.backend.save(&self.service, &self.account, &bytes));
                    match saved {
                        Ok(()) => outcome.remembered = true,
                        Err(_) => outcome.notice = Some(CredentialNotice::RememberFailed),
                    }
                }
            }
            ConnectOutcome::ConfirmedSuccess | ConnectOutcome::Failed => {}
        }
        outcome
    }
}

fn select(
    mut credentials: OpenVpnCredentials,
    needs: CredentialRequirements,
) -> Option<OpenVpnCredentials> {
    if !needs.user_pass {
        credentials.auth_user_pass = None;
    } else if !credentials
        .auth_user_pass
        .as_ref()
        .is_some_and(|auth| !auth.username.is_empty() && !auth.password.is_empty())
    {
        return None;
    }
    if !needs.key_passphrase {
        credentials.private_key_passphrase = None;
    } else if !credentials
        .private_key_passphrase
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return None;
    }
    Some(credentials)
}

// Keep the existing Swift payload, but only inside the Keychain boundary.
#[derive(Serialize, Deserialize)]
struct KeychainSecrets {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    passphrase: String,
}

fn decode(bytes: &[u8]) -> Result<OpenVpnCredentials, CredentialStoreError> {
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(CredentialStoreError::InvalidData);
    }
    let value: KeychainSecrets =
        serde_json::from_slice(bytes).map_err(|_| CredentialStoreError::InvalidData)?;
    Ok(OpenVpnCredentials {
        auth_user_pass: if value.username.is_empty() && value.password.is_empty() {
            None
        } else {
            Some(OpenVpnUserPass {
                username: value.username,
                password: value.password,
            })
        },
        private_key_passphrase: if value.passphrase.is_empty() {
            None
        } else {
            Some(value.passphrase)
        },
    })
}

fn encode(credentials: &OpenVpnCredentials) -> Result<Vec<u8>, CredentialStoreError> {
    // Serialize borrowed fields: no extra owned secret copies are needed.
    #[derive(Serialize)]
    struct Payload<'a> {
        username: &'a str,
        password: &'a str,
        passphrase: &'a str,
    }
    let (username, password) = credentials
        .auth_user_pass
        .as_ref()
        .map(|auth| (auth.username.as_str(), auth.password.as_str()))
        .unwrap_or_default();
    let payload = Payload {
        username,
        password,
        passphrase: credentials
            .private_key_passphrase
            .as_deref()
            .unwrap_or_default(),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| CredentialStoreError::InvalidData)?;
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(CredentialStoreError::InvalidData);
    }
    Ok(bytes)
}

pub struct NativeKeychain;

#[cfg(not(target_os = "macos"))]
impl SecretStore for NativeKeychain {
    fn load(&self, _: &str, _: &str) -> Result<Option<Vec<u8>>, CredentialStoreError> {
        Err(CredentialStoreError::Unavailable)
    }
    fn save(&self, _: &str, _: &str, _: &[u8]) -> Result<(), CredentialStoreError> {
        Err(CredentialStoreError::Unavailable)
    }
    fn delete(&self, _: &str, _: &str) -> Result<(), CredentialStoreError> {
        Err(CredentialStoreError::Unavailable)
    }
}

#[cfg(target_os = "macos")]
#[path = "macos_credentials_keychain.rs"]
mod keychain;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeSecrets {
        values: Mutex<HashMap<(String, String), Vec<u8>>>,
        fail: Mutex<bool>,
    }

    impl SecretStore for FakeSecrets {
        fn load(
            &self,
            service: &str,
            account: &str,
        ) -> Result<Option<Vec<u8>>, CredentialStoreError> {
            if *self.fail.lock().unwrap() {
                return Err(CredentialStoreError::Locked);
            }
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(&(service.into(), account.into()))
                .cloned())
        }
        fn save(
            &self,
            service: &str,
            account: &str,
            bytes: &[u8],
        ) -> Result<(), CredentialStoreError> {
            if *self.fail.lock().unwrap() {
                return Err(CredentialStoreError::Locked);
            }
            self.values
                .lock()
                .unwrap()
                .insert((service.into(), account.into()), bytes.to_vec());
            Ok(())
        }
        fn delete(&self, service: &str, account: &str) -> Result<(), CredentialStoreError> {
            if *self.fail.lock().unwrap() {
                return Err(CredentialStoreError::Locked);
            }
            self.values
                .lock()
                .unwrap()
                .remove(&(service.into(), account.into()));
            Ok(())
        }
    }

    fn secrets() -> OpenVpnCredentials {
        OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "secret-user".into(),
                password: "secret-password".into(),
            }),
            private_key_passphrase: Some("secret-passphrase".into()),
        }
    }

    fn ready(resolution: CredentialResolution) -> CredentialAttempt {
        match resolution {
            CredentialResolution::Ready(attempt) => attempt,
            CredentialResolution::Required(_) => panic!("unexpected credential request"),
        }
    }

    #[test]
    fn requirements_and_selection_do_not_send_unneeded_fields() {
        let needs = requirements("auth-user-pass\n", &BTreeMap::new());
        assert_eq!(
            needs,
            CredentialRequirements {
                user_pass: true,
                key_passphrase: false
            }
        );
        let root = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeSecrets::default());
        let store = OpenVpnCredentialStore::new(root.path(), root.path(), backend).unwrap();
        let attempt = ready(
            store
                .resolve("profile", needs, Some(secrets()), false, false)
                .unwrap(),
        );
        assert!(attempt
            .credentials()
            .unwrap()
            .private_key_passphrase
            .is_none());
        assert!(!format!("{attempt:?}").contains("secret-password"));
        assert!(
            !attempt
                .complete(ConnectOutcome::ConfirmedSuccess)
                .remembered
        );
        assert!(matches!(
            store.resolve("profile", needs, None, false, false).unwrap(),
            CredentialResolution::Required(_)
        ));
    }

    #[test]
    fn remembers_only_confirmed_success_never_failure_or_drop() {
        let root = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeSecrets::default());
        let store = OpenVpnCredentialStore::new(root.path(), root.path(), backend.clone()).unwrap();
        let needs = CredentialRequirements {
            user_pass: true,
            key_passphrase: true,
        };
        let attempt = ready(
            store
                .resolve("profile", needs, Some(secrets()), true, false)
                .unwrap(),
        );
        drop(attempt);
        assert!(backend.values.lock().unwrap().is_empty());
        let outcome = ready(
            store
                .resolve("profile", needs, Some(secrets()), true, false)
                .unwrap(),
        )
        .complete(ConnectOutcome::Failed);
        assert!(!outcome.remembered);
        assert!(backend.values.lock().unwrap().is_empty());
        let outcome = ready(
            store
                .resolve("profile", needs, Some(secrets()), true, false)
                .unwrap(),
        )
        .complete(ConnectOutcome::ConfirmedSuccess);
        assert!(outcome.remembered);
        let encoded = serde_json::to_string(&outcome).unwrap();
        assert!(!encoded.contains("secret-"));
        assert!(matches!(
            store.resolve("profile", needs, None, false, false).unwrap(),
            CredentialResolution::Ready(_)
        ));
        assert!(store.forget("profile").unwrap().forgotten);
        assert!(backend.values.lock().unwrap().is_empty());
    }

    #[test]
    fn root_isolation_and_legacy_production_identity_are_preserved() {
        let production = tempfile::tempdir().unwrap();
        let custom = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeSecrets::default());
        backend.values.lock().unwrap().insert(
            (KEYCHAIN_SERVICE.into(), "profile".into()),
            br#"{"username":"legacy-user","password":"legacy-password","passphrase":""}"#.to_vec(),
        );
        let prod =
            OpenVpnCredentialStore::new(production.path(), production.path(), backend.clone())
                .unwrap();
        let other =
            OpenVpnCredentialStore::new(custom.path(), production.path(), backend.clone()).unwrap();
        let needs = CredentialRequirements {
            user_pass: true,
            key_passphrase: false,
        };
        let saved = ready(prod.resolve("profile", needs, None, false, false).unwrap());
        assert_eq!(
            saved
                .credentials()
                .unwrap()
                .auth_user_pass
                .as_ref()
                .unwrap()
                .username,
            "legacy-user"
        );
        assert!(matches!(
            other.resolve("profile", needs, None, false, false).unwrap(),
            CredentialResolution::Required(_)
        ));
        ready(
            other
                .resolve("profile", needs, Some(secrets()), true, false)
                .unwrap(),
        )
        .complete(ConnectOutcome::ConfirmedSuccess);
        other.forget("profile").unwrap();
        assert_eq!(backend.values.lock().unwrap().len(), 1);
        assert!(matches!(
            prod.resolve("profile", needs, None, false, false).unwrap(),
            CredentialResolution::Ready(_)
        ));
    }

    #[test]
    fn rejected_auth_forgets_and_never_retries_stored_values() {
        let root = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeSecrets::default());
        let store = OpenVpnCredentialStore::new(root.path(), root.path(), backend.clone()).unwrap();
        let needs = CredentialRequirements {
            user_pass: true,
            key_passphrase: false,
        };
        ready(
            store
                .resolve("profile", needs, Some(secrets()), true, false)
                .unwrap(),
        )
        .complete(ConnectOutcome::ConfirmedSuccess);
        match store.resolve("profile", needs, None, false, true).unwrap() {
            CredentialResolution::Required(prompt) => assert!(prompt.rejected),
            CredentialResolution::Ready(_) => panic!("reused rejected credentials"),
        }
        assert!(backend.values.lock().unwrap().is_empty());
        let result = ready(
            store
                .resolve("profile", needs, Some(secrets()), true, false)
                .unwrap(),
        )
        .complete(ConnectOutcome::AuthenticationRejected);
        assert!(!result.remembered && result.forgotten);
        assert!(backend.values.lock().unwrap().is_empty());
    }

    #[test]
    fn keychain_failures_are_safe_actionable_and_do_not_claim_success() {
        let root = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeSecrets::default());
        let store = OpenVpnCredentialStore::new(root.path(), root.path(), backend.clone()).unwrap();
        *backend.fail.lock().unwrap() = true;
        let needs = CredentialRequirements {
            user_pass: true,
            key_passphrase: false,
        };
        let attempt = ready(
            store
                .resolve("profile", needs, Some(secrets()), true, true)
                .unwrap(),
        );
        assert_eq!(attempt.notice(), Some(CredentialNotice::ForgetFailed));
        let result = attempt.complete(ConnectOutcome::ConfirmedSuccess);
        assert!(!result.remembered);
        assert_eq!(result.notice, Some(CredentialNotice::RememberFailed));
        assert!(!serde_json::to_string(&result).unwrap().contains("secret-"));
        assert!(store.forget("profile").is_err());
        match store.resolve("profile", needs, None, false, false).unwrap() {
            CredentialResolution::Required(prompt) => {
                assert_eq!(prompt.notice, Some(CredentialNotice::KeychainUnavailable))
            }
            CredentialResolution::Ready(_) => panic!("missing credentials treated as ready"),
        }
    }

    #[test]
    fn incomplete_invalid_and_oversized_values_do_not_reach_store_or_runtime() {
        let root = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeSecrets::default());
        let store = OpenVpnCredentialStore::new(root.path(), root.path(), backend.clone()).unwrap();
        let needs = CredentialRequirements {
            user_pass: true,
            key_passphrase: true,
        };
        let incomplete = OpenVpnCredentials {
            auth_user_pass: None,
            private_key_passphrase: Some("pass".into()),
        };
        assert!(matches!(
            store
                .resolve("profile", needs, Some(incomplete), true, false)
                .unwrap(),
            CredentialResolution::Required(_)
        ));
        let mut invalid = secrets();
        invalid.auth_user_pass.as_mut().unwrap().password = "secret\nvalue".into();
        assert!(store
            .resolve("profile", needs, Some(invalid), true, false)
            .is_err());
        backend.values.lock().unwrap().insert(
            (KEYCHAIN_SERVICE.into(), "profile".into()),
            vec![b' '; MAX_SECRET_BYTES + 1],
        );
        match store.resolve("profile", needs, None, false, false).unwrap() {
            CredentialResolution::Required(prompt) => assert_eq!(
                prompt.notice,
                Some(CredentialNotice::StoredCredentialsInvalid)
            ),
            CredentialResolution::Ready(_) => panic!("invalid saved credentials accepted"),
        }
    }

    #[test]
    fn passphrase_only_and_no_requirements_never_forward_other_secrets() {
        let root = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeSecrets::default());
        let store = OpenVpnCredentialStore::new(root.path(), root.path(), backend.clone()).unwrap();
        let needs = CredentialRequirements {
            user_pass: false,
            key_passphrase: true,
        };
        let attempt = ready(
            store
                .resolve("profile", needs, Some(secrets()), true, false)
                .unwrap(),
        );
        assert!(attempt.credentials().unwrap().auth_user_pass.is_none());
        assert!(
            attempt
                .complete(ConnectOutcome::ConfirmedSuccess)
                .remembered
        );
        let values = backend.values.lock().unwrap();
        let bytes = values
            .get(&(KEYCHAIN_SERVICE.into(), "profile".into()))
            .unwrap();
        let saved: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(saved["username"], "");
        assert_eq!(saved["password"], "");
        assert_eq!(saved["passphrase"], "secret-passphrase");
        drop(values);
        let attempt = ready(
            store
                .resolve(
                    "other",
                    CredentialRequirements::default(),
                    Some(secrets()),
                    true,
                    false,
                )
                .unwrap(),
        );
        assert!(attempt.credentials().is_none());
        assert!(
            !attempt
                .complete(ConnectOutcome::ConfirmedSuccess)
                .remembered
        );
        assert_eq!(backend.values.lock().unwrap().len(), 1);
    }

    #[test]
    fn unrelated_failure_keeps_saved_credentials_and_rejected_completion_deletes_them() {
        let root = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeSecrets::default());
        let store = OpenVpnCredentialStore::new(root.path(), root.path(), backend.clone()).unwrap();
        let needs = CredentialRequirements {
            user_pass: true,
            key_passphrase: false,
        };
        ready(
            store
                .resolve("profile", needs, Some(secrets()), true, false)
                .unwrap(),
        )
        .complete(ConnectOutcome::ConfirmedSuccess);
        let attempt = ready(store.resolve("profile", needs, None, false, false).unwrap());
        assert!(!attempt.complete(ConnectOutcome::Failed).forgotten);
        assert_eq!(backend.values.lock().unwrap().len(), 1);
        let attempt = ready(store.resolve("profile", needs, None, false, false).unwrap());
        assert!(
            attempt
                .complete(ConnectOutcome::AuthenticationRejected)
                .forgotten
        );
        assert!(backend.values.lock().unwrap().is_empty());
    }
}
