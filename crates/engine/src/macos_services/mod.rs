//! Portable native-client business services. Executable profiles remain private to
//! the runtime; presentation methods return the Core redacted profile projection.
use net_manager_core::daemon_protocol::{NetIntentSetParams, NetIntentView, OpenVpnCredentials};
use net_manager_core::{config_vault::ConfigVault, models::*, profiles::ProfileStore};
use serde::Serialize;
use std::path::{Path, PathBuf};

mod orchestration;
mod profiles;
mod routing;
mod subscriptions;
pub use orchestration::*;
pub use profiles::*;
pub use routing::*;
pub use subscriptions::*;

const UNSUPPORTED: &str = "This action needs the macOS connection runtime";

/// The only runtime seam needed by business orchestration. Tests inject this
/// seam, not a different platform's engine or a replacement business service.
pub trait BusinessRuntime: Send + Sync {
    fn is_running(&self, root: &Path, profile: &Profile) -> Result<bool, String>;
    /// Implementations hold the common root operation lock across stop/change/start.
    fn restart_around<T>(
        &self,
        root: &Path,
        store: &ProfileStore,
        id: &str,
        change: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String>;
    fn managed_executable(&self, _root: &Path) -> Option<PathBuf> {
        None
    }
    fn connect(
        &self,
        _root: &Path,
        _store: &ProfileStore,
        _profile: &Profile,
        _credentials: Option<OpenVpnCredentials>,
    ) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }
    fn disconnect(&self, _root: &Path, _profile: &Profile, _all: &[Profile]) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }
    fn intents(&self, _root: &Path) -> Result<Vec<NetIntentView>, String> {
        Err(UNSUPPORTED.into())
    }
    fn set_intent(&self, _root: &Path, _params: NetIntentSetParams) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }
    fn diagnose(
        &self,
        _root: &Path,
        _profile: &Profile,
        _context: crate::DiagnosticsContext<'_>,
    ) -> Result<ProfileDiagnostics, String> {
        Err(UNSUPPORTED.into())
    }
    fn credential_requirements(
        &self,
        _root: &Path,
        _profile: &Profile,
    ) -> Result<crate::macos_credentials::CredentialRequirements, String> {
        Ok(Default::default())
    }
    fn authentication_rejected(&self, _root: &Path, _profile: &Profile) -> Result<bool, String> {
        Ok(false)
    }
    fn running_interfaces(
        &self,
        _root: &Path,
        _profiles: &[Profile],
    ) -> Result<Vec<String>, String> {
        Ok(vec![])
    }
}
#[derive(Clone, Copy, Default)]
pub struct PlatformRuntime;
impl BusinessRuntime for PlatformRuntime {
    fn is_running(&self, root: &Path, profile: &Profile) -> Result<bool, String> {
        crate::Engine::new(root).is_running(profile)
    }
    fn restart_around<T>(
        &self,
        root: &Path,
        store: &ProfileStore,
        id: &str,
        change: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        crate::Engine::new(root).restart_around(store, id, change)
    }
    fn managed_executable(&self, root: &Path) -> Option<PathBuf> {
        crate::Engine::new(root).managed_executable()
    }
    fn connect(
        &self,
        root: &Path,
        store: &ProfileStore,
        profile: &Profile,
        credentials: Option<OpenVpnCredentials>,
    ) -> Result<(), String> {
        crate::Engine::new(root).connect(store, profile, credentials)
    }
    fn disconnect(&self, root: &Path, profile: &Profile, all: &[Profile]) -> Result<(), String> {
        crate::Engine::new(root)
            .disconnect(profile, all)
            .map(|_| ())
    }
    fn intents(&self, root: &Path) -> Result<Vec<NetIntentView>, String> {
        crate::Engine::new(root).intents()
    }
    fn set_intent(&self, root: &Path, params: NetIntentSetParams) -> Result<(), String> {
        crate::Engine::new(root).set_intent(params).map(|_| ())
    }
    fn diagnose(
        &self,
        root: &Path,
        profile: &Profile,
        context: crate::DiagnosticsContext<'_>,
    ) -> Result<ProfileDiagnostics, String> {
        crate::Engine::new(root).diagnose(profile, context)
    }
    fn credential_requirements(
        &self,
        root: &Path,
        profile: &Profile,
    ) -> Result<crate::macos_credentials::CredentialRequirements, String> {
        let needs = crate::Engine::new(root).credential_requirements(profile)?;
        Ok(crate::macos_credentials::CredentialRequirements {
            user_pass: needs.user_pass,
            key_passphrase: needs.key_passphrase,
        })
    }
    fn authentication_rejected(&self, root: &Path, profile: &Profile) -> Result<bool, String> {
        Ok(crate::Engine::new(root)
            .snapshot(std::slice::from_ref(profile))?
            .statuses
            .iter()
            .any(|s| {
                s.profile_id == profile.id
                    && s.message.as_deref() == Some("OpenVPN authentication failed")
            }))
    }
    fn running_interfaces(&self, root: &Path, profiles: &[Profile]) -> Result<Vec<String>, String> {
        Ok(crate::Engine::new(root)
            .snapshot(profiles)?
            .statuses
            .into_iter()
            .filter(|s| s.state == TunnelState::Running)
            .filter_map(|s| s.interface_name)
            .collect())
    }
}

pub struct MacosServices<R = PlatformRuntime> {
    root: PathBuf,
    runtime: R,
    network: crate::macos_network::MacNetwork,
}
impl MacosServices<PlatformRuntime> {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, String> {
        Self::with_runtime(root, PlatformRuntime)
    }
}
impl<R: BusinessRuntime> MacosServices<R> {
    pub fn with_runtime(root: impl Into<PathBuf>, runtime: R) -> Result<Self, String> {
        let root = crate::macos_transaction::normalized_root_path(&root.into(), None)?;
        let network = crate::macos_network::MacNetwork::new(root.clone());
        Ok(Self {
            root,
            runtime,
            network,
        })
    }
    pub fn with_network(
        root: impl Into<PathBuf>,
        runtime: R,
        network: crate::macos_network::MacNetwork,
    ) -> Result<Self, String> {
        let root = crate::macos_transaction::normalized_root_path(&root.into(), None)?;
        Ok(Self {
            root,
            runtime,
            network,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    fn store(&self) -> ProfileStore {
        ProfileStore::new(self.root.join("profiles.json"))
    }
    fn vault(&self) -> ConfigVault {
        ConfigVault::new(self.root.join("configs"))
    }
    fn locked<T>(&self, action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        crate::macos_transaction::with_root_lock(&self.root, action)
    }
    /// Executable profile for a typed runtime call. Never serialize this value.
    pub fn profile(&self, id: &str) -> Result<Profile, String> {
        let mut profile = self
            .store()
            .load()
            .map_err(store_error)?
            .profiles
            .into_iter()
            .find(|p| p.id == id)
            .ok_or_else(|| "Profile not found".to_string())?;
        normalize_profile_path(&mut profile, None)?;
        Ok(profile)
    }
    pub fn public_profiles(&self) -> Result<Vec<Profile>, String> {
        Ok(redact_profiles(
            self.store().load().map_err(store_error)?.profiles,
        ))
    }
    fn profiles(&self) -> Result<Vec<Profile>, String> {
        let mut profiles = self.store().load().map_err(store_error)?.profiles;
        for profile in &mut profiles {
            normalize_profile_path(profile, None)?;
        }
        Ok(profiles)
    }
    fn public_profile(&self, id: &str) -> Result<Profile, String> {
        Ok(redact(self.profile(id)?))
    }
    fn change_profile(
        &self,
        id: &str,
        restart: bool,
        change: impl FnOnce(&mut Profile) -> Result<(), String>,
    ) -> Result<Profile, String> {
        let action = || {
            let mut profile = self.profile(id)?;
            change(&mut profile)?;
            self.store().upsert(profile).map_err(store_error)?;
            self.public_profile(id)
        };

        if restart {
            self.runtime
                .restart_around(&self.root, &self.store(), id, action)
        } else {
            self.locked(action)
        }
    }
}
/// Normalize only directories. ConfigVault's snapshot readers must still inspect
/// and reject a linked configuration leaf without following it.
pub(crate) fn normalize_profile_path(
    profile: &mut Profile,
    expected_uid: Option<u32>,
) -> Result<(), String> {
    if profile.config_path.as_os_str().is_empty() {
        return Ok(());
    }
    let parent = profile
        .config_path
        .parent()
        .ok_or("The configuration directory is invalid")?;
    let filename = profile
        .config_path
        .file_name()
        .ok_or("The configuration filename is invalid")?;
    let parent = crate::macos_transaction::normalized_root_path(parent, expected_uid)?;
    let path = parent.join(filename);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("Configuration files must not be symbolic links".into())
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("The configuration file could not be inspected".into()),
    }
    profile.config_path = path;
    Ok(())
}
fn store_error(_: std::io::Error) -> String {
    "The profile operation could not be completed. Check the input and file permissions.".into()
}
fn redact(mut profile: Profile) -> Profile {
    profile.config_path.clear();
    if let Some(meta) = &mut profile.subscription {
        meta.url.clear();
        meta.hwid.clear();
    }
    for check in &mut profile.xray_service_checks {
        check.url.clear();
    }
    profile
}
fn redact_profiles(profiles: Vec<Profile>) -> Vec<Profile> {
    profiles.into_iter().map(redact).collect()
}
fn required(value: &str) -> Result<&str, String> {
    let value = value.trim();
    if value.is_empty() {
        Err("A required field is empty".into())
    } else {
        Ok(value)
    }
}
fn local_port_available(port: u16) -> bool {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
}
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .unwrap_or(0)
}

/// Global helper diagnostics do not depend on a user's profile directory.
pub fn helper_log() -> String {
    crate::runtime::helper_log_text(Path::new("/var/log/network-orchestrator-helper.log"))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelperStatus {
    pub reachable: bool,
    pub denied: bool,
    pub protocol_error: bool,
    pub version: String,
    pub capabilities: Vec<String>,
}
pub fn helper_status() -> HelperStatus {
    use net_manager_core::helper_client::{is_denied, HelperClient, HelperError};
    match HelperClient::new(crate::helper_socket())
        .with_timeout(std::time::Duration::from_secs(3))
        .hello()
    {
        Ok(hello) => HelperStatus {
            reachable: true,
            denied: false,
            protocol_error: false,
            version: hello.daemon_version,
            capabilities: hello.capabilities,
        },
        Err(error) => HelperStatus {
            reachable: false,
            denied: is_denied(&error),
            protocol_error: matches!(error, HelperError::Protocol(_)),
            version: String::new(),
            capabilities: vec![],
        },
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosCapabilities {
    pub os: &'static str,
    #[serde(rename = "minimumOS")]
    pub minimum_os: &'static str,
    #[serde(rename = "nativeUI")]
    pub native_ui: bool,
    pub profiles: bool,
    pub network_inventory: bool,
    pub network_mutations: bool,
    pub proxy_connections: bool,
    #[serde(rename = "systemVPN")]
    pub system_vpn: &'static str,
    pub version: &'static str,
}
pub fn capabilities() -> MacosCapabilities {
    MacosCapabilities {
        os: "macos",
        minimum_os: "27.0",
        native_ui: true,
        profiles: true,
        network_inventory: true,
        network_mutations: false,
        proxy_connections: cfg!(all(target_os = "macos", target_arch = "aarch64")),
        system_vpn: "providerSetupRequired",
        version: env!("CARGO_PKG_VERSION"),
    }
}
#[cfg(test)]
mod tests;
