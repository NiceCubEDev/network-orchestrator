//! Shared state of one `netorch` invocation on Linux.
use crate::target::{self, Lookup};
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::models::Profile;
use net_manager_core::profiles::ProfileStore;
use net_manager_engine::linux_engine::LinuxEngine;
use net_manager_engine::linux_paths::{self, APPLICATION_ID};
use std::path::PathBuf;

pub struct Ctx {
    pub root: PathBuf,
    pub engine: LinuxEngine,
    /// Whether this process is root; tests set it directly.
    pub root_user: bool,
    #[cfg(target_os = "linux")]
    credentials: net_manager_engine::linux_credentials::OpenVpnCredentialStore,
}

pub fn is_root() -> bool {
    // SAFETY: geteuid never fails.
    unsafe { libc::geteuid() == 0 }
}

/// Home of the user who ran `sudo`: where their app data is, even though
/// `$HOME` is root's.
fn sudo_user_home() -> Option<PathBuf> {
    let uid: libc::uid_t = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    // SAFETY: getpwuid returns null or a pointer valid until the next call;
    // the directory is copied out immediately.
    unsafe {
        let entry = libc::getpwuid(uid);
        if entry.is_null() {
            return None;
        }
        let dir = std::ffi::CStr::from_ptr((*entry).pw_dir).to_str().ok()?;
        Some(PathBuf::from(dir))
    }
}

pub fn default_root() -> Result<PathBuf, String> {
    if is_root() {
        // Root needs no polkit prompt, so `sudo netorch up` works; it only
        // reads the invoking user's data (writing would leave root-owned files).
        return linux_paths::data_root(APPLICATION_ID, None, None, sudo_user_home()).map_err(
            |_| {
                "Run netorch as your own user, or with sudo from your account. \
             Use --data-dir to point root at a data directory."
                    .to_string()
            },
        );
    }
    linux_paths::from_environment(APPLICATION_ID)
}

impl Ctx {
    pub fn new(root: PathBuf, engine: LinuxEngine) -> Result<Self, String> {
        if !root.is_absolute() {
            return Err("The data directory must be an absolute path".into());
        }
        let engine = engine.with_data_root(root.clone());
        Ok(Self {
            root,
            engine,
            root_user: is_root(),
            #[cfg(target_os = "linux")]
            credentials: net_manager_engine::linux_credentials::OpenVpnCredentialStore::new(
                Box::new(net_manager_engine::linux_credentials::SecretServiceStore),
            ),
        })
    }

    pub fn store(&self) -> ProfileStore {
        ProfileStore::new(self.root.join("profiles.json"))
    }

    pub fn vault(&self) -> ConfigVault {
        ConfigVault::new(self.root.join("configs"))
    }

    #[cfg(target_os = "linux")]
    pub fn credentials(
        &self,
    ) -> Result<&net_manager_engine::linux_credentials::OpenVpnCredentialStore, String> {
        if self.root_user {
            return Err("Run credential changes as your own user, without sudo".into());
        }
        Ok(&self.credentials)
    }

    /// Profiles as stored, for running them. Never printed as they are.
    pub fn profiles(&self) -> Result<Vec<Profile>, String> {
        self.store()
            .load()
            .map(|document| document.profiles)
            .map_err(|_| "Profiles could not be loaded".to_string())
    }

    pub fn find(&self, query: &str) -> Result<Profile, String> {
        let profiles = self.profiles()?;
        match target::resolve(&profiles, query) {
            Lookup::Found(profile) => Ok(profile.clone()),
            Lookup::Missing => Err("No saved profile matches. `netorch ls` lists them.".into()),
            Lookup::Ambiguous(_) => {
                Err("Several saved profiles match; use an ID from `netorch ls`.".into())
            }
        }
    }
}

impl net_manager_engine::linux::CredentialSource for Ctx {
    fn load(
        &self,
        profile_id: &str,
        legacy: &std::path::Path,
    ) -> Result<
        (
            Option<net_manager_core::daemon_protocol::OpenVpnCredentials>,
            Option<&'static str>,
        ),
        String,
    > {
        #[cfg(target_os = "linux")]
        if !self.root_user {
            return self.credentials.load(profile_id, legacy);
        }
        let _ = (profile_id, legacy);
        // A root invocation must not migrate or rewrite the user's secrets.
        Ok((None, None))
    }
}
