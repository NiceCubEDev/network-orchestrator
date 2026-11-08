//! Shared state of one `netorch` invocation.
use crate::target::{self, Lookup};
use net_manager_core::models::Profile;
use net_manager_core::profiles::ProfileStore;
use net_manager_engine::Engine;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct Ctx {
    pub root: PathBuf,
    pub json: bool,
}

pub fn is_root() -> bool {
    // SAFETY: geteuid never fails.
    unsafe { libc::geteuid() == 0 }
}

/// Home of the user at the console: where the app keeps its data even when
/// `sudo` has changed `$HOME`.
fn console_home() -> Option<PathBuf> {
    let uid = net_manager_engine::macos_session::console_user_uid().ok()?;
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

/// The app's own data directory, so profiles are shared with the GUI.
pub fn default_root() -> Result<PathBuf, String> {
    let home = if is_root() {
        console_home()
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    .filter(|home| home.is_absolute())
    .ok_or("The home directory could not be found")?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("com.netmanager.app.macos"))
}

impl Ctx {
    pub fn new(root: PathBuf, json: bool) -> Result<Self, String> {
        let expected_uid = if is_root() {
            Some(net_manager_engine::macos_session::console_user_uid()?)
        } else {
            None
        };
        let root =
            net_manager_engine::macos_transaction::normalized_root_path(&root, expected_uid)?;
        Ok(Self { root, json })
    }

    /// Commands that write the app's data must not run as root: the files
    /// would become root-owned and the app could no longer change them.
    pub fn require_user(&self) -> Result<(), String> {
        if is_root() {
            Err("This command changes your Network Orchestrator data; run it without sudo".into())
        } else {
            Ok(())
        }
    }

    pub fn store(&self) -> ProfileStore {
        ProfileStore::new(self.root.join("profiles.json"))
    }

    pub fn engine(&self) -> Engine {
        Engine::new(&self.root)
    }

    pub fn services(&self) -> Result<net_manager_engine::macos_services::MacosServices, String> {
        net_manager_engine::macos_services::MacosServices::new(&self.root)
    }

    pub fn network(&self) -> net_manager_engine::macos_network::MacNetwork {
        net_manager_engine::macos_network::MacNetwork::new(&self.root)
    }

    /// Only safe DTOs may be passed here; executable profiles/credentials are not output.
    pub fn output(&self, value: &impl serde::Serialize) -> Result<(), String> {
        let encoded =
            serde_json::to_string_pretty(value).map_err(|_| "Could not encode the result")?;
        println!("{encoded}");
        Ok(())
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
            Lookup::Ambiguous(_) => Err(
                "Several saved profiles match. Use an exact profile ID from `netorch ls`.".into(),
            ),
        }
    }

    /// `--json` prints the value, otherwise the text.
    pub fn emit(&self, value: Value, text: impl FnOnce() -> String) {
        emit(self.json, value, text);
    }

    pub fn note(&self, message: &str) {
        if !self.json {
            eprintln!("{message}");
        }
    }
}

pub fn emit(json: bool, value: Value, text: impl FnOnce() -> String) {
    if json {
        println!("{value:#}");
    } else {
        let text = text();
        if !text.is_empty() {
            println!("{text}");
        }
    }
}

pub fn random_suffix() -> Result<String, String> {
    let mut bytes = [0u8; 3];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|_| "No random source")?,
        &mut bytes,
    )
    .map_err(|_| "No random source".to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn ok_json() -> Value {
    json!({"ok": true})
}
