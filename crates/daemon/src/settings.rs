//! Administrator-chosen daemon settings, persisted next to the journal.

use net_manager_core::daemon_protocol::VpnAuthMode;
use net_manager_core::journal::write_atomic;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

pub const SETTINGS_FILE: &str = "settings.json";
const SETTINGS_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DaemonSettings {
    pub vpn_auth_mode: VpnAuthMode,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsDocument {
    version: u32,
    #[serde(flatten)]
    settings: DaemonSettings,
}

pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// A missing file uses the initial default. A damaged file requires
    /// administrator confirmation for every VPN connection instead of
    /// silently weakening a previously selected prompt policy.
    pub fn load(&self) -> DaemonSettings {
        let fail_closed = DaemonSettings {
            vpn_auth_mode: VpnAuthMode::Always,
        };
        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return DaemonSettings::default(),
            Err(err) => {
                eprintln!(
                    "network-orchestrator-daemon: cannot read settings, requiring administrator confirmation: {err}"
                );
                return fail_closed;
            }
        };
        match serde_json::from_slice::<SettingsDocument>(&raw) {
            Ok(doc) if doc.version == SETTINGS_VERSION => doc.settings,
            _ => {
                eprintln!("network-orchestrator-daemon: settings file is invalid, requiring administrator confirmation");
                fail_closed
            }
        }
    }

    pub fn save(&self, settings: DaemonSettings) -> io::Result<()> {
        let doc = SettingsDocument {
            version: SETTINGS_VERSION,
            settings,
        };
        let json = serde_json::to_vec_pretty(&doc)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        write_atomic(&self.path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn store(name: &str) -> (SettingsStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "netorch-settings-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        (SettingsStore::new(dir.join(SETTINGS_FILE)), dir)
    }

    #[test]
    fn missing_settings_allow_full_and_split_tunnels_without_admin_prompt() {
        let (store, dir) = store("missing");
        let mode = store.load().vpn_auth_mode;
        for broad in [false, true] {
            assert_eq!(
                crate::auth::connect_action(mode, broad),
                crate::auth::Action::ConnectProfile
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn save_roundtrips_with_private_mode() {
        let (store, dir) = store("roundtrip");
        for mode in [
            VpnAuthMode::NoPrompt,
            VpnAuthMode::FullTunnelOnly,
            VpnAuthMode::Always,
        ] {
            store
                .save(DaemonSettings {
                    vpn_auth_mode: mode,
                })
                .unwrap();
            assert_eq!(store.load().vpn_auth_mode, mode);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(SETTINGS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_file_requires_administrator_confirmation() {
        let (store, dir) = store("invalid");
        for body in [
            &b"{ not json"[..],
            br#"{"version":9,"vpnAuthMode":"noPrompt"}"#,
        ] {
            fs::write(dir.join(SETTINGS_FILE), body).unwrap();
            assert_eq!(store.load().vpn_auth_mode, VpnAuthMode::Always);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_settings_fail_closed_for_vpn_authorization() {
        let (store, dir) = store("fail-closed");
        fs::write(dir.join(SETTINGS_FILE), b"{ corrupt").unwrap();
        assert_eq!(store.load().vpn_auth_mode, VpnAuthMode::Always);
        fs::remove_file(dir.join(SETTINGS_FILE)).unwrap();
        fs::create_dir(dir.join(SETTINGS_FILE)).unwrap();
        assert_eq!(store.load().vpn_auth_mode, VpnAuthMode::Always);
        fs::remove_dir_all(dir).unwrap();
    }
}
