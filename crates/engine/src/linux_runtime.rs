//! Shared Linux lifecycle, credential policy and explicit startup execution.
use crate::linux::{openvpn_credentials_path, prepare_linux_openvpn_request, CredentialSource};
use crate::linux_credentials::OpenVpnCredentialStore;
use crate::linux_engine::LinuxEngine;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::{method, OpenVpnCredentials, OpenVpnPlanResult};
use net_manager_core::models::*;
use net_manager_core::profiles::ProfileStore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Borrowed resources for one shared data-root lifecycle operation.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub engine: &'a LinuxEngine,
    pub root: &'a Path,
    pub vault: &'a ConfigVault,
    pub store: &'a ProfileStore,
}

pub fn connect(
    context: &Context<'_>,
    profile_id: &str,
    supplied: Option<OpenVpnCredentials>,
    remembered: &dyn CredentialSource,
    remember_into: Option<&OpenVpnCredentialStore>,
) -> Result<TunnelStatus, String> {
    connect_with_credentials(
        context,
        profile_id,
        supplied,
        remembered,
        remember_into,
        remember_into.is_some(),
    )
}

pub fn connect_with_credentials(
    context: &Context<'_>,
    profile_id: &str,
    supplied: Option<OpenVpnCredentials>,
    remembered: &dyn CredentialSource,
    credential_store: Option<&OpenVpnCredentialStore>,
    remember: bool,
) -> Result<TunnelStatus, String> {
    let Context {
        root, vault, store, ..
    } = *context;
    let result = (|| {
        if remember && credential_store.is_none() {
            return Err("Remembered credentials are unavailable for this caller".into());
        }
        let mut profiles = store
            .load()
            .map_err(|_| "Profiles could not be loaded")?
            .profiles;
        let mut profile = profiles
            .iter()
            .find(|p| p.id == profile_id)
            .cloned()
            .ok_or("Profile not found")?;
        profile.check_role()?;
        if supplied.is_some() && profile.backend != TunnelBackend::OpenVpn {
            return Err("Credentials require an OpenVPN profile".into());
        }
        let notice = prepare_listener_ports(
            vault,
            store,
            &mut profile,
            &mut profiles,
            unsafe { libc::geteuid() } == 0,
        )?;
        let prepared = prepare_connection(
            context,
            &profile,
            supplied,
            remembered,
            credential_store,
            remember,
            false,
        )?;
        let mut status = execute_prepared(context, &prepared, credential_store)?;
        append_notice(&mut status, notice.as_deref());
        Ok(status)
    })();
    record_lifecycle(root, "connect", profile_id, &result);
    result
}

fn prepare_listener_ports(
    vault: &ConfigVault,
    store: &ProfileStore,
    profile: &mut Profile,
    profiles: &mut [Profile],
    root: bool,
) -> Result<Option<String>, String> {
    if profile.backend != TunnelBackend::Xray {
        return Ok(None);
    }
    if root {
        if net_manager_core::profile_import::select_connect_ports(profiles, profile, port_available)
            .map_err(|_| "Cannot prepare listener ports")?
            .is_some()
        {
            return Err("Listener ports need updating; run as your own user".into());
        }
        Ok(None)
    } else {
        net_manager_core::profile_import::prepare_connect_ports(
            vault,
            store,
            profile,
            profiles,
            port_available,
        )
        .map_err(|_| "Cannot prepare listener ports".into())
    }
}

/// Input-only request/credential snapshot; contains secrets and must not be logged.
pub struct PreparedConnection {
    request: crate::linux_engine::PreparedConnection,
    retained: Option<OpenVpnCredentials>,
    explicit: bool,
    remember: bool,
    notice: Option<String>,
}

impl PreparedConnection {
    pub fn profile(&self) -> &Profile {
        self.request.profile()
    }
    pub fn validate_prepared_configuration(&self, engine: &LinuxEngine) -> Result<(), String> {
        engine.validate_prepared_configuration(&self.request)
    }
}

pub fn prepare_connection(
    context: &Context<'_>,
    profile: &Profile,
    supplied: Option<OpenVpnCredentials>,
    remembered: &dyn CredentialSource,
    credential_store: Option<&OpenVpnCredentialStore>,
    remember: bool,
    prepare_ports: bool,
) -> Result<PreparedConnection, String> {
    let Context {
        engine,
        vault,
        store,
        ..
    } = *context;
    if supplied.is_some() && profile.backend != TunnelBackend::OpenVpn {
        return Err("Credentials require an OpenVPN profile".into());
    }
    if remember && credential_store.is_none() {
        return Err("Remembered credentials are unavailable for this caller".into());
    }
    let root = unsafe { libc::geteuid() } == 0;
    if root && supplied.is_some() && credential_store.is_some() {
        return Err("Run credential changes as your own user".into());
    }
    let explicit = supplied.is_some();
    let retained = if remember { supplied.clone() } else { None };
    let mut candidate = None;
    let notice = if prepare_ports && profile.backend == TunnelBackend::Xray {
        let mut profiles = store
            .load()
            .map_err(|_| "Profiles could not be loaded")?
            .profiles;
        let snapshot = candidate.insert(profile.clone());
        prepare_listener_ports(vault, store, snapshot, &mut profiles, root)?
    } else {
        None
    };
    let profile = candidate.as_ref().unwrap_or(profile);
    let request = engine.prepare_connection(
        vault,
        profile,
        supplied,
        credential_source(remembered, root),
        false,
    )?;
    Ok(PreparedConnection {
        request,
        retained,
        explicit,
        remember,
        notice,
    })
}

pub fn execute_prepared(
    context: &Context<'_>,
    prepared: &PreparedConnection,
    credential_store: Option<&OpenVpnCredentialStore>,
) -> Result<TunnelStatus, String> {
    let Context { engine, vault, .. } = *context;
    if prepared.remember && credential_store.is_none() {
        return Err("Remembered credentials are unavailable for this caller".into());
    }
    let mut status = engine.execute_prepared(&prepared.request)?;
    if status.state != TunnelState::Running {
        return Err("The backend did not confirm the connection".into());
    }
    if let Some(credentials) = credential_store {
        let notice = if prepared.remember {
            apply_credential_policy(
                vault,
                prepared.profile(),
                prepared.retained.as_ref(),
                credentials,
                true,
            )
        } else if prepared.explicit {
            forget_credential_notice(vault, prepared.profile(), credentials)
        } else {
            None
        };
        append_notice(&mut status, notice);
    }
    append_notice(&mut status, prepared.notice.as_deref());
    Ok(status)
}

/// Connect a validated candidate, including live profile cutovers before persistence.
pub fn connect_prepared(
    context: &Context<'_>,
    profile: &Profile,
    supplied: Option<OpenVpnCredentials>,
    remembered: &dyn CredentialSource,
    credential_store: Option<&OpenVpnCredentialStore>,
    remember: bool,
) -> Result<TunnelStatus, String> {
    let prepared = prepare_connection(
        context,
        profile,
        supplied,
        remembered,
        credential_store,
        remember,
        profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Socks,
    )?;
    execute_prepared(context, &prepared, credential_store)
}

fn port_available(port: u16) -> bool {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
}

fn append_notice(status: &mut TunnelStatus, notice: Option<&str>) {
    if let Some(notice) = notice {
        status.message = Some(match status.message.take() {
            Some(message) => format!("{message}; {notice}"),
            None => notice.into(),
        });
    }
}

fn apply_credential_policy(
    vault: &ConfigVault,
    profile: &Profile,
    supplied: Option<&OpenVpnCredentials>,
    credentials: &OpenVpnCredentialStore,
    remember: bool,
) -> Option<&'static str> {
    let supplied = supplied?;
    if remember {
        credentials.remember(&profile.id, supplied)
    } else {
        forget_credential_notice(vault, profile, credentials)
    }
}

fn forget_credential_notice(
    vault: &ConfigVault,
    profile: &Profile,
    credentials: &OpenVpnCredentialStore,
) -> Option<&'static str> {
    let legacy = openvpn_credentials_path(vault, profile).ok();
    credentials
        .forget(&profile.id, legacy.as_deref())
        .err()
        .map(|_| "OpenVPN started, but old remembered credentials could not be removed")
}

pub fn disconnect(
    engine: &LinuxEngine,
    store: &ProfileStore,
    profile_id: &str,
) -> Result<TunnelStatus, String> {
    let profile = store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles
        .into_iter()
        .find(|p| p.id == profile_id)
        .ok_or("Profile not found")?;
    engine.disconnect(&profile)
}

pub fn disconnect_with_root(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
    profile_id: &str,
) -> Result<TunnelStatus, String> {
    let profile = store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles
        .into_iter()
        .find(|p| p.id == profile_id)
        .ok_or("Profile not found")?;
    disconnect_profile_with_root(engine, root, &profile)
}

pub fn disconnect_profile_with_root(
    engine: &LinuxEngine,
    root: &Path,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    let result = engine.disconnect(profile);
    record_lifecycle(root, "disconnect", &profile.id, &result);
    result
}

pub fn status(engine: &LinuxEngine, profile: &Profile) -> Result<TunnelStatus, String> {
    engine.status(profile)
}

pub fn statuses(engine: &LinuxEngine, store: &ProfileStore) -> Result<Vec<TunnelStatus>, String> {
    let profiles = store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles;
    statuses_for(engine, &profiles)
}

pub fn statuses_for(
    engine: &LinuxEngine,
    profiles: &[Profile],
) -> Result<Vec<TunnelStatus>, String> {
    Ok(profiles
        .iter()
        .map(|profile| {
            engine.status(profile).unwrap_or_else(|_| TunnelStatus {
                profile_id: profile.id.clone(),
                state: TunnelState::Failed,
                message: Some("Runtime status is unavailable".into()),
                interface_name: None,
                failover: None,
                watchdog: None,
            })
        })
        .collect())
}

pub fn reload(
    engine: &LinuxEngine,
    vault: &ConfigVault,
    profile: &Profile,
) -> Result<TunnelStatus, String> {
    let result = engine.reload_xray(vault, profile);
    if let Some(root) = vault.root().parent() {
        record_lifecycle(root, "reload", &profile.id, &result);
    }
    result
}

fn credential_source(remembered: &dyn CredentialSource, root: bool) -> &dyn CredentialSource {
    if root {
        &()
    } else {
        remembered
    }
}

pub fn openvpn_plan(
    engine: &LinuxEngine,
    vault: &ConfigVault,
    profile: &Profile,
    remembered: &dyn CredentialSource,
) -> Result<OpenVpnPlanResult, String> {
    require_openvpn(profile)?;
    let remembered = credential_source(remembered, unsafe { libc::geteuid() } == 0);
    let (request, _) = prepare_linux_openvpn_request(
        vault,
        remembered,
        profile,
        None,
        profile.effective_routes(),
        method::OPENVPN_PLAN,
    )?;
    engine.ask(method::OPENVPN_PLAN, request)
}

pub fn openvpn_probe(
    engine: &LinuxEngine,
    vault: &ConfigVault,
    profile: &Profile,
    remembered: &dyn CredentialSource,
) -> Result<Vec<AnalyzedRoute>, String> {
    require_openvpn(profile)?;
    let remembered = credential_source(remembered, unsafe { libc::geteuid() } == 0);
    engine.probe_openvpn_routes(vault, profile, remembered)
}

pub fn forget_credentials(
    vault: &ConfigVault,
    credentials: &OpenVpnCredentialStore,
    profile: &Profile,
) -> Result<(), String> {
    require_openvpn(profile)?;
    if unsafe { libc::geteuid() } == 0 {
        return Err("Run credential changes as your own user".into());
    }
    let legacy = openvpn_credentials_path(vault, profile).ok();
    credentials.forget(&profile.id, legacy.as_deref())
}

fn require_openvpn(profile: &Profile) -> Result<(), String> {
    if profile.backend != TunnelBackend::OpenVpn {
        Err("Profile is not OpenVPN".into())
    } else {
        Ok(())
    }
}

pub(crate) fn record_lifecycle(
    root: &Path,
    action: &str,
    id: &str,
    result: &Result<TunnelStatus, String>,
) {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    use crate::linux_diagnostics::{record_log, LogLevel};
    let (level, outcome) = if result.is_ok() {
        (LogLevel::Info, "succeeded")
    } else {
        (LogLevel::Error, "failed")
    };
    let _ = record_log(root, level, &format!("{action} profile {id}: {outcome}"));
}

pub fn daemon_owner(profile: &Profile) -> Option<String> {
    match profile.backend {
        TunnelBackend::None => Some(profile.id.clone()),
        TunnelBackend::WireGuard => Some(format!("wg:{}", profile.id)),
        TunnelBackend::OpenVpn => Some(format!("ovpn:{}", profile.id)),
        TunnelBackend::Xray if profile.xray_mode == XrayMode::Tun => {
            Some(format!("xray:{}", profile.id))
        }
        TunnelBackend::Xray => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutoConnectResult {
    pub failed_count: usize,
    pub startup_failed: bool,
}

fn execute_auto_connect(
    profiles: &[Profile],
    mut status: impl FnMut(&Profile) -> Result<TunnelState, String>,
    mut connect: impl FnMut(&Profile) -> Result<(), String>,
) -> AutoConnectResult {
    let mut result = AutoConnectResult {
        failed_count: 0,
        startup_failed: false,
    };
    let mut candidates = Vec::new();
    let mut primary_running = false;
    for profile in profiles
        .iter()
        .filter(|p| p.auto_connect || p.tunnel_role == TunnelRole::Primary)
    {
        match status(profile) {
            Ok(TunnelState::Running) => {
                primary_running |= profile.tunnel_role == TunnelRole::Primary;
            }
            Ok(TunnelState::Stopped) if profile.auto_connect => candidates.push(profile),
            Ok(TunnelState::Stopped) => {}
            Ok(TunnelState::Failed) | Err(_) => result.startup_failed |= profile.auto_connect,
        }
    }
    // Stable partition: preserve saved order within each role.
    for role in [TunnelRole::Primary, TunnelRole::Secondary] {
        for profile in candidates.iter().filter(|p| p.tunnel_role == role) {
            if role == TunnelRole::Secondary && !primary_running {
                result.failed_count += 1;
                continue;
            }
            match connect(profile) {
                Ok(()) => primary_running |= role == TunnelRole::Primary,
                Err(_) => result.failed_count += 1,
            }
        }
    }
    result
}

pub fn run_auto_connect(
    engine: &LinuxEngine,
    root: &Path,
    vault: &ConfigVault,
    store: &ProfileStore,
    remembered: &dyn CredentialSource,
) -> Result<AutoConnectResult, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("Run auto-connect as your own user".into());
    }
    let _run = result_lock(root, "auto-connect-run.lock")?;
    let context = Context {
        engine,
        root,
        vault,
        store,
    };
    let result = match store.load() {
        Ok(document) => execute_auto_connect(
            &document.profiles,
            |profile| engine.status(profile).map(|status| status.state),
            |profile| connect(&context, &profile.id, None, remembered, None).map(|_| ()),
        ),
        Err(_) => AutoConnectResult {
            failed_count: 0,
            startup_failed: true,
        },
    };
    save_auto_connect_result(root, result)?;
    Ok(result)
}

fn private_file(file: &std::fs::File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|_| "Auto-connect state is unavailable")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("Auto-connect state is not private".into());
    }
    Ok(())
}

fn result_lock(root: &Path, name: &str) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(root).map_err(|_| "Cannot create auto-connect state directory")?;
    let metadata =
        std::fs::symlink_metadata(root).map_err(|_| "Cannot inspect auto-connect directory")?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("Auto-connect directory is not owned by this user".into());
    }
    net_manager_core::config_security::protect_path(root)
        .map_err(|_| "Cannot protect auto-connect directory")?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(name))
        .map_err(|_| "Cannot open auto-connect lock")?;
    private_file(&file)?;
    file.lock().map_err(|_| "Cannot lock auto-connect state")?;
    Ok(file)
}

fn save_auto_connect_result(root: &Path, result: AutoConnectResult) -> Result<(), String> {
    let _lock = result_lock(root, "auto-connect-result.lock")?;
    let path = root.join("auto-connect-result.json");
    let temp = root.join("auto-connect-result.tmp");
    match std::fs::remove_file(&temp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Cannot remove interrupted auto-connect result".into()),
    }
    let result = (|| {
        let bytes = serde_json::to_vec(&result).map_err(|_| "Cannot encode auto-connect result")?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| "Cannot stage auto-connect result")?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Cannot save auto-connect result")?;
        std::fs::rename(&temp, &path).map_err(|_| "Cannot commit auto-connect result")?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temp);
    result
}

pub fn auto_connect_result(root: &Path) -> Result<Option<AutoConnectResult>, String> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join("auto-connect-result.json"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Auto-connect result is unavailable".into()),
    };
    private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read auto-connect result")?;
    if bytes.len() > 4096 {
        return Err("Auto-connect result exceeds its size bound".into());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "Auto-connect result is invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_credentials::SecretStore;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    fn profile(id: &str, role: TunnelRole) -> Profile {
        Profile {
            id: id.into(),
            name: id.into(),
            backend: TunnelBackend::WireGuard,
            auto_connect: true,
            tunnel_role: role,
            ..Default::default()
        }
    }

    #[test]
    fn root_read_policy_never_calls_credential_migration_source() {
        struct Source(std::sync::atomic::AtomicUsize);
        impl CredentialSource for Source {
            fn load(
                &self,
                _: &str,
                _: &Path,
            ) -> Result<(Option<OpenVpnCredentials>, Option<&'static str>), String> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err("migration-capable source called".into())
            }
        }
        let source = Source(std::sync::atomic::AtomicUsize::new(0));
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("credentials.json");
        assert!(credential_source(&source, true)
            .load("vpn", &legacy)
            .unwrap()
            .0
            .is_none());
        assert_eq!(source.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(!legacy.exists());
        assert!(credential_source(&source, false)
            .load("vpn", &legacy)
            .is_err());
        assert_eq!(source.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn cached_profile_can_disconnect_after_profile_store_has_been_removed() {
        struct Daemon(Mutex<Vec<serde_json::Value>>);
        impl crate::Privileged for Daemon {
            fn hello(
                &self,
            ) -> Result<
                net_manager_core::daemon_protocol::HelloResult,
                net_manager_core::helper_client::HelperError,
            > {
                Err(net_manager_core::helper_client::HelperError::Protocol(
                    "unexpected handshake".into(),
                ))
            }
            fn call_raw(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> Result<serde_json::Value, net_manager_core::helper_client::HelperError>
            {
                assert_eq!(
                    method,
                    net_manager_core::daemon_protocol::method::WIREGUARD_DISCONNECT
                );
                self.0.lock().unwrap().push(params);
                Ok(serde_json::json!({"stopped": true}))
            }
            fn log_dir(&self) -> std::path::PathBuf {
                Default::default()
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let daemon = Arc::new(Daemon(Mutex::new(Vec::new())));
        let engine = LinuxEngine::with_privileged(daemon.clone());
        let cached = profile("cached", TunnelRole::Primary);
        let status = disconnect_profile_with_root(&engine, dir.path(), &cached).unwrap();
        assert_eq!(status.state, TunnelState::Stopped);
        assert_eq!(
            daemon.0.lock().unwrap().as_slice(),
            &[serde_json::json!({"profileId": "cached"})]
        );
        assert!(!dir.path().join("profiles.json").exists());
    }

    #[test]
    fn startup_unknown_is_never_connected_and_primary_precedes_secondary() {
        let profiles = [
            profile("secondary", TunnelRole::Secondary),
            profile("unknown", TunnelRole::Primary),
            profile("primary", TunnelRole::Primary),
            profile("running", TunnelRole::Primary),
        ];
        let calls = RefCell::new(Vec::new());
        let result = execute_auto_connect(
            &profiles,
            |p| match p.id.as_str() {
                "unknown" => Err("unavailable".into()),
                "running" => Ok(TunnelState::Running),
                _ => Ok(TunnelState::Stopped),
            },
            |p| {
                calls.borrow_mut().push(p.id.clone());
                Ok(())
            },
        );
        assert_eq!(*calls.borrow(), ["primary", "secondary"]);
        assert!(result.startup_failed);
        assert_eq!(result.failed_count, 0);
    }

    #[test]
    fn startup_failed_primary_does_not_connect_its_secondary() {
        let profiles = [
            profile("secondary", TunnelRole::Secondary),
            profile("primary", TunnelRole::Primary),
        ];
        let calls = RefCell::new(Vec::new());
        let result = execute_auto_connect(
            &profiles,
            |_| Ok(TunnelState::Stopped),
            |p| {
                calls.borrow_mut().push(p.id.clone());
                Err("start failed".into())
            },
        );
        assert_eq!(*calls.borrow(), ["primary"]);
        assert_eq!(result.failed_count, 2);
    }

    #[test]
    fn startup_secondary_uses_existing_primary_even_when_not_auto_enabled() {
        let mut primary = profile("primary", TunnelRole::Primary);
        primary.auto_connect = false;
        let profiles = [profile("secondary", TunnelRole::Secondary), primary];
        let calls = RefCell::new(Vec::new());
        let result = execute_auto_connect(
            &profiles,
            |p| {
                Ok(if p.id == "primary" {
                    TunnelState::Running
                } else {
                    TunnelState::Stopped
                })
            },
            |p| {
                calls.borrow_mut().push(p.id.clone());
                Ok(())
            },
        );
        assert_eq!(*calls.borrow(), ["secondary"]);
        assert_eq!(result.failed_count, 0);
    }

    #[derive(Clone, Default)]
    struct Secrets(Arc<Mutex<Option<Vec<u8>>>>);
    impl SecretStore for Secrets {
        fn load(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save(&self, _: &str, bytes: &[u8]) -> std::io::Result<()> {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
        fn delete(&self, _: &str) -> std::io::Result<()> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    #[test]
    fn credential_policy_explicit_no_remember_removes_old_secret() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let secrets = Secrets::default();
        let store = OpenVpnCredentialStore::new(Box::new(secrets.clone()));
        let p = Profile {
            id: "vpn".into(),
            backend: TunnelBackend::OpenVpn,
            ..Default::default()
        };
        let credentials = OpenVpnCredentials {
            auth_user_pass: Some(net_manager_core::daemon_protocol::OpenVpnUserPass {
                username: "private-user".into(),
                password: "private-password".into(),
            }),
            private_key_passphrase: None,
        };
        assert_eq!(
            apply_credential_policy(&vault, &p, Some(&credentials), &store, true),
            None
        );
        assert!(secrets.0.lock().unwrap().is_some());
        assert_eq!(
            apply_credential_policy(&vault, &p, None, &store, false),
            None
        );
        assert!(
            secrets.0.lock().unwrap().is_some(),
            "implicit reuse preserves credentials"
        );
        assert_eq!(
            apply_credential_policy(&vault, &p, Some(&credentials), &store, false),
            None
        );
        assert!(secrets.0.lock().unwrap().is_none());
    }

    #[test]
    fn explicit_forget_still_removes_keyring_when_managed_config_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let secrets = Secrets::default();
        *secrets.0.lock().unwrap() = Some(b"old remembered secret".to_vec());
        let store = OpenVpnCredentialStore::new(Box::new(secrets.clone()));
        let profile = Profile {
            id: "removed-config".into(),
            backend: TunnelBackend::OpenVpn,
            ..Default::default()
        };
        let result = forget_credentials(&vault, &store, &profile);
        if unsafe { libc::geteuid() } == 0 {
            assert!(result.is_err());
            assert!(secrets.0.lock().unwrap().is_some());
        } else {
            result.unwrap();
            assert!(secrets.0.lock().unwrap().is_none());
        }
    }

    #[test]
    fn startup_result_roundtrip_is_private_bounded_and_rejects_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(auto_connect_result(dir.path()).unwrap(), None);
        let result = AutoConnectResult {
            failed_count: 3,
            startup_failed: true,
        };
        std::fs::write(
            dir.path().join("auto-connect-result.tmp"),
            b"interrupted write",
        )
        .unwrap();
        save_auto_connect_result(dir.path(), result).unwrap();
        assert_eq!(auto_connect_result(dir.path()).unwrap(), Some(result));
        let path = dir.path().join("auto-connect-result.json");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(&path, vec![b' '; 4097]).unwrap();
        assert!(auto_connect_result(dir.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"private").unwrap();
        symlink(&outside, &path).unwrap();
        assert!(auto_connect_result(dir.path()).is_err());
    }
}
