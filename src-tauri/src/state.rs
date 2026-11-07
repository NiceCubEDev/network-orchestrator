use crate::route_runtime::RouteRuntime;
use net_manager_core::backend_settings::BackendSettingsStore;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::managed_xray;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
use net_manager_core::managed_xray::MANAGED_XRAY_VERSION;
use net_manager_core::models::*;
use net_manager_core::profiles::{ProfileDocument, ProfileStore};
#[cfg(any(not(target_os = "linux"), test))]
use net_manager_core::system_proxy::SystemProxyManager;
use net_manager_core::vpn::{self, TunnelManager};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

pub(crate) struct RuntimeState {
    pub(crate) tunnels: TunnelManager,
    pub(crate) routes: RouteRuntime,
    #[cfg(any(not(target_os = "linux"), test))]
    pub(crate) proxy: SystemProxyManager,
}

#[derive(Debug)]
pub(crate) struct ResolvedBackendExecutable {
    pub(crate) path: PathBuf,
    pub(crate) source: BackendExecutableSource,
    pub(crate) version: Option<String>,
}

pub(crate) struct AppState {
    pub(crate) profiles: ProfileStore,
    pub(crate) config_vault: ConfigVault,
    pub(crate) backend_settings: BackendSettingsStore,
    /// Windows managed-install store root; on 64-bit Linux managed Xray
    /// lives in the daemon-owned package root instead.
    #[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), allow(dead_code))]
    pub(crate) managed_xray_root: PathBuf,
    /// Per-profile downloaded geoip.dat/geosite.dat overrides
    /// (`geoassets/<sha256(url-pair)[:16]>/` — shared between profiles).
    #[cfg(target_os = "linux")]
    pub(crate) geo_assets_root: PathBuf,
    pub(crate) backend_install_lock: tokio::sync::Mutex<()>,
    pub(crate) backend_install_cancel: AtomicBool,
    pub(crate) shutting_down: AtomicBool,
    pub(crate) cleanup_complete: AtomicBool,
    pub(crate) runtime: tokio::sync::Mutex<RuntimeState>,
    /// Bounded app-side event log for the Logs view (connect/disconnect,
    /// errors). Never persisted — ring buffer, newest last.
    pub(crate) log: std::sync::Mutex<std::collections::VecDeque<crate::commands::logs::LogEvent>>,
    #[cfg(target_os = "linux")]
    pub(crate) openvpn_credentials:
        std::sync::Arc<net_manager_engine::linux_credentials::OpenVpnCredentialStore>,
}

pub(crate) fn resolve_backend_path(
    backend: TunnelBackend,
    configured: Option<&Path>,
) -> io::Result<PathBuf> {
    match backend {
        TunnelBackend::None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static-routes backend has no executable",
        )),
        TunnelBackend::WireGuard => vpn::resolve_wireguard_executable(configured),
        TunnelBackend::OpenVpn => vpn::resolve_openvpn_executable(configured),
        TunnelBackend::Xray => vpn::resolve_xray_executable(configured),
    }
}

impl AppState {
    #[cfg(target_os = "linux")]
    pub(crate) fn data_dir(&self) -> &Path {
        self.config_vault
            .root()
            .parent()
            .expect("vault is under the application data directory")
    }

    pub(crate) async fn proxy_ownership(
        &self,
    ) -> io::Result<Option<net_manager_core::system_proxy::ProxyOwnership>> {
        #[cfg(target_os = "linux")]
        {
            net_manager_core::system_proxy::load_ownership(
                &self.data_dir().join("proxy-state.json"),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(self.runtime.lock().await.proxy.ownership().cloned())
        }
    }

    pub(crate) fn resolve_backend_executable(
        &self,
        backend: TunnelBackend,
    ) -> io::Result<ResolvedBackendExecutable> {
        match self.backend_settings.get(backend)? {
            None => Ok(ResolvedBackendExecutable {
                path: resolve_backend_path(backend, None)?,
                source: BackendExecutableSource::AutoDetected,
                version: None,
            }),
            Some(setting) => match setting.source {
                BackendExecutableSource::AutoDetected => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "persisted auto-detected backend source is not valid",
                )),
                BackendExecutableSource::Configured => Ok(ResolvedBackendExecutable {
                    path: resolve_backend_path(backend, Some(&setting.path))?,
                    source: BackendExecutableSource::Configured,
                    version: setting.version,
                }),
                BackendExecutableSource::Managed => {
                    if backend != TunnelBackend::Xray {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "managed executables are only supported for the Xray backend",
                        ));
                    }
                    // Linux managed installs live in the daemon-owned
                    // package root; Windows keeps a user-owned store under
                    // `managed_xray_root`. Each verifies against its own
                    // pinned version and file hashes.
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    {
                        if setting.version.as_deref() != Some(managed_xray::LINUX_XRAY_VERSION) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "managed Xray setting does not match the managed version",
                            ));
                        }
                        managed_xray::verify_managed_linux_executable(
                            Path::new(managed_xray::LINUX_XRAY_PACKAGE_ROOT),
                            &setting.path,
                        )?;
                    }
                    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                    {
                        if setting.version.as_deref() != Some(MANAGED_XRAY_VERSION) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "managed Xray setting does not match the managed version",
                            ));
                        }
                        managed_xray::verify_managed_executable(
                            &self.managed_xray_root,
                            &setting.path,
                        )?;
                    }
                    Ok(ResolvedBackendExecutable {
                        path: vpn::resolve_xray_executable(Some(&setting.path))?,
                        source: BackendExecutableSource::Managed,
                        version: setting.version,
                    })
                }
            },
        }
    }
}

pub(crate) fn build_state(data_dir: PathBuf) -> std::io::Result<AppState> {
    let store = ProfileStore::new(data_dir.join("profiles.json"));
    let routes = RouteRuntime::new(&data_dir)?;
    let config_vault = ConfigVault::new(data_dir.join("configs"));
    config_vault.ensure_root_protected()?;
    let backend_settings = BackendSettingsStore::new(data_dir.join("backend-settings.json"));
    let backend_document = backend_settings.load()?;
    let setting_path = |setting: Option<net_manager_core::models::BackendExecutableSetting>| {
        setting.map(|s| s.path)
    };
    Ok(AppState {
        profiles: store,
        config_vault,
        backend_settings,
        managed_xray_root: data_dir.join("backends").join("xray"),
        #[cfg(target_os = "linux")]
        geo_assets_root: data_dir.join("geoassets"),
        backend_install_lock: tokio::sync::Mutex::new(()),
        backend_install_cancel: AtomicBool::new(false),
        shutting_down: AtomicBool::new(false),
        cleanup_complete: AtomicBool::new(false),
        runtime: tokio::sync::Mutex::new(RuntimeState {
            tunnels: TunnelManager::with_all_executables_and_log_dir(
                setting_path(backend_document.wire_guard),
                setting_path(backend_document.open_vpn),
                setting_path(backend_document.xray),
                data_dir.join("logs"),
            ),
            routes,
            #[cfg(any(not(target_os = "linux"), test))]
            proxy: SystemProxyManager::new(data_dir.join("proxy-state.json"))?,
        }),
        log: std::sync::Mutex::new(std::collections::VecDeque::new()),
        #[cfg(target_os = "linux")]
        openvpn_credentials: std::sync::Arc::new(
            net_manager_engine::linux_credentials::OpenVpnCredentialStore::new(Box::new(
                net_manager_engine::linux_credentials::SecretServiceStore,
            )),
        ),
    })
}

pub(crate) fn find_profile(store: &ProfileStore, id: &str) -> Result<Profile, String> {
    store
        .load()
        .map_err(|e| e.to_string())?
        .profiles
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| format!("profile '{id}' not found"))
}

pub(crate) fn existing_profile_for_update<'a>(
    document: &'a ProfileDocument,
    incoming_id: &str,
) -> Option<&'a Profile> {
    document.profiles.iter().find(|p| p.id == incoming_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use std::fs;

    #[test]
    fn update_status_check_selects_stored_profile_backend() {
        let mut stored = profile("wg-work");
        stored.backend = TunnelBackend::WireGuard;
        let document = ProfileDocument {
            version: 1,
            profiles: vec![stored.clone()],
        };
        let mut incoming = stored.clone();
        incoming.backend = TunnelBackend::OpenVpn;

        let selected = existing_profile_for_update(&document, &incoming.id).unwrap();

        assert_eq!(selected.backend, TunnelBackend::WireGuard);
        assert_eq!(selected, &stored);
    }

    #[test]
    fn update_status_check_returns_none_for_new_profile() {
        let document = ProfileDocument {
            version: 1,
            profiles: vec![profile("wg-work")],
        };
        assert!(existing_profile_for_update(&document, "other-id").is_none());
    }

    #[test]
    fn configured_backend_resolution_uses_persisted_path() {
        let dir = unique_dir("resolve-cfg");
        let state = app_state(&dir);
        let exe = dir.join("custom-xray.exe");
        fs::write(&exe, b"MZ").unwrap();
        state
            .backend_settings
            .set(
                TunnelBackend::Xray,
                Some(BackendExecutableSetting {
                    path: exe.clone(),
                    source: BackendExecutableSource::Configured,
                    version: None,
                }),
            )
            .unwrap();

        let resolved = state
            .resolve_backend_executable(TunnelBackend::Xray)
            .unwrap();

        assert_eq!(resolved.path, exe);
        assert_eq!(resolved.source, BackendExecutableSource::Configured);
        assert_eq!(resolved.version, None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn managed_backend_resolution_rejects_tampered_binary() {
        let dir = unique_dir("resolve-mg");
        let state = app_state(&dir);
        let version_dir = state
            .managed_xray_root
            .join(net_manager_core::managed_xray::MANAGED_XRAY_VERSION);
        fs::create_dir_all(&version_dir).unwrap();
        for name in ["xray.exe", "geoip.dat", "geosite.dat"] {
            fs::write(version_dir.join(name), b"tampered").unwrap();
        }
        state
            .backend_settings
            .set(
                TunnelBackend::Xray,
                Some(BackendExecutableSetting {
                    path: version_dir.join("xray.exe"),
                    source: BackendExecutableSource::Managed,
                    version: Some(net_manager_core::managed_xray::MANAGED_XRAY_VERSION.into()),
                }),
            )
            .unwrap();

        let err = state
            .resolve_backend_executable(TunnelBackend::Xray)
            .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn managed_backend_resolution_rejects_non_xray_backend() {
        let dir = unique_dir("resolve-mg-wg");
        let state = app_state(&dir);
        state
            .backend_settings
            .set(
                TunnelBackend::WireGuard,
                Some(BackendExecutableSetting {
                    path: dir.join("wg.exe"),
                    source: BackendExecutableSource::Managed,
                    version: Some("v1".into()),
                }),
            )
            .unwrap();

        let err = state
            .resolve_backend_executable(TunnelBackend::WireGuard)
            .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }
}
