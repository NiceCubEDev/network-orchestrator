//! Linux provider and enrollment operations shared by CLI and GUI adapters.
use crate::linux_engine::{daemon_error, LinuxEngine};
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::*;
use net_manager_core::models::{Profile, TunnelBackend};
use serde_json::Value;
use std::path::Path;

pub fn nm_list(engine: &LinuxEngine) -> Result<NmListResult, String> {
    engine
        .privileged()
        .call(method::NM_LIST, Value::Null)
        .map_err(daemon_error)
}

pub fn nm_set_active(engine: &LinuxEngine, uuid: &str, active: bool) -> Result<(), String> {
    let _: Value = engine
        .privileged()
        .call(
            method::NM_SET_ACTIVE,
            NmSetActiveParams {
                uuid: uuid.into(),
                active,
            },
        )
        .map_err(daemon_error)?;
    Ok(())
}

pub fn tailscale_status(engine: &LinuxEngine) -> Result<TailscaleStatusResult, String> {
    engine
        .privileged()
        .call(method::TAILSCALE_STATUS, Value::Null)
        .map_err(daemon_error)
}

pub fn tailscale_set_running(
    engine: &LinuxEngine,
    running: bool,
) -> Result<TailscaleStatusResult, String> {
    engine
        .privileged()
        .call(
            if running {
                method::TAILSCALE_UP
            } else {
                method::TAILSCALE_DOWN
            },
            Value::Null,
        )
        .map_err(daemon_error)
}

fn public_netbird(mut status: Value) -> Value {
    if let Some(fields) = status.as_object_mut() {
        fields.remove("managementUrl");
    }
    status
}

pub fn netbird_status(root: &Path) -> Result<Value, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("Run NetBird control as your own user, without sudo".into());
    }
    Ok(public_netbird(
        net_manager_core::netbird::NetBird::detect().status_in(&root.join("runtime")),
    ))
}

pub fn netbird_up(
    root: &Path,
    management_url: Option<&str>,
    setup_key: Option<&str>,
) -> Result<Value, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("Run NetBird control as your own user, without sudo".into());
    }
    net_manager_core::netbird::NetBird::detect()
        .up(
            &root.join("runtime"),
            management_url.filter(|value| !value.is_empty()),
            setup_key.filter(|value| !value.is_empty()),
        )
        .map(public_netbird)
}

pub fn netbird_down(root: &Path) -> Result<Value, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("Run NetBird control as your own user, without sudo".into());
    }
    net_manager_core::netbird::NetBird::detect()
        .down_in(&root.join("runtime"))
        .map(public_netbird)
}

fn build_definition(vault: &ConfigVault, profile: &Profile) -> Result<AlwaysOnDefinition, String> {
    let routes = profile.effective_routes();
    net_manager_core::models::validate_secondary(
        profile.tunnel_role,
        &routes,
        &profile.tunnel_dns_domains,
    )
    .map_err(str::to_string)?;
    match profile.backend {
        TunnelBackend::WireGuard => {
            use std::io::Read;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
            if !vault.is_managed_profile_path(&profile.id, &profile.config_path)
                || profile.config_path.to_string_lossy().ends_with(".dpapi")
            {
                return Err("always-on WireGuard requires its own managed config".into());
            }
            let revision = profile
                .config_path
                .parent()
                .ok_or("managed WireGuard config is invalid")?;
            let profile_dir = revision
                .parent()
                .ok_or("managed WireGuard config is invalid")?;
            for path in [vault.root(), profile_dir, revision] {
                if !std::fs::symlink_metadata(path)
                    .is_ok_and(|metadata| metadata.file_type().is_dir())
                {
                    return Err("managed WireGuard config is invalid".into());
                }
            }
            let metadata = std::fs::symlink_metadata(&profile.config_path)
                .map_err(|_| "managed WireGuard config is unavailable")?;
            if !metadata.file_type().is_file()
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.len() > 256 * 1024
            {
                return Err("managed WireGuard config is invalid".into());
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&profile.config_path)
                .map_err(|_| "managed WireGuard config is unavailable")?;
            let opened = file
                .metadata()
                .map_err(|_| "managed WireGuard config is unavailable")?;
            if !opened.file_type().is_file()
                || opened.ino() != metadata.ino()
                || opened.dev() != metadata.dev()
            {
                return Err("managed WireGuard config is invalid".into());
            }
            let mut bytes = Vec::new();
            file.take(256 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "cannot read managed WireGuard config")?;
            if bytes.len() > 256 * 1024 {
                return Err("managed WireGuard config is too large".into());
            }
            let config =
                String::from_utf8(bytes).map_err(|_| "managed WireGuard config is not UTF-8")?;
            Ok(AlwaysOnDefinition::WireGuard(WireGuardConnectParams {
                profile_id: profile.id.clone(),
                config,
                routes,
                interface_name: crate::linux::link_name_hint(profile),
                role: profile.tunnel_role,
                dns_domains: profile.tunnel_dns_domains.clone(),
            }))
        }
        TunnelBackend::None => {
            let name = profile.interface_name.as_str();
            if name.is_empty()
                || name.len() > 15
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                || routes.is_empty()
            {
                return Err(
                    "always-on static routes require routes and a stable interface name".into(),
                );
            }
            Ok(AlwaysOnDefinition::StaticRoutes(AlwaysOnStaticRoutes {
                profile_id: profile.id.clone(),
                interface_name: name.into(),
                routes,
            }))
        }
        TunnelBackend::OpenVpn | TunnelBackend::Xray => {
            Err("always-on supports only WireGuard and static routes".into())
        }
    }
}

pub fn always_on_list(engine: &LinuxEngine) -> Result<AlwaysOnListResult, String> {
    engine
        .privileged()
        .call(method::ALWAYS_ON_LIST, Value::Null)
        .map_err(daemon_error)
}

pub fn always_on_set(
    engine: &LinuxEngine,
    vault: &ConfigVault,
    profile: &Profile,
) -> Result<AlwaysOnSetResult, String> {
    let definition = build_definition(vault, profile)?;
    engine
        .privileged()
        .call(method::ALWAYS_ON_SET, AlwaysOnSetParams { definition })
        .map_err(daemon_error)
}

pub fn always_on_remove(
    engine: &LinuxEngine,
    kind: AlwaysOnKind,
    profile_id: &str,
) -> Result<AlwaysOnRemoveResult, String> {
    engine
        .privileged()
        .call(
            method::ALWAYS_ON_REMOVE,
            AlwaysOnRemoveParams {
                kind,
                profile_id: profile_id.into(),
            },
        )
        .map_err(daemon_error)
}

pub fn always_on_resume(engine: &LinuxEngine) -> Result<AlwaysOnResumeResult, String> {
    engine
        .privileged()
        .call(method::ALWAYS_ON_RESUME, Value::Null)
        .map_err(daemon_error)
}

pub fn ensure_not_enrolled(engine: &LinuxEngine, profile: &Profile) -> Result<(), String> {
    if matches!(
        profile.backend,
        TunnelBackend::OpenVpn | TunnelBackend::Xray
    ) {
        return Ok(());
    }
    if always_on_list(engine)?
        .profiles
        .iter()
        .any(|item| item.profile_id == profile.id)
    {
        return Err("disable always-on before editing or deleting this profile".into());
    }
    Ok(())
}

pub fn condition_list(engine: &LinuxEngine) -> Result<CondRulesListResult, String> {
    engine
        .privileged()
        .call(method::COND_RULES_LIST, Value::Null)
        .map_err(daemon_error)
}

pub fn condition_put(
    engine: &LinuxEngine,
    rule: ConditionalRouteRule,
) -> Result<CondRulesPutResult, String> {
    engine
        .privileged()
        .call(method::COND_RULES_PUT, CondRulesPutParams { rule })
        .map_err(daemon_error)
}

pub fn condition_remove(
    engine: &LinuxEngine,
    rule_id: &str,
) -> Result<CondRulesRemoveResult, String> {
    engine
        .privileged()
        .call(
            method::COND_RULES_REMOVE,
            CondRulesRemoveParams {
                rule_id: rule_id.into(),
            },
        )
        .map_err(daemon_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::models::{PolicyRoute, TunnelRole};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fixture() -> (PathBuf, ConfigVault) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "netorch-services-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let vault = ConfigVault::new(root.join("configs"));
        (root, vault)
    }

    #[test]
    fn enrollment_rejects_unsupported_backends_and_unstable_static_interfaces() {
        let (root, vault) = fixture();
        for backend in [TunnelBackend::OpenVpn, TunnelBackend::Xray] {
            let profile = Profile {
                id: "test".into(),
                backend,
                ..Profile::default()
            };
            assert!(build_definition(&vault, &profile).is_err());
        }
        for interface_name in ["", "interface-too-long", "eth0;id", "../eth0"] {
            let profile = Profile {
                id: "test".into(),
                backend: TunnelBackend::None,
                interface_name: interface_name.into(),
                routes: vec![route()],
                ..Profile::default()
            };
            assert!(build_definition(&vault, &profile).is_err());
        }
        let profile = Profile {
            id: "test".into(),
            backend: TunnelBackend::None,
            interface_name: "eth0".into(),
            routes: vec![route()],
            ..Profile::default()
        };
        let AlwaysOnDefinition::StaticRoutes(definition) =
            build_definition(&vault, &profile).unwrap()
        else {
            panic!("expected static routes")
        };
        assert_eq!(definition.routes, profile.routes);
        assert_eq!(definition.interface_name, "eth0");
        std::fs::remove_dir_all(root).unwrap();
    }

    fn route() -> PolicyRoute {
        PolicyRoute {
            destination: "203.0.113.0/24".parse().unwrap(),
            metric: 5,
            via: None,
        }
    }

    #[test]
    fn wireguard_enrollment_only_reads_owned_private_regular_vault_files() {
        let (root, vault) = fixture();
        let config = b"[Interface]\nPrivateKey = test-secret\n";
        let stored = vault.store_wireguard_config("wg1", config).unwrap();
        let profile = Profile {
            id: "wg1".into(),
            backend: TunnelBackend::WireGuard,
            config_path: stored.config_path,
            ..Profile::default()
        };
        let AlwaysOnDefinition::WireGuard(definition) = build_definition(&vault, &profile).unwrap()
        else {
            panic!("expected WireGuard")
        };
        assert_eq!(definition.config.as_bytes(), config);
        assert!(!format!("{definition:?}").contains("test-secret"));
        let external = Profile {
            config_path: root.join("outside.conf"),
            ..profile.clone()
        };
        assert!(build_definition(&vault, &external).is_err());
        std::fs::set_permissions(&profile.config_path, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(build_definition(&vault, &profile).is_err());
        std::fs::remove_file(&profile.config_path).unwrap();
        std::fs::write(root.join("outside.conf"), config).unwrap();
        symlink(root.join("outside.conf"), &profile.config_path).unwrap();
        assert!(build_definition(&vault, &profile).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wireguard_enrollment_preserves_secondary_scope() {
        let (root, vault) = fixture();
        let stored = vault
            .store_wireguard_config("wg1", b"[Interface]\nPrivateKey = test-secret\n")
            .unwrap();
        let profile = Profile {
            id: "wg1".into(),
            backend: TunnelBackend::WireGuard,
            config_path: stored.config_path,
            tunnel_role: TunnelRole::Secondary,
            tunnel_networks: vec!["203.0.113.0/24".parse().unwrap()],
            tunnel_dns_domains: vec!["office.example".into()],
            ..Profile::default()
        };
        let AlwaysOnDefinition::WireGuard(definition) = build_definition(&vault, &profile).unwrap()
        else {
            panic!("expected WireGuard")
        };
        assert_eq!(definition.role, TunnelRole::Secondary);
        assert_eq!(definition.routes, profile.effective_routes());
        assert_eq!(definition.dns_domains, profile.tunnel_dns_domains);
        let invalid = Profile {
            tunnel_networks: vec![],
            ..profile
        };
        assert!(build_definition(&vault, &invalid).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
