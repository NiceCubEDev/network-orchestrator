//! Shared, local-only share-link import. Never starts a VPN or changes networking.
use crate::{
    analysis,
    config_vault::ConfigVault,
    models::*,
    profiles::{ProfileDocument, ProfileStore},
    xray,
};
use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const AUTO_SOCKS_PORT_START: u16 = 10808;
const AUTO_SOCKS_PORT_END: u16 = 10999;

pub fn select_available_socks_port(
    used: &HashSet<u16>,
    available: impl Fn(u16) -> bool,
) -> io::Result<u16> {
    (AUTO_SOCKS_PORT_START..=AUTO_SOCKS_PORT_END)
        .find(|port| !used.contains(port) && available(*port))
        .ok_or_else(|| {
            io::Error::other(format!(
                "no available SOCKS5 port in automatic range {AUTO_SOCKS_PORT_START}-{AUTO_SOCKS_PORT_END}"
            ))
        })
}

pub fn select_generated_ports(
    preferred_socks: Option<u16>,
    preferred_http: Option<u16>,
    used: &HashSet<u16>,
    available: impl Fn(u16) -> bool,
) -> io::Result<(u16, u16)> {
    let socks = match preferred_socks {
        Some(port) if port != 0 && !used.contains(&port) && available(port) => port,
        Some(_) => return Err(io::Error::other("SOCKS5 port is unavailable")),
        None => select_available_socks_port(used, &available)?,
    };
    let mut reserved = used.clone();
    reserved.insert(socks);
    let http = match preferred_http {
        Some(port) if port != 0 && !reserved.contains(&port) && available(port) => port,
        _ => select_available_socks_port(&reserved, &available)?,
    };
    Ok((socks, http))
}

/// Replacement listener ports for a connect, when the profile's own SOCKS or
/// HTTP port is already taken by another process. `None` keeps the stored ports.
pub fn select_connect_ports(
    profiles: &[Profile],
    profile: &Profile,
    available: impl Fn(u16) -> bool,
) -> io::Result<Option<(u16, Option<u16>)>> {
    let Some(socks_port) = profile.xray_socks_port else {
        return Ok(None);
    };
    let http_port = profile.xray_http_port;
    let socks_occupied = !available(socks_port);
    let http_occupied = http_port.is_some_and(|port| !available(port));
    if !socks_occupied && !http_occupied {
        return Ok(None);
    }
    let mut used = profile_listener_ports(profiles, &profile.id);
    if let Some(http_port) = http_port {
        used.insert(http_port);
    }
    let socks_port = if socks_occupied {
        select_available_socks_port(&used, &available)?
    } else {
        socks_port
    };
    used.insert(socks_port);
    let http_port = if http_occupied {
        Some(select_available_socks_port(&used, available)?)
    } else {
        http_port
    };
    Ok(Some((socks_port, http_port)))
}

/// Rewrite the SOCKS/HTTP inbound ports of a managed generated Xray config
/// into a new vault revision and point the profile at it.
pub fn rewrite_generated_proxy_ports(
    vault: &ConfigVault,
    profile: &mut Profile,
    new_socks_port: u16,
    new_http_port: Option<u16>,
) -> io::Result<std::path::PathBuf> {
    if profile.backend != TunnelBackend::Xray
        || profile.xray_socks_port.is_none()
        || !vault.is_managed_profile_path(&profile.id, &profile.config_path)
    {
        return Err(io::Error::other(
            "profile does not use a managed generated Xray config",
        ));
    }
    if new_socks_port == 0
        || new_http_port == Some(0)
        || new_http_port == Some(new_socks_port)
        || profile.xray_http_port.is_some() != new_http_port.is_some()
    {
        return Err(io::Error::other(
            "generated Xray listener ports are invalid",
        ));
    }
    let bytes = crate::config_security::read_xray_config(&profile.config_path, &profile.id)?;
    let mut doc: serde_json::Value = serde_json::from_slice(&bytes)?;
    let inbounds = doc
        .get_mut("inbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| io::Error::other("generated config has no inbounds array"))?;
    let inbound = inbounds
        .iter_mut()
        .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some("socks-in"))
        .ok_or_else(|| io::Error::other("generated config has no 'socks-in' inbound"))?;
    inbound["port"] = serde_json::json!(new_socks_port);
    if let Some(http_port) = new_http_port {
        let inbound = inbounds
            .iter_mut()
            .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some("http-in"))
            .ok_or_else(|| io::Error::other("generated config has no 'http-in' inbound"))?;
        inbound["port"] = serde_json::json!(http_port);
    }
    let body = serde_json::to_vec_pretty(&doc)?;
    let import = vault.store_generated_xray(&profile.id, &body)?;
    profile.config_path = import.config_path.clone();
    profile.xray_socks_port = Some(new_socks_port);
    profile.xray_http_port = new_http_port;
    Ok(import.config_path)
}

/// Move a profile off occupied listener ports before connecting: pick free
/// ports, store a new vault revision, persist the profile and drop the old
/// revision. Returns a user-facing notice when a port changed.
pub fn prepare_connect_ports(
    vault: &ConfigVault,
    store: &ProfileStore,
    profile: &mut Profile,
    profiles: &mut [Profile],
    available: impl Fn(u16) -> bool,
) -> io::Result<Option<String>> {
    let old_socks = profile.xray_socks_port;
    let old_http = profile.xray_http_port;
    let Some((new_socks, new_http)) = select_connect_ports(profiles, profile, available)? else {
        return Ok(None);
    };
    let old_path = profile.config_path.clone();
    rewrite_generated_proxy_ports(vault, profile, new_socks, new_http)?;
    let updated = store.update_profile(&profile.id, |stored| {
        if stored.config_path != old_path
            || stored.xray_socks_port != old_socks
            || stored.xray_http_port != old_http
        {
            return Err(io::Error::other(
                "profile changed while preparing listener ports",
            ));
        }
        stored.config_path = profile.config_path.clone();
        stored.xray_socks_port = profile.xray_socks_port;
        stored.xray_http_port = profile.xray_http_port;
        Ok(())
    });
    let document = match updated {
        Ok(document) => document,
        Err(error) => {
            let _ = vault.remove_revision_for_config(&profile.config_path);
            return Err(error);
        }
    };
    *profile = document
        .profiles
        .into_iter()
        .find(|stored| stored.id == profile.id)
        .expect("updated profile remains in its document");
    if let Some(stored) = profiles.iter_mut().find(|stored| stored.id == profile.id) {
        *stored = profile.clone();
    }
    if vault.is_managed_profile_path(&profile.id, &old_path) {
        vault.remove_revision_for_config(&old_path)?;
    }
    let mut notices = Vec::new();
    if let Some(port) = old_socks.filter(|port| *port != new_socks) {
        notices.push(format!("SOCKS5 port changed from {port} to {new_socks}."));
    }
    if let (Some(port), Some(new_port)) = (old_http, new_http) {
        if port != new_port {
            notices.push(format!("HTTP port changed from {port} to {new_port}."));
        }
    }
    Ok(Some(notices.join(" ")))
}

pub fn profile_listener_ports(profiles: &[Profile], exclude_id: &str) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for profile in profiles {
        if profile.id == exclude_id {
            continue;
        }
        if let Some(port) = profile.xray_socks_port {
            ports.insert(port);
        }
        if let Some(port) = profile.xray_http_port {
            ports.insert(port);
        }
        if let Ok(analysis) = analysis::analyze_profile(profile) {
            for listener in &analysis.listeners {
                if matches!(
                    listener.address.as_str(),
                    "127.0.0.1" | "0.0.0.0" | "::" | ""
                ) {
                    ports.insert(listener.port);
                }
            }
        }
    }
    ports
}

/// Create a new managed Xray profile, deriving an optional name from the URL fragment.
/// `available` checks listener ports without starting a tunnel; tests inject a fake check.
pub fn import_share_link(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    name: &str,
    link: &str,
    xray_mode: XrayMode,
    available: impl Fn(u16) -> bool,
) -> io::Result<ProfileDocument> {
    crate::config_vault::sanitize_profile_id(id)?;
    let link = link.trim();
    if link.is_empty() || link.len() > 65536 || link.contains(['\r', '\n']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Paste one supported share link",
        ));
    }
    let document = store.load()?;
    if document.profiles.iter().any(|p| p.id == id) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "A profile with this identifier already exists",
        ));
    }
    let used = profile_listener_ports(&document.profiles, id);
    let (socks, http) = select_generated_ports(None, None, &used, available)?;
    let config = xray::generate_share_link_config_with_http(link, socks, http).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid or unsupported share link. Use vless://, hysteria2:// or hy2://.",
        )
    })?;
    let body = serde_json::to_vec_pretty(&config)?;
    let imported = vault.store_generated_xray(id, &body)?;
    let profile = Profile {
        id: id.into(),
        name: if name.trim().is_empty() {
            xray::share_link_name(link).unwrap_or_else(|| "Imported connection".into())
        } else {
            name.trim().into()
        },
        backend: TunnelBackend::Xray,
        config_path: imported.config_path.clone(),
        xray_socks_port: Some(socks),
        xray_http_port: Some(http),
        xray_mode,
        ..Profile::default()
    };
    let result = analysis::analyze_profile(&profile).and_then(|_| store.upsert(profile));
    if result.is_err() {
        let _ = vault.remove_revision_for_config(&imported.config_path);
    }
    result
}

/// Detect a tunnel backend for `path` by extension, with a small content sniff
/// for the ambiguous `.conf` case (WireGuard and OpenVPN both use it).
/// Returns `None` when the extension is unrecognized and no `default` hint is
/// given.
pub fn detect_backend(path: &Path, default: Option<TunnelBackend>) -> Option<TunnelBackend> {
    let lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    if lower.ends_with(".ovpn") {
        return Some(TunnelBackend::OpenVpn);
    }
    if lower.ends_with(".json") {
        return Some(TunnelBackend::Xray);
    }
    if lower.ends_with(".conf.dpapi") {
        return Some(TunnelBackend::WireGuard);
    }
    if lower.ends_with(".conf") {
        if let Ok(bytes) = std::fs::read(path) {
            let head = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]);
            if head.contains("[Interface]") {
                return Some(TunnelBackend::WireGuard);
            }
            for line in head.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("dev ")
                    || trimmed.starts_with("proto ")
                    || trimmed == "client"
                    || trimmed.starts_with("remote ")
                {
                    return Some(TunnelBackend::OpenVpn);
                }
            }
        }
        return default;
    }
    default
}

fn backend_label(backend: TunnelBackend) -> &'static str {
    match backend {
        TunnelBackend::None => "Static routes",
        TunnelBackend::WireGuard => "WireGuard",
        TunnelBackend::OpenVpn => "OpenVPN",
        TunnelBackend::Xray => "Xray",
    }
}

pub fn generate_import_id(index: usize) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("import-{nanos:x}-{index}")
}

/// Pure, testable core of `import_configs_batch`: imports each path into the
/// vault and upserts a profile, collecting per-file errors instead of aborting.
pub fn import_configs_into(
    vault: &ConfigVault,
    store: &ProfileStore,
    paths: &[String],
    default_backend: Option<TunnelBackend>,
    xray_mode: XrayMode,
) -> std::io::Result<BatchImportResult> {
    let mut errors: Vec<BatchImportError> = Vec::new();
    for (index, raw) in paths.iter().enumerate() {
        let path = PathBuf::from(raw);
        let backend = match detect_backend(&path, default_backend) {
            Some(b) => b,
            None => {
                errors.push(BatchImportError {
                    path: raw.clone(),
                    error: "could not determine backend from extension; set a default backend"
                        .into(),
                });
                continue;
            }
        };
        let id = generate_import_id(index);
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{} {}", backend_label(backend), index + 1));
        let import = match vault.import(&id, backend, &path) {
            Ok(import) => import,
            Err(err) => {
                errors.push(BatchImportError {
                    path: raw.clone(),
                    error: err.to_string(),
                });
                continue;
            }
        };
        let config_path = import.config_path.clone();
        let profile = Profile {
            id: id.clone(),
            name,
            backend,
            config_path,
            routes: import.routes,
            xray_mode,
            ..Default::default()
        };
        if let Err(err) = store.upsert(profile) {
            let _ = vault.remove_revision_for_config(&import.config_path);
            errors.push(BatchImportError {
                path: raw.clone(),
                error: err.to_string(),
            });
        }
    }
    let profiles = store.load()?.profiles;
    Ok(BatchImportResult { profiles, errors })
}

#[cfg(test)]
mod tests {
    #[test]
    fn connect_ports_move_only_when_a_listener_port_is_taken() {
        let mut profile = Profile {
            id: "a".into(),
            backend: TunnelBackend::Xray,
            xray_socks_port: Some(10808),
            xray_http_port: Some(10809),
            ..Profile::default()
        };
        assert_eq!(select_connect_ports(&[], &profile, |_| true).unwrap(), None);
        assert_eq!(
            select_connect_ports(&[], &profile, |port| port != 10809).unwrap(),
            Some((10808, Some(10810)))
        );
        let both = select_connect_ports(&[], &profile, |port| !matches!(port, 10808 | 10809));
        assert_eq!(both.unwrap(), Some((10810, Some(10811))));
        profile.xray_socks_port = None;
        assert_eq!(
            select_connect_ports(&[], &profile, |_| false).unwrap(),
            None
        );
    }

    use super::*;
    const LINK: &str = "vless://synthetic-id@node.test:443?security=tls#Lab%20Node";

    #[test]
    fn share_link_import_names_ports_and_duplicate_ids_are_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let doc = import_share_link(
            &vault,
            &store,
            "one",
            "  Custom name  ",
            LINK,
            XrayMode::Socks,
            |p| p != 10808,
        )
        .unwrap();
        assert_eq!(doc.profiles[0].name, "Custom name");
        assert_eq!(doc.profiles[0].xray_socks_port, Some(10809));
        assert_eq!(doc.profiles[0].xray_http_port, Some(10810));
        assert_eq!(doc.profiles[0].xray_mode, XrayMode::Socks);
        let path = doc.profiles[0].config_path.clone();
        assert_eq!(
            import_share_link(
                &vault,
                &store,
                "one",
                "Replacement",
                LINK,
                XrayMode::Socks,
                |_| true
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(store.load().unwrap(), doc);
        assert!(path.exists());
        let doc = import_share_link(
            &vault,
            &store,
            "two",
            "",
            "hy2://synthetic-password@node.test:443",
            XrayMode::Socks,
            |_| true,
        )
        .unwrap();
        assert_eq!(doc.profiles[1].name, "Imported connection");
        assert_ne!(
            doc.profiles[1].xray_socks_port,
            doc.profiles[0].xray_socks_port
        );
        assert_ne!(
            doc.profiles[1].xray_http_port,
            doc.profiles[0].xray_http_port
        );
    }

    #[test]
    fn failed_profile_save_removes_the_generated_revision() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        // The document is absent but its staging path cannot be written.
        std::fs::create_dir(dir.path().join("profiles.json.tmp")).unwrap();
        assert!(import_share_link(
            &vault,
            &store,
            "failed",
            "Lab",
            LINK,
            XrayMode::Socks,
            |_| true
        )
        .is_err());
        assert!(!dir.path().join("profiles.json").exists());
        assert_eq!(
            std::fs::read_dir(vault.root().join("failed"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn imported_file_listeners_are_reserved_even_without_port_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let config = vault.store_generated_xray("file", br#"{"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}"#).unwrap();
        store
            .upsert(Profile {
                id: "file".into(),
                name: "File".into(),
                backend: TunnelBackend::Xray,
                config_path: config.config_path,
                ..Profile::default()
            })
            .unwrap();
        let doc = import_share_link(&vault, &store, "link", "Lab", LINK, XrayMode::Socks, |_| {
            true
        })
        .unwrap();
        assert_eq!(doc.profiles[1].xray_socks_port, Some(10809));
        assert_eq!(doc.profiles[1].xray_http_port, Some(10810));
    }

    #[test]
    fn unavailable_ports_and_multiline_links_write_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        assert!(
            import_share_link(&vault, &store, "none", "", LINK, XrayMode::Socks, |_| false)
                .is_err()
        );
        assert!(import_share_link(
            &vault,
            &store,
            "many",
            "",
            &format!("{LINK}\n{LINK}"),
            XrayMode::Socks,
            |_| true
        )
        .is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[test]
    fn imports_persist_the_explicit_mode_instead_of_the_build_host_default() {
        for mode in [XrayMode::Socks, XrayMode::Tun] {
            let dir = tempfile::tempdir().unwrap();
            let vault = ConfigVault::new(dir.path().join("configs"));
            let store = ProfileStore::new(dir.path().join("profiles.json"));
            let imported =
                import_share_link(&vault, &store, "link", "Link", LINK, mode, |_| true).unwrap();
            assert_eq!(imported.profiles[0].xray_mode, mode);
            assert_eq!(store.load().unwrap().profiles[0].xray_mode, mode);
            let source = dir.path().join("source.json");
            std::fs::write(&source, r#"{"outbounds":[{"protocol":"freedom"}]}"#).unwrap();
            let imported = import_configs_into(
                &vault,
                &store,
                &[source.to_string_lossy().into_owned()],
                None,
                mode,
            )
            .unwrap();
            assert!(imported.errors.is_empty());
            assert!(imported.profiles.iter().all(|p| p.xray_mode == mode));
            assert!(store
                .load()
                .unwrap()
                .profiles
                .iter()
                .all(|p| p.xray_mode == mode));
        }
    }
}
