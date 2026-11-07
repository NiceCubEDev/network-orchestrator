use crate::models::{Profile, TunnelBackend};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::PathBuf;

pub const PROFILE_DOCUMENT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDocument {
    pub version: u32,
    pub profiles: Vec<Profile>,
}

pub struct ProfileStore {
    path: PathBuf,
}

impl ProfileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> io::Result<ProfileDocument> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(ProfileDocument {
                    version: PROFILE_DOCUMENT_VERSION,
                    profiles: Vec::new(),
                });
            }
            Err(err) => return Err(err),
        };
        let document: ProfileDocument =
            serde_json::from_str(&raw).map_err(|_| invalid_data("invalid profile document"))?;
        if document.version != PROFILE_DOCUMENT_VERSION {
            return Err(invalid_data(format!(
                "unsupported profile document version {}",
                document.version
            )));
        }
        for profile in &document.profiles {
            crate::service_checks::validate_profile_service_checks(profile)?;
            crate::proxy_exits::validate_profile_proxy_exits(profile)?;
        }
        Ok(document)
    }

    pub fn save(&self, document: &ProfileDocument) -> io::Result<()> {
        // Reject invalid input before creating even the transaction lock.
        for profile in &document.profiles {
            crate::service_checks::validate_profile_service_checks(profile)?;
            crate::proxy_exits::validate_profile_proxy_exits(profile)?;
        }
        let _guard = self.lock()?;
        self.save_locked(document)
    }

    /// A separate file survives atomic replacement of the document. Each
    /// transaction opens its own handle, so threads and other processes use
    /// the same OS lock; dropping the handle releases it even on errors.
    fn lock(&self) -> io::Result<fs::File> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            crate::config_security::protect_path(parent)?;
        }
        let mut name = self.path.clone().into_os_string();
        name.push(".lock");
        let path = PathBuf::from(name);
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|_| io::Error::other("cannot open profile transaction lock"))?;
        crate::config_security::protect_path(&path)?;
        file.lock()
            .map_err(|_| io::Error::other("cannot lock profile store"))?;
        Ok(file)
    }

    fn save_locked(&self, document: &ProfileDocument) -> io::Result<()> {
        for profile in &document.profiles {
            crate::service_checks::validate_profile_service_checks(profile)?;
            crate::proxy_exits::validate_profile_proxy_exits(profile)?;
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            crate::config_security::protect_path(parent)?;
        }
        let json = serde_json::to_string_pretty(document)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let mut temp_name = self.path.clone().into_os_string();
        temp_name.push(".tmp");
        let temp_path = PathBuf::from(temp_name);
        fs::write(&temp_path, json)?;
        crate::config_security::protect_path(&temp_path)?;
        if let Err(err) = fs::rename(&temp_path, &self.path) {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
        Ok(())
    }

    pub fn upsert(&self, profile: Profile) -> io::Result<ProfileDocument> {
        validate_profile(&profile)?;
        let _guard = self.lock()?;
        let mut document = self.load()?;
        if let Some(existing) = document.profiles.iter_mut().find(|p| p.id == profile.id) {
            *existing = profile;
        } else {
            document.profiles.push(profile);
        }
        self.save_locked(&document)?;
        Ok(document)
    }

    /// Change one existing profile under the store transaction, preserving
    /// unrelated edits made while a network operation was in flight.
    pub fn update_profile(
        &self,
        id: &str,
        update: impl FnOnce(&mut Profile) -> io::Result<()>,
    ) -> io::Result<ProfileDocument> {
        let _guard = self.lock()?;
        let mut document = self.load()?;
        let profile = document
            .profiles
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "profile not found"))?;
        update(profile)?;
        validate_profile(profile)?;
        self.save_locked(&document)?;
        Ok(document)
    }

    /// Flags whether the app starts this profile when it launches.
    pub fn set_auto_connect(&self, id: &str, enabled: bool) -> io::Result<ProfileDocument> {
        let _guard = self.lock()?;
        let mut document = self.load()?;
        let profile = document
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("profile '{id}' not found"))
            })?;
        profile.auto_connect = enabled;
        self.save_locked(&document)?;
        Ok(document)
    }

    /// Whether a static-route profile arms its routes while the interface is
    /// absent (true) or refuses to connect (false).
    pub fn set_wait_for_interface(&self, id: &str, enabled: bool) -> io::Result<ProfileDocument> {
        let _guard = self.lock()?;
        let mut document = self.load()?;
        let profile = document
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("profile '{id}' not found"))
            })?;
        profile.wait_for_interface = enabled;
        self.save_locked(&document)?;
        Ok(document)
    }

    pub fn delete(&self, id: &str) -> io::Result<ProfileDocument> {
        let _guard = self.lock()?;
        let mut document = self.load()?;
        let len_before = document.profiles.len();
        document.profiles.retain(|p| p.id != id);
        if document.profiles.len() == len_before {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("profile '{id}' not found"),
            ));
        }
        self.save_locked(&document)?;
        Ok(document)
    }

    /// Reorders the profiles of one backend group in place. `ordered_ids`
    /// must be exactly the ids of the stored profiles with `backend`, in the
    /// desired order; profiles of other backends keep their positions.
    pub fn reorder(
        &self,
        backend: TunnelBackend,
        ordered_ids: &[String],
    ) -> io::Result<ProfileDocument> {
        let _guard = self.lock()?;
        let mut document = self.load()?;
        let positions: Vec<usize> = document
            .profiles
            .iter()
            .enumerate()
            .filter(|(_, p)| p.backend == backend)
            .map(|(i, _)| i)
            .collect();
        if positions.len() != ordered_ids.len() {
            return Err(invalid_input(
                "reorder must list every profile of the group exactly once",
            ));
        }
        let mut seen = HashSet::with_capacity(ordered_ids.len());
        let mut ordered: Vec<Profile> = Vec::with_capacity(ordered_ids.len());
        for id in ordered_ids {
            if !seen.insert(id.as_str()) {
                return Err(invalid_input(format!(
                    "reorder lists profile '{id}' more than once"
                )));
            }
            let profile = document
                .profiles
                .iter()
                .find(|p| p.backend == backend && p.id == *id)
                .ok_or_else(|| {
                    invalid_input(format!("profile '{id}' is not in the reordered group"))
                })?;
            ordered.push(profile.clone());
        }
        let mut ordered = ordered.into_iter();
        for &index in &positions {
            document.profiles[index] = ordered.next().expect("queue covers the group");
        }
        self.save_locked(&document)?;
        Ok(document)
    }
}

pub fn validate_profile(profile: &Profile) -> io::Result<()> {
    if profile.id.trim().is_empty() {
        return Err(invalid_data("profile id must not be blank"));
    }
    if profile.name.trim().is_empty() {
        return Err(invalid_data("profile name must not be blank"));
    }
    if profile.backend != TunnelBackend::None
        && profile.config_path.to_string_lossy().trim().is_empty()
    {
        return Err(invalid_data("profile config path must not be blank"));
    }
    let daemon_assigned_interface = cfg!(target_os = "linux")
        && (matches!(
            profile.backend,
            TunnelBackend::WireGuard | TunnelBackend::OpenVpn
        ) || (profile.backend == TunnelBackend::Xray
            && profile.xray_mode == crate::models::XrayMode::Tun));
    // Нативный клиент macOS импортирует и анализирует OpenVPN без запуска туннеля.
    let read_only_openvpn = cfg!(target_os = "macos") && profile.backend == TunnelBackend::OpenVpn;
    // Static routes that all name their own gateway go through no interface.
    let gateway_only = profile.backend == TunnelBackend::None
        && profile.routes.iter().all(|route| route.via.is_some());
    if !profile.routes.is_empty()
        && profile.interface_name.trim().is_empty()
        && !daemon_assigned_interface
        && !read_only_openvpn
        && !gateway_only
    {
        return Err(invalid_data(
            "profile interface name must not be blank when policy routes are set",
        ));
    }
    for route in &profile.routes {
        if route.metric > 9999 {
            return Err(invalid_data(format!(
                "route metric {} exceeds maximum 9999",
                route.metric
            )));
        }
        if let Some(via) = route.via {
            if via.is_unspecified() {
                return Err(invalid_data(format!(
                    "route {} gateway must not be unspecified",
                    route.destination
                )));
            }
            if via.is_ipv4() != matches!(route.destination, ipnet::IpNet::V4(_)) {
                return Err(invalid_data(format!(
                    "route {} gateway {via} is from a different address family",
                    route.destination
                )));
            }
        }
    }
    crate::service_checks::validate_profile_service_checks(profile)?;
    crate::proxy_exits::validate_profile_proxy_exits(profile)?;
    if profile.backend != TunnelBackend::Xray && !profile.domain_policies.is_empty() {
        return Err(invalid_data(
            "domain policies are only supported for Xray profiles",
        ));
    }
    if profile.backend == TunnelBackend::Xray {
        crate::xray::validate_routing_policy_selectors(&profile.domain_policies)
            .map_err(|error| invalid_data(error.to_string()))?;
        crate::xray::validate_dns_config(&profile.xray_dns)
            .map_err(|error| invalid_data(error.to_string()))?;
        crate::xray::validate_advanced_routing_options(
            &profile.xray_traffic_rules,
            &profile.xray_interface_routes,
            profile.xray_sockopts.as_ref(),
            profile.xray_connection_idle_secs,
            profile.xray_direct_domain_strategy.as_deref(),
        )
        .map_err(|error| invalid_data(error.to_string()))?;
        crate::xray::validate_tun_profile_settings(
            profile.xray_tun_mtu,
            &profile.xray_tun_dns_servers,
        )
        .map_err(|error| invalid_data(error.to_string()))?;
        crate::xray::validate_pinned_routes(&profile.pinned_policies)
            .map_err(|error| invalid_data(error.to_string()))?;
        for policy in &profile.domain_policies {
            if policy.domains.is_empty() {
                return Err(invalid_data("domain policy must list at least one domain"));
            }
            if policy.domains.iter().any(|domain| domain.trim().is_empty()) {
                return Err(invalid_data("domain policy must not contain blank domains"));
            }
        }
        if matches!(profile.xray_socks_port, Some(0)) {
            return Err(invalid_data("xray socks port must be nonzero"));
        }
        if matches!(profile.xray_http_port, Some(0)) {
            return Err(invalid_data("xray http port must be nonzero"));
        }
        if profile.xray_socks_port.is_some() && profile.xray_socks_port == profile.xray_http_port {
            return Err(invalid_data("xray socks and http ports must be different"));
        }
    }
    if profile.use_system_proxy {
        if profile.backend != TunnelBackend::Xray {
            return Err(invalid_data(
                "system proxy is only supported for Xray profiles",
            ));
        }
        match profile.xray_socks_port {
            Some(port) if port != 0 => {}
            _ => {
                return Err(invalid_data(
                    "system proxy requires a nonzero xray socks port",
                ));
            }
        }
    }
    for entry in &profile.proxy_bypass {
        if entry.trim().is_empty() {
            return Err(invalid_data("proxy bypass entries must not be blank"));
        }
        if entry.contains(';') {
            return Err(invalid_data("proxy bypass entries must not contain ';'"));
        }
    }
    let file_name = profile
        .config_path
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let allowed = match profile.backend {
        TunnelBackend::None => true,
        TunnelBackend::WireGuard => {
            file_name.ends_with(".conf") || file_name.ends_with(".conf.dpapi")
        }
        TunnelBackend::OpenVpn => file_name.ends_with(".ovpn") || file_name.ends_with(".conf"),
        TunnelBackend::Xray => file_name.ends_with(".json") || file_name.ends_with(".json.dpapi"),
    };
    if !allowed {
        return Err(invalid_data(format!(
            "config path '{}' has an unsupported extension for {:?}",
            profile.config_path.display(),
            profile.backend
        )));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DomainPolicy, DomainRouteTarget, PolicyRoute, TunnelBackend};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-profiles-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wg_profile() -> Profile {
        Profile {
            id: "work-wg".into(),
            name: "Work WireGuard".into(),
            backend: TunnelBackend::WireGuard,
            config_path: PathBuf::from(r"C:\configs\work.conf"),
            interface_name: "wg-work".into(),
            routes: vec![PolicyRoute {
                destination: "10.7.0.0/24".parse().unwrap(),
                metric: 5,
                via: None,
            }],
            auto_connect: true,
            ..Default::default()
        }
    }

    #[test]
    fn independent_stores_preserve_concurrent_profile_edits() {
        let dir = unique_dir("concurrent-stores");
        let path = dir.join("profiles.json");
        let store = ProfileStore::new(path.clone());
        let mut profile = wg_profile();
        profile.name = "0".into();
        let id = profile.id.clone();
        store.upsert(profile).unwrap();
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                let id = id.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    let independent = ProfileStore::new(path);
                    start.wait();
                    for _ in 0..16 {
                        independent
                            .update_profile(&id, |profile| {
                                let previous: usize = profile.name.parse().unwrap();
                                profile.name = (previous + 1).to_string();
                                Ok(())
                            })
                            .unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(store.load().unwrap().profiles[0].name, "128");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn service_checks_refuse_non_https_destinations_before_persistence() {
        let mut profile = wg_profile();
        profile.backend = TunnelBackend::Xray;
        profile.config_path = PathBuf::from("service-checks.json");
        let mut value = serde_json::to_value(profile).unwrap();
        value["xrayServiceChecks"] = serde_json::json!([{
            "id": "service-example",
            "name": "Example availability",
            "url": "http://example.test/",
            "endpointKey": "1111111111111111",
            "background": false
        }]);
        value["subscription"] = serde_json::json!({
            "url": "https://subscription.example.test/synthetic",
            "hwid": "",
            "endpointCount": 1,
            "activeIndex": 0
        });
        value["xrayServiceChecks"][0]["url"] = serde_json::json!("https://example.test/");
        let valid: Profile = serde_json::from_value(value.clone()).unwrap();
        validate_profile(&valid).unwrap();
        value["xrayServiceChecks"][0]["url"] = serde_json::json!("http://example.test/");
        let invalid: Profile = serde_json::from_value(value).unwrap();
        assert!(validate_profile(&invalid).is_err());
    }

    #[test]
    fn named_proxy_exits_refuse_executable_configuration() {
        let mut profile = wg_profile();
        profile.backend = TunnelBackend::Xray;
        profile.config_path = PathBuf::from("named-proxy.json");
        let mut value = serde_json::to_value(profile).unwrap();
        value["xrayProxyExits"] = serde_json::json!([{
            "name": "default",
            "target": {"kind": "rules"},
            "noProxy": [],
            "command": ["sh", "-c", "exit 0"]
        }]);
        assert!(serde_json::from_value::<Profile>(value).is_err());
    }

    fn subscription_meta() -> crate::models::SubscriptionMeta {
        serde_json::from_value(serde_json::json!({
            "url": "https://subscription.example.test/synthetic",
            "hwid": "",
            "endpointCount": 2,
            "activeIndex": 0
        }))
        .unwrap()
    }

    fn xray_sub_profile() -> Profile {
        let mut profile = wg_profile();
        profile.id = "proxy-host".into();
        profile.backend = TunnelBackend::Xray;
        profile.config_path = PathBuf::from("proxy-host.json");
        profile.subscription = Some(subscription_meta());
        profile
    }

    #[test]
    fn named_proxy_exits_persist_and_validate_boundaries() {
        use crate::models::{NamedProxyExit, ProxyTarget};

        // A valid mixed spec survives a store round trip with order intact.
        let dir = unique_dir("named-exits");
        let store = ProfileStore::new(dir.join("profiles.json"));
        let mut profile = xray_sub_profile();
        profile.xray_proxy_exits = vec![
            NamedProxyExit {
                name: "work".into(),
                target: ProxyTarget::Node {
                    endpoint_key: "1111111111111111".into(),
                },
                no_proxy: vec!["intranet.corp".into(), "10.0.0.0/8".into()],
            },
            NamedProxyExit {
                name: "media-pool".into(),
                target: ProxyTarget::Pool {
                    endpoint_keys: vec!["2222222222222222".into(), "3333333333333333".into()],
                },
                no_proxy: Vec::new(),
            },
            NamedProxyExit {
                name: "direct".into(),
                target: ProxyTarget::Direct,
                no_proxy: Vec::new(),
            },
        ];
        store.upsert(profile).unwrap();
        let stored = store.load().unwrap().profiles.remove(0);
        assert_eq!(stored.xray_proxy_exits.len(), 3);
        assert_eq!(stored.xray_proxy_exits[0].name, "work");
        assert_eq!(stored.xray_proxy_exits[0].no_proxy.len(), 2);
        assert!(matches!(
            stored.xray_proxy_exits[1].target,
            ProxyTarget::Pool { .. }
        ));

        // Rejected on upsert (validated before persistence): bad or
        // reserved names, duplicates, malformed key rules.
        let mut bad = xray_sub_profile();
        for name in ["list", "set", "remove", "help", "UPPER", "-lead", "a b"] {
            bad.xray_proxy_exits = vec![NamedProxyExit {
                name: name.into(),
                target: ProxyTarget::Direct,
                no_proxy: Vec::new(),
            }];
            assert!(
                store.upsert(bad.clone()).is_err(),
                "name {name:?} must be rejected"
            );
        }
        bad.xray_proxy_exits = vec![
            NamedProxyExit {
                name: "a".into(),
                target: ProxyTarget::Direct,
                no_proxy: Vec::new(),
            },
            NamedProxyExit {
                name: "a".into(),
                target: ProxyTarget::Rules,
                no_proxy: Vec::new(),
            },
        ];
        assert!(store.upsert(bad.clone()).is_err(), "duplicate names");
        for target in [
            ProxyTarget::Node {
                endpoint_key: "nothex".into(),
            },
            ProxyTarget::Node {
                endpoint_key: "AAAAAAAAAAAAAAAA".into(),
            },
            ProxyTarget::Pool {
                endpoint_keys: Vec::new(),
            },
            ProxyTarget::Pool {
                endpoint_keys: vec!["1111111111111111".into(), "1111111111111111".into()],
            },
            ProxyTarget::Pool {
                endpoint_keys: (0..9).map(|i| format!("{i:016x}")).collect(),
            },
        ] {
            bad.xray_proxy_exits = vec![NamedProxyExit {
                name: "ok".into(),
                target,
                no_proxy: Vec::new(),
            }];
            assert!(store.upsert(bad.clone()).is_err(), "bad target rejected");
        }
        for entry in [
            "",
            "has space",
            "user@host",
            "host?query",
            "a,b",
            "semi;colon",
        ] {
            bad.xray_proxy_exits = vec![NamedProxyExit {
                name: "ok".into(),
                target: ProxyTarget::Direct,
                no_proxy: vec![entry.into()],
            }];
            assert!(
                store.upsert(bad.clone()).is_err(),
                "noProxy {entry:?} must be rejected"
            );
        }
        // 17 exits exceed the listener slot budget.
        bad.xray_proxy_exits = (0..crate::proxy_exits::MAX_PROXY_EXITS + 1)
            .map(|i| NamedProxyExit {
                name: format!("exit{i}"),
                target: ProxyTarget::Direct,
                no_proxy: Vec::new(),
            })
            .collect();
        assert!(store.upsert(bad.clone()).is_err(), "exit count budget");
        // A 34th distinct pin key exceeds the daemon pin-listener budget.
        let mut over = xray_sub_profile();
        over.pinned_policies = (0..32)
            .map(|i| crate::models::PinnedRoute {
                selectors: vec![format!("domain:{i}.test")],
                endpoint_key: format!("{i:016x}"),
                missing: false,
            })
            .collect();
        over.xray_dns.outbound_key = Some("eeeeeeeeeeeeeeee".into());
        over.xray_proxy_exits = vec![NamedProxyExit {
            name: "spare".into(),
            target: ProxyTarget::Node {
                endpoint_key: "ffffffffffffffff".into(),
            },
            no_proxy: Vec::new(),
        }];
        assert!(store.upsert(over).is_err(), "33-key pin budget");

        // Node/pool exits need subscription metadata; rules/direct do not.
        let mut plain = xray_sub_profile();
        plain.subscription = None;
        plain.xray_proxy_exits = vec![NamedProxyExit {
            name: "work".into(),
            target: ProxyTarget::Node {
                endpoint_key: "1111111111111111".into(),
            },
            no_proxy: Vec::new(),
        }];
        assert!(
            store.upsert(plain.clone()).is_err(),
            "node without subscription"
        );
        plain.xray_proxy_exits = vec![
            NamedProxyExit {
                name: "lax".into(),
                target: ProxyTarget::Rules,
                no_proxy: Vec::new(),
            },
            NamedProxyExit {
                name: "out".into(),
                target: ProxyTarget::Direct,
                no_proxy: Vec::new(),
            },
        ];
        store.upsert(plain).unwrap();
        // Non-Xray backends cannot carry exits at all.
        let mut wg = wg_profile();
        wg.id = "wg-exits".into();
        wg.xray_proxy_exits = vec![NamedProxyExit {
            name: "lax".into(),
            target: ProxyTarget::Direct,
            no_proxy: Vec::new(),
        }];
        assert!(store.upsert(wg).is_err(), "non-Xray exits rejected");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn auto_connect_flag_is_persisted_per_profile_and_unknown_ids_fail() {
        let dir = unique_dir("auto-connect-flag");
        let store = ProfileStore::new(dir.join("profiles.json"));
        let mut a = wg_profile();
        a.id = "a".into();
        a.auto_connect = false;
        let mut b = wg_profile();
        b.id = "b".into();
        b.auto_connect = false;
        store.upsert(a).unwrap();
        store.upsert(b).unwrap();

        let document = store.set_auto_connect("b", true).unwrap();
        assert!(!document.profiles[0].auto_connect);
        assert!(document.profiles[1].auto_connect);
        assert!(store.load().unwrap().profiles[1].auto_connect);

        let document = store.set_auto_connect("b", false).unwrap();
        assert!(!document.profiles[1].auto_connect);

        let err = store.set_auto_connect("missing", true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wait_for_interface_is_persisted_per_profile_and_unknown_ids_fail() {
        let dir = unique_dir("wait-for-interface");
        let store = ProfileStore::new(dir.join("profiles.json"));
        let mut a = wg_profile();
        a.id = "a".into();
        let mut b = wg_profile();
        b.id = "b".into();
        store.upsert(a).unwrap();
        store.upsert(b).unwrap();

        let document = store.set_wait_for_interface("b", true).unwrap();
        assert!(!document.profiles[0].wait_for_interface);
        assert!(document.profiles[1].wait_for_interface);
        assert!(store.load().unwrap().profiles[1].wait_for_interface);
        let document = store.set_wait_for_interface("b", false).unwrap();
        assert!(!document.profiles[1].wait_for_interface);
        let err = store.set_wait_for_interface("missing", true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reorder_permutates_only_the_target_backend() {
        let dir = unique_dir("reorder");
        let store = ProfileStore::new(dir.join("profiles.json"));
        let mut wg_a = wg_profile();
        wg_a.id = "wg-a".into();
        let mut xray = xray_profile();
        xray.id = "xr-1".into();
        let mut wg_b = wg_profile();
        wg_b.id = "wg-b".into();
        let mut ovpn = wg_profile();
        ovpn.id = "ov-1".into();
        ovpn.backend = TunnelBackend::OpenVpn;
        let mut wg_c = wg_profile();
        wg_c.id = "wg-c".into();
        for profile in [&wg_a, &xray, &wg_b, &ovpn, &wg_c] {
            store.upsert(profile.clone()).unwrap();
        }

        let doc = store
            .reorder(
                TunnelBackend::WireGuard,
                &["wg-c".into(), "wg-a".into(), "wg-b".into()],
            )
            .unwrap();

        let ids: Vec<&str> = doc.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["wg-c", "xr-1", "wg-a", "ov-1", "wg-b"]);
        assert_eq!(doc.profiles[0].name, wg_c.name);
        let loaded = store.load().unwrap();
        assert_eq!(loaded.profiles, doc.profiles);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reorder_rejects_incomplete_and_foreign_ids() {
        let dir = unique_dir("reorder-invalid");
        let store = ProfileStore::new(dir.join("profiles.json"));
        let mut wg_a = wg_profile();
        wg_a.id = "wg-a".into();
        let mut wg_b = wg_profile();
        wg_b.id = "wg-b".into();
        let mut xray = xray_profile();
        xray.id = "xr-1".into();
        for profile in [&wg_a, &wg_b, &xray] {
            store.upsert(profile.clone()).unwrap();
        }

        // Missing member of the group.
        let err = store
            .reorder(TunnelBackend::WireGuard, &["wg-a".into()])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Id that belongs to another backend group.
        let err = store
            .reorder(TunnelBackend::WireGuard, &["wg-a".into(), "xr-1".into()])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Duplicate id passes the length check but must still fail.
        let err = store
            .reorder(TunnelBackend::WireGuard, &["wg-a".into(), "wg-a".into()])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Unknown id.
        let err = store
            .reorder(TunnelBackend::WireGuard, &["wg-a".into(), "ghost".into()])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Nothing was persisted.
        let loaded = store.load().unwrap();
        let ids: Vec<&str> = loaded.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["wg-a", "wg-b", "xr-1"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_upserts_keep_every_profile() {
        let dir = unique_dir("concurrent");
        let store = std::sync::Arc::new(ProfileStore::new(dir.join("profiles.json")));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        let threads: Vec<_> = (0..12)
            .map(|index| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut profile = wg_profile();
                    profile.id = format!("concurrent-{index}");
                    barrier.wait();
                    store.upsert(profile)
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(
            results.iter().all(Result::is_ok),
            "concurrent writes failed"
        );
        assert_eq!(store.load().unwrap().profiles.len(), 12);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn saved_profile_document_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("private");
        let path = dir.join("profiles.json");
        let store = ProfileStore::new(&path);
        store.upsert(wg_profile()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn xray_http_listener_requires_nonzero_distinct_port() {
        let mut profile = wg_profile();
        profile.backend = TunnelBackend::Xray;
        profile.config_path = PathBuf::from("config.json");
        profile.xray_socks_port = Some(10808);
        profile.xray_http_port = Some(0);
        assert!(validate_profile(&profile).is_err());
        profile.xray_http_port = profile.xray_socks_port;
        assert!(validate_profile(&profile).is_err());
        profile.xray_http_port = Some(10809);
        assert!(validate_profile(&profile).is_ok());
    }

    #[test]
    fn missing_store_returns_empty_v1_document() {
        let dir = unique_dir("missing");
        let store = ProfileStore::new(dir.join("profiles.json"));

        let doc = store.load().unwrap();

        assert_eq!(doc.version, PROFILE_DOCUMENT_VERSION);
        assert!(doc.profiles.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn round_trip_preserves_wireguard_profile() {
        let dir = unique_dir("roundtrip");
        let store = ProfileStore::new(dir.join("profiles.json"));
        let profile = wg_profile();

        let saved = store.upsert(profile.clone()).unwrap();
        assert_eq!(saved.profiles, vec![profile.clone()]);

        let loaded = store.load().unwrap();
        assert_eq!(loaded.version, PROFILE_DOCUMENT_VERSION);
        assert_eq!(loaded.profiles, vec![profile]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn upsert_replaces_same_id_instead_of_duplicating() {
        let dir = unique_dir("upsert");
        let store = ProfileStore::new(dir.join("profiles.json"));

        store.upsert(wg_profile()).unwrap();
        let mut updated = wg_profile();
        updated.name = "Renamed".into();
        updated.auto_connect = false;
        let doc = store.upsert(updated.clone()).unwrap();

        assert_eq!(doc.profiles.len(), 1);
        assert_eq!(doc.profiles[0], updated);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validation_rejects_wrong_extension_and_blank_interface_name() {
        let mut bad_ext = wg_profile();
        bad_ext.config_path = PathBuf::from(r"C:\configs\work.txt");
        let err = validate_profile(&bad_ext).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut blank_iface = wg_profile();
        blank_iface.backend = TunnelBackend::None;
        blank_iface.config_path = PathBuf::new();
        blank_iface.interface_name = "   ".into();
        let err = validate_profile(&blank_iface).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn blank_interface_allowed_for_unrouted_and_linux_daemon_tunnels() {
        let mut profile = wg_profile();
        profile.interface_name = "   ".into();
        profile.routes = vec![];
        assert!(validate_profile(&profile).is_ok());

        profile.routes = vec![PolicyRoute {
            destination: "10.7.0.0/24".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        if cfg!(target_os = "linux") {
            assert!(validate_profile(&profile).is_ok());
        } else {
            let err = validate_profile(&profile).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn openvpn_imported_routes_allow_blank_interface_on_linux_and_macos() {
        let mut profile = wg_profile();
        profile.backend = TunnelBackend::OpenVpn;
        profile.config_path = PathBuf::from("client.ovpn");
        profile.interface_name.clear();
        profile.routes = vec![PolicyRoute {
            destination: "10.20.0.0/16".parse().unwrap(),
            metric: 0,
            via: None,
        }];
        assert_eq!(
            validate_profile(&profile).is_ok(),
            cfg!(target_os = "linux") || cfg!(target_os = "macos")
        );
    }

    #[test]
    fn static_routes_profile_needs_no_config_file() {
        let profile = Profile {
            id: "local-routes".into(),
            name: "Local routes".into(),
            backend: TunnelBackend::None,
            config_path: PathBuf::new(),
            interface_name: "eth0".into(),
            routes: vec![PolicyRoute {
                destination: "203.0.113.0/24".parse().unwrap(),
                metric: 5,
                via: None,
            }],
            ..Default::default()
        };
        assert!(validate_profile(&profile).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_managed_tunnels_need_no_user_interface_name_for_policy_routes() {
        let mut wg = wg_profile();
        wg.interface_name.clear();
        let mut openvpn = wg.clone();
        openvpn.backend = TunnelBackend::OpenVpn;
        openvpn.config_path = PathBuf::from("client.ovpn");
        let mut xray_tun = wg.clone();
        xray_tun.backend = TunnelBackend::Xray;
        xray_tun.config_path = PathBuf::from("config.json");
        xray_tun.xray_mode = crate::models::XrayMode::Tun;
        for profile in [&wg, &openvpn, &xray_tun] {
            assert!(validate_profile(profile).is_ok(), "{:?}", profile.backend);
        }
        xray_tun.xray_mode = crate::models::XrayMode::Socks;
        assert!(validate_profile(&xray_tun).is_err());
    }

    #[test]
    fn static_routes_that_all_name_a_gateway_need_no_interface() {
        let mut profile = wg_profile();
        profile.backend = TunnelBackend::None;
        profile.interface_name.clear();
        profile.routes = vec![PolicyRoute {
            destination: "192.0.2.0/24".parse().unwrap(),
            metric: 5,
            via: Some("10.0.0.1".parse().unwrap()),
        }];
        assert!(validate_profile(&profile).is_ok());
        profile.routes[0].via = None;
        assert!(validate_profile(&profile).is_err());
    }

    #[test]
    fn policy_route_without_via_deserializes() {
        let route: PolicyRoute =
            serde_json::from_str(r#"{"destination":"10.7.0.0/24","metric":5}"#).unwrap();
        assert_eq!(route.via, None);
    }

    #[test]
    fn profile_validation_rejects_via_family_mismatch() {
        let mut profile = wg_profile();
        profile.routes = vec![PolicyRoute {
            destination: "10.7.0.0/24".parse().unwrap(),
            metric: 5,
            via: Some("fe80::1".parse().unwrap()),
        }];
        let err = validate_profile(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn profile_validation_rejects_unspecified_via() {
        let mut profile = wg_profile();
        profile.routes = vec![PolicyRoute {
            destination: "10.7.0.0/24".parse().unwrap(),
            metric: 5,
            via: Some("0.0.0.0".parse().unwrap()),
        }];
        let err = validate_profile(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn xray_profile() -> Profile {
        Profile {
            id: "work-xray".into(),
            name: "Work Xray".into(),
            backend: TunnelBackend::Xray,
            config_path: PathBuf::from(r"C:\configs\work.json"),
            interface_name: String::new(),
            domain_policies: vec![DomainPolicy {
                domains: vec!["example.com".into()],
                target: DomainRouteTarget::Proxy,
            }],
            xray_socks_port: Some(10808),
            ..Default::default()
        }
    }

    #[test]
    fn xray_requires_json_extension() {
        assert!(validate_profile(&xray_profile()).is_ok());

        let mut bad = xray_profile();
        bad.config_path = PathBuf::from(r"C:\configs\work.conf");
        let err = validate_profile(&bad).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut upper = xray_profile();
        upper.config_path = PathBuf::from(r"C:\configs\WORK.JSON");
        assert!(validate_profile(&upper).is_ok());

        let mut protected = xray_profile();
        protected.config_path = PathBuf::from(r"C:\configs\work.json.dpapi");
        assert!(validate_profile(&protected).is_ok());
    }

    #[test]
    fn legacy_profile_json_deserializes_without_xray_fields() {
        let json = r#"{
            "id": "legacy",
            "name": "Legacy WG",
            "backend": "wireGuard",
            "configPath": "C:\\configs\\legacy.conf",
            "interfaceName": "wg0",
            "routes": [],
            "autoConnect": false
        }"#;
        let profile: Profile = serde_json::from_str(json).unwrap();
        assert!(profile.domain_policies.is_empty());
        assert_eq!(profile.xray_socks_port, None);
        assert!(validate_profile(&profile).is_ok());
    }

    #[test]
    fn domain_policies_rejected_for_non_xray_backends() {
        let mut profile = wg_profile();
        profile.domain_policies = vec![DomainPolicy {
            domains: vec!["example.com".into()],
            target: DomainRouteTarget::Direct,
        }];
        let err = validate_profile(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn xray_domain_policies_require_nonblank_domains() {
        let mut empty_list = xray_profile();
        empty_list.domain_policies = vec![DomainPolicy {
            domains: vec![],
            target: DomainRouteTarget::Proxy,
        }];
        assert_eq!(
            validate_profile(&empty_list).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut blank = xray_profile();
        blank.domain_policies = vec![DomainPolicy {
            domains: vec!["example.com".into(), "   ".into()],
            target: DomainRouteTarget::Direct,
        }];
        assert_eq!(
            validate_profile(&blank).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn system_proxy_requires_xray_with_socks_port() {
        let mut ok = xray_profile();
        ok.use_system_proxy = true;
        ok.proxy_bypass = vec!["<local>".into(), "10.*".into()];
        assert!(validate_profile(&ok).is_ok());

        let mut wg = wg_profile();
        wg.use_system_proxy = true;
        assert_eq!(
            validate_profile(&wg).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut no_port = xray_profile();
        no_port.use_system_proxy = true;
        no_port.xray_socks_port = None;
        assert_eq!(
            validate_profile(&no_port).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn proxy_bypass_rejects_blank_and_semicolon() {
        let mut blank = xray_profile();
        blank.use_system_proxy = true;
        blank.proxy_bypass = vec!["   ".into()];
        assert_eq!(
            validate_profile(&blank).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut semicolon = xray_profile();
        semicolon.use_system_proxy = true;
        semicolon.proxy_bypass = vec!["a;b".into()];
        assert_eq!(
            validate_profile(&semicolon).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn xray_socks_port_must_be_nonzero() {
        let mut zero = xray_profile();
        zero.xray_socks_port = Some(0);
        assert_eq!(
            validate_profile(&zero).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut absent = xray_profile();
        absent.xray_socks_port = None;
        assert!(validate_profile(&absent).is_ok());
    }

    #[test]
    fn load_rejects_unsupported_version() {
        let dir = unique_dir("version");
        let path = dir.join("profiles.json");
        fs::write(&path, r#"{"version":2,"profiles":[]}"#).unwrap();
        let store = ProfileStore::new(&path);

        let err = store.load().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }
}
