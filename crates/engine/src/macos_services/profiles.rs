use super::*;
use ipnet::IpNet;
use net_manager_core::analysis;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaticProfileCreate {
    pub id: String,
    pub name: String,
    pub interface_name: String,
    pub routes: Vec<PolicyRoute>,
    pub endpoint_bypasses: Vec<String>,
}
pub struct ShareLinkImport {
    pub id: String,
    pub name: String,
    pub link: String,
}
pub struct ConfigImport {
    pub id: String,
    pub name: String,
    pub backend: TunnelBackend,
    pub path: PathBuf,
}

impl<R: BusinessRuntime> MacosServices<R> {
    pub fn create_static(&self, request: StaticProfileCreate) -> Result<Profile, String> {
        self.locked(|| {
            let id = required(&request.id)?;
            required(&request.name)?;
            net_manager_core::config_vault::sanitize_profile_id(id).map_err(store_error)?;
            if self
                .store()
                .load()
                .map_err(store_error)?
                .profiles
                .iter()
                .any(|p| p.id == id)
            {
                return Err("A profile with this identifier already exists".into());
            }
            if request.routes.is_empty() {
                return Err("Add at least one route".into());
            }
            let profile = Profile {
                id: id.into(),
                name: request.name.trim().into(),
                interface_name: request.interface_name.trim().into(),
                routes: request.routes,
                endpoint_bypasses: request.endpoint_bypasses,
                ..Profile::default()
            };
            net_manager_core::route_intents::static_intents(&profile, &[])?;
            self.store().upsert(profile).map_err(store_error)?;
            self.public_profile(id)
        })
    }
    pub fn rename_profile(&self, id: &str, name: &str) -> Result<Profile, String> {
        let name = required(name)?.to_string();
        self.change_profile(id, false, move |p| {
            p.name = name;
            Ok(())
        })
    }
    /// Preserve native behavior: deleting a profile neither prunes saved sets nor
    /// deletes remembered credentials. A running connection is not stopped here.
    pub fn delete_profile(&self, id: &str) -> Result<(), String> {
        self.locked(|| {
            self.store().delete(id).map_err(store_error)?;
            self.vault().remove_profile(id).map_err(store_error)
        })
    }
    pub fn reorder_profiles(
        &self,
        backend: TunnelBackend,
        ids: &[String],
    ) -> Result<Vec<Profile>, String> {
        self.locked(|| {
            Ok(redact_profiles(
                self.store()
                    .reorder(backend, ids)
                    .map_err(|_| "The order could not be saved".to_string())?
                    .profiles,
            ))
        })
    }
    pub fn import_share_link(&self, request: ShareLinkImport) -> Result<Profile, String> {
        self.locked(|| {
            required(&request.id)?;
            required(&request.link)?;
            net_manager_core::profile_import::import_share_link(
                &self.vault(),
                &self.store(),
                &request.id,
                &request.name,
                &request.link,
                XrayMode::Socks,
                local_port_available,
            )
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::InvalidInput => {
                    "Invalid or unsupported share link. Use vless://, hysteria2:// or hy2://."
                        .to_string()
                }
                std::io::ErrorKind::AlreadyExists => {
                    "A profile with this identifier already exists".to_string()
                }
                _ => store_error(error),
            })?;
            self.public_profile(&request.id)
        })
    }
    pub fn import_config(&self, request: ConfigImport) -> Result<Profile, String> {
        self.locked(|| {
            let id = required(&request.id)?;
            let name = required(&request.name)?;
            if self
                .store()
                .load()
                .map_err(store_error)?
                .profiles
                .iter()
                .any(|p| p.id == id)
            {
                return Err("A profile with this identifier already exists".into());
            }
            let imported = self
                .vault()
                .import(id, request.backend, &request.path)
                .map_err(|error| {
                    let message = error.to_string();
                    match message.as_str() {
                        "unsupported OpenVPN route directive"
                        | "OpenVPN referenced asset is missing" => message,
                        _ => store_error(error),
                    }
                })?;
            let profile = Profile {
                id: id.into(),
                name: name.into(),
                backend: request.backend,
                config_path: imported.config_path.clone(),
                routes: imported.routes,
                xray_mode: XrayMode::Socks,
                ..Profile::default()
            };
            let result = analysis::analyze_profile(&profile)
                .map_err(|_| "The configuration could not be analyzed".to_string())
                .and_then(|_| self.store().upsert(profile).map_err(store_error));
            match result {
                Ok(_) => self.public_profile(id),
                Err(error) => {
                    let _ = self
                        .vault()
                        .remove_revision_for_config(&imported.config_path);
                    Err(error)
                }
            }
        })
    }
    pub fn set_xray_mode(&self, id: &str, mode: XrayMode) -> Result<Profile, String> {
        self.change_profile(id, true, |p| {
            if p.backend != TunnelBackend::Xray {
                return Err("The mode can be changed for Xray connections".into());
            }
            p.xray_mode = mode;
            Ok(())
        })
    }
    pub fn set_auto_connect(&self, id: &str, enabled: bool) -> Result<Profile, String> {
        self.change_profile(id, false, |p| {
            p.auto_connect = enabled;
            Ok(())
        })
    }
    pub fn set_wait_for_interface(&self, id: &str, enabled: bool) -> Result<Profile, String> {
        self.change_profile(id, false, |p| {
            p.wait_for_interface = enabled;
            Ok(())
        })
    }
    pub fn set_tunnel_role(&self, id: &str, role: TunnelRole) -> Result<Profile, String> {
        self.change_profile(id, true, |p| {
            require_tunnel(p)?;
            p.tunnel_role = role;
            Ok(())
        })
    }
    pub fn set_tunnel_networks(
        &self,
        id: &str,
        networks: Vec<IpNet>,
        dns_domains: Vec<String>,
    ) -> Result<Profile, String> {
        // Keep validation identical to the native text input while exposing typed networks.
        let networks = net_manager_core::models::parse_networks(
            &networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )?;
        let dns_domains = net_manager_core::models::parse_dns_domains(&dns_domains.join(","))?;
        self.change_profile(id, true, move |p| {
            require_tunnel(p)?;
            p.tunnel_networks = networks;
            p.tunnel_dns_domains = dns_domains;
            Ok(())
        })
    }
    pub fn inspect_profile(&self, id: &str) -> Result<ConfigAnalysis, String> {
        analysis::analyze_profile(&self.profile(id)?)
            .map_err(|_| "The configuration could not be analyzed".into())
    }
}
fn require_tunnel(profile: &Profile) -> Result<(), String> {
    if profile.backend == TunnelBackend::None {
        Err("Static routes do not create a tunnel".into())
    } else {
        Ok(())
    }
}
