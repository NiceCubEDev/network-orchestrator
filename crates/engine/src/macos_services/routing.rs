use super::*;
use net_manager_core::{
    happ_routing,
    route_check::{self, GeoDbs, GeoIpDb, GeoSiteDb},
    xray::{self, ProfileRoutingOptions},
};

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileRouting {
    pub policies: Vec<DomainPolicy>,
    pub private_lan_direct: bool,
    pub domain_strategy: Option<XrayDomainStrategy>,
    pub domain_matcher: Option<XrayDomainMatcher>,
    pub dns: XrayDnsConfig,
    pub geoip_url: Option<String>,
    pub geosite_url: Option<String>,
}
#[derive(Default)]
pub struct ProfileRoutingUpdate {
    pub policies: Vec<DomainPolicy>,
    pub private_lan_direct: bool,
    pub advanced: Option<AdvancedRouting>,
    pub geo_urls: Option<GeoUrls>,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdvancedRouting {
    pub domain_strategy: Option<XrayDomainStrategy>,
    pub domain_matcher: Option<XrayDomainMatcher>,
    pub dns: XrayDnsConfig,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeoUrls {
    pub geoip_url: Option<String>,
    pub geosite_url: Option<String>,
}
impl From<&Profile> for ProfileRouting {
    fn from(p: &Profile) -> Self {
        Self {
            policies: p.domain_policies.clone(),
            private_lan_direct: p.private_lan_direct,
            domain_strategy: p.xray_domain_strategy,
            domain_matcher: p.xray_domain_matcher,
            dns: p.xray_dns.clone(),
            geoip_url: p.xray_geoip_url.clone(),
            geosite_url: p.xray_geosite_url.clone(),
        }
    }
}
impl<R: BusinessRuntime> MacosServices<R> {
    pub fn profile_routing(&self, id: &str) -> Result<ProfileRouting, String> {
        Ok(ProfileRouting::from(&self.profile(id)?))
    }
    pub fn set_profile_routing(
        &self,
        id: &str,
        update: ProfileRoutingUpdate,
    ) -> Result<Profile, String> {
        xray::validate_routing_policy_selectors(&update.policies)
            .map_err(|_| "Invalid routing rule".to_string())?;
        if let Some(advanced) = &update.advanced {
            xray::validate_dns_config(&advanced.dns)
                .map_err(|_| "The DNS settings are not valid".to_string())?;
        }
        if let Some(urls) = &update.geo_urls {
            for url in [&urls.geoip_url, &urls.geosite_url].into_iter().flatten() {
                net_manager_core::geo_assets::validate_geo_asset_url(url)
                    .map_err(|_| "A geo data address must start with https://".to_string())?;
            }
        }
        self.change_profile(id, true, move |p| {
            if p.backend != TunnelBackend::Xray {
                return Err("Routing rules are available for Xray connections".into());
            }
            p.domain_policies = update.policies;
            p.private_lan_direct = update.private_lan_direct;
            if let Some(advanced) = update.advanced {
                p.xray_domain_strategy = advanced.domain_strategy;
                p.xray_domain_matcher = advanced.domain_matcher;
                p.xray_dns = advanced.dns;
            }
            if let Some(urls) = update.geo_urls {
                p.xray_geoip_url = urls.geoip_url;
                p.xray_geosite_url = urls.geosite_url;
            }
            Ok(())
        })
    }
    pub fn parse_happ_routing(
        &self,
        payload: &str,
    ) -> Result<happ_routing::HappRoutingImport, String> {
        happ_routing::parse_happ_routing(payload)
            .map_err(|_| "This is not a Happ or Incy routing profile".into())
    }
    pub fn import_happ_routing(&self, id: &str, payload: &str) -> Result<Profile, String> {
        let import = self.parse_happ_routing(payload)?;
        self.change_profile(id, true, move |profile| {
            if profile.backend != TunnelBackend::Xray {
                return Err("Routing rules are available for Xray connections".into());
            }
            profile.domain_policies = import.domain_policies;
            if let Some(lan) = import.private_lan_direct {
                profile.private_lan_direct = lan;
            }
            if let Some(strategy) = import.domain_strategy {
                profile.xray_domain_strategy = Some(strategy);
            }
            if let Some(matcher) = import.domain_matcher {
                profile.xray_domain_matcher = Some(matcher);
            }
            if !import.dns.is_empty() {
                profile.xray_dns = import.dns;
            }
            if let Some(url) = import.geoip_url {
                profile.xray_geoip_url = Some(url);
            }
            if let Some(url) = import.geosite_url {
                profile.xray_geosite_url = Some(url);
            }
            xray::validate_routing_policy_selectors(&profile.domain_policies)
                .map_err(|_| "Invalid routing rule".to_string())?;
            xray::validate_dns_config(&profile.xray_dns)
                .map_err(|_| "The DNS settings are not valid".to_string())?;
            Ok(())
        })
    }
    pub fn check_routing(
        &self,
        target: &str,
        routing: &ProfileRouting,
    ) -> Result<route_check::RouteCheckResult, String> {
        xray::validate_routing_policy_selectors(&routing.policies)
            .map_err(|_| "Invalid routing rule".to_string())?;
        xray::validate_dns_config(&routing.dns)
            .map_err(|_| "The DNS settings are not valid".to_string())?;
        // Only the managed backend's pinned directory is consulted, never user
        // URLs or arbitrary files from a draft. Read a bounded open file to avoid
        // a metadata/read race allocating an unbounded geo asset.
        let directory = net_manager_core::managed_xray::macos_managed_version_dir(
            &self.root.join("backends/xray"),
        );
        let geo_site = load_asset(&directory.join("geosite.dat"), GeoSiteDb::parse);
        let geo_ip = load_asset(&directory.join("geoip.dat"), GeoIpDb::parse);
        let options = ProfileRoutingOptions {
            private_lan_direct: routing.private_lan_direct,
            domain_strategy: routing.domain_strategy,
            domain_matcher: routing.domain_matcher,
            dns: routing.dns.clone(),
            ..Default::default()
        };
        route_check::check_route(
            &routing.policies,
            &options,
            target,
            &GeoDbs {
                geo_site: geo_site.as_ref(),
                geo_ip: geo_ip.as_ref(),
            },
        )
        .map_err(|e| e.to_string())
    }
}
fn load_asset<T>(path: &Path, parse: fn(&[u8]) -> std::io::Result<T>) -> Option<T> {
    use std::io::Read;
    const MAX: u64 = 64 * 1024 * 1024;
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX {
        return None;
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX {
        return None;
    }
    parse(&bytes).ok()
}
