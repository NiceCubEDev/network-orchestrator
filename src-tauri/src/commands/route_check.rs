//! `xray_test_route` — offline route-decision simulator. Replays the rule
//! chain `apply_profile_routing` would emit for the *draft* profile fields
//! the form passes in, so rules can be checked before saving. Geo selectors
//! resolve against whatever `geoip.dat`/`geosite.dat` the machine already
//! has (override cache first, then the managed install); missing assets only
//! degrade the verdict to `probable`.

#[cfg(not(target_os = "linux"))]
use net_manager_core::models::{DomainPolicy, XrayDnsConfig, XrayDomainStrategy};
use net_manager_core::route_check::RouteCheckResult;
#[cfg(not(target_os = "linux"))]
use net_manager_core::route_check::{check_route, GeoDbs, GeoIpDb, GeoSiteDb};
#[cfg(not(target_os = "linux"))]
use net_manager_core::xray::ProfileRoutingOptions;
#[cfg(not(target_os = "linux"))]
use serde::Deserialize;
#[cfg(not(target_os = "linux"))]
use std::path::PathBuf;
use tauri::State;

use crate::state::AppState;
#[cfg(target_os = "linux")]
pub(crate) use net_manager_engine::linux_network::RouteCheckRequest;

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RouteCheckRequest {
    /// `host`, `host:port`, `scheme://host/…` or a literal IP.
    pub target: String,
    #[serde(default)]
    pub domain_policies: Vec<DomainPolicy>,
    #[serde(default)]
    pub private_lan_direct: bool,
    #[serde(default)]
    pub domain_strategy: Option<XrayDomainStrategy>,
    #[serde(default)]
    pub dns: XrayDnsConfig,
    /// Geo override URLs as currently entered in the form — they pick which
    /// override cache directory the dat files are read from.
    #[serde(default)]
    pub geoip_url: Option<String>,
    #[serde(default)]
    pub geosite_url: Option<String>,
}

/// Same bound the Linux geo-asset downloader enforces.
#[cfg(not(target_os = "linux"))]
const MAX_GEO_ASSET_BYTES: u64 = 64 * 1024 * 1024;

/// Directories that may hold `geoip.dat`/`geosite.dat`, most specific first.
#[cfg(not(target_os = "linux"))]
fn asset_dirs(
    state: &AppState,
    geoip_url: Option<&str>,
    geosite_url: Option<&str>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    #[cfg(not(target_os = "linux"))]
    let _ = (geoip_url, geosite_url);
    dirs.push(net_manager_core::managed_xray::managed_version_dir(
        &state.managed_xray_root,
    ));
    dirs
}

/// Read and parse one dat file across the candidate dirs. The first dir is
/// the highest-precedence provider overlay, the last is the managed stock
/// file; when both exist they are merged exactly like the daemon stages
/// them, so the checker sees the same category set as the runtime. A
/// missing/oversized/undecodable file simply yields `None` (the checker
/// then reports those selectors as unevaluated rather than failing).
#[cfg(not(target_os = "linux"))]
fn load_asset<T>(
    dirs: &[PathBuf],
    name: &str,
    parse: fn(&[u8]) -> std::io::Result<T>,
) -> Option<T> {
    let mut contents = Vec::with_capacity(dirs.len());
    for dir in dirs {
        let path = dir.join(name);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_GEO_ASSET_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        contents.push(bytes);
    }
    if let [overlay, stock] = contents.as_slice() {
        if let Ok(merged) = net_manager_core::geo_list::merge_geo_list(stock, overlay) {
            if let Ok(parsed) = parse(&merged) {
                return Some(parsed);
            }
        }
    }
    contents.iter().find_map(|bytes| parse(bytes).ok())
}

#[tauri::command]
pub(crate) fn xray_test_route(
    state: State<'_, AppState>,
    request: RouteCheckRequest,
) -> Result<RouteCheckResult, String> {
    #[cfg(target_os = "linux")]
    return net_manager_engine::linux_network::test_route(state.data_dir(), request);
    #[cfg(not(target_os = "linux"))]
    {
        let dirs = asset_dirs(
            &state,
            request.geoip_url.as_deref(),
            request.geosite_url.as_deref(),
        );
        let geo_site = load_asset(&dirs, "geosite.dat", GeoSiteDb::parse);
        let geo_ip = load_asset(&dirs, "geoip.dat", GeoIpDb::parse);
        let geo = GeoDbs {
            geo_site: geo_site.as_ref(),
            geo_ip: geo_ip.as_ref(),
        };
        let options = ProfileRoutingOptions {
            private_lan_direct: request.private_lan_direct,
            domain_strategy: request.domain_strategy,
            domain_matcher: None,
            dns: request.dns,
            ..ProfileRoutingOptions::default()
        };
        check_route(&request.domain_policies, &options, &request.target, &geo)
            .map_err(|err| err.to_string())
    }
}
