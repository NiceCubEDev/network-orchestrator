//! Shared Linux network inventory, daemon-authorized edits and offline routing tools.
use crate::linux_engine::{daemon_error, LinuxEngine};
use net_manager_core::daemon_protocol::*;
use net_manager_core::explorer;
use net_manager_core::happ_routing::HappRoutingImport;
use net_manager_core::models::*;
use net_manager_core::profiles::ProfileStore;
use net_manager_core::route_check::{check_route, GeoDbs, GeoIpDb, GeoSiteDb, RouteCheckResult};
use net_manager_core::route_plan::build_route_map;
use net_manager_core::xray::ProfileRoutingOptions;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

fn request<P: Serialize, T: serde::de::DeserializeOwned>(
    engine: &LinuxEngine,
    method: &str,
    params: P,
) -> Result<T, String> {
    engine
        .privileged()
        .call(method, params)
        .map_err(daemon_error)
}

pub fn interfaces() -> Result<Vec<NetworkInterface>, String> {
    explorer::list_interfaces().map_err(|error| error.to_string())
}

pub async fn routes() -> Result<Vec<RouteEntry>, String> {
    explorer::list_routes()
        .await
        .map_err(|error| error.to_string())
}

pub async fn lookup(destination: IpAddr) -> Result<RouteLookupResult, String> {
    explorer::lookup_route(destination)
        .await
        .map_err(|error| error.to_string())
}

pub fn set_interface_state(engine: &LinuxEngine, name: &str, up: bool) -> Result<(), String> {
    let _: serde_json::Value = request(
        engine,
        method::LINK_SET_STATE,
        LinkSetStateParams {
            name: name.into(),
            up,
        },
    )?;
    Ok(())
}

pub fn stop_external_tunnel(engine: &LinuxEngine, name: &str) -> Result<(), String> {
    let _: serde_json::Value = request(
        engine,
        method::EXTERNAL_TUNNEL_STOP,
        ExternalTunnelStopParams { name: name.into() },
    )?;
    Ok(())
}

pub fn tables(engine: &LinuxEngine) -> Result<NetTablesResult, String> {
    request(engine, method::NET_TABLES, ())
}

pub fn route_add(engine: &LinuxEngine, params: NetRouteAddParams) -> Result<(), String> {
    let _: serde_json::Value = request(engine, method::NET_ROUTE_ADD, params)?;
    Ok(())
}

pub fn route_delete(engine: &LinuxEngine, route: SystemRoute) -> Result<NetEditResult, String> {
    request(engine, method::NET_ROUTE_DEL, NetRouteDelParams { route })
}

pub fn rule_add(engine: &LinuxEngine, params: NetRuleAddParams) -> Result<(), String> {
    let _: serde_json::Value = request(engine, method::NET_RULE_ADD, params)?;
    Ok(())
}

pub fn rule_delete(engine: &LinuxEngine, rule: SystemRule) -> Result<NetEditResult, String> {
    request(engine, method::NET_RULE_DEL, NetRuleDelParams { rule })
}

pub fn explain(engine: &LinuxEngine) -> Result<NetExplainResult, String> {
    request(engine, method::NET_EXPLAIN, ())
}

pub fn dns_status(engine: &LinuxEngine) -> Result<NetDnsStatusResult, String> {
    request(engine, method::NET_DNS_STATUS, ())
}

pub fn dns_probe(
    engine: &LinuxEngine,
    params: NetDnsProbeParams,
) -> Result<NetDnsProbeResult, String> {
    request(engine, method::NET_DNS_PROBE, params)
}

pub fn intent_list(engine: &LinuxEngine) -> Result<NetIntentListResult, String> {
    request(engine, method::NET_INTENT_LIST, ())
}

pub fn intent_set(
    engine: &LinuxEngine,
    params: NetIntentSetParams,
) -> Result<NetIntentResult, String> {
    request(engine, method::NET_INTENT_SET, params)
}

pub fn intent_delete(engine: &LinuxEngine, id: &str) -> Result<NetIntentResult, String> {
    request(
        engine,
        method::NET_INTENT_DEL,
        NetIntentDelParams { id: id.into() },
    )
}

pub fn parse_bulk_cidrs(input: &str) -> Result<Vec<String>, String> {
    net_manager_core::cidr_bulk::parse_bulk_cidrs(input)
        .map(|routes| routes.into_iter().map(|route| route.to_string()).collect())
        .map_err(|_| "Invalid CIDR list (maximum 1 MiB and 8192 routes)".to_string())
}

pub fn parse_happ_routing(input: &str) -> Result<HappRoutingImport, String> {
    net_manager_core::happ_routing::parse_happ_routing(input)
        .map_err(|_| "Invalid Happ routing profile".to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteCheckRequest {
    pub target: String,
    #[serde(default)]
    pub domain_policies: Vec<DomainPolicy>,
    #[serde(default)]
    pub private_lan_direct: bool,
    #[serde(default)]
    pub domain_strategy: Option<XrayDomainStrategy>,
    #[serde(default)]
    pub dns: XrayDnsConfig,
    #[serde(default)]
    pub geoip_url: Option<String>,
    #[serde(default)]
    pub geosite_url: Option<String>,
}

pub fn geo_asset_dirs(
    root: &Path,
    geoip_url: Option<&str>,
    geosite_url: Option<&str>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if geoip_url.is_some() || geosite_url.is_some() {
        dirs.push(crate::linux_geo_assets::profile_asset_dir(
            &root.join("geoassets"),
            geoip_url,
            geosite_url,
        ));
    }
    #[cfg(target_arch = "x86_64")]
    dirs.push(net_manager_core::managed_xray::linux_managed_version_dir(
        Path::new(net_manager_core::managed_xray::LINUX_XRAY_PACKAGE_ROOT),
    ));
    #[cfg(not(target_arch = "x86_64"))]
    dirs.push(net_manager_core::managed_xray::managed_version_dir(
        &root.join("managed-xray"),
    ));
    dirs
}

const MAX_GEO_ASSET_BYTES: u64 = 64 * 1024 * 1024;

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
        if let Ok(bytes) = std::fs::read(&path) {
            contents.push(bytes);
        }
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

pub fn load_geo_assets(dirs: &[PathBuf]) -> (Option<GeoSiteDb>, Option<GeoIpDb>) {
    (
        load_asset(dirs, "geosite.dat", GeoSiteDb::parse),
        load_asset(dirs, "geoip.dat", GeoIpDb::parse),
    )
}

pub fn test_route(root: &Path, request: RouteCheckRequest) -> Result<RouteCheckResult, String> {
    let dirs = geo_asset_dirs(
        root,
        request.geoip_url.as_deref(),
        request.geosite_url.as_deref(),
    );
    let (geo_site, geo_ip) = load_geo_assets(&dirs);
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
        .map_err(|_| "Invalid route-check request".into())
}

pub fn select_route_profiles(
    profiles: &[Profile],
    statuses: &[TunnelStatus],
    include_inactive: bool,
) -> Vec<(Profile, bool)> {
    let by_id: HashMap<&str, &TunnelStatus> = statuses
        .iter()
        .map(|status| (status.profile_id.as_str(), status))
        .collect();
    profiles
        .iter()
        .filter_map(|profile| {
            let status = by_id.get(profile.id.as_str()).copied();
            let active = status.is_some_and(|status| status.state == TunnelState::Running);
            if !include_inactive && !active {
                return None;
            }
            let mut profile = profile.clone();
            if active {
                if let Some(name) = status
                    .and_then(|status| status.interface_name.as_deref())
                    .filter(|name| !name.is_empty())
                {
                    profile.interface_name = name.into();
                }
            }
            Some((profile, active))
        })
        .collect()
}

fn applied_openvpn_routes(
    profile: &Profile,
    status: &OpenVpnStatusResult,
) -> Result<Vec<PlannedRoute>, String> {
    if status.profile_id != profile.id {
        return Err("Daemon returned a different OpenVPN route owner".into());
    }
    if status.state != OpenVpnConnectionState::Connected {
        return Ok(Vec::new());
    }
    Ok(status
        .applied_routes
        .iter()
        .map(|destination| PlannedRoute {
            destination: *destination,
            owner_profile_id: profile.id.clone(),
            owner_name: profile.name.clone(),
            source: "daemon-applied".into(),
            interface_name: status.interface_name.clone(),
            metric: None,
            active: true,
        })
        .collect())
}

pub async fn route_map(
    engine: &LinuxEngine,
    store: &ProfileStore,
    include_inactive: bool,
) -> Result<RouteMap, String> {
    let profiles = store
        .load()
        .map_err(|_| "Profiles could not be loaded")?
        .profiles;
    let mut statuses = Vec::with_capacity(profiles.len());
    let mut pushed_routes = Vec::new();
    let mut warnings = Vec::new();
    for profile in &profiles {
        let status = if profile.backend == TunnelBackend::OpenVpn {
            engine
                .openvpn_status_result(&profile.id)
                .and_then(|status| {
                    pushed_routes.extend(applied_openvpn_routes(profile, &status)?);
                    Ok(crate::linux::linux_openvpn_tunnel_status(status))
                })
        } else {
            engine.status(profile)
        }
        .unwrap_or_else(|_| TunnelStatus {
            profile_id: profile.id.clone(),
            state: TunnelState::Failed,
            message: Some("Runtime status is unavailable".into()),
            interface_name: None,
            failover: None,
            watchdog: None,
        });
        if status.state == TunnelState::Failed {
            warnings.push(format!(
                "Profile '{}': {}",
                profile.id,
                status
                    .message
                    .as_deref()
                    .unwrap_or("Runtime status unavailable"),
            ));
            if profile.backend == TunnelBackend::OpenVpn {
                warnings.push(format!(
                    "OpenVPN applied routes unavailable for profile '{}'",
                    profile.id,
                ));
            }
        }
        statuses.push(status);
    }
    let selected = select_route_profiles(&profiles, &statuses, include_inactive);
    let mut map = build_route_map(&selected, &routes().await?);
    map.pushed_routes = pushed_routes;
    map.warnings.extend(warnings);
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_map_keeps_static_owner_without_importing_tunnel_journal_owners() {
        struct OwnedInventory(OwnedListResult);
        impl crate::privileged::Privileged for OwnedInventory {
            fn hello(&self) -> Result<HelloResult, net_manager_core::helper_client::HelperError> {
                Err(net_manager_core::helper_client::HelperError::Protocol(
                    "unexpected handshake".into(),
                ))
            }

            fn call_raw(
                &self,
                method_name: &str,
                params: serde_json::Value,
            ) -> Result<serde_json::Value, net_manager_core::helper_client::HelperError>
            {
                assert_eq!(method_name, method::OWNED_LIST);
                assert!(params.is_null());
                Ok(serde_json::to_value(&self.0).unwrap())
            }

            fn log_dir(&self) -> PathBuf {
                PathBuf::new()
            }
        }

        let root = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(root.path().join("profiles.json"));
        let mut document = store.load().unwrap();
        document.profiles.push(Profile {
            id: "static-owner".into(),
            name: "Static routes".into(),
            interface_name: "static0".into(),
            routes: vec![PolicyRoute {
                destination: "198.18.72.0/24".parse().unwrap(),
                metric: 72,
                via: None,
            }],
            ..Profile::default()
        });
        store.save(&document).unwrap();
        let static_route = OwnedResource::Route(AppliedRoute::on_link(
            document.profiles[0].routes[0].destination,
            71,
            72,
        ));
        let tunnel_route = OwnedResource::Route(AppliedRoute::on_link(
            "198.18.73.0/24".parse().unwrap(),
            72,
            73,
        ));
        let mut owners = vec![
            OwnedEntry {
                owner: "static-owner".into(),
                state: OwnedState::Applied,
                resources: vec![static_route],
            },
            OwnedEntry {
                owner: "wireguard-link-owner".into(),
                state: OwnedState::Applied,
                resources: vec![
                    tunnel_route.clone(),
                    OwnedResource::WireGuardLink(WireGuardLinkResource {
                        name: "wg-inventory".into(),
                        index: 72,
                        owner_marker: "wireguard-link-owner".into(),
                        full: None,
                        warnings: Vec::new(),
                    }),
                ],
            },
        ];
        for owner in [
            "wg:wireguard",
            "ovpn:openvpn",
            "ovpn-probe:probe",
            "xray:xray",
        ] {
            owners.push(OwnedEntry {
                owner: owner.into(),
                state: OwnedState::Applied,
                resources: vec![tunnel_route.clone()],
            });
        }
        let engine =
            LinuxEngine::with_privileged(std::sync::Arc::new(OwnedInventory(OwnedListResult {
                owners,
            })));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let map = runtime.block_on(route_map(&engine, &store, false)).unwrap();
        assert_eq!(map.predicted.len(), 1);
        assert_eq!(map.predicted[0].owner_profile_id, "static-owner");
        assert_eq!(
            map.predicted[0].destination,
            document.profiles[0].routes[0].destination
        );
        assert!(map.predicted[0].active);
        assert!(map.pushed_routes.is_empty());
        assert!(map.warnings.is_empty());
    }

    #[test]
    fn route_map_keeps_kernel_and_inactive_plans_when_daemon_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let openvpn_source = root.path().join("source.ovpn");
        let wireguard_source = root.path().join("source.conf");
        std::fs::write(&openvpn_source, "client\ndev tun\nremote 192.0.2.1 1194\n").unwrap();
        std::fs::write(&wireguard_source, "[Interface]\nAddress = 192.0.2.2/32\n").unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(root.path().join("configs"));
        let openvpn_config = vault
            .import(
                "unavailable-openvpn",
                TunnelBackend::OpenVpn,
                &openvpn_source,
            )
            .unwrap()
            .config_path;
        let wireguard_config = vault
            .import(
                "unavailable-wireguard",
                TunnelBackend::WireGuard,
                &wireguard_source,
            )
            .unwrap()
            .config_path;
        let store = ProfileStore::new(root.path().join("profiles.json"));
        let mut document = store.load().unwrap();
        document.profiles = vec![
            Profile {
                id: "unavailable-openvpn".into(),
                name: "Unavailable OpenVPN".into(),
                backend: TunnelBackend::OpenVpn,
                config_path: openvpn_config,
                interface_name: "ovpn-missing".into(),
                routes: vec![PolicyRoute {
                    destination: "198.18.1.0/24".parse().unwrap(),
                    metric: 71,
                    via: None,
                }],
                ..Profile::default()
            },
            Profile {
                id: "unavailable-wireguard".into(),
                name: "Unavailable WireGuard".into(),
                backend: TunnelBackend::WireGuard,
                config_path: wireguard_config,
                interface_name: "wg-missing".into(),
                routes: vec![PolicyRoute {
                    destination: "2001:db8:71::/48".parse().unwrap(),
                    metric: 72,
                    via: None,
                }],
                ..Profile::default()
            },
        ];
        store.save(&document).unwrap();
        let engine =
            LinuxEngine::for_socket(root.path().join("missing-daemon.sock"), "route-map-test");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let effective = build_route_map(&[], &routes().await.unwrap()).effective;
            let map = route_map(&engine, &store, true)
                .await
                .expect("unavailable profile status must not discard the network inventory");
            assert_eq!(map.effective, effective);
            for profile in &document.profiles {
                assert!(map.predicted.iter().any(|route| {
                    route.owner_profile_id == profile.id
                        && route.destination == profile.routes[0].destination
                        && !route.active
                }));
                assert!(map.warnings.iter().any(|warning| {
                    warning.contains(&profile.id) && warning.contains("unavailable")
                }));
            }
            assert!(map.pushed_routes.is_empty());
            assert!(map.warnings.iter().any(|warning| {
                warning.contains("unavailable-openvpn") && warning.contains("applied routes")
            }));
            let active_only = route_map(&engine, &store, false).await.unwrap();
            assert!(active_only.predicted.is_empty());
            assert_eq!(active_only.effective, effective);
        });
    }

    #[test]
    fn bulk_import_keeps_both_families_and_deduplicates() {
        assert_eq!(
            parse_bulk_cidrs("10.0.0.0/8\n2001:db8::/32\n10.0.0.0/8").unwrap(),
            vec!["10.0.0.0/8", "2001:db8::/32"]
        );
    }

    #[test]
    fn parser_errors_do_not_echo_input_secrets() {
        let secret = "https://user:credential@example.invalid/private-token";
        assert!(!parse_bulk_cidrs(secret).unwrap_err().contains("credential"));
        assert!(!parse_happ_routing(secret)
            .unwrap_err()
            .contains("credential"));
    }

    #[test]
    fn route_profile_selection_uses_only_matching_running_status() {
        let profile = Profile {
            id: "saved".into(),
            interface_name: "configured".into(),
            ..Profile::default()
        };
        let status = TunnelStatus {
            profile_id: "foreign".into(),
            state: TunnelState::Running,
            interface_name: Some("foreign0".into()),
            message: None,
            failover: None,
            watchdog: None,
        };
        assert!(select_route_profiles(std::slice::from_ref(&profile), &[status], false).is_empty());
        let stopped = TunnelStatus {
            profile_id: "saved".into(),
            state: TunnelState::Stopped,
            interface_name: Some("stale0".into()),
            message: None,
            failover: None,
            watchdog: None,
        };
        let selected = select_route_profiles(&[profile], &[stopped], true);
        assert!(!selected[0].1);
        assert_eq!(selected[0].0.interface_name, "configured");
    }

    #[test]
    fn pushed_route_map_rejects_mismatched_daemon_owner() {
        let profile = Profile {
            id: "saved".into(),
            backend: TunnelBackend::OpenVpn,
            ..Profile::default()
        };
        let status = OpenVpnStatusResult {
            profile_id: "foreign".into(),
            state: OpenVpnConnectionState::Connected,
            interface_name: Some("ovpn-test".into()),
            rx_bytes: 0,
            tx_bytes: 0,
            applied_routes: vec!["2001:db8::/32".parse().unwrap()],
            warnings: vec![],
            failure_reason: None,
        };
        assert!(applied_openvpn_routes(&profile, &status).is_err());
    }
}
