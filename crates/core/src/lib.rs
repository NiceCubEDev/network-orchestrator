/// Version of the shared core (its own release line, see `versions.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod analysis;
pub mod backend_settings;
pub mod cidr_bulk;
pub mod config_security;
pub mod config_vault;
pub mod connect_plan;
pub mod daemon_protocol;
pub mod diagnostics;
pub mod dns_diag;
pub mod dns_probe;
pub mod exit_ip;
pub mod explorer;
pub mod geo_assets;
pub mod geo_list;
pub mod happ_routing;
#[cfg(unix)]
pub mod helper_client;
pub mod intent_doctor;
pub mod journal;
pub mod log_sanitize;
#[cfg(target_os = "macos")]
mod macos_inventory;
pub mod macos_vpn;
pub mod managed_xray;
pub mod models;
#[cfg(unix)]
pub mod netbird;
pub mod node_pool;
pub mod openvpn_config;
pub mod openvpn_management;
pub mod policy;
pub mod profile_import;
pub mod profiles;
pub mod proxy_exits;
pub mod recovery;
pub mod route_check;
pub mod route_conditions;
pub mod route_intents;
pub mod route_plan;
pub mod route_state;
pub mod service_checks;
pub mod subscription;
pub mod system_proxy;
pub mod vpn;
pub mod windows_job;
pub mod xray;
pub mod xray_migrate;
