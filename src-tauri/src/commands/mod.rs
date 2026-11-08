pub(crate) mod always_on;
pub(crate) mod bulk_routes;
pub(crate) mod cond_rules;
pub(crate) mod diagnostics;
pub(crate) mod exit_ips;
pub(crate) mod explorer;
pub(crate) mod happ_routing;
pub(crate) mod logs;
pub(crate) mod net_tables;
pub(crate) mod netbird;
pub(crate) mod nm;
pub(crate) mod profiles;
pub(crate) mod proxies;
pub(crate) mod recovery;
pub(crate) mod route_check;
pub(crate) mod route_map;
pub(crate) mod system;
pub(crate) mod tunnels;

pub(crate) use always_on::{
    get_always_on_profiles, remove_always_on_profile, resume_always_on, set_always_on_profile,
};
pub(crate) use bulk_routes::parse_bulk_cidrs;
pub(crate) use cond_rules::{
    list_conditional_rules, put_conditional_rule, remove_conditional_rule,
};
pub(crate) use diagnostics::{diagnose_profile, inspect_profile_by_id, inspect_profiles};
pub(crate) use exit_ips::check_exit_ips;
pub(crate) use explorer::{
    get_interfaces, get_routes, lookup_destination, set_interface_state, stop_external_tunnel,
};
pub(crate) use happ_routing::parse_happ_routing;
pub(crate) use logs::{clear_logs, daemon_log_tail, get_logs};
pub(crate) use net_tables::{
    get_net_tables, net_dns_probe, net_dns_status, net_explain, net_intent_del, net_intent_list,
    net_intent_set, net_route_add, net_route_del, net_rule_add, net_rule_del,
};
pub(crate) use netbird::{netbird_down, netbird_status, netbird_up};
pub(crate) use nm::{nm_list_connections, nm_set_active};
pub(crate) use profiles::{
    apply_xray_policy_migration, delete_profile, get_profile_for_edit, get_profiles,
    get_subscription_endpoints, import_configs_batch, import_share_link, import_subscription,
    measure_subscription_endpoint_delay, preview_xray_policy_migration,
    rebuild_subscription_node_pool, refresh_subscription, reorder_profiles,
    run_xray_service_checks, save_profile, save_vless_profile, save_wireguard_profile,
    set_pinned_routes, set_subscription_auto_return, set_subscription_backups,
    set_subscription_node_pool, set_subscription_refresh_interval, set_tunnel_networks,
    set_tunnel_role, set_xray_service_checks, switch_subscription_endpoint,
    verify_subscription_exits,
};
pub(crate) use proxies::scan_local_proxies;
pub(crate) use recovery::{cleanup_recovery, get_recovery_report};
pub(crate) use route_check::xray_test_route;
pub(crate) use route_map::get_route_map;
pub(crate) use system::{
    cancel_managed_xray_install, daemon_status, discover_wireguard_configs,
    get_backend_availability, get_managed_xray_offer, get_platform_capabilities, get_vpn_auth_mode,
    install_managed_xray, is_elevated, remove_managed_xray, reset_backend_executable,
    restart_elevated, set_backend_executable, set_vpn_auth_mode, system_proxy_status,
};
pub(crate) use tunnels::{
    connect_openvpn_with_credentials, connect_profile, disconnect_profile, get_tunnel_statuses,
    openvpn_plan, probe_openvpn_routes, reload_xray_profile, tailscale_set_running,
    tailscale_status,
};
