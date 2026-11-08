#[cfg(target_os = "linux")]
mod auto_connect;
mod commands;
#[cfg(target_os = "linux")]
mod daemon_client;
#[cfg(target_os = "linux")]
mod daemon_watcher;
mod elevation;
mod lifecycle;
#[cfg(target_os = "linux")]
mod profile_watcher;
#[cfg(not(target_os = "linux"))]
mod route_runtime;
mod state;
#[cfg(test)]
mod test_support;
#[cfg(target_os = "linux")]
mod tray;

#[cfg(target_os = "linux")]
use auto_connect::get_auto_connect_result;
use commands::*;
use net_manager_core::explorer;
use tauri::{Emitter, Manager};

#[cfg(target_os = "linux")]
use tray::{get_login_autostart, set_login_autostart};

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn get_login_autostart() -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn set_login_autostart(_enabled: bool) -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn get_auto_connect_result() -> Option<serde_json::Value> {
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Must be first: a second launch exits here and focuses the running UI
        // before setup starts auto-connect, refresh loops or the tray again.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            #[cfg(target_os = "linux")]
            let data_dir =
                net_manager_engine::linux_paths::from_environment(&app.config().identifier)
                    .map_err(std::io::Error::other)?;
            #[cfg(not(target_os = "linux"))]
            let data_dir = app.path().app_data_dir()?;
            #[cfg(target_os = "linux")]
            let profile_path = data_dir.join("profiles.json");
            app.manage(state::build_state(data_dir)?);
            #[cfg(target_os = "linux")]
            tauri::async_runtime::spawn(profile_watcher::watch(app.handle().clone(), profile_path));
            #[cfg(target_os = "linux")]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn_blocking(move || daemon_watcher::watch(handle));
            }
            #[cfg(target_os = "linux")]
            {
                match tray::install(app) {
                    Ok(true) => {
                        tauri::async_runtime::spawn(tray::refresh_loop(app.handle().clone()));
                    }
                    Ok(false) => {}
                    Err(err) => eprintln!("network-orchestrator: tray unavailable: {err}"),
                }
            }
            #[cfg(target_os = "linux")]
            {
                // `tauri.localhost`/`ipc.localhost` are real http URLs that
                // pass through WebKit's GIO proxy resolver; a system-wide
                // proxy left on by another VPN client (e.g. Happ) hijacks or
                // kills them and the window renders a blank error page. The
                // UI only ever talks to loopback pseudo-hosts, so bypass the
                // system proxy entirely.
                use webkit2gtk::{NetworkProxyMode, WebViewExt, WebsiteDataManagerExt};
                for (_label, window) in app.webview_windows() {
                    let _ = window.with_webview(|webview| {
                        let wv = webview.inner();
                        if let Some(manager) = wv.website_data_manager() {
                            manager.set_network_proxy_settings(NetworkProxyMode::NoProxy, None);
                        }
                        wv.reload();
                    });
                }
            }
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                #[cfg(target_os = "linux")]
                auto_connect::start(handle.clone()).await;
                commands::profiles::run_subscription_refresh_loop(handle).await;
            });
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(explorer::route_watcher_loop(move || {
                let _ = handle.emit("route-changed", ());
            }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_interfaces,
            get_routes,
            parse_bulk_cidrs,
            parse_happ_routing,
            xray_test_route,
            lookup_destination,
            set_interface_state,
            stop_external_tunnel,
            nm_list_connections,
            nm_set_active,
            get_net_tables,
            net_route_add,
            net_route_del,
            net_rule_add,
            net_rule_del,
            net_explain,
            net_dns_status,
            net_dns_probe,
            net_intent_list,
            net_intent_set,
            net_intent_del,
            scan_local_proxies,
            get_always_on_profiles,
            set_always_on_profile,
            remove_always_on_profile,
            resume_always_on,
            get_profiles,
            get_profile_for_edit,
            save_profile,
            save_vless_profile,
            save_wireguard_profile,
            import_configs_batch,
            import_share_link,
            import_subscription,
            refresh_subscription,
            set_subscription_refresh_interval,
            measure_subscription_endpoint_delay,
            get_subscription_endpoints,
            switch_subscription_endpoint,
            set_subscription_backups,
            set_subscription_auto_return,
            set_pinned_routes,
            set_xray_service_checks,
            run_xray_service_checks,
            set_subscription_node_pool,
            rebuild_subscription_node_pool,
            verify_subscription_exits,
            preview_xray_policy_migration,
            apply_xray_policy_migration,
            delete_profile,
            reorder_profiles,
            set_tunnel_role,
            set_tunnel_networks,
            connect_profile,
            connect_openvpn_with_credentials,
            disconnect_profile,
            openvpn_plan,
            probe_openvpn_routes,
            reload_xray_profile,
            tailscale_status,
            netbird_status,
            netbird_up,
            netbird_down,
            tailscale_set_running,
            inspect_profile_by_id,
            inspect_profiles,
            diagnose_profile,
            check_exit_ips,
            get_tunnel_statuses,
            get_logs,
            clear_logs,
            daemon_log_tail,
            get_recovery_report,
            cleanup_recovery,
            list_conditional_rules,
            put_conditional_rule,
            remove_conditional_rule,
            is_elevated,
            daemon_status,
            system_proxy_status,
            restart_elevated,
            discover_wireguard_configs,
            get_route_map,
            get_backend_availability,
            set_backend_executable,
            reset_backend_executable,
            install_managed_xray,
            cancel_managed_xray_install,
            remove_managed_xray,
            get_managed_xray_offer,
            get_platform_capabilities,
            get_vpn_auth_mode,
            set_vpn_auth_mode,
            get_auto_connect_result,
            get_login_autostart,
            set_login_autostart,
            list_connection_sets,
            get_connection_set,
            put_connection_set,
            delete_connection_set,
            import_connection_sets,
            capture_connection_set,
            apply_connection_set,
            down_connection_set
        ])
        .on_window_event(lifecycle::handle_window_event)
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(lifecycle::handle_run_event);
}
