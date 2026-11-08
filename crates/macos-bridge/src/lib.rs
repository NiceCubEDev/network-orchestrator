//! Bounded JSON C ABI. Business logic lives in typed Engine services.
use net_manager_core::{models::*, profiles::ProfileStore};
use net_manager_engine::{
    macos_network::{DnsFamily, DnsProbeRequest, MacNetwork, NetBirdConnectOptions},
    macos_services::*,
    macos_state::{AppMode, SettingsStore},
    Engine,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::ffi::{c_char, CString};
use std::path::{Path, PathBuf};
mod routing;
mod runtime;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
#[derive(Deserialize)]
struct Request {
    root: PathBuf,
    method: String,
    #[serde(default)]
    args: Value,
}
fn text_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "A required field is empty".into())
}
fn text<'a>(args: &'a Value, key: &str) -> &'a str {
    args[key].as_str().unwrap_or_default()
}
fn flag(args: &Value, key: &str) -> bool {
    text(args, key) == "true"
}
fn number<T: std::str::FromStr>(args: &Value, key: &str, error: &str) -> Result<T, String> {
    text_arg(args, key)?.parse().map_err(|_| error.into())
}
fn decode<T: DeserializeOwned>(args: &Value, key: &str) -> Result<T, String> {
    serde_json::from_str(text_arg(args, key)?).map_err(|_| "The supplied data is not valid".into())
}
fn encode(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|_| "Could not encode the result".into())
}
fn profile_array(
    service: &MacosServices,
    change: impl FnOnce() -> Result<Profile, String>,
) -> Result<Value, String> {
    change()?;
    encode(service.public_profiles()?)
}
fn dispatch(root: &Path, method: &str, args: &Value) -> Result<Value, String> {
    if !root.is_absolute() {
        return Err("App data location must be absolute".into());
    }
    let service = MacosServices::new(root)?;
    let root = service.root();
    let network = MacNetwork::new(root);
    let engine = Engine::new(root);
    let store = ProfileStore::new(root.join("profiles.json"));
    if let Some(result) = runtime::handle(root, &store, method, args) {
        return result;
    }
    if let Some(result) = routing::handle(
        root,
        || service.profile_routing(text_arg(args, "id")?),
        method,
        args,
    ) {
        return result;
    }
    match method {
        "capabilities" => {
            let mut result = capabilities();
            result.version = env!("CARGO_PKG_VERSION");
            encode(result)
        }
        "helper_status" => encode(helper_status()),
        "profiles" => encode(service.public_profiles()?),
        "snapshot" => encode(service.network_snapshot()?),
        "interfaces" => encode(network.interfaces()?),
        "lookup" => encode(
            network.lookup_route(
                text_arg(args, "destination")?
                    .parse()
                    .map_err(|_| "Enter an IPv4 or IPv6 address".to_string())?,
            )?,
        ),
        "user_network_settings" => encode(network.user_network_settings()?),
        "dns_status" => encode(network.dns_status()?),
        "dns_probe" => {
            let server = text(args, "server").trim();
            let server = if server.is_empty() {
                None
            } else {
                Some(
                    server
                        .parse()
                        .map_err(|_| "Enter an IPv4 or IPv6 address as the server".to_string())?,
                )
            };
            encode(network.dns_probe(&DnsProbeRequest {
                hostname: text_arg(args, "hostname")?.into(),
                server,
                family: if text(args, "family") == "aaaa" {
                    DnsFamily::Aaaa
                } else {
                    DnsFamily::A
                },
            })?)
        }
        "netbird_status" => encode(engine.netbird_status()?),
        "netbird_up" => encode(
            engine.netbird_up(&NetBirdConnectOptions {
                management_url: (!text(args, "managementUrl").is_empty())
                    .then(|| text(args, "managementUrl").into()),
                setup_key: (!text(args, "setupKey").is_empty())
                    .then(|| text(args, "setupKey").into()),
            })?,
        ),
        "netbird_down" => encode(engine.netbird_down()?),
        "netbird_log" => encode(network.netbird_log()?),
        "tailscale_status" => encode(engine.tailscale_status()?),
        "tailscale_up" => encode(engine.tailscale_up()?.status),
        "tailscale_down" => encode(engine.tailscale_down()?.status),
        "tailscale_sync" => encode(engine.sync_tailscale()?),
        "external_vpns" => encode(network.external_vpns()?),
        "set_external_vpn" => {
            encode(engine.set_external_vpn(text(args, "id"), flag(args, "connect"))?)
        }
        "generate_hwid" => encode(service.generate_subscription_hwid()?),
        "create_static" => {
            let request = StaticProfileCreate {
                id: text_arg(args, "id")?.into(),
                name: text_arg(args, "name")?.into(),
                interface_name: text(args, "interfaceName").trim().into(),
                routes: net_manager_core::cidr_bulk::parse_static_routes(
                    text_arg(args, "cidrs")?,
                    5,
                )
                .map_err(|_| {
                    "Enter valid CIDRs, optionally followed by 'via <gateway>'".to_string()
                })?,
                endpoint_bypasses: text(args, "bypass")
                    .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';'))
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect(),
            };
            profile_array(&service, || service.create_static(request))
        }
        "rename" => profile_array(&service, || {
            service.rename_profile(text_arg(args, "id")?, text_arg(args, "name")?)
        }),
        "delete" => {
            service.delete_profile(text_arg(args, "id")?)?;
            encode(service.public_profiles()?)
        }
        "reorder" => {
            let backend = serde_json::from_value(args["backend"].clone())
                .map_err(|_| "Unknown connection type".to_string())?;
            encode(
                service.reorder_profiles(
                    backend,
                    &text_arg(args, "ids")?
                        .split(',')
                        .map(String::from)
                        .collect::<Vec<_>>(),
                )?,
            )
        }
        "import_share_link" => profile_array(&service, || {
            service.import_share_link(ShareLinkImport {
                id: text_arg(args, "id")?.into(),
                name: text(args, "name").into(),
                link: text_arg(args, "link")?.into(),
            })
        }),
        "import" => {
            let request = ConfigImport {
                id: text_arg(args, "id")?.into(),
                name: text_arg(args, "name")?.into(),
                path: PathBuf::from(text_arg(args, "path")?),
                backend: serde_json::from_value(args["backend"].clone())
                    .map_err(|_| "Choose a valid VPN type".to_string())?,
            };
            profile_array(&service, || service.import_config(request))
        }
        "import_subscription" => {
            encode(service.import_subscription(SubscriptionImportRequest {
                id: text_arg(args, "id")?.into(),
                name: text(args, "name").into(),
                url: text_arg(args, "url")?.into(),
                hwid: text(args, "hwid").into(),
            })?)
        }
        "refresh_subscription" => encode(service.refresh_subscription(text_arg(args, "id")?)?),
        "subscription_endpoints" => encode(service.subscription_endpoints(text_arg(args, "id")?)?),
        "switch_subscription_endpoint" => profile_array(&service, || {
            service.switch_subscription_endpoint(
                text_arg(args, "id")?,
                number(args, "index", "Invalid endpoint index")?,
            )
        }),
        "measure_delay" => encode(service.measure_subscription_delay(
            text_arg(args, "id")?,
            number(args, "index", "Invalid endpoint index")?,
        )?),
        "measure_delays" => encode(service.measure_subscription_delays(text_arg(args, "id")?)?),
        "check_exit_ip" => encode(service.check_exit_ip(match text(args, "via") {
            "" | "direct" => ExitIpVia::Direct,
            id => ExitIpVia::ProfileSocks(id.into()),
        })?),
        "import_log" => encode(service.subscription_import_log()),
        "set_routing_rules" => profile_array(&service, || {
            service.set_profile_routing(text_arg(args, "id")?, routing::draft(args)?)
        }),
        "import_happ_routing" => profile_array(&service, || {
            service.import_happ_routing(text_arg(args, "id")?, text_arg(args, "payload")?)
        }),
        "set_xray_mode" => profile_array(&service, || {
            service.set_xray_mode(
                text_arg(args, "id")?,
                match text_arg(args, "mode")? {
                    "socks" => XrayMode::Socks,
                    "tun" => XrayMode::Tun,
                    _ => return Err("Unknown connection mode".into()),
                },
            )
        }),
        "set_auto_connect" => profile_array(&service, || {
            service.set_auto_connect(text_arg(args, "id")?, flag(args, "enabled"))
        }),
        "set_wait_for_interface" => profile_array(&service, || {
            service.set_wait_for_interface(text_arg(args, "id")?, flag(args, "enabled"))
        }),
        "set_tunnel_role" => profile_array(&service, || {
            service.set_tunnel_role(
                text_arg(args, "id")?,
                match text_arg(args, "role")? {
                    "primary" => TunnelRole::Primary,
                    "secondary" => TunnelRole::Secondary,
                    _ => return Err("Unknown connection role".into()),
                },
            )
        }),
        "set_tunnel_networks" => profile_array(&service, || {
            service.set_tunnel_networks(
                text_arg(args, "id")?,
                net_manager_core::models::parse_networks(text(args, "networks"))?,
                net_manager_core::models::parse_dns_domains(text(args, "dnsDomains"))?,
            )
        }),
        "set_refresh_interval" => profile_array(&service, || {
            service.set_subscription_refresh_interval(
                text_arg(args, "id")?,
                if text(args, "minutes").is_empty() {
                    None
                } else {
                    Some(number(
                        args,
                        "minutes",
                        "unsupported subscription refresh interval",
                    )?)
                },
            )
        }),
        "inspect" => encode(service.inspect_profile(text_arg(args, "id")?)?),
        "diagnose" => encode(service.diagnose_profile(text_arg(args, "id")?)?),
        "intent_doctor" => encode(service.intent_suggestions()?),
        "apply_intent_fixes" => encode(service.apply_intent_fixes(&decode::<
            Vec<net_manager_core::daemon_protocol::NetIntentSetParams>,
        >(args, "payload")?)?),
        "settings" => encode(SettingsStore::new(root).load()?),
        "set_app_mode" => encode(
            SettingsStore::new(root).set_app_mode(
                serde_json::from_value::<AppMode>(args["mode"].clone())
                    .map_err(|_| "Unknown app mode".to_string())?,
            )?,
        ),
        "import_legacy_state" => encode(service.import_legacy_state(
            &production_root()?,
            args["appMode"].as_str(),
            if text(args, "connectionSets").is_empty() {
                vec![]
            } else {
                decode(args, "connectionSets")?
            },
        )?),
        "sets" => encode(service.list_sets()?),
        "capture_set" => {
            encode(service.capture_set(text_arg(args, "id")?, text_arg(args, "name")?)?)
        }
        "put_set" => encode(service.put_set(decode(args, "payload")?)?),
        "delete_set" => encode(service.delete_set(text_arg(args, "id")?)?),
        "import_sets" => encode(service.import_sets(decode(args, "payload")?)?),
        "apply_set" => encode(service.apply_set(
            &service.get_set(text_arg(args, "id")?)?,
            &StartPolicy::current(),
            &credential_inputs(args)?,
            &service.native_credential_store()?,
        )?),
        "disconnect_set" => {
            encode(service.disconnect_set(&service.get_set(text_arg(args, "id")?)?)?)
        }
        "auto_connect" => encode(service.auto_connect(
            &StartPolicy::current(),
            &credential_inputs(args)?,
            &service.native_credential_store()?,
        )?),
        "disconnect_all" => encode(service.disconnect_all()?),
        "refresh_subscriptions" => encode(service.refresh_subscriptions(
            flag(args, "dueOnly"),
            if text(args, "now").is_empty() {
                unix_now()
            } else {
                number(args, "now", "Invalid refresh time")?
            },
        )?),
        "start_eligibilities" => encode(service.start_eligibilities()?),
        "connect_profile" => encode(service.connect_profile(
            text_arg(args, "id")?,
            runtime::credentials_from_args(args),
            flag(args, "remember"),
            &service.native_credential_store()?,
        )?),
        "forget_credentials" => encode(
            service
                .native_credential_store()?
                .forget(text_arg(args, "id")?)?,
        ),
        "proxy_exports" => encode(service.proxy_exports(text_arg(args, "id")?)?),
        "open_browser" => {
            service.open_browser(text_arg(args, "id")?)?;
            Ok(json!({}))
        }
        "proxy_override" => encode(service.proxy_override()?),
        _ => Err(
            "This action needs the macOS VPN provider. Network changes are disabled in this build."
                .into(),
        ),
    }
}
fn credential_inputs(
    args: &Value,
) -> Result<net_manager_core::connection_sets::CredentialInputs, String> {
    if text(args, "credentials").is_empty() {
        Ok(Default::default())
    } else {
        decode(args, "credentials")
    }
}
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .unwrap_or(0)
}
fn response(bytes: &[u8]) -> Value {
    let result = serde_json::from_slice::<Request>(bytes)
        .map_err(|_| "Invalid bridge request".to_string())
        .and_then(|r| dispatch(&r.root, &r.method, &r.args));
    match result {
        Ok(data) => json!({"ok":true,"data":data}),
        Err(error) => json!({"ok":false,"error":error}),
    }
}
/// # Safety
/// `bytes` must reference `length` readable bytes until this call returns.
/// Free the returned string exactly once with `netorch_free`.
#[no_mangle]
pub unsafe extern "C" fn netorch_call(bytes: *const u8, length: usize) -> *mut c_char {
    let value = if bytes.is_null() || length > MAX_REQUEST_BYTES {
        json!({"ok":false,"error":"Invalid bridge request"})
    } else {
        std::panic::catch_unwind(|| response(unsafe { std::slice::from_raw_parts(bytes, length) }))
            .unwrap_or_else(|_| json!({"ok":false,"error":"Native core request failed"}))
    };
    CString::new(value.to_string())
        .expect("JSON encodes null characters")
        .into_raw()
}
/// # Safety
/// `value` must be null or a still-owned string returned by `netorch_call`.
#[no_mangle]
pub unsafe extern "C" fn netorch_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c_abi_rejects_invalid_buffers_and_returns_owned_json() {
        for (input, length) in [
            (std::ptr::null(), 1),
            (b"x".as_ptr(), MAX_REQUEST_BYTES + 1),
            (b"{".as_ptr(), 1),
        ] {
            let owned = unsafe { netorch_call(input, length) };
            let result: Value =
                serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(owned) }.to_bytes())
                    .unwrap();
            assert_eq!(result["ok"], false);
            unsafe { netorch_free(owned) };
        }
        let dir = tempfile::tempdir().unwrap();
        let request = json!({"root":dir.path(),"method":"capabilities"}).to_string();
        let owned = unsafe { netorch_call(request.as_ptr(), request.len()) };
        let result: Value =
            serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(owned) }.to_bytes()).unwrap();
        assert_eq!(result["data"]["minimumOS"], "27.0");
        unsafe {
            netorch_free(owned);
            netorch_free(std::ptr::null_mut());
        }
    }
    #[test]
    fn daemon_protocol_methods_are_never_served_by_the_bridge() {
        use net_manager_core::daemon_protocol::method;
        let dir = tempfile::tempdir().unwrap();
        for name in method::CAPABILITIES.iter().chain(&[method::HELLO]) {
            assert!(dispatch(dir.path(), name, &json!({})).is_err());
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[test]
    fn profile_wire_preserves_legacy_array_shape_and_redaction() {
        let dir = tempfile::tempdir().unwrap();
        let result=dispatch(dir.path(),"import_share_link",&json!({"id":"one","name":"","link":"vless://private-id@example.test:443?security=tls#One"})).unwrap();
        assert!(result.is_array());
        assert_eq!(result[0]["id"], "one");
        assert!(!result.to_string().contains("private-id"));
        assert_eq!(
            dispatch(dir.path(), "rename", &json!({"id":"one","name":"Renamed"})).unwrap()[0]
                ["name"],
            "Renamed"
        );
    }
    #[test]
    fn relative_roots_and_invalid_wire_inputs_are_rejected_without_store_changes() {
        assert!(dispatch(Path::new("relative"), "profiles", &json!({})).is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(dispatch(
            dir.path(),
            "create_static",
            &json!({"id":"bad","name":"Bad","cidrs":"not-a-route"})
        )
        .is_err());
        assert!(dispatch(dir.path(), "import_sets", &json!({"payload":"not-json"})).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
