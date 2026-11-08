//! A static-route profile (`none` backend): its routes through a named
//! interface, kept by the privileged helper as a routing intent. Connecting
//! the profile creates the intent, disconnecting deletes it, and the helper's
//! reconcile keeps the routes in place (and waits while the interface is
//! absent). Routes with their own gateway and the endpoint bypass become
//! further intents of the same profile. The rules live in
//! `core::route_intents`.
use crate::privileged::Privileged;
use net_manager_core::daemon_protocol::{
    method, NetIntentDelParams, NetIntentListResult, NetIntentResult, NetIntentView,
};
use net_manager_core::models::{Profile, TunnelBackend, TunnelStatus};
use net_manager_core::route_intents::{static_belongs, static_intents, static_state};
use serde_json::json;
use std::net::{IpAddr, ToSocketAddrs};

pub(crate) fn is_static(profile: &Profile) -> bool {
    profile.backend == TunnelBackend::None
}

fn helper_message(error: net_manager_core::helper_client::HelperError) -> String {
    use net_manager_core::daemon_protocol::ErrorCode;
    use net_manager_core::helper_client::HelperError;
    match error {
        HelperError::Rejected(body) if body.code == ErrorCode::UnsupportedMethod => {
            "The installed helper is too old for static routes. Update it in Settings.".to_string()
        }
        other => crate::helper_error(other),
    }
}

/// Whether the machine has an interface with this name right now.
fn interface_exists(name: &str) -> bool {
    net_manager_core::explorer::list_interfaces()
        .map(|list| list.iter().any(|interface| interface.name == name))
        .unwrap_or(false)
}

fn list_intents(privileged: &dyn Privileged) -> Result<Vec<NetIntentView>, String> {
    let list: NetIntentListResult = privileged
        .call(method::NET_INTENT_LIST, json!({}))
        .map_err(helper_message)?;
    Ok(list.intents)
}

/// The profile's own intents among everything the helper holds.
fn own_intents(
    privileged: &dyn Privileged,
    profile: &Profile,
) -> Result<Vec<NetIntentView>, String> {
    Ok(list_intents(privileged)?
        .into_iter()
        .filter(|intent| static_belongs(&profile.id, &intent.id))
        .collect())
}

/// Addresses for the profile's endpoint bypass entries: literal IPs as they
/// are, names through `resolve`. A name that does not resolve fails the start
/// (the error names the entry's position, never the host).
fn bypass_addresses(
    profile: &Profile,
    resolve: &dyn Fn(&str) -> Vec<IpAddr>,
) -> Result<Vec<IpAddr>, String> {
    let mut addresses = Vec::new();
    for (index, entry) in profile.endpoint_bypasses.iter().enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let found = match entry.parse::<IpAddr>() {
            Ok(address) => vec![address],
            Err(_) => resolve(entry),
        };
        if found.is_empty() {
            return Err(format!(
                "Endpoint bypass entry {} cannot be resolved",
                index + 1
            ));
        }
        for address in found {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    Ok(addresses)
}

fn system_resolve(host: &str) -> Vec<IpAddr> {
    (host, 0)
        .to_socket_addrs()
        .map(|found| found.map(|socket| socket.ip()).collect())
        .unwrap_or_default()
}

pub(crate) fn start(privileged: &dyn Privileged, profile: &Profile) -> Result<(), String> {
    start_with(privileged, profile, &system_resolve)
}

fn start_with(
    privileged: &dyn Privileged,
    profile: &Profile,
    resolve: &dyn Fn(&str) -> Vec<IpAddr>,
) -> Result<(), String> {
    let bypass = bypass_addresses(profile, resolve)?;
    let intents = static_intents(profile, &bypass)?;
    // Strict by default, like the other clients: a missing interface is an
    // error unless the profile asked to wait for it.
    let interface = profile.interface_name.trim();
    let uses_interface = profile.routes.iter().any(|route| route.via.is_none());
    if uses_interface && !profile.wait_for_interface && !interface_exists(interface) {
        return Err(format!(
            "The interface {interface} is not present. Turn on waiting for the interface to arm these routes."
        ));
    }
    let mut applied: Vec<String> = Vec::new();
    for intent in intents {
        let id = intent.id.clone();
        if let Err(error) = privileged.call::<_, NetIntentResult>(method::NET_INTENT_SET, intent) {
            // Do not leave half a profile behind.
            for done in applied.iter().rev() {
                let _ = privileged.call::<_, NetIntentResult>(
                    method::NET_INTENT_DEL,
                    NetIntentDelParams { id: done.clone() },
                );
            }
            return Err(helper_message(error));
        }
        applied.push(id);
    }
    Ok(())
}

pub(crate) fn stop(privileged: &dyn Privileged, profile: &Profile) -> Result<(), String> {
    let own = own_intents(privileged, profile)?;
    if own.is_empty() {
        return Err("The connection is not running".into());
    }
    // The routes go before the bypass that protects the tunnel's own packets.
    let mut ids: Vec<String> = own.into_iter().map(|intent| intent.id).collect();
    ids.sort_by_key(|id| id.ends_with("-bypass"));
    let mut failure = None;
    for id in ids {
        if let Err(error) =
            privileged.call::<_, NetIntentResult>(method::NET_INTENT_DEL, NetIntentDelParams { id })
        {
            failure.get_or_insert_with(|| helper_message(error));
        }
    }
    failure.map_or(Ok(()), Err)
}

/// Stopped when the helper has none of its intents or cannot be asked.
pub(crate) fn status(privileged: &dyn Privileged, profile: &Profile) -> TunnelStatus {
    let own = own_intents(privileged, profile).unwrap_or_default();
    let (state, message) = static_state(&own);
    TunnelStatus {
        profile_id: profile.id.clone(),
        state,
        message,
        interface_name: Some(profile.interface_name.clone()).filter(|name| !name.is_empty()),
        failover: None,
        watchdog: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{ErrorBody, ErrorCode, HelloResult};
    use net_manager_core::helper_client::HelperError;
    use net_manager_core::models::{PolicyRoute, TunnelState};
    use serde_json::Value;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// A helper that keeps intents like the real one and records requests.
    #[derive(Default)]
    struct Fake {
        intents: Mutex<Vec<Value>>,
        calls: Mutex<Vec<(String, Value)>>,
        old: bool,
    }

    impl Privileged for Fake {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            unreachable!()
        }
        fn call_raw(&self, name: &str, params: Value) -> Result<Value, HelperError> {
            self.calls
                .lock()
                .unwrap()
                .push((name.into(), params.clone()));
            if self.old {
                return Err(HelperError::Rejected(ErrorBody {
                    code: ErrorCode::UnsupportedMethod,
                    message: "no".into(),
                }));
            }
            let mut intents = self.intents.lock().unwrap();
            match name {
                method::NET_INTENT_SET => {
                    let id = params["id"].as_str().unwrap().to_string();
                    intents.retain(|i| i["id"] != id.as_str());
                    intents.push(json!({
                        "id": id, "destinations": params["destinations"], "path": params["path"],
                        "metric": 5, "enabled": true, "status": "effective",
                        "detail": "1 route(s) in place", "installed": 1, "wanted": 1
                    }));
                    Ok(json!({ "id": id }))
                }
                method::NET_INTENT_DEL => {
                    let id = params["id"].as_str().unwrap().to_string();
                    let before = intents.len();
                    intents.retain(|i| i["id"] != id.as_str());
                    if intents.len() == before {
                        return Err(HelperError::Rejected(ErrorBody {
                            code: ErrorCode::NotFound,
                            message: "There is no intent with that name".into(),
                        }));
                    }
                    Ok(json!({ "id": id }))
                }
                method::NET_INTENT_LIST => Ok(json!({ "intents": *intents })),
                _ => Err(HelperError::Protocol("unexpected".into())),
            }
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    fn profile(wait: bool) -> Profile {
        Profile {
            id: "office".into(),
            name: "Office".into(),
            backend: TunnelBackend::None,
            // Not a real interface on any machine, so the strict check fails.
            interface_name: "en97".into(),
            routes: vec![PolicyRoute {
                destination: "192.0.2.0/24".parse().unwrap(),
                metric: 5,
                via: None,
            }],
            wait_for_interface: wait,
            ..Default::default()
        }
    }

    #[test]
    fn only_the_route_backend_is_static() {
        assert!(is_static(&profile(false)));
        let mut wg = profile(false);
        wg.backend = TunnelBackend::WireGuard;
        assert!(!is_static(&wg));
    }

    #[test]
    fn connecting_creates_the_intent_and_the_status_follows_it() {
        let helper = Fake::default();
        let p = profile(true);
        assert_eq!(status(&helper, &p).state, TunnelState::Stopped);
        start(&helper, &p).unwrap();
        let sent = helper
            .calls
            .lock()
            .unwrap()
            .iter()
            .find(|(n, _)| n == method::NET_INTENT_SET)
            .cloned()
            .unwrap();
        assert_eq!(sent.1["id"], "static-office");
        assert_eq!(sent.1["path"]["interface"], "en97");
        let after = status(&helper, &p);
        assert_eq!(after.state, TunnelState::Running);
        assert_eq!(after.interface_name.as_deref(), Some("en97"));
        stop(&helper, &p).unwrap();
        assert_eq!(status(&helper, &p).state, TunnelState::Stopped);
    }

    #[test]
    fn stopping_what_is_not_running_says_so() {
        let helper = Fake::default();
        assert_eq!(
            stop(&helper, &profile(true)).unwrap_err(),
            "The connection is not running"
        );
    }

    #[test]
    fn a_missing_interface_is_an_error_unless_the_profile_waits_for_it() {
        let helper = Fake::default();
        let error = start(&helper, &profile(false)).unwrap_err();
        assert!(
            error.contains("en97") && error.contains("waiting"),
            "{error}"
        );
        assert!(helper.calls.lock().unwrap().is_empty(), "nothing is sent");
        start(&helper, &profile(true)).unwrap();
    }

    #[test]
    fn a_profile_that_cannot_be_enforced_is_refused_before_the_helper_is_asked() {
        let helper = Fake::default();
        let mut with_gateway = profile(true);
        with_gateway.routes[0].via = Some("127.0.0.1".parse().unwrap());
        assert!(start(&helper, &with_gateway)
            .unwrap_err()
            .contains("gateway"));
        assert!(helper.calls.lock().unwrap().is_empty());
    }

    fn ids(helper: &Fake) -> Vec<String> {
        helper
            .intents
            .lock()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap().to_string())
            .collect()
    }

    fn external(wait: bool) -> Profile {
        let mut p = profile(wait);
        p.endpoint_bypasses = vec!["203.0.113.7".into(), "vpn.example".into(), " ".into()];
        p.routes.push(PolicyRoute {
            destination: "198.51.100.0/24".parse().unwrap(),
            metric: 5,
            via: Some("10.0.0.1".parse().unwrap()),
        });
        p
    }

    fn resolver(host: &str) -> Vec<IpAddr> {
        if host == "vpn.example" {
            vec![
                "203.0.113.7".parse().unwrap(),
                "2001:db8::7".parse().unwrap(),
            ]
        } else {
            vec![]
        }
    }

    #[test]
    fn one_profile_is_several_intents_applied_bypass_first_and_removed_together() {
        let helper = Fake::default();
        let p = external(true);
        start_with(&helper, &p, &resolver).unwrap();
        assert_eq!(
            ids(&helper),
            ["static-office-bypass", "static-office", "static-office-gw1"]
        );
        let calls = helper.calls.lock().unwrap();
        let bypass = &calls
            .iter()
            .find(|(_, v)| v["id"] == "static-office-bypass")
            .unwrap()
            .1;
        // Names are resolved, literals kept, duplicates and blanks dropped.
        assert_eq!(
            bypass["destinations"],
            json!(["203.0.113.7/32", "2001:db8::7/128"])
        );
        assert_eq!(bypass["path"]["kind"], "direct");
        drop(calls);
        assert_eq!(status(&helper, &p).state, TunnelState::Running);
        // Someone else's intent is left alone, even with a similar name.
        helper.intents.lock().unwrap().push(json!({
            "id": "static-office2", "destinations": ["192.0.2.0/24"], "path": {"kind": "direct"},
            "metric": 5, "enabled": true, "status": "effective", "detail": "", "installed": 1, "wanted": 1
        }));
        stop(&helper, &p).unwrap();
        assert_eq!(ids(&helper), ["static-office2"]);
        let order: Vec<_> = helper
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == method::NET_INTENT_DEL)
            .map(|(_, v)| v["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(order.last().unwrap(), "static-office-bypass");
        assert_eq!(status(&helper, &p).state, TunnelState::Stopped);
    }

    #[test]
    fn an_endpoint_that_does_not_resolve_stops_the_start_before_anything_is_sent() {
        let helper = Fake::default();
        let mut p = external(true);
        p.endpoint_bypasses = vec!["gone.example".into()];
        let error = start_with(&helper, &p, &resolver).unwrap_err();
        assert!(
            error.contains("entry 1") && !error.contains("gone"),
            "{error}"
        );
        assert!(helper.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_failure_part_way_removes_what_was_already_applied() {
        struct Failing(Fake);
        impl Privileged for Failing {
            fn hello(&self) -> Result<HelloResult, HelperError> {
                unreachable!()
            }
            fn call_raw(&self, name: &str, params: Value) -> Result<Value, HelperError> {
                if name == method::NET_INTENT_SET && params["id"] == "static-office-gw1" {
                    return Err(HelperError::Rejected(ErrorBody {
                        code: ErrorCode::InvalidParams,
                        message: "no".into(),
                    }));
                }
                self.0.call_raw(name, params)
            }
            fn log_dir(&self) -> PathBuf {
                PathBuf::new()
            }
        }
        let helper = Failing(Fake::default());
        assert!(start_with(&helper, &external(true), &resolver).is_err());
        assert!(ids(&helper.0).is_empty(), "{:?}", ids(&helper.0));
    }

    #[test]
    fn gateway_only_routes_need_no_interface() {
        let helper = Fake::default();
        let mut p = external(false);
        p.interface_name = String::new();
        p.routes.remove(0);
        p.endpoint_bypasses.clear();
        // Strict mode only checks an interface the profile actually uses.
        start_with(&helper, &p, &resolver).unwrap();
        assert_eq!(ids(&helper), ["static-office-gw1"]);
    }

    #[test]
    fn an_old_helper_is_explained_and_reads_as_stopped() {
        let helper = Fake {
            old: true,
            ..Default::default()
        };
        let error = start(&helper, &profile(true)).unwrap_err();
        assert!(
            error.contains("too old") && error.contains("Settings"),
            "{error}"
        );
        assert_eq!(status(&helper, &profile(true)).state, TunnelState::Stopped);
    }

    #[test]
    fn an_intent_waiting_for_its_interface_counts_as_running_with_a_note() {
        let helper = Fake::default();
        helper.intents.lock().unwrap().push(json!({
            "id": "static-office", "destinations": ["192.0.2.0/24"],
            "path": {"kind": "interface", "interface": "en97"}, "metric": 5, "enabled": true,
            "status": "deferred", "detail": "interface en97 is absent", "installed": 0, "wanted": 0
        }));
        let s = status(&helper, &profile(true));
        assert_eq!(s.state, TunnelState::Running);
        assert_eq!(s.message.as_deref(), Some("interface en97 is absent"));
    }
}
