//! JSON face of the connection engine (`net-manager-engine`) for the native
//! client. All orchestration — Xray loopback runtime, system proxy, requests
//! to the privileged helper — lives in the engine; this module only decodes
//! arguments and encodes the engine's answers.
use net_manager_core::daemon_protocol::{OpenVpnCredentials, OpenVpnUserPass};
use net_manager_core::models::Profile;
use net_manager_core::profiles::ProfileStore;
use net_manager_engine::{
    find_profile,
    macos_services::{ConnectProfileOutcome, MacosServices},
    Engine,
};
use serde_json::{json, Value};
use std::path::Path;

fn find(profiles: &[Profile], args: &Value) -> Result<Profile, String> {
    find_profile(profiles, args["id"].as_str().unwrap_or_default())
}

fn encode(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|_| "Could not encode the result".into())
}

/// Credentials typed into the app, passed as flat strings.
pub(crate) fn credentials_from_args(args: &Value) -> Option<OpenVpnCredentials> {
    let text = |key: &str| {
        args[key]
            .as_str()
            .map(str::to_string)
            .filter(|value| !value.is_empty())
    };
    let user_pass = match (text("username"), text("password")) {
        (Some(username), Some(password)) => Some(OpenVpnUserPass { username, password }),
        _ => None,
    };
    let passphrase = text("passphrase");
    (user_pass.is_some() || passphrase.is_some()).then_some(OpenVpnCredentials {
        auth_user_pass: user_pass,
        private_key_passphrase: passphrase,
    })
}

/// A `net.intent.set` request from the client's string arguments:
/// `destinations` separated by commas, spaces or lines; `kind` `direct` or
/// `interface` with its `interface`.
fn intent_params(
    args: &Value,
) -> Result<net_manager_core::daemon_protocol::NetIntentSetParams, String> {
    use net_manager_core::daemon_protocol::{NetIntentPath, NetIntentSetParams};
    let text = |key: &str| args[key].as_str().unwrap_or_default().trim().to_string();
    let destinations = text("destinations")
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|part| !part.is_empty())
        .map(String::from)
        .collect();
    let interface = text("interface");
    Ok(NetIntentSetParams {
        id: text("id"),
        destinations,
        path: NetIntentPath {
            gateway: None,
            kind: text("kind"),
            interface: (!interface.is_empty()).then_some(interface),
        },
        metric: text("metric").parse().ok(),
        enabled: match args["enabled"].as_str() {
            Some("true") => Some(true),
            Some("false") => Some(false),
            _ => None,
        },
    })
}

/// A conditional rule from the client's string arguments. `routes` has one
/// route per line (or after `;`): `10.99.0.0/24` or `10.99.0.0/24 via 10.1.1.1`.
fn cond_rule_params(
    args: &Value,
) -> Result<net_manager_core::daemon_protocol::ConditionalRouteRule, String> {
    use net_manager_core::daemon_protocol::{ConditionalRouteRule, RouteCondition};
    use net_manager_core::models::PolicyRoute;
    let text = |key: &str| args[key].as_str().unwrap_or_default().trim().to_string();
    let prefix = text("prefix")
        .parse()
        .map_err(|_| "The condition network must look like 10.228.32.0/21".to_string())?;
    let mut routes = Vec::new();
    for line in text("routes").split(['\n', ';']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let destination = words.next().unwrap_or_default();
        let via = match (words.next(), words.next(), words.next()) {
            (None, ..) => None,
            (Some("via"), Some(gateway), None) => Some(
                gateway
                    .parse()
                    .map_err(|_| format!("'{gateway}' is not a gateway address"))?,
            ),
            _ => {
                return Err(format!(
                    "'{line}' must look like 10.99.0.0/24 or 10.99.0.0/24 via 10.1.1.1"
                ))
            }
        };
        routes.push(PolicyRoute {
            destination: destination
                .parse()
                .map_err(|_| format!("'{destination}' must look like 10.99.0.0/24"))?,
            metric: 100,
            via,
        });
    }
    Ok(ConditionalRouteRule {
        id: text("id"),
        name: text("name"),
        enabled: args["enabled"].as_str() != Some("false"),
        condition: RouteCondition::InterfaceAddressIn { prefix },
        routes,
    })
}

pub(crate) fn handle(
    root: &Path,
    store: &ProfileStore,
    method: &str,
    args: &Value,
) -> Option<Result<Value, String>> {
    let engine = Engine::new(root);
    let load = || {
        store
            .load()
            .map(|document| document.profiles)
            .map_err(|_| "Profiles could not be loaded".to_string())
    };
    let result = match method {
        "runtime" => load().and_then(|profiles| encode(engine.snapshot(&profiles)?)),
        "install_xray" => engine
            .install_xray(args["archivePath"].as_str())
            .map(|()| json!({"installed": true})),
        "credential_requirements" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            let needs = engine.credential_requirements(&profile)?;
            Ok(json!({"userPass": needs.user_pass, "keyPassphrase": needs.key_passphrase}))
        }),
        "connect" => (|| {
            let service = MacosServices::new(root)?;
            let outcome = service.connect_profile(
                args["id"].as_str().unwrap_or_default(),
                credentials_from_args(args),
                args["remember"].as_str() == Some("true"),
                &service.native_credential_store()?,
            )?;
            match outcome {
                ConnectProfileOutcome::Connected { .. } => encode(engine.snapshot(&load()?)?),
                ConnectProfileOutcome::CredentialsRequired { .. } => {
                    Err("OpenVPN credentials required".into())
                }
            }
        })(),
        "disconnect" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            encode(engine.disconnect(&profile, &profiles)?)
        }),
        "set_system_proxy" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            let enable = args["enabled"].as_str() == Some("true");
            encode(engine.set_system_proxy(&profile, &profiles, enable)?)
        }),
        // Leftovers of a crashed session; the helper does the cleanup itself,
        // so no elevation is ever asked for.
        "recovery_report" => load().and_then(|profiles| encode(engine.recovery_report(&profiles)?)),
        "recovery_cleanup" => {
            load().and_then(|profiles| encode(engine.recovery_cleanup(&profiles)?))
        }
        "shutdown" => load().and_then(|profiles| {
            engine.shutdown(&profiles)?;
            Ok(json!({}))
        }),
        // Privileged: the helper decides what may be switched.
        "set_interface_state" => engine
            .set_interface_state(
                args["name"].as_str().unwrap_or_default(),
                args["up"].as_str() == Some("true"),
            )
            .map(|()| json!({})),
        // Routing intents live in the helper; the bridge only forwards.
        "intents" => engine.intents().and_then(encode),
        "set_intent" => intent_params(args).and_then(|params| {
            engine.set_intent(params)?;
            Ok(json!({}))
        }),
        "delete_intent" => engine
            .delete_intent(args["id"].as_str().unwrap_or_default())
            .map(|()| json!({})),
        "cond_rules" => engine.cond_rules().and_then(encode),
        "put_cond_rule" => cond_rule_params(args)
            .and_then(|rule| engine.put_cond_rule(rule))
            .and_then(encode),
        "delete_cond_rule" => engine
            .remove_cond_rule(args["id"].as_str().unwrap_or_default())
            .map(|removed| json!({ "removed": removed })),
        "helper_log" => Ok(json!(net_manager_engine::macos_services::helper_log())),
        "log" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            Ok(json!(engine.log(&profile)?))
        }),
        _ => return None,
    };
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_credentials_need_a_full_pair_or_a_passphrase() {
        let both = credentials_from_args(&json!({"username": "u", "password": "p"})).unwrap();
        let pair = both.auth_user_pass.unwrap();
        assert_eq!((pair.username.as_str(), pair.password.as_str()), ("u", "p"));
        assert!(credentials_from_args(&json!({"username": "u"})).is_none());
        assert!(credentials_from_args(&json!({"passphrase": ""})).is_none());
        assert!(credentials_from_args(&json!({})).is_none());
        let key = credentials_from_args(&json!({"passphrase": "k"})).unwrap();
        assert_eq!(key.private_key_passphrase.as_deref(), Some("k"));
    }

    #[test]
    fn an_unknown_profile_id_reads_as_not_found() {
        assert_eq!(
            find(&[], &json!({"id": "x"})).unwrap_err(),
            "Profile not found"
        );
    }

    #[test]
    fn the_recovery_report_has_the_shared_shape_and_asks_for_no_elevation() {
        // Read-only: lists the helper's records when one answers, else nothing.
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let report = handle(dir.path(), &store, "recovery_report", &json!({}))
            .unwrap()
            .unwrap();
        assert!(report["issues"].is_array());
        assert_eq!(report["requiresElevation"], false);
    }

    #[test]
    fn intent_arguments_are_split_and_typed() {
        let params = intent_params(&json!({
            "id": "office", "destinations": "10.0.0.0/8, 172.16.0.0/12\n192.0.2.9;fd00::/8",
            "kind": "interface", "interface": "utun5", "metric": "50", "enabled": "false",
        }))
        .unwrap();
        assert_eq!(params.id, "office");
        assert_eq!(
            params.destinations,
            ["10.0.0.0/8", "172.16.0.0/12", "192.0.2.9", "fd00::/8"]
        );
        assert_eq!(params.path.kind, "interface");
        assert_eq!(params.path.interface.as_deref(), Some("utun5"));
        assert_eq!((params.metric, params.enabled), (Some(50), Some(false)));
        let plain =
            intent_params(&json!({"id": "x", "destinations": "10.0.0.0/8", "kind": "direct"}))
                .unwrap();
        assert_eq!(
            (plain.path.interface, plain.metric, plain.enabled),
            (None, None, None)
        );
    }

    #[test]
    fn rule_arguments_are_parsed_into_a_typed_rule() {
        let rule = cond_rule_params(&json!({
            "id": "office", "name": " Office LAN ", "prefix": "10.228.32.0/21", "enabled": "true",
            "routes": "10.99.0.0/24\n10.98.0.0/16 via 10.228.32.9; 10.97.0.0/16",
        }))
        .unwrap();
        assert_eq!(
            (rule.id.as_str(), rule.name.as_str()),
            ("office", "Office LAN")
        );
        assert_eq!(rule.routes.len(), 3);
        assert_eq!(rule.routes[1].via, Some("10.228.32.9".parse().unwrap()));
        assert_eq!(rule.routes[2].via, None);
        assert!(rule.enabled);
        let off = cond_rule_params(&json!({"id": "x", "name": "x", "prefix": "10.0.0.0/8", "enabled": "false", "routes": "10.1.0.0/16"})).unwrap();
        assert!(!off.enabled);
        for (args, why) in [
            (
                json!({"prefix": "nonsense", "routes": "10.1.0.0/16"}),
                "network",
            ),
            (
                json!({"prefix": "10.0.0.0/8", "routes": "10.1.0.0/16 via nope"}),
                "gateway",
            ),
            (
                json!({"prefix": "10.0.0.0/8", "routes": "10.1.0.0/16 around 10.0.0.1"}),
                "must look like",
            ),
            (
                json!({"prefix": "10.0.0.0/8", "routes": "bad"}),
                "must look like",
            ),
        ] {
            let error = cond_rule_params(&args).unwrap_err();
            assert!(error.contains(why), "{error}");
        }
    }

    #[test]
    fn methods_of_other_modules_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        assert!(handle(dir.path(), &store, "profiles", &json!({})).is_none());
    }
}
