//! `ls`, `status`, `up` and `down` over the network daemon. Each command
//! returns the JSON value and the text it prints, so tests need no terminal.
use super::args::UpArgs;
use super::auth;
use super::ctx::Ctx;
use super::endpoints;
#[cfg(test)]
use super::hold;
use super::library;
use crate::prompt;
use crate::render::{kind_of, row_of, table};
use crate::target::{self, Input};
use net_manager_core::daemon_protocol::OpenVpnCredentials;
use net_manager_core::models::{Profile, TunnelBackend, TunnelState, TunnelStatus};
use net_manager_engine::linux::openvpn_requirements;
use net_manager_engine::linux_engine::LinuxEngine;
use serde_json::{json, Value};

pub type Output = (Value, String);

pub fn ls(ctx: &Ctx) -> Result<Output, String> {
    let profiles = ctx.profiles()?;
    let servers: Vec<Option<String>> = profiles
        .iter()
        .map(|profile| endpoints::active_name(ctx, profile))
        .collect();
    let rows: Vec<_> = profiles.iter().map(row_of).collect();
    let mut value = serde_json::to_value(&rows).map_err(|_| "Could not encode the list")?;
    for (item, server) in value.as_array_mut().into_iter().flatten().zip(&servers) {
        item["server"] = json!(server);
    }
    let text = if rows.is_empty() {
        "No profiles yet. `netorch add <link|url|file>` saves one.".to_string()
    } else {
        table(
            &["ID", "NAME", "KIND", "ROLE", "SERVER"],
            &rows
                .iter()
                .zip(&servers)
                .map(|(row, server)| {
                    vec![
                        row.id.clone(),
                        row.name.clone(),
                        row.kind.into(),
                        row.role.into(),
                        server.clone().unwrap_or_default(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    };
    Ok((value, text))
}

fn state_word(state: TunnelState) -> &'static str {
    match state {
        TunnelState::Stopped => "stopped",
        TunnelState::Running => "running",
        TunnelState::Failed => "failed",
    }
}

fn status_json(ctx: &Ctx, profile: &Profile, status: &TunnelStatus) -> Value {
    let failover = serde_json::to_value(&status.failover).unwrap_or(Value::Null);
    let active_node = failover
        .get("activeKey")
        .and_then(Value::as_str)
        .and_then(|key| endpoints::node_name(ctx, profile, key));
    json!({
        "server": endpoints::active_name(ctx, profile),
        "id": profile.id,
        "name": profile.name,
        "kind": kind_of(profile),
        "state": state_word(status.state),
        "interface": status.interface_name,
        "message": status.message,
        "failover": failover,
        "failoverServer": active_node,
        "watchdog": status.watchdog,
    })
}

/// The node actually carrying traffic: the primary name, or the backup's
/// name flagged while the failover chain is live.
fn active_node(ctx: &Ctx, profile: &Profile, status: &TunnelStatus) -> String {
    let failover = serde_json::to_value(&status.failover).unwrap_or(Value::Null);
    if let Some(key) = failover.get("activeKey").and_then(Value::as_str) {
        if let Some(name) = endpoints::node_name(ctx, profile, key) {
            let on_backup = failover
                .get("failoverActive")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            return if on_backup {
                format!("{name} (backup)")
            } else {
                name
            };
        }
    }
    endpoints::active_name(ctx, profile).unwrap_or_default()
}

/// Profiles supported by the system daemon or shared user runtime.
fn daemon_profiles(ctx: &Ctx) -> Result<Vec<Profile>, String> {
    Ok(ctx
        .profiles()?
        .into_iter()
        .filter(LinuxEngine::handles)
        .collect())
}

pub fn status(ctx: &Ctx, target: Option<&str>) -> Result<Output, String> {
    let profiles = match target {
        Some(query) => vec![ctx.find(query)?],
        None => daemon_profiles(ctx)?,
    };
    #[cfg(target_os = "linux")]
    let mut statuses =
        net_manager_engine::linux_runtime::statuses_for(&ctx.engine, &profiles)?.into_iter();
    let mut rows = Vec::new();
    for profile in &profiles {
        #[cfg(target_os = "linux")]
        let status = statuses
            .next()
            .ok_or("The requested connection status is unavailable")?;
        #[cfg(not(target_os = "linux"))]
        let status = ctx.engine.status(profile)?;
        if target.is_some() || status.state != TunnelState::Stopped {
            rows.push((profile, status));
        }
    }
    let value = Value::Array(rows.iter().map(|(p, s)| status_json(ctx, p, s)).collect());
    let text = if rows.is_empty() {
        "No connection is running.".to_string()
    } else {
        table(
            &["ID", "NAME", "STATE", "INTERFACE", "SERVER"],
            &rows
                .iter()
                .map(|(profile, status)| {
                    vec![
                        profile.id.clone(),
                        profile.name.clone(),
                        state_word(status.state).into(),
                        status.interface_name.clone().unwrap_or_default(),
                        active_node(ctx, profile, status),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    };
    Ok((value, text))
}

/// A saved profile, or the one `up` imports from a link, URL or file first.
fn resolve_or_add(ctx: &Ctx, args: &UpArgs) -> Result<Profile, String> {
    if let Input::Saved(query) = target::classify(&args.target, |path| path.is_file()) {
        return ctx.find(&query);
    }
    let mut added = library::add_input(ctx, &args.target, args.name.as_deref())?;
    if added.len() != 1 {
        return Err(format!(
            "That subscription added {} profiles; pick one from `netorch ls` and run `netorch up <name>`",
            added.len()
        ));
    }
    let profile = added.remove(0);
    eprintln!("Saved \"{}\"", profile.name);
    Ok(profile)
}

#[cfg(not(target_os = "linux"))]
/// Connects a profile the daemon runs; a failed start is an error.
pub fn connect(
    ctx: &Ctx,
    profile: &Profile,
    credentials: Option<OpenVpnCredentials>,
) -> Result<TunnelStatus, String> {
    if !LinuxEngine::handles(profile) {
        return Err(format!(
            "\"{}\" ({}) does not run through the network daemon; netorch connects \
             WireGuard, OpenVPN and Xray TUN profiles for now",
            profile.name,
            kind_of(profile)
        ));
    }
    let status = auth::run(ctx.root_user, || {
        ctx.engine
            .connect(&ctx.vault(), profile, credentials.clone(), ctx)
    })?;
    if status.state == TunnelState::Failed {
        return Err(status
            .message
            .unwrap_or_else(|| format!("\"{}\" failed to connect", profile.name)));
    }
    Ok(status)
}

#[cfg(target_os = "linux")]
pub fn connect(
    ctx: &Ctx,
    profile: &Profile,
    credentials: Option<OpenVpnCredentials>,
) -> Result<TunnelStatus, String> {
    auth::run(ctx.root_user, || {
        net_manager_engine::linux_runtime::connect(
            &net_manager_engine::linux_runtime::Context {
                engine: &ctx.engine,
                root: &ctx.root,
                vault: &ctx.vault(),
                store: &ctx.store(),
            },
            &profile.id,
            credentials.clone(),
            ctx,
            None,
        )
    })
}

pub fn up(ctx: &Ctx, args: &UpArgs) -> Result<Output, String> {
    if ctx.root_user && !args.foreground {
        return Err("Use --foreground when connecting as root".into());
    }
    let mut profile = resolve_or_add(ctx, args)?;
    if let Some(server) = &args.endpoint {
        endpoints::use_endpoint(ctx, &profile.id, Some(server))?;
        profile = ctx.find(&profile.id)?;
    }
    let connect_with_prompt = || {
        let needs = openvpn_requirements(&ctx.vault(), &profile)?;
        let credentials = prompt::collect(
            needs.user_pass,
            needs.key_passphrase,
            args.auth_stdin,
            args.passphrase_stdin,
        )?;
        connect(ctx, &profile, credentials)
    };
    let status = if profile.backend == TunnelBackend::OpenVpn {
        if args.auth_stdin || args.passphrase_stdin {
            connect_with_prompt()?
        } else {
            match connect(ctx, &profile, None) {
                Err(error) if error == net_manager_engine::linux_engine::CREDENTIALS_REQUIRED => {
                    connect_with_prompt()?
                }
                result => result?,
            }
        }
    } else {
        connect(ctx, &profile, None)?
    };
    let server = endpoints::active_name(ctx, &profile);
    let text = format!(
        "Connected \"{}\"{}{}",
        profile.name,
        server
            .as_deref()
            .map(|name| format!(" via {name}"))
            .unwrap_or_default(),
        status
            .interface_name
            .as_deref()
            .map(|name| format!(" on {name}"))
            .unwrap_or_default()
    );
    Ok((status_json(ctx, &profile, &status), text))
}

pub fn down(ctx: &Ctx, target: Option<&str>, all: bool) -> Result<Output, String> {
    let profiles = match (target, all) {
        (Some(query), false) => vec![ctx.find(query)?],
        (None, true) => {
            let mut running = Vec::new();
            for profile in daemon_profiles(ctx)? {
                if ctx.engine.status(&profile)?.state != TunnelState::Stopped {
                    running.push(profile);
                }
            }
            running
        }
        _ => return Err("Name a connection, or use --all".into()),
    };
    let mut stopped = Vec::new();
    for profile in &profiles {
        // Only a running tunnel needs the daemon (and polkit); `down` on a
        // stopped one just makes sure nothing is left holding it.
        let running = LinuxEngine::handles(profile)
            && ctx.engine.status(profile)?.state != TunnelState::Stopped;
        if running {
            #[cfg(target_os = "linux")]
            auth::run(ctx.root_user, || {
                net_manager_engine::linux_runtime::disconnect_with_root(
                    &ctx.engine,
                    &ctx.root,
                    &ctx.store(),
                    &profile.id,
                )
            })?;
            #[cfg(not(target_os = "linux"))]
            auth::run(ctx.root_user, || ctx.engine.disconnect(profile))?;
            stopped.push(profile.name.clone());
        }
    }
    let text = if stopped.is_empty() {
        "No connection is running.".to_string()
    } else {
        format!("Disconnected {}", stopped.join(", "))
    };
    Ok((json!({"stopped": stopped}), text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::{compat, route};
    use net_manager_core::daemon_protocol::{
        feature, XrayConnectParams, XrayConnectResult, XrayDisconnectResult, XrayProfileParams,
        XrayStatusResult,
    };
    use net_manager_core::daemon_protocol::{method, HelloResult, PROTOCOL_VERSION};
    use net_manager_core::helper_client::HelperError;
    use net_manager_core::models::{PolicyRoute, TunnelRole};
    use net_manager_engine::Privileged;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeDaemon {
        replies: HashMap<&'static str, Value>,
        calls: Mutex<Vec<String>>,
        /// What the handshake answers; a current, complete daemon by default.
        hello: Option<HelloResult>,
        xray: Option<Mutex<XrayRuntime>>,
    }

    #[derive(Clone, Copy)]
    enum DisconnectFailure {
        Stopped,
        Failed,
        Running,
        Unknown,
    }

    #[derive(Default)]
    struct XrayRuntime {
        active: Option<(String, String)>,
        failed: Option<String>,
        reject_once: Option<String>,
        reject_all: bool,
        disconnect_failure: Option<DisconnectFailure>,
        status_unknown: bool,
        connection_identity: u64,
    }

    impl XrayRuntime {
        fn status(&self, profile_id: String) -> XrayStatusResult {
            let running = self
                .active
                .as_ref()
                .is_some_and(|(id, _)| *id == profile_id);
            XrayStatusResult {
                profile_id: profile_id.clone(),
                state: if running {
                    TunnelState::Running
                } else if self.failed.as_deref() == Some(profile_id.as_str()) {
                    TunnelState::Failed
                } else {
                    TunnelState::Stopped
                },
                interface_name: running.then(|| "xray0".into()),
                dns_applied: running,
                ipv4_covered: running,
                ipv6_covered: running,
                rx_bytes: None,
                tx_bytes: None,
                failover: None,
                watchdog: None,
                proxy_exits: Vec::new(),
            }
        }

        fn request(&mut self, method: &str, params: Value) -> Value {
            match method {
                method::XRAY_CONNECT => {
                    let request: XrayConnectParams = serde_json::from_value(params).unwrap();
                    let config: Value = serde_json::from_str(&request.config).unwrap();
                    let endpoint = config["outbounds"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find_map(|outbound| outbound["settings"]["vnext"][0]["address"].as_str())
                        .expect("generated VLESS config must contain its endpoint")
                        .to_string();
                    let rejected_once = self.reject_once.as_deref() == Some(endpoint.as_str());
                    if self.reject_all || rejected_once {
                        if rejected_once {
                            self.reject_once = None;
                        }
                        self.active = None;
                        self.failed = Some(request.profile_id.clone());
                    } else {
                        self.active = Some((request.profile_id.clone(), endpoint));
                        self.failed = None;
                        self.connection_identity += 1;
                    }
                    serde_json::to_value(XrayConnectResult {
                        status: self.status(request.profile_id),
                    })
                    .unwrap()
                }
                method::XRAY_DISCONNECT => {
                    let request: XrayProfileParams = serde_json::from_value(params).unwrap();
                    if self
                        .active
                        .as_ref()
                        .is_some_and(|(id, _)| *id == request.profile_id)
                    {
                        self.active = None;
                    }
                    self.failed = None;
                    serde_json::to_value(XrayDisconnectResult { stopped: true }).unwrap()
                }
                method::XRAY_STATUS => {
                    let request: XrayProfileParams = serde_json::from_value(params).unwrap();
                    serde_json::to_value(self.status(request.profile_id)).unwrap()
                }
                _ => unreachable!("only Xray lifecycle calls enter the stateful provider"),
            }
        }
    }
    impl Privileged for FakeDaemon {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            Ok(self.hello.clone().unwrap_or_else(|| HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: compat::CLIENT_VERSION.into(),
                uid: 1000,
                capabilities: net_manager_engine::linux_compat::REQUIRED_METHODS
                    .iter()
                    .copied()
                    .chain(std::iter::once(feature::XRAY_TUN_IPV6))
                    .map(str::to_string)
                    .collect(),
                tools: Default::default(),
            }))
        }
        fn call_raw(&self, method: &str, params: Value) -> Result<Value, HelperError> {
            self.calls.lock().unwrap().push(method.into());
            if let Some(runtime) = &self.xray {
                if matches!(
                    method,
                    method::XRAY_CONNECT | method::XRAY_DISCONNECT | method::XRAY_STATUS
                ) {
                    let mut runtime = runtime.lock().unwrap();
                    if method == method::XRAY_DISCONNECT {
                        if let Some(failure) = runtime.disconnect_failure.take() {
                            let request: XrayProfileParams =
                                serde_json::from_value(params).unwrap();
                            match failure {
                                DisconnectFailure::Stopped => {
                                    runtime.active = None;
                                    runtime.failed = None;
                                }
                                DisconnectFailure::Failed => {
                                    runtime.active = None;
                                    runtime.failed = Some(request.profile_id);
                                }
                                DisconnectFailure::Running => {}
                                DisconnectFailure::Unknown => runtime.status_unknown = true,
                            }
                            return Err(HelperError::Protocol("fixture teardown failure".into()));
                        }
                    }
                    if method == method::XRAY_STATUS && runtime.status_unknown {
                        return Err(HelperError::Protocol("fixture status unavailable".into()));
                    }
                    return Ok(runtime.request(method, params));
                }
            }
            self.replies
                .get(method)
                .cloned()
                .ok_or_else(|| HelperError::Protocol(format!("unexpected {method}")))
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    fn wg_status(state: &str) -> Value {
        json!({"profileId": "wg1", "state": state, "interfaceName": "wg-test",
            "latestHandshake": null, "rxBytes": 0, "txBytes": 0, "dnsApplied": true,
            "warnings": []})
    }

    /// A data directory with one WireGuard profile and one static profile.
    fn setup(mut daemon: FakeDaemon) -> (tempfile::TempDir, Ctx, Arc<FakeDaemon>) {
        let dir = tempfile::tempdir().unwrap();
        daemon
            .replies
            .entry(method::OWNED_LIST)
            .or_insert_with(|| json!({"owners": []}));
        let daemon = Arc::new(daemon);
        let mut ctx = Ctx::new(
            dir.path().to_path_buf(),
            LinuxEngine::with_privileged(daemon.clone()),
        )
        .unwrap();
        ctx.root_user = false;
        let imported = ctx
            .vault()
            .store_wireguard_config(
                "wg1",
                b"[Interface]\nPrivateKey = x\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = y\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.5:51820\n",
            )
            .unwrap();
        ctx.store()
            .upsert(Profile {
                id: "wg1".into(),
                name: "Office".into(),
                backend: TunnelBackend::WireGuard,
                config_path: imported.config_path,
                interface_name: "wg1".into(),
                routes: vec![PolicyRoute {
                    destination: "0.0.0.0/1".parse().unwrap(),
                    metric: 5,
                    via: None,
                }],
                ..Default::default()
            })
            .unwrap();
        ctx.store()
            .upsert(Profile {
                id: "static1".into(),
                name: "Static".into(),
                backend: TunnelBackend::None,
                tunnel_role: TunnelRole::Primary,
                ..Default::default()
            })
            .unwrap();
        (dir, ctx, daemon)
    }

    #[test]
    fn ls_lists_every_profile_without_paths() {
        let (_dir, ctx, _) = setup(FakeDaemon::default());
        let (value, text) = ls(&ctx).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 2);
        assert!(text.contains("Office") && text.contains("wireguard"));
        assert!(!value.to_string().contains("configPath"));
    }

    #[test]
    fn status_shows_only_running_connections_and_skips_the_rest() {
        let (_dir, ctx, _) = setup(FakeDaemon {
            replies: HashMap::from([(method::WIREGUARD_STATUS, wg_status("running"))]),
            ..Default::default()
        });
        let (value, _) = status(&ctx, None).unwrap();
        assert_eq!(value[0]["interface"], "wg-test");
        assert_eq!(value[0]["state"], "running");
        let reported: Vec<_> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        assert_eq!(reported, ["wg1"]);
    }

    #[test]
    fn status_with_nothing_running_says_so() {
        let (_dir, ctx, _) = setup(FakeDaemon {
            replies: HashMap::from([(method::WIREGUARD_STATUS, wg_status("stopped"))]),
            ..Default::default()
        });
        let (value, text) = status(&ctx, None).unwrap();
        assert!(value.as_array().unwrap().is_empty());
        assert_eq!(text, "No connection is running.");
    }

    #[test]
    fn up_connects_through_the_daemon() {
        let (_dir, ctx, daemon) = setup(FakeDaemon {
            replies: HashMap::from([(
                method::WIREGUARD_CONNECT,
                json!({"status": wg_status("running")}),
            )]),
            ..Default::default()
        });
        let args = UpArgs {
            target: "Office".into(),
            name: None,
            endpoint: None,
            foreground: false,
            auth_stdin: false,
            passphrase_stdin: false,
        };
        let (value, text) = up(&ctx, &args).unwrap();
        assert_eq!(text, "Connected \"Office\" on wg-test");
        assert_eq!(value["state"], "running");
        assert_eq!(
            daemon.calls.lock().unwrap().as_slice(),
            [method::WIREGUARD_CONNECT]
        );
    }

    #[test]
    fn up_reports_a_failed_connect_as_an_error() {
        let (_dir, ctx, _) = setup(FakeDaemon {
            replies: HashMap::from([(
                method::WIREGUARD_CONNECT,
                json!({"status": wg_status("failed")}),
            )]),
            ..Default::default()
        });
        let args = UpArgs {
            target: "wg1".into(),
            name: None,
            endpoint: None,
            foreground: false,
            auth_stdin: false,
            passphrase_stdin: false,
        };
        assert!(up(&ctx, &args).is_err());
    }

    #[test]
    fn down_all_disconnects_only_what_runs() {
        let (_dir, ctx, _) = setup(FakeDaemon {
            replies: HashMap::from([
                (method::WIREGUARD_STATUS, wg_status("running")),
                (method::WIREGUARD_DISCONNECT, json!({"stopped": true})),
            ]),
            ..Default::default()
        });
        let (value, _) = down(&ctx, None, true).unwrap();
        assert_eq!(value["stopped"], json!(["Office"]));
    }

    #[test]
    fn down_needs_a_target_or_all() {
        let (_dir, ctx, _) = setup(FakeDaemon::default());
        assert!(down(&ctx, None, false).is_err());
    }

    const LINK: &str = "vless://synthetic-id@node.test:443?security=tls#Lab%20Node";

    #[test]
    fn add_saves_a_share_link_under_its_own_name_and_never_prints_it() {
        let (_dir, ctx, daemon) = setup(FakeDaemon::default());
        let (value, text) = library::add(&ctx, LINK, None).unwrap();
        assert_eq!(value[0]["name"], "Lab Node");
        // Xray defaults to TUN on Linux only.
        assert_eq!(
            value[0]["kind"],
            if cfg!(target_os = "linux") {
                "xray-tun"
            } else {
                "xray-socks"
            }
        );
        assert!(text.contains("Lab Node"));
        assert!(!text.contains("synthetic-id") && !value.to_string().contains("node.test"));
        assert_eq!(ctx.profiles().unwrap().len(), 3);
        assert!(daemon.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn add_takes_a_name_and_a_wireguard_file() {
        let (dir, ctx, _) = setup(FakeDaemon::default());
        let file = dir.path().join("home.conf");
        std::fs::write(
            &file,
            "[Interface]\nPrivateKey = x\nAddress = 10.9.0.3/32\n[Peer]\nPublicKey = y\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.9:51820\n",
        )
        .unwrap();
        let (value, _) = library::add(&ctx, file.to_str().unwrap(), Some("Home")).unwrap();
        assert_eq!(value[0]["name"], "Home");
        assert_eq!(value[0]["kind"], "wireguard");
    }

    #[test]
    fn add_refuses_what_is_not_a_link_url_or_file() {
        let (_dir, ctx, _) = setup(FakeDaemon::default());
        assert!(library::add(&ctx, "no-such-profile", None).is_err());
        assert!(library::add(&ctx, "vless://", None).is_err());
        assert_eq!(ctx.profiles().unwrap().len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn up_imports_a_link_first_then_connects_its_actual_endpoint() {
        let (_dir, ctx, daemon) = setup(FakeDaemon {
            xray: Some(Mutex::new(XrayRuntime::default())),
            ..Default::default()
        });
        let (value, text) = up(
            &ctx,
            &UpArgs {
                target: LINK.into(),
                name: None,
                endpoint: None,
                foreground: false,
                auth_stdin: false,
                passphrase_stdin: false,
            },
        )
        .unwrap();
        let profile = ctx.find(value["id"].as_str().unwrap()).unwrap();
        assert_eq!(profile.backend, TunnelBackend::Xray);
        assert!(ctx
            .vault()
            .is_managed_profile_path(&profile.id, &profile.config_path));
        assert!(profile.config_path.is_file());
        assert_eq!(ctx.profiles().unwrap().len(), 3);
        assert_eq!(
            ctx.engine.status(&profile).unwrap().state,
            TunnelState::Running
        );
        let runtime = daemon.xray.as_ref().unwrap().lock().unwrap();
        assert_eq!(
            runtime.active,
            Some((profile.id.clone(), "node.test".into()))
        );
        assert!(!text.contains(LINK) && !value.to_string().contains("node.test"));
    }

    #[test]
    fn rename_changes_only_the_name() {
        let (_dir, ctx, _) = setup(FakeDaemon::default());
        library::rename(&ctx, "Office", "HQ").unwrap();
        assert_eq!(ctx.find("wg1").unwrap().name, "HQ");
        assert!(library::rename(&ctx, "wg1", "  ").is_err());
    }

    #[test]
    fn rm_deletes_a_stopped_profile_and_its_stored_config() {
        let (_dir, ctx, _) = setup(FakeDaemon {
            replies: HashMap::from([
                (method::WIREGUARD_STATUS, wg_status("stopped")),
                (
                    method::ALWAYS_ON_LIST,
                    json!({"profiles": [], "paused": false, "supportedKinds": []}),
                ),
            ]),
            ..Default::default()
        });
        let config = ctx.find("wg1").unwrap().config_path;
        assert!(config.exists());
        library::rm(&ctx, "wg1").unwrap();
        assert_eq!(ctx.profiles().unwrap().len(), 1);
        assert!(!config.exists());
    }

    #[test]
    fn rm_refuses_a_connected_profile() {
        let (_dir, ctx, _) = setup(FakeDaemon {
            replies: HashMap::from([(method::WIREGUARD_STATUS, wg_status("running"))]),
            ..Default::default()
        });
        let before = ctx.profiles().unwrap();
        let config = ctx.find("wg1").unwrap().config_path;
        let config_before = std::fs::read(&config).unwrap();
        assert!(library::rm(&ctx, "wg1").is_err());
        assert_eq!(ctx.profiles().unwrap(), before);
        assert_eq!(std::fs::read(config).unwrap(), config_before);
    }

    #[test]
    fn commands_that_write_the_data_refuse_to_run_as_root() {
        let (_dir, mut ctx, _) = setup(FakeDaemon::default());
        ctx.root_user = true;
        assert!(library::add(&ctx, LINK, None).is_err());
        assert!(library::rename(&ctx, "wg1", "x").is_err());
        assert!(library::rm(&ctx, "wg1").is_err());
        assert_eq!(ctx.profiles().unwrap().len(), 2);
    }

    /// A three-server subscription profile (`sub1`) running as Xray TUN.
    fn subscription_setup(daemon: FakeDaemon) -> (tempfile::TempDir, Ctx, Arc<FakeDaemon>) {
        let (dir, ctx, daemon) = setup(daemon);
        let body = "vless://id1@a.test:443?security=tls#Alpha%20DE\n\
                    vless://id2@b.test:443?security=tls#Beta%20NL\n\
                    vless://id3@c.test:443?security=tls#Gamma%20DE\n";
        net_manager_core::subscription::import_body(
            &ctx.vault(),
            &ctx.store(),
            &net_manager_core::subscription::SubscriptionImport {
                id: "sub1",
                url: "https://panel.test/sub",
                hwid: "",
                name: "",
                refresh_interval_minutes: None,
            },
            body,
            Default::default(),
            |_| true,
        )
        .unwrap();
        let mut profile = ctx.find("sub1").unwrap();
        profile.xray_mode = net_manager_core::models::XrayMode::Tun;
        ctx.store().upsert(profile).unwrap();
        (dir, ctx, daemon)
    }

    fn xray_status(state: &str) -> Value {
        json!({"profileId": "sub1", "state": state, "interfaceName": "xray0",
            "dnsApplied": true, "ipv4Covered": true, "ipv6Covered": true})
    }

    fn server_of(ctx: &Ctx) -> String {
        endpoints::active_name(ctx, &ctx.find("sub1").unwrap()).unwrap()
    }

    #[test]
    fn endpoints_lists_names_and_marks_the_active_one_without_hosts() {
        let (_dir, ctx, _) = subscription_setup(FakeDaemon::default());
        let (value, text) = endpoints::list(&ctx, "sub1").unwrap();
        assert_eq!(value.as_array().unwrap().len(), 3);
        assert_eq!(value[0]["active"], true);
        assert!(text.contains("Beta NL"));
        assert!(!text.contains("b.test") && !text.contains("id2"));
        assert!(endpoints::list(&ctx, "wg1").is_err());
    }

    #[test]
    fn use_switches_the_server_by_name_or_number_and_ls_shows_it() {
        let (_dir, ctx, _) = subscription_setup(FakeDaemon {
            replies: HashMap::from([(method::XRAY_STATUS, xray_status("stopped"))]),
            ..Default::default()
        });
        assert_eq!(server_of(&ctx), "Alpha DE");
        endpoints::use_endpoint(&ctx, "sub1", Some("beta")).unwrap();
        assert_eq!(server_of(&ctx), "Beta NL");
        endpoints::use_endpoint(&ctx, "sub1", Some("3")).unwrap();
        assert_eq!(server_of(&ctx), "Gamma DE");
        assert!(ls(&ctx).unwrap().1.contains("Gamma DE"));
        assert!(endpoints::use_endpoint(&ctx, "sub1", Some("de")).is_err());
        assert_eq!(server_of(&ctx), "Gamma DE");
    }

    #[test]
    fn use_without_a_server_off_a_terminal_asks_for_one() {
        let (_dir, ctx, _) = subscription_setup(FakeDaemon {
            replies: HashMap::from([(method::XRAY_STATUS, xray_status("stopped"))]),
            ..Default::default()
        });
        // Tests run without a terminal on stdin.
        let error = endpoints::use_endpoint(&ctx, "sub1", None).unwrap_err();
        assert!(error.contains("Name a server"), "{error}");
    }

    #[test]
    fn use_refuses_while_connected_and_switch_reconnects() {
        let (_dir, ctx, daemon) = subscription_setup(FakeDaemon {
            xray: Some(Mutex::new(XrayRuntime {
                active: Some(("sub1".into(), "a.test".into())),
                ..Default::default()
            })),
            ..Default::default()
        });
        let error = endpoints::use_endpoint(&ctx, "sub1", Some("beta")).unwrap_err();
        assert!(error.contains("netorch switch"), "{error}");
        assert_eq!(server_of(&ctx), "Alpha DE");
        let (value, text) = endpoints::switch(&ctx, "sub1", Some("beta")).unwrap();
        assert_eq!(value["connected"], true);
        assert!(text.contains("reconnected"));
        assert_eq!(server_of(&ctx), "Beta NL");
        assert_eq!(
            ctx.engine.status(&ctx.find("sub1").unwrap()).unwrap().state,
            TunnelState::Running
        );
        assert_eq!(
            daemon.xray.as_ref().unwrap().lock().unwrap().active,
            Some(("sub1".into(), "b.test".into()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_switch_preserves_previous_profile_and_config_when_reconnect_fails() {
        let (_dir, ctx, daemon) = subscription_setup(FakeDaemon {
            xray: Some(Mutex::new(XrayRuntime {
                active: Some(("sub1".into(), "a.test".into())),
                reject_all: true,
                ..Default::default()
            })),
            ..Default::default()
        });
        let before = ctx.find("sub1").unwrap();
        let config_before = std::fs::read(&before.config_path).unwrap();
        let endpoints_before = ctx.vault().read_subscription_endpoints("sub1").unwrap();
        assert!(endpoints::switch(&ctx, "sub1", Some("beta")).is_err());
        assert_eq!(ctx.find("sub1").unwrap(), before);
        assert_eq!(std::fs::read(&before.config_path).unwrap(), config_before);
        assert_eq!(
            ctx.vault().read_subscription_endpoints("sub1").unwrap(),
            endpoints_before
        );
        assert_eq!(server_of(&ctx), "Alpha DE");
        assert_eq!(
            ctx.engine.status(&before).unwrap().state,
            TunnelState::Failed
        );
        assert!(daemon
            .xray
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .active
            .is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_new_endpoint_restores_the_running_previous_endpoint() {
        let (_dir, ctx, daemon) = subscription_setup(FakeDaemon {
            xray: Some(Mutex::new(XrayRuntime {
                active: Some(("sub1".into(), "a.test".into())),
                reject_once: Some("b.test".into()),
                ..Default::default()
            })),
            ..Default::default()
        });
        let before = ctx.find("sub1").unwrap();
        let config_before = std::fs::read(&before.config_path).unwrap();
        assert!(endpoints::switch(&ctx, "sub1", Some("beta")).is_err());
        assert_eq!(ctx.find("sub1").unwrap(), before);
        assert_eq!(std::fs::read(&before.config_path).unwrap(), config_before);
        assert_eq!(server_of(&ctx), "Alpha DE");
        assert_eq!(
            ctx.engine.status(&before).unwrap().state,
            TunnelState::Running
        );
        let runtime = daemon.xray.as_ref().unwrap().lock().unwrap();
        assert_eq!(runtime.active, Some(("sub1".into(), "a.test".into())));
        assert!(
            runtime.reject_once.is_none(),
            "the replacement endpoint failure must actually occur"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn switch_teardown_error_restores_known_inactive_original_connection() {
        for failure in [DisconnectFailure::Stopped, DisconnectFailure::Failed] {
            let (_dir, ctx, daemon) = subscription_setup(FakeDaemon {
                xray: Some(Mutex::new(XrayRuntime {
                    active: Some(("sub1".into(), "a.test".into())),
                    disconnect_failure: Some(failure),
                    reject_once: Some("b.test".into()),
                    ..Default::default()
                })),
                ..Default::default()
            });
            let before = ctx.find("sub1").unwrap();
            let config_before = std::fs::read(&before.config_path).unwrap();
            let error = endpoints::switch(&ctx, "sub1", Some("beta")).unwrap_err();
            assert_eq!(ctx.find("sub1").unwrap(), before);
            assert_eq!(std::fs::read(&before.config_path).unwrap(), config_before);
            assert_eq!(server_of(&ctx), "Alpha DE");
            assert_eq!(
                ctx.engine.status(&before).unwrap().state,
                TunnelState::Running
            );
            let runtime = daemon.xray.as_ref().unwrap().lock().unwrap();
            assert_eq!(runtime.active, Some(("sub1".into(), "a.test".into())));
            assert!(error.contains("restored"), "{error}");
            assert_eq!(
                runtime.reject_once.as_deref(),
                Some("b.test"),
                "The replacement must never start after teardown failed"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn switch_teardown_error_preserves_still_running_original_connection() {
        let (_dir, ctx, daemon) = subscription_setup(FakeDaemon {
            xray: Some(Mutex::new(XrayRuntime {
                active: Some(("sub1".into(), "a.test".into())),
                disconnect_failure: Some(DisconnectFailure::Running),
                reject_once: Some("b.test".into()),
                ..Default::default()
            })),
            ..Default::default()
        });
        let before = ctx.find("sub1").unwrap();
        let config_before = std::fs::read(&before.config_path).unwrap();
        let identity = daemon
            .xray
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .connection_identity;
        assert!(endpoints::switch(&ctx, "sub1", Some("beta")).is_err());
        assert_eq!(ctx.find("sub1").unwrap(), before);
        assert_eq!(std::fs::read(&before.config_path).unwrap(), config_before);
        assert_eq!(
            ctx.engine.status(&before).unwrap().state,
            TunnelState::Running
        );
        let runtime = daemon.xray.as_ref().unwrap().lock().unwrap();
        assert_eq!(runtime.active, Some(("sub1".into(), "a.test".into())));
        assert_eq!(
            runtime.connection_identity, identity,
            "The healthy original must not restart"
        );
        assert_eq!(runtime.reject_once.as_deref(), Some("b.test"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn switch_teardown_error_with_unknown_status_does_not_blindly_reconnect() {
        let (_dir, ctx, daemon) = subscription_setup(FakeDaemon {
            xray: Some(Mutex::new(XrayRuntime {
                active: Some(("sub1".into(), "a.test".into())),
                disconnect_failure: Some(DisconnectFailure::Unknown),
                reject_once: Some("b.test".into()),
                ..Default::default()
            })),
            ..Default::default()
        });
        let before = ctx.find("sub1").unwrap();
        let config_before = std::fs::read(&before.config_path).unwrap();
        let identity = daemon
            .xray
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .connection_identity;
        assert!(endpoints::switch(&ctx, "sub1", Some("beta")).is_err());
        assert_eq!(ctx.find("sub1").unwrap(), before);
        assert_eq!(std::fs::read(&before.config_path).unwrap(), config_before);
        assert!(ctx.engine.status(&before).is_err());
        let runtime = daemon.xray.as_ref().unwrap().lock().unwrap();
        assert_eq!(runtime.active, Some(("sub1".into(), "a.test".into())));
        assert_eq!(
            runtime.connection_identity, identity,
            "Unknown status must not trigger a restart"
        );
        assert_eq!(runtime.reject_once.as_deref(), Some("b.test"));
    }

    #[test]
    fn up_with_a_server_picks_it_first() {
        let (_dir, ctx, daemon) = subscription_setup(FakeDaemon {
            xray: Some(Mutex::new(XrayRuntime::default())),
            ..Default::default()
        });
        let args = UpArgs {
            target: "sub1".into(),
            name: None,
            endpoint: Some("gamma".into()),
            foreground: false,
            auth_stdin: false,
            passphrase_stdin: false,
        };
        let (_, text) = up(&ctx, &args).unwrap();
        assert!(text.contains("via Gamma DE"), "{text}");
        assert_eq!(
            ctx.engine.status(&ctx.find("sub1").unwrap()).unwrap().state,
            TunnelState::Running
        );
        assert_eq!(
            daemon.xray.as_ref().unwrap().lock().unwrap().active,
            Some(("sub1".into(), "c.test".into()))
        );
    }

    fn backup_command(
        kind: super::super::args::BackupCommand,
    ) -> super::super::args::BackupCommand {
        kind
    }

    #[test]
    fn backups_form_an_ordered_chain_and_missing_keys_survive() {
        use super::super::args::BackupCommand::*;
        let (_dir, ctx, _) = subscription_setup(FakeDaemon {
            replies: HashMap::from([(method::XRAY_STATUS, xray_status("stopped"))]),
            ..Default::default()
        });
        let (_, text) = endpoints::backup(
            &ctx,
            backup_command(Set {
                profile: "sub1".into(),
                servers: vec!["gamma".into(), "beta".into()],
            }),
        )
        .unwrap();
        assert!(text.contains("Gamma DE, then Beta NL"), "{text}");
        let meta = ctx.find("sub1").unwrap().subscription.unwrap();
        assert_eq!(meta.backup_keys.len(), 2);
        // A remembered-but-gone key is kept: it may reappear on refresh.
        endpoints::backup(
            &ctx,
            backup_command(Set {
                profile: "sub1".into(),
                servers: vec!["deadbeefdeadbeef".into(), "beta".into()],
            }),
        )
        .unwrap();
        let (value, text) = endpoints::backup(
            &ctx,
            backup_command(Show {
                profile: "sub1".into(),
            }),
        )
        .unwrap();
        assert!(text.contains("backup 1"), "{text}");
        assert_eq!(value["backups"].as_array().unwrap().len(), 2);
        assert_eq!(value["backups"][0]["missing"], true);
        assert_eq!(value["autoReturn"], true);
        // The primary cannot be its own backup.
        assert!(endpoints::backup(
            &ctx,
            backup_command(Add {
                profile: "sub1".into(),
                server: "alpha".into(),
            }),
        )
        .is_err());
        endpoints::backup(
            &ctx,
            backup_command(Rm {
                profile: "sub1".into(),
                server: "deadbeefdeadbeef".into(),
            }),
        )
        .unwrap();
        let meta = ctx.find("sub1").unwrap().subscription.unwrap();
        assert_eq!(meta.backup_keys.len(), 1);
        endpoints::backup(
            &ctx,
            backup_command(Auto {
                profile: "sub1".into(),
                enabled: super::super::args::BoolOnOff::Off,
            }),
        )
        .unwrap();
        let meta = ctx.find("sub1").unwrap().subscription.unwrap();
        assert_eq!(meta.auto_return_primary, Some(false));
    }

    #[test]
    fn pinned_routes_bind_domains_to_a_node_and_unpin_frees_them() {
        let (_dir, ctx, _) = subscription_setup(FakeDaemon {
            replies: HashMap::from([(method::XRAY_STATUS, xray_status("stopped"))]),
            ..Default::default()
        });
        let (value, text) = route::run(
            &ctx,
            super::super::args::RouteCommand::Pin {
                profile: "sub1".into(),
                via: "beta".into(),
                selector: vec!["domain:bank.test".into(), "geosite:category-gov".into()],
            },
        )
        .unwrap();
        assert!(text.contains("Beta NL"), "{text}");
        assert_eq!(value["selectors"].as_array().unwrap().len(), 2);
        let profile = ctx.find("sub1").unwrap();
        assert_eq!(profile.pinned_policies.len(), 1);
        assert_eq!(profile.pinned_policies[0].selectors.len(), 2);
        // Addresses and geoip selectors do not pin; domain rules do.
        assert!(route::run(
            &ctx,
            super::super::args::RouteCommand::Pin {
                profile: "sub1".into(),
                via: "beta".into(),
                selector: vec!["203.0.113.9".into()],
            },
        )
        .is_err());
        // The same selector cannot follow two routes.
        assert!(route::run(
            &ctx,
            super::super::args::RouteCommand::Add {
                profile: "sub1".into(),
                rules: super::super::args::RuleArgs {
                    proxy: vec!["domain:bank.test".into()],
                    ..Default::default()
                },
            },
        )
        .is_err());
        let (_, text) = route::run(
            &ctx,
            super::super::args::RouteCommand::Unpin {
                profile: "sub1".into(),
                via: "beta".into(),
                selector: vec![],
            },
        )
        .unwrap();
        assert!(text.contains("Unpinned"), "{text}");
        assert!(ctx.find("sub1").unwrap().pinned_policies.is_empty());
    }

    #[test]
    fn pool_filters_bind_countries_and_clear_turns_the_pool_off() {
        use super::super::args::{BackupCommand::*, PoolCommand};
        let (_dir, ctx, _) = subscription_setup(FakeDaemon::default());
        let (value, _) = endpoints::backup(
            &ctx,
            Pool(PoolCommand::Set {
                profile: "sub1".into(),
                filters: vec!["DE:erman|Герман".into()],
                no_verify: false,
            }),
        )
        .unwrap();
        let meta = ctx.find("sub1").unwrap().subscription.unwrap();
        let pool = meta.node_pool.unwrap();
        assert!(pool.verify_exit_country);
        assert_eq!(pool.filters.len(), 1);
        assert_eq!(pool.filters[0].exit_country.as_deref(), Some("DE"));
        assert_eq!(pool.filters[0].name_contains.len(), 2);
        assert_eq!(value["pool"]["verifyExitCountry"], true);
        // Country-less filters need --no-verify, which cannot promise exits.
        assert!(endpoints::backup(
            &ctx,
            Pool(PoolCommand::Set {
                profile: "sub1".into(),
                filters: vec!["erman".into()],
                no_verify: false,
            }),
        )
        .is_err());
        assert!(endpoints::backup(
            &ctx,
            Pool(PoolCommand::Set {
                profile: "sub1".into(),
                filters: vec!["DE:erman".into()],
                no_verify: true,
            }),
        )
        .is_err());
        let (_, text) = endpoints::backup(
            &ctx,
            Pool(PoolCommand::Show {
                profile: "sub1".into(),
            }),
        )
        .unwrap();
        assert!(text.contains("DE:erman|Герман"), "{text}");
        endpoints::backup(
            &ctx,
            Pool(PoolCommand::Clear {
                profile: "sub1".into(),
            }),
        )
        .unwrap();
        let meta = ctx.find("sub1").unwrap().subscription.unwrap();
        assert!(meta.node_pool.is_none());
        assert!(meta.pool_keys.is_empty());
    }

    #[test]
    fn quic_reject_is_a_profile_flag_shown_with_the_rules() {
        let (_dir, ctx, _) = subscription_setup(FakeDaemon::default());
        let (_, text) = route::run(
            &ctx,
            super::super::args::RouteCommand::Quic {
                profile: "sub1".into(),
                enabled: Some(super::super::args::BoolOnOff::On),
            },
        )
        .unwrap();
        assert!(text.contains("on"), "{text}");
        assert!(ctx.find("sub1").unwrap().xray_quic_reject);
        let (value, _) = route::run(
            &ctx,
            super::super::args::RouteCommand::Quic {
                profile: "sub1".into(),
                enabled: None,
            },
        )
        .unwrap();
        assert_eq!(value["quicReject"], true);
        route::run(
            &ctx,
            super::super::args::RouteCommand::Quic {
                profile: "sub1".into(),
                enabled: Some(super::super::args::BoolOnOff::Off),
            },
        )
        .unwrap();
        assert!(!ctx.find("sub1").unwrap().xray_quic_reject);
    }

    #[test]
    fn flag_country_reads_regional_indicators() {
        assert_eq!(
            crate::linux::endpoints::flag_country("🇷🇺 Россия"),
            Some("RU".into())
        );
        assert_eq!(crate::linux::endpoints::flag_country("Beta NL"), None);
    }

    #[test]
    fn migration_preview_reports_and_apply_refuses_unsupported_rules() {
        use super::super::args::MigrateCommand::*;
        let (_dir, ctx, _) = subscription_setup(FakeDaemon::default());
        let source_dir = tempfile::tempdir().unwrap();
        let file = source_dir.path().join("config.json");
        std::fs::write(
            &file,
            r#"{"outbounds":[
                {"tag":"proxy","protocol":"vless"},
                {"tag":"direct","protocol":"freedom"},
                {"tag":"block","protocol":"blackhole"},
                {"tag":"exotic","protocol":"vless"}
              ],
              "routing":{"rules":[
                {"type":"field","domain":["domain:home.test"],"outboundTag":"direct"},
                {"type":"field","domain":["domain:mystery.test"],"outboundTag":"exotic"}
              ]}}"#,
        )
        .unwrap();
        let (value, _) = crate::linux::migrate::run(
            &ctx,
            Preview {
                profile: "sub1".into(),
                from: file.clone(),
            },
        )
        .unwrap();
        assert_eq!(value["policies"]["direct"], 1, "{value}");
        assert!(crate::linux::migrate::run(
            &ctx,
            Apply {
                profile: "sub1".into(),
                from: file,
            },
        )
        .is_err());
        // The refused apply changed nothing.
        assert!(ctx.find("sub1").unwrap().domain_policies.is_empty());
    }

    #[test]
    fn a_keeper_ends_on_a_signal_or_when_the_tunnel_has_stayed_down() {
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;
        let tick = Duration::from_millis(1);
        let (_dir, ctx, _) = setup(FakeDaemon {
            replies: HashMap::from([(method::WIREGUARD_STATUS, wg_status("stopped"))]),
            ..Default::default()
        });
        let profile = ctx.find("wg1").unwrap();
        let go = AtomicBool::new(false);
        assert_eq!(
            hold::watch(&ctx.engine, &profile, &go, tick, 3),
            hold::WatchEnd::TunnelGone
        );
        let stop = AtomicBool::new(true);
        assert_eq!(
            hold::watch(&ctx.engine, &profile, &stop, tick, 3),
            hold::WatchEnd::Signal
        );
    }

    #[test]
    fn a_running_tunnel_or_an_unreachable_daemon_does_not_end_a_keeper() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        let (_dir, ctx, daemon) = setup(FakeDaemon {
            replies: HashMap::from([(method::WIREGUARD_STATUS, wg_status("running"))]),
            ..Default::default()
        });
        let profile = ctx.find("wg1").unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stopper = stop.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            stopper.store(true, Ordering::SeqCst);
        });
        let end = hold::watch(&ctx.engine, &profile, &stop, Duration::from_millis(1), 3);
        handle.join().unwrap();
        assert_eq!(end, hold::WatchEnd::Signal);
        assert!(daemon.calls.lock().unwrap().len() > 3);
        // A daemon with no answers (errors) is not read as "tunnel gone".
        let (_dir2, ctx2, _) = setup(FakeDaemon::default());
        let profile2 = ctx2.find("wg1").unwrap();
        let stop2 = std::sync::Arc::new(AtomicBool::new(false));
        let stopper2 = stop2.clone();
        let handle2 = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            stopper2.store(true, Ordering::SeqCst);
        });
        let end2 = hold::watch(&ctx2.engine, &profile2, &stop2, Duration::from_millis(1), 3);
        handle2.join().unwrap();
        assert_eq!(end2, hold::WatchEnd::Signal);
    }

    #[test]
    fn down_on_a_stopped_profile_does_not_ask_the_daemon_to_disconnect() {
        let (_dir, ctx, daemon) = setup(FakeDaemon {
            replies: HashMap::from([(method::WIREGUARD_STATUS, wg_status("stopped"))]),
            ..Default::default()
        });
        let (value, text) = down(&ctx, Some("wg1"), false).unwrap();
        assert!(value["stopped"].as_array().unwrap().is_empty());
        assert_eq!(text, "No connection is running.");
        assert_eq!(
            daemon.calls.lock().unwrap().as_slice(),
            [method::WIREGUARD_STATUS]
        );
    }

    fn hello_of(version: &str, protocol: u32, drop: &[&str]) -> HelloResult {
        HelloResult {
            protocol,
            daemon_version: version.into(),
            uid: 1000,
            capabilities: net_manager_engine::linux_compat::REQUIRED_METHODS
                .iter()
                .filter(|name| !drop.contains(name))
                .map(|name| name.to_string())
                .collect(),
            tools: Default::default(),
        }
    }

    #[test]
    fn a_current_daemon_passes_the_guard_and_version_reports_it() {
        let (_dir, ctx, _) = setup(FakeDaemon::default());
        compat::guard(&ctx).unwrap();
        let (value, text) = compat::version(&ctx).unwrap();
        assert_eq!(value["netorch"], compat::CLIENT_VERSION);
        assert_eq!(value["daemon"]["compatibility"], "compatible");
        assert!(text.contains("compatible"));
    }

    #[test]
    fn the_guard_refuses_a_daemon_that_cannot_serve_the_cli() {
        let (_dir, ctx, daemon) = setup(FakeDaemon {
            hello: Some(hello_of("0.9.1", PROTOCOL_VERSION + 1, &[])),
            ..Default::default()
        });
        let error = compat::guard(&ctx).unwrap_err();
        assert!(error.contains("Update netorch"), "{error}");
        assert!(daemon.calls.lock().unwrap().is_empty());
        let (value, _) = compat::version(&ctx).unwrap();
        assert_eq!(value["daemon"]["compatibility"], "incompatible");

        let (_dir, ctx, _) = setup(FakeDaemon {
            hello: Some(hello_of("0.9.1", PROTOCOL_VERSION, &[method::XRAY_CONNECT])),
            ..Default::default()
        });
        assert!(compat::guard(&ctx).unwrap_err().contains("xray.connect"));
    }

    #[test]
    fn an_older_daemon_still_works_but_version_says_so() {
        let (_dir, ctx, _) = setup(FakeDaemon {
            hello: Some(hello_of("0.1.0", PROTOCOL_VERSION, &[])),
            ..Default::default()
        });
        compat::guard(&ctx).unwrap();
        let (value, text) = compat::version(&ctx).unwrap();
        assert_eq!(value["daemon"]["compatibility"], "warning");
        assert!(text.contains("older than netorch"));
    }
}
