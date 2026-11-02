//! Connection engine for the Linux network daemon: "connect / disconnect /
//! status of this profile" as plain calls, with no UI state. The Tauri app
//! keeps its own async client for now; the `netorch` CLI is built on this.
//!
//! The engine never touches routes, interfaces or DNS. It checks the profile,
//! builds the typed `daemon_protocol` request from the vault (see
//! [`crate::linux`]) and asks the daemon, which authorizes through polkit and
//! applies it. Roles are enforced twice: here before anything is sent, and by
//! the daemon itself.
use crate::linux::{
    finish_openvpn_connect, linux_openvpn_tunnel_status, linux_wireguard_tunnel_status,
    linux_xray_tunnel_status, prepare_linux_openvpn_request, prepare_linux_xray_tun_params,
    wireguard_connect_params, CredentialSource,
};
use crate::privileged::Privileged;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::{
    method, ErrorCode, OpenVpnConnectResult, OpenVpnCredentials, OpenVpnDisconnectResult,
    OpenVpnProfileParams, OpenVpnStatusResult, WireGuardConnectResult, WireGuardDisconnectResult,
    WireGuardProfileParams, WireGuardStatusResult, XrayConnectResult, XrayDisconnectResult,
    XrayProfileParams, XrayStatusResult, DEFAULT_SOCKET_PATH, SOCKET_ENV,
};
use net_manager_core::helper_client::{HelperClient, HelperError};
use net_manager_core::models::{Profile, TunnelBackend, TunnelState, TunnelStatus, XrayMode};
use std::path::PathBuf;
use std::sync::Arc;

/// Text the client matches to ask the user for OpenVPN credentials.
pub const CREDENTIALS_REQUIRED: &str = "OpenVPN credentials required";

/// Socket of the Linux daemon; tests and the E2E harness point it elsewhere.
pub fn daemon_socket() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| DEFAULT_SOCKET_PATH.into())
}

/// What a user sees when polkit refuses because no agent can ask them.
pub const POLKIT_DENIED: &str =
    "Authorization was denied by polkit. Check that a polkit authentication agent is running.";

/// Whether a message from [`daemon_error`] means "no polkit agent answered".
pub fn is_polkit_denied(message: &str) -> bool {
    message.contains(POLKIT_DENIED)
}

/// The message a user sees for a daemon failure.
pub fn daemon_error(error: HelperError) -> String {
    match error {
        HelperError::Unreachable(_) => {
            "The network daemon is not running. Start it with: systemctl start network-orchestrator"
                .into()
        }
        HelperError::Rejected(body) => match body.code {
            ErrorCode::NotAuthorized => POLKIT_DENIED.into(),
            ErrorCode::AuthorizationDismissed => {
                "The polkit authorization dialog was dismissed.".into()
            }
            _ => body.message,
        },
        HelperError::Protocol(message) => format!("daemon protocol error: {message}"),
    }
}

#[derive(Clone)]
pub struct LinuxEngine {
    privileged: Arc<dyn Privileged>,
}

impl LinuxEngine {
    /// Engine that talks to the system daemon over its socket; `client_name`
    /// (for example `netorch/0.10.0`) is what the daemon logs for this client.
    pub fn new(client_name: impl Into<String>) -> Self {
        let client = HelperClient::new(daemon_socket()).with_client_name(client_name);
        Self::with_privileged(Arc::new(client))
    }

    /// Engine with another privileged side (a fake in tests).
    pub fn with_privileged(privileged: Arc<dyn Privileged>) -> Self {
        Self { privileged }
    }

    pub fn privileged(&self) -> &dyn Privileged {
        self.privileged.as_ref()
    }

    fn ask<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method_name: &str,
        params: P,
    ) -> Result<R, String> {
        self.privileged()
            .call(method_name, params)
            .map_err(daemon_error)
    }

    /// Whether the daemon handles this profile; everything else (static
    /// routes, a local Xray proxy) runs in the client process.
    pub fn handles(profile: &Profile) -> bool {
        matches!(
            profile.backend,
            TunnelBackend::WireGuard | TunnelBackend::OpenVpn
        ) || (profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun)
    }

    pub fn connect(
        &self,
        vault: &ConfigVault,
        profile: &Profile,
        credentials: Option<OpenVpnCredentials>,
        remembered: &dyn CredentialSource,
    ) -> Result<TunnelStatus, String> {
        profile.check_role()?;
        if !Self::handles(profile) {
            return Err("This connection does not run through the network daemon".into());
        }
        match profile.backend {
            TunnelBackend::WireGuard => {
                let params = wireguard_connect_params(vault, profile)?;
                let result: WireGuardConnectResult = self.ask(method::WIREGUARD_CONNECT, params)?;
                Ok(linux_wireguard_tunnel_status(result.status))
            }
            TunnelBackend::OpenVpn => {
                let (request, notice) = prepare_linux_openvpn_request(
                    vault,
                    remembered,
                    profile,
                    credentials,
                    profile.effective_routes(),
                    method::OPENVPN_CONNECT,
                )?;
                let result: OpenVpnConnectResult = self.ask(method::OPENVPN_CONNECT, request)?;
                Ok(finish_openvpn_connect(result.status, notice))
            }
            _ => {
                // No inline geo assets here: the daemon falls back to the
                // managed ones. The app attaches user-supplied lists itself.
                let params = prepare_linux_xray_tun_params(vault, profile)?;
                let result: XrayConnectResult = self.ask(method::XRAY_CONNECT, params)?;
                Ok(linux_xray_tunnel_status(result.status, profile))
            }
        }
    }

    pub fn disconnect(&self, profile: &Profile) -> Result<TunnelStatus, String> {
        let id = profile.id.clone();
        let stopped = match profile.backend {
            TunnelBackend::WireGuard => {
                let result: WireGuardDisconnectResult = self.ask(
                    method::WIREGUARD_DISCONNECT,
                    WireGuardProfileParams { profile_id: id },
                )?;
                result.stopped
            }
            TunnelBackend::OpenVpn => {
                let result: OpenVpnDisconnectResult = self.ask(
                    method::OPENVPN_DISCONNECT,
                    OpenVpnProfileParams { profile_id: id },
                )?;
                result.stopped
            }
            _ if Self::handles(profile) => {
                let result: XrayDisconnectResult = self.ask(
                    method::XRAY_DISCONNECT,
                    XrayProfileParams { profile_id: id },
                )?;
                result.stopped
            }
            _ => return Err("This connection does not run through the network daemon".into()),
        };
        if !stopped {
            return Err("The network daemon did not confirm the disconnect".into());
        }
        Ok(TunnelStatus {
            profile_id: profile.id.clone(),
            state: TunnelState::Stopped,
            message: None,
            interface_name: None,
            failover: None,
            watchdog: None,
        })
    }

    pub fn status(&self, profile: &Profile) -> Result<TunnelStatus, String> {
        let id = profile.id.clone();
        match profile.backend {
            TunnelBackend::WireGuard => {
                let status: WireGuardStatusResult = self.ask(
                    method::WIREGUARD_STATUS,
                    WireGuardProfileParams { profile_id: id },
                )?;
                Ok(linux_wireguard_tunnel_status(status))
            }
            TunnelBackend::OpenVpn => {
                let status: OpenVpnStatusResult = self.ask(
                    method::OPENVPN_STATUS,
                    OpenVpnProfileParams { profile_id: id },
                )?;
                Ok(linux_openvpn_tunnel_status(status))
            }
            _ if Self::handles(profile) => {
                let status: XrayStatusResult =
                    self.ask(method::XRAY_STATUS, XrayProfileParams { profile_id: id })?;
                Ok(linux_xray_tunnel_status(status, profile))
            }
            _ => Err("This connection does not run through the network daemon".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{HelloResult, PROTOCOL_VERSION};
    use net_manager_core::models::{PolicyRoute, TunnelRole};
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A daemon that answers from a table and remembers what it was asked.
    #[derive(Default)]
    struct FakeDaemon {
        replies: HashMap<&'static str, Value>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Privileged for FakeDaemon {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            Ok(HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: "test".into(),
                uid: 1000,
                capabilities: Vec::new(),
                tools: Default::default(),
            })
        }
        fn call_raw(&self, method: &str, params: Value) -> Result<Value, HelperError> {
            self.calls.lock().unwrap().push((method.into(), params));
            self.replies
                .get(method)
                .cloned()
                .ok_or_else(|| HelperError::Protocol(format!("unexpected {method}")))
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    struct NoCredentials;
    impl CredentialSource for NoCredentials {
        fn load(
            &self,
            _: &str,
            _: &std::path::Path,
        ) -> Result<(Option<OpenVpnCredentials>, Option<&'static str>), String> {
            Ok((None, None))
        }
    }

    fn engine(daemon: FakeDaemon) -> (LinuxEngine, Arc<FakeDaemon>) {
        let daemon = Arc::new(daemon);
        (LinuxEngine::with_privileged(daemon.clone()), daemon)
    }

    fn wireguard_profile(dir: &std::path::Path) -> (ConfigVault, Profile) {
        let vault = ConfigVault::new(dir.join("configs"));
        let imported = vault
            .store_wireguard_config(
                "wg1",
                b"[Interface]\nPrivateKey = x\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = y\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.5:51820\n",
            )
            .unwrap();
        let profile = Profile {
            id: "wg1".into(),
            name: "Office".into(),
            backend: TunnelBackend::WireGuard,
            config_path: imported.config_path,
            interface_name: "wg1".into(),
            ..Default::default()
        };
        (vault, profile)
    }

    fn wg_status(state: &str) -> Value {
        json!({"profileId": "wg1", "state": state, "interfaceName": "wg1",
            "latestHandshake": null, "rxBytes": 0, "txBytes": 0, "dnsApplied": true,
            "warnings": []})
    }

    #[test]
    fn a_primary_wireguard_connect_sends_the_profile_routes_and_role() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut profile) = wireguard_profile(dir.path());
        profile.routes = vec![PolicyRoute {
            destination: "0.0.0.0/1".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        let (engine, daemon) = engine(FakeDaemon {
            replies: HashMap::from([(
                method::WIREGUARD_CONNECT,
                json!({"status": wg_status("running")}),
            )]),
            ..Default::default()
        });
        let status = engine
            .connect(&vault, &profile, None, &NoCredentials)
            .unwrap();
        assert_eq!(status.state, TunnelState::Running);
        assert_eq!(status.interface_name.as_deref(), Some("wg1"));
        let calls = daemon.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, method::WIREGUARD_CONNECT);
        assert_eq!(calls[0].1["routes"][0]["destination"], "0.0.0.0/1");
        assert!(calls[0].1.get("role").is_none(), "primary is the default");
    }

    #[test]
    fn a_secondary_connect_sends_only_its_networks_and_domains() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut profile) = wireguard_profile(dir.path());
        profile.tunnel_role = TunnelRole::Secondary;
        profile.tunnel_networks = vec!["10.20.0.0/16".parse().unwrap()];
        profile.tunnel_dns_domains = vec!["corp.example".into()];
        let (engine, daemon) = engine(FakeDaemon {
            replies: HashMap::from([(
                method::WIREGUARD_CONNECT,
                json!({"status": wg_status("running")}),
            )]),
            ..Default::default()
        });
        engine
            .connect(&vault, &profile, None, &NoCredentials)
            .unwrap();
        let calls = daemon.calls.lock().unwrap();
        assert_eq!(calls[0].1["role"], "secondary");
        assert_eq!(calls[0].1["routes"].as_array().unwrap().len(), 1);
        assert_eq!(calls[0].1["routes"][0]["destination"], "10.20.0.0/16");
        assert_eq!(calls[0].1["dnsDomains"], json!(["corp.example"]));
    }

    #[test]
    fn a_secondary_without_networks_is_refused_before_the_daemon_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut profile) = wireguard_profile(dir.path());
        profile.tunnel_role = TunnelRole::Secondary;
        let (engine, daemon) = engine(FakeDaemon::default());
        let error = engine
            .connect(&vault, &profile, None, &NoCredentials)
            .unwrap_err();
        assert!(error.contains("at least one network"), "{error}");
        assert!(daemon.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_proxy_only_profile_is_not_the_daemons_to_run() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut profile) = wireguard_profile(dir.path());
        profile.backend = TunnelBackend::None;
        assert!(!LinuxEngine::handles(&profile));
        let (engine, daemon) = engine(FakeDaemon::default());
        assert!(engine
            .connect(&vault, &profile, None, &NoCredentials)
            .is_err());
        assert!(daemon.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn disconnect_and_status_go_through_the_matching_methods() {
        let dir = tempfile::tempdir().unwrap();
        let (_, profile) = wireguard_profile(dir.path());
        let (engine, daemon) = engine(FakeDaemon {
            replies: HashMap::from([
                (method::WIREGUARD_DISCONNECT, json!({"stopped": true})),
                (method::WIREGUARD_STATUS, wg_status("running")),
            ]),
            ..Default::default()
        });
        assert_eq!(engine.status(&profile).unwrap().state, TunnelState::Running);
        let stopped = engine.disconnect(&profile).unwrap();
        assert_eq!(stopped.state, TunnelState::Stopped);
        let calls = daemon.calls.lock().unwrap();
        assert_eq!(calls[0].0, method::WIREGUARD_STATUS);
        assert_eq!(calls[1].0, method::WIREGUARD_DISCONNECT);
        assert_eq!(calls[1].1["profileId"], "wg1");
    }

    #[test]
    fn an_unconfirmed_disconnect_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (_, profile) = wireguard_profile(dir.path());
        let (engine, _) = engine(FakeDaemon {
            replies: HashMap::from([(method::WIREGUARD_DISCONNECT, json!({"stopped": false}))]),
            ..Default::default()
        });
        assert!(engine.disconnect(&profile).is_err());
    }

    #[test]
    fn daemon_errors_read_as_advice() {
        let unreachable = HelperError::Unreachable(std::io::Error::other("no socket"));
        assert!(daemon_error(unreachable).contains("systemctl start"));
        let denied = HelperError::Rejected(net_manager_core::daemon_protocol::ErrorBody {
            code: ErrorCode::NotAuthorized,
            message: "nope".into(),
        });
        assert!(daemon_error(denied).contains("polkit"));
    }
}
