//! Shared Linux connection engine. Both the CLI and the GUI use these
//! operations; frontends provide presentation, prompts and async scheduling.
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
    feature, method, ErrorCode, OpenVpnConnectRequest, OpenVpnConnectResult, OpenVpnCredentials,
    OpenVpnDisconnectResult, OpenVpnPlanResult, OpenVpnProbeResult, OpenVpnProfileParams,
    OpenVpnStatusResult, RoutesApplyParams, RoutesApplyResult, WireGuardConnectParams,
    WireGuardConnectResult, WireGuardDisconnectResult, WireGuardProfileParams,
    WireGuardStatusResult, XrayConnectParams, XrayConnectResult, XrayDisconnectResult,
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
    data_root: Option<PathBuf>,
    // Injected/in-process privileged adapters remain caller-owned.
    socket: Option<PathBuf>,
}

/// A concrete connection request and immutable profile snapshot; never expose secrets in output.
pub struct PreparedConnection {
    profile: Profile,
    request: PreparedRequest,
}

enum PreparedRequest {
    Routes(RoutesApplyParams),
    WireGuard(WireGuardConnectParams),
    OpenVpn(OpenVpnConnectRequest, Option<&'static str>),
    Xray(XrayConnectParams, Vec<String>),
    #[cfg(target_os = "linux")]
    Local(
        crate::linux_session::PreparedLocalRequest,
        Option<RoutesApplyParams>,
    ),
}

impl PreparedConnection {
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
}

impl LinuxEngine {
    /// Engine that talks to the system daemon over its socket; `client_name`
    /// (for example `netorch/0.10.0`) is what the daemon logs for this client.
    pub fn new(client_name: impl Into<String>) -> Self {
        Self::for_socket(daemon_socket(), client_name)
    }

    /// Explicit transport endpoint for a sandbox or isolated development daemon.
    pub fn for_socket(socket: PathBuf, client_name: impl Into<String>) -> Self {
        Self::for_socket_with_timeout(socket, client_name, std::time::Duration::from_secs(330))
    }

    /// Bounded read-only observation must not wait for a mutation's polkit deadline.
    pub fn for_socket_with_timeout(
        socket: PathBuf,
        client_name: impl Into<String>,
        timeout: std::time::Duration,
    ) -> Self {
        let client = HelperClient::new(&socket)
            .with_client_name(client_name)
            .with_timeout(timeout);
        Self {
            privileged: Arc::new(client),
            data_root: None,
            socket: Some(socket),
        }
    }

    /// Inject a caller-owned privileged adapter, without a detached Unix-session coordinator.
    pub fn with_privileged(privileged: Arc<dyn Privileged>) -> Self {
        Self {
            privileged,
            data_root: None,
            socket: None,
        }
    }

    pub fn with_data_root(mut self, root: PathBuf) -> Self {
        self.data_root = Some(root);
        self
    }

    #[cfg(target_os = "linux")]
    fn local_request(
        &self,
        request: crate::linux_session::Request,
    ) -> Result<TunnelStatus, String> {
        let root = self
            .data_root
            .as_deref()
            .ok_or("The application data directory is required")?;
        let socket = self
            .socket
            .as_deref()
            .ok_or("A daemon socket is required for the shared user runtime")?;
        crate::linux_session::request(root, socket, request)
    }

    #[cfg(target_os = "linux")]
    pub fn disconnect_local_proxies(&self) -> Result<(), String> {
        self.local_request(crate::linux_session::Request::Cleanup)
            .map(|_| ())
    }

    #[cfg(target_os = "linux")]
    pub fn recover_local_proxy(&self) -> Result<(), String> {
        self.local_request(crate::linux_session::Request::RecoverProxy)
            .map(|_| ())
    }

    pub fn requires_daemon(profile: &Profile) -> bool {
        profile.backend != TunnelBackend::Xray
            || profile.xray_mode != XrayMode::Socks
            || !profile.routes.is_empty()
            || !profile.endpoint_bypasses.is_empty()
    }

    fn prepare_profile_routes(&self, profile: &Profile) -> Result<RoutesApplyParams, String> {
        use net_manager_core::daemon_protocol::AttachSpecParams;
        let interfaces = net_manager_core::explorer::list_interfaces()
            .map_err(|_| "Cannot enumerate network interfaces")?;
        let plan = net_manager_core::policy::plan_profile(profile, &interfaces)
            .map_err(|error| error.to_string())?;
        let mut routes = plan.routes;
        routes.extend(plan.bypasses);
        let attach = ((profile.wait_for_interface && !profile.interface_name.is_empty())
            || !profile.endpoint_bypasses.is_empty())
        .then(|| AttachSpecParams {
            interface_name: profile.interface_name.clone(),
            routes: profile.routes.clone(),
            endpoint_bypasses: profile.endpoint_bypasses.clone(),
            uplink: false,
        });
        Ok(RoutesApplyParams {
            owner: profile.id.clone(),
            routes,
            attach,
        })
    }

    fn remove_profile_routes(&self, id: &str) -> Result<(), String> {
        let _: net_manager_core::daemon_protocol::RoutesRemoveResult = self.ask(
            method::ROUTES_REMOVE,
            net_manager_core::daemon_protocol::OwnerParams { owner: id.into() },
        )?;
        Ok(())
    }

    pub fn static_status(&self, id: &str, interface_name: &str) -> Result<TunnelStatus, String> {
        use net_manager_core::daemon_protocol::{OwnedListResult, OwnedState};
        let owners: OwnedListResult = self.ask(method::OWNED_LIST, serde_json::Value::Null)?;
        let entry = owners.owners.iter().find(|entry| entry.owner == id);
        Ok(TunnelStatus {
            profile_id: id.into(),
            state: match entry {
                None => TunnelState::Stopped,
                Some(entry) if entry.state == OwnedState::Applied => TunnelState::Running,
                _ => TunnelState::Failed,
            },
            message: entry
                .filter(|entry| entry.state != OwnedState::Applied)
                .map(|_| "The daemon reports incomplete route ownership".into()),
            interface_name: (!interface_name.is_empty()).then(|| interface_name.into()),
            failover: None,
            watchdog: None,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn local_proxy_status(&self, id: &str) -> Result<TunnelStatus, String> {
        self.local_request(crate::linux_session::Request::Status { id: id.into() })
    }

    pub fn privileged(&self) -> &dyn Privileged {
        self.privileged.as_ref()
    }

    pub(crate) fn socket_path(&self) -> Option<&std::path::Path> {
        self.socket.as_deref()
    }

    pub(crate) fn ask<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method_name: &str,
        params: P,
    ) -> Result<R, String> {
        self.privileged()
            .call(method_name, params)
            .map_err(daemon_error)
    }

    /// Reconfigure diagnostics only; never reload the child or alter routing.
    pub fn set_xray_service_checks(
        &self,
        profile_id: &str,
        checks: Vec<net_manager_core::models::ServiceCheck>,
    ) -> Result<Vec<net_manager_core::models::ServiceCheckResult>, String> {
        self.ask(
            method::XRAY_SERVICE_CHECKS,
            net_manager_core::daemon_protocol::XrayServiceChecksParams {
                profile_id: profile_id.to_owned(),
                checks,
            },
        )
    }

    /// Read actual listeners only; this never connects, reloads or mutates routing.
    pub fn named_proxy_exits(
        &self,
        profile_id: &str,
    ) -> Result<Vec<net_manager_core::daemon_protocol::ProxyExitStatus>, String> {
        self.ask(
            method::XRAY_PROXY_EXITS,
            XrayProfileParams {
                profile_id: profile_id.to_owned(),
            },
        )
    }

    /// Whether the shared Linux runtime supports this profile.
    pub fn handles(profile: &Profile) -> bool {
        profile.backend != TunnelBackend::Xray
            || profile.xray_mode == XrayMode::Tun
            || cfg!(target_os = "linux")
    }

    #[cfg(target_os = "linux")]
    fn rollback_local_route_failure(
        &self,
        id: &str,
        error: String,
        cleanup: impl FnOnce() -> Result<(), String>,
    ) -> String {
        let mut message = error;
        if let Err(cause) = self.remove_profile_routes(id) {
            message.push_str(&format!("; route cleanup failed: {cause}"));
        }
        if let Err(cause) = cleanup() {
            message.push_str(&format!("; local cleanup failed: {cause}"));
        }
        message
    }

    pub fn connect(
        &self,
        vault: &ConfigVault,
        profile: &Profile,
        credentials: Option<OpenVpnCredentials>,
        remembered: &dyn CredentialSource,
    ) -> Result<TunnelStatus, String> {
        let prepared = self.prepare_connection(vault, profile, credentials, remembered, true)?;
        self.execute_prepared(&prepared)
    }

    /// Read and validate concrete payloads without starting/stopping any resource.
    pub fn prepare_connection(
        &self,
        vault: &ConfigVault,
        profile: &Profile,
        credentials: Option<OpenVpnCredentials>,
        remembered: &dyn CredentialSource,
        prepare_local_ports: bool,
    ) -> Result<PreparedConnection, String> {
        #[cfg(not(target_os = "linux"))]
        let _ = prepare_local_ports;
        profile.check_role()?;
        if !Self::handles(profile) {
            return Err("This connection does not run through the network daemon".into());
        }
        let request = match profile.backend {
            TunnelBackend::None => {
                if profile.routes.is_empty() && profile.endpoint_bypasses.is_empty() {
                    return Err("Static-route profile has no routes or endpoint bypasses".into());
                }
                PreparedRequest::Routes(self.prepare_profile_routes(profile)?)
            }
            #[cfg(target_os = "linux")]
            TunnelBackend::Xray if profile.xray_mode == XrayMode::Socks => {
                let root = self
                    .data_root
                    .as_deref()
                    .ok_or("The application data directory is required")?;
                let socket = self
                    .socket
                    .as_deref()
                    .ok_or("A daemon socket is required for the shared user runtime")?;
                crate::linux_session::ensure_prepared_support(root, socket)?;
                let local =
                    crate::linux_session::prepare_connection(root, profile, prepare_local_ports)?;
                let routes = if Self::requires_daemon(profile) {
                    Some(self.prepare_profile_routes(profile)?)
                } else {
                    None
                };
                PreparedRequest::Local(local, routes)
            }
            TunnelBackend::WireGuard => {
                PreparedRequest::WireGuard(wireguard_connect_params(vault, profile)?)
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
                PreparedRequest::OpenVpn(request, notice)
            }
            _ => {
                let (params, notices) = self.xray_params(vault, profile)?;
                if params
                    .routes
                    .iter()
                    .any(|route| route.destination.addr().is_ipv6())
                    || params.dns_servers.iter().any(|server| server.is_ipv6())
                {
                    let hello = self.privileged().hello().map_err(daemon_error)?;
                    net_manager_core::helper_client::require_capability(
                        &hello,
                        feature::XRAY_TUN_IPV6,
                    )
                    .map_err(daemon_error)?;
                }
                PreparedRequest::Xray(params, notices)
            }
        };
        Ok(PreparedConnection {
            profile: profile.clone(),
            request,
        })
    }

    /// Validate set cutovers against the same config policies the daemon executes.
    /// Ordinary single-profile connects keep their existing daemon compatibility.
    pub fn validate_prepared_configuration(
        &self,
        prepared: &PreparedConnection,
    ) -> Result<(), String> {
        match &prepared.request {
            PreparedRequest::WireGuard(params) => {
                net_manager_core::wireguard_config::parse_wireguard_config(
                    &params.config,
                    &params.routes,
                )
                .map_err(|error| error.to_string())?;
                net_manager_core::models::validate_secondary(
                    params.role,
                    &params.routes,
                    &params.dns_domains,
                )
                .map_err(str::to_owned)?;
            }
            PreparedRequest::OpenVpn(request, _) => {
                let _: OpenVpnPlanResult = self.ask(method::OPENVPN_PLAN, request)?;
            }
            PreparedRequest::Routes(_) | PreparedRequest::Xray(_, _) => {}
            #[cfg(target_os = "linux")]
            PreparedRequest::Local(_, _) => {}
        }
        Ok(())
    }

    pub fn execute_prepared(&self, prepared: &PreparedConnection) -> Result<TunnelStatus, String> {
        let profile = &prepared.profile;
        let status = match &prepared.request {
            PreparedRequest::Routes(params) => {
                let _: RoutesApplyResult = self.ask(method::ROUTES_APPLY, params)?;
                self.static_status(&profile.id, &profile.interface_name)
            }
            PreparedRequest::WireGuard(params) => {
                let result: WireGuardConnectResult = self.ask(method::WIREGUARD_CONNECT, params)?;
                Ok(linux_wireguard_tunnel_status(result.status))
            }
            PreparedRequest::OpenVpn(request, notice) => {
                let result: OpenVpnConnectResult = self.ask(method::OPENVPN_CONNECT, request)?;
                Ok(finish_openvpn_connect(result.status, *notice))
            }
            PreparedRequest::Xray(params, notices) => {
                self.execute_xray(profile, params, notices, method::XRAY_CONNECT)
            }
            #[cfg(target_os = "linux")]
            PreparedRequest::Local(local, routes) => {
                let root = self
                    .data_root
                    .as_deref()
                    .ok_or("The application data directory is required")?;
                let socket = self
                    .socket
                    .as_deref()
                    .ok_or("A daemon socket is required for the shared user runtime")?;
                let status = crate::linux_session::execute_prepared(root, socket, local)?;
                if let Some(routes) = routes {
                    let applied: Result<RoutesApplyResult, String> =
                        self.ask(method::ROUTES_APPLY, routes);
                    if let Err(error) = applied {
                        return Err(self.rollback_local_route_failure(&profile.id, error, || {
                            self.local_request(crate::linux_session::Request::Disconnect {
                                id: profile.id.clone(),
                            })
                            .map(|_| ())
                        }));
                    }
                }
                Ok(status)
            }
        }?;
        Ok(status)
    }
    fn xray_params(
        &self,
        vault: &ConfigVault,
        profile: &Profile,
    ) -> Result<(XrayConnectParams, Vec<String>), String> {
        let params = prepare_linux_xray_tun_params(vault, profile)?;
        #[cfg(not(target_os = "linux"))]
        let notices: Vec<String> = Vec::new();
        #[cfg(target_os = "linux")]
        let (params, notices) = {
            let mut params = params;
            let root = vault
                .root()
                .parent()
                .ok_or("The application data directory is unavailable")?
                .join("geoassets");
            let (directory, warnings) = crate::linux_geo_assets::prepare_blocking(&root, profile)?;
            if let Some(directory) = directory {
                params.geo_assets = Some(crate::linux_geo_assets::protocol_geo_assets(&directory)?);
            }
            (params, warnings)
        };
        crate::linux::check_xray_frame_size(&params)
            .map_err(|_| "geo assets are too large for daemon protocol".to_string())?;
        Ok((params, notices))
    }

    fn start_xray(
        &self,
        vault: &ConfigVault,
        profile: &Profile,
        method_name: &str,
    ) -> Result<TunnelStatus, String> {
        let (params, notices) = self.xray_params(vault, profile)?;
        self.execute_xray(profile, &params, &notices, method_name)
    }

    fn execute_xray(
        &self,
        profile: &Profile,
        params: &XrayConnectParams,
        notices: &[String],
        method_name: &str,
    ) -> Result<TunnelStatus, String> {
        let needs_ipv6 = params
            .routes
            .iter()
            .any(|route| route.destination.addr().is_ipv6())
            || params.dns_servers.iter().any(|server| server.is_ipv6());
        let result: XrayConnectResult = if needs_ipv6 {
            self.privileged()
                .call_with_capability(method_name, params, feature::XRAY_TUN_IPV6)
                .map_err(daemon_error)?
        } else {
            self.ask(method_name, params)?
        };
        let mut status = linux_xray_tunnel_status(result.status, profile);
        for notice in notices {
            status.message = Some(match status.message.take() {
                Some(message) => format!("{message}; {notice}"),
                None => notice.clone(),
            });
        }
        Ok(status)
    }

    pub fn reload_xray(
        &self,
        vault: &ConfigVault,
        profile: &Profile,
    ) -> Result<TunnelStatus, String> {
        profile.check_role()?;
        if profile.backend != TunnelBackend::Xray || profile.xray_mode != XrayMode::Tun {
            return Err("Reload requires an Xray TUN profile".into());
        }
        self.start_xray(vault, profile, method::XRAY_RELOAD)
    }

    pub fn probe_openvpn_routes(
        &self,
        vault: &ConfigVault,
        profile: &Profile,
        remembered: &dyn CredentialSource,
    ) -> Result<Vec<net_manager_core::models::AnalyzedRoute>, String> {
        let (request, _) = prepare_linux_openvpn_request(
            vault,
            remembered,
            profile,
            None,
            Vec::new(),
            method::OPENVPN_PROBE,
        )?;
        let result: OpenVpnProbeResult = self.ask(method::OPENVPN_PROBE, request)?;
        Ok(result.routes)
    }

    pub fn wireguard_status_result(
        &self,
        profile_id: &str,
    ) -> Result<WireGuardStatusResult, String> {
        self.ask(
            method::WIREGUARD_STATUS,
            WireGuardProfileParams {
                profile_id: profile_id.into(),
            },
        )
    }

    pub fn openvpn_status_result(&self, profile_id: &str) -> Result<OpenVpnStatusResult, String> {
        self.ask(
            method::OPENVPN_STATUS,
            OpenVpnProfileParams {
                profile_id: profile_id.into(),
            },
        )
    }

    pub fn xray_status_result(&self, profile_id: &str) -> Result<XrayStatusResult, String> {
        self.ask(
            method::XRAY_STATUS,
            XrayProfileParams {
                profile_id: profile_id.into(),
            },
        )
    }

    pub fn disconnect(&self, profile: &Profile) -> Result<TunnelStatus, String> {
        let id = profile.id.clone();
        let stopped = match profile.backend {
            TunnelBackend::None => {
                self.remove_profile_routes(&profile.id)?;
                true
            }
            #[cfg(target_os = "linux")]
            TunnelBackend::Xray if profile.xray_mode == XrayMode::Socks => {
                self.local_request(crate::linux_session::Request::Disconnect {
                    id: profile.id.clone(),
                })?;
                // The saved profile may have been edited since connect. The
                // daemon's ownership, not its current route list, is authoritative.
                if Self::requires_daemon(profile)
                    || self.socket.as_ref().is_some_and(|socket| socket.exists())
                {
                    let owned: net_manager_core::daemon_protocol::OwnedListResult =
                        self.ask(method::OWNED_LIST, serde_json::Value::Null)?;
                    if owned.owners.iter().any(|entry| entry.owner == profile.id) {
                        self.remove_profile_routes(&profile.id)?;
                    }
                }
                true
            }
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
            TunnelBackend::None => self.static_status(&profile.id, &profile.interface_name),
            #[cfg(target_os = "linux")]
            TunnelBackend::Xray if profile.xray_mode == XrayMode::Socks => {
                self.local_proxy_status(&profile.id)
            }
            TunnelBackend::WireGuard => {
                let status = self.wireguard_status_result(&id)?;
                Ok(linux_wireguard_tunnel_status(status))
            }
            TunnelBackend::OpenVpn => {
                let status = self.openvpn_status_result(&id)?;
                Ok(linux_openvpn_tunnel_status(status))
            }
            _ if Self::handles(profile) => {
                let status = self.xray_status_result(&id)?;
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
        capabilities: Vec<String>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Privileged for FakeDaemon {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            Ok(HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: "test".into(),
                uid: 1000,
                capabilities: self.capabilities.clone(),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn ambiguous_route_apply_rolls_back_owned_routes_and_local_proxy() {
        struct CommittedDaemon(Mutex<Option<String>>);
        impl Privileged for CommittedDaemon {
            fn hello(&self) -> Result<HelloResult, HelperError> {
                FakeDaemon::default().hello()
            }
            fn call_raw(&self, method: &str, params: Value) -> Result<Value, HelperError> {
                match method {
                    method::ROUTES_APPLY => {
                        *self.0.lock().unwrap() = Some(params["owner"].as_str().unwrap().into());
                        Ok(json!({}))
                    }
                    method::ROUTES_REMOVE => {
                        assert_eq!(self.0.lock().unwrap().as_deref(), params["owner"].as_str());
                        *self.0.lock().unwrap() = None;
                        Ok(json!({"removed": 1}))
                    }
                    _ => panic!("unexpected daemon method"),
                }
            }
            fn log_dir(&self) -> PathBuf {
                PathBuf::new()
            }
        }
        let daemon = Arc::new(CommittedDaemon(Mutex::new(None)));
        let engine = LinuxEngine::with_privileged(daemon.clone());
        let apply: Result<net_manager_core::daemon_protocol::RoutesApplyResult, String> =
            engine.ask(method::ROUTES_APPLY, json!({"owner": "mixed"}));
        let mut local_running = true;
        let error = engine.rollback_local_route_failure("mixed", apply.unwrap_err(), || {
            local_running = false;
            Ok(())
        });
        assert!(!error.is_empty());
        assert!(!local_running);
        assert!(daemon.0.lock().unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_and_local_rollback_failures_are_both_reported() {
        let (engine, daemon) = engine(FakeDaemon::default());
        let message = engine.rollback_local_route_failure("mixed", "apply failed".into(), || {
            Err("local failed".into())
        });
        assert!(message.contains("apply failed"));
        assert!(message.contains("route cleanup failed"));
        assert!(message.contains("local cleanup failed: local failed"));
        assert_eq!(daemon.calls.lock().unwrap()[0].1["owner"], "mixed");
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

    fn xray_profile(dir: &std::path::Path) -> (ConfigVault, Profile) {
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        net_manager_core::profile_import::import_share_link(
            &vault,
            &store,
            "xray1",
            "Xray capability fixture",
            "vless://synthetic-id@node.test:443?security=tls#Capability",
            net_manager_core::models::XrayMode::platform_default(),
            |_| true,
        )
        .unwrap();
        let mut profile = store.load().unwrap().profiles.remove(0);
        profile.xray_mode = XrayMode::Tun;
        (vault, profile)
    }

    fn xray_daemon(ipv6: bool) -> FakeDaemon {
        let mut capabilities = vec![method::XRAY_CONNECT.into(), method::XRAY_RELOAD.into()];
        if ipv6 {
            capabilities.push("xray.tun.ipv6".into());
        }
        let status = json!({
            "profileId": "xray1", "state": "running", "interfaceName": "nxray1",
            "dnsApplied": true, "ipv4Covered": true, "ipv6Covered": ipv6,
            "rxBytes": null, "txBytes": null, "failover": null, "watchdog": null,
            "proxyExits": []
        });
        FakeDaemon {
            capabilities,
            replies: HashMap::from([
                (method::XRAY_CONNECT, json!({"status": status.clone()})),
                (method::XRAY_RELOAD, json!({"status": status})),
            ]),
            ..Default::default()
        }
    }

    fn xray_mutation(
        engine: &LinuxEngine,
        vault: &ConfigVault,
        profile: &Profile,
        method_name: &str,
    ) -> Result<TunnelStatus, String> {
        match method_name {
            method::XRAY_CONNECT => engine.connect(vault, profile, None, &NoCredentials),
            method::XRAY_RELOAD => engine.reload_xray(vault, profile),
            _ => unreachable!(),
        }
    }

    fn policy_route(destination: &str) -> PolicyRoute {
        PolicyRoute {
            destination: destination.parse().unwrap(),
            metric: 5,
            via: None,
        }
    }

    #[test]
    fn xray_tun_ipv6_capability_missing_rejects_explicit_routes_before_mutation() {
        for method_name in [method::XRAY_CONNECT, method::XRAY_RELOAD] {
            for (role, destinations) in [
                (TunnelRole::Primary, vec!["2001:db8:20::/48"]),
                (
                    TunnelRole::Primary,
                    vec!["10.20.0.0/16", "2001:db8:20::/48"],
                ),
                (TunnelRole::Secondary, vec!["2001:db8:20::/48"]),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let (vault, mut profile) = xray_profile(dir.path());
                profile.tunnel_role = role;
                profile.routes = destinations
                    .iter()
                    .map(|route| policy_route(route))
                    .collect();
                profile.tunnel_networks = destinations
                    .iter()
                    .map(|network| network.parse().unwrap())
                    .collect();
                let (engine, daemon) = engine(xray_daemon(false));

                let result = xray_mutation(&engine, &vault, &profile, method_name);

                assert!(
                    daemon.calls.lock().unwrap().is_empty(),
                    "{method_name} must not mutate a legacy daemon for {role:?} {destinations:?}"
                );
                assert!(result.is_err(), "missing IPv6 support must be rejected");
            }
        }
    }

    #[test]
    fn xray_tun_ipv6_capability_missing_rejects_default_routes_before_mutation() {
        for method_name in [method::XRAY_CONNECT, method::XRAY_RELOAD] {
            for split_default in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let (vault, mut profile) = xray_profile(dir.path());
                profile.xray_split_default = split_default;
                assert!(profile.routes.is_empty());
                let (engine, daemon) = engine(xray_daemon(false));

                let result = xray_mutation(&engine, &vault, &profile, method_name);

                assert!(
                    daemon.calls.lock().unwrap().is_empty(),
                    "{method_name} must not mutate a legacy daemon for dual-stack defaults"
                );
                assert!(result.is_err(), "missing IPv6 support must be rejected");
            }
        }
    }

    #[test]
    fn xray_tun_ipv6_capability_missing_rejects_dns_before_mutation() {
        for method_name in [method::XRAY_CONNECT, method::XRAY_RELOAD] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut profile) = xray_profile(dir.path());
            profile.routes = vec![policy_route("10.20.0.0/16")];
            profile.xray_tun_dns_servers = vec!["2001:db8::53".parse().unwrap()];
            let (engine, daemon) = engine(xray_daemon(false));

            let result = xray_mutation(&engine, &vault, &profile, method_name);

            assert!(
                daemon.calls.lock().unwrap().is_empty(),
                "{method_name} must not mutate a legacy daemon for IPv6 DNS on IPv4 routes"
            );
            assert!(result.is_err(), "missing IPv6 DNS support must be rejected");
        }
    }

    #[test]
    fn xray_tun_ipv6_capability_is_not_required_for_ipv4_only_requests() {
        for method_name in [method::XRAY_CONNECT, method::XRAY_RELOAD] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut profile) = xray_profile(dir.path());
            profile.routes = vec![policy_route("10.20.0.0/16")];
            profile.xray_tun_dns_servers = vec!["10.20.0.53".parse().unwrap()];
            let (engine, daemon) = engine(xray_daemon(false));

            let status = xray_mutation(&engine, &vault, &profile, method_name).unwrap();

            assert_eq!(status.state, TunnelState::Running);
            let calls = daemon.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, method_name);
            assert_eq!(
                calls[0].1["routes"],
                json!([{
                    "destination": "10.20.0.0/16", "metric": 5
                }])
            );
            assert_eq!(calls[0].1["dnsServers"], json!(["10.20.0.53"]));
        }
    }

    #[test]
    fn xray_tun_ipv6_capability_advertised_permits_the_intended_mutation() {
        for method_name in [method::XRAY_CONNECT, method::XRAY_RELOAD] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut profile) = xray_profile(dir.path());
            profile.routes = vec![
                policy_route("10.20.0.0/16"),
                policy_route("2001:db8:20::/48"),
            ];
            profile.xray_tun_dns_servers = vec![
                "10.20.0.53".parse().unwrap(),
                "2001:db8:20::53".parse().unwrap(),
            ];
            let (engine, daemon) = engine(xray_daemon(true));

            let status = xray_mutation(&engine, &vault, &profile, method_name).unwrap();

            assert_eq!(status.state, TunnelState::Running);
            let calls = daemon.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, method_name);
            let sent: XrayConnectParams = serde_json::from_value(calls[0].1.clone()).unwrap();
            assert_eq!(sent.profile_id, profile.id);
            assert_eq!(sent.routes, profile.routes);
            assert_eq!(sent.dns_servers, profile.xray_tun_dns_servers);
        }
    }

    #[test]
    fn xray_tun_ipv6_capability_missing_effective_networks_give_update_guidance() {
        for method_name in [method::XRAY_CONNECT, method::XRAY_RELOAD] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut profile) = xray_profile(dir.path());
            profile.tunnel_role = TunnelRole::Secondary;
            profile.tunnel_networks = vec!["2001:db8:20::/48".parse().unwrap()];
            let (engine, daemon) = engine(xray_daemon(false));

            let message = xray_mutation(&engine, &vault, &profile, method_name).unwrap_err();

            assert!(daemon.calls.lock().unwrap().is_empty());
            assert!(message.contains("xray.tun.ipv6"));
            assert!(message.contains("Update"));
            assert!(message.contains("restart"));
        }
    }

    #[test]
    fn xray_tun_ipv6_capability_missing_still_allows_status_and_disconnect() {
        let dir = tempfile::tempdir().unwrap();
        let (_, mut profile) = xray_profile(dir.path());
        profile.routes = vec![policy_route("2001:db8:20::/48")];
        let mut legacy = xray_daemon(false);
        let status = legacy.replies[method::XRAY_CONNECT]["status"].clone();
        legacy.replies.insert(method::XRAY_STATUS, status);
        legacy
            .replies
            .insert(method::XRAY_DISCONNECT, json!({"stopped": true}));
        let (engine, daemon) = engine(legacy);

        assert_eq!(engine.status(&profile).unwrap().state, TunnelState::Running);
        assert_eq!(
            engine.disconnect(&profile).unwrap().state,
            TunnelState::Stopped
        );
        let calls = daemon.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, method::XRAY_STATUS);
        assert_eq!(calls[1].0, method::XRAY_DISCONNECT);
    }

    #[test]
    fn xray_tun_ipv6_capability_is_not_required_for_other_backends() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut profile) = wireguard_profile(dir.path());
        profile.routes = vec![policy_route("2001:db8:20::/48")];
        let (engine, daemon) = engine(FakeDaemon {
            capabilities: vec![
                method::WIREGUARD_CONNECT.into(),
                method::XRAY_CONNECT.into(),
            ],
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
        let calls = daemon.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, method::WIREGUARD_CONNECT);
        assert_eq!(calls[0].1["routes"][0]["destination"], "2001:db8:20::/48");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_connection_does_not_require_a_user_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, profile) = wireguard_profile(dir.path());
        let (mut engine, daemon) = engine(FakeDaemon {
            replies: HashMap::from([(
                method::WIREGUARD_CONNECT,
                json!({"status": wg_status("running")}),
            )]),
            ..Default::default()
        });
        engine.data_root = Some(PathBuf::from("not-an-absolute-data-root"));
        engine.socket = Some(dir.path().join("daemon.sock"));
        let status = engine
            .connect(&vault, &profile, None, &NoCredentials)
            .unwrap();
        assert_eq!(status.state, TunnelState::Running);
        assert_eq!(daemon.calls.lock().unwrap().len(), 1);
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
    fn empty_static_routes_are_refused_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut profile) = wireguard_profile(dir.path());
        profile.backend = TunnelBackend::None;
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
