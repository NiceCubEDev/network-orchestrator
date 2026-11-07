//! WireGuard and OpenVPN profiles. The bridge only reads the profile's managed
//! files and asks the privileged helper over `daemon_protocol`; routes,
//! interfaces, DNS and the VPN processes themselves stay in the helper.
use crate::privileged::Privileged;
use base64::Engine as _;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::{
    method, OpenVpnConnectParams, OpenVpnConnectRequest, OpenVpnConnectResult,
    OpenVpnConnectionState, OpenVpnCredentials, OpenVpnDisconnectResult, OpenVpnFailure,
    OpenVpnProfileParams, OpenVpnStatusResult, OpenVpnWarning, WireGuardConnectParams,
    WireGuardConnectResult, WireGuardDisconnectResult, WireGuardProfileParams,
    WireGuardStatusResult, WireGuardWarning,
};
use net_manager_core::helper_client::HelperError;
use net_manager_core::models::{
    secondary_networks, PolicyRoute, Profile, TunnelBackend, TunnelRole, TunnelState, TunnelStatus,
};
use net_manager_core::openvpn_config::{credential_requirements, CredentialRequirements};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_ASSET_BYTES: u64 = 512 * 1024;
const MAX_ASSETS: usize = 32;
/// Shown (and translated) by the client; also what the Swift side matches.
pub const CREDENTIALS_REQUIRED: &str = "OpenVPN credentials required";

/// The routes the helper is asked to install: a secondary connection carries
/// exactly the networks listed for it, a primary one keeps what the profile has.
pub(crate) fn routes_for(profile: &Profile) -> Vec<PolicyRoute> {
    if profile.tunnel_role == TunnelRole::Secondary {
        profile.secondary_routes()
    } else {
        profile.routes.clone()
    }
}

/// A secondary connection must list valid networks before anything is started.
pub(crate) fn check_role(profile: &Profile) -> Result<(), String> {
    if profile.tunnel_role == TunnelRole::Secondary {
        secondary_networks(&profile.secondary_routes()).map_err(str::to_string)?;
    }
    Ok(())
}

pub(crate) fn is_wireguard(profile: &Profile) -> bool {
    profile.backend == TunnelBackend::WireGuard
}

pub(crate) fn is_openvpn(profile: &Profile) -> bool {
    profile.backend == TunnelBackend::OpenVpn
}

fn stopped(profile: &Profile) -> TunnelStatus {
    TunnelStatus {
        profile_id: profile.id.clone(),
        state: TunnelState::Stopped,
        message: None,
        interface_name: None,
        failover: None,
    }
}

fn wireguard_notice(status: &WireGuardStatusResult) -> Option<String> {
    status
        .warnings
        .iter()
        .find_map(|warning| match warning {
            WireGuardWarning::DnsNotApplied => {
                Some("The tunnel's DNS settings could not be applied")
            }
            WireGuardWarning::Ipv6NotCovered => Some("IPv6 traffic is not covered by this tunnel"),
            WireGuardWarning::IgnoredHook => Some("Scripts in the WireGuard config are ignored"),
            WireGuardWarning::IgnoredSaveConfig => None,
        })
        .map(str::to_string)
}

pub(crate) fn wireguard_status(client: &dyn Privileged, profile: &Profile) -> TunnelStatus {
    match client.call::<_, WireGuardStatusResult>(
        method::WIREGUARD_STATUS,
        WireGuardProfileParams {
            profile_id: profile.id.clone(),
        },
    ) {
        Ok(status) => TunnelStatus {
            profile_id: profile.id.clone(),
            message: wireguard_notice(&status).or_else(|| {
                (status.state == TunnelState::Failed)
                    .then(|| "The WireGuard tunnel stopped".to_string())
            }),
            state: status.state,
            interface_name: status.interface_name,
            failover: None,
        },
        Err(_) => stopped(profile),
    }
}

fn openvpn_failure_text(failure: OpenVpnFailure) -> &'static str {
    match failure {
        OpenVpnFailure::AuthenticationFailure => "OpenVPN authentication failed",
        OpenVpnFailure::CredentialsRequired => CREDENTIALS_REQUIRED,
        OpenVpnFailure::ResolveError => "The OpenVPN server name could not be resolved",
        OpenVpnFailure::ConnectError => "The OpenVPN server is unreachable",
        OpenVpnFailure::TlsError => "The OpenVPN TLS handshake failed",
        OpenVpnFailure::ConnectionLost => "The OpenVPN connection was lost",
        OpenVpnFailure::ExitWithError
        | OpenVpnFailure::ExitNotification
        | OpenVpnFailure::Terminated => "OpenVPN stopped",
    }
}

fn openvpn_notice(status: &OpenVpnStatusResult) -> Option<String> {
    let text = match status.state {
        OpenVpnConnectionState::Connecting => Some("OpenVPN is connecting"),
        OpenVpnConnectionState::Reconnecting => Some("OpenVPN is reconnecting"),
        OpenVpnConnectionState::Failed => Some(
            status
                .failure_reason
                .map(openvpn_failure_text)
                .unwrap_or("OpenVPN stopped"),
        ),
        _ => status.warnings.first().map(|warning| match warning {
            OpenVpnWarning::DnsNotApplied => "The tunnel's DNS settings could not be applied",
            OpenVpnWarning::Ipv6NotCovered => "IPv6 traffic is not covered by this tunnel",
            OpenVpnWarning::AuthenticationFailed => "OpenVPN authentication failed",
        }),
    };
    text.map(str::to_string)
}

pub(crate) fn openvpn_status(client: &dyn Privileged, profile: &Profile) -> TunnelStatus {
    match client.call::<_, OpenVpnStatusResult>(
        method::OPENVPN_STATUS,
        OpenVpnProfileParams {
            profile_id: profile.id.clone(),
        },
    ) {
        Ok(status) => TunnelStatus {
            profile_id: profile.id.clone(),
            state: match status.state {
                OpenVpnConnectionState::Stopped => TunnelState::Stopped,
                OpenVpnConnectionState::Failed => TunnelState::Failed,
                _ => TunnelState::Running,
            },
            message: openvpn_notice(&status),
            interface_name: status.interface_name.clone(),
            failover: None,
        },
        Err(_) => stopped(profile),
    }
}

pub(crate) fn stop(
    client: &dyn Privileged,
    profile: &Profile,
    helper_error: impl Fn(HelperError) -> String,
) -> Result<(), String> {
    let stopped = if is_wireguard(profile) {
        client
            .call::<_, WireGuardDisconnectResult>(
                method::WIREGUARD_DISCONNECT,
                WireGuardProfileParams {
                    profile_id: profile.id.clone(),
                },
            )
            .map(|result| result.stopped)
    } else {
        client
            .call::<_, OpenVpnDisconnectResult>(
                method::OPENVPN_DISCONNECT,
                OpenVpnProfileParams {
                    profile_id: profile.id.clone(),
                },
            )
            .map(|result| result.stopped)
    }
    .map_err(helper_error)?;
    stopped
        .then_some(())
        .ok_or_else(|| "The connection is not running".into())
}

/// A managed regular file of bounded size, as text.
fn read_managed_text(
    vault: &ConfigVault,
    profile: &Profile,
    path: &Path,
) -> Result<String, String> {
    if !vault.is_managed_profile_path(&profile.id, path) {
        return Err("The connection's configuration is not managed by the app".into());
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "The connection's configuration could not be read".to_string())?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err("The connection's configuration is invalid".into());
    }
    std::fs::read_to_string(path)
        .map_err(|_| "The connection's configuration could not be read".to_string())
}

/// `assets/<name>` → bytes, for the files an OpenVPN config references.
fn read_assets(
    vault: &ConfigVault,
    profile: &Profile,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut assets = BTreeMap::new();
    let Some(directory) = profile.config_path.parent().map(|dir| dir.join("assets")) else {
        return Ok(assets);
    };
    if !directory.exists() {
        return Ok(assets);
    }
    let invalid = || "A managed OpenVPN asset is invalid".to_string();
    if !std::fs::symlink_metadata(&directory)
        .map_err(|_| invalid())?
        .file_type()
        .is_dir()
    {
        return Err(invalid());
    }
    for entry in std::fs::read_dir(&directory).map_err(|_| invalid())? {
        let entry = entry.map_err(|_| invalid())?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| invalid())?;
        if !vault.is_managed_profile_path(&profile.id, &path)
            || !metadata.file_type().is_file()
            || metadata.len() > MAX_ASSET_BYTES
            || assets.len() >= MAX_ASSETS
        {
            return Err(invalid());
        }
        let name = entry.file_name().into_string().map_err(|_| invalid())?;
        assets.insert(
            format!("assets/{name}"),
            std::fs::read(&path).map_err(|_| invalid())?,
        );
    }
    Ok(assets)
}

fn capable(client: &dyn Privileged, name: &str, missing: &str) -> Result<(), String> {
    let hello = client.hello().map_err(crate::helper_error)?;
    if hello
        .capabilities
        .iter()
        .any(|capability| capability == name)
    {
        Ok(())
    } else {
        Err(missing.into())
    }
}

pub(crate) fn start_wireguard(
    root: &Path,
    client: &dyn Privileged,
    profile: &Profile,
) -> Result<(), String> {
    check_role(profile)?;
    capable(
        client,
        method::WIREGUARD_CONNECT,
        "This helper cannot run WireGuard; update the app",
    )?;
    let vault = ConfigVault::new(root.join("configs"));
    let config = read_managed_text(&vault, profile, &profile.config_path)?;
    request_wireguard(client, profile, config)
}

/// The `wireguard.connect` request.
pub(crate) fn request_wireguard(
    client: &dyn Privileged,
    profile: &Profile,
    config: String,
) -> Result<(), String> {
    client
        .call::<_, WireGuardConnectResult>(
            method::WIREGUARD_CONNECT,
            WireGuardConnectParams {
                profile_id: profile.id.clone(),
                config,
                routes: routes_for(profile),
                interface_name: None,
                role: profile.tunnel_role,
                dns_domains: profile.tunnel_dns_domains.clone(),
            },
        )
        .map(|_| ())
        .map_err(crate::helper_error)
}

/// What the profile needs from the user before it can connect.
pub(crate) fn requirements(
    root: &Path,
    profile: &Profile,
) -> Result<CredentialRequirements, String> {
    if !is_openvpn(profile) {
        return Ok(CredentialRequirements::default());
    }
    let vault = ConfigVault::new(root.join("configs"));
    let config = read_managed_text(&vault, profile, &profile.config_path)?;
    let assets = read_assets(&vault, profile)?;
    Ok(credential_requirements(&config, &assets))
}

/// Builds the request, refusing early when a needed credential is missing and
/// dropping any that the profile does not ask for.
pub(crate) fn openvpn_request(
    root: &Path,
    profile: &Profile,
    supplied: Option<OpenVpnCredentials>,
) -> Result<OpenVpnConnectRequest, String> {
    let vault = ConfigVault::new(root.join("configs"));
    let config = read_managed_text(&vault, profile, &profile.config_path)?;
    let assets = read_assets(&vault, profile)?;
    let needs = credential_requirements(&config, &assets);
    let credentials = supplied.map(|supplied| OpenVpnCredentials {
        auth_user_pass: supplied.auth_user_pass.filter(|_| needs.user_pass),
        private_key_passphrase: supplied
            .private_key_passphrase
            .filter(|_| needs.key_passphrase),
    });
    if needs.user_pass
        && credentials
            .as_ref()
            .is_none_or(|value| value.auth_user_pass.is_none())
        || needs.key_passphrase
            && credentials
                .as_ref()
                .is_none_or(|value| value.private_key_passphrase.is_none())
    {
        return Err(CREDENTIALS_REQUIRED.into());
    }
    let credentials = credentials
        .filter(|value| value.auth_user_pass.is_some() || value.private_key_passphrase.is_some());
    if let Some(credentials) = &credentials {
        net_manager_core::openvpn_management::validate_openvpn_credentials(credentials)
            .map_err(|_| "The OpenVPN credentials are not valid".to_string())?;
    }
    let assets = assets
        .into_iter()
        .map(|(name, bytes)| {
            (
                name,
                base64::engine::general_purpose::STANDARD.encode(bytes),
            )
        })
        .collect();
    let request = OpenVpnConnectRequest {
        profile: OpenVpnConnectParams {
            profile_id: profile.id.clone(),
            config,
            assets,
            routes: routes_for(profile),
            interface_name: None,
            role: profile.tunnel_role,
            dns_domains: profile.tunnel_dns_domains.clone(),
        },
        credentials,
    };
    let frame = net_manager_core::daemon_protocol::RequestFrame {
        id: 2,
        method: method::OPENVPN_CONNECT.into(),
        params: serde_json::to_value(&request)
            .map_err(|_| "The OpenVPN configuration could not be encoded".to_string())?,
    };
    if net_manager_core::daemon_protocol::encode_line(&frame)
        .map_err(|_| "The OpenVPN configuration could not be encoded".to_string())?
        .len()
        > net_manager_core::daemon_protocol::MAX_FRAME_BYTES
    {
        return Err("The OpenVPN configuration is too large".into());
    }
    Ok(request)
}

pub(crate) fn start_openvpn(
    root: &Path,
    client: &dyn Privileged,
    profile: &Profile,
    credentials: Option<OpenVpnCredentials>,
) -> Result<(), String> {
    check_role(profile)?;
    capable(
        client,
        method::OPENVPN_CONNECT,
        "This helper cannot run OpenVPN; update the app",
    )?;
    let request = openvpn_request(root, profile, credentials)?;
    client
        .call::<_, OpenVpnConnectResult>(method::OPENVPN_CONNECT, request)
        .map(|_| ())
        .map_err(crate::helper_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{
        encode_line, ErrorCode, HelloResult, OpenVpnUserPass, RequestFrame, ResponseFrame,
        PROTOCOL_VERSION,
    };
    use net_manager_core::helper_client::HelperClient;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    /// Serves every connection: `hello`, then at most one request each.
    fn fake_helper(
        dir: &Path,
        capability: &'static str,
        reply: impl Fn(&RequestFrame) -> ResponseFrame + Send + Sync + 'static,
    ) -> (HelperClient, mpsc::Receiver<RequestFrame>) {
        let socket = dir.join("h.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (tx, rx) = mpsc::channel();
        let reply = std::sync::Arc::new(reply);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let (tx, reply) = (tx.clone(), reply.clone());
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let hello: RequestFrame = serde_json::from_str(&line).unwrap();
                    let result = HelloResult {
                        protocol: PROTOCOL_VERSION,
                        daemon_version: "t".into(),
                        uid: 501,
                        capabilities: vec![capability.into()],
                        tools: Default::default(),
                    };
                    let ok = ResponseFrame::ok(hello.id, serde_json::to_value(result).unwrap());
                    stream.write_all(&encode_line(&ok).unwrap()).unwrap();
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) > 0 {
                        let request: RequestFrame = serde_json::from_str(&line).unwrap();
                        let response = reply(&request);
                        let _ = tx.send(request);
                        stream.write_all(&encode_line(&response).unwrap()).unwrap();
                    }
                });
            }
        });
        (HelperClient::new(socket), rx)
    }

    /// A managed OpenVPN profile on disk, the way the importer lays it out.
    fn openvpn_profile(root: &Path, config: &str) -> Profile {
        let revision = root.join("configs/ovpn-1/rev-1");
        std::fs::create_dir_all(revision.join("assets")).unwrap();
        std::fs::write(revision.join("client.ovpn"), config).unwrap();
        std::fs::write(revision.join("assets/ca.crt"), b"CERT").unwrap();
        Profile {
            id: "ovpn-1".into(),
            name: "Office".into(),
            backend: TunnelBackend::OpenVpn,
            config_path: revision.join("client.ovpn"),
            ..Default::default()
        }
    }

    fn wireguard_profile(root: &Path, text: &str) -> Profile {
        let revision = root.join("configs/wg-1/rev-1");
        std::fs::create_dir_all(&revision).unwrap();
        std::fs::write(revision.join("wg-1.conf"), text).unwrap();
        Profile {
            id: "wg-1".into(),
            name: "Home".into(),
            backend: TunnelBackend::WireGuard,
            config_path: revision.join("wg-1.conf"),
            ..Default::default()
        }
    }

    #[test]
    fn wireguard_request_carries_the_managed_config() {
        let dir = tempfile::tempdir().unwrap();
        let profile = wireguard_profile(dir.path(), "[Interface]\nPrivateKey = x\n");
        let (client, seen) = fake_helper(dir.path(), method::WIREGUARD_CONNECT, |request| {
            ResponseFrame::ok(
                request.id,
                json!({"status": {"profileId":"wg-1","state":"running","interfaceName":"utun11",
                    "latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[]}}),
            )
        });
        start_wireguard(dir.path(), &client, &profile).unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.method, method::WIREGUARD_CONNECT);
        assert_eq!(request.params["profileId"], "wg-1");
        assert!(request.params["config"]
            .as_str()
            .unwrap()
            .contains("PrivateKey"));
    }

    #[test]
    fn a_helper_without_the_capability_is_reported_before_anything_is_sent() {
        let dir = tempfile::tempdir().unwrap();
        let profile = wireguard_profile(dir.path(), "x");
        let (client, seen) = fake_helper(dir.path(), method::XRAY_CONNECT, |_| unreachable!());
        let error = start_wireguard(dir.path(), &client, &profile).unwrap_err();
        assert!(error.contains("cannot run WireGuard"), "{error}");
        assert!(seen.try_recv().is_err());
    }

    #[test]
    fn unmanaged_or_missing_configs_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = wireguard_profile(dir.path(), "x");
        profile.config_path = dir.path().join("elsewhere.conf");
        std::fs::write(&profile.config_path, "x").unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        assert!(read_managed_text(&vault, &profile, &profile.config_path).is_err());
    }

    #[test]
    fn openvpn_asks_for_credentials_before_it_connects() {
        let dir = tempfile::tempdir().unwrap();
        let profile = openvpn_profile(
            dir.path(),
            "client\nremote vpn.example 1194\nca assets/ca.crt\nauth-user-pass\n",
        );
        assert_eq!(
            requirements(dir.path(), &profile).unwrap(),
            CredentialRequirements {
                user_pass: true,
                key_passphrase: false
            }
        );
        let error = openvpn_request(dir.path(), &profile, None).unwrap_err();
        assert_eq!(error, CREDENTIALS_REQUIRED);
        let supplied = Some(OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "u".into(),
                password: "p".into(),
            }),
            private_key_passphrase: None,
        });
        let request = openvpn_request(dir.path(), &profile, supplied).unwrap();
        assert_eq!(request.profile.assets["assets/ca.crt"], "Q0VSVA==");
        let user = request.credentials.unwrap().auth_user_pass.unwrap();
        assert_eq!((user.username.as_str(), user.password.as_str()), ("u", "p"));
    }

    #[test]
    fn credentials_the_profile_does_not_ask_for_are_not_sent() {
        let dir = tempfile::tempdir().unwrap();
        let profile = openvpn_profile(dir.path(), "client\nremote vpn.example\nca assets/ca.crt\n");
        let supplied = Some(OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "u".into(),
                password: "p".into(),
            }),
            private_key_passphrase: Some("k".into()),
        });
        let request = openvpn_request(dir.path(), &profile, supplied).unwrap();
        assert!(request.credentials.is_none());
    }

    #[test]
    fn openvpn_request_goes_to_the_helper_with_the_assets() {
        let dir = tempfile::tempdir().unwrap();
        let profile = openvpn_profile(dir.path(), "client\nremote vpn.example\nca assets/ca.crt\n");
        let (client, seen) = fake_helper(dir.path(), method::OPENVPN_CONNECT, |request| {
            ResponseFrame::ok(
                request.id,
                json!({"status": {"profileId":"ovpn-1","state":"connecting","interfaceName":"utun12",
                    "rxBytes":0,"txBytes":0,"appliedRoutes":[],"warnings":[]}}),
            )
        });
        start_openvpn(dir.path(), &client, &profile, None).unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.params["profileId"], "ovpn-1");
        assert_eq!(request.params["assets"]["assets/ca.crt"], "Q0VSVA==");
        assert!(request.params.get("credentials").is_none());
    }

    #[test]
    fn helper_failures_become_readable_statuses() {
        let dir = tempfile::tempdir().unwrap();
        let profile = openvpn_profile(dir.path(), "client\nremote a\n");
        let (client, _) = fake_helper(dir.path(), method::OPENVPN_STATUS, |request| {
            ResponseFrame::ok(
                request.id,
                json!({"profileId":"ovpn-1","state":"failed","interfaceName":"utun12","rxBytes":0,
                    "txBytes":0,"appliedRoutes":[],"warnings":[],"failureReason":"authenticationFailure"}),
            )
        });
        let status = openvpn_status(&client, &profile);
        assert_eq!(status.state, TunnelState::Failed);
        assert_eq!(
            status.message.as_deref(),
            Some("OpenVPN authentication failed")
        );
        let missing = HelperClient::new(dir.path().join("none.sock"));
        assert_eq!(
            openvpn_status(&missing, &profile).state,
            TunnelState::Stopped
        );
        assert_eq!(
            wireguard_status(&missing, &profile).state,
            TunnelState::Stopped
        );
    }

    #[test]
    fn a_refusal_from_the_helper_reaches_the_user() {
        let dir = tempfile::tempdir().unwrap();
        let profile = wireguard_profile(dir.path(), "x");
        let (client, _) = fake_helper(dir.path(), method::WIREGUARD_CONNECT, |request| {
            ResponseFrame::error(
                request.id,
                ErrorCode::Conflict,
                "a Xray tunnel is already active; disconnect it first",
            )
        });
        let error = start_wireguard(dir.path(), &client, &profile).unwrap_err();
        assert_eq!(
            error,
            "a Xray tunnel is already active; disconnect it first"
        );
    }

    #[test]
    fn a_secondary_connection_sends_its_own_networks_and_role() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = wireguard_profile(dir.path(), "[Interface]\nPrivateKey = x\n");
        profile.tunnel_role = TunnelRole::Secondary;
        profile.tunnel_networks = vec!["10.10.0.0/16".parse().unwrap()];
        profile.tunnel_dns_domains = vec!["corp.example".into()];
        // The imported routes are not what a secondary connection carries.
        profile.routes = vec![PolicyRoute {
            destination: "172.16.0.0/12".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        let (client, seen) = fake_helper(dir.path(), method::WIREGUARD_CONNECT, |request| {
            ResponseFrame::ok(
                request.id,
                json!({"status": {"profileId":"wg-1","state":"running","interfaceName":"utun11",
                    "latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":false,"warnings":[]}}),
            )
        });
        start_wireguard(dir.path(), &client, &profile).unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.params["role"], "secondary");
        assert_eq!(request.params["routes"][0]["destination"], "10.10.0.0/16");
        assert_eq!(request.params["routes"].as_array().unwrap().len(), 1);
        assert_eq!(request.params["dnsDomains"], json!(["corp.example"]));
    }

    #[test]
    fn a_primary_connection_sends_no_role_and_keeps_its_routes() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = openvpn_profile(dir.path(), "client\nremote a\nca assets/ca.crt\n");
        profile.routes = vec![PolicyRoute {
            destination: "172.16.0.0/12".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        let request = openvpn_request(dir.path(), &profile, None).unwrap();
        assert_eq!(request.profile.role, TunnelRole::Primary);
        assert_eq!(request.profile.routes.len(), 1);
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("role").is_none());
    }

    #[test]
    fn a_secondary_connection_without_networks_is_refused_before_the_helper() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = wireguard_profile(dir.path(), "x");
        profile.tunnel_role = TunnelRole::Secondary;
        let (client, seen) = fake_helper(dir.path(), method::WIREGUARD_CONNECT, |_| unreachable!());
        let error = start_wireguard(dir.path(), &client, &profile).unwrap_err();
        assert!(error.contains("at least one network"), "{error}");
        assert!(seen.try_recv().is_err());
    }
}
