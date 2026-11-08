//! User-level macOS network inventory and foreign VPN controls. Privileged
//! route, DNS and interface mutations remain exclusively in the helper.
pub use net_manager_core::dns_diag::{DnsConfig, ProbePath};
pub use net_manager_core::dns_probe::{DnsFamily, DnsProbeResult};
pub use net_manager_core::models::{NetworkInterface, RouteEntry, RouteLookupResult};
use net_manager_core::{dns_diag, dns_probe, macos_vpn};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[path = "macos_network_inventory.rs"]
mod inventory;
pub use inventory::{
    collect as collect_user_network_settings, HostEntry, PersistentRoute, Resolver, ServiceSetting,
    ServiceSettings, Sources as UserNetworkSources, StartupJob, StaticRoute, UserNetworkSettings,
};
#[cfg(target_os = "macos")]
#[path = "macos_network_native.rs"]
mod native;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalVpn {
    pub id: String,
    pub name: String,
    pub state: String,
    pub provider: Option<String>,
    pub enabled: bool,
}
impl From<macos_vpn::ExternalVpn> for ExternalVpn {
    fn from(service: macos_vpn::ExternalVpn) -> Self {
        Self {
            id: service.id,
            name: service.name,
            state: service.state,
            provider: service.provider,
            enabled: service.enabled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderState {
    Connected,
    Connecting,
    Disconnected,
    NeedsLogin,
    DaemonStopped,
    NotInstalled,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetBirdState {
    pub installed: bool,
    pub state: ProviderState,
    #[serde(default)]
    pub daemon_status: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub fqdn: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub management_url: Option<String>,
    #[serde(default)]
    pub management_connected: bool,
    #[serde(default)]
    pub peers_connected: u64,
    #[serde(default)]
    pub peers_total: u64,
    #[serde(default)]
    pub session_expires_at: Option<String>,
    #[serde(default)]
    pub networks: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleState {
    pub installed: bool,
    pub state: ProviderState,
    #[serde(default)]
    pub backend_state: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub tailnet: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub peers_online: u64,
    #[serde(default)]
    pub peers_total: u64,
    #[serde(default)]
    pub exit_node: bool,
    /// Explicit sign-in action only. Never include this capability URL in logs.
    #[serde(default)]
    pub auth_url: Option<String>,
}
impl std::fmt::Debug for TailscaleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TailscaleState")
            .field("installed", &self.installed)
            .field("state", &self.state)
            .field("auth_url", &self.auth_url.as_ref().map(|_| "[redacted]"))
            .finish_non_exhaustive()
    }
}

/// Setup keys go only to the existing Core provider's protected one-use file,
/// never argv, a saved profile or printable diagnostics.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetBirdConnectOptions {
    pub management_url: Option<String>,
    pub setup_key: Option<String>,
}
impl std::fmt::Debug for NetBirdConnectOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetBirdConnectOptions")
            .field(
                "management_url",
                &self.management_url.as_deref().map(inventory::public_url),
            )
            .field("setup_key", &self.setup_key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsProbeRequest {
    pub hostname: String,
    pub server: Option<IpAddr>,
    pub family: DnsFamily,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsProbeAnswer {
    pub probe: DnsProbeResult,
    pub resolver_index: Option<u32>,
    pub resolver_domain: Option<String>,
    pub path: Option<ProbePath>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TailscaleControl {
    NativeService,
    Cli,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleControlOutcome {
    pub control: TailscaleControl,
    pub status: TailscaleState,
    pub external_vpns: Vec<ExternalVpn>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyOverrideStatus {
    pub primary_interface: Option<String>,
    pub overridden: bool,
    pub reason: Option<ProxyOverrideReason>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyOverrideReason {
    ForeignPrimaryTunnel,
}

/// Transported only over the runtime owner's private, same-user protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase")]
pub enum ProviderRequest {
    NetBirdStatus,
    NetBirdUp { options: NetBirdConnectOptions },
    NetBirdDown,
    TailscaleStatus,
    TailscaleControl { connect: bool },
    SetExternalVpn { id: String, connect: bool },
}
impl ProviderRequest {
    pub fn is_mutation(&self) -> bool {
        !matches!(self, Self::NetBirdStatus | Self::TailscaleStatus)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "provider", content = "result", rename_all = "camelCase")]
pub enum ProviderResponse {
    NetBird(NetBirdState),
    Tailscale(TailscaleState),
    TailscaleControl(TailscaleControlOutcome),
    ExternalVpns(Vec<ExternalVpn>),
}

fn unsupported<T>() -> Result<T, String> {
    Err("This network operation requires macOS".into())
}

/// OS seam: parsers, DNS target/path selection, lookup policy and native-service
/// preference remain real shared algorithms when a deterministic collector is used.
pub trait NetworkBackend: Send + Sync {
    fn user_network_settings(&self) -> Result<UserNetworkSettings, String> {
        unsupported()
    }
    fn interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        unsupported()
    }
    fn routes(&self) -> Result<Vec<RouteEntry>, String> {
        unsupported()
    }
    fn dns_config(&self) -> Result<DnsConfig, String> {
        unsupported()
    }
    fn dns_query(
        &self,
        _hostname: &str,
        _target: SocketAddr,
        _family: DnsFamily,
    ) -> Result<DnsProbeResult, String> {
        unsupported()
    }
    fn external_vpns(&self) -> Result<Vec<ExternalVpn>, String> {
        unsupported()
    }
    fn set_external_vpn(&self, _id: &str, _connect: bool) -> Result<(), String> {
        unsupported()
    }
    fn netbird_status(&self, _runtime: &Path) -> Result<NetBirdState, String> {
        unsupported()
    }
    fn netbird_up(
        &self,
        _runtime: &Path,
        _options: &NetBirdConnectOptions,
    ) -> Result<NetBirdState, String> {
        unsupported()
    }
    fn netbird_down(&self, _runtime: &Path) -> Result<NetBirdState, String> {
        unsupported()
    }
    fn netbird_log(&self, _runtime: &Path) -> Result<String, String> {
        unsupported()
    }
    fn tailscale_status(&self) -> Result<TailscaleState, String> {
        unsupported()
    }
    fn tailscale_control(&self, _connect: bool) -> Result<TailscaleState, String> {
        unsupported()
    }
    fn primary_interface(&self) -> Result<Option<String>, String> {
        unsupported()
    }
}

pub struct SystemNetwork;
#[cfg(not(target_os = "macos"))]
impl NetworkBackend for SystemNetwork {}

#[derive(Clone)]
pub struct MacNetwork {
    root: PathBuf,
    backend: Arc<dyn NetworkBackend>,
}
impl MacNetwork {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_backend(root, Arc::new(SystemNetwork))
    }
    pub fn with_backend(root: impl Into<PathBuf>, backend: Arc<dyn NetworkBackend>) -> Self {
        Self {
            root: root.into(),
            backend,
        }
    }
    pub fn user_network_settings(&self) -> Result<UserNetworkSettings, String> {
        self.backend.user_network_settings()
    }
    pub fn interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        self.backend.interfaces()
    }
    pub fn routes(&self) -> Result<Vec<RouteEntry>, String> {
        self.backend.routes()
    }
    pub fn lookup_route(&self, destination: IpAddr) -> Result<RouteLookupResult, String> {
        let routes = self.routes()?;
        let matched = net_manager_core::explorer::longest_prefix_match(destination, &routes)
            .ok_or("No route could be read for this address")?;
        Ok(RouteLookupResult {
            destination,
            matched_route: matched.clone(),
            interface_name: matched.interface_name.clone(),
            table: None,
        })
    }
    pub fn dns_status(&self) -> Result<DnsConfig, String> {
        self.backend.dns_config()
    }
    pub fn dns_probe(&self, request: &DnsProbeRequest) -> Result<DnsProbeAnswer, String> {
        let hostname = request.hostname.trim();
        if dns_probe::build_query(hostname, request.family, 0).is_none() {
            return Err("Enter a valid host name".into());
        }
        let config = if request.server.is_some() {
            DnsConfig::default()
        } else {
            self.dns_status()?
        };
        let target = dns_diag::choose_target(&config, hostname, request.server)
            .ok_or("No DNS server is configured")?;
        let probe = self.backend.dns_query(
            hostname,
            SocketAddr::new(target.server, target.port),
            request.family,
        )?;
        // A route read failure must not discard a successfully received DNS answer.
        let path = dns_diag::path_to(target.server, &self.routes().unwrap_or_default());
        Ok(DnsProbeAnswer {
            probe,
            resolver_index: target.resolver_index,
            resolver_domain: target.resolver_domain,
            path,
        })
    }
    pub fn external_vpns(&self) -> Result<Vec<ExternalVpn>, String> {
        self.backend.external_vpns()
    }
    pub fn set_external_vpn(&self, id: &str, connect: bool) -> Result<Vec<ExternalVpn>, String> {
        macos_vpn::nc_command(id, connect).map_err(|_| "Unknown VPN service".to_string())?;
        self.backend.set_external_vpn(id, connect)?;
        self.external_vpns()
    }
    pub fn netbird_status(&self) -> Result<NetBirdState, String> {
        self.backend.netbird_status(&self.root.join("runtime"))
    }
    pub fn netbird_up(&self, options: &NetBirdConnectOptions) -> Result<NetBirdState, String> {
        self.backend.netbird_up(&self.root.join("runtime"), options)
    }
    pub fn netbird_down(&self) -> Result<NetBirdState, String> {
        self.backend.netbird_down(&self.root.join("runtime"))
    }
    pub fn netbird_log(&self) -> Result<String, String> {
        self.backend
            .netbird_log(&self.root.join("runtime"))
            .map(|text| redact_provider_log(&text))
    }
    pub fn tailscale_status(&self) -> Result<TailscaleState, String> {
        self.backend.tailscale_status()
    }
    pub fn tailscale_up(&self) -> Result<TailscaleControlOutcome, String> {
        self.tailscale_control(true)
    }
    pub fn tailscale_down(&self) -> Result<TailscaleControlOutcome, String> {
        self.tailscale_control(false)
    }
    fn tailscale_control(&self, connect: bool) -> Result<TailscaleControlOutcome, String> {
        let services = self.external_vpns()?;
        if let Some(service) = services.iter().find(|service| {
            service
                .provider
                .as_deref()
                .is_some_and(|provider| provider.starts_with("io.tailscale."))
        }) {
            let external_vpns = self.set_external_vpn(&service.id, connect)?;
            return Ok(TailscaleControlOutcome {
                control: TailscaleControl::NativeService,
                status: self.tailscale_status()?,
                external_vpns,
            });
        }
        Ok(TailscaleControlOutcome {
            control: TailscaleControl::Cli,
            status: self.backend.tailscale_control(connect)?,
            external_vpns: services,
        })
    }
    pub fn primary_interface(&self) -> Result<Option<String>, String> {
        self.backend.primary_interface()
    }
    pub fn proxy_override(
        &self,
        owned_interfaces: &[String],
    ) -> Result<ProxyOverrideStatus, String> {
        let primary_interface = self.primary_interface()?;
        let overridden = primary_interface.as_deref().is_some_and(|name| {
            name.starts_with("utun") && !owned_interfaces.iter().any(|owned| owned == name)
        });
        Ok(ProxyOverrideStatus {
            primary_interface,
            overridden,
            reason: overridden.then_some(ProxyOverrideReason::ForeignPrimaryTunnel),
        })
    }

    /// Execute inside the shared runtime owner for process-owned CLI logins.
    /// The owner supplies the root operation lock for mutating requests.
    pub fn provider_request(&self, request: ProviderRequest) -> Result<ProviderResponse, String> {
        match request {
            ProviderRequest::NetBirdStatus => self.netbird_status().map(ProviderResponse::NetBird),
            ProviderRequest::NetBirdUp { options } => {
                self.netbird_up(&options).map(ProviderResponse::NetBird)
            }
            ProviderRequest::NetBirdDown => self.netbird_down().map(ProviderResponse::NetBird),
            ProviderRequest::TailscaleStatus => {
                self.tailscale_status().map(ProviderResponse::Tailscale)
            }
            ProviderRequest::TailscaleControl { connect } => self
                .tailscale_control(connect)
                .map(ProviderResponse::TailscaleControl),
            ProviderRequest::SetExternalVpn { id, connect } => self
                .set_external_vpn(&id, connect)
                .map(ProviderResponse::ExternalVpns),
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn decode_netbird(value: serde_json::Value) -> Result<NetBirdState, String> {
    let mut state: NetBirdState =
        serde_json::from_value(value).map_err(|_| "NetBird answered unexpectedly".to_string())?;
    state.management_url = state.management_url.as_deref().map(inventory::public_url);
    Ok(state)
}
#[cfg(target_os = "macos")]
fn decode_tailscale(value: serde_json::Value) -> Result<TailscaleState, String> {
    serde_json::from_value(value).map_err(|_| "Tailscale answered unexpectedly".into())
}

pub fn parse_primary_interface(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        let value = value.trim();
        (key.trim() == "PrimaryInterface"
            && !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
        .then(|| value.to_string())
    })
}

fn redact_provider_log(text: &str) -> String {
    let lines = text
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if ["setup-key", "setupkey", "auth-key", "authkey"]
                .iter()
                .any(|key| lower.contains(key))
            {
                return "[redacted]".to_string();
            }
            line.split_whitespace()
                .map(|word| {
                    if word.contains("://") {
                        "[redacted URL]"
                    } else {
                        word
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    net_manager_core::vpn::redact_runtime_log(&lines)
}

impl crate::Engine {
    pub fn network(&self) -> MacNetwork {
        MacNetwork::new(self.root())
    }
    pub fn user_network_settings(&self) -> Result<UserNetworkSettings, String> {
        self.network().user_network_settings()
    }
    pub fn interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        self.network().interfaces()
    }
    pub fn routes(&self) -> Result<Vec<RouteEntry>, String> {
        self.network().routes()
    }
    pub fn lookup_route(&self, destination: IpAddr) -> Result<RouteLookupResult, String> {
        self.network().lookup_route(destination)
    }
    pub fn dns_status(&self) -> Result<DnsConfig, String> {
        self.network().dns_status()
    }
    pub fn dns_probe(&self, request: &DnsProbeRequest) -> Result<DnsProbeAnswer, String> {
        self.network().dns_probe(request)
    }
    pub fn external_vpns(&self) -> Result<Vec<ExternalVpn>, String> {
        self.network().external_vpns()
    }
    pub fn set_external_vpn(&self, id: &str, connect: bool) -> Result<Vec<ExternalVpn>, String> {
        match self.provider_rpc(ProviderRequest::SetExternalVpn {
            id: id.into(),
            connect,
        })? {
            ProviderResponse::ExternalVpns(services) => Ok(services),
            _ => Err("The runtime answered unexpectedly".into()),
        }
    }
    pub fn netbird_status(&self) -> Result<NetBirdState, String> {
        match self.provider_rpc(ProviderRequest::NetBirdStatus)? {
            ProviderResponse::NetBird(state) => Ok(state),
            _ => Err("The runtime answered unexpectedly".into()),
        }
    }
    pub fn netbird_up(&self, options: &NetBirdConnectOptions) -> Result<NetBirdState, String> {
        match self.provider_rpc(ProviderRequest::NetBirdUp {
            options: options.clone(),
        })? {
            ProviderResponse::NetBird(state) => Ok(state),
            _ => Err("The runtime answered unexpectedly".into()),
        }
    }
    pub fn netbird_down(&self) -> Result<NetBirdState, String> {
        match self.provider_rpc(ProviderRequest::NetBirdDown)? {
            ProviderResponse::NetBird(state) => Ok(state),
            _ => Err("The runtime answered unexpectedly".into()),
        }
    }
    pub fn netbird_log(&self) -> Result<String, String> {
        self.network().netbird_log()
    }
    pub fn tailscale_status(&self) -> Result<TailscaleState, String> {
        match self.provider_rpc(ProviderRequest::TailscaleStatus)? {
            ProviderResponse::Tailscale(state) => Ok(state),
            _ => Err("The runtime answered unexpectedly".into()),
        }
    }
    pub fn tailscale_up(&self) -> Result<TailscaleControlOutcome, String> {
        self.tailscale_provider_control(true)
    }
    pub fn tailscale_down(&self) -> Result<TailscaleControlOutcome, String> {
        self.tailscale_provider_control(false)
    }
    fn tailscale_provider_control(&self, connect: bool) -> Result<TailscaleControlOutcome, String> {
        match self.provider_rpc(ProviderRequest::TailscaleControl { connect })? {
            ProviderResponse::TailscaleControl(outcome) => Ok(outcome),
            _ => Err("The runtime answered unexpectedly".into()),
        }
    }
    pub fn primary_interface(&self) -> Result<Option<String>, String> {
        self.network().primary_interface()
    }
    pub fn proxy_override(
        &self,
        owned_interfaces: &[String],
    ) -> Result<ProxyOverrideStatus, String> {
        self.network().proxy_override(owned_interfaces)
    }
}

#[cfg(test)]
#[path = "macos_network_tests.rs"]
mod tests;
