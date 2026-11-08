//! Wire protocol between the app and `network-orchestrator-daemon`.
//!
//! Newline-delimited JSON over a unix socket. Every request is a
//! [`RequestFrame`]; the daemon answers with a [`ResponseFrame`] carrying the
//! same `id`, and pushes [`EventFrame`]s to subscribed connections. Params
//! and results are typed per method but travel as raw JSON inside the frame,
//! so an unknown method still parses and can be answered with
//! `unsupportedMethod`.

use crate::models::{AnalyzedRoute, AppliedRoute, PolicyRoute, TunnelRole, TunnelState};
use ipnet::IpNet;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_SOCKET_PATH: &str = "/run/network-orchestrator/daemon.sock";
pub const SOCKET_ENV: &str = "NETWORK_ORCHESTRATOR_SOCKET";
/// Socket of the macOS launchd helper.
pub const MACOS_SOCKET_PATH: &str = "/var/run/network-orchestrator/helper.sock";
/// Hard cap for one frame; read buffers grow with actual bytes, the cap is
/// only an abort threshold. `xray.connect` may carry inline base64 geo
/// assets (two ~10 MiB dat files → ~27 MiB frame); `xray.install` carries a
/// base64 archive bounded by `managed_xray::MAX_XRAY_ARCHIVE_BYTES`
/// (64 MiB → ~86 MiB on the wire), so the cap covers that plus envelope.
/// Anything above is `frameTooLarge`.
pub const MAX_FRAME_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_ROUTES_PER_REQUEST: usize = 8192;
pub const MAX_OWNER_BYTES: usize = 128;
pub const HELLO_TIMEOUT_SECS: u64 = 5;
pub const MAX_CONNECTIONS: usize = 64;

pub mod method {
    pub const HELLO: &str = "hello";
    pub const ROUTES_APPLY: &str = "routes.apply";
    pub const ROUTES_REMOVE: &str = "routes.remove";
    pub const LINK_SET_STATE: &str = "link.set_state";
    pub const OWNED_LIST: &str = "owned.list";
    pub const RECOVERY_CLEANUP: &str = "recovery.cleanup";
    pub const SUBSCRIBE: &str = "subscribe";
    pub const WIREGUARD_CONNECT: &str = "wireguard.connect";
    pub const WIREGUARD_DISCONNECT: &str = "wireguard.disconnect";
    pub const WIREGUARD_STATUS: &str = "wireguard.status";
    pub const OPENVPN_CONNECT: &str = "openvpn.connect";
    pub const OPENVPN_DISCONNECT: &str = "openvpn.disconnect";
    pub const OPENVPN_STATUS: &str = "openvpn.status";
    pub const OPENVPN_PROBE: &str = "openvpn.probe";
    pub const OPENVPN_PLAN: &str = "openvpn.plan";
    pub const XRAY_CONNECT: &str = "xray.connect";
    pub const XRAY_DISCONNECT: &str = "xray.disconnect";
    pub const XRAY_STATUS: &str = "xray.status";
    pub const XRAY_RELOAD: &str = "xray.reload";
    pub const XRAY_SERVICE_CHECKS: &str = "xray.serviceChecks";
    pub const XRAY_PROXY_EXITS: &str = "xray.proxyExits";
    pub const XRAY_INSTALL: &str = "xray.install";
    pub const XRAY_REMOVE: &str = "xray.remove";
    pub const TAILSCALE_STATUS: &str = "tailscale.status";
    pub const TAILSCALE_UP: &str = "tailscale.up";
    pub const TAILSCALE_DOWN: &str = "tailscale.down";
    /// macOS helper only (not in [`CAPABILITIES`], the Linux daemon's list):
    /// keep the user's Tailscale reachable next to a primary tunnel.
    pub const TAILSCALE_PROTECT: &str = "tailscale.protect";
    pub const TAILSCALE_RELEASE: &str = "tailscale.release";
    pub const ALWAYS_ON_SET: &str = "alwaysOn.set";
    pub const ALWAYS_ON_LIST: &str = "alwaysOn.list";
    pub const ALWAYS_ON_REMOVE: &str = "alwaysOn.remove";
    pub const ALWAYS_ON_RESUME: &str = "alwaysOn.resume";
    pub const SETTINGS_GET: &str = "settings.get";
    pub const SETTINGS_SET: &str = "settings.set";
    pub const COND_RULES_LIST: &str = "condRules.list";
    pub const COND_RULES_PUT: &str = "condRules.put";
    pub const COND_RULES_REMOVE: &str = "condRules.remove";
    pub const EXTERNAL_TUNNEL_STOP: &str = "externalTunnel.stop";
    pub const NM_LIST: &str = "nm.list";
    pub const NM_SET_ACTIVE: &str = "nm.setActive";
    pub const NET_TABLES: &str = "net.tables";
    pub const NET_ROUTE_ADD: &str = "net.route.add";
    pub const NET_ROUTE_DEL: &str = "net.route.del";
    pub const NET_RULE_ADD: &str = "net.rule.add";
    pub const NET_RULE_DEL: &str = "net.rule.del";
    pub const NET_EXPLAIN: &str = "net.explain";
    pub const NET_DNS_STATUS: &str = "net.dns.status";
    pub const NET_DNS_PROBE: &str = "net.dns.probe";
    pub const NET_INTENT_LIST: &str = "net.intent.list";
    pub const NET_INTENT_SET: &str = "net.intent.set";
    pub const NET_INTENT_DEL: &str = "net.intent.del";

    /// Methods implemented by the daemon and reported in `hello.capabilities`.
    pub const CAPABILITIES: &[&str] = &[
        ROUTES_APPLY,
        ROUTES_REMOVE,
        LINK_SET_STATE,
        OWNED_LIST,
        RECOVERY_CLEANUP,
        SUBSCRIBE,
        WIREGUARD_CONNECT,
        WIREGUARD_DISCONNECT,
        WIREGUARD_STATUS,
        OPENVPN_CONNECT,
        OPENVPN_DISCONNECT,
        OPENVPN_STATUS,
        OPENVPN_PROBE,
        OPENVPN_PLAN,
        XRAY_CONNECT,
        XRAY_DISCONNECT,
        XRAY_STATUS,
        XRAY_RELOAD,
        XRAY_SERVICE_CHECKS,
        XRAY_PROXY_EXITS,
        XRAY_INSTALL,
        XRAY_REMOVE,
        TAILSCALE_STATUS,
        TAILSCALE_UP,
        TAILSCALE_DOWN,
        ALWAYS_ON_SET,
        ALWAYS_ON_LIST,
        ALWAYS_ON_REMOVE,
        ALWAYS_ON_RESUME,
        SETTINGS_GET,
        SETTINGS_SET,
        COND_RULES_LIST,
        COND_RULES_PUT,
        COND_RULES_REMOVE,
        EXTERNAL_TUNNEL_STOP,
        NM_LIST,
        NM_SET_ACTIVE,
        NET_TABLES,
        NET_ROUTE_ADD,
        NET_ROUTE_DEL,
        NET_RULE_ADD,
        NET_RULE_DEL,
        NET_EXPLAIN,
        NET_DNS_STATUS,
        NET_DNS_PROBE,
        NET_INTENT_LIST,
        NET_INTENT_SET,
        NET_INTENT_DEL,
    ];
}

/// Non-method promises carried in `hello.capabilities`. Unknown entries remain
/// readable by older clients; only the implementing daemon advertises them.
pub mod feature {
    /// Linux Xray TUN owns both families' link addresses, routes and DNS.
    /// Not part of the shared method list or the macOS helper's capabilities.
    pub const XRAY_TUN_IPV6: &str = "xray.tun.ipv6";
}

/// Tool names reported in `HelloResult::tools`. A `false` value means the
/// daemon cannot use the required system binary right now; a missing key
/// (older daemon) means "unknown", not "missing" — callers must treat it
/// as usable to stay compatible.
pub mod tool {
    pub const WIREGUARD: &str = "wireguard";
    pub const OPENVPN: &str = "openvpn";
}

/// When connecting a VPN profile asks for an administrator password. Chosen
/// by an administrator and enforced by the daemon, never by the client.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VpnAuthMode {
    /// Any profile connects without a prompt in an active session.
    NoPrompt,
    /// Split tunnels connect without a prompt; changes that capture all
    /// traffic of the machine (full tunnel, global DNS) and every OpenVPN
    /// profile (its server may push a full tunnel) require an administrator.
    #[default]
    FullTunnelOnly,
    /// Every connect requires an administrator.
    Always,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SettingsResult {
    pub vpn_auth_mode: VpnAuthMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SettingsSetParams {
    pub vpn_auth_mode: VpnAuthMode,
}

pub mod event {
    pub const OWNED_CHANGED: &str = "owned.changed";
    /// Sent when a subscriber missed events; the client must re-read state.
    pub const RESYNC: &str = "resync";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestFrame {
    pub id: u64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
}

/// `{"id","ok":true,"result"}` or `{"id","ok":false,"error"}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawResponse", into = "RawResponse")]
pub struct ResponseFrame {
    pub id: u64,
    pub outcome: Result<Value, ErrorBody>,
}

impl ResponseFrame {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            id,
            outcome: Ok(result),
        }
    }

    pub fn error(id: u64, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id,
            outcome: Err(ErrorBody {
                code,
                message: message.into(),
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RawResponse {
    id: u64,
    ok: bool,
    // `Some(Value::Null)` still serializes as `"result":null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

impl TryFrom<RawResponse> for ResponseFrame {
    type Error = String;

    fn try_from(raw: RawResponse) -> Result<Self, String> {
        let outcome = match (raw.ok, raw.error) {
            (true, _) => Ok(raw.result.unwrap_or(Value::Null)),
            (false, Some(error)) => Err(error),
            (false, None) => return Err("error response without an error body".into()),
        };
        Ok(Self {
            id: raw.id,
            outcome,
        })
    }
}

impl From<ResponseFrame> for RawResponse {
    fn from(frame: ResponseFrame) -> Self {
        match frame.outcome {
            Ok(result) => Self {
                id: frame.id,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => Self {
                id: frame.id,
                ok: false,
                result: None,
                error: Some(error),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    HandshakeRequired,
    ProtocolMismatch,
    UnsupportedMethod,
    InvalidParams,
    FrameTooLarge,
    Busy,
    NotAuthorized,
    AuthorizationDismissed,
    Conflict,
    NotFound,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventFrame {
    pub event: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

impl EventFrame {
    pub fn new(event: &str, data: Value) -> Self {
        Self {
            event: event.to_string(),
            data,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HelloParams {
    pub protocol: u32,
    pub client: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HelloResult {
    pub protocol: u32,
    pub daemon_version: String,
    pub uid: u32,
    /// Implemented method names and explicit `feature::*` promises.
    pub capabilities: Vec<String>,
    /// Whether each `tool::*` system binary is present and safe for the
    /// daemon to execute. Absent entirely on daemons older than this
    /// field — see `tool` for the missing-key contract.
    #[serde(default)]
    pub tools: std::collections::BTreeMap<String, bool>,
}

/// Attach intent for a routes owner: `routes` bind to `interface_name`
/// whenever that link exists, and `endpoint_bypasses` stay pinned to the
/// physical uplink. External tunnels re-create their links, so the daemon
/// re-plans the spec on every reconcile instead of trusting one ifindex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttachSpecParams {
    pub interface_name: String,
    pub routes: Vec<PolicyRoute>,
    pub endpoint_bypasses: Vec<String>,
    /// `true` pins `routes` to the current physical uplink instead of a
    /// named link — a "direct, do not tunnel" intent. The next hop is
    /// re-derived from the live default gateway on every reconcile, so the
    /// routes follow uplink changes and Wi-Fi/Ethernet switches.
    #[serde(default)]
    pub uplink: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutesApplyParams {
    pub owner: String,
    pub routes: Vec<AppliedRoute>,
    /// Present when the owner arms an external-interface attach: the daemon
    /// re-derives routes from the spec on every reconcile. `routes` still
    /// carries what is installable right now (empty when the target link is
    /// absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attach: Option<AttachSpecParams>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutesApplyResult {
    pub applied: usize,
}

/// Backend family of a NetworkManager connection profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NmConnectionKind {
    WireGuard,
    OpenVpn,
    /// Another NM VPN plugin (openconnect, l2tp, …).
    Vpn,
    /// Not a tunnel profile; filtered out of `nm.list` results.
    Other,
}

/// Live activation state of an NM connection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NmConnectionState {
    Inactive,
    Activating,
    Active,
}

/// One NetworkManager connection profile (VPN/WireGuard) with live state.
/// NM owns the secrets; the app only sees metadata and may ask the daemon
/// to activate/deactivate by UUID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NmConnection {
    pub uuid: String,
    pub id: String,
    pub kind: NmConnectionKind,
    /// Bound interface from the profile settings, or the live device while
    /// the connection is active. `None` = NM picks the name on connect.
    pub interface_name: Option<String>,
    pub state: NmConnectionState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NmListResult {
    pub connections: Vec<NmConnection>,
    /// False when the daemon could not reach NetworkManager at all — the
    /// UI should explain the missing backend instead of showing an empty
    /// list.
    #[serde(default)]
    pub available: bool,
}

/// One kernel route as the daemon sees it — every routing table, not only
/// `main`. Field names mirror what `ip route` prints so the UI can render
/// a faithful line without guessing kernel conventions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemRoute {
    pub family: IpFamily,
    pub destination: IpNet,
    /// Kernel routing-table id (254 main, 253 default, 255 local; the UI
    /// renders named tables itself).
    pub table: u32,
    /// Route type rendered like `ip route`: `unicast`, `local`,
    /// `blackhole`, `unreachable`, … (`"type N"` for unknown codes).
    /// Serialized as `routeType` — `kind` is the `OwnedResource` tag key
    /// when a route is journaled as `NetRoute`/`SuppressedRoute`.
    #[serde(rename = "routeType")]
    pub kind: String,
    /// Scope rendered like `ip route`: `universe`, `site`, `link`, `host`,
    /// `nowhere` (`"scope N"` for unknown codes).
    pub scope: String,
    /// `rt_proto` byte. The daemon stamps its own installs with
    /// `RTPROT_NETWORK_ORCHESTRATOR`; the UI flags those via `managed`
    /// rather than hardcoding the number.
    pub protocol: u8,
    /// Installed by this daemon (protocol marker matches).
    pub managed: bool,
    pub gateway: Option<IpAddr>,
    pub interface_index: Option<u32>,
    /// Resolved from the interface dump; `None` for detached ifindices.
    pub interface_name: Option<String>,
    pub metric: Option<u32>,
    /// Preferred source (`src`) if the route carries one.
    pub pref_source: Option<IpAddr>,
    /// ECMP nexthops; non-empty only for multipath routes.
    pub nexthops: Vec<SystemNexthop>,
}

/// One nexthop of a multipath (`RTA_MULTIPATH`) route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemNexthop {
    pub gateway: Option<IpAddr>,
    pub interface_index: u32,
    pub interface_name: Option<String>,
    /// Kernel weight (`hops`); `ip route` prints `weight N` when > 0.
    pub weight: u8,
}

/// One policy-routing rule as the daemon sees it (`ip rule` equivalent):
/// every selector the kernel reports plus its action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemRule {
    pub family: IpFamily,
    /// `ip rule` prints `0:` for a rule with no FRA_PRIORITY.
    pub priority: u32,
    /// Action rendered like `ip rule`: `lookup`, `goto`, `unreachable`,
    /// `blackhole`, `prohibit`, `nop` (`"type N"` for unknown codes).
    pub action: String,
    pub table: u32,
    /// Target priority when `action` is `goto`.
    pub goto: Option<u32>,
    /// `from` selector: the FRA_SRC address under `src_len`.
    pub from: Option<IpNet>,
    /// `to` selector: the FRA_DST address under `dst_len`.
    pub to: Option<IpNet>,
    pub fwmark: Option<u32>,
    /// `None` means the kernel's implicit all-ones mask.
    pub fwmask: Option<u32>,
    pub iifname: Option<String>,
    pub oifname: Option<String>,
    /// `[start, end]` uid range.
    pub uid_range: Option<[u32; 2]>,
    /// `[start, end]` port ranges.
    pub source_port_range: Option<[u16; 2]>,
    pub destination_port_range: Option<[u16; 2]>,
    /// IP-protocol selector rendered as a name when common (`tcp`, `udp`,
    /// `icmp`, `icmpv6`), otherwise the protocol number.
    pub ip_protocol: Option<String>,
    pub suppress_prefix_length: Option<u32>,
    pub suppress_if_group: Option<u32>,
    pub tun_id: Option<u32>,
    /// `dsfield`/`tos` selector; `ip rule` prints `tos 0xNN` when nonzero.
    pub tos: u8,
    /// `ip rule ... not` — the FIB_RULE_INVERT flag.
    pub invert: bool,
    /// FRA_PROTOCOL rt_proto byte; rules the kernel reports without one
    /// carry 0.
    pub protocol: u8,
    /// Installed by this daemon (protocol marker matches).
    pub managed: bool,
}

/// Full privileged view of the host routing plane (`ip route` + `ip rule`
/// across every table), read via the daemon's rtnetlink socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetTablesResult {
    pub routes: Vec<SystemRoute>,
    pub rules: Vec<SystemRule>,
    /// False when the daemon could not dump the kernel state — the UI
    /// should explain instead of showing empty tables.
    #[serde(default)]
    pub available: bool,
}

/// `net.route.add`: install a daemon-owned (`RTPROT`) unicast route.
/// Exactly one of `interface_name`/`interface_index` must identify the
/// output link. Tables `unspec`(0) and `local`(255) are rejected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetRouteAddParams {
    pub destination: IpNet,
    /// Target table; `None` means `main` (254).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_index: Option<u32>,
    /// `None` installs metric 0 like plain `ip route add`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pref_source: Option<IpAddr>,
}

/// `net.route.del`: delete the route exactly as reported by `net.tables`.
/// Foreign routes are journaled and re-installed when the manual owner is
/// cleaned up — deletion is a temporary suppression, never permanent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetRouteDelParams {
    pub route: SystemRoute,
}

/// `net.rule.add`: install a daemon-owned policy rule. `action` is
/// implied `lookup` into `table`; wider actions are not editable yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetRuleAddParams {
    pub family: IpFamily,
    /// `FRA_PRIORITY`; required so ordering is explicit.
    pub priority: u32,
    /// Lookup target table (`ip rule ... table N`).
    pub table: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fwmask: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iifname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oifname: Option<String>,
    #[serde(default)]
    pub invert: bool,
}

/// `net.rule.del`: delete the rule exactly as reported by `net.tables`.
/// Foreign rules follow the same suppress-and-restore journal contract
/// as foreign routes. Priority 0 is never deletable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetRuleDelParams {
    pub rule: SystemRule,
}

/// What a `net.*.del` call did with the kernel object.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NetEditOutcome {
    /// A daemon-owned object was removed (journal updated).
    Deleted,
    /// A foreign object was removed and journaled for re-installation
    /// when the manual owner is torn down.
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetEditResult {
    pub outcome: NetEditOutcome,
}

/// Reconciliation status of one intent piece, for `net.explain`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ExplainStatus {
    /// Present in the kernel exactly as desired.
    Effective,
    /// Realization is pending — e.g. the target interface is absent.
    Deferred,
    /// The kernel holds an equivalent object that is not ours.
    Conflicted,
    /// Desired but absent from the kernel; reconcile will retry.
    Missing,
    /// An override (suppressed foreign object) is holding.
    Active,
    /// Stored but deliberately not enforced — disabled by the user.
    Disabled,
}

/// One line of `net.explain` output: why a journaled intent looks the way
/// it does right now.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExplainEntry {
    /// Journal owner (`wg:home`, `manual`, `cond:…`, a client owner).
    pub owner: String,
    pub state: OwnedState,
    /// `route`, `rule`, `attach`, `suppressed-route`, `suppressed-rule`,
    /// `link`, `dns`, `process`.
    pub kind: String,
    /// Human-readable subject, e.g. `10.0.0.0/8 via wg0 table main`.
    pub subject: String,
    pub status: ExplainStatus,
    /// Why it is in this status ("interface wg1 is absent", "foreign
    /// route occupies destination", …). English, daemon-composed.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetExplainResult {
    pub entries: Vec<ExplainEntry>,
    /// False when the kernel dump was unavailable; statuses are unknown.
    #[serde(default)]
    pub available: bool,
}

/// Where a user intent sends its destinations: `interface` binds to a
/// link (tunnel, uplink, any netdev — armed until it appears), `direct`
/// pins to the current physical uplink so the traffic bypasses tunnels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetIntentPath {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// `gateway` paths (macOS): the next hop for the destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

/// `net.intent.set`: upsert a routing intent. `id` is a stable slug that
/// becomes journal owner `intent:<id>`; the daemon journaled attach spec
/// re-derives and enforces the routes on every reconcile, so the intent
/// survives interface re-creation, uplink changes and daemon restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetIntentSetParams {
    pub id: String,
    /// Destination prefixes (CIDR) the intent captures.
    pub destinations: Vec<String>,
    pub path: NetIntentPath,
    /// Metric for the installed routes; defaults to 100.
    #[serde(default)]
    pub metric: Option<u32>,
    /// `false` stores the intent without enforcing it; absent means on.
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetIntentDelParams {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetIntentResult {
    pub id: String,
}

/// One intent in `net.intent.list`: the declared spec plus its live
/// reconciliation status against the kernel inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetIntentView {
    pub id: String,
    pub destinations: Vec<String>,
    pub path: NetIntentPath,
    /// Route metric the intent installs with.
    pub metric: u32,
    /// False when the intent is stored but not enforced.
    pub enabled: bool,
    pub status: ExplainStatus,
    pub detail: String,
    /// Desired routes currently present in the kernel.
    pub installed: usize,
    /// Desired routes the spec wants right now (0 while deferred).
    pub wanted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetIntentListResult {
    pub intents: Vec<NetIntentView>,
}

/// DNS configuration of one link as systemd-resolved reports it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsLinkStatus {
    pub interface_index: u32,
    pub interface_name: String,
    /// Currently configured DNS servers (`Link.DNS`).
    pub servers: Vec<IpAddr>,
    /// The server resolved would use next on this link
    /// (`Link.CurrentDNSServer`).
    pub current_server: Option<IpAddr>,
    /// `Link.Domains` — `~.` style route domains, `true` marks route-only.
    pub domains: Vec<DnsDomain>,
    /// `Link.DefaultRoute` — whether general queries may use this link.
    pub default_route: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsDomain {
    pub domain: String,
    pub route_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetDnsStatusResult {
    pub links: Vec<DnsLinkStatus>,
    /// False when systemd-resolved is unreachable (stub resolv.conf,
    /// other resolver, …); the UI then shows the file's `nameserver`s.
    #[serde(default)]
    pub available: bool,
    /// `nameserver` lines from /etc/resolv.conf — the stub view apps use.
    #[serde(default)]
    pub resolv_conf: Vec<IpAddr>,
}

/// `net.dns.probe`: send one real DNS query and report the path it took.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetDnsProbeParams {
    /// A/AAAA name to resolve.
    pub hostname: String,
    /// Resolver to hit; `None` picks the current default-route link's
    /// server (or the resolv.conf stub).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<IpAddr>,
    /// Record family; `None` asks for A.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<IpFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetDnsProbeResult {
    /// Server the query was sent to.
    pub server: IpAddr,
    /// Route lookup for that server: source address the kernel picked.
    pub source: Option<IpAddr>,
    /// Output interface of the route lookup.
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
    /// Gateway the traffic would take (`None` = on-link).
    pub gateway: Option<IpAddr>,
    /// Answer RRs rendered like dig (`name TTL A 1.2.3.4`).
    pub answers: Vec<String>,
    /// DNS header status (`NOERROR`, `NXDOMAIN`, …).
    pub status: String,
    pub rtt_ms: u64,
}

/// Result of a kernel `RTM_GETROUTE` lookup — where a packet to `to`
/// would egress right now (source address, output link, gateway, table).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteLookup {
    pub source: Option<IpAddr>,
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
    pub gateway: Option<IpAddr>,
    pub table: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NmSetActiveParams {
    pub uuid: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnerParams {
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutesRemoveResult {
    pub removed: usize,
}

/// The app reads the vault entry and sends its contents over the local socket.
/// Daemon must not accept a client-supplied path to a privileged config file.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardConnectParams {
    pub profile_id: String,
    pub config: String,
    #[serde(default)]
    pub routes: Vec<PolicyRoute>,
    /// Optional kernel interface-name hint (e.g. the profile name). The daemon
    /// sanitizes it and falls back to the deterministic hash name when absent,
    /// unusable, or (in a shortened form) already taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    /// macOS: a secondary tunnel carries only `routes`; the primary owns the
    /// default route and system DNS. Other platforms ignore it.
    #[serde(default, skip_serializing_if = "TunnelRole::is_primary")]
    pub role: TunnelRole,
    /// macOS secondary tunnels: names under these suffixes resolve through the
    /// tunnel's DNS servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_domains: Vec<String>,
}

impl std::fmt::Debug for WireGuardConnectParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardConnectParams")
            .field("profile_id", &self.profile_id)
            .field("config", &"[REDACTED]")
            .field("routes", &self.routes)
            .field("interface_name", &self.interface_name)
            .field("role", &self.role)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardProfileParams {
    pub profile_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WireGuardWarning {
    IgnoredHook,
    IgnoredSaveConfig,
    DnsNotApplied,
    Ipv6NotCovered,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardStatusResult {
    pub profile_id: String,
    pub state: TunnelState,
    pub interface_name: Option<String>,
    pub latest_handshake: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub dns_applied: bool,
    pub warnings: Vec<WireGuardWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardConnectResult {
    pub status: WireGuardStatusResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardDisconnectResult {
    pub stopped: bool,
}

/// The app sends vault contents, not paths for the privileged daemon to open.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnConnectParams {
    pub profile_id: String,
    pub config: String,
    /// Managed asset bytes encoded as base64, keyed by their config references.
    pub assets: BTreeMap<String, String>,
    #[serde(default)]
    pub routes: Vec<PolicyRoute>,
    /// Human-readable interface-name hint (display name or explicit setting).
    /// The daemon sanitizes it and falls back to the deterministic name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    /// macOS: a secondary tunnel carries only `routes` (pushed routes are
    /// ignored); the primary owns the default route and system DNS.
    #[serde(default, skip_serializing_if = "TunnelRole::is_primary")]
    pub role: TunnelRole,
    /// macOS secondary tunnels: names under these suffixes resolve through the
    /// pushed DNS servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_domains: Vec<String>,
}

impl std::fmt::Debug for OpenVpnConnectParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVpnConnectParams")
            .field("profile_id", &self.profile_id)
            .field("config", &"[REDACTED]")
            .field("assets", &"[REDACTED]")
            .field("routes", &self.routes)
            .field("interface_name", &self.interface_name)
            .field("role", &self.role)
            .finish()
    }
}

/// Credentials are carried in the connect request only and are never journaled.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnUserPass {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for OpenVpnUserPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVpnUserPass")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_user_pass: Option<OpenVpnUserPass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_passphrase: Option<String>,
}

impl std::fmt::Debug for OpenVpnCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVpnCredentials")
            .field(
                "auth_user_pass",
                &self.auth_user_pass.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "private_key_passphrase",
                &self.private_key_passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Keeps legacy connect fields flat while allowing optional secret fields.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnConnectRequest {
    #[serde(flatten)]
    pub profile: OpenVpnConnectParams,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<OpenVpnCredentials>,
}

impl From<OpenVpnConnectParams> for OpenVpnConnectRequest {
    fn from(profile: OpenVpnConnectParams) -> Self {
        Self {
            profile,
            credentials: None,
        }
    }
}

impl std::fmt::Debug for OpenVpnConnectRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVpnConnectRequest")
            .field("profile", &self.profile)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnProfileParams {
    pub profile_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OpenVpnConnectionState {
    Stopped,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OpenVpnWarning {
    DnsNotApplied,
    Ipv6NotCovered,
    AuthenticationFailed,
}

/// Sanitized reason for a failed OpenVPN session. Values map to fixed
/// keywords from the management `STATE` detail field and daemon-side
/// credential checks — no raw log text crosses the wire.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OpenVpnFailure {
    /// `auth-failure` detail or a `PASSWORD:Verification Failed` event.
    AuthenticationFailure,
    /// The server asked for credentials (or a key passphrase) that the
    /// profile does not supply.
    CredentialsRequired,
    /// `resolve-error` — the remote host could not be resolved.
    ResolveError,
    /// `connect-error`/`proxy-reconnect` — the server was unreachable.
    ConnectError,
    /// `tls-error`/`tls-failed` — TLS handshake failure.
    TlsError,
    /// `connection-reset`, `ping-restart`, `ping-exit`, `inactive-exit`,
    /// `reconnect`, `suspend`, `network-change`, `primary-changing`.
    ConnectionLost,
    /// `exit-with-error` — exited without a more specific reason.
    ExitWithError,
    /// `exit-with-notification` — server asked the client to exit.
    ExitNotification,
    /// `sigint`/`sigterm`/`sighup`/`sigusr1` — terminated by a signal.
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnStatusResult {
    pub profile_id: String,
    pub state: OpenVpnConnectionState,
    pub interface_name: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub applied_routes: Vec<IpNet>,
    pub warnings: Vec<OpenVpnWarning>,
    /// Present while `state == "failed"` when a sanitized reason is known.
    #[serde(default)]
    pub failure_reason: Option<OpenVpnFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnConnectResult {
    pub status: OpenVpnStatusResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnDisconnectResult {
    pub stopped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnProbeResult {
    pub routes: Vec<AnalyzedRoute>,
}

/// A resource the predicted OpenVPN connection would collide with.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OpenVpnPlanConflict {
    /// The same profile already has a live connection.
    ActiveConnection,
    /// A route probe for the same profile is in flight.
    ActiveProbe,
    /// A candidate TUN name is taken; when set, `interface_name` already
    /// reflects the fallback (connect still fails if no candidate is free).
    InterfaceOccupied,
    /// A leftover staging directory exists under the runtime root.
    StagingLeftover,
}

/// Deterministic paths/names a profile would use at connect time, plus the
/// conflicts it would hit. Purely predictive — nothing is created or removed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnPlanResult {
    pub profile_id: String,
    pub owner: String,
    /// The name a connect would pick: the human-readable primary when free,
    /// otherwise the hash-suffixed fallback.
    pub interface_name: String,
    /// Deterministic collision fallback (identical to `interface_name` when no
    /// usable hint was supplied).
    pub fallback_interface_name: String,
    pub staging_dir: String,
    pub config_path: String,
    pub management_socket: String,
    pub conflicts: Vec<OpenVpnPlanConflict>,
}

/// Managed generated Xray JSON from the app's vault; never a user path.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayConnectParams {
    pub profile_id: String,
    pub config: String,
    #[serde(default)]
    pub routes: Vec<PolicyRoute>,
    #[serde(default)]
    pub dns_servers: Vec<std::net::IpAddr>,
    #[serde(default)]
    pub dns_domains: Vec<String>,
    /// Hosts (literal IPs or resolvable names) that must stay reachable
    /// through the physical gateway while the tunnel captures the family:
    /// upstream DNS resolvers and well-known resolvers clients may point
    /// at. The daemon installs `/32`/`/128` host routes for them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_bypass: Vec<String>,
    /// Optional kernel interface-name hint; sanitized by the daemon, which
    /// falls back to the deterministic hash name when absent or unusable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    /// Optional `geoip.dat`/`geosite.dat` overrides sent inline (base64);
    /// the daemon cannot read caller paths — its unit runs with
    /// `ProtectHome=yes`/`PrivateTmp=yes`, so paths would be invisible.
    /// Decoded bytes land in the root-owned staging dir which becomes
    /// `XRAY_LOCATION_ASSET`; absent fields fall back to managed assets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_assets: Option<XrayGeoAssets>,
    /// macOS only: the console user's app data root holding the managed Xray
    /// (`<root>/backends/xray`). The helper re-verifies the pinned hashes and
    /// owner before executing it, always as that user, never as root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_data_root: Option<String>,
    /// macOS: with several tunnels running, a secondary one carries only
    /// `routes` and leaves the default route and system DNS to the primary.
    /// Other platforms ignore it.
    #[serde(default, skip_serializing_if = "TunnelRole::is_primary")]
    pub role: TunnelRole,
    /// Ordered failover candidates and probe policy. Present only on
    /// subscription profiles that picked backups (or pinned routes) —
    /// the generated config then carries one outbound per node and a
    /// `failover` balancer the daemon steers at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<XrayFailoverParams>,
    #[serde(default)]
    pub reject_quic: bool,
    /// Explicit bounded HTTPS health target; absent legacy callers opt out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// User-owned diagnostic targets. Kept in memory, never in the ownership journal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_checks: Vec<crate::models::ServiceCheck>,
    /// Named process proxy listeners injected by the Linux daemon.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_exits: Vec<crate::models::NamedProxyExit>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XrayServiceChecksParams {
    pub profile_id: String,
    pub checks: Vec<crate::models::ServiceCheck>,
}

/// One ordered failover candidate; `key` is the stable subscription
/// endpoint key ([`crate::subscription::endpoint_key`], 16 lowercase hex)
/// and doubles as the suffix of the config's `node-<key>` outbound tag.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayFailoverNode {
    pub key: String,
}

/// Multinode failover the daemon supervises for one Xray tunnel.
///
/// `nodes` is ordered by preference — `nodes[0]` is the primary. The daemon
/// probes every node through its own loopback SOCKS inbound (each node's
/// health path really traverses that node) and pins the `failover` balancer
/// to the first healthy candidate with a `xray api bo` override. When every
/// candidate fails the balancer moves to the `unavailable` blackhole —
/// traffic is dropped, never sent direct and never silently rerouted to an
/// unpicked node. With `auto_return_primary` the primary wins back the
/// override as soon as it probes healthy again.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayFailoverParams {
    pub nodes: Vec<XrayFailoverNode>,
    pub primary_key: String,
    #[serde(default = "default_auto_return")]
    pub auto_return_primary: bool,
    /// HTTPS endpoint probed through every node. GET only, no redirects,
    /// bounded body; `socks5h` keeps DNS resolution on the node side.
    pub probe_url: String,
    #[serde(default = "default_probe_interval")]
    pub interval_secs: u16,
}

fn default_auto_return() -> bool {
    true
}

fn default_probe_interval() -> u16 {
    10
}

/// Inline geo asset overrides for [`XrayConnectParams`]; base64-encoded dat
/// file contents. Size is bounded by the frame cap.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayGeoAssets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip_dat_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geosite_dat_b64: Option<String>,
}

impl std::fmt::Debug for XrayConnectParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XrayConnectParams")
            .field("profile_id", &self.profile_id)
            .field("config", &"[REDACTED]")
            .field("routes", &self.routes)
            .field("dns_servers", &self.dns_servers)
            .field("dns_domains", &self.dns_domains)
            .field("dns_bypass", &self.dns_bypass)
            .field("interface_name", &self.interface_name)
            .field("macos_data_root", &self.macos_data_root)
            .field("role", &self.role)
            .field("failover", &self.failover.is_some())
            .field(
                "geo_assets",
                &self.geo_assets.as_ref().map(|assets| {
                    assets.geoip_dat_b64.is_some() || assets.geosite_dat_b64.is_some()
                }),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayProfileParams {
    pub profile_id: String,
}

/// Install the pinned managed Xray package: `archive_b64` is the raw release
/// ZIP in base64 — the daemon re-verifies the pinned archive hash and the
/// per-file hashes itself, then lays down root-owned files. Caller bytes are
/// never trusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayInstallParams {
    pub archive_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayInstallResult {
    pub version: String,
    /// `true` when the version tree was created; `false` when the exact
    /// verified installation already existed.
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayRemoveResult {
    pub removed: bool,
}

/// A running listener binding, without client environment or subscription secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyExitBinding {
    pub name: String,
    pub target: crate::models::ProxyTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyExitStatus {
    pub name: String,
    pub target: crate::models::ProxyTarget,
    pub socks_port: u16,
    pub http_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<crate::models::FailoverStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayStatusResult {
    pub profile_id: String,
    pub state: TunnelState,
    pub interface_name: Option<String>,
    pub dns_applied: bool,
    pub ipv4_covered: bool,
    pub ipv6_covered: bool,
    /// TUN inbound counters from the Xray stats API; `None` when the
    /// statsquery endpoint is unreachable (e.g. an older staged config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<u64>,
    /// Live multinode state from the daemon's probe supervisor; absent for
    /// single-endpoint tunnels and unsupported backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<crate::models::FailoverStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watchdog: Option<crate::models::WatchdogStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_exits: Vec<ProxyExitStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayConnectResult {
    pub status: XrayStatusResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayDisconnectResult {
    pub stopped: bool,
}

/// The system `tailscaled` is a *foreign* daemon: it owns its own process,
/// TUN and policy routing, so nothing here is journaled. These methods just
/// proxy the LocalAPI status and the WantRunning pref (`tailscale up/down`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TailscalePeer {
    pub host_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(default)]
    pub tailscale_ips: Vec<String>,
    /// Advertised routes for subnet routers (`AllowedIPs` minus the node's
    /// own /32 and /128 addresses), e.g. `192.168.1.0/24`.
    #[serde(default)]
    pub routes: Vec<String>,
    /// This peer currently is our exit node.
    #[serde(default)]
    pub exit_node: bool,
    /// This peer offers itself as an exit node.
    #[serde(default)]
    pub exit_node_option: bool,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub os: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleStatusResult {
    /// `false` when `tailscaled` is absent or its socket is unreachable —
    /// an absent daemon is a state, not an RPC error.
    pub available: bool,
    /// `ipnstate` BackendState verbatim: "Running", "Stopped", "NeedsLogin"…
    pub backend_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailnet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_dns_suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_host_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_dns_name: Option<String>,
    #[serde(default)]
    pub self_ips: Vec<String>,
    #[serde(default)]
    pub exit_node_active: bool,
    #[serde(default)]
    pub peers: Vec<TailscalePeer>,
}

/// macOS: what the user's own Tailscale needs so that a primary tunnel does
/// not cut the tailnet off. The unprivileged side reads Tailscale's state and
/// the helper only validates and installs routes: `self_ips` identify which
/// utun is Tailscale's (the one carrying one of these addresses), `endpoints`
/// are the remote addresses its own traffic uses (direct peers, DERP, the
/// control server) and must keep reaching the physical uplink.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleProtectParams {
    #[serde(default)]
    pub self_ips: Vec<std::net::IpAddr>,
    #[serde(default)]
    pub endpoints: Vec<std::net::IpAddr>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleProtectResult {
    /// Tailscale's interface, when one carries a given address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Tailnet prefixes the helper had to pin to that interface because
    /// something else was winning them (empty when Tailscale's own routes
    /// already win, the usual case).
    #[serde(default)]
    pub pinned: Vec<String>,
    /// Remote hosts now routed around the primary tunnel.
    #[serde(default)]
    pub bypassed: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleReleaseResult {
    pub released: bool,
}

/// Only these backends support pre-login replay. OpenVPN credentials and Xray
/// plaintext need a separate persistence/security review before enrollment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AlwaysOnKind {
    WireGuard,
    StaticRoutes,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnStaticRoutes {
    pub profile_id: String,
    /// Stable interface name, resolved to an ifindex again after reboot.
    pub interface_name: String,
    pub routes: Vec<PolicyRoute>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "profile", rename_all = "camelCase")]
pub enum AlwaysOnDefinition {
    WireGuard(WireGuardConnectParams),
    StaticRoutes(AlwaysOnStaticRoutes),
}

impl AlwaysOnDefinition {
    pub fn kind(&self) -> AlwaysOnKind {
        match self {
            Self::WireGuard(_) => AlwaysOnKind::WireGuard,
            Self::StaticRoutes(_) => AlwaysOnKind::StaticRoutes,
        }
    }

    pub fn profile_id(&self) -> &str {
        match self {
            Self::WireGuard(profile) => &profile.profile_id,
            Self::StaticRoutes(profile) => &profile.profile_id,
        }
    }

    pub fn owner(&self) -> String {
        match self {
            Self::WireGuard(profile) => format!("wg:{}", profile.profile_id),
            Self::StaticRoutes(profile) => profile.profile_id.clone(),
        }
    }
}

impl std::fmt::Debug for AlwaysOnDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlwaysOnDefinition")
            .field("kind", &self.kind())
            .field("profile", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnSetParams {
    pub definition: AlwaysOnDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnRemoveParams {
    pub kind: AlwaysOnKind,
    pub profile_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnProfileInfo {
    pub kind: AlwaysOnKind,
    pub profile_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnListResult {
    pub profiles: Vec<AlwaysOnProfileInfo>,
    pub paused: bool,
    pub supported_kinds: Vec<AlwaysOnKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnSetResult {
    pub stored: bool,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnRemoveResult {
    pub removed: bool,
    pub disconnected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnResumeResult {
    pub resumed: bool,
}

/// When a conditional rule's routes may be installed. The daemon evaluates
/// conditions against kernel state (local addresses, interfaces) — never a
/// probe through the tunnel the condition controls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RouteCondition {
    /// Active while a non-tunnel interface holds a global-scope address
    /// inside `prefix` — e.g. "this machine is on the office LAN".
    InterfaceAddressIn { prefix: IpNet },
}

/// A named conditional route set, persisted per uid in the daemon. While
/// `condition` holds (and `enabled`), `routes` are installed on the matched
/// interface; when it stops holding they are removed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalRouteRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub condition: RouteCondition,
    pub routes: Vec<PolicyRoute>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConditionalRuleState {
    /// `enabled` is false; no routes are wanted.
    Disabled,
    /// The condition does not currently hold; nothing is installed.
    Inactive,
    /// The condition holds and the routes are installed.
    Active,
    /// The last apply/remove failed; `detail` carries the error.
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalRuleStatus {
    pub state: ConditionalRuleState,
    /// Interface that satisfied the condition during the last evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_interface: Option<String>,
    /// Routes currently installed for this rule.
    pub applied_routes: usize,
    /// Error detail for `state == error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalRuleEntry {
    pub rule: ConditionalRouteRule,
    pub status: ConditionalRuleStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CondRulesListResult {
    pub rules: Vec<ConditionalRuleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CondRulesPutParams {
    pub rule: ConditionalRouteRule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CondRulesPutResult {
    pub stored: bool,
    pub status: ConditionalRuleStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CondRulesRemoveParams {
    pub rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CondRulesRemoveResult {
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinkSetStateParams {
    pub name: String,
    pub up: bool,
}

/// Stop a tunnel interface the daemon does not own (wg-quick, another VPN
/// app's device). WireGuard devices are deleted; foreign TUN devices are
/// admin-downed since only the owning process can unlink them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalTunnelStopParams {
    pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OwnedState {
    /// Write-ahead record: netlink changes may be partially applied.
    Applying,
    Applied,
    /// Teardown failed; the listed resources may still exist.
    Stale,
}

/// One resource the daemon created for an owner. Tagged by `kind` so later
/// stages can add links, rules, DNS or processes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OwnedResource {
    Route(AppliedRoute),
    WireGuardLink(WireGuardLinkResource),
    OpenVpnProcess(OpenVpnProcessResource),
    XrayProcess(XrayProcessResource),
    Address(WireGuardAddressResource),
    Rule(OwnedRuleResource),
    Dns(WireGuardDnsResource),
    /// Deferred intent: routes bound to an external interface by *name*
    /// plus uplink bypasses. Carries no kernel artifact by itself; realized
    /// `Route` resources on the same entry are its current derivation.
    AttachSpec(AttachSpecParams),
    /// A route installed through `net.route.add` (full kernel spec, daemon
    /// protocol marker). Removed on owner teardown.
    NetRoute(SystemRoute),
    /// A policy rule installed through `net.rule.add` (full kernel spec,
    /// daemon protocol marker). Removed on owner teardown.
    NetRule(SystemRule),
    /// A foreign route the user deleted through `net.route.del`. The
    /// kernel object is gone; teardown *re-installs* the snapshot so the
    /// system comes back exactly as it was.
    SuppressedRoute(SystemRoute),
    /// A foreign rule deleted through `net.rule.del`, restored on teardown.
    SuppressedRule(SystemRule),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardFullResource {
    pub table: u32,
    pub fwmark: u32,
    pub priority_main: u32,
    pub priority_tunnel: u32,
    pub ipv4: bool,
    pub ipv6: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnedRuleResource {
    pub family: IpFamily,
    pub priority: u32,
    pub table: u32,
    pub fwmark: Option<u32>,
    pub invert: bool,
    pub suppress_prefix_length: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardDnsResource {
    pub interface_index: u32,
    pub name: String,
    pub servers: Vec<std::net::IpAddr>,
    pub domains: Vec<String>,
    pub full: bool,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardLinkResource {
    pub name: String,
    /// Zero means creation was journaled but the kernel index was not yet known.
    pub index: u32,
    pub owner_marker: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<WireGuardFullResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<WireGuardWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardAddressResource {
    pub interface_index: u32,
    pub address: IpNet,
}

/// Journal marker for a daemon-owned OpenVPN process, without a reusable PID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnProcessResource {
    pub name: String,
    pub owner_marker: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_mark: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<WireGuardFullResource>,
}

/// Journal marker for a daemon-owned Xray TUN process. Config stays private.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayProcessResource {
    pub name: String,
    /// Zero until the process creates the TUN link.
    #[serde(default)]
    pub index: u32,
    pub owner_marker: String,
    pub transport_mark: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<WireGuardFullResource>,
    /// Multinode probe policy, journaled so a daemon restart can resurrect
    /// the failover supervisor alongside the tunnel itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<XrayFailoverParams>,
    #[serde(default)]
    pub reject_quic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_exits: Vec<ProxyExitBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnedEntry {
    pub owner: String,
    pub state: OwnedState,
    pub resources: Vec<OwnedResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnedListResult {
    pub owners: Vec<OwnedEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupResult {
    pub removed_owners: Vec<String>,
    /// Owners whose teardown failed; they stay listed as `stale`.
    pub failed: Vec<String>,
}

/// Payload of the `owned.changed` event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnedChanged {
    pub owner: String,
}

/// Decode typed params/results; malformed input is `InvalidData`.
pub fn from_value<T: DeserializeOwned>(value: Value) -> io::Result<T> {
    serde_json::from_value(value).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Serialize one frame as a single JSON line terminated by `\n`.
pub fn encode_line<T: Serialize>(frame: &T) -> io::Result<Vec<u8>> {
    let mut line =
        serde_json::to_vec(frame).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    line.push(b'\n');
    Ok(line)
}

/// Read one `\n`-terminated frame (without the newline).
///
/// - `Ok(None)` on a clean EOF between frames;
/// - `InvalidData` as soon as the frame grows past `max` bytes, without
///   waiting for the rest of it;
/// - `UnexpectedEof` if the peer closes mid-frame.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed in the middle of a frame",
                ))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        if line.len() + chunk.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame exceeds {max} bytes"),
            ));
        }
        line.extend_from_slice(chunk);
        let consumed = chunk.len() + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AppliedRoute;
    use serde::de::DeserializeOwned;
    use serde_json::{json, Value};
    use std::time::Duration;
    use tokio::io::{AsyncWriteExt, BufReader};

    /// Parse `text` into `T`, serialize it back and require the exact same
    /// JSON value (field order aside).
    fn round_trip<T: Serialize + DeserializeOwned>(text: &str) -> T {
        let original: Value = serde_json::from_str(text).unwrap();
        let typed: T = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(&typed).unwrap(), original, "{text}");
        typed
    }

    fn request<P: DeserializeOwned>(text: &str) -> (RequestFrame, P) {
        let frame: RequestFrame = round_trip(text);
        let params: P = from_value(frame.params.clone()).unwrap();
        (frame, params)
    }

    fn ok_response<R: Serialize + DeserializeOwned>(text: &str) -> (u64, R) {
        let frame: ResponseFrame = round_trip(text);
        let value = frame.outcome.clone().expect("ok response");
        let result: R = from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&result).unwrap(), value);
        (frame.id, result)
    }

    fn error_response(text: &str) -> (u64, ErrorBody) {
        let frame: ResponseFrame = round_trip(text);
        (frame.id, frame.outcome.expect_err("error response"))
    }

    #[test]
    fn golden_hello() {
        let (frame, params): (_, HelloParams) = request(
            r#"{"id":1,"method":"hello","params":{"protocol":1,"client":"net-manager-app/0.1.1"}}"#,
        );
        assert_eq!(frame.method, method::HELLO);
        assert_eq!(params.protocol, PROTOCOL_VERSION);
        assert_eq!(params.client, "net-manager-app/0.1.1");

        let (id, result): (_, HelloResult) = ok_response(
            r#"{"id":1,"ok":true,"result":{"protocol":1,"daemonVersion":"0.1.1","uid":1000,
              "capabilities":["routes.apply","routes.remove","link.set_state","owned.list","recovery.cleanup","subscribe","wireguard.connect","wireguard.disconnect","wireguard.status","openvpn.connect","openvpn.disconnect","openvpn.status","openvpn.probe","openvpn.plan","xray.connect","xray.disconnect","xray.status","xray.reload","xray.install","xray.remove","tailscale.status","tailscale.up","tailscale.down","alwaysOn.set","alwaysOn.list","alwaysOn.remove","alwaysOn.resume","settings.get","settings.set","condRules.list","condRules.put","condRules.remove","externalTunnel.stop","nm.list","nm.setActive","net.tables","net.route.add","net.route.del","net.rule.add","net.rule.del","net.explain","net.dns.status","net.dns.probe","net.intent.list","net.intent.set","net.intent.del"],"tools":{}}}"#,
        );
        assert_eq!(id, 1);
        assert_eq!(result.uid, 1000);
        assert_eq!(result.daemon_version, "0.1.1");

        // A pre-tools daemon leaves the map empty: missing keys mean
        // "unknown", which callers treat as usable.
        let legacy: HelloResult = serde_json::from_str(
            r#"{"protocol":1,"daemonVersion":"0.1.1","uid":1000,"capabilities":[]}"#,
        )
        .unwrap();
        assert!(legacy.tools.is_empty());

        let (id, result): (_, HelloResult) = ok_response(
            r#"{"id":2,"ok":true,"result":{"protocol":1,"daemonVersion":"0.3.0","uid":0,
              "capabilities":[],"tools":{"wireguard":true,"openvpn":false}}}"#,
        );
        assert_eq!(id, 2);
        assert_eq!(result.tools.get(tool::WIREGUARD), Some(&true));
        assert_eq!(result.tools.get(tool::OPENVPN), Some(&false));

        let (_, error) = error_response(
            r#"{"id":1,"ok":false,"error":{"code":"protocolMismatch","message":"daemon speaks protocol 1, client 2"}}"#,
        );
        assert_eq!(error.code, ErrorCode::ProtocolMismatch);
    }

    #[test]
    fn hello_feature_promises_remain_string_list_compatible() {
        let hello: HelloResult = serde_json::from_str(
            r#"{"protocol":1,"daemonVersion":"new","uid":1000,"capabilities":["xray.connect","xray.tun.ipv6","future.feature"]}"#,
        )
        .unwrap();
        assert_eq!(hello.protocol, PROTOCOL_VERSION);
        assert_eq!(hello.capabilities[1], feature::XRAY_TUN_IPV6);
        assert_eq!(hello.capabilities[2], "future.feature");
        assert!(hello.tools.is_empty());
        let encoded = serde_json::to_value(&hello).unwrap();
        assert_eq!(encoded["capabilities"][1], "xray.tun.ipv6");
        assert_eq!(encoded["capabilities"][2], "future.feature");
    }

    #[test]
    fn golden_tailscale() {
        let (frame, _): (_, serde_json::Value) =
            request(r#"{"id":40,"method":"tailscale.status","params":{}}"#);
        assert_eq!(frame.method, method::TAILSCALE_STATUS);

        let (_, result): (_, TailscaleStatusResult) = ok_response(
            r#"{"id":41,"ok":true,"result":{"available":true,"backendState":"Running",
              "tailnet":"tailnet.test","selfIps":["100.78.82.81"],
              "exitNodeActive":false,
              "peers":[{"hostName":"kzn1","tailscaleIps":["100.85.160.64"],
                "routes":["192.168.9.0/24"],"exitNode":false,
                "exitNodeOption":false,"online":true,"os":"linux"}]}}"#,
        );
        assert!(result.available);
        assert_eq!(result.backend_state, "Running");
        assert_eq!(result.peers[0].routes, ["192.168.9.0/24"]);
        // Round-trip keeps camelCase on the wire.
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("backendState").is_some());
        assert!(json.get("backend_state").is_none());
        let (_, empty): (_, TailscaleStatusResult) = ok_response(
            r#"{"id":42,"ok":true,"result":{"available":false,"backendState":"Unavailable","selfIps":[],"exitNodeActive":false,"peers":[]}}"#,
        );
        assert!(!empty.available);
    }

    #[test]
    fn golden_tailscale_protect() {
        let (frame, params): (_, TailscaleProtectParams) = request(
            r#"{"id":50,"method":"tailscale.protect","params":{"selfIps":["100.115.39.70","fd7a:115c:a1e0::c82f:2747"],"endpoints":["203.0.113.7"]}}"#,
        );
        assert_eq!(frame.method, method::TAILSCALE_PROTECT);
        assert_eq!(params.self_ips.len(), 2);
        assert_eq!(
            params.endpoints,
            ["203.0.113.7".parse::<std::net::IpAddr>().unwrap()]
        );
        let (_, result): (_, TailscaleProtectResult) = ok_response(
            r#"{"id":51,"ok":true,"result":{"interface":"utun12","pinned":["100.64.0.0/10"],"bypassed":1}}"#,
        );
        assert_eq!(result.interface.as_deref(), Some("utun12"));
        assert_eq!(result.bypassed, 1);
        let none: TailscaleProtectResult = serde_json::from_str("{}").unwrap();
        assert_eq!(none, TailscaleProtectResult::default());
        assert!(!method::CAPABILITIES.contains(&method::TAILSCALE_PROTECT));
    }

    #[test]
    fn golden_settings() {
        let (frame, params): (_, SettingsSetParams) =
            request(r#"{"id":8,"method":"settings.set","params":{"vpnAuthMode":"always"}}"#);
        assert_eq!(frame.method, method::SETTINGS_SET);
        assert_eq!(params.vpn_auth_mode, VpnAuthMode::Always);
        let (_, result): (_, SettingsResult) =
            ok_response(r#"{"id":9,"ok":true,"result":{"vpnAuthMode":"fullTunnelOnly"}}"#);
        assert_eq!(result.vpn_auth_mode, VpnAuthMode::FullTunnelOnly);
        assert_eq!(VpnAuthMode::default(), VpnAuthMode::FullTunnelOnly);
        let _: SettingsSetParams = serde_json::from_str(r#"{"vpnAuthMode":"noPrompt"}"#).unwrap();
    }

    #[test]
    fn golden_routes_apply() {
        let (frame, params): (_, RoutesApplyParams) = request(
            r#"{"id":2,"method":"routes.apply","params":{"owner":"static-office","routes":[
              {"destination":"203.0.113.0/24","interfaceIndex":2,"gateway":"192.168.1.1","metric":5},
              {"destination":"2001:db8::/32","interfaceIndex":2,"metric":5}]}}"#,
        );
        assert_eq!(frame.method, method::ROUTES_APPLY);
        assert_eq!(params.owner, "static-office");
        assert_eq!(
            params.routes[0].gateway,
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(
            params.routes[1],
            AppliedRoute::on_link("2001:db8::/32".parse().unwrap(), 2, 5)
        );

        let (_, result): (_, RoutesApplyResult) =
            ok_response(r#"{"id":2,"ok":true,"result":{"applied":2}}"#);
        assert_eq!(result.applied, 2);

        let (_, error) = error_response(
            r#"{"id":2,"ok":false,"error":{"code":"authorizationDismissed","message":"authorization dialog was dismissed; nothing was applied"}}"#,
        );
        assert_eq!(error.code, ErrorCode::AuthorizationDismissed);
    }

    #[test]
    fn golden_always_on_wireguard_and_static_are_typed_and_redacted() {
        let (_, set): (_, AlwaysOnSetParams) = request(
            r#"{"id":20,"method":"alwaysOn.set","params":{"definition":{"kind":"wireGuard","profile":{"profileId":"home","config":"[Interface]\nPrivateKey = secret-marker\n","routes":[]}}}}"#,
        );
        assert_eq!(set.definition.owner(), "wg:home");
        assert!(!format!("{set:?}").contains("secret-marker"));
        let (_, static_set): (_, AlwaysOnSetParams) = request(
            r#"{"id":21,"method":"alwaysOn.set","params":{"definition":{"kind":"staticRoutes","profile":{"profileId":"office","interfaceName":"eth0","routes":[{"destination":"203.0.113.0/24","metric":5,"via":"192.0.2.1"}]}}}}"#,
        );
        assert_eq!(static_set.definition.owner(), "office");
        assert_eq!(method::ALWAYS_ON_SET, "alwaysOn.set");
        assert_eq!(method::ALWAYS_ON_REMOVE, "alwaysOn.remove");
        assert_eq!(method::ALWAYS_ON_RESUME, "alwaysOn.resume");
    }

    #[test]
    fn golden_cond_rules() {
        let (frame, params): (_, CondRulesPutParams) = request(
            r#"{"id":30,"method":"condRules.put","params":{"rule":{
              "id":"office-lan","name":"Office LAN direct","enabled":true,
              "condition":{"kind":"interfaceAddressIn","prefix":"10.228.32.0/21"},
              "routes":[{"destination":"10.99.0.0/24","metric":5,"via":"10.228.32.1"}]}}}"#,
        );
        assert_eq!(frame.method, method::COND_RULES_PUT);
        assert_eq!(
            params.rule.condition,
            RouteCondition::InterfaceAddressIn {
                prefix: "10.228.32.0/21".parse().unwrap()
            }
        );
        assert_eq!(
            params.rule.routes[0].destination.to_string(),
            "10.99.0.0/24"
        );

        let (_, status): (_, CondRulesPutResult) = ok_response(
            r#"{"id":30,"ok":true,"result":{"stored":true,"status":{"state":"active","matchedInterface":"enp1s0","appliedRoutes":1}}}"#,
        );
        assert_eq!(status.status.state, ConditionalRuleState::Active);
        assert_eq!(status.status.matched_interface.as_deref(), Some("enp1s0"));

        let (_, list): (_, CondRulesListResult) = ok_response(
            r#"{"id":31,"ok":true,"result":{"rules":[{"rule":{"id":"office-lan","name":"Office LAN direct","enabled":false,
              "condition":{"kind":"interfaceAddressIn","prefix":"10.228.32.0/21"},"routes":[]},
              "status":{"state":"disabled","appliedRoutes":0}}]}}"#,
        );
        assert_eq!(list.rules[0].status.state, ConditionalRuleState::Disabled);

        let (frame, params): (_, CondRulesRemoveParams) =
            request(r#"{"id":32,"method":"condRules.remove","params":{"ruleId":"office-lan"}}"#);
        assert_eq!(frame.method, method::COND_RULES_REMOVE);
        assert_eq!(params.rule_id, "office-lan");
        let (_, result): (_, CondRulesRemoveResult) =
            ok_response(r#"{"id":32,"ok":true,"result":{"removed":true}}"#);
        assert!(result.removed);
    }

    #[test]
    fn golden_routes_remove() {
        let (frame, params): (_, OwnerParams) =
            request(r#"{"id":3,"method":"routes.remove","params":{"owner":"static-office"}}"#);
        assert_eq!(frame.method, method::ROUTES_REMOVE);
        assert_eq!(params.owner, "static-office");
        let (_, result): (_, RoutesRemoveResult) =
            ok_response(r#"{"id":3,"ok":true,"result":{"removed":2}}"#);
        assert_eq!(result.removed, 2);
    }

    #[test]
    fn golden_link_set_state() {
        let (frame, params): (_, LinkSetStateParams) =
            request(r#"{"id":4,"method":"link.set_state","params":{"name":"enp0s3","up":false}}"#);
        assert_eq!(frame.method, method::LINK_SET_STATE);
        assert_eq!(params.name, "enp0s3");
        assert!(!params.up);
        let (_, result): (_, Value) = ok_response(r#"{"id":4,"ok":true,"result":null}"#);
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn golden_external_tunnel_stop() {
        let (frame, params): (_, ExternalTunnelStopParams) =
            request(r#"{"id":41,"method":"externalTunnel.stop","params":{"name":"wg-quick0"}}"#);
        assert_eq!(frame.method, method::EXTERNAL_TUNNEL_STOP);
        assert_eq!(params.name, "wg-quick0");
        let (_, result): (_, Value) = ok_response(r#"{"id":41,"ok":true,"result":null}"#);
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn golden_owned_list() {
        let frame: RequestFrame = round_trip(r#"{"id":5,"method":"owned.list"}"#);
        assert_eq!(frame.method, method::OWNED_LIST);
        assert_eq!(frame.params, Value::Null);

        let (_, result): (_, OwnedListResult) = ok_response(
            r#"{"id":5,"ok":true,"result":{"owners":[{"owner":"static-office","state":"applied","resources":[
              {"kind":"route","destination":"203.0.113.0/24","interfaceIndex":2,"gateway":"192.168.1.1","metric":5}]}]}}"#,
        );
        let entry = &result.owners[0];
        assert_eq!(entry.owner, "static-office");
        assert_eq!(entry.state, OwnedState::Applied);
        let OwnedResource::Route(route) = &entry.resources[0] else {
            panic!("expected route");
        };
        assert_eq!(route.gateway, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn golden_recovery_cleanup() {
        let frame: RequestFrame = round_trip(r#"{"id":6,"method":"recovery.cleanup"}"#);
        assert_eq!(frame.method, method::RECOVERY_CLEANUP);
        let (_, result): (_, CleanupResult) = ok_response(
            r#"{"id":6,"ok":true,"result":{"removedOwners":["static-office"],"failed":[]}}"#,
        );
        assert_eq!(result.removed_owners, vec!["static-office".to_string()]);
        assert!(result.failed.is_empty());
    }

    #[test]
    fn golden_subscribe_and_events() {
        let frame: RequestFrame = round_trip(r#"{"id":7,"method":"subscribe"}"#);
        assert_eq!(frame.method, method::SUBSCRIBE);
        let (_, result): (_, Value) = ok_response(r#"{"id":7,"ok":true,"result":null}"#);
        assert_eq!(result, Value::Null);

        let event: EventFrame =
            round_trip(r#"{"event":"owned.changed","data":{"owner":"static-office"}}"#);
        assert_eq!(event.event, event::OWNED_CHANGED);
        let data: OwnedChanged = from_value(event.data).unwrap();
        assert_eq!(data.owner, "static-office");

        let event: EventFrame = round_trip(r#"{"event":"resync"}"#);
        assert_eq!(event.event, event::RESYNC);
    }

    #[test]
    fn golden_wireguard_methods() {
        let (frame, params): (_, WireGuardConnectParams) = request(
            r#"{"id":8,"method":"wireguard.connect","params":{"profileId":"home","config":"[Interface]\nPrivateKey = test\n","routes":[]}}"#,
        );
        assert_eq!(frame.method, method::WIREGUARD_CONNECT);
        assert_eq!(params.profile_id, "home");
        assert!(params.config.contains("[Interface]"));
        assert!(params.routes.is_empty());

        let (_, result): (_, WireGuardConnectResult) = ok_response(
            r#"{"id":8,"ok":true,"result":{"status":{"profileId":"home","state":"running","interfaceName":"wg-ab12","latestHandshake":null,"rxBytes":0,"txBytes":0,"dnsApplied":true,"warnings":[]}}}"#,
        );
        assert_eq!(result.status.interface_name.as_deref(), Some("wg-ab12"));
        assert!(result.status.dns_applied);

        let (frame, params): (_, WireGuardProfileParams) =
            request(r#"{"id":9,"method":"wireguard.status","params":{"profileId":"home"}}"#);
        assert_eq!(frame.method, method::WIREGUARD_STATUS);
        assert_eq!(params.profile_id, "home");
        let (_, status): (_, WireGuardStatusResult) = ok_response(
            r#"{"id":9,"ok":true,"result":{"profileId":"home","state":"running","interfaceName":"wg-ab12","latestHandshake":42,"rxBytes":7,"txBytes":8,"dnsApplied":false,"warnings":["dnsNotApplied","ignoredSaveConfig"]}}"#,
        );
        assert_eq!(
            status.warnings,
            vec![
                WireGuardWarning::DnsNotApplied,
                WireGuardWarning::IgnoredSaveConfig
            ]
        );

        let (frame, _): (_, WireGuardProfileParams) =
            request(r#"{"id":10,"method":"wireguard.disconnect","params":{"profileId":"home"}}"#);
        assert_eq!(frame.method, method::WIREGUARD_DISCONNECT);
        let (_, result): (_, WireGuardDisconnectResult) =
            ok_response(r#"{"id":10,"ok":true,"result":{"stopped":true}}"#);
        assert!(result.stopped);
    }

    #[test]
    fn golden_openvpn_methods() {
        let (frame, params): (_, OpenVpnConnectParams) = request(
            r#"{"id":11,"method":"openvpn.connect","params":{"profileId":"office","config":"client\nremote vpn.example 1194\n","assets":{"ca.crt":"Y2VydA=="},"routes":[{"destination":"10.9.0.0/16","metric":5}]}}"#,
        );
        assert_eq!(frame.method, method::OPENVPN_CONNECT);
        assert_eq!(params.profile_id, "office");
        assert_eq!(params.assets["ca.crt"], "Y2VydA==");
        assert_eq!(params.routes[0].destination, "10.9.0.0/16".parse().unwrap());

        let (_, result): (_, OpenVpnConnectResult) = ok_response(
            r#"{"id":11,"ok":true,"result":{"status":{"profileId":"office","state":"connecting","interfaceName":"ovpn-ab12","rxBytes":0,"txBytes":0,"appliedRoutes":[],"warnings":[],"failureReason":null}}}"#,
        );
        assert_eq!(result.status.state, OpenVpnConnectionState::Connecting);

        let (frame, params): (_, OpenVpnProfileParams) =
            request(r#"{"id":12,"method":"openvpn.status","params":{"profileId":"office"}}"#);
        assert_eq!(frame.method, method::OPENVPN_STATUS);
        assert_eq!(params.profile_id, "office");
        let (_, status): (_, OpenVpnStatusResult) = ok_response(
            r#"{"id":12,"ok":true,"result":{"profileId":"office","state":"connected","interfaceName":"ovpn-ab12","rxBytes":7,"txBytes":8,"appliedRoutes":["10.9.0.0/16"],"warnings":["dnsNotApplied","ipv6NotCovered"],"failureReason":null}}"#,
        );
        assert_eq!(status.state, OpenVpnConnectionState::Connected);
        assert_eq!(status.failure_reason, None);
        assert_eq!(status.applied_routes, vec!["10.9.0.0/16".parse().unwrap()]);
        assert_eq!(
            status.warnings,
            vec![
                OpenVpnWarning::DnsNotApplied,
                OpenVpnWarning::Ipv6NotCovered
            ]
        );

        let (frame, _): (_, OpenVpnProfileParams) =
            request(r#"{"id":13,"method":"openvpn.disconnect","params":{"profileId":"office"}}"#);
        assert_eq!(frame.method, method::OPENVPN_DISCONNECT);
        let (_, result): (_, OpenVpnDisconnectResult) =
            ok_response(r#"{"id":13,"ok":true,"result":{"stopped":true}}"#);
        assert!(result.stopped);
    }

    #[test]
    fn golden_openvpn_probe_returns_analyzed_routes() {
        let (frame, params): (_, OpenVpnConnectRequest) = request(
            r#"{"id":14,"method":"openvpn.probe","params":{"profileId":"office","config":"client\nremote vpn.example\n","assets":{},"routes":[]}}"#,
        );
        assert_eq!(frame.method, method::OPENVPN_PROBE);
        assert_eq!(params.profile.profile_id, "office");
        assert!(params.credentials.is_none());
        let (_, result): (_, OpenVpnProbeResult) = ok_response(
            r#"{"id":14,"ok":true,"result":{"routes":[{"destination":"10.89.0.0/24","source":"OpenVPN pushed","metric":null}]}}"#,
        );
        assert_eq!(
            result.routes[0].destination,
            "10.89.0.0/24".parse().unwrap()
        );
    }

    #[test]
    fn golden_xray_methods_and_redacted_config() {
        let (frame, params): (_, XrayConnectParams) = request(
            r#"{"id":21,"method":"xray.connect","params":{"profileId":"office","config":"{\"outbounds\":[]}","routes":[{"destination":"10.9.0.0/16","metric":5}],"dnsServers":["10.9.0.53"],"dnsDomains":["corp.example"]}}"#,
        );
        assert_eq!(frame.method, method::XRAY_CONNECT);
        assert_eq!(params.routes[0].destination, "10.9.0.0/16".parse().unwrap());
        assert!(!format!("{params:?}").contains("outbounds"));
        let (_, result): (_, XrayConnectResult) = ok_response(
            r#"{"id":21,"ok":true,"result":{"status":{"profileId":"office","state":"running","interfaceName":"xray-ab12","dnsApplied":true,"ipv4Covered":false,"ipv6Covered":false}}}"#,
        );
        assert_eq!(result.status.state, TunnelState::Running);
        let (frame, _): (_, XrayProfileParams) =
            request(r#"{"id":22,"method":"xray.status","params":{"profileId":"office"}}"#);
        assert_eq!(frame.method, method::XRAY_STATUS);
        let (frame, _): (_, XrayProfileParams) =
            request(r#"{"id":23,"method":"xray.disconnect","params":{"profileId":"office"}}"#);
        assert_eq!(frame.method, method::XRAY_DISCONNECT);
        let (_, result): (_, XrayDisconnectResult) =
            ok_response(r#"{"id":23,"ok":true,"result":{"stopped":true}}"#);
        assert!(result.stopped);
        // xray.reload carries the same connect params — the daemon validates
        // them against the live tunnel before restarting the child in place.
        let (frame, params): (_, XrayConnectParams) = request(
            r#"{"id":24,"method":"xray.reload","params":{"profileId":"office","config":"{\"outbounds\":[]}","routes":[],"dnsServers":[],"dnsDomains":[]}}"#,
        );
        assert_eq!(frame.method, method::XRAY_RELOAD);
        assert_eq!(params.profile_id, "office");
        assert!(!format!("{params:?}").contains("outbounds"));
    }

    #[test]
    fn xray_geo_assets_round_trip_and_stay_out_of_debug() {
        let (frame, params): (_, XrayConnectParams) = request(
            r#"{"id":24,"method":"xray.connect","params":{"profileId":"office","config":"{}","routes":[],"dnsServers":[],"dnsDomains":[],"geoAssets":{"geoipDatB64":"QUJD","geositeDatB64":"REVG"}}}"#,
        );
        assert_eq!(frame.method, method::XRAY_CONNECT);
        let assets = params.geo_assets.as_ref().expect("geo assets");
        assert_eq!(assets.geoip_dat_b64.as_deref(), Some("QUJD"));
        assert_eq!(assets.geosite_dat_b64.as_deref(), Some("REVG"));
        let debug = format!("{params:?}");
        assert!(!debug.contains("QUJD") && !debug.contains("REVG"));

        let encoded = serde_json::to_value(&params).unwrap();
        assert_eq!(encoded["geoAssets"]["geoipDatB64"], "QUJD");
        assert_eq!(encoded["geoAssets"]["geositeDatB64"], "REVG");

        let (_, absent): (_, XrayConnectParams) = request(
            r#"{"id":25,"method":"xray.connect","params":{"profileId":"office","config":"{}","routes":[],"dnsServers":[],"dnsDomains":[]}}"#,
        );
        assert!(absent.geo_assets.is_none());
    }

    #[test]
    fn openvpn_request_debug_redacts_config_and_asset_names_and_values() {
        let params: OpenVpnConnectParams = from_value(json!({
            "profileId": "office",
            "config": "secret-config-marker",
            "assets": {"secret-asset-name": "secret-asset-value"}
        }))
        .unwrap();
        assert!(params.routes.is_empty());
        let debug = format!("{params:?}");
        assert!(debug.contains("[REDACTED]"));
        for secret in [
            "secret-config-marker",
            "secret-asset-name",
            "secret-asset-value",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn openvpn_credentials_round_trip_without_debug_disclosure() {
        let request: OpenVpnConnectRequest = from_value(json!({
            "profileId": "office",
            "config": "secret-config-marker",
            "assets": {"secret-asset-name": "secret-asset-value"},
            "credentials": {
                "authUserPass": {
                    "username": "secret-user-marker",
                    "password": "secret-password-marker"
                },
                "privateKeyPassphrase": "secret-key-marker"
            }
        }))
        .unwrap();
        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(encoded["profileId"], "office");
        assert_eq!(
            encoded["credentials"]["authUserPass"]["username"],
            "secret-user-marker"
        );
        let debug = format!("{request:?} {:?}", request.credentials.as_ref().unwrap());
        for secret in [
            "secret-config-marker",
            "secret-asset-name",
            "secret-asset-value",
            "secret-user-marker",
            "secret-password-marker",
            "secret-key-marker",
        ] {
            assert!(!debug.contains(secret));
        }
        let legacy: OpenVpnConnectRequest = from_value(json!({
            "profileId": "office",
            "config": "client\nremote vpn.example\n",
            "assets": {}
        }))
        .unwrap();
        assert!(legacy.credentials.is_none());
    }

    #[test]
    fn openvpn_process_resource_contains_no_pid_or_secrets() {
        let entry: OwnedEntry = round_trip(
            r#"{"owner":"ovpn:office","state":"applied","resources":[{"kind":"openVpnProcess","name":"ovpn-ab12","ownerMarker":"network-orchestrator:1000:ovpn:office"}]}"#,
        );
        assert!(
            matches!(&entry.resources[0], OwnedResource::OpenVpnProcess(resource) if resource.name == "ovpn-ab12")
        );
    }

    #[test]
    fn openvpn_process_journals_transport_mark_and_full_policy_plan() {
        let entry: OwnedEntry = round_trip(
            r#"{"owner":"ovpn:office","state":"applied","resources":[{"kind":"openVpnProcess","name":"ovpn-ab12","ownerMarker":"network-orchestrator:1000:ovpn:office","transportMark":51820,"full":{"table":51820,"fwmark":51820,"priorityMain":10000,"priorityTunnel":10001,"ipv4":true,"ipv6":false}}]}"#,
        );
        assert!(
            matches!(&entry.resources[0], OwnedResource::OpenVpnProcess(resource) if resource.name == "ovpn-ab12")
        );
    }

    #[test]
    fn full_wireguard_resources_are_kind_tagged_and_secret_free() {
        let entry: OwnedEntry = round_trip(
            r#"{"owner":"wg:home","state":"applied","resources":[
              {"kind":"wireGuardLink","name":"wg-ab12","index":42,"ownerMarker":"network-orchestrator:1000:wg:home","full":{"table":51820,"fwmark":51820,"priorityMain":10000,"priorityTunnel":10001,"ipv4":true,"ipv6":false}},
              {"kind":"rule","family":"ipv4","priority":10000,"table":254,"fwmark":null,"invert":false,"suppressPrefixLength":0},
              {"kind":"dns","interfaceIndex":42,"name":"wg-ab12","servers":["10.77.0.1"],"domains":[],"full":true,"applied":true}
            ]}"#,
        );
        assert_eq!(entry.resources.len(), 3);
        assert!(matches!(&entry.resources[1], OwnedResource::Rule(rule) if rule.priority == 10000));
    }

    #[test]
    fn s1_owned_route_remains_readable() {
        let old = r#"{"owner":"office","state":"applied","resources":[{"kind":"route","destination":"10.0.0.0/8","interfaceIndex":2,"metric":5}]}"#;
        let entry: OwnedEntry = serde_json::from_str(old).unwrap();
        assert!(matches!(
            entry.resources.as_slice(),
            [OwnedResource::Route(_)]
        ));
    }

    #[test]
    fn unknown_method_parses_as_frame() {
        let frame: RequestFrame =
            serde_json::from_str(r#"{"id":9,"method":"frobnicate","params":{"x":1}}"#).unwrap();
        assert_eq!(frame.id, 9);
        assert_eq!(frame.method, "frobnicate");
        assert_eq!(frame.params, json!({"x":1}));
    }

    #[test]
    fn owned_resource_route_is_kind_tagged() {
        let resource =
            OwnedResource::Route(AppliedRoute::on_link("10.0.0.0/8".parse().unwrap(), 3, 1));
        assert_eq!(
            serde_json::to_value(&resource).unwrap(),
            json!({"kind":"route","destination":"10.0.0.0/8","interfaceIndex":3,"metric":1})
        );
    }

    #[test]
    fn unknown_resource_kind_is_invalid_data() {
        let err =
            from_value::<OwnedResource>(json!({"kind":"dns","server":"1.1.1.1"})).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn encode_line_appends_single_newline() {
        let line = encode_line(&EventFrame::new(event::RESYNC, Value::Null)).unwrap();
        assert_eq!(line, b"{\"event\":\"resync\"}\n");
    }

    #[tokio::test]
    async fn read_frame_splits_lines() {
        let mut reader: &[u8] = b"{\"a\":1}\n{\"b\":2}\n";
        assert_eq!(
            read_frame(&mut reader, 64).await.unwrap().unwrap(),
            b"{\"a\":1}"
        );
        assert_eq!(
            read_frame(&mut reader, 64).await.unwrap().unwrap(),
            b"{\"b\":2}"
        );
        assert!(read_frame(&mut reader, 64).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_without_newline() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(&[b'a'; 64]).await.unwrap();
        // The writer stays open: the limit must trip without waiting for
        // a newline or EOF.
        let mut reader = BufReader::new(reader);
        let result = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut reader, 16))
            .await
            .expect("read_frame must not wait for a newline");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        drop(writer);
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let mut reader: &[u8] = b"";
        assert!(read_frame(&mut reader, 16).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_eof_mid_frame() {
        let mut reader: &[u8] = b"{\"a\":";
        let err = read_frame(&mut reader, 16).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
