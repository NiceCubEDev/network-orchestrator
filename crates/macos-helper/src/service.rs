//! The helper's own methods. Executors register here as they are
//! implemented; the capability list stays honest and everything else is
//! refused as unsupported.

use crate::intents::IntentExecutor;
use crate::journal::Record;
use crate::openvpn::OpenVpnExecutor;
use crate::peer::Peer;
use crate::server::Handler;
use crate::sysexec::Runner;
use crate::tailscale::{self, TailscaleGuard};
use crate::wireguard::WireGuardExecutor;
use crate::xray::{Error, XrayExecutor};
use net_manager_core::daemon_protocol::{
    from_value, method, CleanupResult, CondRulesListResult, CondRulesPutParams,
    CondRulesRemoveParams, ErrorCode, LinkSetStateParams, NetIntentDelParams, NetIntentListResult,
    NetIntentSetParams, OpenVpnConnectRequest, OpenVpnProcessResource, OpenVpnProfileParams,
    OwnedEntry, OwnedListResult, OwnedResource, OwnedState, RequestFrame, ResponseFrame,
    TailscaleProtectParams, TailscaleReleaseResult, WireGuardConnectParams, WireGuardLinkResource,
    WireGuardProfileParams, XrayConnectParams, XrayProcessResource, XrayProfileParams,
};
use net_manager_core::models::TunnelRole;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

pub struct HelperService {
    xray: Arc<XrayExecutor>,
    wireguard: Arc<WireGuardExecutor>,
    openvpn: Arc<OpenVpnExecutor>,
    tailscale: Option<Arc<TailscaleGuard>>,
    /// Runs `ifconfig` for `link.set_state`; the method is advertised only
    /// when this is set.
    links: Option<Arc<dyn Runner>>,
    /// Routing intents; `net.intent.*` is advertised only when this is set.
    intents: Option<Arc<IntentExecutor>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Xray,
    WireGuard,
    OpenVpn,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Xray => "Xray",
            Kind::WireGuard => "WireGuard",
            Kind::OpenVpn => "OpenVPN",
        }
    }
}

impl HelperService {
    pub fn new(
        xray: Arc<XrayExecutor>,
        wireguard: Arc<WireGuardExecutor>,
        openvpn: Arc<OpenVpnExecutor>,
    ) -> Self {
        Self {
            xray,
            wireguard,
            openvpn,
            tailscale: None,
            links: None,
            intents: None,
        }
    }

    /// Serve `tailscale.protect` / `tailscale.release` with this guard.
    pub fn with_tailscale(mut self, guard: Arc<TailscaleGuard>) -> Self {
        self.tailscale = Some(guard);
        self
    }

    /// Serve `link.set_state` with this runner.
    pub fn with_links(mut self, runner: Arc<dyn Runner>) -> Self {
        self.links = Some(runner);
        self
    }

    /// Serve `net.intent.list/set/del` with this executor.
    pub fn with_intents(mut self, executor: Arc<IntentExecutor>) -> Self {
        self.intents = Some(executor);
        self
    }

    /// Devices of the tunnels this helper runs or still records.
    fn own_interfaces(&self) -> Vec<String> {
        [
            self.xray.owned(),
            self.wireguard.owned(),
            self.openvpn.owned(),
        ]
        .into_iter()
        .flatten()
        .map(|record| record.interface)
        .filter(|name| !name.is_empty())
        .collect()
    }

    /// Tunnels of different kinds run together, but only one of them may be
    /// the primary: two would fight over the default route and the system DNS.
    /// Secondary tunnels carry only their own networks and never conflict.
    fn primary_held_by_another(&self, kind: Kind, role: TunnelRole) -> Option<Kind> {
        if role != TunnelRole::Primary {
            return None;
        }
        [
            (Kind::Xray, self.xray.holds_primary()),
            (Kind::WireGuard, self.wireguard.holds_primary()),
            (Kind::OpenVpn, self.openvpn.holds_primary()),
        ]
        .into_iter()
        .find(|(other, holds)| *other != kind && *holds)
        .map(|(other, _)| other)
    }
}

fn ok<T: Serialize>(id: u64, value: &T) -> ResponseFrame {
    match serde_json::to_value(value) {
        Ok(value) => ResponseFrame::ok(id, value),
        Err(err) => ResponseFrame::error(id, ErrorCode::Internal, err.to_string()),
    }
}

impl From<tailscale::Error> for Error {
    fn from(error: tailscale::Error) -> Self {
        match error {
            tailscale::Error::Invalid(message) => Error::Invalid(message),
            tailscale::Error::Unavailable(message) => Error::Unavailable(message),
        }
    }
}

fn failure(id: u64, error: Error) -> ResponseFrame {
    let code = match &error {
        Error::Invalid(_) => ErrorCode::InvalidParams,
        Error::Conflict(_) => ErrorCode::Conflict,
        Error::NotFound(_) => ErrorCode::NotFound,
        Error::Unavailable(_) => ErrorCode::Unavailable,
    };
    ResponseFrame::error(id, code, error.to_string())
}

fn invalid_params(id: u64) -> ResponseFrame {
    ResponseFrame::error(id, ErrorCode::InvalidParams, "invalid parameters")
}

/// Decode params, run `action`, answer.
fn call<P: DeserializeOwned, R: Serialize>(
    request: RequestFrame,
    action: impl FnOnce(P) -> Result<R, Error>,
) -> ResponseFrame {
    let id = request.id;
    match from_value::<P>(request.params) {
        Ok(params) => match action(params) {
            Ok(result) => ok(id, &result),
            Err(error) => failure(id, error),
        },
        Err(_) => invalid_params(id),
    }
}

fn owner_of(kind: Kind, profile_id: &str) -> String {
    let prefix = match kind {
        Kind::Xray => "xray",
        Kind::WireGuard => "wireguard",
        Kind::OpenVpn => "openvpn",
    };
    format!("{prefix}:{profile_id}")
}

fn owned_entry(kind: Kind, record: Record) -> OwnedEntry {
    let owner_marker = record.profile_id.clone();
    let name = record.interface.clone();
    let resource = match kind {
        Kind::Xray => OwnedResource::XrayProcess(XrayProcessResource {
            name,
            index: 0,
            owner_marker,
            transport_mark: 0,
            full: None,
            failover: None,
            reject_quic: false,
            probe_url: None,
            pinned_keys: Vec::new(),
            mtu: None,
        }),
        Kind::WireGuard => OwnedResource::WireGuardLink(WireGuardLinkResource {
            name,
            index: 0,
            owner_marker,
            full: None,
            warnings: Vec::new(),
        }),
        Kind::OpenVpn => OwnedResource::OpenVpnProcess(OpenVpnProcessResource {
            name,
            owner_marker,
            transport_mark: None,
            full: None,
        }),
    };
    OwnedEntry {
        owner: owner_of(kind, &record.profile_id),
        state: if record.pid == 0 {
            OwnedState::Applying
        } else {
            OwnedState::Applied
        },
        resources: vec![resource],
    }
}

impl Handler for HelperService {
    fn capabilities(&self) -> Vec<String> {
        let tailscale = self
            .tailscale
            .iter()
            .flat_map(|_| [method::TAILSCALE_PROTECT, method::TAILSCALE_RELEASE]);
        [
            method::OWNED_LIST,
            method::RECOVERY_CLEANUP,
            method::XRAY_CONNECT,
            method::XRAY_DISCONNECT,
            method::XRAY_STATUS,
            method::WIREGUARD_CONNECT,
            method::WIREGUARD_DISCONNECT,
            method::WIREGUARD_STATUS,
            method::OPENVPN_CONNECT,
            method::OPENVPN_DISCONNECT,
            method::OPENVPN_STATUS,
        ]
        .into_iter()
        .chain(tailscale)
        .chain(self.links.iter().map(|_| method::LINK_SET_STATE))
        .chain(self.intents.iter().flat_map(|_| {
            [
                method::NET_INTENT_LIST,
                method::NET_INTENT_SET,
                method::NET_INTENT_DEL,
                method::COND_RULES_LIST,
                method::COND_RULES_PUT,
                method::COND_RULES_REMOVE,
            ]
        }))
        .map(|name| name.to_string())
        .collect()
    }

    fn handle(&self, peer: &Peer, request: RequestFrame) -> ResponseFrame {
        let id = request.id;
        let uid = peer.uid;
        let conflict = |kind: Kind, role: TunnelRole| {
            self.primary_held_by_another(kind, role).map(|other| {
                Error::Conflict(format!(
                    "the {} connection is already the primary one; make one of them secondary or disconnect it",
                    other.label()
                ))
            })
        };
        match request.method.as_str() {
            method::OWNED_LIST => {
                let owners = [
                    (Kind::Xray, self.xray.owned()),
                    (Kind::WireGuard, self.wireguard.owned()),
                    (Kind::OpenVpn, self.openvpn.owned()),
                ]
                .into_iter()
                .filter_map(|(kind, record)| record.map(|record| owned_entry(kind, record)))
                .collect();
                ok(id, &OwnedListResult { owners })
            }
            method::RECOVERY_CLEANUP => {
                // Only a tunnel nobody is running is "recovered"; a live one
                // is torn down by its own disconnect.
                let mut result = CleanupResult::default();
                let owner = |kind: Kind, record: Option<Record>| {
                    record.map(|record| owner_of(kind, &record.profile_id))
                };
                for (kind, before, outcome) in [
                    (Kind::Xray, self.xray.owned(), self.xray.recover()),
                    (
                        Kind::WireGuard,
                        self.wireguard.owned(),
                        self.wireguard.recover(),
                    ),
                    (Kind::OpenVpn, self.openvpn.owned(), self.openvpn.recover()),
                ] {
                    match outcome {
                        Ok(true) => result.removed_owners.extend(owner(kind, before)),
                        Ok(false) => {}
                        Err(_) => result.failed.extend(owner(kind, before)),
                    }
                }
                ok(id, &result)
            }
            method::NET_INTENT_LIST if self.intents.is_some() => {
                let executor = self.intents.as_deref().expect("checked by the arm guard");
                ok(
                    id,
                    &NetIntentListResult {
                        intents: executor.list(uid),
                    },
                )
            }
            method::NET_INTENT_SET if self.intents.is_some() => {
                call(request, |params: NetIntentSetParams| {
                    let executor = self.intents.as_deref().expect("checked by the arm guard");
                    executor.set(uid, params)
                })
            }
            method::COND_RULES_LIST if self.intents.is_some() => {
                let executor = self.intents.as_deref().expect("checked by the arm guard");
                ok(
                    id,
                    &CondRulesListResult {
                        rules: executor.list_rules(uid),
                    },
                )
            }
            method::COND_RULES_PUT if self.intents.is_some() => {
                call(request, |params: CondRulesPutParams| {
                    let executor = self.intents.as_deref().expect("checked by the arm guard");
                    executor.put_rule(uid, params.rule)
                })
            }
            method::COND_RULES_REMOVE if self.intents.is_some() => {
                call(request, |params: CondRulesRemoveParams| {
                    let executor = self.intents.as_deref().expect("checked by the arm guard");
                    Ok::<_, Error>(executor.remove_rule(uid, &params.rule_id))
                })
            }
            method::NET_INTENT_DEL if self.intents.is_some() => {
                call(request, |params: NetIntentDelParams| {
                    let executor = self.intents.as_deref().expect("checked by the arm guard");
                    executor.delete(uid, &params.id)
                })
            }
            method::LINK_SET_STATE if self.links.is_some() => {
                call(request, |params: LinkSetStateParams| {
                    let runner = self.links.as_deref().expect("checked by the arm guard");
                    crate::link::set_state(runner, &params.name, params.up, &self.own_interfaces())
                })
            }
            method::XRAY_CONNECT => call(request, |params: XrayConnectParams| {
                if let Some(error) = conflict(Kind::Xray, params.role) {
                    return Err(error);
                }
                self.xray.connect(uid, params)
            }),
            method::XRAY_STATUS => call(request, |params: XrayProfileParams| {
                Ok(self.xray.status(uid, &params.profile_id))
            }),
            method::XRAY_DISCONNECT => call(request, |params: XrayProfileParams| {
                self.xray.disconnect(uid, &params.profile_id)
            }),
            method::WIREGUARD_CONNECT => call(request, |params: WireGuardConnectParams| {
                if let Some(error) = conflict(Kind::WireGuard, params.role) {
                    return Err(error);
                }
                self.wireguard.connect(uid, params)
            }),
            method::WIREGUARD_STATUS => call(request, |params: WireGuardProfileParams| {
                Ok(self.wireguard.status(uid, &params.profile_id))
            }),
            method::WIREGUARD_DISCONNECT => call(request, |params: WireGuardProfileParams| {
                self.wireguard.disconnect(uid, &params.profile_id)
            }),
            method::OPENVPN_CONNECT => call(request, |params: OpenVpnConnectRequest| {
                if let Some(error) = conflict(Kind::OpenVpn, params.profile.role) {
                    return Err(error);
                }
                self.openvpn.connect(uid, params)
            }),
            method::OPENVPN_STATUS => call(request, |params: OpenVpnProfileParams| {
                Ok(self.openvpn.status(uid, &params.profile_id))
            }),
            method::OPENVPN_DISCONNECT => call(request, |params: OpenVpnProfileParams| {
                self.openvpn.disconnect(uid, &params.profile_id)
            }),
            method::TAILSCALE_PROTECT if self.tailscale.is_some() => {
                call(request, |params: TailscaleProtectParams| {
                    let guard = self.tailscale.as_ref().expect("checked by the arm");
                    Ok(guard.protect(&params)?)
                })
            }
            method::TAILSCALE_RELEASE if self.tailscale.is_some() => {
                let guard = self.tailscale.as_ref().expect("checked by the arm");
                match guard.release() {
                    Ok(released) => ok(id, &TailscaleReleaseResult { released }),
                    Err(error) => failure(id, error.into()),
                }
            }
            _ => ResponseFrame::error(
                id,
                ErrorCode::UnsupportedMethod,
                "this method is not available in the macOS helper yet",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Journal;
    use crate::openvpn::{OvpnPlatform, SpawnSpec as OvpnSpawn};
    use crate::sysexec::fake::FakeRunner;
    use crate::wg_engine::PacketIo;
    use crate::wireguard::WgPlatform;
    use crate::xray::{Platform, Process, SpawnSpec, TunDevice};
    use base64::Engine as _;
    use serde_json::{json, Value};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixDatagram;
    use std::path::PathBuf;

    /// Never reaches the machine: every device or launch attempt is refused.
    struct Denied;
    impl Platform for Denied {
        fn open_tun(&self, _: u32) -> io::Result<Box<dyn TunDevice>> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
        fn verify_xray(&self, _: u32, _: Option<&str>) -> Result<PathBuf, Error> {
            Err(Error::Unavailable(
                "Install Xray to start this connection".into(),
            ))
        }
        fn spawn(&self, _: &dyn TunDevice, _: &SpawnSpec) -> io::Result<Box<dyn Process>> {
            unreachable!()
        }
        fn resolve(&self, _: &str) -> Vec<Ipv4Addr> {
            vec![]
        }
        fn is_our_xray(&self, _: u32) -> bool {
            false
        }
        fn kill(&self, _: u32) {}
    }

    struct DeniedWg;
    impl WgPlatform for DeniedWg {
        fn create_tun(&self, _: u32) -> io::Result<(Box<dyn TunDevice>, Box<dyn PacketIo>)> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
        fn resolve(&self, _: &str) -> Option<SocketAddr> {
            None
        }
    }

    struct DeniedOvpn;
    impl OvpnPlatform for DeniedOvpn {
        fn stage_binary(&self) -> io::Result<PathBuf> {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
        fn free_unit(&self) -> io::Result<String> {
            Ok("utun12".into())
        }
        fn spawn(&self, _: &OvpnSpawn) -> io::Result<Box<dyn Process>> {
            unreachable!()
        }
        fn resolve(&self, _: &str) -> Vec<IpAddr> {
            vec![]
        }
        fn is_our_openvpn(&self, _: u32) -> bool {
            false
        }
        fn kill(&self, _: u32) {}
    }

    /// A WireGuard platform that works, to have a live tunnel in the way.
    struct FakeTun;
    impl TunDevice for FakeTun {
        fn name(&self) -> &str {
            "utun11"
        }
    }
    struct FakeIo(UnixDatagram);
    impl PacketIo for FakeIo {
        fn raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.recv(buf)
        }
        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            self.0.send(packet).map(|_| ())
        }
    }
    struct WorkingWg;
    impl WgPlatform for WorkingWg {
        fn create_tun(&self, _: u32) -> io::Result<(Box<dyn TunDevice>, Box<dyn PacketIo>)> {
            let (engine_side, far) = UnixDatagram::pair()?;
            engine_side.set_nonblocking(true)?;
            std::mem::forget(far);
            Ok((Box::new(FakeTun), Box::new(FakeIo(engine_side))))
        }
        fn resolve(&self, _: &str) -> Option<SocketAddr> {
            Some("203.0.113.7:51820".parse().unwrap())
        }
    }

    fn build(wg: Box<dyn WgPlatform>, runner: FakeRunner) -> (HelperService, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let xray = XrayExecutor::new(
            Box::new(Denied),
            Box::new(FakeRunner::default()),
            Journal::new(dir.path()),
            dir.path().join("xray.log"),
        );
        let wireguard = WireGuardExecutor::new(
            wg,
            Box::new(runner),
            Journal::named(dir.path(), "wireguard.json"),
            dir.path().join("resolver"),
        );
        let openvpn = OpenVpnExecutor::new(
            Box::new(DeniedOvpn),
            Box::new(FakeRunner::default()),
            Journal::named(dir.path(), "openvpn.json"),
            dir.path().join("openvpn"),
            dir.path().join("resolver"),
        );
        (
            HelperService::new(Arc::new(xray), Arc::new(wireguard), Arc::new(openvpn)),
            dir,
        )
    }

    fn service() -> (HelperService, tempfile::TempDir) {
        build(Box::new(DeniedWg), FakeRunner::default())
    }

    fn call(service: &HelperService, name: &str, params: Value) -> ResponseFrame {
        service.handle(
            &Peer { uid: 501, pid: 1 },
            RequestFrame {
                id: 9,
                method: name.into(),
                params,
            },
        )
    }

    fn wg_config() -> String {
        let key = |b: u8| base64::engine::general_purpose::STANDARD.encode([b; 32]);
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.7.0.2/32\n[Peer]\nPublicKey = {}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.7.0.0/24\n",
            key(1),
            key(2)
        )
    }

    #[test]
    fn owned_list_and_cleanup_are_empty_without_a_tunnel() {
        let (service, _dir) = service();
        assert_eq!(
            call(&service, method::OWNED_LIST, Value::Null)
                .outcome
                .unwrap()["owners"],
            json!([])
        );
        assert!(call(&service, method::RECOVERY_CLEANUP, Value::Null)
            .outcome
            .is_ok());
    }

    /// Lets a test read what the helper ran.
    struct Shared(Arc<FakeRunner>);
    impl Runner for Shared {
        fn run(&self, program: &str, args: &[String]) -> io::Result<String> {
            self.0.run(program, args)
        }
    }

    fn with_links() -> (HelperService, Arc<FakeRunner>, tempfile::TempDir) {
        let runner = Arc::new(FakeRunner::default());
        runner.reply("ifconfig -l", "lo0 en0 en7 utun9\n");
        let (service, dir) = service();
        (
            service.with_links(Arc::new(Shared(runner.clone()))),
            runner,
            dir,
        )
    }

    #[test]
    fn turning_interfaces_on_or_off_is_advertised_only_when_it_is_enabled() {
        let (plain, _dir) = service();
        assert!(!plain
            .capabilities()
            .iter()
            .any(|c| c == method::LINK_SET_STATE));
        let error = call(
            &plain,
            method::LINK_SET_STATE,
            json!({"name": "en7", "up": false}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedMethod);
        let (enabled, _runner, _dir) = with_links();
        assert!(enabled
            .capabilities()
            .iter()
            .any(|c| c == method::LINK_SET_STATE));
    }

    #[test]
    fn an_interface_is_switched_through_ifconfig_and_bad_requests_are_refused() {
        let (service, runner, _dir) = with_links();
        assert!(call(
            &service,
            method::LINK_SET_STATE,
            json!({"name": "en7", "up": false})
        )
        .outcome
        .is_ok());
        assert!(runner.calls().contains(&"ifconfig en7 down".to_string()));
        let loopback = call(
            &service,
            method::LINK_SET_STATE,
            json!({"name": "lo0", "up": false}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(loopback.code, ErrorCode::InvalidParams);
        let junk = call(
            &service,
            method::LINK_SET_STATE,
            json!({"name": "en7; ls", "up": true}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(junk.code, ErrorCode::InvalidParams);
        let missing = call(
            &service,
            method::LINK_SET_STATE,
            json!({"name": "en42", "up": true}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);
        let wrong = call(&service, method::LINK_SET_STATE, json!({"name": "en7"}))
            .outcome
            .unwrap_err();
        assert_eq!(wrong.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn the_device_of_a_running_tunnel_cannot_be_switched_off() {
        let route = FakeRunner::default();
        route.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        let (service, _dir) = build(Box::new(WorkingWg), route);
        let runner = Arc::new(FakeRunner::default());
        runner.reply("ifconfig -l", "lo0 en0 utun9\n");
        let service = service.with_links(Arc::new(Shared(runner.clone())));
        let up = call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "wg", "config": wg_config()}),
        );
        assert!(up.outcome.is_ok(), "{up:?}");
        let device = service.own_interfaces();
        assert_eq!(device.len(), 1, "{device:?}");
        let error = call(
            &service,
            method::LINK_SET_STATE,
            json!({"name": device[0], "up": false}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(!runner.calls().iter().any(|c| c.contains("down")));
    }

    struct FixedNetwork;
    impl crate::intents::NetworkProbe for FixedNetwork {
        fn view(&self) -> net_manager_core::route_intents::NetworkView {
            net_manager_core::route_intents::NetworkView {
                uplink: None,
                interfaces: vec!["utun5".into()],
                addresses: Vec::new(),
            }
        }
        fn routes(&self) -> Vec<net_manager_core::models::RouteEntry> {
            Vec::new()
        }
    }

    fn with_intents() -> (HelperService, Arc<FakeRunner>, tempfile::TempDir) {
        let runner = Arc::new(FakeRunner::default());
        let (service, dir) = service();
        let executor = IntentExecutor::new(
            Box::new(Shared(runner.clone())),
            Box::new(FixedNetwork),
            dir.path().join("intents.json"),
        )
        .unwrap();
        (service.with_intents(Arc::new(executor)), runner, dir)
    }

    #[test]
    fn intents_are_advertised_only_when_the_executor_is_set() {
        let (plain, _dir) = service();
        for name in [
            method::NET_INTENT_LIST,
            method::NET_INTENT_SET,
            method::NET_INTENT_DEL,
        ] {
            assert!(!plain.capabilities().iter().any(|c| c == name), "{name}");
            let error = call(&plain, name, json!({})).outcome.unwrap_err();
            assert_eq!(error.code, ErrorCode::UnsupportedMethod, "{name}");
        }
        let (enabled, _runner, _dir) = with_intents();
        for name in [
            method::NET_INTENT_LIST,
            method::NET_INTENT_SET,
            method::NET_INTENT_DEL,
        ] {
            assert!(enabled.capabilities().iter().any(|c| c == name), "{name}");
        }
    }

    #[test]
    fn an_intent_is_set_listed_and_deleted_through_the_protocol() {
        let (service, runner, _dir) = with_intents();
        let set = call(
            &service,
            method::NET_INTENT_SET,
            json!({"id": "office", "destinations": ["10.0.0.0/8"],
                   "path": {"kind": "interface", "interface": "utun5"}}),
        );
        assert_eq!(set.outcome.unwrap()["id"], "office");
        assert!(
            runner
                .calls()
                .iter()
                .any(|c| c.starts_with("route -n add -net 10.0.0.0")),
            "{:?}",
            runner.calls()
        );
        let list = call(&service, method::NET_INTENT_LIST, json!({}))
            .outcome
            .unwrap();
        assert_eq!(list["intents"][0]["id"], "office");
        assert_eq!(list["intents"][0]["destinations"][0], "10.0.0.0/8");
        let gone = call(&service, method::NET_INTENT_DEL, json!({"id": "office"}));
        assert_eq!(gone.outcome.unwrap()["id"], "office");
        let list = call(&service, method::NET_INTENT_LIST, json!({}))
            .outcome
            .unwrap();
        assert_eq!(list["intents"], json!([]));
        let missing = call(&service, method::NET_INTENT_DEL, json!({"id": "office"}))
            .outcome
            .unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);
    }

    #[test]
    fn conditional_rules_are_put_listed_and_removed_through_the_protocol() {
        let (service, _runner, _dir) = with_intents();
        assert!(service
            .capabilities()
            .iter()
            .any(|c| c == method::COND_RULES_PUT));
        let rule = json!({"id": "office", "name": "Office", "enabled": true,
            "condition": {"kind": "interfaceAddressIn", "prefix": "10.228.32.0/21"},
            "routes": [{"destination": "10.99.0.0/24", "metric": 5}]});
        let put = call(&service, method::COND_RULES_PUT, json!({"rule": rule}))
            .outcome
            .unwrap();
        assert_eq!(put["stored"], true);
        assert_eq!(put["status"]["state"], "inactive");
        let list = call(&service, method::COND_RULES_LIST, json!({}))
            .outcome
            .unwrap();
        assert_eq!(list["rules"][0]["rule"]["id"], "office");
        let gone = call(
            &service,
            method::COND_RULES_REMOVE,
            json!({"ruleId": "office"}),
        )
        .outcome
        .unwrap();
        assert_eq!(gone["removed"], true);
        let again = call(
            &service,
            method::COND_RULES_REMOVE,
            json!({"ruleId": "office"}),
        )
        .outcome
        .unwrap();
        assert_eq!(again["removed"], false);
        let bad = call(
            &service,
            method::COND_RULES_PUT,
            json!({"rule": {"id": "-x", "name": "x", "enabled": true,
                "condition": {"kind": "interfaceAddressIn", "prefix": "10.0.0.0/8"}, "routes": []}}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(bad.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn conditional_rules_are_unsupported_without_the_executor() {
        let (plain, _dir) = service();
        for name in [
            method::COND_RULES_LIST,
            method::COND_RULES_PUT,
            method::COND_RULES_REMOVE,
        ] {
            assert!(!plain.capabilities().iter().any(|c| c == name), "{name}");
            assert_eq!(
                call(&plain, name, json!({})).outcome.unwrap_err().code,
                ErrorCode::UnsupportedMethod
            );
        }
    }

    #[test]
    fn a_bad_intent_is_refused_with_invalid_params_and_changes_nothing() {
        let (service, runner, _dir) = with_intents();
        for bad in [
            json!({"id": "Bad Id", "destinations": ["10.0.0.0/8"], "path": {"kind": "direct"}}),
            json!({"id": "x", "destinations": ["127.0.0.1"], "path": {"kind": "direct"}}),
            json!({"id": "x", "destinations": ["10.0.0.0/8"], "path": {"kind": "interface", "interface": "lo0"}}),
            json!({"id": "x"}),
        ] {
            let error = call(&service, method::NET_INTENT_SET, bad)
                .outcome
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidParams);
        }
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn the_three_tunnel_kinds_are_advertised_and_the_rest_is_refused() {
        let (service, _dir) = service();
        let capabilities = service.capabilities();
        for name in [
            method::XRAY_CONNECT,
            method::XRAY_DISCONNECT,
            method::XRAY_STATUS,
            method::WIREGUARD_CONNECT,
            method::WIREGUARD_DISCONNECT,
            method::WIREGUARD_STATUS,
            method::OPENVPN_CONNECT,
            method::OPENVPN_DISCONNECT,
            method::OPENVPN_STATUS,
        ] {
            assert!(capabilities.iter().any(|c| c == name), "{name}");
        }
        for name in [
            method::ROUTES_APPLY,
            method::XRAY_INSTALL,
            method::OPENVPN_PROBE,
            method::OPENVPN_PLAN,
            method::TAILSCALE_UP,
        ] {
            let error = call(&service, name, Value::Null).outcome.unwrap_err();
            assert_eq!(error.code, ErrorCode::UnsupportedMethod, "{name}");
            assert!(!capabilities.iter().any(|c| c == name), "{name}");
        }
    }

    #[test]
    fn tailscale_protection_is_served_only_when_a_guard_is_attached() {
        let (service, dir) = service();
        for name in [method::TAILSCALE_PROTECT, method::TAILSCALE_RELEASE] {
            assert!(!service.capabilities().iter().any(|c| c == name), "{name}");
            let error = call(&service, name, json!({})).outcome.unwrap_err();
            assert_eq!(error.code, ErrorCode::UnsupportedMethod, "{name}");
        }
        let service = service.with_tailscale(Arc::new(TailscaleGuard::new(
            Box::new(FakeRunner::default()),
            Journal::named(dir.path(), "tailscale.json"),
        )));
        for name in [method::TAILSCALE_PROTECT, method::TAILSCALE_RELEASE] {
            assert!(service.capabilities().iter().any(|c| c == name), "{name}");
        }
        // Addresses that are not Tailscale's are refused before any command runs.
        let error = call(
            &service,
            method::TAILSCALE_PROTECT,
            json!({"selfIps": ["192.168.1.2"]}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        let released = call(&service, method::TAILSCALE_RELEASE, json!({}))
            .outcome
            .unwrap();
        assert_eq!(released["released"], false);
    }

    #[test]
    fn every_tunnel_method_validates_params_and_maps_errors() {
        let (service, _dir) = service();
        for name in [
            method::XRAY_CONNECT,
            method::WIREGUARD_CONNECT,
            method::OPENVPN_CONNECT,
        ] {
            let error = call(&service, name, json!({"nope": 1}))
                .outcome
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidParams, "{name}");
        }
        // Xray without an install, WireGuard without a usable config.
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "p", "config": "{\"outbounds\":[]}"}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unavailable);
        let error = call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "p", "config": "garbage"}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        assert!(!error.message.contains("garbage"));
        // Status of nothing is a stopped profile, disconnect a no-op.
        for (status, disconnect, key) in [
            (method::XRAY_STATUS, method::XRAY_DISCONNECT, "profileId"),
            (
                method::WIREGUARD_STATUS,
                method::WIREGUARD_DISCONNECT,
                "profileId",
            ),
            (
                method::OPENVPN_STATUS,
                method::OPENVPN_DISCONNECT,
                "profileId",
            ),
        ] {
            let state = call(&service, status, json!({ key: "p" })).outcome.unwrap();
            assert_eq!(state["state"], "stopped", "{status}");
            let stopped = call(&service, disconnect, json!({ key: "p" }))
                .outcome
                .unwrap();
            assert_eq!(stopped["stopped"], false, "{disconnect}");
        }
    }

    #[test]
    fn a_running_tunnel_blocks_the_other_kinds_and_is_listed() {
        let runner = FakeRunner::default();
        runner.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        let (service, _dir) = build(Box::new(WorkingWg), runner);
        let connected = call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "wg", "config": wg_config()}),
        );
        assert!(connected.outcome.is_ok(), "{connected:?}");

        for (name, params) in [
            (
                method::XRAY_CONNECT,
                json!({"profileId": "x", "config": "{}"}),
            ),
            (
                method::OPENVPN_CONNECT,
                json!({"profileId": "o", "config": "client\nremote a.example\n", "assets": {}}),
            ),
        ] {
            let error = call(&service, name, params).outcome.unwrap_err();
            assert_eq!(error.code, ErrorCode::Conflict, "{name}");
            assert!(error.message.contains("WireGuard"), "{}", error.message);
            assert!(error.message.contains("primary"), "{}", error.message);
        }
        let owners = call(&service, method::OWNED_LIST, Value::Null)
            .outcome
            .unwrap();
        assert_eq!(owners["owners"][0]["owner"], "wireguard:wg");
        assert_eq!(owners["owners"][0]["resources"][0]["kind"], "wireGuardLink");

        let stopped = call(
            &service,
            method::WIREGUARD_DISCONNECT,
            json!({"profileId": "wg"}),
        )
        .outcome
        .unwrap();
        assert_eq!(stopped["stopped"], true);
        // Free again: the other kind gets as far as its own validation.
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "x", "config": "{}"}),
        )
        .outcome
        .unwrap_err();
        assert_ne!(error.code, ErrorCode::Conflict);
    }

    #[test]
    fn secondary_tunnels_never_conflict_and_only_one_primary_may_exist() {
        let runner = FakeRunner::default();
        runner.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        let (service, _dir) = build(Box::new(WorkingWg), runner);
        // A secondary WireGuard is up (it carries one network).
        let up = call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "wg", "config": wg_config(), "role": "secondary",
                   "routes": [{"destination": "10.7.0.0/24", "metric": 5}]}),
        );
        assert!(up.outcome.is_ok(), "{up:?}");
        // A primary of another kind is allowed next to it: it gets as far as
        // its own checks (no Xray install / no bundled OpenVPN here).
        for (name, params) in [
            (
                method::XRAY_CONNECT,
                json!({"profileId": "x", "config": "{}"}),
            ),
            (
                method::OPENVPN_CONNECT,
                json!({"profileId": "o", "config": "client\nremote a.example\n", "assets": {}}),
            ),
        ] {
            let error = call(&service, name, params).outcome.unwrap_err();
            assert_ne!(error.code, ErrorCode::Conflict, "{name}: {}", error.message);
        }
        call(
            &service,
            method::WIREGUARD_DISCONNECT,
            json!({"profileId": "wg"}),
        );
        // Now WireGuard is the primary: another primary conflicts, a secondary does not.
        assert!(call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "wg", "config": wg_config()})
        )
        .outcome
        .is_ok());
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "x", "config": "{}"}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "x", "config": "{}", "role": "secondary",
                   "routes": [{"destination": "10.9.0.0/16", "metric": 5}]}),
        )
        .outcome
        .unwrap_err();
        assert_ne!(error.code, ErrorCode::Conflict);
    }
}
