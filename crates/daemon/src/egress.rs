//! Effective underlay identity, independent of route metrics and NM noise.
use crate::netlink::NetlinkExecutor;
use futures::StreamExt;
use net_manager_core::daemon_protocol::{IpFamily, SystemRoute};
use net_manager_core::policy::RouteExecutor;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkFlag;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::AsyncSocket;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct EgressPath {
    pub gateway: Option<IpAddr>,
    pub device_index: u32,
    pub source: IpAddr,
    pub carrier_changes: Option<u64>,
}
impl PartialEq for EgressPath {
    fn eq(&self, other: &Self) -> bool {
        self.gateway == other.gateway
            && self.device_index == other.device_index
            && self.source == other.source
            && self.carrier_changes == other.carrier_changes
    }
}
impl Eq for EgressPath {}
impl Hash for EgressPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.gateway.hash(state);
        self.device_index.hash(state);
        self.source.hash(state);
        self.carrier_changes.hash(state);
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EgressSignature {
    pub paths: Vec<EgressPath>,
}
#[derive(Debug, Clone, Default)]
pub struct EgressSample {
    pub signature: Option<EgressSignature>,
    pub interrupted: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressEvent {
    Stable,
    Changed,
    Flap,
    Lost,
    Online,
}
#[derive(Default)]
pub struct EgressTracker {
    last: Option<EgressSignature>,
    offline: bool,
}
impl EgressTracker {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn signature(&self) -> Option<&EgressSignature> {
        self.last.as_ref()
    }
    pub fn observe(&mut self, sample: &EgressSample) -> EgressEvent {
        let Some(now) = &sample.signature else {
            let lost = self.last.is_some() && !self.offline;
            self.offline = true;
            return if lost {
                EgressEvent::Lost
            } else {
                EgressEvent::Stable
            };
        };
        let event = match &self.last {
            None => EgressEvent::Online,
            Some(last) if last != now => EgressEvent::Changed,
            Some(_) if self.offline || sample.interrupted => EgressEvent::Flap,
            Some(_) => EgressEvent::Stable,
        };
        self.last = Some(now.clone());
        self.offline = false;
        event
    }
}
pub fn fingerprint(signature: &EgressSignature) -> String {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    signature.hash(&mut hash);
    format!("{:016x}", hash.finish())
}

pub(crate) fn bind_device(fd: RawFd, name: &str) -> io::Result<()> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid probe interface"))?;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
pub(crate) fn set_mark(fd: RawFd, mark: u32) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn selected_source(name: &str, index: u32, mark: u32, target: IpAddr) -> io::Result<IpAddr> {
    let socket = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    bind_device(socket.as_raw_fd(), name)?;
    set_mark(socket.as_raw_fd(), mark)?;
    let target = match target {
        IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
            ip,
            9,
            0,
            if ip.is_unicast_link_local() { index } else { 0 },
        )),
        ip => SocketAddr::new(ip, 9),
    };
    // UDP connect performs source selection, but sends no packet.
    socket.connect(target)?;
    Ok(socket.local_addr()?.ip())
}
fn main_default(route: &SystemRoute, family: IpFamily, excluded: &str) -> bool {
    route.table == 254
        && route.family == family
        && route.kind == "unicast"
        && route.destination.prefix_len() == 0
        && route.interface_name.as_deref() != Some(excluded)
}
fn destructive_for(paths: &[EgressPath], event: &RouteNetlinkMessage) -> bool {
    match event {
        RouteNetlinkMessage::DelLink(link) => paths.iter().any(|path| path.device_index == link.header.index),
        RouteNetlinkMessage::NewLink(link) if !link.header.flags.contains(&LinkFlag::Up) => {
            paths.iter().any(|path| path.device_index == link.header.index)
        }
        RouteNetlinkMessage::DelAddress(address) => paths.iter().any(|path| {
            path.device_index == address.header.index && address.attributes.iter().any(|attribute| {
                matches!(attribute, AddressAttribute::Address(ip) | AddressAttribute::Local(ip) if *ip == path.source)
            })
        }),
        // A route replacement can be only a metric/DHCP renewal. Compare
        // its final effective identity in sample(), never reset from it alone.
        _ => false,
    }
}

/// Read-only sampler and cancellable link/address latch, all outside core.
pub struct EgressSampler {
    netlink: NetlinkExecutor,
    mark: u32,
    excluded: String,
    targets: Vec<IpAddr>,
    selected: Arc<Mutex<Vec<EgressPath>>>,
    interrupted: Arc<AtomicBool>,
    listener: tokio::task::JoinHandle<()>,
}
impl EgressSampler {
    pub fn new(
        netlink: NetlinkExecutor,
        runtime: &tokio::runtime::Handle,
        mark: u32,
        excluded: String,
        targets: Vec<IpAddr>,
        authorized: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let selected = Arc::new(Mutex::new(Vec::new()));
        let interrupted = Arc::new(AtomicBool::new(false));
        let listener = {
            let _entered = runtime.enter();
            let (mut connection, _handle, mut messages) = rtnetlink::new_connection()?;
            let groups = rtnetlink::constants::RTMGRP_LINK
                | rtnetlink::constants::RTMGRP_IPV4_IFADDR
                | rtnetlink::constants::RTMGRP_IPV6_IFADDR
                | rtnetlink::constants::RTMGRP_IPV4_ROUTE
                | rtnetlink::constants::RTMGRP_IPV6_ROUTE;
            connection
                .socket_mut()
                .socket_mut()
                .bind(&netlink_sys::SocketAddr::new(0, groups))?;
            let selected = Arc::clone(&selected);
            let interrupted = Arc::clone(&interrupted);
            runtime.spawn(async move {
                tokio::pin!(connection);
                loop {
                    tokio::select! {
                        _ = &mut connection => break,
                        message = messages.next() => {
                            let Some((message, _)) = message else { break };
                            if let NetlinkPayload::InnerMessage(event) = message.payload {
                                if selected.lock().is_ok_and(|paths| destructive_for(&paths, &event)) {
                                    interrupted.store(true, Ordering::Relaxed);
                                    authorized.store(false, Ordering::Relaxed);
                                }
                                // Route replacement invalidates permission to recover,
                                // not effective identity: DHCP/metric churn isn't a flap.
                                if matches!(&event, RouteNetlinkMessage::DelRoute(route)
                                    if route.header.destination_prefix_length == 0
                                        && route.header.table == 254) {
                                    authorized.store(false, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            })
        };
        Ok(Self {
            netlink,
            mark,
            excluded,
            targets,
            selected,
            interrupted,
            listener,
        })
    }
    pub fn sample(&mut self) -> io::Result<EgressSample> {
        let tables = self.netlink.net_tables()?;
        let addresses = self.netlink.interface_addrs()?;
        let mut paths = Vec::new();
        for family in [IpFamily::Ipv4, IpFamily::Ipv6] {
            let ipv4 = family == IpFamily::Ipv4;
            if !self.targets.is_empty()
                && !self
                    .targets
                    .iter()
                    .any(|ip| ip.is_ipv4() == ipv4 && !ip.is_loopback())
            {
                continue;
            }
            let best = tables
                .routes
                .iter()
                .filter(|route| main_default(route, family, &self.excluded))
                .map(|route| route.metric.unwrap_or(0))
                .min();
            for route in tables.routes.iter().filter(|route| {
                main_default(route, family, &self.excluded)
                    && Some(route.metric.unwrap_or(0)) == best
            }) {
                let ordinary = route
                    .interface_index
                    .zip(route.interface_name.as_deref())
                    .map(|(index, name)| (index, name, route.gateway));
                let hops = ordinary.into_iter().chain(
                    route
                        .nexthops
                        .iter()
                        .filter(|_| ordinary.is_none())
                        .filter_map(|hop| {
                            hop.interface_name
                                .as_deref()
                                .map(|name| (hop.interface_index, name, hop.gateway))
                        }),
                );
                for (index, name, gateway) in hops {
                    if name == self.excluded {
                        continue;
                    }
                    let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))?;
                    if u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap_or(0)
                        & 1
                        == 0
                    {
                        continue;
                    }
                    if std::fs::read_to_string(format!("/sys/class/net/{name}/carrier"))
                        .is_ok_and(|value| value.trim() == "0")
                    {
                        continue;
                    }
                    let target = gateway.or_else(|| {
                        self.targets
                            .iter()
                            .copied()
                            .find(|ip| ip.is_ipv4() == ipv4 && !ip.is_loopback())
                    });
                    let Some(target) = target else { continue };
                    let Ok(source) = selected_source(name, index, self.mark, target) else {
                        continue;
                    };
                    if !addresses
                        .iter()
                        .any(|address| address.ifindex == index && address.address.addr() == source)
                    {
                        continue;
                    }
                    let carrier_changes =
                        std::fs::read_to_string(format!("/sys/class/net/{name}/carrier_changes"))
                            .ok()
                            .and_then(|value| value.trim().parse().ok());
                    paths.push(EgressPath {
                        gateway,
                        device_index: index,
                        source,
                        carrier_changes,
                    });
                    if paths.len() > 16 {
                        return Err(io::Error::other("underlay path limit exceeded"));
                    }
                }
            }
        }
        // Local-only proxies do not require a physical default route.
        if paths.is_empty()
            && !self.targets.is_empty()
            && self.targets.iter().all(IpAddr::is_loopback)
        {
            paths.push(EgressPath {
                gateway: None,
                device_index: 1,
                source: self.targets[0],
                carrier_changes: None,
            });
        }
        paths.sort_by_key(|path| {
            (
                path.source.is_ipv6(),
                path.device_index,
                path.gateway,
                path.source,
            )
        });
        paths.dedup();
        *self
            .selected
            .lock()
            .map_err(|_| io::Error::other("egress observation lock failed"))? = paths.clone();
        Ok(EgressSample {
            signature: (!paths.is_empty()).then_some(EgressSignature { paths }),
            interrupted: self.interrupted.swap(false, Ordering::Relaxed),
        })
    }
}
impl Drop for EgressSampler {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn signature(source: &str, device: u32, carrier: u64) -> EgressSignature {
        EgressSignature {
            paths: vec![EgressPath {
                gateway: Some("192.0.2.1".parse().unwrap()),
                device_index: device,
                source: source.parse().unwrap(),
                carrier_changes: Some(carrier),
            }],
        }
    }
    fn sample(signature: Option<EgressSignature>) -> EgressSample {
        EgressSample {
            signature,
            interrupted: false,
        }
    }
    #[test]
    fn unchanged_dhcp_identity_preserves_streams_but_source_and_carrier_changes_do_not() {
        let mut tracker = EgressTracker::new();
        let original = signature("192.0.2.2", 3, 1);
        assert_eq!(
            tracker.observe(&sample(Some(original.clone()))),
            EgressEvent::Online
        );
        assert_eq!(
            tracker.observe(&sample(Some(original))),
            EgressEvent::Stable
        );
        assert_eq!(
            tracker.observe(&sample(Some(signature("192.0.2.3", 3, 1)))),
            EgressEvent::Changed
        );
        assert_eq!(
            tracker.observe(&sample(Some(signature("192.0.2.3", 3, 3)))),
            EgressEvent::Changed
        );
    }
    #[test]
    fn offline_then_identical_return_and_subsample_link_loss_are_flaps() {
        let mut tracker = EgressTracker::new();
        let original = signature("192.0.2.2", 3, 1);
        tracker.observe(&sample(Some(original.clone())));
        assert_eq!(tracker.observe(&sample(None)), EgressEvent::Lost);
        assert_eq!(tracker.observe(&sample(None)), EgressEvent::Stable);
        assert_eq!(
            tracker.observe(&sample(Some(original.clone()))),
            EgressEvent::Flap
        );
        assert_eq!(
            tracker.observe(&EgressSample {
                signature: Some(original),
                interrupted: true
            }),
            EgressEvent::Flap
        );
    }
    #[test]
    fn unrelated_address_deletion_and_route_replacement_do_not_interrupt() {
        let paths = signature("192.0.2.2", 3, 1).paths;
        let mut address = netlink_packet_route::address::AddressMessage::default();
        address.header.index = 3;
        address
            .attributes
            .push(AddressAttribute::Local("192.0.2.9".parse().unwrap()));
        assert!(!destructive_for(
            &paths,
            &RouteNetlinkMessage::DelAddress(address.clone())
        ));
        address.attributes = vec![AddressAttribute::Local("192.0.2.2".parse().unwrap())];
        assert!(destructive_for(
            &paths,
            &RouteNetlinkMessage::DelAddress(address.clone())
        ));
        address.header.index = 7;
        assert!(!destructive_for(
            &paths,
            &RouteNetlinkMessage::DelAddress(address)
        ));
        assert!(!destructive_for(
            &paths,
            &RouteNetlinkMessage::DelRoute(Default::default())
        ));
    }
    #[test]
    fn deleting_only_the_selected_link_interrupts() {
        let paths = signature("192.0.2.2", 3, 1).paths;
        let mut link = netlink_packet_route::link::LinkMessage::default();
        link.header.index = 7;
        assert!(!destructive_for(
            &paths,
            &RouteNetlinkMessage::DelLink(link.clone())
        ));
        link.header.index = 3;
        assert!(destructive_for(&paths, &RouteNetlinkMessage::DelLink(link)));
    }
    #[test]
    fn ipv6_source_and_gateway_are_part_of_identity() {
        let mut tracker = EgressTracker::new();
        tracker.observe(&sample(Some(signature("2001:db8::2", 3, 1))));
        assert_eq!(
            tracker.observe(&sample(Some(signature("2001:db8::3", 3, 1)))),
            EgressEvent::Changed
        );
        let mut changed_gateway = signature("2001:db8::3", 3, 1);
        changed_gateway.paths[0].gateway = Some("2001:db8::1".parse().unwrap());
        assert_eq!(
            tracker.observe(&sample(Some(changed_gateway))),
            EgressEvent::Changed
        );
    }
}
