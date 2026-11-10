//! rtnetlink executor. Message building and errno mapping are pure and
//! unit-tested; the socket lives in a dedicated actor thread with its own
//! `current_thread` runtime, so synchronous callers never nest `block_on`.

use crate::cond_rules::{IfaceAddr, NetworkObservation};
use crate::core::{ExternalLinkKind, LinkExecutor, PolicyRuleExecutor, WgSystem};
use futures::{StreamExt, TryStreamExt};
use ipnet::IpNet;
use net_manager_core::daemon_protocol::{
    IpFamily, NetTablesResult, OwnedRuleResource, RouteLookup, SystemNexthop, SystemRoute,
    SystemRule,
};
use net_manager_core::models::AppliedRoute;
use net_manager_core::policy::RouteExecutor;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkFlag, LinkInfo, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteNextHop, RouteProtocol,
    RouteScope, RouteType,
};
use netlink_packet_route::rule::{
    RuleAction, RuleAttribute, RuleFlag, RuleMessage, RulePortRange, RuleUidRange,
};
use netlink_packet_route::{AddressFamily, IpProtocol, RouteNetlinkMessage};
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc as async_mpsc;

/// `RTPROT` stamped on every route the daemon installs; deletes filter on
/// it, so routes installed by anyone else are never removed.
pub const RTPROT_NETWORK_ORCHESTRATOR: u8 = 79;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOp {
    Add,
    Delete,
}

/// Build the `RTM_NEWROUTE`/`RTM_DELROUTE` body for `route`. Adds go out
/// with `NLM_F_EXCL` (rtnetlink's default), so an existing identical route
/// is a conflict rather than being taken over.
pub fn route_request(route: &AppliedRoute, op: RouteOp) -> RouteMessage {
    let mut message = RouteMessage::default();
    let header = &mut message.header;
    header.protocol = RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR);
    header.kind = RouteType::Unicast;
    header.destination_prefix_length = route.destination.prefix_len();
    header.table = RouteHeader::RT_TABLE_MAIN;
    header.scope = match (op, route.destination, route.gateway) {
        // Like `ip route del`: match whatever scope the route has.
        (RouteOp::Delete, _, _) => RouteScope::NoWhere,
        (RouteOp::Add, IpNet::V4(_), None) => RouteScope::Link,
        (RouteOp::Add, _, _) => RouteScope::Universe,
    };
    match route.destination {
        IpNet::V4(net) => {
            header.address_family = AddressFamily::Inet;
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(
                    net.network(),
                )));
        }
        IpNet::V6(net) => {
            header.address_family = AddressFamily::Inet6;
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet6(
                    net.network(),
                )));
        }
    }
    match route.table {
        None => {}
        Some(table) if table <= 255 => message.header.table = table as u8,
        Some(table) => {
            message.header.table = RouteHeader::RT_TABLE_UNSPEC;
            message.attributes.push(RouteAttribute::Table(table));
        }
    }
    message
        .attributes
        .push(RouteAttribute::Oif(route.interface_index));
    message
        .attributes
        .push(RouteAttribute::Priority(route.metric));
    if let Some(gateway) = route.gateway {
        let address = match gateway {
            IpAddr::V4(addr) => RouteAddress::Inet(addr),
            IpAddr::V6(addr) => RouteAddress::Inet6(addr),
        };
        message.attributes.push(RouteAttribute::Gateway(address));
    }
    message
}

fn owned_route_snapshot(message: &RouteMessage) -> Option<AppliedRoute> {
    if message.header.protocol != RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR)
        || message.header.kind != RouteType::Unicast
    {
        return None;
    }
    let destination = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => Some(IpAddr::V4(*address)),
            RouteAttribute::Destination(RouteAddress::Inet6(address)) => Some(IpAddr::V6(*address)),
            _ => None,
        })
        .or_else(|| {
            if message.header.destination_prefix_length != 0 {
                return None;
            }
            match message.header.address_family {
                AddressFamily::Inet => Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                AddressFamily::Inet6 => Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
                _ => None,
            }
        })?;
    let destination = IpNet::new(destination, message.header.destination_prefix_length)
        .ok()?
        .trunc();
    let interface_index = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })?;
    let metric = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        })
        .unwrap_or(0);
    let gateway = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Gateway(RouteAddress::Inet(address)) => Some(IpAddr::V4(*address)),
            RouteAttribute::Gateway(RouteAddress::Inet6(address)) => Some(IpAddr::V6(*address)),
            _ => None,
        });
    let table = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .or_else(|| {
            (message.header.table != RouteHeader::RT_TABLE_MAIN)
                .then_some(message.header.table as u32)
        })
        .filter(|table| *table != RouteHeader::RT_TABLE_MAIN as u32);
    Some(AppliedRoute {
        destination,
        interface_index,
        metric,
        gateway,
        table,
    })
}

/// A connected main-table subnet: unicast, carries an output interface, no
/// gateway — i.e. an on-link network. Returns `(interface, destination)`.
fn on_link_network(message: &RouteMessage) -> Option<(u32, IpNet)> {
    if message.header.kind != RouteType::Unicast
        || message.header.destination_prefix_length == 0
        || route_table(message) != RouteHeader::RT_TABLE_MAIN as u32
        || message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, RouteAttribute::Gateway(_)))
    {
        return None;
    }
    let destination = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => Some(IpAddr::V4(*address)),
            RouteAttribute::Destination(RouteAddress::Inet6(address)) => Some(IpAddr::V6(*address)),
            _ => None,
        })?;
    let interface = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })?;
    let destination = IpNet::new(destination, message.header.destination_prefix_length)
        .ok()?
        .trunc();
    Some((interface, destination))
}

/// A main-table default route carrying a gateway and an output interface —
/// i.e. the physical uplink. Tunnel-carrying routes live in policy tables or
/// lack a gateway, so they are naturally excluded.
fn default_gateway(message: &RouteMessage) -> Option<(IpAddr, u32)> {
    if message.header.destination_prefix_length != 0
        || message.header.kind != RouteType::Unicast
        || message.header.protocol == RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR)
        || route_table(message) != RouteHeader::RT_TABLE_MAIN as u32
    {
        return None;
    }
    let gateway = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Gateway(RouteAddress::Inet(address)) => Some(IpAddr::V4(*address)),
            RouteAttribute::Gateway(RouteAddress::Inet6(address)) => Some(IpAddr::V6(*address)),
            _ => None,
        })?;
    let interface = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })?;
    Some((gateway, interface))
}

fn rule_family(family: IpFamily) -> AddressFamily {
    match family {
        IpFamily::Ipv4 => AddressFamily::Inet,
        IpFamily::Ipv6 => AddressFamily::Inet6,
    }
}

fn rule_snapshot(message: &RuleMessage) -> OwnedRuleResource {
    OwnedRuleResource {
        family: if message.header.family == AddressFamily::Inet6 {
            IpFamily::Ipv6
        } else {
            IpFamily::Ipv4
        },
        priority: rule_priority(message).unwrap_or(0),
        table: rule_table(message),
        fwmark: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::FwMark(value) => Some(*value),
            _ => None,
        }),
        invert: message.header.flags.contains(&RuleFlag::Invert),
        suppress_prefix_length: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::SuppressPrefixLen(value) => Some(*value),
            _ => None,
        }),
    }
}

fn rule_request(rule: &OwnedRuleResource) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = rule_family(rule.family);
    message.header.action = RuleAction::ToTable;
    if rule.invert {
        message.header.flags.push(RuleFlag::Invert);
    }
    if rule.table <= u8::MAX as u32 {
        message.header.table = rule.table as u8;
    } else {
        message.attributes.push(RuleAttribute::Table(rule.table));
    }
    message
        .attributes
        .push(RuleAttribute::Priority(rule.priority));
    if let Some(mark) = rule.fwmark {
        message.attributes.push(RuleAttribute::FwMark(mark));
        message.attributes.push(RuleAttribute::FwMask(u32::MAX));
    }
    if let Some(prefix) = rule.suppress_prefix_length {
        message
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(prefix));
    }
    message
        .attributes
        .push(RuleAttribute::Protocol(RouteProtocol::from(
            RTPROT_NETWORK_ORCHESTRATOR,
        )));
    message
}

fn rule_priority(message: &RuleMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Priority(value) => Some(*value),
            _ => None,
        })
}

fn rule_table(message: &RuleMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Table(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(message.header.table as u32)
}

fn route_table(message: &RouteMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(message.header.table as u32)
}

fn route_kind_name(kind: RouteType) -> String {
    match kind {
        RouteType::Unspec => "unspec".into(),
        RouteType::Unicast => "unicast".into(),
        RouteType::Local => "local".into(),
        RouteType::Broadcast => "broadcast".into(),
        RouteType::Anycast => "anycast".into(),
        RouteType::Multicast => "multicast".into(),
        RouteType::BlackHole => "blackhole".into(),
        RouteType::Unreachable => "unreachable".into(),
        RouteType::Prohibit => "prohibit".into(),
        RouteType::Throw => "throw".into(),
        RouteType::Nat => "nat".into(),
        RouteType::ExternalResolve => "xresolve".into(),
        RouteType::Other(code) => format!("type {code}"),
        _ => format!("{:?}", kind).to_lowercase(),
    }
}

fn route_scope_name(scope: RouteScope) -> String {
    match scope {
        RouteScope::Universe => "universe".into(),
        RouteScope::Site => "site".into(),
        RouteScope::Link => "link".into(),
        RouteScope::Host => "host".into(),
        RouteScope::NoWhere => "nowhere".into(),
        RouteScope::Other(code) => format!("scope {code}"),
        _ => format!("{:?}", scope).to_lowercase(),
    }
}

fn rule_action_name(action: RuleAction) -> String {
    match action {
        RuleAction::ToTable => "lookup".into(),
        RuleAction::Goto => "goto".into(),
        RuleAction::Nop => "nop".into(),
        RuleAction::Blackhole => "blackhole".into(),
        RuleAction::Unreachable => "unreachable".into(),
        RuleAction::Prohibit => "prohibit".into(),
        RuleAction::Unspec => "unspec".into(),
        RuleAction::Other(code) => format!("type {code}"),
        _ => format!("{:?}", action).to_lowercase(),
    }
}

fn ip_protocol_name(protocol: IpProtocol) -> String {
    match i32::from(protocol) {
        1 => "icmp".into(),
        6 => "tcp".into(),
        17 => "udp".into(),
        58 => "icmpv6".into(),
        132 => "sctp".into(),
        other => other.to_string(),
    }
}

fn rule_selector(message: &RuleMessage, is_source: bool) -> Option<IpNet> {
    let (address, length) = if is_source {
        (
            message.attributes.iter().find_map(|attr| match attr {
                RuleAttribute::Source(address) => Some(*address),
                _ => None,
            }),
            message.header.src_len,
        )
    } else {
        (
            message.attributes.iter().find_map(|attr| match attr {
                RuleAttribute::Destination(address) => Some(*address),
                _ => None,
            }),
            message.header.dst_len,
        )
    };
    let address = match address {
        Some(address) => address,
        // `ip rule` omits the selector entirely when the prefix length is
        // zero — a "from all" rule reports no FRA_SRC.
        None if length == 0 => return None,
        None => match message.header.family {
            AddressFamily::Inet => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            _ => return None,
        },
    };
    IpNet::new(address, length).ok().map(|net| net.trunc())
}

/// A `RouteMessage` rendered for the net.tables view. Routes without a
/// resolvable family are skipped.
fn system_route(message: &RouteMessage, names: &HashMap<u32, String>) -> Option<SystemRoute> {
    let family = match message.header.address_family {
        AddressFamily::Inet => IpFamily::Ipv4,
        AddressFamily::Inet6 => IpFamily::Ipv6,
        _ => return None,
    };
    let address = |addr: &RouteAddress| -> Option<IpAddr> {
        match addr {
            RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
            RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
            _ => None,
        }
    };
    let find_address = |wanted: fn(&RouteAttribute) -> Option<&RouteAddress>| {
        message
            .attributes
            .iter()
            .find_map(|attr| wanted(attr).and_then(address))
    };
    let destination = find_address(|attr| match attr {
        RouteAttribute::Destination(address) => Some(address),
        _ => None,
    })
    .or_else(|| {
        if message.header.destination_prefix_length != 0 {
            return None;
        }
        match message.header.address_family {
            AddressFamily::Inet => Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            AddressFamily::Inet6 => Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
            _ => None,
        }
    })
    .and_then(|addr| IpNet::new(addr, message.header.destination_prefix_length).ok())
    .map(|net| net.trunc())?;
    let interface_index = message.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Oif(index) => Some(*index),
        _ => None,
    });
    let protocol = u8::from(message.header.protocol);
    let nexthops = message
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::MultiPath(hops) => Some(hops),
            _ => None,
        })
        .map(|hops| {
            hops.iter()
                .map(|hop| {
                    let gateway = hop.attributes.iter().find_map(|attr| match attr {
                        RouteAttribute::Gateway(gw) => address(gw),
                        _ => None,
                    });
                    SystemNexthop {
                        gateway,
                        interface_index: hop.interface_index,
                        interface_name: names.get(&hop.interface_index).cloned(),
                        weight: hop.hops,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Some(SystemRoute {
        family,
        destination,
        table: route_table(message),
        kind: route_kind_name(message.header.kind),
        scope: route_scope_name(message.header.scope),
        protocol,
        managed: protocol == RTPROT_NETWORK_ORCHESTRATOR,
        gateway: find_address(|attr| match attr {
            RouteAttribute::Gateway(address) => Some(address),
            _ => None,
        }),
        interface_index,
        interface_name: interface_index.and_then(|index| names.get(&index).cloned()),
        metric: message.attributes.iter().find_map(|attr| match attr {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        }),
        pref_source: find_address(|attr| match attr {
            RouteAttribute::PrefSource(address) => Some(address),
            _ => None,
        }),
        nexthops,
    })
}

/// A `RuleMessage` rendered for the net.tables view — every selector the
/// kernel reports, not only the fields the daemon mutates itself.
fn system_rule(message: &RuleMessage) -> SystemRule {
    let protocol = message
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RuleAttribute::Protocol(value) => Some(u8::from(*value)),
            _ => None,
        })
        .unwrap_or(0);
    let find =
        |wanted: fn(&RuleAttribute) -> Option<u32>| message.attributes.iter().find_map(wanted);
    SystemRule {
        family: if message.header.family == AddressFamily::Inet6 {
            IpFamily::Ipv6
        } else {
            IpFamily::Ipv4
        },
        priority: rule_priority(message).unwrap_or(0),
        action: rule_action_name(message.header.action),
        table: rule_table(message),
        goto: find(|attr| match attr {
            RuleAttribute::Goto(value) => Some(*value),
            _ => None,
        }),
        from: rule_selector(message, true),
        to: rule_selector(message, false),
        fwmark: find(|attr| match attr {
            RuleAttribute::FwMark(value) => Some(*value),
            _ => None,
        }),
        fwmask: find(|attr| match attr {
            RuleAttribute::FwMask(value) => Some(*value),
            _ => None,
        }),
        iifname: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::Iifname(name) => Some(name.clone()),
            _ => None,
        }),
        oifname: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::Oifname(name) => Some(name.clone()),
            _ => None,
        }),
        uid_range: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::UidRange(range) => Some([range.start, range.end]),
            _ => None,
        }),
        source_port_range: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::SourcePortRange(range) => Some([range.start, range.end]),
            _ => None,
        }),
        destination_port_range: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::DestinationPortRange(range) => Some([range.start, range.end]),
            _ => None,
        }),
        ip_protocol: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::IpProtocol(protocol) => Some(ip_protocol_name(*protocol)),
            _ => None,
        }),
        suppress_prefix_length: find(|attr| match attr {
            RuleAttribute::SuppressPrefixLen(value) if *value != u32::MAX => Some(*value),
            _ => None,
        }),
        suppress_if_group: find(|attr| match attr {
            RuleAttribute::SuppressIfGroup(value) if *value != u32::MAX => Some(*value),
            _ => None,
        }),
        tun_id: find(|attr| match attr {
            RuleAttribute::TunId(value) => Some(*value),
            _ => None,
        }),
        tos: message.header.tos,
        invert: message.header.flags.contains(&RuleFlag::Invert),
        protocol,
        managed: protocol == RTPROT_NETWORK_ORCHESTRATOR,
    }
}

fn route_kind_value(name: &str) -> RouteType {
    match name {
        "unicast" => RouteType::Unicast,
        "local" => RouteType::Local,
        "broadcast" => RouteType::Broadcast,
        "anycast" => RouteType::Anycast,
        "multicast" => RouteType::Multicast,
        "blackhole" => RouteType::BlackHole,
        "unreachable" => RouteType::Unreachable,
        "prohibit" => RouteType::Prohibit,
        "throw" => RouteType::Throw,
        "nat" => RouteType::Nat,
        "xresolve" => RouteType::ExternalResolve,
        other => other
            .strip_prefix("type ")
            .and_then(|code| code.parse::<u8>().ok())
            .map(RouteType::Other)
            .unwrap_or(RouteType::Unspec),
    }
}

fn route_scope_value(name: &str) -> RouteScope {
    match name {
        "universe" => RouteScope::Universe,
        "site" => RouteScope::Site,
        "link" => RouteScope::Link,
        "host" => RouteScope::Host,
        "nowhere" => RouteScope::NoWhere,
        other => other
            .strip_prefix("scope ")
            .and_then(|code| code.parse::<u8>().ok())
            .map(RouteScope::Other)
            // `ip route del` matches on NoWhere — the wildcard scope.
            .unwrap_or(RouteScope::NoWhere),
    }
}

fn rule_action_value(name: &str) -> RuleAction {
    match name {
        "lookup" => RuleAction::ToTable,
        "goto" => RuleAction::Goto,
        "nop" => RuleAction::Nop,
        "blackhole" => RuleAction::Blackhole,
        "unreachable" => RuleAction::Unreachable,
        "prohibit" => RuleAction::Prohibit,
        "unspec" => RuleAction::Unspec,
        other => other
            .strip_prefix("type ")
            .and_then(|code| code.parse::<u8>().ok())
            .map(RuleAction::Other)
            .unwrap_or(RuleAction::Unspec),
    }
}

fn ip_protocol_value(name: &str) -> Option<IpProtocol> {
    let code = match name {
        "icmp" => 1,
        "tcp" => 6,
        "udp" => 17,
        "icmpv6" => 58,
        "sctp" => 132,
        other => other.parse::<i32>().ok()?,
    };
    Some(IpProtocol::from(code))
}

fn route_address(ip: IpAddr) -> RouteAddress {
    match ip {
        IpAddr::V4(address) => RouteAddress::Inet(address),
        IpAddr::V6(address) => RouteAddress::Inet6(address),
    }
}

/// Rebuild the `RTM_*ROUTE` body from a dumped [`SystemRoute`]. Used for
/// `net.route.del` (delete exactly what was reported) and for restoring a
/// suppressed foreign route with its original protocol and attributes.
fn system_route_message(route: &SystemRoute) -> RouteMessage {
    let mut message = RouteMessage::default();
    let header = &mut message.header;
    header.address_family = match route.family {
        IpFamily::Ipv4 => AddressFamily::Inet,
        IpFamily::Ipv6 => AddressFamily::Inet6,
    };
    header.kind = route_kind_value(&route.kind);
    header.scope = route_scope_value(&route.scope);
    header.protocol = RouteProtocol::from(route.protocol);
    header.destination_prefix_length = route.destination.prefix_len();
    if route.table <= u8::MAX as u32 {
        header.table = route.table as u8;
    } else {
        header.table = RouteHeader::RT_TABLE_UNSPEC;
        message.attributes.push(RouteAttribute::Table(route.table));
    }
    if route.destination.prefix_len() != 0 {
        message
            .attributes
            .push(RouteAttribute::Destination(route_address(
                route.destination.addr(),
            )));
    }
    if let Some(index) = route.interface_index {
        message.attributes.push(RouteAttribute::Oif(index));
    }
    if let Some(metric) = route.metric {
        message.attributes.push(RouteAttribute::Priority(metric));
    }
    if let Some(gateway) = route.gateway {
        message
            .attributes
            .push(RouteAttribute::Gateway(route_address(gateway)));
    }
    if let Some(source) = route.pref_source {
        message
            .attributes
            .push(RouteAttribute::PrefSource(route_address(source)));
    }
    if !route.nexthops.is_empty() {
        let hops = route
            .nexthops
            .iter()
            .map(|hop| {
                let mut next = RouteNextHop::default();
                next.interface_index = hop.interface_index;
                next.hops = hop.weight;
                if let Some(gateway) = hop.gateway {
                    next.attributes
                        .push(RouteAttribute::Gateway(route_address(gateway)));
                }
                next
            })
            .collect();
        message.attributes.push(RouteAttribute::MultiPath(hops));
    }
    message
}

/// Rebuild the `RTM_*RULE` body from a dumped [`SystemRule`] — the exact
/// inverse of [`system_rule`], including kernel sentinel defaults for
/// suppressors. Used by `net.rule.del` and by suppression restore.
fn system_rule_message(rule: &SystemRule) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = rule_family(rule.family);
    message.header.action = rule_action_value(&rule.action);
    message.header.tos = rule.tos;
    if rule.invert {
        message.header.flags.push(RuleFlag::Invert);
    }
    message.header.src_len = rule.from.map(|net| net.prefix_len()).unwrap_or(0);
    message.header.dst_len = rule.to.map(|net| net.prefix_len()).unwrap_or(0);
    if rule.table <= u8::MAX as u32 {
        message.header.table = rule.table as u8;
    } else {
        message.attributes.push(RuleAttribute::Table(rule.table));
    }
    if rule.priority != 0 {
        message
            .attributes
            .push(RuleAttribute::Priority(rule.priority));
    }
    if let Some(net) = rule.from {
        message.attributes.push(RuleAttribute::Source(net.addr()));
    }
    if let Some(net) = rule.to {
        message
            .attributes
            .push(RuleAttribute::Destination(net.addr()));
    }
    if let Some(mark) = rule.fwmark {
        message.attributes.push(RuleAttribute::FwMark(mark));
    }
    if let Some(mask) = rule.fwmask {
        message.attributes.push(RuleAttribute::FwMask(mask));
    }
    if let Some(name) = &rule.iifname {
        message
            .attributes
            .push(RuleAttribute::Iifname(name.clone()));
    }
    if let Some(name) = &rule.oifname {
        message
            .attributes
            .push(RuleAttribute::Oifname(name.clone()));
    }
    if let Some([start, end]) = rule.uid_range {
        message
            .attributes
            .push(RuleAttribute::UidRange(RuleUidRange { start, end }));
    }
    if let Some([start, end]) = rule.source_port_range {
        message
            .attributes
            .push(RuleAttribute::SourcePortRange(RulePortRange { start, end }));
    }
    if let Some([start, end]) = rule.destination_port_range {
        message
            .attributes
            .push(RuleAttribute::DestinationPortRange(RulePortRange {
                start,
                end,
            }));
    }
    if let Some(protocol) = rule.ip_protocol.as_deref().and_then(ip_protocol_value) {
        message.attributes.push(RuleAttribute::IpProtocol(protocol));
    }
    message.attributes.push(RuleAttribute::SuppressPrefixLen(
        rule.suppress_prefix_length.unwrap_or(u32::MAX),
    ));
    message.attributes.push(RuleAttribute::SuppressIfGroup(
        rule.suppress_if_group.unwrap_or(u32::MAX),
    ));
    if let Some(tun_id) = rule.tun_id {
        message.attributes.push(RuleAttribute::TunId(tun_id));
    }
    if let Some(target) = rule.goto {
        message.attributes.push(RuleAttribute::Goto(target));
    }
    if rule.protocol != 0 {
        message
            .attributes
            .push(RuleAttribute::Protocol(RouteProtocol::from(rule.protocol)));
    }
    message
}

fn is_owned_rule(message: &RuleMessage, rule: &OwnedRuleResource) -> bool {
    let expected = rule_request(rule);
    if message.header.family != expected.header.family
        || message.header.src_len != 0
        || message.header.dst_len != 0
        || message.header.tos != 0
        || message.header.action != RuleAction::ToTable
        || message.header.flags != expected.header.flags
        || rule_table(message) != rule.table
        || (message.header.table != expected.header.table
            && !(rule.table <= u8::MAX as u32 && message.header.table == 0)
            && !(rule.table > u8::MAX as u32 && message.header.table == 252))
    {
        return false;
    }
    // The kernel may echo FRA_TABLE even for a one-byte table. Compare the
    // complete attribute set, allowing only that equivalent encoding.
    let mut attributes = message.attributes.clone();
    // The kernel echoes an unset suppress length as UINT_MAX.
    if rule.suppress_prefix_length.is_none() {
        attributes.retain(
            |attr| !matches!(attr, RuleAttribute::SuppressPrefixLen(value) if *value == u32::MAX),
        );
    }
    // `FRA_FWMASK` is optional; without it the kernel uses all bits.
    if rule.fwmark.is_some()
        && !attributes
            .iter()
            .any(|attr| matches!(attr, RuleAttribute::FwMask(_)))
    {
        attributes.push(RuleAttribute::FwMask(u32::MAX));
    }
    if rule.table <= u8::MAX as u32 {
        if let Some(pos) = attributes
            .iter()
            .position(|attr| matches!(attr, RuleAttribute::Table(value) if *value == rule.table))
        {
            attributes.remove(pos);
        }
    }
    attributes.len() == expected.attributes.len()
        && expected.attributes.iter().all(|attr| {
            if let Some(pos) = attributes.iter().position(|candidate| candidate == attr) {
                attributes.remove(pos);
                true
            } else {
                false
            }
        })
}

/// `RTM_SETLINK` body toggling only `IFF_UP`.
pub fn link_request(index: u32, up: bool) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.header.index = index;
    if up {
        message.header.flags.push(LinkFlag::Up);
    }
    message.header.change_mask.push(LinkFlag::Up);
    message
}

fn wireguard_create_request(name: &str, owner_marker: &str) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.attributes.push(LinkAttribute::IfName(name.into()));
    message
        .attributes
        .push(LinkAttribute::IfAlias(owner_marker.into()));
    message
        .attributes
        .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Wireguard,
        )]));
    message
}

fn is_owned_wireguard_link(
    message: &LinkMessage,
    name: &str,
    index: u32,
    owner_marker: &str,
) -> bool {
    is_wireguard_link(message, name, index)
        && message
            .attributes
            .contains(&LinkAttribute::IfAlias(owner_marker.into()))
}

fn is_wireguard_link(message: &LinkMessage, name: &str, index: u32) -> bool {
    (index == 0 || message.header.index == index)
        && message
            .attributes
            .contains(&LinkAttribute::IfName(name.into()))
        && message.attributes.iter().any(|attribute| {
            matches!(attribute, LinkAttribute::LinkInfo(info) if info.contains(&LinkInfo::Kind(InfoKind::Wireguard)))
        })
}

fn address_delete_request(index: u32, address: IpNet) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.index = index;
    message.header.prefix_len = address.prefix_len();
    let ip = address.addr();
    message.header.family = match ip {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    message.attributes.push(AddressAttribute::Address(ip));
    message.attributes.push(AddressAttribute::Local(ip));
    message
}

pub fn classify_errno(errno: i32) -> io::ErrorKind {
    match errno {
        libc::EEXIST => io::ErrorKind::AlreadyExists,
        libc::ESRCH | libc::ENOENT | libc::ENODEV => io::ErrorKind::NotFound,
        libc::EPERM | libc::EACCES => io::ErrorKind::PermissionDenied,
        libc::EINVAL | libc::ENETUNREACH | libc::EHOSTUNREACH => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    }
}

/// RTM_DELADDR reports an address that is already gone as EADDRNOTAVAIL.
pub fn classify_address_delete_errno(errno: i32) -> io::ErrorKind {
    if errno == libc::EADDRNOTAVAIL {
        io::ErrorKind::NotFound
    } else {
        classify_errno(errno)
    }
}

pub fn netlink_error_to_io(err: rtnetlink::Error) -> io::Error {
    netlink_error_with(err, classify_errno)
}

fn netlink_error_with(err: rtnetlink::Error, classify: fn(i32) -> io::ErrorKind) -> io::Error {
    match err {
        rtnetlink::Error::NetlinkError(message) => {
            let errno = message.raw_code().abs();
            io::Error::new(classify(errno), message.to_io().to_string())
        }
        other => io::Error::other(other.to_string()),
    }
}

enum Command {
    Route {
        op: RouteOp,
        route: AppliedRoute,
        reply: mpsc::Sender<io::Result<()>>,
    },
    OwnedRoutesSnapshot {
        reply: mpsc::Sender<io::Result<Vec<AppliedRoute>>>,
    },
    /// Routes across every table plus all policy rules, for the
    /// `ip route`/`ip rule` inventory view.
    NetTablesDump {
        reply: mpsc::Sender<io::Result<NetTablesResult>>,
    },
    /// Add or delete a route by full kernel spec (manual edits and
    /// suppressed-foreign restore).
    SystemRoute {
        op: RouteOp,
        route: SystemRoute,
        reply: mpsc::Sender<io::Result<()>>,
    },
    /// Add or delete a policy rule by full kernel spec.
    SystemRule {
        add: bool,
        rule: SystemRule,
        reply: mpsc::Sender<io::Result<()>>,
    },
    /// `RTM_GETROUTE` lookup for one destination — the egress the policy
    /// rules pick right now (used by the DNS probe to show the exit path).
    RouteLookup {
        to: IpAddr,
        reply: mpsc::Sender<io::Result<RouteLookup>>,
    },
    DefaultGateways {
        reply: mpsc::Sender<io::Result<Vec<(IpAddr, u32)>>>,
    },
    OnLinkNetworks {
        reply: mpsc::Sender<io::Result<Vec<(u32, IpNet)>>>,
    },
    RulesSnapshot {
        reply: mpsc::Sender<io::Result<Vec<OwnedRuleResource>>>,
    },
    Rule {
        rule: OwnedRuleResource,
        add: bool,
        reply: mpsc::Sender<io::Result<()>>,
    },
    TableInUse {
        table: u32,
        reply: mpsc::Sender<io::Result<bool>>,
    },
    RulePresent {
        rule: OwnedRuleResource,
        reply: mpsc::Sender<io::Result<bool>>,
    },
    Link {
        index: u32,
        up: bool,
        reply: mpsc::Sender<io::Result<()>>,
    },
    /// Delete a netdev the daemon does not journal (foreign tunnels).
    LinkDel {
        index: u32,
        reply: mpsc::Sender<io::Result<()>>,
    },
    InterfaceAddrs {
        reply: mpsc::Sender<io::Result<Vec<IfaceAddr>>>,
    },
    WgCreate {
        name: String,
        owner_marker: String,
        reply: mpsc::Sender<io::Result<u32>>,
    },
    WgDelete {
        name: String,
        index: u32,
        owner_marker: String,
        reply: mpsc::Sender<io::Result<()>>,
    },
    WgOwned {
        name: String,
        index: u32,
        owner_marker: String,
        reply: mpsc::Sender<io::Result<bool>>,
    },
    WgPresent {
        name: String,
        index: u32,
        reply: mpsc::Sender<io::Result<bool>>,
    },
    WgAddress {
        index: u32,
        address: IpNet,
        add: bool,
        reply: mpsc::Sender<io::Result<()>>,
    },
    WgMtu {
        index: u32,
        mtu: u32,
        reply: mpsc::Sender<io::Result<()>>,
    },
}

impl Command {
    fn operation(&self) -> &'static str {
        match self {
            Self::Route { .. } => "route",
            Self::OwnedRoutesSnapshot { .. } => "owned_routes_snapshot",
            Self::NetTablesDump { .. } => "net_tables_dump",
            Self::SystemRoute { .. } => "system_route",
            Self::SystemRule { .. } => "system_rule",
            Self::RouteLookup { .. } => "route_lookup",
            Self::DefaultGateways { .. } => "default_gateways",
            Self::OnLinkNetworks { .. } => "on_link_networks",
            Self::RulesSnapshot { .. } => "rules_snapshot",
            Self::Rule { .. } => "rule",
            Self::TableInUse { .. } => "table_in_use",
            Self::RulePresent { .. } => "rule_present",
            Self::Link { .. } => "link_set",
            Self::LinkDel { .. } => "link_delete",
            Self::InterfaceAddrs { .. } => "interface_addrs",
            Self::WgCreate { .. } => "wireguard_create",
            Self::WgDelete { .. } => "wireguard_delete",
            Self::WgOwned { .. } => "wireguard_owned",
            Self::WgPresent { .. } => "wireguard_present",
            Self::WgAddress { .. } => "wireguard_address",
            Self::WgMtu { .. } => "wireguard_mtu",
        }
    }
}

struct QueuedCommand {
    command: Command,
    id: u64,
    queued: Instant,
}

impl QueuedCommand {
    fn new(command: Command) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        crate::diagnostic_logging::trace(format_args!(
            "netlink enqueue id={id} operation={}",
            command.operation()
        ));
        Self {
            command,
            id,
            queued: Instant::now(),
        }
    }
}

/// Handle to the netlink actor thread. Cloneable; every call blocks the
/// calling (non-async) thread until the kernel answers or times out.
#[derive(Clone)]
pub struct NetlinkExecutor {
    tx: async_mpsc::UnboundedSender<QueuedCommand>,
    reply_timeout: Duration,
}

impl NetlinkExecutor {
    /// Start the actor and open the rtnetlink socket. Needs no privileges
    /// to open; mutations need `CAP_NET_ADMIN`.
    pub fn spawn() -> io::Result<Self> {
        let (tx, rx) = async_mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();
        std::thread::Builder::new()
            .name("netlink-actor".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = ready_tx.send(Err(err));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let (connection, handle, _) = match rtnetlink::new_connection() {
                        Ok(parts) => parts,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                            return;
                        }
                    };
                    tokio::spawn(connection);
                    let _ = ready_tx.send(Ok(()));
                    run_actor(handle, rx).await;
                });
            })?;
        ready_rx.recv().map_err(|_| actor_gone())??;
        Ok(Self {
            tx,
            reply_timeout: ACTOR_REPLY_TIMEOUT,
        })
    }

    fn call(
        &self,
        command: impl FnOnce(mpsc::Sender<io::Result<()>>) -> Command,
    ) -> io::Result<()> {
        let (reply_tx, reply_rx) = mpsc::channel();
        let command = command(reply_tx);
        let operation = command.operation();
        let queued = QueuedCommand::new(command);
        let id = queued.id;
        self.tx.send(queued).map_err(|_| {
            eprintln!(
                "network-orchestrator-daemon: netlink actor unavailable operation={operation}"
            );
            actor_gone()
        })?;
        // An unbounded recv here wedges every caller forever once the actor
        // stalls (e.g. a dead rtnetlink connection task); fail instead.
        reply_rx
            .recv_timeout(self.reply_timeout)
            .map_err(|err| {
                eprintln!("network-orchestrator-daemon: netlink reply failed operation={operation} reason={err:?}");
                if matches!(err, mpsc::RecvTimeoutError::Timeout) {
                    crate::diagnostic_logging::snapshot_process(std::process::id(), "netlink_reply_timeout");
                }
                actor_gone()
            })?
            .inspect_err(|err| {
                eprintln!("network-orchestrator-daemon: netlink operation failed operation={operation} kind={:?} os_code={:?}", err.kind(), err.raw_os_error());
            })
            .inspect(|_| crate::diagnostic_logging::trace(format_args!("netlink reply id={id} operation={operation}")))
    }

    fn call_with<T>(
        &self,
        command: impl FnOnce(mpsc::Sender<io::Result<T>>) -> Command,
    ) -> io::Result<T> {
        let (reply_tx, reply_rx) = mpsc::channel();
        let command = command(reply_tx);
        let operation = command.operation();
        let queued = QueuedCommand::new(command);
        let id = queued.id;
        self.tx.send(queued).map_err(|_| {
            eprintln!(
                "network-orchestrator-daemon: netlink actor unavailable operation={operation}"
            );
            actor_gone()
        })?;
        reply_rx
            .recv_timeout(self.reply_timeout)
            .map_err(|err| {
                eprintln!("network-orchestrator-daemon: netlink reply failed operation={operation} reason={err:?}");
                if matches!(err, mpsc::RecvTimeoutError::Timeout) {
                    crate::diagnostic_logging::snapshot_process(std::process::id(), "netlink_reply_timeout");
                }
                actor_gone()
            })?
            .inspect_err(|err| {
                eprintln!("network-orchestrator-daemon: netlink operation failed operation={operation} kind={:?} os_code={:?}", err.kind(), err.raw_os_error());
            })
            .inspect(|_| crate::diagnostic_logging::trace(format_args!("netlink reply id={id} operation={operation}")))
    }

    pub fn owned_routes_snapshot(&self) -> io::Result<Vec<AppliedRoute>> {
        self.call_with(|reply| Command::OwnedRoutesSnapshot { reply })
    }

    /// Every interface address with its link name, for conditional rules.
    pub fn interface_addrs(&self) -> io::Result<Vec<IfaceAddr>> {
        self.call_with(|reply| Command::InterfaceAddrs { reply })
    }
}

impl NetworkObservation for NetlinkExecutor {
    fn interface_addrs(&self) -> io::Result<Vec<IfaceAddr>> {
        NetlinkExecutor::interface_addrs(self)
    }

    fn owned_routes(&self) -> io::Result<Vec<AppliedRoute>> {
        self.owned_routes_snapshot()
    }

    fn route_lookup(&self, to: IpAddr) -> io::Result<RouteLookup> {
        RouteExecutor::route_lookup(self, to)
    }
}

/// Interface index → name map, for resolving `Oif`/`Iif` attributes.
async fn get_link_names(handle: &rtnetlink::Handle) -> io::Result<HashMap<u32, String>> {
    let mut names = HashMap::new();
    let mut links = handle.link().get().execute();
    while let Some(link) = links.try_next().await.map_err(netlink_error_to_io)? {
        for attribute in &link.attributes {
            if let LinkAttribute::IfName(name) = attribute {
                names.insert(link.header.index, name.clone());
            }
        }
    }
    Ok(names)
}

/// Dump links (index→name) and addresses (both families) in one pass.
/// `IFA_LOCAL` is preferred over `IFA_ADDRESS`: on point-to-point links the
/// latter is the peer's address, while the former is always ours.
async fn get_interface_addrs(handle: &rtnetlink::Handle) -> io::Result<Vec<IfaceAddr>> {
    let names = get_link_names(handle).await?;
    let mut addrs = Vec::new();
    let mut stream = handle.address().get().execute();
    while let Some(message) = stream.try_next().await.map_err(netlink_error_to_io)? {
        let mut local = None;
        let mut address = None;
        for attribute in &message.attributes {
            match attribute {
                AddressAttribute::Local(ip) => local = Some(*ip),
                AddressAttribute::Address(ip) => address = Some(*ip),
                _ => {}
            }
        }
        let Some(ip) = local.or(address) else {
            continue;
        };
        let Ok(prefix) = IpNet::new(ip, message.header.prefix_len) else {
            continue;
        };
        addrs.push(IfaceAddr {
            ifindex: message.header.index,
            name: names
                .get(&message.header.index)
                .cloned()
                .unwrap_or_default(),
            address: prefix,
            scope: u8::from(message.header.scope),
        });
    }
    Ok(addrs)
}

async fn get_link(
    handle: &rtnetlink::Handle,
    name: &str,
    index: u32,
) -> io::Result<Option<LinkMessage>> {
    let request = if index == 0 {
        handle.link().get().match_name(name.into())
    } else {
        handle.link().get().match_index(index)
    };
    match request
        .execute()
        .try_next()
        .await
        .map_err(netlink_error_to_io)
    {
        Ok(message) => Ok(message),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// `RTM_F_LOOKUP_TABLE` asks the kernel to resolve a destination through
/// the policy rules, like `ip route get`, instead of dumping one table.
const RTM_F_LOOKUP_TABLE: u16 = 0x1000;

/// `ip route get <to>`: which source address, output link and gateway the
/// policy routing picks right now.
async fn route_lookup(handle: &rtnetlink::Handle, to: IpAddr) -> io::Result<RouteLookup> {
    let mut message = RouteMessage::default();
    message.header.address_family = match to {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    message.header.destination_prefix_length = if to.is_ipv4() { 32 } else { 128 };
    message
        .attributes
        .push(RouteAttribute::Destination(route_address(to)));
    let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(message));
    request.header.flags = NLM_F_REQUEST | RTM_F_LOOKUP_TABLE;
    let mut stream = handle
        .clone()
        .request(request)
        .map_err(netlink_error_to_io)?;
    let reply = stream
        .next()
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no route"))?;
    let route = match reply.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => route,
        NetlinkPayload::Error(err) => {
            return Err(io::Error::new(
                classify_errno(err.raw_code().abs()),
                format!("route lookup failed: {}", err.to_io()),
            ));
        }
        _ => return Err(io::Error::other("unexpected route lookup reply")),
    };
    let names = get_link_names(handle).await?;
    let attr_addr = |wanted: fn(&RouteAttribute) -> Option<&RouteAddress>| {
        route
            .attributes
            .iter()
            .find_map(|attr| wanted(attr))
            .and_then(|address| match address {
                RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
                RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
                _ => None,
            })
    };
    let interface_index = route.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Oif(index) => Some(*index),
        _ => None,
    });
    Ok(RouteLookup {
        source: attr_addr(|attr| match attr {
            RouteAttribute::PrefSource(address) => Some(address),
            _ => None,
        }),
        interface_index,
        interface_name: interface_index.and_then(|index| names.get(&index).cloned()),
        gateway: attr_addr(|attr| match attr {
            RouteAttribute::Gateway(address) => Some(address),
            _ => None,
        }),
        table: route_table(&route),
    })
}

async fn get_rules(handle: &rtnetlink::Handle) -> io::Result<Vec<RuleMessage>> {
    let mut rules = Vec::new();
    for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
        let mut stream = handle.rule().get(version).execute();
        while let Some(message) = stream.try_next().await.map_err(netlink_error_to_io)? {
            rules.push(message);
        }
    }
    Ok(rules)
}

async fn run_actor(
    handle: rtnetlink::Handle,
    mut rx: async_mpsc::UnboundedReceiver<QueuedCommand>,
) {
    while let Some(QueuedCommand {
        command,
        id,
        queued,
    }) = rx.recv().await
    {
        let operation = command.operation();
        let started = Instant::now();
        crate::diagnostic_logging::trace(format_args!(
            "netlink start id={id} operation={operation} queue_ms={}",
            queued.elapsed().as_millis()
        ));
        // A netlink request whose reply never arrives (e.g. the connection
        // task died) would otherwise pin the actor and every queued caller
        // forever; abort the stuck command — dropping the arm's `reply`
        // makes the waiting caller fail fast instead of hanging.
        let executed = tokio::time::timeout(ACTOR_COMMAND_TIMEOUT, async {
            match command {
                Command::Route { op, route, reply } => {
                    let message = route_request(&route, op);
                    let result = match op {
                        RouteOp::Add => {
                            let mut request = handle.route().add();
                            *request.message_mut() = message;
                            request.execute().await
                        }
                        RouteOp::Delete => handle.route().del(message).execute().await,
                    };
                    let _ = reply.send(result.map_err(netlink_error_to_io));
                }
                Command::DefaultGateways { reply } => {
                    let result = async {
                        let mut gateways = Vec::new();
                        for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
                            let mut stream = handle.route().get(version).execute();
                            while let Some(message) =
                                stream.try_next().await.map_err(netlink_error_to_io)?
                            {
                                if let Some(gateway) = default_gateway(&message) {
                                    gateways.push(gateway);
                                }
                            }
                        }
                        Ok(gateways)
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::OnLinkNetworks { reply } => {
                    let result = async {
                        let mut networks = Vec::new();
                        for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
                            let mut stream = handle.route().get(version).execute();
                            while let Some(message) =
                                stream.try_next().await.map_err(netlink_error_to_io)?
                            {
                                if let Some(network) = on_link_network(&message) {
                                    networks.push(network);
                                }
                            }
                        }
                        Ok(networks)
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::OwnedRoutesSnapshot { reply } => {
                    let result = async {
                        let mut routes = Vec::new();
                        for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
                            let mut stream = handle.route().get(version).execute();
                            while let Some(message) =
                                stream.try_next().await.map_err(netlink_error_to_io)?
                            {
                                if let Some(route) = owned_route_snapshot(&message) {
                                    routes.push(route);
                                }
                            }
                        }
                        Ok(routes)
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::NetTablesDump { reply } => {
                    let result = async {
                        let names = get_link_names(&handle).await?;
                        let mut routes = Vec::new();
                        for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
                            let mut stream = handle.route().get(version).execute();
                            while let Some(message) =
                                stream.try_next().await.map_err(netlink_error_to_io)?
                            {
                                if let Some(route) = system_route(&message, &names) {
                                    routes.push(route);
                                }
                            }
                        }
                        let rules = get_rules(&handle).await?.iter().map(system_rule).collect();
                        Ok(NetTablesResult {
                            routes,
                            rules,
                            available: true,
                        })
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::SystemRoute { op, route, reply } => {
                    let message = system_route_message(&route);
                    let result = match op {
                        RouteOp::Add => {
                            let mut request = handle.route().add();
                            *request.message_mut() = message;
                            request.execute().await
                        }
                        RouteOp::Delete => handle.route().del(message).execute().await,
                    };
                    let _ = reply.send(result.map_err(netlink_error_to_io));
                }
                Command::SystemRule { add, rule, reply } => {
                    let message = system_rule_message(&rule);
                    let result = if add {
                        let mut request = handle.rule().add();
                        *request.message_mut() = message;
                        request.execute().await
                    } else {
                        handle.rule().del(message).execute().await
                    };
                    let _ = reply.send(result.map_err(netlink_error_to_io));
                }
                Command::RouteLookup { to, reply } => {
                    let _ = reply.send(route_lookup(&handle, to).await);
                }
                Command::RulesSnapshot { reply } => {
                    let result = async {
                        let messages = get_rules(&handle).await?;
                        Ok(messages.iter().map(rule_snapshot).collect())
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::Rule { rule, add, reply } => {
                    let result = async {
                        let existing = get_rules(&handle).await?;
                        if add {
                            if existing.iter().any(|message| {
                                message.header.family == rule_family(rule.family)
                                    && rule_priority(message) == Some(rule.priority)
                            }) {
                                return Err(io::Error::new(
                                    io::ErrorKind::AlreadyExists,
                                    "policy rule priority is occupied",
                                ));
                            }
                            let mut request = handle.rule().add();
                            *request.message_mut() = rule_request(&rule);
                            request.execute().await.map_err(netlink_error_to_io)
                        } else {
                            let suspicious = existing.iter().any(|message| {
                                message.header.family == rule_family(rule.family)
                                    && rule_priority(message) == Some(rule.priority)
                            });
                            let Some(_message) = existing
                                .iter()
                                .find(|message| is_owned_rule(message, &rule))
                            else {
                                return Err(io::Error::new(
                                    if suspicious {
                                        io::ErrorKind::Other
                                    } else {
                                        io::ErrorKind::NotFound
                                    },
                                    if suspicious {
                                        "policy rule identity is unverified"
                                    } else {
                                        "owned policy rule not found"
                                    },
                                ));
                            };
                            match handle
                                .rule()
                                .del(rule_request(&rule))
                                .execute()
                                .await
                                .map_err(netlink_error_to_io)
                            {
                                Ok(()) => {
                                    if get_rules(&handle)
                                        .await?
                                        .iter()
                                        .any(|message| is_owned_rule(message, &rule))
                                    {
                                        Err(io::Error::other("owned policy rule survived deletion"))
                                    } else {
                                        Ok(())
                                    }
                                }
                                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                                    Err(io::Error::other("owned policy rule could not be deleted"))
                                }
                                Err(err) => Err(err),
                            }
                        }
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::RulePresent { rule, reply } => {
                    let result = get_rules(&handle)
                        .await
                        .map(|rules| rules.iter().any(|message| is_owned_rule(message, &rule)));
                    let _ = reply.send(result);
                }
                Command::TableInUse { table, reply } => {
                    let result = async {
                        if get_rules(&handle)
                            .await?
                            .iter()
                            .any(|rule| rule_table(rule) == table)
                        {
                            return Ok(true);
                        }
                        for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
                            let mut routes = handle.route().get(version).execute();
                            while let Some(route) =
                                routes.try_next().await.map_err(netlink_error_to_io)?
                            {
                                if route_table(&route) == table {
                                    return Ok(true);
                                }
                            }
                        }
                        Ok(false)
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::Link { index, up, reply } => {
                    let mut request = handle.link().set(index);
                    *request.message_mut() = link_request(index, up);
                    let _ = reply.send(request.execute().await.map_err(netlink_error_to_io));
                }
                Command::LinkDel { index, reply } => {
                    let _ = reply.send(
                        handle
                            .link()
                            .del(index)
                            .execute()
                            .await
                            .map_err(netlink_error_to_io),
                    );
                }
                Command::InterfaceAddrs { reply } => {
                    let _ = reply.send(get_interface_addrs(&handle).await);
                }
                Command::WgCreate {
                    name,
                    owner_marker,
                    reply,
                } => {
                    let mut request = handle.link().add();
                    *request.message_mut() = wireguard_create_request(&name, &owner_marker);
                    let result = async {
                        request.execute().await.map_err(netlink_error_to_io)?;
                        let link = get_link(&handle, &name, 0).await?.ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "created interface not found")
                        })?;
                        if !is_wireguard_link(&link, &name, 0) {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "created interface identity changed",
                            ));
                        }
                        let index = link.header.index;
                        let mut set = handle.link().set(index);
                        set.message_mut()
                            .attributes
                            .push(LinkAttribute::IfAlias(owner_marker.clone()));
                        let result = set.execute().await.map_err(netlink_error_to_io);
                        if result.is_err() {
                            let _ = delete_fresh_link(&handle, &name, index).await;
                            return result.map(|()| index);
                        }
                        let verified = get_link(&handle, &name, index).await?;
                        if !verified.is_some_and(|link| {
                            is_owned_wireguard_link(&link, &name, index, &owner_marker)
                        }) {
                            let _ = delete_fresh_link(&handle, &name, index).await;
                            return Err(io::Error::other(
                                "created interface owner marker is missing",
                            ));
                        }
                        Ok(index)
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::WgDelete {
                    name,
                    index,
                    owner_marker,
                    reply,
                } => {
                    let result = async {
                        let Some(link) = get_link(&handle, &name, index).await? else {
                            return Ok(());
                        };
                        if !is_owned_wireguard_link(&link, &name, index, &owner_marker) {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "interface identity does not match owner",
                            ));
                        }
                        handle
                            .link()
                            .del(link.header.index)
                            .execute()
                            .await
                            .map_err(netlink_error_to_io)
                    }
                    .await;
                    let _ = reply.send(result);
                }
                Command::WgOwned {
                    name,
                    index,
                    owner_marker,
                    reply,
                } => {
                    let result = get_link(&handle, &name, index).await.map(|link| {
                        link.is_some_and(|link| {
                            is_owned_wireguard_link(&link, &name, index, &owner_marker)
                        })
                    });
                    let _ = reply.send(result);
                }
                Command::WgPresent { name, index, reply } => {
                    let result = get_link(&handle, &name, index).await.map(|link| {
                        link.is_some_and(|link| is_wireguard_link(&link, &name, index))
                    });
                    let _ = reply.send(result);
                }
                Command::WgAddress {
                    index,
                    address,
                    add,
                    reply,
                } => {
                    let result = if add {
                        handle
                            .address()
                            .add(index, address.addr(), address.prefix_len())
                            .execute()
                            .await
                            .map_err(netlink_error_to_io)
                    } else {
                        handle
                            .address()
                            .del(address_delete_request(index, address))
                            .execute()
                            .await
                            .map_err(|err| netlink_error_with(err, classify_address_delete_errno))
                    };
                    let _ = reply.send(result);
                }
                Command::WgMtu { index, mtu, reply } => {
                    let _ = reply.send(
                        handle
                            .link()
                            .set(index)
                            .mtu(mtu)
                            .execute()
                            .await
                            .map_err(netlink_error_to_io),
                    );
                }
            }
        })
        .await;
        crate::diagnostic_logging::trace(format_args!(
            "netlink finish id={id} operation={operation} duration_ms={} timeout={}",
            started.elapsed().as_millis(),
            executed.is_err()
        ));
        if executed.is_err() {
            crate::diagnostic_logging::snapshot_process(
                std::process::id(),
                "netlink_command_timeout",
            );
            eprintln!(
                "network-orchestrator-daemon: netlink command timed out operation={operation}"
            );
        }
    }
}

async fn delete_fresh_link(handle: &rtnetlink::Handle, name: &str, index: u32) -> io::Result<()> {
    let link = get_link(handle, name, index).await?;
    if link.is_some_and(|link| is_wireguard_link(&link, name, index)) {
        handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(netlink_error_to_io)
    } else {
        Ok(())
    }
}

/// Legacy multicast mask for link, address, route and policy-rule changes.
/// rtnetlink has no constant for `RTNLGRP_IPV6_RULE` (group 19).
const NETWORK_CHANGE_GROUPS: u32 = {
    use rtnetlink::constants::*;
    const RTMGRP_IPV6_RULE: u32 = 1 << (19 - 1);
    RTMGRP_LINK
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV6_IFADDR
        | RTMGRP_IPV4_ROUTE
        | RTMGRP_IPV6_ROUTE
        | RTMGRP_IPV4_RULE
        | RTMGRP_IPV6_RULE
};

/// Call `on_change` for every link, route or policy-rule notification until
/// the returned task is aborted. Messages are only a wake-up signal; the
/// reconcile pass reads the kernel state itself.
pub fn watch_network_changes(
    on_change: impl Fn() + Send + 'static,
) -> io::Result<tokio::task::JoinHandle<()>> {
    use futures::StreamExt;
    use netlink_sys::{AsyncSocket, SocketAddr};
    let (mut connection, _handle, mut messages) = rtnetlink::new_connection()?;
    connection
        .socket_mut()
        .socket_mut()
        .bind(&SocketAddr::new(0, NETWORK_CHANGE_GROUPS))?;
    Ok(tokio::spawn(async move {
        let connection = tokio::spawn(connection);
        while messages.next().await.is_some() {
            on_change();
        }
        connection.abort();
    }))
}

/// Upper bound for a single netlink round-trip; generous for kernel dumps,
/// short enough that a stalled actor fails callers instead of wedging them.
const ACTOR_REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// Upper bound per actor command; below `ACTOR_REPLY_TIMEOUT` so the actor
/// drops a stuck request before callers report it, keeping later commands
/// serviced.
const ACTOR_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

fn actor_gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "netlink actor is not running")
}

impl RouteExecutor for NetlinkExecutor {
    fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        let route = route.clone();
        self.call(|reply| Command::Route {
            op: RouteOp::Add,
            route,
            reply,
        })
    }

    fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        let route = route.clone();
        self.call(|reply| Command::Route {
            op: RouteOp::Delete,
            route,
            reply,
        })
    }

    fn default_gateways(&self) -> io::Result<Vec<(IpAddr, u32)>> {
        self.call_with(|reply| Command::DefaultGateways { reply })
    }

    fn on_link_networks(&self) -> io::Result<Vec<(u32, IpNet)>> {
        self.call_with(|reply| Command::OnLinkNetworks { reply })
    }

    fn net_tables(&self) -> io::Result<NetTablesResult> {
        self.call_with(|reply| Command::NetTablesDump { reply })
    }

    fn add_system_route(&mut self, route: &SystemRoute) -> io::Result<()> {
        let route = route.clone();
        self.call(|reply| Command::SystemRoute {
            op: RouteOp::Add,
            route,
            reply,
        })
    }

    fn remove_system_route(&mut self, route: &SystemRoute) -> io::Result<()> {
        let route = route.clone();
        self.call(|reply| Command::SystemRoute {
            op: RouteOp::Delete,
            route,
            reply,
        })
    }

    fn route_lookup(&self, to: IpAddr) -> io::Result<RouteLookup> {
        self.call_with(|reply| Command::RouteLookup { to, reply })
    }
}

impl PolicyRuleExecutor for NetlinkExecutor {
    fn rules_snapshot(&mut self) -> io::Result<Vec<OwnedRuleResource>> {
        self.call_with(|reply| Command::RulesSnapshot { reply })
    }

    fn add_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
        self.call(|reply| Command::Rule {
            rule: rule.clone(),
            add: true,
            reply,
        })
    }

    fn remove_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
        self.call(|reply| Command::Rule {
            rule: rule.clone(),
            add: false,
            reply,
        })
    }

    fn table_in_use(&mut self, table: u32) -> io::Result<bool> {
        self.call_with(|reply| Command::TableInUse { table, reply })
    }

    fn rule_present(&mut self, rule: &OwnedRuleResource) -> io::Result<bool> {
        let rule = rule.clone();
        self.call_with(|reply| Command::RulePresent { rule, reply })
    }

    fn add_system_rule(&mut self, rule: &SystemRule) -> io::Result<()> {
        let rule = rule.clone();
        self.call(|reply| Command::SystemRule {
            add: true,
            rule,
            reply,
        })
    }

    fn remove_system_rule(&mut self, rule: &SystemRule) -> io::Result<()> {
        let rule = rule.clone();
        self.call(|reply| Command::SystemRule {
            add: false,
            rule,
            reply,
        })
    }
}

impl LinkExecutor for NetlinkExecutor {
    /// `name` is validated by `DaemonCore` before it gets here.
    fn set_link_state(&mut self, name: &str, up: bool) -> io::Result<()> {
        let c_name = CString::new(name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;
        // SAFETY: `c_name` is a valid NUL-terminated string for the call.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            ));
        }
        self.call(|reply| Command::Link { index, up, reply })
    }

    /// Foreign tunnels carry no owner marker; the caller checked the link is
    /// not journaled before this call. `name` is validated by `DaemonCore`.
    fn remove_link(&mut self, name: &str) -> io::Result<()> {
        let c_name = CString::new(name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;
        // SAFETY: `c_name` is a valid NUL-terminated string for the call.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            ));
        }
        self.call(|reply| Command::LinkDel { index, reply })
    }

    /// Classify a netdev via sysfs: `DEVTYPE=wireguard` in the device uevent,
    /// else a `tun_flags` entry marks a TUN/TAP device. Read-only probe.
    fn link_kind(&mut self, name: &str) -> io::Result<ExternalLinkKind> {
        let base = format!("/sys/class/net/{name}");
        if !std::path::Path::new(&base).exists() {
            return Ok(ExternalLinkKind::Missing);
        }
        let devtype = std::fs::read_to_string(format!("{base}/uevent"))
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("DEVTYPE=").map(str::trim))
                    .map(str::to_string)
            });
        if devtype.as_deref() == Some("wireguard") {
            Ok(ExternalLinkKind::WireGuard)
        } else if std::path::Path::new(&format!("{base}/tun_flags")).exists() {
            Ok(ExternalLinkKind::Tun)
        } else {
            Ok(ExternalLinkKind::Other)
        }
    }

    /// Read-only name → ifindex probe; 0 means "no such interface".
    fn link_index(&self, name: &str) -> io::Result<Option<u32>> {
        let c_name = CString::new(name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;
        // SAFETY: `c_name` is a valid NUL-terminated string for the call.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        Ok((index != 0).then_some(index))
    }
}

impl WgSystem for NetlinkExecutor {
    fn create_link(&mut self, name: &str, owner_marker: &str) -> io::Result<u32> {
        self.call_with(|reply| Command::WgCreate {
            name: name.into(),
            owner_marker: owner_marker.into(),
            reply,
        })
    }

    fn delete_link(&mut self, name: &str, index: u32, owner_marker: &str) -> io::Result<()> {
        self.call(|reply| Command::WgDelete {
            name: name.into(),
            index,
            owner_marker: owner_marker.into(),
            reply,
        })
    }

    fn link_owned(&mut self, name: &str, index: u32, owner_marker: &str) -> io::Result<bool> {
        self.call_with(|reply| Command::WgOwned {
            name: name.into(),
            index,
            owner_marker: owner_marker.into(),
            reply,
        })
    }

    fn link_present(&mut self, name: &str, index: u32) -> io::Result<bool> {
        self.call_with(|reply| Command::WgPresent {
            name: name.into(),
            index,
            reply,
        })
    }

    fn add_address(&mut self, index: u32, address: IpNet) -> io::Result<()> {
        self.call(|reply| Command::WgAddress {
            index,
            address,
            add: true,
            reply,
        })
    }

    fn remove_address(&mut self, index: u32, address: IpNet) -> io::Result<()> {
        self.call(|reply| Command::WgAddress {
            index,
            address,
            add: false,
            reply,
        })
    }

    fn set_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()> {
        self.call(|reply| Command::WgMtu { index, mtu, reply })
    }

    fn set_state(&mut self, index: u32, up: bool) -> io::Result<()> {
        self.call(|reply| Command::Link { index, up, reply })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::address::AddressAttribute;
    use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo};
    use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteHeader};
    use netlink_packet_route::AddressFamily;
    use std::num::NonZeroI32;

    fn owned_rule(family: IpFamily) -> OwnedRuleResource {
        OwnedRuleResource {
            family,
            priority: 30100,
            table: 51820,
            fwmark: Some(0x1234),
            invert: true,
            suppress_prefix_length: Some(0),
        }
    }

    #[test]
    fn rule_request_has_exact_v4_selector_and_table() {
        let rule = owned_rule(IpFamily::Ipv4);
        let message = rule_request(&rule);
        assert_eq!(message.header.family, AddressFamily::Inet);
        assert_eq!(message.header.src_len, 0);
        assert_eq!(message.header.dst_len, 0);
        assert_eq!(message.header.action, RuleAction::ToTable);
        assert_eq!(message.header.table, 0);
        assert_eq!(message.header.flags, vec![RuleFlag::Invert]);
        assert!(message.attributes.contains(&RuleAttribute::Priority(30100)));
        assert!(message.attributes.contains(&RuleAttribute::Table(51820)));
        assert!(message.attributes.contains(&RuleAttribute::FwMark(0x1234)));
        assert!(message
            .attributes
            .contains(&RuleAttribute::FwMask(u32::MAX)));
        assert!(message
            .attributes
            .contains(&RuleAttribute::SuppressPrefixLen(0)));
        assert!(message
            .attributes
            .contains(&RuleAttribute::Protocol(RouteProtocol::from(
                RTPROT_NETWORK_ORCHESTRATOR
            ))));
    }

    #[test]
    fn rule_request_has_exact_v6_selector_and_small_table() {
        let mut rule = owned_rule(IpFamily::Ipv6);
        rule.table = 100;
        rule.fwmark = None;
        rule.invert = false;
        rule.suppress_prefix_length = None;
        let message = rule_request(&rule);
        assert_eq!(message.header.family, AddressFamily::Inet6);
        assert_eq!(message.header.table, 100);
        assert!(message.header.flags.is_empty());
        assert!(!message.attributes.iter().any(|attr| matches!(
            attr,
            RuleAttribute::FwMark(_)
                | RuleAttribute::FwMask(_)
                | RuleAttribute::SuppressPrefixLen(_)
                | RuleAttribute::Table(_)
        )));
    }

    #[test]
    fn rule_identity_rejects_foreign_selector_and_protocol() {
        let rule = owned_rule(IpFamily::Ipv4);
        let message = rule_request(&rule);
        assert!(is_owned_rule(&message, &rule));

        let mut foreign = message.clone();
        foreign
            .attributes
            .push(RuleAttribute::Iifname("eth0".into()));
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = message.clone();
        foreign
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::Protocol(_)));
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = message.clone();
        foreign
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::FwMask(_)));
        foreign.attributes.push(RuleAttribute::FwMask(0xff));
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = message;
        foreign.header.flags.clear();
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = rule_request(&rule);
        foreign.header.table = 100;
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = rule_request(&rule);
        foreign.attributes.push(RuleAttribute::Table(rule.table));
        assert!(!is_owned_rule(&foreign, &rule));
    }

    #[test]
    fn rule_collision_and_table_occupancy_detect_foreign_state() {
        let desired = owned_rule(IpFamily::Ipv4);
        let mut foreign = rule_request(&desired);
        foreign
            .attributes
            .push(RuleAttribute::Iifname("eth0".into()));
        assert!(rule_priority(&foreign) == Some(desired.priority));
        assert!(rule_table(&foreign) == desired.table);

        let mut route = RouteMessage::default();
        route.header.table = 0;
        route.attributes.push(RouteAttribute::Table(desired.table));
        assert_eq!(route_table(&route), desired.table);
    }

    fn attrs(message: &RouteMessage) -> &[RouteAttribute] {
        &message.attributes
    }

    #[test]
    fn route_request_v4_on_link_has_link_scope_and_own_protocol() {
        let route = AppliedRoute::on_link("203.0.113.0/24".parse().unwrap(), 2, 5);
        let message = route_request(&route, RouteOp::Add);
        assert_eq!(message.header.address_family, AddressFamily::Inet);
        assert_eq!(message.header.destination_prefix_length, 24);
        assert_eq!(message.header.table, RouteHeader::RT_TABLE_MAIN);
        assert_eq!(u8::from(message.header.protocol), 79);
        assert_eq!(message.header.scope, RouteScope::Link);
        assert_eq!(message.header.kind, RouteType::Unicast);
        assert!(
            attrs(&message).contains(&RouteAttribute::Destination(RouteAddress::Inet(
                "203.0.113.0".parse().unwrap()
            )))
        );
        assert!(attrs(&message).contains(&RouteAttribute::Oif(2)));
        assert!(attrs(&message).contains(&RouteAttribute::Priority(5)));
        assert!(!attrs(&message)
            .iter()
            .any(|attr| matches!(attr, RouteAttribute::Gateway(_))));
    }

    #[test]
    fn route_request_v4_gateway_has_universe_scope() {
        let mut route = AppliedRoute::on_link("203.0.113.0/24".parse().unwrap(), 2, 5);
        route.gateway = Some("192.168.1.1".parse().unwrap());
        let message = route_request(&route, RouteOp::Add);
        assert_eq!(message.header.scope, RouteScope::Universe);
        assert!(
            attrs(&message).contains(&RouteAttribute::Gateway(RouteAddress::Inet(
                "192.168.1.1".parse().unwrap()
            )))
        );
    }

    #[test]
    fn route_request_v6_uses_inet6_and_universe_scope() {
        let mut route = AppliedRoute::on_link("2001:db8::/32".parse().unwrap(), 3, 7);
        route.gateway = Some("fe80::1".parse().unwrap());
        let message = route_request(&route, RouteOp::Add);
        assert_eq!(message.header.address_family, AddressFamily::Inet6);
        assert_eq!(message.header.destination_prefix_length, 32);
        assert_eq!(message.header.scope, RouteScope::Universe);
        assert!(
            attrs(&message).contains(&RouteAttribute::Destination(RouteAddress::Inet6(
                "2001:db8::".parse().unwrap()
            )))
        );
        assert!(
            attrs(&message).contains(&RouteAttribute::Gateway(RouteAddress::Inet6(
                "fe80::1".parse().unwrap()
            )))
        );
        assert!(attrs(&message).contains(&RouteAttribute::Oif(3)));
    }

    #[test]
    fn default_gateway_accepts_main_table_default_with_gateway() {
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet;
        message.header.kind = RouteType::Unicast;
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.attributes = vec![
            RouteAttribute::Gateway(RouteAddress::Inet("192.168.1.1".parse().unwrap())),
            RouteAttribute::Oif(3),
        ];
        assert_eq!(
            default_gateway(&message),
            Some(("192.168.1.1".parse::<IpAddr>().unwrap(), 3))
        );

        let mut v6 = RouteMessage::default();
        v6.header.address_family = AddressFamily::Inet6;
        v6.header.kind = RouteType::Unicast;
        v6.header.table = RouteHeader::RT_TABLE_MAIN;
        v6.attributes = vec![
            RouteAttribute::Gateway(RouteAddress::Inet6("fe80::1".parse().unwrap())),
            RouteAttribute::Oif(4),
        ];
        assert_eq!(
            default_gateway(&v6),
            Some(("fe80::1".parse::<IpAddr>().unwrap(), 4))
        );
    }

    #[test]
    fn default_gateway_rejects_non_uplink_routes() {
        let mut base = RouteMessage::default();
        base.header.address_family = AddressFamily::Inet;
        base.header.kind = RouteType::Unicast;
        base.header.table = RouteHeader::RT_TABLE_MAIN;
        base.attributes = vec![
            RouteAttribute::Gateway(RouteAddress::Inet("192.168.1.1".parse().unwrap())),
            RouteAttribute::Oif(3),
        ];
        // Non-default prefix.
        let mut prefixed = base.clone();
        prefixed.header.destination_prefix_length = 24;
        assert_eq!(default_gateway(&prefixed), None);
        // Our own tunnel-carrying routes never offer an uplink gateway.
        let mut owned = base.clone();
        owned.header.protocol = RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR);
        assert_eq!(default_gateway(&owned), None);
        // Policy-table routes are not the physical uplink.
        let mut table = base.clone();
        table.attributes.push(RouteAttribute::Table(51820));
        assert_eq!(default_gateway(&table), None);
        // On-link defaults (e.g. point-to-point) carry no gateway.
        let mut on_link = base.clone();
        on_link
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Gateway(_)));
        assert_eq!(default_gateway(&on_link), None);
    }

    #[test]
    fn route_request_table_above_255_uses_table_attribute() {
        let mut route = AppliedRoute::on_link("10.0.0.0/8".parse().unwrap(), 2, 5);
        route.table = Some(51820);
        let message = route_request(&route, RouteOp::Add);
        assert_eq!(message.header.table, RouteHeader::RT_TABLE_UNSPEC);
        assert!(attrs(&message).contains(&RouteAttribute::Table(51820)));

        route.table = Some(100);
        assert_eq!(route_request(&route, RouteOp::Add).header.table, 100);
    }

    #[test]
    fn delete_request_matches_any_scope_but_only_own_protocol() {
        let route = AppliedRoute::on_link("203.0.113.0/24".parse().unwrap(), 2, 5);
        let message = route_request(&route, RouteOp::Delete);
        assert_eq!(message.header.scope, RouteScope::NoWhere);
        assert_eq!(
            u8::from(message.header.protocol),
            RTPROT_NETWORK_ORCHESTRATOR
        );
        assert!(attrs(&message).contains(&RouteAttribute::Priority(5)));
        assert!(attrs(&message).contains(&RouteAttribute::Oif(2)));
    }

    #[test]
    fn link_request_toggles_up_flag_with_change_mask() {
        let up = link_request(4, true);
        assert_eq!(up.header.index, 4);
        assert_eq!(up.header.flags, vec![LinkFlag::Up]);
        assert_eq!(up.header.change_mask, vec![LinkFlag::Up]);

        let down = link_request(4, false);
        assert!(down.header.flags.is_empty());
        assert_eq!(down.header.change_mask, vec![LinkFlag::Up]);
    }

    #[test]
    fn wireguard_create_request_carries_owner_marker_and_kind() {
        let message = wireguard_create_request("wg-test", "owner-123");
        assert!(message
            .attributes
            .contains(&LinkAttribute::IfName("wg-test".into())));
        assert!(message
            .attributes
            .contains(&LinkAttribute::IfAlias("owner-123".into())));
        assert!(message
            .attributes
            .contains(&LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Wireguard
            )])));
    }

    #[test]
    fn wireguard_identity_requires_index_name_kind_and_owner() {
        let mut message = wireguard_create_request("wg-test", "owner-123");
        message.header.index = 12;
        assert!(is_owned_wireguard_link(
            &message,
            "wg-test",
            12,
            "owner-123"
        ));
        assert!(!is_owned_wireguard_link(
            &message,
            "wg-test",
            13,
            "owner-123"
        ));
        assert!(!is_owned_wireguard_link(
            &message,
            "wg-other",
            12,
            "owner-123"
        ));
        assert!(!is_owned_wireguard_link(&message, "wg-test", 12, "other"));
        message
            .attributes
            .retain(|attribute| !matches!(attribute, LinkAttribute::LinkInfo(_)));
        assert!(!is_owned_wireguard_link(
            &message,
            "wg-test",
            12,
            "owner-123"
        ));
    }

    #[test]
    fn inverted_fwmark_rule_accepts_kernel_default_full_mask_encoding() {
        let owned = OwnedRuleResource {
            family: IpFamily::Ipv4,
            priority: 10001,
            table: 51820,
            fwmark: Some(51820),
            invert: true,
            suppress_prefix_length: None,
        };
        let mut kernel = rule_request(&owned);
        kernel
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::FwMask(_)));
        assert!(is_owned_rule(&kernel, &owned));
    }

    #[test]
    fn inverted_rule_accepts_kernel_compat_table_and_unset_suppress_sentinel() {
        let owned = OwnedRuleResource {
            family: IpFamily::Ipv4,
            priority: 10001,
            table: 51820,
            fwmark: Some(51820),
            invert: true,
            suppress_prefix_length: None,
        };
        let mut kernel = rule_request(&owned);
        kernel.header.table = 252;
        kernel
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(u32::MAX));
        assert!(is_owned_rule(&kernel, &owned));
        kernel
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::SuppressPrefixLen(_)));
        kernel.attributes.push(RuleAttribute::SuppressPrefixLen(0));
        assert!(!is_owned_rule(&kernel, &owned));
    }

    #[test]
    fn address_delete_request_targets_exact_interface_address() {
        let address: IpNet = "10.20.30.4/24".parse().unwrap();
        let message = address_delete_request(12, address);
        assert_eq!(message.header.index, 12);
        assert_eq!(message.header.prefix_len, 24);
        assert_eq!(message.header.family, AddressFamily::Inet);
        assert!(message
            .attributes
            .contains(&AddressAttribute::Address("10.20.30.4".parse().unwrap())));
        assert!(message
            .attributes
            .contains(&AddressAttribute::Local("10.20.30.4".parse().unwrap())));
    }

    #[test]
    fn classify_errno_maps_kernel_errors() {
        assert_eq!(classify_errno(libc::EEXIST), io::ErrorKind::AlreadyExists);
        assert_eq!(classify_errno(libc::ESRCH), io::ErrorKind::NotFound);
        assert_eq!(classify_errno(libc::ENOENT), io::ErrorKind::NotFound);
        assert_eq!(classify_errno(libc::ENODEV), io::ErrorKind::NotFound);
        assert_eq!(classify_errno(libc::EPERM), io::ErrorKind::PermissionDenied);
        assert_eq!(
            classify_errno(libc::EACCES),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(classify_errno(libc::EINVAL), io::ErrorKind::InvalidInput);
        assert_eq!(
            classify_errno(libc::ENETUNREACH),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(classify_errno(libc::EBUSY), io::ErrorKind::Other);
    }

    #[test]
    fn address_delete_treats_missing_address_as_already_gone() {
        assert_eq!(
            classify_address_delete_errno(libc::EADDRNOTAVAIL),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            classify_address_delete_errno(libc::EPERM),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(classify_errno(libc::EADDRNOTAVAIL), io::ErrorKind::Other);
    }

    #[test]
    fn netlink_error_uses_negative_kernel_code() {
        let mut err = rtnetlink::Error::NetlinkError(Default::default());
        if let rtnetlink::Error::NetlinkError(message) = &mut err {
            message.code = NonZeroI32::new(-libc::EEXIST);
        }
        assert_eq!(
            netlink_error_to_io(err).kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            netlink_error_to_io(rtnetlink::Error::RequestFailed).kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn owned_route_snapshot_requires_proto_and_exact_attributes() {
        let route = AppliedRoute {
            destination: "203.0.113.0/24".parse().unwrap(),
            interface_index: 7,
            metric: 13,
            gateway: Some("192.0.2.1".parse().unwrap()),
            table: None,
        };
        let mut message = route_request(&route, RouteOp::Add);
        assert_eq!(owned_route_snapshot(&message), Some(route.clone()));
        message.header.protocol = RouteProtocol::Static;
        assert_eq!(owned_route_snapshot(&message), None);
        message.header.protocol = RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR);
        message
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Oif(_)));
        assert_eq!(owned_route_snapshot(&message), None);

        let default = AppliedRoute::on_link("0.0.0.0/0".parse().unwrap(), 7, 13);
        let mut default_message = route_request(&default, RouteOp::Add);
        default_message
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Destination(_)));
        assert_eq!(owned_route_snapshot(&default_message), Some(default));

        let mut main_table = route_request(&route, RouteOp::Add);
        main_table.attributes.push(RouteAttribute::Table(254));
        assert_eq!(owned_route_snapshot(&main_table), Some(route));
    }

    fn names() -> HashMap<u32, String> {
        HashMap::from([(7, "enp1s0".into()), (42, "wg0".into())])
    }

    #[test]
    fn system_route_renders_extended_table_gateway_route() {
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet;
        message.header.kind = RouteType::Unicast;
        message.header.scope = RouteScope::Universe;
        message.header.protocol = RouteProtocol::Static;
        message.header.destination_prefix_length = 24;
        message
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(
                "198.51.100.0".parse().unwrap(),
            )));
        message
            .attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(
                "192.0.2.1".parse().unwrap(),
            )));
        message.attributes.push(RouteAttribute::Oif(7));
        message.attributes.push(RouteAttribute::Priority(600));
        message.attributes.push(RouteAttribute::Table(51820));

        let route = system_route(&message, &names()).unwrap();
        assert_eq!(route.family, IpFamily::Ipv4);
        assert_eq!(route.destination, "198.51.100.0/24".parse().unwrap());
        assert_eq!(route.table, 51820);
        assert_eq!(route.kind, "unicast");
        assert_eq!(route.scope, "universe");
        assert_eq!(route.gateway, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(route.interface_name.as_deref(), Some("enp1s0"));
        assert_eq!(route.metric, Some(600));
        assert!(!route.managed);
    }

    #[test]
    fn system_route_marks_daemon_protocol_and_resolves_default() {
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet;
        message.header.kind = RouteType::Unicast;
        message.header.protocol = RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR);
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.attributes.push(RouteAttribute::Oif(42));

        let route = system_route(&message, &names()).unwrap();
        assert_eq!(route.destination, "0.0.0.0/0".parse().unwrap());
        assert_eq!(route.table, 254);
        assert_eq!(route.interface_name.as_deref(), Some("wg0"));
        assert!(route.managed);
    }

    #[test]
    fn system_route_renders_multipath_nexthops() {
        use netlink_packet_route::route::RouteNextHop;
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet;
        message.header.kind = RouteType::Unicast;
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        let mut hop = RouteNextHop::default();
        hop.interface_index = 7;
        hop.hops = 1;
        hop.attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(
                "192.0.2.1".parse().unwrap(),
            )));
        message
            .attributes
            .push(RouteAttribute::MultiPath(vec![hop]));

        let route = system_route(&message, &names()).unwrap();
        assert_eq!(route.nexthops.len(), 1);
        assert_eq!(route.nexthops[0].interface_name.as_deref(), Some("enp1s0"));
        assert_eq!(
            route.nexthops[0].gateway,
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(route.nexthops[0].weight, 1);
    }

    #[test]
    fn system_route_skips_unknown_family() {
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Unspec;
        assert!(system_route(&message, &names()).is_none());
    }

    #[test]
    fn system_rule_renders_full_selector() {
        let mut message = RuleMessage::default();
        message.header.family = AddressFamily::Inet;
        message.header.action = RuleAction::ToTable;
        message.header.src_len = 24;
        message.header.dst_len = 8;
        message.header.tos = 0x10;
        message.header.flags.push(RuleFlag::Invert);
        message.attributes.push(RuleAttribute::Priority(30100));
        message.attributes.push(RuleAttribute::Table(51820));
        message
            .attributes
            .push(RuleAttribute::Source("10.1.2.0".parse().unwrap()));
        message
            .attributes
            .push(RuleAttribute::Destination("10.9.0.0".parse().unwrap()));
        message.attributes.push(RuleAttribute::FwMark(0x1234));
        message.attributes.push(RuleAttribute::FwMask(0xffff));
        message
            .attributes
            .push(RuleAttribute::Iifname("enp1s0".into()));
        message
            .attributes
            .push(RuleAttribute::Oifname("wg0".into()));
        message.attributes.push(RuleAttribute::SuppressPrefixLen(2));
        message
            .attributes
            .push(RuleAttribute::Protocol(RouteProtocol::from(
                RTPROT_NETWORK_ORCHESTRATOR,
            )));

        let rule = system_rule(&message);
        assert_eq!(rule.family, IpFamily::Ipv4);
        assert_eq!(rule.priority, 30100);
        assert_eq!(rule.action, "lookup");
        assert_eq!(rule.table, 51820);
        assert_eq!(rule.from, Some("10.1.2.0/24".parse().unwrap()));
        assert_eq!(rule.to, Some("10.0.0.0/8".parse().unwrap()));
        assert_eq!(rule.fwmark, Some(0x1234));
        assert_eq!(rule.fwmask, Some(0xffff));
        assert_eq!(rule.iifname.as_deref(), Some("enp1s0"));
        assert_eq!(rule.oifname.as_deref(), Some("wg0"));
        assert_eq!(rule.suppress_prefix_length, Some(2));
        assert_eq!(rule.tos, 0x10);
        assert!(rule.invert);
        assert!(rule.managed);
    }

    #[test]
    fn system_rule_defaults_are_ip_rule_compatible() {
        // A bare `0: from all lookup main` rule: no selectors, no protocol.
        let mut message = RuleMessage::default();
        message.header.family = AddressFamily::Inet;
        message.header.action = RuleAction::ToTable;
        message.header.table = RouteHeader::RT_TABLE_MAIN;

        let rule = system_rule(&message);
        assert_eq!(rule.priority, 0);
        assert_eq!(rule.table, 254);
        assert_eq!(rule.from, None);
        assert_eq!(rule.to, None);
        assert!(!rule.invert);
        assert!(!rule.managed);
    }

    #[test]
    fn system_rule_ignores_kernel_default_suppress() {
        let mut message = RuleMessage::default();
        message.header.family = AddressFamily::Inet;
        message.header.action = RuleAction::ToTable;
        message
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(u32::MAX));
        message
            .attributes
            .push(RuleAttribute::SuppressIfGroup(u32::MAX));

        let rule = system_rule(&message);
        assert_eq!(rule.suppress_prefix_length, None);
        assert_eq!(rule.suppress_if_group, None);
    }
}

#[cfg(test)]
mod executor_tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc as async_mpsc;

    fn executor(tx: async_mpsc::UnboundedSender<QueuedCommand>) -> NetlinkExecutor {
        NetlinkExecutor {
            tx,
            reply_timeout: Duration::from_millis(50),
        }
    }

    #[test]
    fn call_errors_fast_when_actor_channel_dropped() {
        let (tx, rx) = async_mpsc::unbounded_channel();
        drop(rx);
        assert!(executor(tx).owned_routes_snapshot().is_err());
    }

    #[test]
    fn call_times_out_when_actor_never_replies() {
        let (tx, rx) = async_mpsc::unbounded_channel();
        let _keep = rx; // channel alive, but no command is ever serviced
        let start = Instant::now();
        assert!(executor(tx).owned_routes_snapshot().is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn call_with_times_out_when_actor_never_replies() {
        let (tx, rx) = async_mpsc::unbounded_channel();
        let _keep = rx;
        let start = Instant::now();
        assert!(executor(tx).interface_addrs().is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
