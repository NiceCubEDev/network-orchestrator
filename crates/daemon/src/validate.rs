//! Request validation. The daemon never trusts the client: every field that
//! reaches netlink is checked here first, before polkit is even asked.

use ipnet::IpNet;
use net_manager_core::daemon_protocol::{
    AttachSpecParams, MAX_OWNER_BYTES, MAX_ROUTES_PER_REQUEST,
};
use net_manager_core::models::AppliedRoute;
use std::collections::HashSet;
use std::net::IpAddr;

/// Cap on `endpoint_bypasses` per attach spec: endpoints are a handful of
/// VPN servers, not a bulk list.
pub const MAX_ENDPOINT_BYPASSES: usize = 256;

/// Linux interface names are limited to `IFNAMSIZ - 1` = 15 bytes. Beyond
/// that we accept only characters that can never be mistaken for a flag or a
/// shell metacharacter, even though nothing here ever touches a shell.
pub fn validate_iface_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!(
            "interface name must be 1-15 bytes, got {}",
            name.len()
        ));
    }
    if name.starts_with('-') {
        return Err("interface name must not start with '-'".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("interface name contains unsupported characters".into());
    }
    Ok(())
}

pub fn validate_owner(owner: &str) -> Result<(), String> {
    if owner.is_empty() || owner.len() > MAX_OWNER_BYTES {
        return Err(format!(
            "owner must be 1-{MAX_OWNER_BYTES} bytes, got {}",
            owner.len()
        ));
    }
    if owner.chars().any(char::is_control) {
        return Err("owner must not contain control characters".into());
    }
    Ok(())
}

/// An attach spec reaches the journal verbatim and is re-planned on every
/// reconcile, so every field is checked once here. `via` on a policy route
/// names an on-link peer (e.g. a tun gateway); it must be unicast and match
/// the destination family, same as `AppliedRoute.gateway`.
pub fn validate_attach(spec: &AttachSpecParams) -> Result<(), String> {
    if spec.uplink {
        // Uplink ("direct") specs bind routes to whatever the physical
        // uplink is at reconcile time — naming a link contradicts that.
        if !spec.interface_name.is_empty() {
            return Err("uplink specs do not take an interface name".into());
        }
    // An empty interface name is legal for bypass-only specs — there is no
    // link to bind — but declared routes always need a binding target.
    } else if !spec.interface_name.is_empty() {
        validate_iface_name(&spec.interface_name)?;
    } else if !spec.routes.is_empty() {
        return Err("attach routes need an interface name".into());
    }
    if spec.routes.len() > MAX_ROUTES_PER_REQUEST {
        return Err(format!(
            "at most {MAX_ROUTES_PER_REQUEST} spec routes, got {}",
            spec.routes.len()
        ));
    }
    if spec.endpoint_bypasses.len() > MAX_ENDPOINT_BYPASSES {
        return Err(format!(
            "at most {MAX_ENDPOINT_BYPASSES} endpoint bypasses, got {}",
            spec.endpoint_bypasses.len()
        ));
    }
    for route in &spec.routes {
        if let Some(via) = route.via {
            let same_family = via.is_ipv4() == route.destination.addr().is_ipv4();
            if !same_family || via.is_unspecified() || via.is_multicast() {
                return Err(format!(
                    "via {via} must be a unicast address in the family of {}",
                    route.destination
                ));
            }
        }
    }
    for host in &spec.endpoint_bypasses {
        if host.is_empty() || host.len() > 253 {
            return Err("endpoint bypass host must be 1-253 bytes".into());
        }
        if host.parse::<IpAddr>().is_err()
            && !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            return Err(format!(
                "endpoint bypass host {host:?} is not a DNS name or IP"
            ));
        }
    }
    Ok(())
}

pub fn validate_route(route: &AppliedRoute) -> Result<(), String> {
    let destination = route.destination;
    if destination.trunc() != destination {
        return Err(format!("destination {destination} has host bits set"));
    }
    if route.table.is_some() {
        return Err("routing table is chosen by the daemon, not the client".into());
    }
    if route.interface_index == 0 {
        return Err(format!("route {destination} has no interface index"));
    }
    if let Some(gateway) = route.gateway {
        let same_family = matches!(
            (destination, gateway),
            (IpNet::V4(_), IpAddr::V4(_)) | (IpNet::V6(_), IpAddr::V6(_))
        );
        if !same_family {
            return Err(format!(
                "gateway {gateway} is not in the address family of {destination}"
            ));
        }
        if gateway.is_unspecified() || gateway.is_multicast() {
            return Err(format!("gateway {gateway} must be a unicast address"));
        }
    }
    Ok(())
}

pub fn validate_apply(routes: &[AppliedRoute]) -> Result<(), String> {
    if routes.len() > MAX_ROUTES_PER_REQUEST {
        return Err(format!(
            "at most {MAX_ROUTES_PER_REQUEST} routes per request, got {}",
            routes.len()
        ));
    }
    let mut seen = HashSet::new();
    for route in routes {
        validate_route(route)?;
        if !seen.insert((route.destination, route.metric)) {
            return Err(format!(
                "duplicate route {} with metric {}",
                route.destination, route.metric
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::MAX_ROUTES_PER_REQUEST;
    use net_manager_core::models::AppliedRoute;

    fn route(dest: &str, metric: u32) -> AppliedRoute {
        AppliedRoute::on_link(dest.parse().unwrap(), 2, metric)
    }

    fn via(dest: &str, gateway: &str) -> AppliedRoute {
        AppliedRoute {
            gateway: Some(gateway.parse().unwrap()),
            ..route(dest, 5)
        }
    }

    #[test]
    fn iface_name_accepts_typical_linux_names() {
        for name in ["wg0", "eth0", "veth-abc123", "br_lan", "tun.100"] {
            assert!(validate_iface_name(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn iface_name_rejects_empty_and_oversized() {
        assert!(validate_iface_name("").is_err());
        assert!(validate_iface_name("this-name-is-16c").is_err());
        assert!(validate_iface_name("exactly15chars.").is_ok());
    }

    #[test]
    fn iface_name_rejects_leading_dash_and_unsafe_characters() {
        assert!(
            validate_iface_name("-f").is_err(),
            "must not look like an ip flag"
        );
        assert!(validate_iface_name("wg0; rm -rf /").is_err());
        assert!(validate_iface_name("wg 0").is_err());
        assert!(validate_iface_name("wg0/24").is_err());
    }

    #[test]
    fn owner_accepts_profile_ids_up_to_128_bytes() {
        assert!(validate_owner("static-office").is_ok());
        assert!(validate_owner("профиль").is_ok());
        assert!(validate_owner(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn owner_rejects_empty_oversized_and_control_characters() {
        assert!(validate_owner("").is_err());
        assert!(validate_owner(&"a".repeat(129)).is_err());
        assert!(validate_owner("a\nb").is_err());
        assert!(validate_owner("a\u{7f}").is_err());
    }

    #[test]
    fn route_accepts_on_link_and_gateway_routes() {
        assert!(validate_route(&route("203.0.113.0/24", 5)).is_ok());
        assert!(validate_route(&route("2001:db8::/32", 5)).is_ok());
        assert!(validate_route(&via("203.0.113.0/24", "192.168.1.1")).is_ok());
        assert!(validate_route(&via("2001:db8::/32", "fe80::1")).is_ok());
    }

    #[test]
    fn route_rejects_host_bits() {
        assert!(validate_route(&route("203.0.113.7/24", 5)).is_err());
        assert!(validate_route(&route("2001:db8::1/32", 5)).is_err());
    }

    #[test]
    fn route_rejects_client_chosen_table() {
        let mut r = route("203.0.113.0/24", 5);
        r.table = Some(255);
        assert!(validate_route(&r).unwrap_err().contains("table"));
    }

    #[test]
    fn route_rejects_zero_interface_index() {
        let mut r = route("203.0.113.0/24", 5);
        r.interface_index = 0;
        assert!(validate_route(&r).is_err());
    }

    #[test]
    fn route_rejects_gateway_family_mismatch() {
        assert!(validate_route(&via("203.0.113.0/24", "fe80::1")).is_err());
        assert!(validate_route(&via("2001:db8::/32", "192.168.1.1")).is_err());
    }

    #[test]
    fn route_rejects_unspecified_and_multicast_gateway() {
        assert!(validate_route(&via("203.0.113.0/24", "0.0.0.0")).is_err());
        assert!(validate_route(&via("203.0.113.0/24", "224.0.0.1")).is_err());
        assert!(validate_route(&via("2001:db8::/32", "::")).is_err());
        assert!(validate_route(&via("2001:db8::/32", "ff02::1")).is_err());
    }

    #[test]
    fn apply_rejects_more_than_the_route_limit() {
        let routes: Vec<AppliedRoute> = (0..=MAX_ROUTES_PER_REQUEST as u32)
            .map(|metric| route("10.0.0.0/8", metric))
            .collect();
        assert!(validate_apply(&routes).is_err());
        assert!(validate_apply(&routes[..MAX_ROUTES_PER_REQUEST]).is_ok());
    }

    #[test]
    fn apply_rejects_duplicate_destination_and_metric() {
        let routes = vec![route("10.0.0.0/8", 1), route("10.0.0.0/8", 1)];
        assert!(validate_apply(&routes).unwrap_err().contains("duplicate"));
        let routes = vec![route("10.0.0.0/8", 1), route("10.0.0.0/8", 2)];
        assert!(validate_apply(&routes).is_ok());
    }

    #[test]
    fn apply_validates_every_route() {
        let routes = vec![route("10.0.0.0/8", 1), route("10.0.0.1/8", 2)];
        assert!(validate_apply(&routes).is_err());
    }
}
