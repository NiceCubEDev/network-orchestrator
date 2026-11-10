use crate::models::*;
use net_route::Handle as RouteHandle;
use std::collections::HashMap;
use std::net::IpAddr;

// ── Route table reading (cross-platform via net-route) ──────────────────

/// List all IPv4 and IPv6 routes from the system routing table.
pub async fn list_routes() -> std::io::Result<Vec<RouteEntry>> {
    let handle = RouteHandle::new()?;
    let routes = handle.list().await?;
    Ok(route_entries(routes, &build_ifindex_name_map()))
}

fn route_entries(
    routes: Vec<net_route::Route>,
    name_map: &HashMap<u32, String>,
) -> Vec<RouteEntry> {
    routes
        .into_iter()
        .map(|r| {
            let if_index = r.ifindex.unwrap_or(0);
            let name = name_map
                .get(&if_index)
                .cloned()
                .unwrap_or_else(|| format!("ifindex {}", if_index));
            RouteEntry {
                destination: r.destination,
                prefix_len: r.prefix,
                gateway: r.gateway,
                interface_index: if_index,
                interface_name: name,
                metric: route_metric(&r),
            }
        })
        .collect()
}

/// Build a map of interface index → friendly name.
/// Uses the platform-specific interface listing.
fn build_ifindex_name_map() -> HashMap<u32, String> {
    list_interfaces()
        .unwrap_or_default()
        .into_iter()
        .map(|i| (i.if_index, i.friendly_name))
        .collect()
}

/// Extract metric from a net-route Route (platform-dependent field).
fn route_metric(r: &net_route::Route) -> u32 {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        r.metric.unwrap_or(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        // net-route does not expose route metrics on macOS.
        let _ = r;
        0
    }
}

// ── Route lookup ────────────────────────────────────────────────────────

/// Longest prefix wins; ties go to the lowest metric. Routes of the other
/// address family never match.
pub fn longest_prefix_match(dest: IpAddr, routes: &[RouteEntry]) -> Option<&RouteEntry> {
    routes
        .iter()
        .filter(|r| {
            ipnet::IpNet::new(r.destination, r.prefix_len).is_ok_and(|net| net.contains(&dest))
        })
        .min_by_key(|r| (std::cmp::Reverse(r.prefix_len), r.metric))
}

/// Given a destination IP, find which route and interface the OS would use.
#[cfg(not(target_os = "linux"))]
pub async fn lookup_route(dest: IpAddr) -> std::io::Result<RouteLookupResult> {
    let routes = list_routes().await?;
    let matched = longest_prefix_match(dest, &routes)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no matching route"))?;

    Ok(RouteLookupResult {
        destination: dest,
        matched_route: matched.clone(),
        interface_name: matched.interface_name.clone(),
        table: None,
    })
}

#[cfg(target_os = "linux")]
const MAX_ROUTE_GET_BYTES: usize = 16 * 1024;

#[cfg(target_os = "linux")]
fn parse_linux_route_get(
    dest: IpAddr,
    bytes: &[u8],
    interfaces: &[NetworkInterface],
) -> std::io::Result<RouteLookupResult> {
    use serde::Deserialize;
    use std::io::{Error, ErrorKind};

    #[derive(Deserialize)]
    struct RouteGetRow {
        dst: String,
        dev: String,
        gateway: Option<String>,
        metric: Option<u32>,
        table: Option<serde_json::Value>,
    }

    let invalid = || Error::new(ErrorKind::InvalidData, "invalid route lookup response");
    if bytes.len() > MAX_ROUTE_GET_BYTES {
        return Err(invalid());
    }
    let mut rows: Vec<RouteGetRow> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if rows.len() != 1 {
        return Err(invalid());
    }
    let row = rows.pop().ok_or_else(invalid)?;
    if row.dev.is_empty() {
        return Err(invalid());
    }
    let (destination, prefix_len) = if row.dst == "default" {
        (
            if dest.is_ipv4() { "0.0.0.0" } else { "::" }
                .parse()
                .unwrap(),
            0,
        )
    } else if let Ok(net) = row.dst.parse::<ipnet::IpNet>() {
        (net.addr(), net.prefix_len())
    } else {
        let address: IpAddr = row.dst.parse().map_err(|_| invalid())?;
        (address, if address.is_ipv4() { 32 } else { 128 })
    };
    if destination.is_ipv4() != dest.is_ipv4()
        || !ipnet::IpNet::new(destination, prefix_len)
            .map_err(|_| invalid())?
            .contains(&dest)
    {
        return Err(invalid());
    }
    let table = match row.table {
        None => "main".to_string(),
        Some(serde_json::Value::String(table)) if !table.is_empty() && table.len() <= 32 => table,
        Some(serde_json::Value::Number(table)) => {
            let id = table
                .as_u64()
                .filter(|id| *id <= u32::MAX as u64)
                .ok_or_else(invalid)?;
            id.to_string()
        }
        _ => return Err(invalid()),
    };
    let gateway = row
        .gateway
        .map(|value| value.parse().map_err(|_| invalid()))
        .transpose()?;
    let (interface_index, interface_name) = interfaces
        .iter()
        .find(|interface| interface.name == row.dev)
        .map(|interface| (interface.if_index, interface.friendly_name.clone()))
        .unwrap_or((0, row.dev));
    Ok(RouteLookupResult {
        destination: dest,
        matched_route: RouteEntry {
            destination,
            prefix_len,
            gateway,
            interface_index,
            interface_name: interface_name.clone(),
            metric: row.metric.unwrap_or(0),
        },
        interface_name,
        table: Some(table),
    })
}

#[cfg(target_os = "linux")]
pub async fn lookup_route(dest: IpAddr) -> std::io::Result<RouteLookupResult> {
    use std::io::{Error, ErrorKind};
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    let mut child = tokio::process::Command::new("/usr/sbin/ip")
        .args([
            "-j",
            if dest.is_ipv4() { "-4" } else { "-6" },
            "route",
            "get",
            "fibmatch",
        ])
        .arg(dest.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Error::new(ErrorKind::NotFound, "iproute2 is unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::other("route lookup failed"))?;
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        stdout
            .take((MAX_ROUTE_GET_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > MAX_ROUTE_GET_BYTES {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "route lookup response too large",
            ));
        }
        if !child.wait().await?.success() {
            return Err(Error::new(ErrorKind::NotFound, "no matching route"));
        }
        Ok(())
    })
    .await;
    match result {
        Ok(Ok(())) => parse_linux_route_get(dest, &bytes, &list_interfaces().unwrap_or_default()),
        Ok(Err(err)) => {
            let _ = child.kill().await;
            Err(err)
        }
        Err(_) => {
            let _ = child.kill().await;
            Err(Error::new(ErrorKind::TimedOut, "route lookup timed out"))
        }
    }
}

// ── Route change watcher (cross-platform via net-route) ─────────────────

use futures::StreamExt;

/// Async loop that calls the callback whenever the routing table changes.
/// The caller is responsible for spawning this on an appropriate runtime.
pub async fn route_watcher_loop<F>(callback: F)
where
    F: Fn() + Send + 'static,
{
    let handle = match RouteHandle::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("route watcher init failed: {e}");
            return;
        }
    };
    let stream = handle.route_listen_stream();
    tokio::pin!(stream);
    while let Some(_change) = stream.next().await {
        callback();
    }
}

// ── Interface inventory ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;

#[cfg(target_os = "windows")]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_INCLUDE_PREFIX,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let mut buf_len: u32 = 0;
    unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buf_len,
        );
    }

    let mut buf = vec![0u8; buf_len as usize];
    let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(head),
            &mut buf_len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::from_raw_os_error(ret as i32));
    }

    let mut result = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        let adapter = unsafe { &*cur };
        result.push(adapter_to_model(adapter));
        cur = unsafe { (*cur).Next };
    }

    // FreeMibTable expects the pointer that was allocated by GetAdaptersAddresses
    // (which writes into our buffer), so we must NOT free it — the buffer is
    // owned by `buf` and will be dropped. FreeMibTable is for tables allocated
    // by functions like GetIpForwardTable2. Skip it here.
    Ok(result)
}

#[cfg(target_os = "windows")]
fn adapter_to_model(adapter: &IP_ADAPTER_ADDRESSES_LH) -> NetworkInterface {
    use windows::Win32::NetworkManagement::Ndis::IF_OPER_STATUS;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let friendly_name = unsafe { adapter.FriendlyName.to_string().unwrap_or_default() };
    let raw_name = unsafe { adapter.AdapterName.to_string().unwrap_or_default() };
    let description = unsafe { adapter.Description.to_string().unwrap_or_default() };
    let if_type = adapter.IfType;
    let tunnel_type = tunnel_type_name(adapter.TunnelType);
    let kind = classify_interface(&raw_name, &friendly_name, &description, if_type);
    let state = if adapter.OperStatus == IF_OPER_STATUS(1) {
        InterfaceState::Up
    } else {
        InterfaceState::Down
    };

    let mut addresses = Vec::new();
    let mut ip = adapter.FirstUnicastAddress;
    while !ip.is_null() {
        let ua = unsafe { &*ip };
        let sockaddr = ua.Address.lpSockaddr;
        if !sockaddr.is_null() {
            let sa = unsafe { *sockaddr };
            let family = sa.sa_family;
            if family == AF_INET || family == AF_INET6 {
                if let Some(addr) = sockaddr_to_ip(sockaddr) {
                    addresses.push(InterfaceAddress {
                        address: addr,
                        prefix_len: ua.OnLinkPrefixLength,
                        family: if addr.is_ipv4() {
                            AddressFamily::Ipv4
                        } else {
                            AddressFamily::Ipv6
                        },
                    });
                }
            }
        }
        ip = ua.Next;
    }

    let dns_servers = collect_dns(adapter);

    // MAC address
    let mac = if adapter.PhysicalAddressLength == 6 {
        let bytes = &adapter.PhysicalAddress[..adapter.PhysicalAddressLength as usize];
        Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        ))
    } else {
        None
    };

    // Gateway from FirstGatewayAddress
    let gateway = if !adapter.FirstGatewayAddress.is_null() {
        let gw = unsafe { &*adapter.FirstGatewayAddress };
        sockaddr_to_ip(gw.Address.lpSockaddr)
    } else {
        None
    };

    // DNS suffix
    let dns_suffix = unsafe { adapter.DnsSuffix.to_string() }
        .ok()
        .filter(|s| !s.is_empty());

    // Link speed (ReceiveLinkSpeed is in bps, convert to Mbps)
    // Some virtual adapters report u64::MAX — filter those out.
    let link_speed_mbps =
        if adapter.ReceiveLinkSpeed > 0 && adapter.ReceiveLinkSpeed < 1_000_000_000_000 {
            Some(adapter.ReceiveLinkSpeed / 1_000_000)
        } else {
            None
        };

    // MTU: some virtual adapters report absurd values — filter those out.
    let mtu = if adapter.Mtu > 0 && adapter.Mtu <= 65535 {
        Some(adapter.Mtu)
    } else {
        None
    };

    let category = classify_category(&friendly_name, &description, &kind, if_type);

    NetworkInterface {
        name: raw_name,
        friendly_name,
        kind,
        state,
        addresses,
        dns_servers,
        dns_suffix,
        mtu,
        if_index: unsafe { adapter.Anonymous1.Anonymous.IfIndex },
        physical: is_physical_windows(adapter.IfType),
        mac,
        gateway,
        ipv6_gateway: None, // Windows keeps the single `gateway` field
        rx_bytes: None,     // requires GetIfEntry2 — deferred
        tx_bytes: None,     // requires GetIfEntry2 — deferred
        link_speed_mbps,
        category,
        description,
        if_type,
        tunnel_type,
    }
}

#[cfg(target_os = "windows")]
fn sockaddr_to_ip(sa: *const windows::Win32::Networking::WinSock::SOCKADDR) -> Option<IpAddr> {
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    let raw = unsafe { *sa };
    match raw.sa_family {
        f if f == AF_INET => {
            let sin = unsafe { *(sa as *const SOCKADDR_IN) };
            let bytes = unsafe { sin.sin_addr.S_un.S_addr.to_ne_bytes() };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(bytes)))
        }
        f if f == AF_INET6 => {
            let sin6 = unsafe { *(sa as *const SOCKADDR_IN6) };
            let bytes = unsafe { sin6.sin6_addr.u.Byte };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn collect_dns(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Vec<IpAddr> {
    let mut dns = Vec::new();
    let mut cur = adapter.FirstDnsServerAddress;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        let sa = entry.Address.lpSockaddr;
        if !sa.is_null() {
            if let Some(addr) = sockaddr_to_ip(sa) {
                dns.push(addr);
            }
        }
        cur = entry.Next;
    }
    dns
}

#[cfg(target_os = "windows")]
fn is_physical_windows(if_type: u32) -> bool {
    // IF_TYPE_ETHERNET_CSMACD = 6, IF_TYPE_IEEE80211 = 71
    if_type == 6 || if_type == 71
}

#[cfg(target_os = "windows")]
fn tunnel_type_name(t: windows::Win32::NetworkManagement::Ndis::TUNNEL_TYPE) -> Option<String> {
    use windows::Win32::NetworkManagement::Ndis::*;
    match t {
        TUNNEL_TYPE_NONE => None,
        TUNNEL_TYPE_OTHER => Some("Other".into()),
        TUNNEL_TYPE_DIRECT => Some("Direct".into()),
        TUNNEL_TYPE_6TO4 => Some("6to4".into()),
        TUNNEL_TYPE_ISATAP => Some("ISATAP".into()),
        TUNNEL_TYPE_TEREDO => Some("Teredo".into()),
        TUNNEL_TYPE_IPHTTPS => Some("IP-HTTPS".into()),
        _ => Some(format!("{:?}", t)),
    }
}

#[cfg(target_os = "windows")]
fn classify_category(
    friendly_name: &str,
    description: &str,
    kind: &InterfaceKind,
    if_type: u32,
) -> InterfaceCategory {
    let lower = friendly_name.to_lowercase();
    let desc_lower = description.to_lowercase();

    // Filter drivers and lightweight filters — by friendly name suffix
    const FILTER_KEYWORDS: &[&str] = &[
        "lightweight filter",
        "wfp native mac layer",
        "wfp 802.3 mac layer",
        "npcap packet driver",
        "qos packet scheduler",
        "hyper-v virtual switch extension",
        "virtual filtering platform vmswitch",
        "virtual wifi filter driver",
        "native wifi filter driver",
    ];
    if FILTER_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return InterfaceCategory::Filter;
    }

    // Description-based classification (more reliable than friendly name)
    // Wi-Fi Direct virtual adapters — virtual, not tunnel
    if desc_lower.contains("wi-fi direct") {
        return InterfaceCategory::Virtual;
    }
    // WAN Miniports — Windows built-in VPN miniports (PPTP, L2TP, IKEv2, SSTP, PPPOE, IP, IPv6, NetMon)
    if desc_lower.contains("wan miniport") {
        return InterfaceCategory::Tunnel;
    }
    // Kernel debug adapter — system
    if desc_lower.contains("kernel debug") {
        return InterfaceCategory::System;
    }
    // Bluetooth PAN — virtual (Windows uses if_type 6, not 7)
    if desc_lower.contains("bluetooth") {
        return InterfaceCategory::Virtual;
    }

    // OS-internal tunnel pseudo-interfaces by if_type
    // IF_TYPE_TUNNEL = 131
    if if_type == 131 {
        return InterfaceCategory::Tunnel;
    }
    const TUNNEL_KEYWORDS: &[&str] = &["teredo", "6to4", "ip-https", "isatap"];
    if TUNNEL_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return InterfaceCategory::Tunnel;
    }
    // Remaining "Подключение по локальной сети* N" not caught by description above
    if lower.starts_with("подключение по локальной сети*") || lower.starts_with("lan connection*")
    {
        return InterfaceCategory::Tunnel;
    }

    match kind {
        InterfaceKind::Loopback => InterfaceCategory::System,
        InterfaceKind::WireGuard | InterfaceKind::OpenVpn | InterfaceKind::Xray => {
            InterfaceCategory::Vpn
        }
        InterfaceKind::Other(s) => {
            let s = s.to_lowercase();
            match s.as_str() {
                "tailscale" => InterfaceCategory::Vpn,
                "hyper-v" | "cellular" | "bluetooth" => InterfaceCategory::Virtual,
                _ => {
                    // If description mentions VPN/tunnel driver, it's a VPN
                    if desc_lower.contains("wireguard")
                        || desc_lower.contains("wintun")
                        || desc_lower.contains("tap-windows")
                        || desc_lower.contains("tun/tap")
                    {
                        InterfaceCategory::Vpn
                    } else {
                        InterfaceCategory::Physical
                    }
                }
            }
        }
        InterfaceKind::Ethernet | InterfaceKind::Wifi => InterfaceCategory::Physical,
    }
}

#[cfg(target_os = "windows")]
fn classify_interface(
    raw: &str,
    friendly: &str,
    description: &str,
    _if_type: u32,
) -> InterfaceKind {
    let lower = friendly.to_lowercase();
    let desc_lower = description.to_lowercase();

    // VPN detection by driver description (most reliable)
    if desc_lower.contains("wireguard") || desc_lower.contains("wintun") {
        return InterfaceKind::WireGuard;
    }
    if desc_lower.contains("tap-windows") || desc_lower.contains("tun/tap") {
        return InterfaceKind::OpenVpn;
    }

    // VPN by friendly name
    if lower.contains("wireguard") || raw.starts_with("wg") {
        return InterfaceKind::WireGuard;
    }
    if lower.contains("openvpn") || lower.contains("tap-") || lower.contains("tun-") {
        return InterfaceKind::OpenVpn;
    }
    if lower.contains("xray") || lower.contains("wintun") {
        return InterfaceKind::Xray;
    }
    if lower.contains("tailscale") {
        return InterfaceKind::Other("Tailscale".into());
    }

    // Bluetooth: by description (Windows uses if_type 6 for Bluetooth PAN, not 7)
    if desc_lower.contains("bluetooth") || lower.contains("bluetooth") {
        return InterfaceKind::Other("Bluetooth".into());
    }

    // Kernel debug adapter
    if desc_lower.contains("kernel debug") {
        return InterfaceKind::Other("Kernel Debug".into());
    }

    // Wi-Fi Direct virtual adapters
    if desc_lower.contains("wi-fi direct") {
        return InterfaceKind::Other("Wi-Fi Direct".into());
    }

    // WiFi by description (Russian friendly names like "Беспроводная сеть" don't contain "wifi")
    if desc_lower.contains("wi-fi") || desc_lower.contains("wireless") {
        return InterfaceKind::Wifi;
    }

    // Hyper-V virtual switches
    if lower.starts_with("vethernet") || lower.contains("hyper-v") || lower.starts_with("vswitch") {
        return InterfaceKind::Other("Hyper-V".into());
    }

    // Cellular (wwan) — note: real wwan adapters have if_type 106, not name-based
    if lower.starts_with("wwan") && !desc_lower.contains("wintun") {
        return InterfaceKind::Other("Cellular".into());
    }

    if lower.contains("wi-fi") || lower.contains("wifi") || lower.contains("wireless") {
        return InterfaceKind::Wifi;
    }
    if lower.contains("ethernet") {
        return InterfaceKind::Ethernet;
    }
    if lower.contains("loopback") || raw == "lo" {
        return InterfaceKind::Loopback;
    }
    InterfaceKind::Other(lower)
}

// ── Linux interface inventory ───────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    use std::ffi::CStr;
    use std::mem;

    unsafe {
        let mut ifap: *mut libc::ifaddrs = mem::zeroed();
        let ret = libc::getifaddrs(&mut ifap);
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let head = ifap;

        // First pass: collect unique interface names in insertion order
        let mut names: Vec<String> = Vec::new();
        let mut name_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut is_up_map: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();

        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() {
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let is_up = (ifa.ifa_flags & libc::IFF_UP as u32) != 0;
                if name_set.insert(name.clone()) {
                    names.push(name.clone());
                }
                *is_up_map.entry(name).or_insert(false) |= is_up;
            }
            cur = ifa.ifa_next;
        }

        // Second pass: collect addresses per interface
        let mut addr_map: std::collections::HashMap<String, Vec<InterfaceAddress>> =
            std::collections::HashMap::new();

        cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let family = (*ifa.ifa_addr).sa_family as i32;

                let addr = if family == libc::AF_INET {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let bytes = sin.sin_addr.s_addr.to_ne_bytes();
                    Some((
                        IpAddr::V4(std::net::Ipv4Addr::from(bytes)),
                        AddressFamily::Ipv4,
                    ))
                } else if family == libc::AF_INET6 {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let bytes = sin6.sin6_addr.s6_addr;
                    Some((
                        IpAddr::V6(std::net::Ipv6Addr::from(bytes)),
                        AddressFamily::Ipv6,
                    ))
                } else {
                    None
                };

                if let Some((ip, fam)) = addr {
                    let prefix_len = get_prefix_len(ifa.ifa_netmask, family);
                    addr_map.entry(name).or_default().push(InterfaceAddress {
                        address: ip,
                        prefix_len,
                        family: fam,
                    });
                }
            }
            cur = ifa.ifa_next;
        }

        libc::freeifaddrs(head);

        // Build result in deterministic order
        let mut result = Vec::new();
        for name in names.iter() {
            // Kernel ifindex, so route entries (which carry the kernel index)
            // resolve to the right interface name.
            let if_index = std::ffi::CString::new(name.as_str())
                .map(|c_name| libc::if_nametoindex(c_name.as_ptr()))
                .unwrap_or(0);
            let addresses = addr_map.remove(name).unwrap_or_default();
            let kind = classify_interface_linux(name);
            let is_up = *is_up_map.get(name).unwrap_or(&false);
            let state = if is_up {
                InterfaceState::Up
            } else {
                InterfaceState::Down
            };

            let mtu = read_linux_mtu(name);
            let physical = std::path::Path::new(&format!("/sys/class/net/{name}/device"))
                .symlink_metadata()
                .is_ok();
            let mac = read_linux_mac(name);
            let gateway = read_linux_gateway(name);
            let ipv6_gateway = read_linux_ipv6_gateway(name);
            let dns_suffix = read_linux_dns_suffix();
            let rx_bytes = read_linux_stat(name, "statistics/rx_bytes");
            let tx_bytes = read_linux_stat(name, "statistics/tx_bytes");
            let link_speed_mbps = read_linux_speed(name);
            let category = classify_category_linux(&kind, physical, name);

            result.push(NetworkInterface {
                name: name.clone(),
                friendly_name: name.clone(),
                kind,
                state,
                addresses,
                dns_servers: Vec::new(),
                dns_suffix,
                mtu,
                if_index,
                physical,
                mac,
                gateway,
                ipv6_gateway,
                rx_bytes,
                tx_bytes,
                link_speed_mbps,
                category,
                description: read_linux_description(name),
                if_type: read_linux_if_type(name),
                tunnel_type: None,
            });
        }

        Ok(result)
    }
}

#[cfg(target_os = "linux")]
fn get_prefix_len(netmask: *const libc::sockaddr, family: i32) -> u8 {
    if netmask.is_null() {
        return if family == libc::AF_INET { 32 } else { 128 };
    }
    if family == libc::AF_INET {
        let sin = unsafe { &*(netmask as *const libc::sockaddr_in) };
        let mask = u32::from_be(sin.sin_addr.s_addr);
        mask.count_ones() as u8
    } else if family == libc::AF_INET6 {
        let sin6 = unsafe { &*(netmask as *const libc::sockaddr_in6) };
        sin6.sin6_addr
            .s6_addr
            .iter()
            .map(|&b| b.count_ones() as u8)
            .sum()
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
fn read_linux_mtu(name: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(target_os = "linux")]
fn read_linux_mac(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00")
}

#[cfg(target_os = "linux")]
fn read_linux_stat(name: &str, stat: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/{stat}"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(target_os = "linux")]
fn read_linux_speed(name: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/speed"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(target_os = "linux")]
fn read_linux_description(name: &str) -> String {
    // /sys/class/net/<name>/device/driver symlink gives the driver name
    if let Ok(target) = std::fs::read_link(format!("/sys/class/net/{name}/device/driver")) {
        if let Some(fname) = target.file_name() {
            return format!("{} driver", fname.to_string_lossy());
        }
    }
    // Fallback: /sys/class/net/<name>/uevent has interface info
    std::fs::read_to_string(format!("/sys/class/net/{name}/uevent"))
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("INTERFACE="))
        .map(|l| l.trim_start_matches("INTERFACE=").to_string())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn read_linux_if_type(name: &str) -> u32 {
    // /sys/class/net/<name>/type contains the ARP type (1=Ethernet, 772=Loopback,
    // 801=Wifi, 6to4=42, etc.)
    std::fs::read_to_string(format!("/sys/class/net/{name}/type"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1)
}

#[cfg(target_os = "linux")]
fn read_linux_gateway(name: &str) -> Option<IpAddr> {
    // Gateway resolution via netlink is async; for the synchronous list_interfaces
    // we read /proc/net/route for the default route on this interface.
    // This is a best-effort heuristic.
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_proc_net_route_default_gateway(&routes, name).map(IpAddr::V4)
}

#[cfg(target_os = "linux")]
fn read_linux_ipv6_gateway(name: &str) -> Option<IpAddr> {
    let routes = std::fs::read_to_string("/proc/net/ipv6_route").ok()?;
    parse_proc_net_ipv6_route_default_gateway(&routes, name).map(IpAddr::V6)
}

/// Lowest-metric IPv6 default next hop on `iface` in `/proc/net/ipv6_route`
/// text (`dst dst_len src src_len next_hop metric refcnt use flags dev`, all
/// hex). The file spans every routing table, so this is a best-effort view.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_ipv6_route_default_gateway(
    text: &str,
    iface: &str,
) -> Option<std::net::Ipv6Addr> {
    const RTF_GATEWAY: u32 = 0x2;
    const RTF_REJECT: u32 = 0x200;
    let mut best: Option<(u32, std::net::Ipv6Addr)> = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || fields[9] != iface || fields[1] != "00" {
            continue;
        }
        let (Ok(destination), Ok(next_hop), Ok(metric), Ok(flags)) = (
            u128::from_str_radix(fields[0], 16),
            u128::from_str_radix(fields[4], 16),
            u32::from_str_radix(fields[5], 16),
            u32::from_str_radix(fields[8], 16),
        ) else {
            continue;
        };
        if destination != 0
            || next_hop == 0
            || flags & RTF_GATEWAY == 0
            || flags & RTF_REJECT != 0
            || best.is_some_and(|(current, _)| current <= metric)
        {
            continue;
        }
        best = Some((metric, std::net::Ipv6Addr::from(next_hop)));
    }
    best.map(|(_, gateway)| gateway)
}

/// Gateway of the first IPv4 default route on `iface` in `/proc/net/route`
/// text. The kernel prints addresses as the raw in-memory `u32` in hex, so
/// `to_ne_bytes` yields the address octets on any endianness.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_route_default_gateway(text: &str, iface: &str) -> Option<std::net::Ipv4Addr> {
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // Field 0 = Iface, 1 = Destination (0.0.0.0 for default), 2 = Gateway
        if fields[0] == iface && fields[1] == "00000000" {
            let gw_hex = fields[2];
            if gw_hex.len() == 8 {
                let gw_u32 = u32::from_str_radix(gw_hex, 16).ok()?;
                // `default dev X` has no next hop; 0.0.0.0 is not a gateway.
                if gw_u32 == 0 {
                    continue;
                }
                let bytes = gw_u32.to_ne_bytes();
                return Some(std::net::Ipv4Addr::from(bytes));
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_linux_dns_suffix() -> Option<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()?
        .lines()
        .find(|l| l.starts_with("search "))
        .map(|l| l.trim_start_matches("search ").trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn classify_interface_linux(name: &str) -> InterfaceKind {
    if name == "lo" {
        return InterfaceKind::Loopback;
    }
    // Kernel-reported link kind beats name heuristics: a WireGuard device can
    // carry any name (`ip link add dev vpn0 type wireguard`), not only `wg*`.
    if linux_devtype(name).as_deref() == Some("wireguard") {
        return InterfaceKind::WireGuard;
    }
    // tun/tap devices export `tun_flags` in sysfs; the name then hints at
    // which userspace daemon owns the device (openvpn, xray, tailscale…).
    if std::path::Path::new(&format!("/sys/class/net/{name}/tun_flags")).exists() {
        return classify_linux_tun_name(name);
    }
    classify_linux_name(name)
}

/// DEVTYPE from `/sys/class/net/<name>/uevent` (e.g. "wireguard", "wlan").
#[cfg(target_os = "linux")]
fn linux_devtype(name: &str) -> Option<String> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{name}/uevent")).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("DEVTYPE=").map(str::trim))
        .map(str::to_string)
}

/// Name-based classification for interfaces the kernel does not tag with an
/// explicit link kind.
#[cfg(any(target_os = "linux", test))]
fn classify_linux_name(name: &str) -> InterfaceKind {
    if name == "lo" {
        return InterfaceKind::Loopback;
    }
    if name.starts_with("wg") || name.contains("wireguard") {
        return InterfaceKind::WireGuard;
    }
    if name.contains("tailscale") {
        return InterfaceKind::Other("Tailscale".into());
    }
    if name.contains("openvpn") {
        return InterfaceKind::OpenVpn;
    }
    if name.starts_with("tun") || name.starts_with("tap") {
        return classify_linux_tun_name(name);
    }
    if name.starts_with("eth") || name.starts_with("en") {
        return InterfaceKind::Ethernet;
    }
    if name.starts_with("wlan") || name.starts_with("wl") || name.starts_with("wlp") {
        return InterfaceKind::Wifi;
    }
    if name.contains("xray") || name.contains("utun") {
        return InterfaceKind::Xray;
    }
    InterfaceKind::Other(name.to_string())
}

/// tun/tap device: the name hints at the owning userspace daemon.
/// Unknown `tun*`/`tap*` names stay `TUN` — guessing OpenVPN for every
/// foreign client (INCY, Happ, Mihomo, …) mislabels them in the UI.
#[cfg(any(target_os = "linux", test))]
fn classify_linux_tun_name(name: &str) -> InterfaceKind {
    let lower = name.to_lowercase();
    if lower.contains("tailscale") {
        return InterfaceKind::Other("Tailscale".into());
    }
    if lower.contains("xray") || lower.contains("sing-box") || lower.contains("singbox") {
        return InterfaceKind::Xray;
    }
    if lower.contains("openvpn") || lower.contains("ovpn") {
        return InterfaceKind::OpenVpn;
    }
    if lower.contains("mihomo") || lower.contains("clash") {
        return InterfaceKind::Other("Mihomo".into());
    }
    // INCY and Happ embed xray-core (e.g. /opt/incy/.../bin/xray,
    // /opt/happ/bin/core/xray) — they are Xray tunnels even when the
    // device name lacks an "xray" token.
    if lower.contains("incy") || lower.contains("happ") {
        return InterfaceKind::Xray;
    }
    if lower.contains("zerotier") {
        return InterfaceKind::Other("ZeroTier".into());
    }
    if lower.contains("warp") {
        return InterfaceKind::Other("WARP".into());
    }
    InterfaceKind::Other("TUN".into())
}

#[cfg(target_os = "linux")]
fn classify_category_linux(kind: &InterfaceKind, physical: bool, _name: &str) -> InterfaceCategory {
    match kind {
        InterfaceKind::Loopback => InterfaceCategory::System,
        InterfaceKind::WireGuard | InterfaceKind::OpenVpn | InterfaceKind::Xray => {
            InterfaceCategory::Vpn
        }
        InterfaceKind::Ethernet | InterfaceKind::Wifi => {
            if physical {
                InterfaceCategory::Physical
            } else {
                InterfaceCategory::Virtual
            }
        }
        InterfaceKind::Other(s) => {
            // Foreign tunnels we detected but do not manage (system wg-quick,
            // other apps' tun devices, tailscaled) belong with the VPN group
            // so conflicts surface next to our own tunnels. The set mirrors
            // the labels `classify_linux_tun_name` hands out.
            if matches!(
                s.as_str(),
                "Tailscale" | "TUN" | "Mihomo" | "ZeroTier" | "WARP"
            ) {
                InterfaceCategory::Vpn
            } else if physical {
                InterfaceCategory::Physical
            } else {
                InterfaceCategory::Virtual
            }
        }
    }
}

// ── Non-Windows/Linux stub ──────────────────────────────────────────────

#[cfg(target_os = "macos")]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    crate::macos_inventory::list_interfaces()
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "interface inventory is only implemented on Windows and Linux",
    ))
}

// ── Interface state control ─────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn windows_interface_name<'a>(
    name: &str,
    interfaces: &'a [NetworkInterface],
) -> std::io::Result<&'a str> {
    let interface = interfaces
        .iter()
        .find(|interface| interface.name.eq_ignore_ascii_case(name))
        .or_else(|| {
            let alias = name.to_lowercase();
            interfaces
                .iter()
                .find(|interface| interface.friendly_name.to_lowercase() == alias)
        })
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "network interface not found")
        })?;
    if interface.friendly_name.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "network interface has no Windows alias",
        ));
    }
    Ok(&interface.friendly_name)
}

#[cfg(target_os = "windows")]
fn netsh_interface_error(name: &str, admin: &str, output: &std::process::Output) -> std::io::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = [stderr.trim(), stdout.trim()]
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let message = format!(
        "netsh interface set interface name={name:?} admin={admin} failed ({})",
        output.status
    );
    std::io::Error::other(if details.is_empty() {
        message
    } else {
        format!("{message}: {details}")
    })
}

/// Bring an interface up or down by name.
/// Requires administrator/root privileges.
pub fn set_interface_state(name: &str, up: bool) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let action = if up { "up" } else { "down" };
        let output = std::process::Command::new("ip")
            .args(["link", "set", name, action])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "ip link set {} {}: {}",
                    name,
                    action,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        let interfaces = list_interfaces()?;
        let name = windows_interface_name(name, &interfaces)?;
        let admin = if up { "enable" } else { "disable" };
        let output = std::process::Command::new("netsh")
            .args([
                "interface",
                "set",
                "interface",
                &format!("name={name}"),
                &format!("admin={admin}"),
            ])
            .output()?;
        if !output.status.success() {
            return Err(netsh_interface_error(name, admin, &output));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (name, up);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "interface state control is only implemented on Windows and Linux",
        ))
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Reverse;
    use std::net::Ipv4Addr;

    #[cfg(target_os = "windows")]
    mod windows_interface_state {
        use super::*;
        use std::os::windows::process::ExitStatusExt;

        fn interface(name: &str, friendly_name: &str) -> NetworkInterface {
            NetworkInterface {
                name: name.into(),
                friendly_name: friendly_name.into(),
                kind: InterfaceKind::OpenVpn,
                state: InterfaceState::Down,
                addresses: vec![],
                dns_servers: vec![],
                dns_suffix: None,
                mtu: None,
                if_index: 24,
                physical: false,
                mac: None,
                gateway: None,
                ipv6_gateway: None,
                rx_bytes: None,
                tx_bytes: None,
                link_speed_mbps: None,
                category: InterfaceCategory::Vpn,
                description: String::new(),
                if_type: 6,
                tunnel_type: None,
            }
        }

        #[test]
        fn resolves_down_adapter_id_and_alias_to_friendly_name() {
            let id = "{11111111-aaaa-4111-8111-111111111111}";
            let alias = "Подключение по локальной сети 2";
            let interfaces = [interface(id, alias)];
            for name in [id.to_uppercase(), alias.to_lowercase()] {
                assert_eq!(windows_interface_name(&name, &interfaces).unwrap(), alias);
            }
        }

        #[test]
        fn adapter_id_takes_priority_over_a_matching_alias() {
            let interfaces = [
                interface("other-id", "target-id"),
                interface("target-id", "OpenVPN adapter"),
            ];
            assert_eq!(
                windows_interface_name("target-id", &interfaces).unwrap(),
                "OpenVPN adapter"
            );
        }

        #[test]
        fn rejects_unknown_adapter_and_blank_alias() {
            let interfaces = [interface("adapter-id", " ")];
            assert_eq!(
                windows_interface_name("missing-id", &interfaces)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
            assert_eq!(
                windows_interface_name("adapter-id", &interfaces)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }

        #[test]
        fn netsh_failures_keep_both_output_streams_and_exit_status() {
            for (stdout, stderr) in [
                ("Interface not found", ""),
                ("", "Access denied"),
                ("Interface not found", "Additional diagnostic"),
                (" \r\n", " \r\n"),
            ] {
                let output = std::process::Output {
                    status: std::process::ExitStatus::from_raw(5),
                    stdout: stdout.as_bytes().to_vec(),
                    stderr: stderr.as_bytes().to_vec(),
                };
                let error = netsh_interface_error("OpenVPN adapter", "enable", &output);
                let message = error.to_string();
                for diagnostic in [stdout.trim(), stderr.trim()] {
                    if !diagnostic.is_empty() {
                        assert!(message.contains(diagnostic), "{message}");
                    }
                }
                assert!(message.contains("5"), "{message}");
                assert!(!message.ends_with(": "), "{message}");
                assert_eq!(error.kind(), std::io::ErrorKind::Other);
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_route_entries_preserve_route_without_metric() {
        let destination = "192.0.2.0".parse().unwrap();
        let gateway = "192.0.2.1".parse().unwrap();
        let mut route = net_route::Route::new(destination, 24);
        route.gateway = Some(gateway);
        route.ifindex = Some(7);
        let entries = route_entries(vec![route], &HashMap::from([(7, "en0".into())]));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].destination, destination);
        assert_eq!(entries[0].prefix_len, 24);
        assert_eq!(entries[0].gateway, Some(gateway));
        assert_eq!(entries[0].interface_index, 7);
        assert_eq!(entries[0].interface_name, "en0");
        assert_eq!(entries[0].metric, 0);
    }

    #[test]
    fn proc_net_route_gateway_is_per_interface() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                    wlp2s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n\
                    enp0s3\t0002000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
                    wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route_default_gateway(text, "enp0s3"), None);
        assert_eq!(parse_proc_net_route_default_gateway(text, "wg0"), None);
        assert_eq!(
            parse_proc_net_route_default_gateway(text, "wlp2s0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn proc_net_ipv6_route_gateway_is_per_interface_and_lowest_metric() {
        let text = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlp2s0\n\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000064 00000001 00000000 00000003 wlp2s0\n\
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 wlp2s0\n\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001 wg0\n\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n\
garbage line\n";
        assert_eq!(
            parse_proc_net_ipv6_route_default_gateway(text, "wlp2s0"),
            Some("fe80::2".parse().unwrap())
        );
        assert_eq!(parse_proc_net_ipv6_route_default_gateway(text, "wg0"), None);
        assert_eq!(parse_proc_net_ipv6_route_default_gateway(text, "lo"), None);
        assert_eq!(
            parse_proc_net_ipv6_route_default_gateway(text, "enp0s3"),
            None
        );
    }

    #[test]
    fn route_entries_keep_ipv6_routes_and_interface_names() {
        let routes = vec![
            net_route::Route::new("0.0.0.0".parse().unwrap(), 0)
                .with_gateway("192.0.2.1".parse().unwrap())
                .with_ifindex(2),
            net_route::Route::new("2001:db8::".parse().unwrap(), 32).with_ifindex(7),
            net_route::Route::new("::".parse().unwrap(), 0)
                .with_gateway("fe80::1".parse().unwrap())
                .with_ifindex(2),
        ];
        let names = HashMap::from([(2, "eth0".to_string()), (7, "wg0".to_string())]);
        let entries = route_entries(routes, &names);
        assert_eq!(entries.len(), 3);
        let v6 = &entries[1];
        assert_eq!(v6.destination, "2001:db8::".parse::<IpAddr>().unwrap());
        assert_eq!(v6.prefix_len, 32);
        assert_eq!(v6.interface_index, 7);
        assert_eq!(v6.interface_name, "wg0");
        assert_eq!(entries[2].gateway, Some("fe80::1".parse().unwrap()));
        assert_eq!(entries[2].interface_name, "eth0");
    }

    #[test]
    fn longest_prefix_match_supports_ipv6_and_keeps_families_apart() {
        let entry = |dest: &str, prefix_len: u8, name: &str, metric: u32| RouteEntry {
            destination: dest.parse().unwrap(),
            prefix_len,
            gateway: None,
            interface_index: 1,
            interface_name: name.into(),
            metric,
        };
        let routes = [
            entry("0.0.0.0", 0, "eth0-v4", 100),
            entry("::", 0, "eth0", 1024),
            entry("2001:db8::", 32, "wg-slow", 50),
            entry("2001:db8::", 32, "wg0", 5),
            entry("2001:db8:1::", 48, "wg1", 500),
        ];
        let best = |dest: &str| {
            longest_prefix_match(dest.parse().unwrap(), &routes)
                .map(|route| route.interface_name.as_str())
        };
        assert_eq!(best("2001:db8:1::5"), Some("wg1"));
        assert_eq!(best("2001:db8:2::5"), Some("wg0"));
        assert_eq!(best("2606:4700::1111"), Some("eth0"));
        assert_eq!(best("8.8.8.8"), Some("eth0-v4"));
        assert_eq!(
            longest_prefix_match("8.8.8.8".parse().unwrap(), &routes[1..]),
            None
        );
    }

    #[test]
    fn longest_prefix_match_logic() {
        let routes = [
            RouteEntry {
                destination: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                prefix_len: 0,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                interface_index: 1,
                interface_name: "Wi-Fi".into(),
                metric: 25,
            },
            RouteEntry {
                destination: IpAddr::V4(Ipv4Addr::new(10, 228, 0, 0)),
                prefix_len: 16,
                gateway: None,
                interface_index: 7,
                interface_name: "WireGuard".into(),
                metric: 5,
            },
        ];

        let dest: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 228, 32, 10));
        let dest_v4 = match dest {
            IpAddr::V4(v) => v,
            _ => unreachable!(),
        };
        let best = routes
            .iter()
            .filter(|r| {
                if let IpAddr::V4(d) = r.destination {
                    let net = ipnet::Ipv4Net::new(d, r.prefix_len).unwrap();
                    net.contains(&dest_v4)
                } else {
                    false
                }
            })
            .min_by_key(|r| (Reverse(r.prefix_len), r.metric))
            .unwrap();

        assert_eq!(best.interface_name, "WireGuard");
        assert_eq!(best.prefix_len, 16);
    }

    #[test]
    fn default_route_matches_any_ip() {
        let routes = [RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: 0,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            interface_index: 1,
            interface_name: "Wi-Fi".into(),
            metric: 25,
        }];

        let dest_v4 = Ipv4Addr::new(8, 8, 8, 8);
        let net = ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap();
        assert!(net.contains(&dest_v4));

        let best = routes
            .iter()
            .filter(|r| {
                if let IpAddr::V4(d) = r.destination {
                    let net = ipnet::Ipv4Net::new(d, r.prefix_len).unwrap();
                    net.contains(&dest_v4)
                } else {
                    false
                }
            })
            .min_by_key(|r| (Reverse(r.prefix_len), r.metric))
            .unwrap();
        assert_eq!(best.interface_name, "Wi-Fi");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn list_interfaces_returns_nonempty() {
        let ifaces = list_interfaces().expect("should list interfaces");
        assert!(!ifaces.is_empty(), "Windows always has at least loopback");
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn list_routes_returns_default() {
        let routes = list_routes().await.expect("should list routes");
        assert!(
            routes.iter().any(|r| r.destination.is_unspecified()),
            "should have a default route"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_get_parser_preserves_policy_table_and_matched_prefix() {
        let dest = "198.51.100.9".parse().unwrap();
        let json =
            br#"[{"dst":"198.51.100.0/24","dev":"wg-test","table":51820,"metric":5,"flags":[]}]"#;

        let result = parse_linux_route_get(dest, json, &[]).unwrap();

        assert_eq!(result.matched_route.destination.to_string(), "198.51.100.0");
        assert_eq!(result.matched_route.prefix_len, 24);
        assert_eq!(result.matched_route.interface_name, "wg-test");
        assert_eq!(result.matched_route.metric, 5);
        assert_eq!(result.table.as_deref(), Some("51820"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_get_parser_defaults_omitted_table_to_main() {
        let dest = "1.1.1.1".parse().unwrap();
        let json = br#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","flags":[]}]"#;

        let result = parse_linux_route_get(dest, json, &[]).unwrap();

        assert_eq!(result.matched_route.destination.to_string(), "0.0.0.0");
        assert_eq!(result.matched_route.prefix_len, 0);
        assert_eq!(
            result.matched_route.gateway.unwrap().to_string(),
            "192.0.2.1"
        );
        assert_eq!(result.table.as_deref(), Some("main"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_get_parser_supports_ipv6_local_and_rejects_bad_shapes() {
        let dest = "::1".parse().unwrap();
        let json = br#"[{"type":"local","dst":"::1","dev":"lo","table":"local"}]"#;
        let result = parse_linux_route_get(dest, json, &[]).unwrap();
        assert_eq!(result.matched_route.prefix_len, 128);
        assert_eq!(result.table.as_deref(), Some("local"));

        for bad in [
            &b"[]"[..],
            &b"[{\"dst\":\"::1\",\"dev\":\"lo\"},{\"dst\":\"::1\",\"dev\":\"lo\"}]"[..],
            &b"[{\"dst\":\"1.1.1.1\",\"dev\":\"lo\"}]"[..],
            &b"[{\"dst\":\"2001:db8::/32\",\"dev\":\"lo\"}]"[..],
            &b"[{\"dst\":\"::1\",\"table\":\"local\"}]"[..],
        ] {
            assert!(parse_linux_route_get(dest, bad, &[]).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_get_parser_bounds_json_and_table_value() {
        let dest = "1.1.1.1".parse().unwrap();
        let oversized = format!(
            r#"[{{"dst":"default","dev":"eth0","padding":"{}"}}]"#,
            "x".repeat(MAX_ROUTE_GET_BYTES)
        );
        assert!(parse_linux_route_get(dest, oversized.as_bytes(), &[]).is_err());
        assert!(parse_linux_route_get(
            dest,
            br#"[{"dst":"default","dev":"eth0","table":true}]"#,
            &[]
        )
        .is_err());
    }

    #[test]
    fn linux_name_classification_recognizes_foreign_tunnels() {
        // wg-quick names are `wg*`; tailscaled names its device `tailscale0`.
        assert!(matches!(
            classify_linux_name("wg-kzn2"),
            InterfaceKind::WireGuard
        ));
        assert!(matches!(
            classify_linux_name("tailscale0"),
            InterfaceKind::Other(ref s) if s == "Tailscale"
        ));
        assert!(matches!(
            classify_linux_name("enp3s0"),
            InterfaceKind::Ethernet
        ));
        assert!(matches!(classify_linux_name("lo"), InterfaceKind::Loopback));
    }

    #[test]
    fn linux_tun_names_classify_by_owner_hint() {
        assert!(matches!(
            classify_linux_tun_name("happ-xray"),
            InterfaceKind::Xray
        ));
        assert!(matches!(
            classify_linux_tun_name("tailscale0"),
            InterfaceKind::Other(ref s) if s == "Tailscale"
        ));
        // An unrecognized tun* name is a TUN, not a guessed OpenVPN.
        assert!(matches!(
            classify_linux_tun_name("tun0"),
            InterfaceKind::Other(ref s) if s == "TUN"
        ));
        assert!(matches!(
            classify_linux_tun_name("tun-ovpn"),
            InterfaceKind::OpenVpn
        ));
        // INCY and Happ embed xray-core — they classify as Xray.
        assert!(matches!(
            classify_linux_tun_name("tun_incy"),
            InterfaceKind::Xray
        ));
        assert!(matches!(
            classify_linux_tun_name("tun-happ"),
            InterfaceKind::Xray
        ));
        assert!(matches!(
            classify_linux_tun_name("devpn"),
            InterfaceKind::Other(ref s) if s == "TUN"
        ));
    }
}
