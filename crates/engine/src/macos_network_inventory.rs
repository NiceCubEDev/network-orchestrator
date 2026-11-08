//! Read-only inventory of routing settings a person made on this Mac:
//! persistent routes from System Settings, static kernel routes, launchd
//! jobs that run `route`, per-domain resolvers, `/etc/hosts` overrides and
//! per-service manual IP, DNS and proxy settings. Nothing here mutates the
//! system; every source is read with bounded size.
use plist::Value as Plist;
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[cfg(target_os = "macos")]
const PREFERENCES: &str = "/Library/Preferences/SystemConfiguration/preferences.plist";
#[cfg(target_os = "macos")]
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const NETWORK_TOOLS: [&str; 6] = [
    "route",
    "networksetup",
    "ifconfig",
    "pfctl",
    "scutil",
    "ipconfig",
];
const TUNNEL_PREFIXES: [&str; 4] = ["utun", "ipsec", "ppp", "tun"];

#[derive(Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserNetworkSettings {
    pub persistent_routes: Vec<PersistentRoute>,
    pub static_routes: Vec<StaticRoute>,
    pub startup_jobs: Vec<StartupJob>,
    pub resolvers: Vec<Resolver>,
    pub hosts: Vec<HostEntry>,
    pub services: Vec<ServiceSettings>,
    /// Sources that exist but could not be read, by display name.
    pub unreadable: Vec<String>,
}

/// `AdditionalRoutes` of a network service — set with
/// `networksetup -setadditionalroutes`, survives reboots.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistentRoute {
    pub service: String,
    pub interface: Option<String>,
    pub destination: String,
    pub gateway: Option<String>,
    pub active: bool,
}

/// A static entry of the live kernel table; it disappears on reboot unless
/// something re-creates it.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticRoute {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub flags: String,
    /// `persistent`, `startupJob`, `tunnel` or `command`.
    pub source: &'static str,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupJob {
    pub label: String,
    pub path: String,
    /// `daemon`, `agent` or `userAgent`.
    pub scope: &'static str,
    pub command: String,
    pub run_at_load: bool,
    pub interval_seconds: Option<u64>,
    pub route: Option<String>,
    pub active: Option<bool>,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolver {
    pub domain: String,
    pub nameservers: Vec<String>,
    pub port: Option<u16>,
    pub search_order: Option<u32>,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostEntry {
    pub address: String,
    pub names: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSettings {
    pub service: String,
    pub interface: Option<String>,
    pub enabled: bool,
    pub items: Vec<ServiceSetting>,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSetting {
    /// `ipv4Address`, `ipv4Router`, `ipv6Address`, `ipv6Router`,
    /// `dnsServers`, `searchDomains`, `httpProxy`, `httpsProxy`,
    /// `socksProxy`, `pacUrl` or `proxyAutoDiscovery`.
    pub kind: &'static str,
    pub value: String,
}

/// Raw inputs, split from the reader so parsing is testable offline.
#[derive(Default)]
pub struct Sources {
    pub preferences: Option<Plist>,
    pub netstat: Option<String>,
    /// `(domain, file text)` from `/etc/resolver`.
    pub resolvers: Vec<(String, String)>,
    pub hosts: Option<String>,
    /// `(plist path, scope, job)`.
    pub launchd: Vec<(String, &'static str, Plist)>,
    pub unreadable: Vec<String>,
}

pub fn collect(sources: Sources) -> UserNetworkSettings {
    let kernel: Vec<KernelRoute> = sources
        .netstat
        .as_deref()
        .map(parse_netstat)
        .unwrap_or_default()
        .into_iter()
        .filter(KernelRoute::is_user_static)
        .collect();
    let installed = |destination: &str| kernel.iter().any(|route| route.destination == destination);
    let mut persistent_routes = Vec::new();
    let mut services = Vec::new();
    if let Some(preferences) = &sources.preferences {
        for service in network_services(preferences) {
            persistent_routes.extend(additional_routes(service).into_iter().map(|mut route| {
                route.active = installed(&route.destination);
                route
            }));
            if let Some(settings) = service_settings(service) {
                services.push(settings);
            }
        }
    }
    let startup_jobs: Vec<StartupJob> = sources
        .launchd
        .iter()
        .filter_map(|(path, scope, job)| startup_job(path, scope, job))
        .map(|mut job| {
            job.active = job.route.as_deref().map(installed);
            job
        })
        .collect();
    let static_routes = kernel
        .into_iter()
        .map(|route| {
            let source = if persistent_routes
                .iter()
                .any(|persistent| persistent.destination == route.destination)
            {
                "persistent"
            } else if startup_jobs
                .iter()
                .any(|job| job.route.as_deref() == Some(route.destination.as_str()))
            {
                "startupJob"
            } else if TUNNEL_PREFIXES
                .iter()
                .any(|prefix| route.interface.starts_with(prefix))
            {
                "tunnel"
            } else {
                "command"
            };
            StaticRoute {
                destination: route.destination,
                gateway: route.gateway,
                interface: route.interface,
                flags: route.flags,
                source,
            }
        })
        .collect();
    UserNetworkSettings {
        persistent_routes,
        static_routes,
        startup_jobs,
        resolvers: sources
            .resolvers
            .iter()
            .map(|(domain, text)| parse_resolver(domain, text))
            .collect(),
        hosts: sources
            .hosts
            .as_deref()
            .map(parse_hosts)
            .unwrap_or_default(),
        services,
        unreadable: sources.unreadable,
    }
}

#[cfg(target_os = "macos")]
pub(super) fn read() -> UserNetworkSettings {
    let mut sources = Sources::default();
    let mut unreadable = Vec::new();
    match read_plist(Path::new(PREFERENCES)) {
        Ok(value) => sources.preferences = Some(value),
        Err(error) => note(&mut unreadable, "System network preferences", &error),
    }
    match super::native::read_command("/usr/sbin/netstat", &["-rn"], None) {
        Ok(text) => sources.netstat = Some(text),
        Err(error) => note(&mut unreadable, "Kernel routing table", &error),
    }
    match std::fs::read_dir("/etc/resolver") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let domain = entry.file_name().to_string_lossy().into_owned();
                if domain.starts_with('.') {
                    continue;
                }
                match read_text(&entry.path()) {
                    Ok(text) => sources.resolvers.push((domain, text)),
                    Err(error) => note(&mut unreadable, &format!("/etc/resolver/{domain}"), &error),
                }
            }
            sources.resolvers.sort_by(|a, b| a.0.cmp(&b.0));
        }
        Err(error) => note(&mut unreadable, "/etc/resolver", &error),
    }
    match read_text(Path::new("/etc/hosts")) {
        Ok(text) => sources.hosts = Some(text),
        Err(error) => note(&mut unreadable, "/etc/hosts", &error),
    }
    let mut folders = vec![
        (PathBuf::from("/Library/LaunchDaemons"), "daemon"),
        (PathBuf::from("/Library/LaunchAgents"), "agent"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        folders.push((Path::new(&home).join("Library/LaunchAgents"), "userAgent"));
    }
    for (folder, scope) in folders {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "plist"))
            .collect();
        paths.sort();
        for path in paths {
            // Jobs readable only by root are skipped: they are not ours to show.
            if let Ok(job) = read_plist(&path) {
                sources
                    .launchd
                    .push((path.to_string_lossy().into_owned(), scope, job));
            }
        }
    }
    sources.unreadable = unreadable;
    collect(sources)
}

/// Missing sources are simply empty; anything else is reported by name.
#[cfg(target_os = "macos")]
fn note(unreadable: &mut Vec<String>, name: &str, error: &std::io::Error) {
    if error.kind() != std::io::ErrorKind::NotFound {
        unreadable.push(name.to_string());
    }
}

#[cfg(target_os = "macos")]
fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_FILE_BYTES {
        return Err(std::io::Error::other("file is too large"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(std::io::Error::other("file is too large"));
    }
    Ok(bytes)
}

#[cfg(target_os = "macos")]
fn read_text(path: &Path) -> std::io::Result<String> {
    read_bounded(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(target_os = "macos")]
fn read_plist(path: &Path) -> std::io::Result<Plist> {
    Plist::from_reader(std::io::Cursor::new(read_bounded(path)?)).map_err(std::io::Error::other)
}

struct KernelRoute {
    destination: String,
    gateway: String,
    interface: String,
    flags: String,
}

impl KernelRoute {
    /// Static (`S`) entries that neither the kernel nor configd made:
    /// no clones, link-layer, multicast/broadcast, interface-scoped or
    /// protocol-tagged routes, no defaults, subnets or loopback.
    fn is_user_static(&self) -> bool {
        self.flags.contains('S')
            && !self
                .flags
                .contains(['W', 'L', 'm', 'b', 'I', '1', '2', '3'])
            && !self.gateway.starts_with("link#")
            && !self.interface.starts_with("lo")
    }
}

fn parse_netstat(text: &str) -> Vec<KernelRoute> {
    let mut routes = Vec::new();
    let mut in_table = false;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.first() {
            None => in_table = false,
            Some(&"Destination") => in_table = true,
            Some(&"default") => {}
            Some(destination) if in_table && fields.len() >= 4 => {
                if let Some(destination) = normalize_destination(destination, fields[2]) {
                    routes.push(KernelRoute {
                        destination,
                        gateway: fields[1].to_string(),
                        flags: fields[2].to_string(),
                        interface: fields[3].to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    routes
}

/// Expands `netstat` shorthand (`10.85/16`, `17`) to full CIDR text.
fn normalize_destination(destination: &str, flags: &str) -> Option<String> {
    let (address, prefix) = match destination.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
        None => (destination, None),
    };
    if address.contains(':') {
        let bare = address.split('%').next()?;
        bare.parse::<std::net::Ipv6Addr>().ok()?;
        let prefix = prefix.unwrap_or(128);
        return (prefix <= 128).then(|| format!("{address}/{prefix}"));
    }
    let octets = address
        .split('.')
        .map(|octet| octet.parse::<u8>().ok())
        .collect::<Option<Vec<u8>>>()?;
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    let prefix = prefix.unwrap_or(if flags.contains('H') || octets.len() == 4 {
        32
    } else {
        8 * octets.len() as u8
    });
    if prefix > 32 {
        return None;
    }
    let mut full = [0u8; 4];
    full[..octets.len()].copy_from_slice(&octets);
    Some(format!("{}/{prefix}", Ipv4Addr::from(full)))
}

fn mask_prefix(mask: &str) -> Option<u8> {
    let bits = u32::from(mask.parse::<Ipv4Addr>().ok()?);
    let ones = bits.leading_ones();
    (bits.count_ones() == ones).then_some(ones as u8)
}

fn text<'a>(value: &'a Plist, key: &str) -> Option<&'a str> {
    value.as_dictionary()?.get(key)?.as_string()
}

fn texts(value: &Plist, key: &str) -> Vec<String> {
    value
        .as_dictionary()
        .and_then(|dict| dict.get(key))
        .and_then(Plist::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_string().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn number(value: &Plist) -> Option<u64> {
    match value {
        Plist::Integer(number) => number.as_unsigned(),
        Plist::Boolean(flag) => Some(u64::from(*flag)),
        _ => None,
    }
}

fn field<'a>(value: &'a Plist, key: &str) -> Option<&'a Plist> {
    value.as_dictionary()?.get(key)
}

fn enabled(value: &Plist, key: &str) -> bool {
    field(value, key).and_then(number) == Some(1)
}

fn inactive(value: &Plist) -> bool {
    field(value, "__INACTIVE__").is_some()
}

/// Services of the preferences file, in the current set's service order.
fn network_services(preferences: &Plist) -> Vec<&Plist> {
    let Some(all) = field(preferences, "NetworkServices").and_then(Plist::as_dictionary) else {
        return Vec::new();
    };
    let order = text(preferences, "CurrentSet")
        .and_then(|set| set.strip_prefix("/Sets/"))
        .and_then(|set| field(preferences, "Sets").and_then(|sets| field(sets, set)))
        .and_then(|set| field(set, "Network"))
        .and_then(|network| field(network, "Global"))
        .and_then(|global| field(global, "IPv4"))
        .map(|ipv4| texts(ipv4, "ServiceOrder"))
        .unwrap_or_default();
    let rank: HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect();
    let mut services: Vec<(&String, &Plist)> = all.iter().collect();
    services.sort_by_key(|(id, service)| {
        (
            rank.get(id.as_str()).copied().unwrap_or(usize::MAX),
            text(service, "UserDefinedName")
                .unwrap_or_default()
                .to_string(),
        )
    });
    services.into_iter().map(|(_, service)| service).collect()
}

fn service_name(service: &Plist) -> String {
    text(service, "UserDefinedName")
        .unwrap_or("Unnamed service")
        .to_string()
}

fn service_interface(service: &Plist) -> Option<String> {
    field(service, "Interface")
        .and_then(|interface| text(interface, "DeviceName"))
        .map(str::to_string)
}

fn additional_routes(service: &Plist) -> Vec<PersistentRoute> {
    let mut routes = Vec::new();
    for family in ["IPv4", "IPv6"] {
        let Some(list) = field(service, family)
            .and_then(|config| field(config, "AdditionalRoutes"))
            .and_then(Plist::as_array)
        else {
            continue;
        };
        for route in list {
            let Some(address) = text(route, "DestinationAddress") else {
                continue;
            };
            let prefix = text(route, "SubnetMask").and_then(mask_prefix).or_else(|| {
                field(route, "PrefixLength")
                    .and_then(number)
                    .map(|n| n as u8)
            });
            let destination = match prefix {
                Some(prefix) => normalize_destination(&format!("{address}/{prefix}"), ""),
                None => normalize_destination(address, "H"),
            };
            if let Some(destination) = destination {
                routes.push(PersistentRoute {
                    service: service_name(service),
                    interface: service_interface(service),
                    destination,
                    gateway: text(route, "GatewayAddress").map(str::to_string),
                    active: false,
                });
            }
        }
    }
    routes
}

fn service_settings(service: &Plist) -> Option<ServiceSettings> {
    let mut items = Vec::new();
    let mut push = |kind: &'static str, value: String| {
        if !value.is_empty() {
            items.push(ServiceSetting { kind, value });
        }
    };
    if let Some(ipv4) = field(service, "IPv4") {
        let method = text(ipv4, "ConfigMethod").unwrap_or_default();
        if matches!(method, "Manual" | "INFORM") {
            let masks = texts(ipv4, "SubnetMasks");
            let addresses = texts(ipv4, "Addresses")
                .iter()
                .enumerate()
                .map(
                    |(index, address)| match masks.get(index).and_then(|mask| mask_prefix(mask)) {
                        Some(prefix) => format!("{address}/{prefix}"),
                        None => address.clone(),
                    },
                )
                .collect::<Vec<_>>();
            push("ipv4Address", addresses.join(", "));
            if method == "Manual" {
                push(
                    "ipv4Router",
                    text(ipv4, "Router").unwrap_or_default().into(),
                );
            }
        }
    }
    if let Some(ipv6) = field(service, "IPv6") {
        if text(ipv6, "ConfigMethod") == Some("Manual") {
            let prefixes: Vec<u64> = field(ipv6, "PrefixLength")
                .and_then(Plist::as_array)
                .map(|items| items.iter().filter_map(number).collect())
                .unwrap_or_default();
            let addresses = texts(ipv6, "Addresses")
                .iter()
                .enumerate()
                .map(|(index, address)| match prefixes.get(index) {
                    Some(prefix) => format!("{address}/{prefix}"),
                    None => address.clone(),
                })
                .collect::<Vec<_>>();
            push("ipv6Address", addresses.join(", "));
            push(
                "ipv6Router",
                text(ipv6, "Router").unwrap_or_default().into(),
            );
        }
    }
    if let Some(dns) = field(service, "DNS").filter(|dns| !inactive(dns)) {
        push("dnsServers", texts(dns, "ServerAddresses").join(", "));
        push("searchDomains", texts(dns, "SearchDomains").join(", "));
    }
    if let Some(proxies) = field(service, "Proxies").filter(|proxies| !inactive(proxies)) {
        for (kind, prefix) in [
            ("httpProxy", "HTTP"),
            ("httpsProxy", "HTTPS"),
            ("socksProxy", "SOCKS"),
        ] {
            if enabled(proxies, &format!("{prefix}Enable")) {
                let host = text(proxies, &format!("{prefix}Proxy")).unwrap_or_default();
                push(
                    kind,
                    match field(proxies, &format!("{prefix}Port")).and_then(number) {
                        Some(port) if !host.is_empty() => format!("{host}:{port}"),
                        _ => host.to_string(),
                    },
                );
            }
        }
        if enabled(proxies, "ProxyAutoConfigEnable") {
            push(
                "pacUrl",
                public_url(text(proxies, "ProxyAutoConfigURLString").unwrap_or_default()),
            );
        }
        if enabled(proxies, "ProxyAutoDiscoveryEnable") {
            push("proxyAutoDiscovery", "on".into());
        }
    }
    (!items.is_empty()).then(|| ServiceSettings {
        service: service_name(service),
        interface: service_interface(service),
        enabled: !inactive(service),
        items,
    })
}

/// Drops credentials, query and fragment, which may carry tokens.
pub(super) fn public_url(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or_default();
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = authority.rsplit('@').next().unwrap_or_default();
            format!("{scheme}://{host}{path}")
        }
        None => url.to_string(),
    }
}

fn startup_job(path: &str, scope: &'static str, job: &Plist) -> Option<StartupJob> {
    let label = text(job, "Label").map(str::to_string).or_else(|| {
        Path::new(path)
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
    })?;
    if label.starts_with("com.apple.") {
        return None;
    }
    let mut argv = texts(job, "ProgramArguments");
    if let Some(program) = text(job, "Program") {
        if argv.is_empty() {
            argv.push(program.to_string());
        } else {
            argv[0] = program.to_string();
        }
    }
    let tool = Path::new(argv.first()?)
        .file_name()?
        .to_string_lossy()
        .into_owned();
    let direct = NETWORK_TOOLS.contains(&tool.as_str());
    let mentions_route = std::iter::once(&label)
        .chain(&argv)
        .any(|value| value.to_ascii_lowercase().contains("route"));
    if !direct && !mentions_route {
        return None;
    }
    // Only route accepts public network operands. Other tools can take proxy
    // passwords, and arbitrary scripts may embed tokens in flag assignments.
    let shown: Vec<String> = argv
        .iter()
        .enumerate()
        .filter(|(index, arg)| tool == "route" || *index == 0 || arg.starts_with(['/', '-']))
        .map(|(_, arg)| {
            let arg = if arg.starts_with('-') {
                arg.split_once('=').map(|(flag, _)| flag).unwrap_or(arg)
            } else {
                arg
            };
            let arg = public_url(arg);
            if arg.contains(' ') {
                format!("\"{arg}\"")
            } else {
                arg
            }
        })
        .collect();
    let command = shown.join(" ");
    Some(StartupJob {
        label,
        path: path.to_string(),
        scope,
        command,
        run_at_load: field(job, "RunAtLoad").and_then(number) == Some(1),
        interval_seconds: field(job, "StartInterval").and_then(number),
        route: (tool == "route")
            .then(|| route_destination(&argv))
            .flatten(),
        active: None,
    })
}

/// Destination of `route [-n] add [-net|-host] DEST [GATEWAY]`.
fn route_destination(argv: &[String]) -> Option<String> {
    let add = argv.iter().position(|arg| arg == "add")?;
    let mut host = false;
    let mut netmask = None;
    let mut destination = None;
    let mut args = argv[add + 1..].iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-host" => host = true,
            "-netmask" => netmask = args.next().and_then(|mask| mask_prefix(mask)),
            "-interface" | "-ifscope" | "-ifp" | "-ifa" => {
                args.next();
            }
            flag if flag.starts_with('-') => {}
            value if destination.is_none() => destination = Some(value),
            _ => {}
        }
    }
    let destination = destination?;
    if host {
        return normalize_destination(destination, "H");
    }
    if let Some(prefix) = netmask {
        return normalize_destination(&format!("{destination}/{prefix}"), "");
    }
    if destination.contains(['/', ':']) {
        return normalize_destination(destination, "");
    }
    // Without a mask `route` uses the classful width of the given octets.
    let mut octets: Vec<&str> = destination.split('.').collect();
    while octets.len() > 1 && octets.last() == Some(&"0") {
        octets.pop();
    }
    normalize_destination(&octets.join("."), "")
}

fn parse_resolver(domain: &str, text: &str) -> Resolver {
    let mut resolver = Resolver {
        domain: domain.to_string(),
        nameservers: Vec::new(),
        port: None,
        search_order: None,
    };
    for line in text.lines() {
        let mut words = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();
        match (words.next(), words.next()) {
            (Some("nameserver"), Some(server)) => resolver.nameservers.push(server.to_string()),
            (Some("port"), Some(port)) => resolver.port = port.parse().ok(),
            (Some("search_order"), Some(order)) => resolver.search_order = order.parse().ok(),
            _ => {}
        }
    }
    resolver
}

fn parse_hosts(text: &str) -> Vec<HostEntry> {
    text.lines()
        .filter_map(|line| {
            let mut words = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace();
            let address = words.next()?.to_string();
            let names: Vec<String> = words.map(str::to_string).collect();
            let default = names
                .iter()
                .all(|name| matches!(name.as_str(), "localhost" | "broadcasthost"));
            (!default).then_some(HostEntry { address, names })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(entries: &[(&str, Plist)]) -> Plist {
        Plist::Dictionary(
            entries
                .iter()
                .map(|(key, value)| (key.to_string(), value.clone()))
                .collect(),
        )
    }
    fn s(value: &str) -> Plist {
        Plist::String(value.into())
    }
    fn arr(values: &[&str]) -> Plist {
        Plist::Array(values.iter().map(|value| s(value)).collect())
    }
    fn int(value: i64) -> Plist {
        Plist::Integer(value.into())
    }

    const NETSTAT: &str = "Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.228.32.1        UGScIg                en7
default            198.18.0.1         UGS1cIg             utun9
10.10.30.156       10.228.32.205      UGHS                  en7
10.85/16           utun100            USc               utun100
10.85.18.199       10.85.18.199       UH                utun100
10.228.32/21       link#13            UCS                   en7      !
10.228.32.1        6c:34:91:42:7d:7a  UHLWIir               en7   1197
17                 10.228.32.1        UGSc                  en7
127                127.0.0.1          UCS                   lo0
192.168.100/24     10.228.32.205      UGSc                  en7
224.0.0/4          link#13            UmCS                  en7      !

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::%utun0                            UGcIg               utun0
2001:db8::/32                           fe80::1%en7                             UGSc                  en7
fe80::%en7/64                           link#13                                 UCI                   en7
";

    fn preferences() -> Plist {
        let wired = dict(&[
            ("UserDefinedName", s("USB LAN")),
            ("Interface", dict(&[("DeviceName", s("en7"))])),
            (
                "IPv4",
                dict(&[
                    ("ConfigMethod", s("DHCP")),
                    (
                        "AdditionalRoutes",
                        Plist::Array(vec![
                            dict(&[
                                ("DestinationAddress", s("10.10.30.156")),
                                ("SubnetMask", s("255.255.255.255")),
                                ("GatewayAddress", s("10.228.32.205")),
                            ]),
                            dict(&[
                                ("DestinationAddress", s("10.20.0.0")),
                                ("SubnetMask", s("255.255.0.0")),
                            ]),
                        ]),
                    ),
                ]),
            ),
            (
                "DNS",
                dict(&[("ServerAddresses", arr(&["1.1.1.1", "8.8.8.8"]))]),
            ),
            (
                "Proxies",
                dict(&[
                    ("HTTPEnable", int(1)),
                    ("HTTPProxy", s("127.0.0.1")),
                    ("HTTPPort", int(8080)),
                    ("SOCKSEnable", int(0)),
                    ("SOCKSProxy", s("127.0.0.1")),
                    ("ProxyAutoConfigEnable", int(1)),
                    (
                        "ProxyAutoConfigURLString",
                        s("https://pac.example/proxy.pac?token=secret"),
                    ),
                ]),
            ),
        ]);
        let manual = dict(&[
            ("UserDefinedName", s("Lab")),
            ("Interface", dict(&[("DeviceName", s("en5"))])),
            (
                "IPv4",
                dict(&[
                    ("ConfigMethod", s("Manual")),
                    ("Addresses", arr(&["192.0.2.10"])),
                    ("SubnetMasks", arr(&["255.255.255.0"])),
                    ("Router", s("192.0.2.1")),
                ]),
            ),
            ("DNS", dict(&[("SearchDomains", arr(&["lab.example"]))])),
        ]);
        let untouched = dict(&[
            ("UserDefinedName", s("Wi-Fi")),
            ("Interface", dict(&[("DeviceName", s("en0"))])),
            ("IPv4", dict(&[("ConfigMethod", s("DHCP"))])),
            ("DNS", dict(&[])),
        ]);
        let vpn = dict(&[
            ("UserDefinedName", s("Corp VPN")),
            ("__INACTIVE__", int(1)),
            ("IPv4", dict(&[("ConfigMethod", s("VPN"))])),
            (
                "DNS",
                dict(&[
                    ("__INACTIVE__", int(1)),
                    ("ServerAddresses", arr(&["10.0.0.53"])),
                ]),
            ),
        ]);
        dict(&[
            ("CurrentSet", s("/Sets/SET")),
            (
                "NetworkServices",
                dict(&[("A", untouched), ("B", manual), ("C", wired), ("D", vpn)]),
            ),
            (
                "Sets",
                dict(&[(
                    "SET",
                    dict(&[(
                        "Network",
                        dict(&[(
                            "Global",
                            dict(&[("IPv4", dict(&[("ServiceOrder", arr(&["C", "B"]))]))]),
                        )]),
                    )]),
                )]),
            ),
        ])
    }

    fn job(label: &str, args: &[&str]) -> Plist {
        dict(&[
            ("Label", s(label)),
            ("ProgramArguments", arr(args)),
            ("RunAtLoad", Plist::Boolean(true)),
        ])
    }

    fn sources() -> Sources {
        Sources {
            preferences: Some(preferences()),
            netstat: Some(NETSTAT.into()),
            resolvers: vec![(
                "corp.example".into(),
                "# comment\nnameserver 10.240.4.250\nnameserver 10.1.150.10\nport 5353\nsearch_order 1\n"
                    .into(),
            )],
            hosts: Some(
                "##\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n::1 localhost\n\n\
                 31.41.241.199 asks.example # work\n203.0.113.5 a.example b.example\n"
                    .into(),
            ),
            launchd: vec![
                (
                    "/Library/LaunchDaemons/com.user.addroute.plist".into(),
                    "daemon",
                    job(
                        "com.user.addroute",
                        &["/sbin/route", "-n", "add", "-net", "192.168.100.0/24", "10.228.32.205"],
                    ),
                ),
                (
                    "/Library/LaunchDaemons/local.vpn.direct-route.plist".into(),
                    "daemon",
                    dict(&[
                        ("Label", s("local.vpn.direct-route")),
                        (
                            "ProgramArguments",
                            arr(&["/bin/bash", "/Library/Scripts/route-helper.sh", "--apply", "s3cr3t"]),
                        ),
                        ("StartInterval", int(5)),
                    ]),
                ),
                (
                    "/Library/LaunchDaemons/com.apple.route.plist".into(),
                    "daemon",
                    job("com.apple.route", &["/sbin/route", "add", "1.2.3.4", "5.6.7.8"]),
                ),
                (
                    "/Library/LaunchAgents/com.example.updater.plist".into(),
                    "agent",
                    job("com.example.updater", &["/usr/local/bin/updater"]),
                ),
            ],
            unreadable: vec![],
        }
    }

    #[test]
    fn persistent_routes_come_from_service_additional_routes() {
        let settings = collect(sources());
        assert_eq!(
            settings.persistent_routes,
            vec![
                PersistentRoute {
                    service: "USB LAN".into(),
                    interface: Some("en7".into()),
                    destination: "10.10.30.156/32".into(),
                    gateway: Some("10.228.32.205".into()),
                    active: true,
                },
                PersistentRoute {
                    service: "USB LAN".into(),
                    interface: Some("en7".into()),
                    destination: "10.20.0.0/16".into(),
                    gateway: None,
                    active: false,
                },
            ]
        );
    }

    #[test]
    fn static_routes_skip_system_entries_and_name_their_source() {
        let routes = collect(sources()).static_routes;
        let summary: Vec<_> = routes
            .iter()
            .map(|route| {
                (
                    route.destination.as_str(),
                    route.gateway.as_str(),
                    route.source,
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                ("10.10.30.156/32", "10.228.32.205", "persistent"),
                ("10.85.0.0/16", "utun100", "tunnel"),
                ("17.0.0.0/8", "10.228.32.1", "command"),
                ("192.168.100.0/24", "10.228.32.205", "startupJob"),
                ("2001:db8::/32", "fe80::1%en7", "command"),
            ]
        );
        assert_eq!(routes[0].interface, "en7");
        assert_eq!(routes[0].flags, "UGHS");
    }

    #[test]
    fn startup_jobs_list_route_tools_and_route_scripts_without_free_arguments() {
        let jobs = collect(sources()).startup_jobs;
        assert_eq!(jobs.len(), 2, "apple and unrelated jobs are skipped");
        assert_eq!(jobs[0].label, "com.user.addroute");
        assert_eq!(
            jobs[0].command,
            "/sbin/route -n add -net 192.168.100.0/24 10.228.32.205"
        );
        assert_eq!(jobs[0].route.as_deref(), Some("192.168.100.0/24"));
        assert_eq!(jobs[0].active, Some(true));
        assert!(jobs[0].run_at_load);
        assert_eq!(jobs[1].label, "local.vpn.direct-route");
        assert_eq!(
            jobs[1].command,
            "/bin/bash /Library/Scripts/route-helper.sh --apply"
        );
        assert!(!jobs[1].command.contains("s3cr3t"));
        assert_eq!(jobs[1].interval_seconds, Some(5));
        assert_eq!(jobs[1].route, None);
        assert_eq!(jobs[1].active, None);
    }

    #[test]
    fn resolvers_and_hosts_skip_comments_and_defaults() {
        let settings = collect(sources());
        assert_eq!(
            settings.resolvers,
            vec![Resolver {
                domain: "corp.example".into(),
                nameservers: vec!["10.240.4.250".into(), "10.1.150.10".into()],
                port: Some(5353),
                search_order: Some(1),
            }]
        );
        assert_eq!(
            settings.hosts,
            vec![
                HostEntry {
                    address: "31.41.241.199".into(),
                    names: vec!["asks.example".into()],
                },
                HostEntry {
                    address: "203.0.113.5".into(),
                    names: vec!["a.example".into(), "b.example".into()],
                },
            ]
        );
    }

    #[test]
    fn services_report_manual_values_in_service_order_and_hide_pac_queries() {
        let services = collect(sources()).services;
        let names: Vec<_> = services
            .iter()
            .map(|service| service.service.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["USB LAN", "Lab"],
            "untouched and inactive-only services are hidden"
        );
        let items = |index: usize| -> Vec<(&str, &str)> {
            services[index]
                .items
                .iter()
                .map(|item| (item.kind, item.value.as_str()))
                .collect()
        };
        assert_eq!(
            items(0),
            vec![
                ("dnsServers", "1.1.1.1, 8.8.8.8"),
                ("httpProxy", "127.0.0.1:8080"),
                ("pacUrl", "https://pac.example/proxy.pac"),
            ]
        );
        assert_eq!(
            items(1),
            vec![
                ("ipv4Address", "192.0.2.10/24"),
                ("ipv4Router", "192.0.2.1"),
                ("searchDomains", "lab.example"),
            ]
        );
        assert!(services.iter().all(|service| service.enabled));
    }

    #[test]
    fn missing_sources_produce_empty_sections_and_keep_unreadable_names() {
        let settings = collect(Sources {
            unreadable: vec!["/etc/hosts".into()],
            ..Sources::default()
        });
        assert_eq!(
            settings,
            UserNetworkSettings {
                unreadable: vec!["/etc/hosts".into()],
                ..UserNetworkSettings::default()
            }
        );
    }

    #[test]
    fn destinations_are_normalized_like_the_kernel_prints_them() {
        assert_eq!(
            normalize_destination("10.85/16", ""),
            Some("10.85.0.0/16".into())
        );
        assert_eq!(
            normalize_destination("17", "UGSc"),
            Some("17.0.0.0/8".into())
        );
        assert_eq!(
            normalize_destination("10.0.0.1", "UGHS"),
            Some("10.0.0.1/32".into())
        );
        assert_eq!(
            normalize_destination("2001:db8::1", "UGHS"),
            Some("2001:db8::1/128".into())
        );
        assert_eq!(normalize_destination("10.300/16", ""), None);
        assert_eq!(mask_prefix("255.255.240.0"), Some(20));
    }

    #[test]
    fn startup_commands_never_expose_proxy_passwords_or_script_flag_values() {
        let proxy = startup_job(
            "/local/proxy.plist",
            "agent",
            &job(
                "local.proxy.route",
                &[
                    "/usr/sbin/networksetup",
                    "-setsocksfirewallproxy",
                    "Wi-Fi",
                    "localhost",
                    "1080",
                    "on",
                    "alice",
                    "PRIVATE",
                ],
            ),
        )
        .unwrap();
        assert!(!proxy.command.contains("PRIVATE"));
        assert!(!proxy.command.contains("alice"));
        let script = startup_job(
            "/local/route.plist",
            "agent",
            &job(
                "local.route",
                &["/bin/sh", "/local/route.sh", "--token=PRIVATE", "--apply"],
            ),
        )
        .unwrap();
        assert!(!script.command.contains("PRIVATE"));
        assert!(script.command.contains("--apply"));
    }
}
