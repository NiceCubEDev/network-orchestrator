//! Read-only per-tunnel probes; only core may act on a recovery request.
//! True underlay changes restart the owned child, never arbitrary sockets.
use crate::egress::{
    bind_device, fingerprint, set_mark, EgressEvent, EgressSampler, EgressSignature, EgressTracker,
};
use crate::netlink::NetlinkExecutor;
use crate::xray_process::{staged_config_path, trusted_binary, verified_process_record};
use net_manager_core::dns_probe::{build_query, parse_response, DnsFamily};
use net_manager_core::models::{ConnStorm, WatchdogStatus};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const EGRESS_INTERVAL: Duration = Duration::from_secs(2);
const SETTLE_DELAY: Duration = Duration::from_secs(12);
const STALL_COOLDOWN: Duration = Duration::from_secs(600);
const EGRESS_COOLDOWN: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const STALL_LIMIT: u32 = 3;
const UDP_LIMIT: u32 = 2_000;
const STORM_LIMIT: u32 = 30;
const MAX_FDS: usize = 16_384;
const MAX_SOCKET_ROWS: usize = 65_536;

#[derive(Clone)]
pub struct WatchdogNetwork {
    pub netlink: NetlinkExecutor,
    pub runtime: tokio::runtime::Handle,
}
#[derive(Clone)]
pub struct WatchdogSpec {
    pub uid: u32,
    pub tun_name: String,
    pub tun_addr: IpAddr,
    pub mark: u32,
    pub probe_url: Option<String>,
    pub dns_servers: Vec<IpAddr>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryReason {
    Egress,
    HttpsStall,
    UdpLeak,
}
#[derive(Debug, Clone, Copy, Default)]
enum ProbeOutcome {
    #[default]
    Skipped,
    Healthy(u32),
    Stalled,
}

struct RecoveryState {
    status: WatchdogStatus,
    probe_after: Instant,
    pending_egress: bool,
    pending_stall: Option<RecoveryReason>,
    last_egress_attempt: Option<Instant>,
    last_egress_change: Option<Instant>,
    last_stall_attempt: Option<Instant>,
    stall_before_request: Option<Instant>,
    resources_unavailable: bool,
}
impl RecoveryState {
    fn new(now: Instant) -> Self {
        Self {
            status: WatchdogStatus::default(),
            probe_after: now + SETTLE_DELAY,
            pending_egress: false,
            pending_stall: None,
            last_egress_attempt: None,
            last_egress_change: None,
            last_stall_attempt: None,
            stall_before_request: None,
            resources_unavailable: false,
        }
    }
    fn egress(
        &mut self,
        event: EgressEvent,
        signature: Option<&EgressSignature>,
        now: Instant,
        unix: u64,
    ) {
        self.status.uplink = Some(signature.is_some());
        self.status.egress_signature = signature.map(fingerprint);
        if matches!(event, EgressEvent::Changed | EgressEvent::Flap) {
            self.pending_egress = true;
            self.last_egress_change = Some(now);
            self.probe_after = now + SETTLE_DELAY;
            self.status.last_egress_change_unix = Some(unix);
            self.status.https_stall_streak = 0;
            self.status.dns_stall_streak = 0;
            self.status.https_latency_ms = None;
        }
    }
    fn observe(
        &mut self,
        https: ProbeOutcome,
        dns: ProbeOutcome,
        node_reachable: bool,
        resources: Option<SocketReport>,
    ) {
        self.pending_stall = None;
        match https {
            ProbeOutcome::Healthy(latency) => {
                self.status.https_stall_streak = 0;
                self.status.https_latency_ms = Some(latency);
            }
            ProbeOutcome::Stalled => {
                self.status.https_stall_streak = self.status.https_stall_streak.saturating_add(1);
                self.status.https_latency_ms = None;
                if self.status.https_stall_streak >= STALL_LIMIT && node_reachable {
                    self.pending_stall = Some(RecoveryReason::HttpsStall);
                }
            }
            ProbeOutcome::Skipped => {}
        }
        match dns {
            ProbeOutcome::Healthy(_) => self.status.dns_stall_streak = 0,
            ProbeOutcome::Stalled => {
                self.status.dns_stall_streak = self.status.dns_stall_streak.saturating_add(1)
            }
            ProbeOutcome::Skipped => {}
        }
        self.resources_unavailable = resources.is_none();
        if let Some(resources) = resources {
            self.status.xray_udp_sockets = resources.udp_sockets;
            self.status.conn_storm = resources.storm;
            if resources.udp_sockets > UDP_LIMIT {
                self.pending_stall = Some(RecoveryReason::UdpLeak);
            }
        }
    }
    fn recovery(&mut self, now: Instant) -> Option<RecoveryReason> {
        if self.status.uplink != Some(true) {
            return None;
        }
        if self.pending_egress
            && self
                .last_egress_attempt
                .is_none_or(|last| now.duration_since(last) >= EGRESS_COOLDOWN)
        {
            self.pending_egress = false;
            self.last_egress_attempt = Some(now);
            return Some(RecoveryReason::Egress);
        }
        if self.pending_stall.is_some()
            && self
                .last_stall_attempt
                .is_none_or(|last| now.duration_since(last) >= STALL_COOLDOWN)
        {
            self.stall_before_request = self.last_stall_attempt;
            self.last_stall_attempt = Some(now);
            return self.pending_stall.take();
        }
        None
    }
    fn acknowledge(&mut self, when: Instant) {
        // A crash recovery also satisfies changes queued during its outage.
        // A newer observed change still needs recovery after the cooldown.
        if self.last_egress_change.is_none_or(|change| change <= when) {
            self.pending_egress = false;
        }
        self.pending_stall = None;
        self.last_egress_attempt = Some(when);
        self.stall_before_request = None;
        self.probe_after = when + SETTLE_DELAY;
        self.status.https_stall_streak = 0;
        self.status.dns_stall_streak = 0;
        self.status.https_latency_ms = None;
    }
    fn cancel_cleared_request(
        &mut self,
        reason: &RecoveryReason,
        https: ProbeOutcome,
        udp_sockets: Option<u32>,
    ) -> bool {
        let cleared = match reason {
            RecoveryReason::HttpsStall => matches!(https, ProbeOutcome::Healthy(_)),
            RecoveryReason::UdpLeak => udp_sockets.is_some_and(|count| count <= UDP_LIMIT),
            RecoveryReason::Egress => false,
        };
        if cleared {
            self.last_stall_attempt = self.stall_before_request.take();
        }
        cleared
    }
    fn refresh_anomalies(&mut self) {
        let anomalies = &mut self.status.anomalies;
        anomalies.clear();
        if self.status.uplink == Some(false) {
            anomalies.push("uplink-offline".into());
        }
        if self.status.uplink.is_none() {
            anomalies.push("egress-observation-unavailable".into());
        }
        if self.status.https_stall_streak >= STALL_LIMIT {
            anomalies.push("https-stalled".into());
        }
        if self.status.dns_stall_streak >= STALL_LIMIT {
            anomalies.push("dns-stalled".into());
        }
        if self.status.xray_udp_sockets > UDP_LIMIT {
            anomalies.push("udp-socket-limit".into());
        }
        if self.status.conn_storm.is_some() {
            anomalies.push("connection-storm".into());
        }
        if self.resources_unavailable {
            anomalies.push("socket-observation-unavailable".into());
        }
    }
}

struct Shared {
    status: WatchdogStatus,
    observed_at: Option<Instant>,
    request: Option<RecoveryReason>,
    recovered_at: Option<Instant>,
}
pub struct WatchdogSupervisor {
    stop: Arc<AtomicBool>,
    authorized: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
    handle: thread::JoinHandle<()>,
}
impl WatchdogSupervisor {
    pub fn spawn(spec: WatchdogSpec, network: WatchdogNetwork) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let authorized = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Mutex::new(Shared {
            status: WatchdogStatus::default(),
            observed_at: None,
            request: None,
            recovered_at: None,
        }));
        let handle = {
            let stop = Arc::clone(&stop);
            let authorized = Arc::clone(&authorized);
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("xray-watchdog".into())
                .spawn(move || {
                    if let Err(err) = run(&spec, &network, &stop, &authorized, &shared) {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        eprintln!("network-orchestrator-daemon: watchdog stopped uid={} kind={:?} os_code={:?}", spec.uid, err.kind(), err.raw_os_error());
                        authorized.store(false, Ordering::Relaxed);
                        if let Ok(mut state) = shared.lock() {
                            state.status.uplink = None;
                            state.status.anomalies = vec!["watchdog-unavailable".into()];
                        }
                    }
                })?
        };
        Ok(Self {
            stop,
            authorized,
            shared,
            handle,
        })
    }
    pub fn status(&self) -> WatchdogStatus {
        let mut status = self
            .shared
            .lock()
            .map(|state| state.status.clone())
            .unwrap_or_default();
        if status.uplink == Some(true) && !self.online() {
            status.uplink = None;
        }
        status
    }
    pub fn online(&self) -> bool {
        self.authorized.load(Ordering::Relaxed)
            && self.shared.lock().is_ok_and(|state| {
                state.status.uplink == Some(true)
                    && state
                        .observed_at
                        .is_some_and(|time| time.elapsed() < Duration::from_secs(30))
            })
    }
    pub fn take_request(&self) -> Option<RecoveryReason> {
        if !self.online() {
            return None;
        }
        self.shared.lock().ok()?.request.take()
    }
    pub fn recovered(&self, unix: u64) {
        if let Ok(mut state) = self.shared.lock() {
            state.status.last_recovery_unix = Some(unix);
            state.recovered_at = Some(Instant::now());
            state.request = None;
        }
    }
    pub fn finished(&self) -> bool {
        self.handle.is_finished()
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
impl Drop for WatchdogSupervisor {
    fn drop(&mut self) {
        // The worker is read-only, checks stop between bounded operations,
        // and owns no core reference. Detach; never join under the core lock.
        self.stop();
    }
}

pub(crate) fn checked_probe_url(text: &str) -> io::Result<String> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid HTTPS probe URL");
    if text.len() > 512 || text.chars().any(char::is_control) {
        return Err(invalid());
    }
    let url = reqwest::Url::parse(text).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(url.to_string())
}
fn probe_host(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host.to_string())
}
fn https_client(interface: &str) -> io::Result<reqwest::blocking::Client> {
    let builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        .pool_max_idle_per_host(0)
        .interface(interface);
    builder
        .build()
        .map_err(|_| io::Error::other("HTTPS prober unavailable"))
}
fn https(client: &reqwest::blocking::Client, url: &str) -> ProbeOutcome {
    let started = Instant::now();
    let result = (|| -> Result<(), (&'static str, Option<u16>)> {
        let response = client.get(url).send().map_err(|error| {
            let reason = if error.is_timeout() {
                "timeout"
            } else if error.is_connect() {
                "connect"
            } else {
                "request"
            };
            (reason, None)
        })?;
        if !response.status().is_success() {
            return Err(("http_status", Some(response.status().as_u16())));
        }
        // A bounded prefix is enough to prove the TLS/HTTP path, not the
        // integrity of an arbitrary site's entire response body.
        io::copy(&mut response.take(64 * 1024), &mut io::sink())
            .map_err(|_| ("body_read", None))?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            crate::diagnostic_logging::trace(format_args!(
                "watchdog https outcome=healthy duration_ms={}",
                started.elapsed().as_millis()
            ));
            ProbeOutcome::Healthy(started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32)
        }
        Err((reason, status)) => {
            crate::diagnostic_logging::debug(format_args!("watchdog https outcome=stalled reason={reason} http_status={status:?} duration_ms={}", started.elapsed().as_millis()));
            ProbeOutcome::Stalled
        }
    }
}
fn dns_probe(interface: &str, server: IpAddr, hostname: &str) -> ProbeOutcome {
    static NEXT_ID: AtomicU16 = AtomicU16::new(1);
    let started = Instant::now();
    let result = (|| -> io::Result<()> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let query = build_query(hostname, DnsFamily::A, id)
            .ok_or_else(|| io::Error::other("invalid DNS probe name"))?;
        let socket = UdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        bind_device(socket.as_raw_fd(), interface)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        socket.connect(SocketAddr::new(server, 53))?;
        socket.send(&query)?;
        let mut bytes = [0u8; 4096];
        let length = socket.recv(&mut bytes)?;
        let reply = parse_response(&bytes[..length], id)?;
        if reply.truncated
            || reply.status != "NOERROR"
            || !reply
                .answers
                .iter()
                .any(|answer| answer.split_whitespace().nth(2) == Some("A"))
        {
            return Err(io::Error::other("DNS probe failed"));
        }
        Ok(())
    })();
    if result.is_ok() {
        ProbeOutcome::Healthy(started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32)
    } else {
        ProbeOutcome::Stalled
    }
}

fn node_address(outbound: &Value) -> Option<SocketAddr> {
    if outbound["protocol"] != "vless" {
        return None;
    }
    let server = outbound.pointer("/settings/vnext/0")?;
    Some(SocketAddr::new(
        server["address"].as_str()?.parse().ok()?,
        u16::try_from(server["port"].as_u64()?).ok()?,
    ))
}
fn tcp_reachable(
    network: &WatchdogNetwork,
    address: SocketAddr,
    mark: u32,
    source: &EgressSignature,
) -> bool {
    let Some(path) = source
        .paths
        .iter()
        .find(|path| path.source.is_ipv4() == address.is_ipv4())
    else {
        return false;
    };
    network.runtime.block_on(async {
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        };
        let Ok(socket) = socket else { return false };
        if set_mark(socket.as_raw_fd(), mark).is_err() {
            return false;
        }
        if socket.bind(SocketAddr::new(path.source, 0)).is_err() {
            return false;
        }
        tokio::time::timeout(Duration::from_secs(1), socket.connect(address))
            .await
            .is_ok_and(|result| result.is_ok())
    })
}
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}
fn run(
    spec: &WatchdogSpec,
    network: &WatchdogNetwork,
    stop: &Arc<AtomicBool>,
    authorized: &Arc<AtomicBool>,
    shared: &Arc<Mutex<Shared>>,
) -> io::Result<()> {
    let binary = trusted_binary()?;
    let config_path = staged_config_path(spec.uid, &spec.tun_name)?;
    let metadata = fs::symlink_metadata(&config_path)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() > crate::xray::MAX_XRAY_CONFIG_BYTES as u64
    {
        return Err(io::Error::other("Xray probe configuration is unsafe"));
    }

    let mut bytes = Vec::new();
    File::open(&config_path)?
        .take(crate::xray::MAX_XRAY_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > crate::xray::MAX_XRAY_CONFIG_BYTES {
        return Err(io::Error::other("Xray probe configuration exceeds limit"));
    }
    let config: Value = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::other("Xray probe configuration invalid"))?;
    let outbounds = config["outbounds"]
        .as_array()
        .ok_or_else(|| io::Error::other("Xray probe targets unavailable"))?;
    let nodes: Vec<_> = outbounds.iter().filter_map(node_address).collect();
    let targets: Vec<_> = outbounds
        .iter()
        .filter_map(|outbound| {
            node_address(outbound)
                .map(|address| address.ip())
                .or_else(|| {
                    outbound
                        .pointer("/settings/address")?
                        .as_str()?
                        .parse::<IpAddr>()
                        .ok()
                })
        })
        .collect();
    let dns_servers: Vec<IpAddr> = if spec.dns_servers.is_empty() {
        config
            .pointer("/dns/servers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry
                    .get("port")
                    .is_none_or(|port| port.as_u64() == Some(53))
            })
            .filter_map(|entry| entry.as_str().or_else(|| entry.get("address")?.as_str()))
            .filter_map(|address| address.parse::<IpAddr>().ok())
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
            .take(8)
            .collect()
    } else {
        spec.dns_servers.clone()
    };
    drop(config);
    drop(bytes);
    let mut sampler = EgressSampler::new(
        network.netlink.clone(),
        &network.runtime,
        spec.mark,
        spec.tun_name.clone(),
        targets,
        Arc::clone(authorized),
    )?;
    let client = spec
        .probe_url
        .as_ref()
        .map(|_| https_client(&spec.tun_name))
        .transpose()?;
    let hostname = spec.probe_url.as_deref().and_then(probe_host);
    let mut tracker = EgressTracker::new();
    let mut state = RecoveryState::new(Instant::now());
    let mut next_egress = Instant::now();
    let mut next_probe = Instant::now();
    let mut rotation = 0usize;
    let mut acknowledged = None;
    while !stop.load(Ordering::Relaxed) {
        sync_recovery(&mut state, &mut acknowledged, shared);
        let now = Instant::now();
        if now >= next_egress {
            match sampler.sample() {
                Ok(sample) => {
                    let event = tracker.observe(&sample);
                    state.egress(event, sample.signature.as_ref(), Instant::now(), unix_now());
                    authorized.store(sample.signature.is_some(), Ordering::Relaxed);
                    if let Ok(mut shared) = shared.lock() {
                        shared.observed_at = Some(Instant::now());
                    }
                }
                Err(_) => {
                    state.status.uplink = None;
                    authorized.store(false, Ordering::Relaxed);
                }
            }
            next_egress = Instant::now() + EGRESS_INTERVAL;
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if now >= next_probe && now >= state.probe_after {
            let online = state.status.uplink == Some(true) && authorized.load(Ordering::Relaxed);
            let mut https_result = ProbeOutcome::Skipped;
            let mut dns_result = ProbeOutcome::Skipped;
            let mut node_reachable = false;
            if online {
                if let (Some(client), Some(url)) = (&client, &spec.probe_url) {
                    https_result = https(client, url);
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if let (Some(name), Some(server)) = (
                    &hostname,
                    dns_servers.get(rotation % dns_servers.len().max(1)),
                ) {
                    dns_result = dns_probe(&spec.tun_name, *server, name);
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if matches!(https_result, ProbeOutcome::Stalled) {
                    if let Some(signature) = tracker.signature() {
                        for offset in 0..nodes.len().min(2) {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            if tcp_reachable(
                                network,
                                nodes[(rotation + offset) % nodes.len()],
                                spec.mark,
                                signature,
                            ) {
                                node_reachable = true;
                                break;
                            }
                        }
                    }
                }
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let resources = socket_report(spec, &binary).ok();
            // Discard results from a child that core replaced mid-round.
            if sync_recovery(&mut state, &mut acknowledged, shared) {
                continue;
            }
            let udp_sockets = resources.as_ref().map(|report| report.udp_sockets);
            crate::diagnostic_logging::trace(format_args!("watchdog observation online={online} https={https_result:?} dns={dns_result:?} node_reachable={node_reachable} udp_sockets={udp_sockets:?}"));
            state.observe(https_result, dns_result, node_reachable, resources);
            if let Ok(mut published) = shared.lock() {
                if let Some(reason) = published.request.as_ref() {
                    if state.cancel_cleared_request(reason, https_result, udp_sockets) {
                        eprintln!("network-orchestrator-daemon: watchdog recovery cancelled uid={} reason={reason:?}", spec.uid);
                        published.request = None;
                    }
                }
            }
            rotation = rotation.wrapping_add(1);
            next_probe = Instant::now() + PROBE_INTERVAL;
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        state.refresh_anomalies();
        if let Ok(mut shared) = shared.lock() {
            if shared.recovered_at != acknowledged {
                continue;
            }
            state.status.last_recovery_unix = shared.status.last_recovery_unix;
            shared.status = state.status.clone();
            if shared.request.is_none() && authorized.load(Ordering::Relaxed) {
                shared.request = state.recovery(Instant::now());
                if let Some(reason) = &shared.request {
                    eprintln!("network-orchestrator-daemon: watchdog recovery requested uid={} reason={reason:?}", spec.uid);
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn sync_recovery(
    state: &mut RecoveryState,
    acknowledged: &mut Option<Instant>,
    shared: &Mutex<Shared>,
) -> bool {
    let current = shared.lock().ok().and_then(|shared| shared.recovered_at);
    if current == *acknowledged {
        return false;
    }
    if let Some(when) = current {
        state.acknowledge(when);
    }
    *acknowledged = current;
    true
}

#[derive(Default)]
struct SocketReport {
    udp_sockets: u32,
    storm: Option<ConnStorm>,
}
#[derive(Debug)]
struct SocketRow {
    local: SocketAddr,
    remote: SocketAddr,
    state: u8,
    inode: u64,
}
fn proc_address(field: &str) -> Option<SocketAddr> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if address.len() == 8 {
        IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(address, 16).ok()?.to_ne_bytes(),
        ))
    } else if address.len() == 32 {
        let mut octets = [0u8; 16];
        for index in 0..4 {
            octets[index * 4..index * 4 + 4].copy_from_slice(
                &u32::from_str_radix(&address[index * 8..index * 8 + 8], 16)
                    .ok()?
                    .to_ne_bytes(),
            );
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        return None;
    };
    Some(SocketAddr::new(ip, port))
}
fn socket_row(line: &str) -> Option<SocketRow> {
    let mut fields = line.split_whitespace();
    fields.next()?;
    let local = proc_address(fields.next()?)?;
    let remote = proc_address(fields.next()?)?;
    let state = u8::from_str_radix(fields.next()?, 16).ok()?;
    let inode = fields.nth(5)?.parse().ok()?;
    Some(SocketRow {
        local,
        remote,
        state,
        inode,
    })
}
fn table_rows(path: &Path, mut observe: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    for _ in 0..MAX_SOCKET_ROWS {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line.len() > 4096 {
            return Err(io::Error::other("socket observation row exceeds limit"));
        }
        observe(&line)?;
    }
    Err(io::Error::other("socket observation exceeds limit"))
}
fn socket_inodes(pid: u32) -> io::Result<HashSet<u64>> {
    let mut inodes = HashSet::new();
    for (index, entry) in fs::read_dir(format!("/proc/{pid}/fd"))?.enumerate() {
        if index >= MAX_FDS {
            return Err(io::Error::other(
                "socket descriptor observation exceeds limit",
            ));
        }
        let entry = entry?;
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if let Some(inode) = target
            .to_str()
            .and_then(|name| name.strip_prefix("socket:["))
            .and_then(|name| name.strip_suffix(']'))
            .and_then(|name| name.parse().ok())
        {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}
fn process_name(uid: u32, inode: u64) -> Option<String> {
    let deadline = Instant::now() + Duration::from_millis(100);
    let target = format!("socket:[{inode}]");
    for (index, process) in fs::read_dir("/proc").ok()?.flatten().enumerate() {
        if index >= 4096 || Instant::now() >= deadline {
            return None;
        }
        if process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        let Ok(metadata) = process.metadata() else {
            continue;
        };
        if metadata.uid() != uid {
            continue;
        }
        let Ok(descriptors) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.take(MAX_FDS).flatten() {
            if Instant::now() >= deadline {
                return None;
            }
            if fs::read_link(descriptor.path())
                .is_ok_and(|link| link.as_os_str() == target.as_str())
            {
                let mut bytes = String::new();
                File::open(process.path().join("comm"))
                    .ok()?
                    .take(64)
                    .read_to_string(&mut bytes)
                    .ok()?;
                let name = bytes.trim();
                return (!name.is_empty() && !name.chars().any(char::is_control))
                    .then(|| name.to_string());
            }
        }
    }
    None
}
fn socket_report(spec: &WatchdogSpec, binary: &Path) -> io::Result<SocketReport> {
    let process = verified_process_record(spec.uid, &spec.tun_name, binary)?
        .ok_or_else(|| io::Error::other("owned Xray process unavailable"))?;
    let inodes = socket_inodes(process.pid)?;
    let mut report = SocketReport::default();
    let mut destinations: HashMap<IpAddr, (u32, u64)> = HashMap::new();
    for file in ["udp", "udp6"] {
        table_rows(
            &std::path::PathBuf::from(format!("/proc/{}/net/{file}", process.pid)),
            |row| {
                if row
                    .split_whitespace()
                    .nth(9)
                    .and_then(|inode| inode.parse::<u64>().ok())
                    .is_some_and(|inode| inodes.contains(&inode))
                {
                    report.udp_sockets = report.udp_sockets.saturating_add(1);
                }
                Ok(())
            },
        )?;
    }
    for file in ["tcp", "tcp6"] {
        table_rows(
            &std::path::PathBuf::from(format!("/proc/{}/net/{file}", process.pid)),
            |row| {
                let Some(row) = socket_row(row) else {
                    return Ok(());
                };
                if row.state == 1 && row.local.ip() == spec.tun_addr {
                    if destinations.len() >= 4096 && !destinations.contains_key(&row.remote.ip()) {
                        return Err(io::Error::other("connection observation exceeds limit"));
                    }
                    let entry = destinations
                        .entry(row.remote.ip())
                        .or_insert((0, row.inode));
                    entry.0 = entry.0.saturating_add(1);
                }
                Ok(())
            },
        )?;
    }
    if verified_process_record(spec.uid, &spec.tun_name, binary)?.as_ref() != Some(&process) {
        return Err(io::Error::other("Xray process changed during observation"));
    }
    if let Some((destination, (count, inode))) = destinations
        .into_iter()
        .max_by_key(|(_, (count, _))| *count)
        .filter(|(_, (count, _))| *count > STORM_LIMIT)
    {
        report.storm = Some(ConnStorm {
            destination: destination.to_string(),
            process: process_name(spec.uid, inode),
            count,
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn online(state: &mut RecoveryState, now: Instant) {
        state.status.uplink = Some(true);
        state.probe_after = now;
    }
    #[test]
    fn node_outage_does_not_restart_xray_but_stalled_process_does_with_cooldown() {
        let now = Instant::now();
        let mut state = RecoveryState::new(now);
        online(&mut state, now);
        for _ in 0..3 {
            state.observe(
                ProbeOutcome::Stalled,
                ProbeOutcome::Skipped,
                false,
                Some(SocketReport::default()),
            );
        }
        assert_eq!(state.recovery(now), None);
        state.observe(
            ProbeOutcome::Stalled,
            ProbeOutcome::Skipped,
            true,
            Some(SocketReport::default()),
        );
        assert_eq!(state.recovery(now), Some(RecoveryReason::HttpsStall));
        state.observe(
            ProbeOutcome::Stalled,
            ProbeOutcome::Skipped,
            true,
            Some(SocketReport::default()),
        );
        assert_eq!(state.recovery(now + Duration::from_secs(599)), None);
        assert_eq!(
            state.recovery(now + STALL_COOLDOWN),
            Some(RecoveryReason::HttpsStall)
        );
    }
    #[test]
    fn offline_guard_defers_egress_recovery_and_churn_is_rate_limited() {
        let now = Instant::now();
        let mut state = RecoveryState::new(now);
        let signature = EgressSignature { paths: Vec::new() };
        state.egress(EgressEvent::Changed, Some(&signature), now, 1000);
        state.egress(EgressEvent::Lost, None, now, 1001);
        assert_eq!(state.recovery(now), None);
        state.egress(EgressEvent::Flap, Some(&signature), now, 1002);
        assert_eq!(state.recovery(now), Some(RecoveryReason::Egress));
        assert_eq!(state.probe_after, now + SETTLE_DELAY);
        state.egress(EgressEvent::Changed, Some(&signature), now, 1003);
        assert_eq!(state.recovery(now + Duration::from_secs(59)), None);
        assert_eq!(
            state.recovery(now + EGRESS_COOLDOWN),
            Some(RecoveryReason::Egress)
        );
    }
    #[test]
    fn crash_acknowledgment_does_not_spend_the_stall_recovery_budget() {
        let now = Instant::now();
        let mut state = RecoveryState::new(now);
        online(&mut state, now);
        state.acknowledge(now);
        for _ in 0..STALL_LIMIT {
            state.observe(
                ProbeOutcome::Stalled,
                ProbeOutcome::Skipped,
                true,
                Some(SocketReport::default()),
            );
        }
        assert_eq!(
            state.recovery(now + SETTLE_DELAY),
            Some(RecoveryReason::HttpsStall)
        );
    }
    #[test]
    fn fresh_positive_proof_cancels_only_its_own_stall_without_spending_cooldown() {
        let now = Instant::now();
        let mut state = RecoveryState::new(now);
        online(&mut state, now);
        for _ in 0..STALL_LIMIT {
            state.observe(
                ProbeOutcome::Stalled,
                ProbeOutcome::Skipped,
                true,
                Some(SocketReport::default()),
            );
        }
        let reason = state.recovery(now).unwrap();
        assert!(!state.cancel_cleared_request(&reason, ProbeOutcome::Skipped, Some(0)));
        assert!(state.cancel_cleared_request(&reason, ProbeOutcome::Healthy(2), Some(0)));
        for _ in 0..STALL_LIMIT {
            state.observe(
                ProbeOutcome::Stalled,
                ProbeOutcome::Skipped,
                true,
                Some(SocketReport::default()),
            );
        }
        assert_eq!(
            state.recovery(now + Duration::from_secs(5)),
            Some(RecoveryReason::HttpsStall)
        );
        assert!(!state.cancel_cleared_request(
            &RecoveryReason::Egress,
            ProbeOutcome::Healthy(1),
            Some(0)
        ));
    }
    #[test]
    fn crash_respawn_satisfies_deferred_egress_but_not_a_newer_change() {
        let now = Instant::now();
        let mut state = RecoveryState::new(now);
        let signature = EgressSignature { paths: Vec::new() };
        state.egress(EgressEvent::Changed, Some(&signature), now, 1000);
        assert_eq!(state.recovery(now), Some(RecoveryReason::Egress));
        state.egress(
            EgressEvent::Flap,
            Some(&signature),
            now + Duration::from_secs(20),
            1020,
        );
        state.acknowledge(now + Duration::from_secs(25));
        assert_eq!(state.recovery(now + Duration::from_secs(120)), None);
        state.egress(
            EgressEvent::Changed,
            Some(&signature),
            now + Duration::from_secs(130),
            1130,
        );
        state.acknowledge(now + Duration::from_secs(125));
        assert_eq!(
            state.recovery(now + Duration::from_secs(185)),
            Some(RecoveryReason::Egress)
        );
    }
    #[test]
    fn resource_thresholds_and_anomalies_clear_after_recovery() {
        let now = Instant::now();
        let mut state = RecoveryState::new(now);
        online(&mut state, now);
        state.observe(
            ProbeOutcome::Skipped,
            ProbeOutcome::Stalled,
            false,
            Some(SocketReport {
                udp_sockets: UDP_LIMIT,
                storm: None,
            }),
        );
        assert_eq!(state.recovery(now), None);
        state.observe(
            ProbeOutcome::Skipped,
            ProbeOutcome::Stalled,
            false,
            Some(SocketReport {
                udp_sockets: UDP_LIMIT + 1,
                storm: None,
            }),
        );
        assert_eq!(state.recovery(now), Some(RecoveryReason::UdpLeak));
        state.refresh_anomalies();
        assert!(state.status.anomalies.contains(&"udp-socket-limit".into()));
        state.observe(
            ProbeOutcome::Healthy(5),
            ProbeOutcome::Healthy(2),
            false,
            Some(SocketReport::default()),
        );
        state.refresh_anomalies();
        assert!(state.status.anomalies.is_empty());
        assert_eq!(state.status.https_latency_ms, Some(5));
    }
    #[test]
    fn url_validation_rejects_credentials_and_parses_ipv6_without_dns_queries() {
        assert_eq!(
            probe_host("https://example.test:9443/path"),
            Some("example.test".into())
        );
        assert_eq!(probe_host("https://[2001:db8::1]:8443/x"), None);
        for url in [
            "http://example.test",
            "https://user:secret@example.test",
            "https://example.test/#fragment",
        ] {
            assert!(checked_probe_url(url).is_err());
        }
    }
    #[test]
    fn proc_rows_preserve_native_endian_addresses_and_inode_identity() {
        let row = socket_row(
            "0: 0100007F:1F90 0200007F:AA00 01 00000000:00000000 00:00000000 00000000 1000 0 111 1",
        )
        .unwrap();
        assert_eq!(row.local, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(row.remote, "127.0.0.2:43520".parse().unwrap());
        assert_eq!(row.inode, 111);
        assert_eq!(
            proc_address("00000000000000000000000001000000:0035"),
            Some("[::1]:53".parse().unwrap())
        );
    }
}
