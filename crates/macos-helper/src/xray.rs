//! Xray full-tunnel executor: owns the utun, the Xray child, the capture
//! routes and the system DNS as one unit with one journal record.
//!
//! Xray runs as the console user (never root). It receives the utun fd via
//! `XRAY_TUN_FD`; the managed binary is re-verified against the pinned
//! hashes right before launch.

use crate::dns::{self, Snapshot};
use crate::journal::{Journal, Record};
use crate::routes::{self, RouteOp};
use crate::sysexec::Runner;
use crate::tun;
use net_manager_core::daemon_protocol::{
    XrayConnectParams, XrayConnectResult, XrayDisconnectResult, XrayStatusResult,
};
use net_manager_core::models::{secondary_networks, TunnelRole, TunnelState};
use net_manager_core::xray::{apply_macos_dns_capture, apply_macos_tun_inbound, strip_tun_inbound};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// Fixed fd number Xray finds the tun on (`XRAY_TUN_FD=3`).
pub const CHILD_TUN_FD: i32 = 3;
const TERM_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Conflict(String),
    NotFound(String),
    Unavailable(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (Self::Invalid(m) | Self::Conflict(m) | Self::NotFound(m) | Self::Unavailable(m)) =
            self;
        f.write_str(m)
    }
}

fn unavailable(message: &str) -> impl FnOnce(io::Error) -> Error + '_ {
    move |_| Error::Unavailable(message.into())
}

/// A created tunnel device. Dropping it removes the interface.
pub trait TunDevice: Send {
    fn name(&self) -> &str;
    /// The descriptor handed to the child; `None` for devices without one.
    fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

impl TunDevice for tun::Utun {
    fn name(&self) -> &str {
        &self.name
    }
    fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        Some(std::os::fd::AsRawFd::as_raw_fd(&self.fd()))
    }
}

pub trait Process: Send {
    fn pid(&self) -> u32;
    /// `true` while the child is alive.
    fn alive(&mut self) -> bool;
    /// SIGTERM, wait up to `grace`, then SIGKILL; reaps the child.
    fn stop(&mut self, grace: Duration);
}

pub struct SpawnSpec<'a> {
    pub executable: &'a Path,
    pub uid: u32,
    pub config: &'a [u8],
    pub log: &'a Path,
    /// Staged geo data for `XRAY_LOCATION_ASSET`; `None` uses the files next
    /// to the executable.
    pub asset_dir: Option<&'a Path>,
}

/// Everything that needs root or a real machine.
pub trait Platform: Send + Sync {
    fn open_tun(&self, mtu: u32) -> io::Result<Box<dyn TunDevice>>;
    /// Verify and return the pinned Xray executable for `uid`.
    fn verify_xray(&self, uid: u32, data_root: Option<&str>) -> Result<PathBuf, Error>;
    fn spawn(&self, tun: &dyn TunDevice, spec: &SpawnSpec) -> io::Result<Box<dyn Process>>;
    fn resolve(&self, host: &str) -> Vec<Ipv4Addr>;
    /// Whether `pid` is still an Xray we launched (recovery only).
    fn is_our_xray(&self, pid: u32) -> bool;
    fn kill(&self, pid: u32);
    /// Pause between launching Xray and cutting traffic over to it.
    fn settle(&self) {}
}

struct Active {
    profile_id: String,
    owner_uid: u32,
    role: TunnelRole,
    record: Record,
    tun: Box<dyn TunDevice>,
    process: Box<dyn Process>,
}

pub struct XrayExecutor {
    platform: Box<dyn Platform>,
    runner: Box<dyn Runner>,
    journal: Journal,
    log: PathBuf,
    /// Where geo data overrides are staged (root-owned); none: unsupported.
    assets: Option<PathBuf>,
    active: Mutex<Option<Active>>,
}

fn is_ip(host: &str) -> Option<IpAddr> {
    host.parse().ok()
}

impl XrayExecutor {
    pub fn new(
        platform: Box<dyn Platform>,
        runner: Box<dyn Runner>,
        journal: Journal,
        log: PathBuf,
    ) -> Self {
        Self {
            platform,
            runner,
            journal,
            log,
            assets: None,
            active: Mutex::new(None),
        }
    }

    /// Serve geo data overrides, staged under `dir`.
    pub fn with_assets(mut self, dir: PathBuf) -> Self {
        self.assets = Some(dir);
        self
    }

    fn staged_assets(&self) -> Option<PathBuf> {
        self.assets.as_ref().map(|dir| dir.join("xray"))
    }

    fn clear_assets(&self) {
        if let Some(dir) = self.staged_assets() {
            crate::geo_stage::clear(&dir);
        }
    }

    pub fn log_path(&self) -> &Path {
        &self.log
    }

    fn status_of(active: &mut Active) -> XrayStatusResult {
        let running = active.process.alive();
        XrayStatusResult {
            profile_id: active.profile_id.clone(),
            state: if running {
                TunnelState::Running
            } else {
                TunnelState::Failed
            },
            interface_name: Some(active.record.interface.clone()),
            dns_applied: active.record.dns.is_some(),
            ipv4_covered: running,
            ipv6_covered: running,
            rx_bytes: None,
            tx_bytes: None,
            failover: None,
            watchdog: None,
        }
    }

    fn stopped(profile_id: &str) -> XrayStatusResult {
        XrayStatusResult {
            profile_id: profile_id.into(),
            state: TunnelState::Stopped,
            interface_name: None,
            dns_applied: false,
            ipv4_covered: false,
            ipv6_covered: false,
            rx_bytes: None,
            tx_bytes: None,
            failover: None,
            watchdog: None,
        }
    }

    /// Undo everything in reverse order. The journal is cleared only when
    /// DNS and routes are verifiably back; otherwise it stays for recovery.
    fn teardown(&self, mut active: Active) -> io::Result<()> {
        active.process.stop(TERM_GRACE);
        let dns_ok = match &active.record.dns {
            Some(snapshot) => dns::restore(&*self.runner, snapshot).is_ok(),
            None => true,
        };
        routes::remove(&*self.runner, &active.record.routes);
        drop(active.tun);
        self.clear_assets();
        if dns_ok {
            self.journal.clear()
        } else {
            Err(io::Error::other("system DNS could not be restored"))
        }
    }

    /// Reap an Xray that died on its own and undo its network changes.
    pub fn reap(&self) {
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if guard.as_mut().is_some_and(|active| !active.process.alive()) {
            if let Some(active) = guard.take() {
                let _ = self.teardown(active);
            }
        }
    }

    pub fn connect(&self, uid: u32, params: XrayConnectParams) -> Result<XrayConnectResult, Error> {
        if params.profile_id.is_empty() || params.profile_id.len() > 128 {
            return Err(Error::Invalid("invalid profile id".into()));
        }
        let base: serde_json::Value = serde_json::from_str(&params.config)
            .map_err(|_| Error::Invalid("the Xray configuration is not valid JSON".into()))?;
        if !base.is_object() {
            return Err(Error::Invalid(
                "the Xray configuration must be an object".into(),
            ));
        }
        // A secondary tunnel carries only the networks listed for it.
        let secondary = params.role == TunnelRole::Secondary;
        let networks = if secondary {
            secondary_networks(&params.routes).map_err(|message| Error::Invalid(message.into()))?
        } else {
            Vec::new()
        };
        self.reap();
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = guard.as_mut() {
            return Err(Error::Conflict(if active.profile_id == params.profile_id {
                "this connection is already running".into()
            } else {
                "another connection already owns the tunnel".into()
            }));
        }
        // A record without an owner means a previous run died mid-teardown.
        self.recover_locked()?;

        let executable = self
            .platform
            .verify_xray(uid, params.macos_data_root.as_deref())?;
        let uplink = routes::detect_uplink(&*self.runner).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                Error::Conflict(err.to_string())
            } else {
                Error::Unavailable("There is no network connection to protect".into())
            }
        })?;
        let mut bypass: Vec<Ipv4Addr> = Vec::new();
        // Resolver bypasses belong to the primary's DNS capture.
        for host in params.dns_bypass.iter().filter(|_| !secondary) {
            match is_ip(host) {
                Some(IpAddr::V4(ip)) => bypass.push(ip),
                Some(IpAddr::V6(_)) => {}
                None => bypass.extend(self.platform.resolve(host)),
            }
        }
        bypass.sort();
        bypass.dedup();

        // Read before anything is changed: the original DNS is both what the
        // direct names keep resolving through and what teardown restores.
        // A secondary tunnel never touches the system DNS.
        let snapshot = if secondary {
            None
        } else {
            dns::snapshot(&*self.runner, &uplink.interface).ok()
        };
        let (local_resolvers, local_domains) = if secondary {
            (Vec::new(), Vec::new())
        } else {
            (
                dns::local_resolvers(&*self.runner, &uplink.interface, snapshot.as_ref()),
                dns::search_domains(
                    &*self.runner,
                    &uplink.interface,
                    snapshot.as_ref().map(|s| s.service.as_str()),
                ),
            )
        };
        let config =
            apply_macos_dns_capture(&strip_tun_inbound(&base), &local_resolvers, &local_domains)
                .and_then(|doc| apply_macos_tun_inbound(&doc, tun::DEFAULT_MTU, &uplink.interface))
                .map_err(|_| {
                    Error::Invalid("the Xray configuration cannot run as a tunnel".into())
                })?;
        let config = serde_json::to_vec(&config).map_err(|_| Error::Invalid("config".into()))?;

        // Write-ahead: from here on a crash leaves a record to recover from.
        let mut record = Record {
            profile_id: params.profile_id.clone(),
            interface: String::new(),
            pid: 0,
            routes: Vec::new(),
            dns: None,
            resolver_domains: Vec::new(),
        };
        self.journal
            .save(&record)
            .map_err(unavailable("The tunnel state could not be recorded"))?;

        // `dns_touched`: the system DNS was (or may have been) changed.
        let rollback = |this: &Self, record: &Record, dns_touched: bool| {
            routes::remove(&*this.runner, &record.routes);
            if let (true, Some(snapshot)) = (dns_touched, &record.dns) {
                let _ = dns::restore(&*this.runner, snapshot);
            }
            this.clear_assets();
            let _ = this.journal.clear();
        };

        let staged = match &params.geo_assets {
            Some(assets) => {
                let Some(dir) = self.staged_assets() else {
                    rollback(self, &record, false);
                    return Err(Error::Unavailable(
                        "This helper cannot serve custom geo data".into(),
                    ));
                };
                let managed = executable.parent().unwrap_or(Path::new("/"));
                if crate::geo_stage::stage(assets, managed, uid, &dir).is_err() {
                    rollback(self, &record, false);
                    return Err(Error::Invalid("The geo data could not be prepared".into()));
                }
                Some(dir)
            }
            None => None,
        };

        let tun = self.platform.open_tun(tun::DEFAULT_MTU).map_err(|err| {
            rollback(self, &record, false);
            // The helper's stderr is its log (launchd StandardErrorPath); the
            // OS error text carries no user data.
            eprintln!("network-orchestrator-helper: tunnel device: {err}");
            if err.kind() == io::ErrorKind::PermissionDenied {
                Error::Unavailable(format!("The helper may not create a tunnel device ({err})"))
            } else {
                Error::Unavailable(format!("The tunnel device could not be created ({err})"))
            }
        })?;
        record.interface = tun.name().to_string();
        let planned = if secondary {
            routes::gateway_routes(tun::GATEWAY, tun.name(), &networks)
        } else {
            routes::plan(&uplink, tun.name(), &bypass)
        };
        // Write-ahead holds only the routes the tunnel cannot do without; the
        // optional bypasses are recorded once they exist, so teardown never
        // deletes a route that was already there.
        record.routes = planned.iter().filter(|op| !op.optional).cloned().collect();

        let mut process = self
            .platform
            .spawn(
                &*tun,
                &SpawnSpec {
                    executable: &executable,
                    uid,
                    config: &config,
                    log: &self.log,
                    asset_dir: staged.as_deref(),
                },
            )
            .map_err(|_| {
                rollback(self, &record, false);
                Error::Unavailable("Xray could not start".into())
            })?;
        record.pid = process.pid();
        // Journal the planned routes and the DNS snapshot before touching them.
        record.dns = snapshot.clone();
        if self.journal.save(&record).is_err() {
            process.stop(TERM_GRACE);
            rollback(self, &record, false);
            return Err(Error::Unavailable(
                "The tunnel state could not be recorded".into(),
            ));
        }

        // Xray exits at once on a bad config; cut traffic over only if it lives.
        self.platform.settle();
        let fail = |this: &Self,
                    process: &mut Box<dyn Process>,
                    record: &Record,
                    dns_touched: bool,
                    msg: &str| {
            process.stop(TERM_GRACE);
            rollback(this, record, dns_touched);
            Error::Unavailable(msg.into())
        };
        if !process.alive() {
            return Err(fail(
                self,
                &mut process,
                &record,
                false,
                "Xray stopped right after start",
            ));
        }
        match routes::apply(&*self.runner, &planned) {
            Ok(installed) if secondary && installed.is_empty() => {
                record.routes.clear();
                return Err(fail(
                    self,
                    &mut process,
                    &record,
                    false,
                    "None of this connection's networks could be routed",
                ));
            }
            Ok(installed) => {
                record.routes = installed;
                if self.journal.save(&record).is_err() {
                    return Err(fail(
                        self,
                        &mut process,
                        &record,
                        false,
                        "The tunnel state could not be recorded",
                    ));
                }
            }
            Err(err) => {
                eprintln!("network-orchestrator-helper: tunnel routes: {err}");
                // `apply` already removed what it added; nothing else is ours.
                record.routes.clear();
                return Err(fail(
                    self,
                    &mut process,
                    &record,
                    false,
                    &format!("The tunnel routes could not be installed ({err})"),
                ));
            }
        }
        if let Some(snapshot) = &snapshot {
            if dns::apply(&*self.runner, snapshot, &[IpAddr::V4(tun::GATEWAY)]).is_err() {
                return Err(fail(
                    self,
                    &mut process,
                    &record,
                    true,
                    "The system DNS could not be changed",
                ));
            }
        }
        let mut active = Active {
            profile_id: params.profile_id,
            owner_uid: uid,
            role: params.role,
            record,
            tun,
            process,
        };
        let status = Self::status_of(&mut active);
        *guard = Some(active);
        Ok(XrayConnectResult { status })
    }

    pub fn status(&self, uid: u32, profile_id: &str) -> XrayStatusResult {
        self.reap();
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_mut() {
            Some(active) if active.profile_id == profile_id && active.owner_uid == uid => {
                Self::status_of(active)
            }
            _ => Self::stopped(profile_id),
        }
    }

    pub fn disconnect(&self, uid: u32, profile_id: &str) -> Result<XrayDisconnectResult, Error> {
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(active) if active.profile_id == profile_id && active.owner_uid == uid => {}
            _ => return Ok(XrayDisconnectResult { stopped: false }),
        }
        let active = guard.take().expect("checked above");
        self.teardown(active).map_err(unavailable(
            "The previous DNS settings could not be restored",
        ))?;
        Ok(XrayDisconnectResult { stopped: true })
    }

    /// Whether the running tunnel is the primary one (default route and DNS).
    pub fn holds_primary(&self) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|active| active.role == TunnelRole::Primary)
    }

    /// Whether a tunnel is running right now (not just journaled).
    pub fn active(&self) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Whether a tunnel (or an unfinished one) is owned.
    pub fn owned(&self) -> Option<Record> {
        let guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .map(|active| active.record.clone())
            .or_else(|| self.journal.load().ok().flatten())
    }

    /// Undo whatever a dead helper left in the journal.
    /// A live tunnel is left to its own disconnect; only what a dead helper
    /// left in the journal is undone.
    pub fn recover(&self) -> io::Result<bool> {
        let guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(false);
        }
        self.recover_locked_io()
    }

    fn recover_locked(&self) -> Result<(), Error> {
        self.recover_locked_io()
            .map(|_| ())
            .map_err(unavailable("A previous tunnel could not be cleaned up"))
    }

    fn recover_locked_io(&self) -> io::Result<bool> {
        let Some(record) = self.journal.load()? else {
            return Ok(false);
        };
        if record.pid != 0 && self.platform.is_our_xray(record.pid) {
            self.platform.kill(record.pid);
        }
        let dns_ok = match &record.dns {
            Some(snapshot) => dns::restore(&*self.runner, snapshot).is_ok(),
            None => true,
        };
        routes::remove(&*self.runner, &record.routes);
        if dns_ok {
            self.journal.clear()?;
            Ok(true)
        } else {
            Err(io::Error::other("system DNS could not be restored"))
        }
    }

    /// Final cleanup when the helper itself shuts down.
    pub fn shutdown(&self) {
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = guard.take() {
            let _ = self.teardown(active);
        }
    }
}

pub fn route_ops(record: &Record) -> &[RouteOp] {
    &record.routes
}

pub fn snapshot_of(record: &Record) -> Option<&Snapshot> {
    record.dns.as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Uplink;
    use crate::sysexec::fake::FakeRunner;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    struct FakeTun(String);
    impl TunDevice for FakeTun {
        fn name(&self) -> &str {
            &self.0
        }
    }

    #[derive(Default)]
    struct Flags {
        alive: AtomicBool,
        stopped: AtomicBool,
        killed: AtomicU32,
        spawn_fails: AtomicBool,
        tun_fails: AtomicBool,
        dies_on_settle: AtomicBool,
        /// The staged asset directory and its `geoip.dat` as Xray saw them.
        staged: Mutex<Option<(PathBuf, Vec<u8>)>>,
    }

    struct FakeProcess(Arc<Flags>);
    impl Process for FakeProcess {
        fn pid(&self) -> u32 {
            4242
        }
        fn alive(&mut self) -> bool {
            self.0.alive.load(Ordering::SeqCst)
        }
        fn stop(&mut self, _: Duration) {
            self.0.alive.store(false, Ordering::SeqCst);
            self.0.stopped.store(true, Ordering::SeqCst);
        }
    }

    struct FakePlatform(Arc<Flags>);
    impl Platform for FakePlatform {
        fn open_tun(&self, _: u32) -> io::Result<Box<dyn TunDevice>> {
            if self.0.tun_fails.load(Ordering::SeqCst) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(Box::new(FakeTun("utun10".into())))
        }
        fn verify_xray(&self, _: u32, _: Option<&str>) -> Result<PathBuf, Error> {
            Ok(PathBuf::from("/data/backends/xray/v1/xray"))
        }
        fn spawn(&self, _: &dyn TunDevice, spec: &SpawnSpec) -> io::Result<Box<dyn Process>> {
            if self.0.spawn_fails.load(Ordering::SeqCst) {
                return Err(io::Error::other("no"));
            }
            // The helper, not the caller, decides the tun inbound.
            let doc: serde_json::Value = serde_json::from_slice(spec.config).unwrap();
            assert_eq!(doc["inbounds"][0]["protocol"], "tun");
            assert_eq!(
                doc["inbounds"][0]["settings"]["autoOutboundsInterface"],
                "en0"
            );
            self.0.alive.store(true, Ordering::SeqCst);
            *self.0.staged.lock().unwrap() = spec.asset_dir.map(|dir| {
                (
                    dir.to_path_buf(),
                    std::fs::read(dir.join("geoip.dat")).unwrap_or_default(),
                )
            });
            Ok(Box::new(FakeProcess(self.0.clone())))
        }
        fn resolve(&self, host: &str) -> Vec<Ipv4Addr> {
            if host == "dns.example" {
                vec![Ipv4Addr::new(9, 9, 9, 9)]
            } else {
                vec![]
            }
        }
        fn is_our_xray(&self, _: u32) -> bool {
            true
        }
        fn kill(&self, _: u32) {
            self.0.killed.fetch_add(1, Ordering::SeqCst);
        }
        fn settle(&self) {
            if self.0.dies_on_settle.load(Ordering::SeqCst) {
                self.0.alive.store(false, Ordering::SeqCst);
            }
        }
    }

    const ORDER: &str = "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n";

    struct Fixture {
        executor: XrayExecutor,
        flags: Arc<Flags>,
        runner: Arc<FakeRunner>,
        dir: tempfile::TempDir,
    }

    struct Shared(Arc<FakeRunner>);
    impl Runner for Shared {
        fn run(&self, program: &str, args: &[String]) -> io::Result<String> {
            self.0.run(program, args)
        }
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let flags = Arc::new(Flags::default());
        let runner = Arc::new(FakeRunner::default());
        runner.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        runner.reply("networksetup -listnetworkserviceorder", ORDER);
        runner.reply("networksetup -getdnsservers", "1.1.1.1\n");
        let executor = XrayExecutor::new(
            Box::new(FakePlatform(flags.clone())),
            Box::new(Shared(runner.clone())),
            Journal::new(dir.path()),
            dir.path().join("xray.log"),
        )
        .with_assets(dir.path().join("geo"));
        Fixture {
            executor,
            flags,
            runner,
            dir,
        }
    }

    fn params(id: &str) -> XrayConnectParams {
        XrayConnectParams {
            profile_id: id.into(),
            config: r#"{"inbounds":[{"tag":"socks-in","protocol":"socks"}],"outbounds":[{"tag":"proxy","protocol":"vless"}]}"#.into(),
            routes: vec![],
            dns_servers: vec![],
            dns_domains: vec![],
            dns_bypass: vec!["1.1.1.1".into(), "dns.example".into(), "2606::1".into()],
            interface_name: None,
            geo_assets: None,
            macos_data_root: None,
            role: Default::default(),
            failover: None,
            reject_quic: false,
            probe_url: None,
        }
    }

    #[test]
    fn connect_captures_traffic_in_order_and_disconnect_restores_everything() {
        let f = fixture();
        let result = f.executor.connect(501, params("p")).unwrap();
        assert_eq!(result.status.state, TunnelState::Running);
        assert_eq!(result.status.interface_name.as_deref(), Some("utun10"));
        assert!(result.status.dns_applied);

        let calls = f.runner.calls();
        let first_capture = calls
            .iter()
            .position(|c| c.starts_with("route -n add -net 128.0.0.0"))
            .unwrap();
        let bypass = calls
            .iter()
            .position(|c| c == "route -n add -host 1.1.1.1 -gateway 192.168.1.1")
            .unwrap();
        let dns_set = calls
            .iter()
            .position(|c| c == "networksetup -setdnsservers Wi-Fi 169.254.10.1")
            .unwrap();
        assert!(bypass < first_capture && first_capture < dns_set);
        assert!(calls.contains(&"route -n add -host 9.9.9.9 -gateway 192.168.1.1".to_string()));

        // The journal records the live tunnel.
        let record = f.executor.owned().unwrap();
        assert_eq!(record.pid, 4242);
        assert_eq!(record.interface, "utun10");

        let stopped = f.executor.disconnect(501, "p").unwrap();
        assert!(stopped.stopped);
        assert!(f.flags.stopped.load(Ordering::SeqCst));
        let calls = f.runner.calls();
        assert!(calls.contains(&"networksetup -setdnsservers Wi-Fi 1.1.1.1".to_string()));
        assert!(calls.contains(&"route -n delete -net 128.0.0.0 -netmask 128.0.0.0".to_string()));
        assert!(f.executor.owned().is_none());
        assert_eq!(f.executor.status(501, "p").state, TunnelState::Stopped);
    }

    fn with_geo(id: &str) -> XrayConnectParams {
        use base64::Engine;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        XrayConnectParams {
            geo_assets: Some(net_manager_core::daemon_protocol::XrayGeoAssets {
                geoip_dat_b64: Some(b64(b"custom-ip")),
                geosite_dat_b64: Some(b64(b"custom-site")),
            }),
            ..params(id)
        }
    }

    #[test]
    fn geo_data_is_staged_for_xray_and_removed_with_the_tunnel() {
        let f = fixture();
        f.executor.connect(501, with_geo("work")).unwrap();
        let (dir, geoip) = f.flags.staged.lock().unwrap().clone().expect("staged");
        assert_eq!(dir, f.dir.path().join("geo/xray"));
        assert_eq!(geoip, b"custom-ip");
        assert!(dir.join("geosite.dat").is_file());
        f.executor.disconnect(501, "work").unwrap();
        assert!(!dir.exists(), "disconnect removes the staged files");
        // Without overrides nothing is staged and Xray uses its own files.
        f.executor.connect(501, params("plain")).unwrap();
        assert!(f.flags.staged.lock().unwrap().is_none());
    }

    #[test]
    fn a_failed_start_leaves_no_staged_files() {
        let f = fixture();
        f.flags.spawn_fails.store(true, Ordering::SeqCst);
        assert!(f.executor.connect(501, with_geo("work")).is_err());
        assert!(!f.dir.path().join("geo/xray").exists());
    }

    #[test]
    fn a_helper_without_staging_refuses_geo_data() {
        let dir = tempfile::tempdir().unwrap();
        let flags = Arc::new(Flags::default());
        let runner = Arc::new(FakeRunner::default());
        runner.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        runner.reply("networksetup -listnetworkserviceorder", ORDER);
        runner.reply("networksetup -getdnsservers", "1.1.1.1\n");
        let executor = XrayExecutor::new(
            Box::new(FakePlatform(flags.clone())),
            Box::new(Shared(runner)),
            Journal::new(dir.path()),
            dir.path().join("xray.log"),
        );
        let error = executor.connect(501, with_geo("work")).unwrap_err();
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
        assert!(!executor.active());
    }

    #[test]
    fn a_second_connection_is_refused_while_one_owns_the_tunnel() {
        let f = fixture();
        f.executor.connect(501, params("p")).unwrap();
        for id in ["p", "q"] {
            assert!(matches!(
                f.executor.connect(501, params(id)),
                Err(Error::Conflict(_))
            ));
        }
    }

    #[test]
    fn other_users_cannot_see_or_stop_the_tunnel() {
        let f = fixture();
        f.executor.connect(501, params("p")).unwrap();
        assert_eq!(f.executor.status(502, "p").state, TunnelState::Stopped);
        assert!(!f.executor.disconnect(502, "p").unwrap().stopped);
        assert_eq!(f.executor.status(501, "p").state, TunnelState::Running);
    }

    #[test]
    fn xray_dying_at_start_changes_nothing_on_the_system() {
        let f = fixture();
        f.flags.dies_on_settle.store(true, Ordering::SeqCst);
        assert!(matches!(
            f.executor.connect(501, params("p")),
            Err(Error::Unavailable(_))
        ));
        let calls = f.runner.calls();
        assert!(!calls.iter().any(|c| c.starts_with("route -n add")));
        assert!(!calls.iter().any(|c| c.contains("-setdnsservers")));
        assert!(f.executor.owned().is_none());
    }

    #[test]
    fn route_failure_rolls_back_process_routes_and_journal() {
        let f = fixture();
        f.runner.fail("route -n add -net 8.0.0.0");
        assert!(f.executor.connect(501, params("p")).is_err());
        assert!(f.flags.stopped.load(Ordering::SeqCst));
        assert!(f
            .runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n delete")));
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.contains("-setdnsservers")));
        assert!(f.executor.owned().is_none());
    }

    #[test]
    fn dns_failure_rolls_back_routes() {
        let f = fixture();
        f.runner.fail("networksetup -setdnsservers Wi-Fi 169.254");
        assert!(f.executor.connect(501, params("p")).is_err());
        assert!(f.flags.stopped.load(Ordering::SeqCst));
        assert!(f
            .runner
            .calls()
            .contains(&"route -n delete -net 128.0.0.0 -netmask 128.0.0.0".to_string()));
        assert!(f.executor.owned().is_none());
    }

    #[test]
    fn device_and_spawn_failures_leave_no_record() {
        let f = fixture();
        f.flags.tun_fails.store(true, Ordering::SeqCst);
        assert!(f.executor.connect(501, params("p")).is_err());
        assert!(f.executor.owned().is_none());
        f.flags.tun_fails.store(false, Ordering::SeqCst);
        f.flags.spawn_fails.store(true, Ordering::SeqCst);
        assert!(f.executor.connect(501, params("p")).is_err());
        assert!(f.executor.owned().is_none());
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n add")));
    }

    #[test]
    fn reap_tears_down_after_xray_dies_on_its_own() {
        let f = fixture();
        f.executor.connect(501, params("p")).unwrap();
        f.flags.alive.store(false, Ordering::SeqCst);
        f.executor.reap();
        assert!(f.executor.owned().is_none());
        assert!(f
            .runner
            .calls()
            .contains(&"networksetup -setdnsservers Wi-Fi 1.1.1.1".to_string()));
        assert_eq!(f.executor.status(501, "p").state, TunnelState::Stopped);
    }

    #[test]
    fn recovery_leaves_a_live_tunnel_alone() {
        let f = fixture();
        f.executor.connect(501, params("p")).unwrap();
        let calls = f.runner.calls().len();
        assert!(!f.executor.recover().unwrap());
        assert_eq!(f.flags.killed.load(Ordering::SeqCst), 0);
        assert_eq!(f.runner.calls().len(), calls);
        assert!(f.executor.owned().is_some());
        assert_eq!(f.executor.status(501, "p").state, TunnelState::Running);
    }

    #[test]
    fn recovery_undoes_a_dead_helpers_tunnel() {
        let f = fixture();
        let record = Record {
            profile_id: "p".into(),
            interface: "utun10".into(),
            pid: 77,
            routes: routes::plan(
                &Uplink {
                    interface: "en0".into(),
                    gateway: None,
                },
                "utun10",
                &[],
            ),
            dns: Some(Snapshot {
                service: "Wi-Fi".into(),
                servers: vec![],
            }),
            resolver_domains: Vec::new(),
        };
        Journal::new(f.dir.path()).save(&record).unwrap();
        assert!(f.executor.recover().unwrap());
        assert_eq!(f.flags.killed.load(Ordering::SeqCst), 1);
        let calls = f.runner.calls();
        assert!(calls.contains(&"networksetup -setdnsservers Wi-Fi Empty".to_string()));
        assert!(calls.iter().any(|c| c.starts_with("route -n delete")));
        assert!(f.executor.owned().is_none());
        assert!(!f.executor.recover().unwrap());
    }

    #[test]
    fn unusable_config_is_refused_before_anything_happens() {
        let f = fixture();
        let mut bad = params("p");
        bad.config = "not json".into();
        assert!(matches!(
            f.executor.connect(501, bad),
            Err(Error::Invalid(_))
        ));
        let mut bad = params("p");
        bad.config = "[]".into();
        assert!(matches!(
            f.executor.connect(501, bad),
            Err(Error::Invalid(_))
        ));
        assert!(f.runner.calls().is_empty());
    }

    #[test]
    fn debug_of_params_never_prints_the_config() {
        let text = format!("{:?}", params("p"));
        assert!(!text.contains("vless"));
    }

    fn secondary(id: &str, networks: &[&str]) -> XrayConnectParams {
        use net_manager_core::models::PolicyRoute;
        let mut p = params(id);
        p.role = TunnelRole::Secondary;
        p.routes = networks
            .iter()
            .map(|n| PolicyRoute {
                destination: n.parse().unwrap(),
                metric: 5,
                via: None,
            })
            .collect();
        p
    }

    #[test]
    fn a_secondary_tunnel_routes_only_its_networks_and_leaves_dns_alone() {
        let f = fixture();
        let result = f
            .executor
            .connect(
                501,
                secondary("corp", &["10.10.4.0/16", "192.168.77.0/24", "fd00::/8"]),
            )
            .unwrap();
        assert_eq!(result.status.state, TunnelState::Running);
        assert!(!result.status.dns_applied);
        let calls = f.runner.calls();
        assert!(calls.contains(
            &"route -n add -net 10.10.0.0 -netmask 255.255.0.0 -gateway 169.254.10.1".to_string()
        ));
        assert!(calls.contains(
            &"route -n add -net 192.168.77.0 -netmask 255.255.255.0 -gateway 169.254.10.1"
                .to_string()
        ));
        assert!(calls.contains(
            &"route -n add -inet6 -net fd00:: -prefixlen 8 -interface utun10".to_string()
        ));
        // No default capture, no resolver bypass, no DNS change.
        assert!(!calls
            .iter()
            .any(|c| c.starts_with("route -n add -net 128.0.0.0")));
        assert!(!calls.iter().any(|c| c.contains("-host")));
        assert!(!calls
            .iter()
            .any(|c| c.contains("-setdnsservers") || c.contains("getdnsservers")));
        assert!(!f.executor.holds_primary());
        assert!(f.executor.active());

        f.executor.disconnect(501, "corp").unwrap();
        assert!(f
            .runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n delete -net 10.10.0.0")));
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.contains("-setdnsservers")));
        assert!(f.executor.owned().is_none());
    }

    #[test]
    fn a_primary_tunnel_reports_itself_as_primary() {
        let f = fixture();
        f.executor.connect(501, params("p")).unwrap();
        assert!(f.executor.holds_primary());
    }

    #[test]
    fn secondary_tunnels_need_valid_networks() {
        let f = fixture();
        for bad in [vec![], vec!["0.0.0.0/0"], vec!["::/0"], vec!["224.0.0.0/4"]] {
            assert!(
                matches!(
                    f.executor.connect(501, secondary("corp", &bad)),
                    Err(Error::Invalid(_))
                ),
                "{bad:?}"
            );
        }
        assert!(f.runner.calls().is_empty());
    }

    #[test]
    fn a_secondary_tunnel_with_no_routable_network_is_rolled_back() {
        let f = fixture();
        f.runner.fail("route -n add -net 10.10.0.0");
        let error = f
            .executor
            .connect(501, secondary("corp", &["10.10.0.0/16"]))
            .expect_err("nothing could be routed");
        assert!(matches!(error, Error::Unavailable(_)));
        assert!(f.flags.stopped.load(Ordering::SeqCst));
        assert!(f.executor.owned().is_none());
    }
}
