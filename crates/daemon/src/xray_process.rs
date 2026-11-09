use std::io;

#[cfg(target_os = "linux")]
use crate::xray::MAX_XRAY_CONFIG_BYTES;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::{self, DirBuilder, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::openvpn::runtime_root;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BINARY_ROOT: &str = "/usr/lib/network-orchestrator/xray";
#[cfg(target_os = "linux")]
const LINK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const STOP_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounded slice of `xray.log` surfaced in errors / the daemon journal.
#[cfg(target_os = "linux")]
const LOG_TAIL_BYTES: u64 = 4 * 1024;

pub trait XrayProcessRunner: Send {
    fn verify_binary(&self) -> io::Result<()>;
    fn link_index(&self, name: &str) -> io::Result<Option<u32>>;
    /// `geo_assets` optionally carries caller-provided `geoip.dat`/
    /// `geosite.dat` contents (base64); they are staged into the root-owned
    /// runtime directory before spawn.
    fn start(
        &mut self,
        uid: u32,
        name: &str,
        config: &str,
        geo_assets: Option<&net_manager_core::daemon_protocol::XrayGeoAssets>,
    ) -> io::Result<()>;
    /// Restart the child in place, reusing the already staged config and geo
    /// assets. Runners without respawn support keep the default failure, and
    /// the reconciler then tears the tunnel down as before.
    fn respawn(&mut self, uid: u32, name: &str) -> io::Result<()> {
        let _ = (uid, name);
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Xray respawn is unsupported",
        ))
    }
    /// Swap the staged `config.json` (and staged geo assets when supplied) and
    /// restart the child on the same staging directory. The TUN link briefly
    /// disappears and comes back with a fresh ifindex; the caller re-applies
    /// link-scoped resources once it reappears.
    fn reload(
        &mut self,
        uid: u32,
        name: &str,
        config: &str,
        geo_assets: Option<&net_manager_core::daemon_protocol::XrayGeoAssets>,
    ) -> io::Result<()> {
        let _ = (uid, name, config, geo_assets);
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Xray reload is unsupported",
        ))
    }
    fn health(&mut self, name: &str) -> io::Result<bool>;
    /// `(rx, tx)` bytes seen by the TUN inbound. The primary source is the
    /// link's sysfs counters (a statsquery subprocess per poll is too slow
    /// to run while the core mutex is held); the local StatsService
    /// dokodemo door on `api_port` is the fallback when link stats are
    /// missing. Runners without stats support keep the default failure and
    /// the caller reports `None`.
    fn query_stats(&mut self, name: &str, api_port: u16) -> io::Result<(u64, u64)> {
        let _ = (name, api_port);
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Xray statsquery is unsupported",
        ))
    }
    fn stop(&mut self, name: &str) -> io::Result<()>;
    fn cleanup(&mut self, uid: u32, name: &str) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
pub struct TrustedXrayProcess {
    children: HashMap<String, (u32, Child)>,
}

#[cfg(target_os = "linux")]
impl TrustedXrayProcess {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }

    /// Spawn the managed binary against `config_path`, redirect both output
    /// streams to `xray.log` (`fresh` truncates/creates, append mode
    /// otherwise), then wait for the TUN link and record `pid starttime`.
    fn spawn_xray_child(
        &self,
        binary: &Path,
        directory: &Path,
        config_path: &Path,
        asset_dir: &Path,
        name: &str,
        fresh_log: bool,
    ) -> io::Result<Child> {
        let log_path = directory.join("xray.log");
        let log = open_log_file(&log_path, fresh_log)?;
        let log_stdout = log
            .try_clone()
            .map_err(|_| io::Error::other("Xray log creation failed"))?;
        let mut child = Command::new(binary)
            .args(xray_args(config_path))
            .env_clear()
            .env("XRAY_LOCATION_ASSET", asset_dir)
            .stdin(Stdio::null())
            // Xray logs to stdout and panic/trace output lands on stderr;
            // keep both so failures are diagnosable after the fact.
            .stdout(Stdio::from(log_stdout))
            .stderr(Stdio::from(log))
            .current_dir(directory)
            .spawn()
            .map_err(|err| {
                eprintln!(
                    "network-orchestrator-daemon: xray spawn failed kind={:?} os_code={:?}",
                    err.kind(),
                    err.raw_os_error()
                );
                io::Error::other("Xray launch failed")
            })?;
        eprintln!(
            "network-orchestrator-daemon: xray spawned pid={}",
            child.id()
        );
        let started = (|| {
            let starttime = read_starttime(child.id())?;
            rewrite_private_file(
                &directory.join("process"),
                format!("{} {starttime}\n", child.id()).as_bytes(),
            )?;
            let deadline = Instant::now() + LINK_TIMEOUT;
            loop {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|_| io::Error::other("Xray child check failed"))?
                {
                    eprintln!("network-orchestrator-daemon: xray unexpected exit phase=start pid={} code={:?} signal={:?}", child.id(), status.code(), status.signal());
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Xray exited before interface appeared",
                    ));
                }
                if self.link_index(name)?.is_some() {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Xray interface did not appear",
                    ));
                }
                thread::sleep(Duration::from_millis(25));
            }
        })();
        if let Err(error) = started {
            let _ = terminate_child(&mut child);
            let tail = log_tail(&log_path);
            return Err(if tail.is_empty() {
                error
            } else {
                let tail = net_manager_core::vpn::redact_runtime_log(&tail);
                io::Error::new(error.kind(), format!("{error}; xray log: {tail}"))
            });
        }
        Ok(child)
    }
}

#[cfg(target_os = "linux")]
impl Default for TrustedXrayProcess {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl XrayProcessRunner for TrustedXrayProcess {
    fn verify_binary(&self) -> io::Result<()> {
        trusted_binary().map(|_| ())
    }

    fn link_index(&self, name: &str) -> io::Result<Option<u32>> {
        if !valid_tun_name(name) {
            return Err(invalid_input());
        }
        let name = CString::new(name).map_err(|_| invalid_input())?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        Ok((index != 0).then_some(index))
    }

    fn start(
        &mut self,
        uid: u32,
        name: &str,
        config: &str,
        geo_assets: Option<&net_manager_core::daemon_protocol::XrayGeoAssets>,
    ) -> io::Result<()> {
        if !valid_tun_name(name) || config.len() > MAX_XRAY_CONFIG_BYTES {
            return Err(invalid_input());
        }
        if self.children.contains_key(name) || self.link_index(name)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Xray interface exists",
            ));
        }
        let binary = trusted_binary()?;
        ensure_runtime_root()?;
        let directory = stage_config_at(runtime_root().as_path(), uid, name, config)?;
        let managed_dir = binary.parent().expect("fixed managed binary");
        let asset_dir = match geo_assets {
            Some(assets) => {
                if let Err(err) = stage_geo_assets(assets, &directory, managed_dir) {
                    let _ = cleanup_stage_at(runtime_root().as_path(), uid, name);
                    return Err(err);
                }
                directory.as_path()
            }
            None => managed_dir,
        };
        let config_path = directory.join("config.json");
        match self.spawn_xray_child(&binary, &directory, &config_path, asset_dir, name, true) {
            Ok(child) => {
                self.children.insert(name.to_owned(), (uid, child));
                Ok(())
            }
            Err(error) => {
                let _ = cleanup_stage_at(runtime_root().as_path(), uid, name);
                Err(error)
            }
        }
    }

    /// Respawn the child on its existing staging directory: the config and
    /// staged geo assets are reused, the log keeps appending, and a stale
    /// recorded process is terminated first. The caller re-applies
    /// link-scoped resources once the TUN reappears.
    fn respawn(&mut self, uid: u32, name: &str) -> io::Result<()> {
        if !valid_tun_name(name) {
            return Err(invalid_input());
        }
        ensure_runtime_root()?;
        let directory = assert_staging_dir(uid, name)?;
        if let Some((owner, _)) = self.children.get(name) {
            if *owner != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Xray process ownership mismatch",
                ));
            }
            self.stop(name)?;
        }
        // Kill a recorded process that outlived our tracking, keeping the
        // staging directory itself.
        recover_child(uid, name)?;
        let config_path = directory.join("config.json");
        let config_metadata = fs::symlink_metadata(&config_path)
            .map_err(|_| io::Error::other("Xray staged config unavailable"))?;
        if !config_metadata.is_file()
            || config_metadata.uid() != 0
            || config_metadata.mode() & 0o077 != 0
            || config_metadata.len() as usize > MAX_XRAY_CONFIG_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray staged config is unsafe",
            ));
        }
        let binary = trusted_binary()?;
        let asset_dir = if directory.join("geoip.dat").is_file() {
            directory.as_path()
        } else {
            binary.parent().expect("fixed managed binary")
        };
        let child =
            self.spawn_xray_child(&binary, &directory, &config_path, asset_dir, name, false)?;
        self.children.insert(name.to_owned(), (uid, child));
        Ok(())
    }

    /// Swap the staged config (and geo assets) while the old child is still
    /// running — it only reads them at spawn, so a failed write leaves the
    /// live tunnel untouched — then restart the child on the same staging
    /// directory with the log appending.
    fn reload(
        &mut self,
        uid: u32,
        name: &str,
        config: &str,
        geo_assets: Option<&net_manager_core::daemon_protocol::XrayGeoAssets>,
    ) -> io::Result<()> {
        if !valid_tun_name(name) || config.len() > MAX_XRAY_CONFIG_BYTES {
            return Err(invalid_input());
        }
        ensure_runtime_root()?;
        let directory = assert_staging_dir(uid, name)?;
        if let Some((owner, _)) = self.children.get(name) {
            if *owner != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Xray process ownership mismatch",
                ));
            }
        }
        rewrite_private_file(&directory.join("config.json"), config.as_bytes())?;
        let binary = trusted_binary()?;
        let managed_dir = binary.parent().expect("fixed managed binary");
        match geo_assets {
            Some(assets) => stage_geo_assets(assets, &directory, managed_dir)?,
            None => {
                // Mirrors `start`: absent caller assets mean the managed
                // files, so any previously staged copies must go or they
                // would shadow them.
                for file in ["geoip.dat", "geosite.dat"] {
                    match fs::remove_file(directory.join(file)) {
                        Ok(()) => {}
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                        Err(_) => {
                            return Err(io::Error::other("Xray geo asset cleanup failed"));
                        }
                    }
                }
            }
        }
        if self.children.contains_key(name) {
            self.stop(name)?;
        }
        recover_child(uid, name)?;
        let config_path = directory.join("config.json");
        let asset_dir = if directory.join("geoip.dat").is_file() {
            directory.as_path()
        } else {
            managed_dir
        };
        let child =
            self.spawn_xray_child(&binary, &directory, &config_path, asset_dir, name, false)?;
        self.children.insert(name.to_owned(), (uid, child));
        Ok(())
    }

    fn health(&mut self, name: &str) -> io::Result<bool> {
        let (_, child) = self
            .children
            .get_mut(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Xray child is not tracked"))?;
        let status = child.try_wait().map_err(|err| {
            eprintln!("network-orchestrator-daemon: xray child check failed pid={} kind={:?} os_code={:?}", child.id(), err.kind(), err.raw_os_error());
            io::Error::other("Xray child check failed")
        })?;
        if let Some(status) = status {
            eprintln!(
                "network-orchestrator-daemon: xray unexpected exit pid={} code={:?} signal={:?}",
                child.id(),
                status.code(),
                status.signal()
            );
            return Ok(false);
        }
        Ok(self.link_index(name)?.is_some())
    }

    fn query_stats(&mut self, name: &str, api_port: u16) -> io::Result<(u64, u64)> {
        if !self.children.contains_key(name) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Xray child is not tracked",
            ));
        }
        if let Ok(stats) = tun_byte_counters(&iface_stats_dir(name)) {
            return Ok(stats);
        }
        let output = run_statsquery(&trusted_binary()?, api_port)?;
        let stats = parse_statsquery(&output);
        Ok(stats)
    }

    fn stop(&mut self, name: &str) -> io::Result<()> {
        let (_, child) = self
            .children
            .get_mut(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Xray child is not tracked"))?;
        eprintln!(
            "network-orchestrator-daemon: xray terminating pid={} cause=stop_or_restart",
            child.id()
        );
        terminate_child(child)?;
        self.children.remove(name);
        Ok(())
    }

    fn cleanup(&mut self, uid: u32, name: &str) -> io::Result<()> {
        if !valid_tun_name(name) {
            return Err(invalid_input());
        }
        if let Some((owner, _)) = self.children.get(name) {
            if *owner != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Xray process ownership mismatch",
                ));
            }
            self.stop(name)?;
        } else {
            recover_child(uid, name)?;
        }
        ensure_runtime_root()?;
        cleanup_stage_at(runtime_root().as_path(), uid, name)
    }
}

#[cfg(target_os = "linux")]
fn invalid_input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid Xray process input")
}

#[cfg(target_os = "linux")]
fn valid_tun_name(name: &str) -> bool {
    name.starts_with("xray-")
        && (6..=15).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn trusted_binary() -> io::Result<PathBuf> {
    let root = Path::new(BINARY_ROOT);
    let binary = net_manager_core::managed_xray::linux_managed_version_dir(root).join("xray");
    if !safe_root_owned_path(&binary)
        || ["geoip.dat", "geosite.dat"].iter().any(|name| {
            !safe_owned_file(
                &binary.parent().expect("fixed managed binary").join(name),
                0,
                false,
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed Xray installation is unsafe",
        ));
    }
    net_manager_core::managed_xray::verify_managed_linux_executable(root, &binary).map_err(
        |_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed Xray verification failed",
            )
        },
    )?;
    Ok(binary)
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
pub(crate) fn trusted_binary() -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed Xray is not supported on this architecture",
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn safe_root_owned_path(path: &Path) -> bool {
    if !safe_owned_file(path, 0, true) {
        return false;
    }
    let mut parent = path.parent();
    while let Some(directory) = parent {
        let Ok(metadata) = fs::symlink_metadata(directory) else {
            return false;
        };
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return false;
        }
        if directory == Path::new("/") {
            return true;
        }
        parent = directory.parent();
    }
    false
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", test)))]
fn safe_owned_file(path: &Path, owner: u32, executable: bool) -> bool {
    let Ok(file) = fs::symlink_metadata(path) else {
        return false;
    };
    file.is_file()
        && file.uid() == owner
        && file.mode() & 0o022 == 0
        && (!executable || file.mode() & 0o111 != 0)
}

/// `xray.install`: verify the caller-supplied release archive against the
/// pinned hashes and lay it down as the managed package. A stale
/// unverified tree (e.g. left by a removed distro package) is dropped
/// first; fresh files get distro-package modes (root-owned `0755`/`0644`)
/// so unprivileged user-space mode can exec them too.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn install_managed_package_at(
    root: &Path,
    archive: &[u8],
) -> io::Result<net_manager_core::managed_xray::ManagedXrayInstallation> {
    use net_manager_core::managed_xray as managed;
    managed::remove_incomplete_linux_version(root)?;
    let installation = managed::install_verified_linux_archive(root, archive)?;
    managed::relax_linux_package_permissions(root)?;
    Ok(installation)
}

/// `xray.remove`: delete the managed version tree. Returns whether anything
/// was removed.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn remove_managed_package_at(root: &Path) -> io::Result<bool> {
    net_manager_core::managed_xray::remove_linux_version(root)
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
pub fn install_managed_package_at(
    _root: &Path,
    _archive: &[u8],
) -> io::Result<net_manager_core::managed_xray::ManagedXrayInstallation> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed Xray is not supported on this architecture",
    ))
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
pub fn remove_managed_package_at(_root: &Path) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed Xray is not supported on this architecture",
    ))
}

#[cfg(target_os = "linux")]
fn ensure_runtime_root() -> io::Result<()> {
    let root = runtime_root();
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| io::Error::other("Xray runtime directory unavailable"))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray runtime directory is unsafe",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const STATSQUERY_TIMEOUT: Duration = Duration::from_millis(1500);

/// Byte counters of the TUN link straight from sysfs. Spawning `xray api
/// statsquery` per poll takes seconds (fresh gRPC client per call) while
/// the daemon core mutex is held, so kernel link stats are the primary
/// source and the stats api stays only as a fallback.
#[cfg(target_os = "linux")]
fn tun_byte_counters(stats_dir: &Path) -> io::Result<(u64, u64)> {
    let counter = |file: &str| -> io::Result<u64> {
        fs::read_to_string(stats_dir.join(file))?
            .trim()
            .parse()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "interface counter is malformed")
            })
    };
    // tun rx = bytes apps pushed into Xray (upload); tx = bytes Xray wrote
    // back to apps (download). Callers count rx/tx from the client's point
    // of view, hence the swap.
    Ok((counter("tx_bytes")?, counter("rx_bytes")?))
}

/// `/sys/class/net/<link>/statistics` for the managed TUN link.
#[cfg(target_os = "linux")]
fn iface_stats_dir(name: &str) -> PathBuf {
    Path::new("/sys/class/net").join(name).join("statistics")
}

/// `xray api statsquery -server=127.0.0.1:<port>` against the managed
/// binary; the counter list is small enough to read after exit.
#[cfg(target_os = "linux")]
fn run_statsquery(binary: &Path, api_port: u16) -> io::Result<String> {
    let mut child = Command::new(binary)
        .args([
            "api",
            "statsquery",
            "-server",
            &format!("127.0.0.1:{api_port}"),
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| io::Error::other("Xray statsquery launch failed"))?;
    let deadline = Instant::now() + STATSQUERY_TIMEOUT;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| io::Error::other("Xray statsquery wait failed"))?
        {
            let mut output = String::new();
            child
                .stdout
                .take()
                .expect("piped stdout")
                .read_to_string(&mut output)
                .map_err(|_| io::Error::other("Xray statsquery read failed"))?;
            if !status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Xray statsquery failed",
                ));
            }
            return Ok(output);
        }
        if Instant::now() >= deadline {
            let _ = terminate_child(&mut child);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Xray statsquery timed out",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// `statsquery` prints one `name>>>...>>>direction  value` line per counter;
/// the TUN inbound's downlink is what the apps received (rx) and uplink is
/// what they sent (tx). Other inbounds (api-in) and outbound counters are
/// intentionally ignored here.
#[cfg(target_os = "linux")]
fn parse_statsquery(output: &str) -> (u64, u64) {
    let (mut rx, mut tx) = (0_u64, 0_u64);
    for line in output.lines() {
        let mut fields = line
            .split([':', '\t', ' ', '='])
            .filter(|field| !field.is_empty());
        let Some(name) = fields.find(|field| field.contains(">>>")) else {
            continue;
        };
        if !name.starts_with("inbound>>>tun-in>>>") {
            continue;
        }
        let Some(value) = fields.find_map(|field| field.parse::<u64>().ok()) else {
            continue;
        };
        if name.ends_with(">>>downlink") {
            rx += value;
        } else if name.ends_with(">>>uplink") {
            tx += value;
        }
    }
    (rx, tx)
}

#[cfg(target_os = "linux")]
fn xray_args(config: &Path) -> Vec<String> {
    vec![
        "run".into(),
        "-config".into(),
        config.to_string_lossy().into_owned(),
    ]
}

#[cfg(target_os = "linux")]
fn stage_config_at(root: &Path, uid: u32, name: &str, config: &str) -> io::Result<PathBuf> {
    if !valid_tun_name(name) || config.len() > MAX_XRAY_CONFIG_BYTES {
        return Err(invalid_input());
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|_| io::Error::other("Xray staging failed"))?;
    if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray runtime directory is unsafe",
        ));
    }
    let owner = metadata.uid();
    let user_dir = root.join(uid.to_string());
    if !user_dir.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(&user_dir)
            .map_err(|_| io::Error::other("Xray staging failed"))?;
    }
    let user =
        fs::symlink_metadata(&user_dir).map_err(|_| io::Error::other("Xray staging failed"))?;
    if !user.is_dir() || user.uid() != owner || user.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray staging directory is unsafe",
        ));
    }
    let directory = user_dir.join(name);
    DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Xray staging directory already exists",
            )
        })?;
    if let Err(error) = write_private_file(&directory.join("config.json"), config.as_bytes()) {
        let _ = cleanup_stage_at(root, uid, name);
        return Err(error);
    }
    Ok(directory)
}

/// Verify the staged directory for `uid`/`name` exists and is still
/// root-owned and private before reusing it (respawn/reload).
#[cfg(target_os = "linux")]
fn assert_staging_dir(uid: u32, name: &str) -> io::Result<PathBuf> {
    let directory = runtime_root().join(uid.to_string()).join(name);
    for path in [
        directory.parent().expect("fixed runtime path"),
        directory.as_path(),
    ] {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| io::Error::other("Xray staging directory unavailable"))?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray staging directory is unsafe",
            ));
        }
    }
    Ok(directory)
}

/// Geo asset files are data parsed by Xray; a generous cap keeps a hostile or
/// corrupt caller file from blowing up memory.
#[cfg(target_os = "linux")]
const MAX_GEO_ASSET_BYTES: u64 = 64 * 1024 * 1024;

/// Stage caller-provided dat contents (or the managed file for absent
/// fields) into the root-owned staging dir so `XRAY_LOCATION_ASSET` can
/// point at a single directory containing both files.
#[cfg(target_os = "linux")]
fn stage_geo_assets(
    assets: &net_manager_core::daemon_protocol::XrayGeoAssets,
    staging: &Path,
    managed_dir: &Path,
) -> io::Result<()> {
    use base64::Engine;
    for (name, encoded) in [
        ("geoip.dat", assets.geoip_dat_b64.as_deref()),
        ("geosite.dat", assets.geosite_dat_b64.as_deref()),
    ] {
        let managed = fs::File::open(managed_dir.join(name))
            .ok()
            .map(|input| {
                let mut bytes = Vec::new();
                let _ = input.take(MAX_GEO_ASSET_BYTES + 1).read_to_end(&mut bytes);
                bytes
            })
            .filter(|bytes| !bytes.is_empty() && bytes.len() as u64 <= MAX_GEO_ASSET_BYTES);
        let bytes = match encoded {
            Some(data) => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|_| invalid_input())?;
                if decoded.is_empty() || decoded.len() as u64 > MAX_GEO_ASSET_BYTES {
                    return Err(invalid_input());
                }
                // Provider dats are minimal overlays (they carry only their
                // own categories), so they are merged over the managed stock
                // file; a missing or malformed stock file falls back to the
                // overlay alone.
                match managed.as_deref() {
                    Some(stock) => net_manager_core::geo_list::merge_geo_list(stock, &decoded)
                        .unwrap_or(decoded),
                    None => decoded,
                }
            }
            None => managed.ok_or_else(|| io::Error::other("geo asset file is unreadable"))?,
        };
        write_private_file(&staging.join(name), &bytes)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| io::Error::other("Xray staging file creation failed"))?;
    file.write_all(bytes)
        .map_err(|_| io::Error::other("Xray staging file write failed"))?;
    file.sync_all()
        .map_err(|_| io::Error::other("Xray staging file sync failed"))
}

/// Open `xray.log` for child output. `fresh` creates the file exclusively
/// (first spawn); the append path verifies the existing file is still
/// owner-only and regular before reusing it (respawn).
#[cfg(target_os = "linux")]
fn open_log_file(path: &Path, fresh: bool) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true);
    if fresh {
        options.create_new(true).mode(0o600);
    } else {
        options.append(true);
        let metadata =
            fs::symlink_metadata(path).map_err(|_| io::Error::other("Xray log check failed"))?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray log is unsafe",
            ));
        }
    }
    options
        .open(path)
        .map_err(|_| io::Error::other("Xray log open failed"))
}

/// Like `write_private_file`, but an existing file is kept if it is still
/// owner-only and regular — used when respawning rewrites `process`.
#[cfg(target_os = "linux")]
fn rewrite_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Xray staging file is unsafe",
                ));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(io::Error::other("Xray staging file check failed")),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| io::Error::other("Xray staging file creation failed"))?;
    file.write_all(bytes)
        .map_err(|_| io::Error::other("Xray staging file write failed"))?;
    file.sync_all()
        .map_err(|_| io::Error::other("Xray staging file sync failed"))
}

/// Last `LOG_TAIL_BYTES` of the child log, starting on a line boundary.
/// Missing/oversized/unreadable logs yield an empty string — diagnostics
/// must never break process lifecycle handling.
#[cfg(target_os = "linux")]
fn log_tail(path: &Path) -> String {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.mode() & 0o077 == 0 => metadata,
        _ => return String::new(),
    };
    if metadata.len() == 0 || metadata.len() > 8 * 1024 * 1024 {
        return String::new();
    }
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return String::new(),
    };
    let start = metadata.len().saturating_sub(LOG_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if file.take(LOG_TAIL_BYTES).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    match text.split_once('\n') {
        // Drop a leading partial line when the tail window cut mid-line.
        Some((_, rest)) if start > 0 => rest.trim().to_owned(),
        _ => text.trim().to_owned(),
    }
}

#[cfg(target_os = "linux")]
fn cleanup_stage_at(root: &Path, uid: u32, name: &str) -> io::Result<()> {
    if !valid_tun_name(name) {
        return Err(invalid_input());
    }
    let root_metadata =
        fs::symlink_metadata(root).map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
    let owner = root_metadata.uid();
    let user_dir = root.join(uid.to_string());
    let user = match fs::symlink_metadata(&user_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("Xray staging cleanup failed")),
    };
    if !user.is_dir() || user.uid() != owner || user.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray staging directory is unsafe",
        ));
    }
    let directory = user_dir.join(name);
    let stage = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("Xray staging cleanup failed")),
    };
    if !stage.is_dir() || stage.uid() != owner || stage.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray staging directory is unsafe",
        ));
    }
    for entry in
        fs::read_dir(&directory).map_err(|_| io::Error::other("Xray staging cleanup failed"))?
    {
        let entry = entry.map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
        let filename = entry.file_name();
        if filename != "config.json"
            && filename != "process"
            && filename != "geoip.dat"
            && filename != "geosite.dat"
            && filename != "xray.log"
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray staging contains unknown file",
            ));
        }
        let file = fs::symlink_metadata(entry.path())
            .map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
        if !file.is_file() || file.uid() != owner || file.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray staging file is unsafe",
            ));
        }
        fs::remove_file(entry.path())
            .map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
    }
    fs::remove_dir(&directory).map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
    let _ = fs::remove_dir(&user_dir);
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_starttime(stat: &str) -> Option<u64> {
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn read_starttime(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| io::Error::other("Xray process identity unavailable"))?;
    parse_starttime(&stat).ok_or_else(|| io::Error::other("Xray process identity invalid"))
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VerifiedProcess {
    pub pid: u32,
    pub starttime: u64,
    pub config: PathBuf,
}

#[cfg(target_os = "linux")]
pub(crate) fn staged_config_path(uid: u32, name: &str) -> io::Result<PathBuf> {
    if !valid_tun_name(name) {
        return Err(invalid_input());
    }
    ensure_runtime_root()?;
    Ok(assert_staging_dir(uid, name)?.join("config.json"))
}

/// Read protected ownership metadata; callers must verify live identity.
#[cfg(target_os = "linux")]
fn read_process_record(uid: u32, name: &str) -> io::Result<Option<VerifiedProcess>> {
    if !valid_tun_name(name) {
        return Err(invalid_input());
    }
    ensure_runtime_root()?;
    let directory = runtime_root().join(uid.to_string()).join(name);
    for path in [
        directory.parent().expect("fixed runtime path"),
        directory.as_path(),
    ] {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(io::Error::other("Xray staging directory unavailable")),
        };
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray staging directory is unsafe",
            ));
        }
    }
    let record_path = directory.join("process");
    let metadata = match fs::symlink_metadata(&record_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(io::Error::other("Xray process record invalid")),
    };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray process record is unsafe",
        ));
    }
    let mut record = String::new();
    fs::File::open(&record_path)?
        .take(65)
        .read_to_string(&mut record)?;
    if record.len() > 64 {
        return Err(io::Error::other("Xray process record invalid"));
    }
    let mut parts = record.split_whitespace();
    let pid: u32 = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or_else(|| io::Error::other("Xray process record invalid"))?;
    let starttime = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or_else(|| io::Error::other("Xray process record invalid"))?;
    if parts.next().is_some() || pid == 0 {
        return Err(io::Error::other("Xray process record invalid"));
    }
    let config = directory.join("config.json");
    Ok(Some(VerifiedProcess {
        pid,
        starttime,
        config,
    }))
}

#[cfg(target_os = "linux")]
pub(crate) fn verified_process_record(
    uid: u32,
    name: &str,
    binary: &Path,
) -> io::Result<Option<VerifiedProcess>> {
    let Some(process) = read_process_record(uid, name)? else {
        return Ok(None);
    };
    if !same_process(process.pid, process.starttime, binary, &process.config)? {
        return Ok(None);
    }
    Ok(Some(process))
}

#[cfg(target_os = "linux")]
fn recover_child(uid: u32, name: &str) -> io::Result<()> {
    let Some(process) = read_process_record(uid, name)? else {
        return Ok(());
    };
    if !same_owned_cleanup_process(&process)? {
        return Ok(());
    }

    let pidfd = match open_pidfd(process.pid) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            // It may have exited between identity check and pidfd_open.
            if !same_owned_cleanup_process(&process)? {
                return Ok(());
            }
            return Err(error);
        }
    };
    if !same_owned_cleanup_process(&process)? {
        return Ok(());
    }

    signal_pidfd(&pidfd, libc::SIGTERM)?;
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if pidfd_exited(&pidfd)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }

    signal_pidfd(&pidfd, libc::SIGKILL)?;

    // Do not delete ownership/staging or launch a replacement while an
    // uninterruptible old process still owns its TUN.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if pidfd_exited(&pidfd)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Xray process did not exit",
    ))
}

#[cfg(target_os = "linux")]
fn same_recorded_command(pid: u32, starttime: u64, config: &Path) -> io::Result<bool> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                "Xray process identity unavailable",
            ))
        }
    };
    if parse_starttime(&stat) != Some(starttime) {
        return Ok(false);
    }

    let mut cmdline = Vec::new();
    let file = match fs::File::open(format!("/proc/{pid}/cmdline")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                "Xray process command unavailable",
            ))
        }
    };
    file.take(4097).read_to_end(&mut cmdline)?;
    if cmdline.len() > 4096 {
        return Err(io::Error::other("Xray process command exceeds limit"));
    }

    let mut args = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty());
    let _argv0 = args.next();
    Ok(args.next() == Some(b"run".as_slice())
        && args.next() == Some(b"-config".as_slice())
        && args.next() == Some(config.as_os_str().as_encoded_bytes())
        && args.next().is_none())
}

#[cfg(target_os = "linux")]
fn same_process(pid: u32, starttime: u64, binary: &Path, config: &Path) -> io::Result<bool> {
    if !same_recorded_command(pid, starttime, config)? {
        return Ok(false);
    }
    match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(executable) => Ok(executable == binary),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io::Error::new(
            error.kind(),
            "Xray executable identity unavailable",
        )),
    }
}

#[cfg(target_os = "linux")]
fn same_owned_cleanup_process(process: &VerifiedProcess) -> io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    if !same_recorded_command(process.pid, process.starttime, &process.config)? {
        return Ok(false);
    }

    let proc_exe = format!("/proc/{}/exe", process.pid);
    let executable = match fs::read_link(&proc_exe) {
        Ok(executable) => executable,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                "Xray executable identity unavailable",
            ))
        }
    };

    // A deleted running executable remains inspectable through /proc/PID/exe.
    let raw = executable.as_os_str().as_bytes();
    let raw = raw.strip_suffix(b" (deleted)").unwrap_or(raw);
    let path = Path::new(std::ffi::OsStr::from_bytes(raw));

    // Location only; do not require the obsolete release to remain installed.
    // This constant is deliberately Linux-wide, unlike current trusted_binary().
    let root = Path::new("/usr/lib/network-orchestrator/xray");
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(false);
    };
    let mut components = relative.components();
    let Some(Component::Normal(version)) = components.next() else {
        return Ok(false);
    };
    let version = version.as_bytes();
    if version.len() < 2
        || version.len() > 64
        || version[0] != b'v'
        || !version[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_'))
        || components.next() != Some(Component::Normal(std::ffi::OsStr::new("xray")))
        || components.next().is_some()
    {
        return Ok(false);
    }

    let metadata = match fs::metadata(&proc_exe) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                "Xray executable identity unavailable",
            ))
        }
    };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Ok(false);
    }

    // Recheck after reading executable metadata. PID reuse never authorizes
    // signalling the new process.
    same_recorded_command(process.pid, process.starttime, &process.config)
}

#[cfg(target_os = "linux")]
fn terminate_child(child: &mut Child) -> io::Result<()> {
    if child
        .try_wait()
        .map_err(|_| io::Error::other("Xray child check failed"))?
        .is_some()
    {
        return Ok(());
    }
    let pidfd = open_pidfd(child.id())?;
    signal_pidfd(&pidfd, libc::SIGTERM)?;
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|_| io::Error::other("Xray child check failed"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    eprintln!(
        "network-orchestrator-daemon: xray termination escalating pid={} signal=SIGKILL",
        child.id()
    );
    signal_pidfd(&pidfd, libc::SIGKILL)?;
    // A child wedged in an uninterruptible syscall survives SIGKILL; keep
    // the reaper bounded too so `stop` never blocks a core task forever.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child
            .try_wait()
            .map_err(|_| io::Error::other("Xray child wait failed"))?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Xray child did not exit",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if raw < 0 {
        eprintln!(
            "network-orchestrator-daemon: xray pidfd open failed pid={pid} os_code={:?}",
            io::Error::last_os_error().raw_os_error()
        );
        return Err(io::Error::other("Xray pidfd unavailable"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
}

#[cfg(target_os = "linux")]
fn signal_pidfd(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        eprintln!(
            "network-orchestrator-daemon: xray signal failed signal={signal} os_code={:?}",
            io::Error::last_os_error().raw_os_error()
        );
        return Err(io::Error::other("Xray process signal failed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pidfd_exited(pidfd: &OwnedFd) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        return Err(io::Error::other("Xray process check failed"));
    }
    Ok(result > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[test]
    fn unexpected_child_exit_reports_code_and_signal() {
        const CHILD: &str = "NETORCH_DIAGNOSTIC_CHILD_TEST";
        if let Ok(mode) = std::env::var(CHILD) {
            let command = if mode == "code" {
                "exit 23"
            } else {
                "kill -TERM $$"
            };
            let mut child = Command::new("sh").args(["-c", command]).spawn().unwrap();
            child.wait().unwrap();
            let mut runner = TrustedXrayProcess::new();
            runner.children.insert("xray-test".into(), (1000, child));
            assert!(!runner.health("xray-test").unwrap());
            return;
        }
        for (mode, expected) in [("code", "code=Some(23)"), ("signal", "signal=Some(15)")] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "xray_process::tests::unexpected_child_exit_reports_code_and_signal",
                    "--nocapture",
                ])
                .env(CHILD, mode)
                .output()
                .unwrap();
            assert!(output.status.success());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains("unexpected"), "{stderr}");
            assert!(stderr.contains(expected), "{stderr}");
        }
    }

    fn temp_root() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "netmgr-xray-process-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn tun_counters_map_iface_stats_to_client_rx_tx() {
        let root = temp_root();
        let stats = root.join("statistics");
        fs::create_dir(&stats).unwrap();
        // tun rx = bytes apps fed into Xray (upload); tx = bytes Xray handed
        // back to apps (download). Client-facing rx/tx swaps them.
        fs::write(stats.join("rx_bytes"), "1000\n").unwrap();
        fs::write(stats.join("tx_bytes"), "2000\n").unwrap();
        assert_eq!(tun_byte_counters(&stats).unwrap(), (2000, 1000));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn tun_counters_reject_missing_or_malformed_stats() {
        let root = temp_root();
        assert!(tun_byte_counters(&root.join("statistics")).is_err());
        let stats = root.join("statistics");
        fs::create_dir(&stats).unwrap();
        fs::write(stats.join("rx_bytes"), "nope").unwrap();
        fs::write(stats.join("tx_bytes"), "1").unwrap();
        assert!(tun_byte_counters(&stats).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn stage_keeps_config_private_and_cleanup_removes_it() {
        let root = temp_root();
        let uid = unsafe { libc::getuid() };
        let dir = stage_config_at(&root, uid, "xray-abcd", "{\"secret\":\"hidden\"}").unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("config.json")).unwrap(),
            "{\"secret\":\"hidden\"}"
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.join("config.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        cleanup_stage_at(&root, uid, "xray-abcd").unwrap();
        assert!(!dir.exists());
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn stage_rejects_name_traversal_and_oversized_config() {
        let root = temp_root();
        let uid = unsafe { libc::getuid() };
        assert!(stage_config_at(&root, uid, "../xray", "{}").is_err());
        assert!(stage_config_at(
            &root,
            uid,
            "xray-abcd",
            &"x".repeat(MAX_XRAY_CONFIG_BYTES + 1)
        )
        .is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn log_tail_returns_bounded_tail_and_tolerates_missing_files() {
        let root = temp_root();
        let log = root.join("xray.log");
        assert!(log_tail(&log).is_empty());

        fs::write(&log, "first\nsecond\nlast\n").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(log_tail(&log), "first\nsecond\nlast");

        // Windowed tail drops the truncated leading line.
        let filler = "x".repeat(LOG_TAIL_BYTES as usize + 64);
        fs::write(&log, format!("{filler}\nkept-line-1\nkept-line-2\n")).unwrap();
        let tail = log_tail(&log);
        assert!(tail.ends_with("kept-line-1\nkept-line-2"));
        assert!(!tail.contains(&"x".repeat(64)));

        // Group/world-readable files are rejected by the safety check.
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(log_tail(&log).is_empty());
        fs::remove_file(&log).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn cleanup_accepts_log_and_geo_files() {
        let root = temp_root();
        let uid = unsafe { libc::getuid() };
        let dir = stage_config_at(&root, uid, "xray-abcd", "{}").unwrap();
        fs::write(dir.join("xray.log"), b"log").unwrap();
        fs::set_permissions(dir.join("xray.log"), fs::Permissions::from_mode(0o600)).unwrap();
        cleanup_stage_at(&root, uid, "xray-abcd").unwrap();
        assert!(!dir.exists());
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn cleanup_refuses_unexpected_file() {
        let root = temp_root();
        let uid = unsafe { libc::getuid() };
        let dir = stage_config_at(&root, uid, "xray-abcd", "{}").unwrap();
        fs::write(dir.join("unexpected"), b"data").unwrap();
        assert_eq!(
            cleanup_stage_at(&root, uid, "xray-abcd")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn geo_assets(
        geoip: Option<&str>,
        geosite: Option<&str>,
    ) -> net_manager_core::daemon_protocol::XrayGeoAssets {
        net_manager_core::daemon_protocol::XrayGeoAssets {
            geoip_dat_b64: geoip.map(str::to_owned),
            geosite_dat_b64: geosite.map(str::to_owned),
        }
    }

    fn staged_fixture() -> (PathBuf, PathBuf, PathBuf) {
        let root = temp_root();
        let staging = root.join("staging");
        let managed = root.join("managed");
        for dir in [&staging, &managed] {
            fs::create_dir(dir).unwrap();
        }
        fs::write(managed.join("geoip.dat"), b"managed-ip").unwrap();
        fs::write(managed.join("geosite.dat"), b"managed-site").unwrap();
        (root, staging, managed)
    }

    #[test]
    fn stage_geo_assets_prefers_caller_files_and_falls_back_per_file() {
        use base64::Engine;
        let (root, staging, managed) = staged_fixture();
        let assets = geo_assets(
            None,
            Some(&base64::engine::general_purpose::STANDARD.encode(b"caller-site".as_slice())),
        );
        stage_geo_assets(&assets, &staging, &managed).unwrap();
        assert_eq!(fs::read(staging.join("geoip.dat")).unwrap(), b"managed-ip");
        assert_eq!(
            fs::read(staging.join("geosite.dat")).unwrap(),
            b"caller-site"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stage_geo_assets_stages_both_caller_files() {
        use base64::Engine;
        let (root, staging, managed) = staged_fixture();
        let encode = base64::engine::general_purpose::STANDARD;
        let assets = geo_assets(
            Some(&encode.encode(b"caller-ip".as_slice())),
            Some(&encode.encode(b"caller-site".as_slice())),
        );
        stage_geo_assets(&assets, &staging, &managed).unwrap();
        assert_eq!(fs::read(staging.join("geoip.dat")).unwrap(), b"caller-ip");
        assert_eq!(
            fs::read(staging.join("geosite.dat")).unwrap(),
            b"caller-site"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stage_geo_assets_rejects_malformed_base64() {
        let (root, staging, managed) = staged_fixture();
        assert!(stage_geo_assets(
            &geo_assets(Some("!!!not-base64!!!"), None),
            &staging,
            &managed
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stage_geo_assets_rejects_oversized_and_empty() {
        use base64::Engine;
        let (root, staging, managed) = staged_fixture();
        let encode = base64::engine::general_purpose::STANDARD;
        let empty = encode.encode(b"".as_slice());
        assert!(stage_geo_assets(&geo_assets(Some(&empty), None), &staging, &managed).is_err());
        let oversized = encode.encode(vec![0u8; MAX_GEO_ASSET_BYTES as usize + 1]);
        assert!(stage_geo_assets(&geo_assets(Some(&oversized), None), &staging, &managed).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    /// Provider dats carry only their own categories, so a provided file is
    /// merged over the managed stock file instead of replacing it.
    #[test]
    fn stage_geo_assets_merges_overlay_over_stock() {
        use base64::Engine;
        let (root, staging, managed) = staged_fixture();
        let entry = |code: &str| -> Vec<u8> {
            let mut record = vec![0x0a, 2 + code.len() as u8, 0x0a, code.len() as u8];
            record.extend_from_slice(code.as_bytes());
            record
        };
        let mut stock = entry("GOOGLE");
        stock.extend(entry("PRIVATE"));
        fs::write(managed.join("geosite.dat"), &stock).unwrap();
        let overlay = entry("TORRENT");
        let assets = geo_assets(
            None,
            Some(&base64::engine::general_purpose::STANDARD.encode(overlay)),
        );
        stage_geo_assets(&assets, &staging, &managed).unwrap();
        let staged = fs::read(staging.join("geosite.dat")).unwrap();
        let codes = net_manager_core::geo_list::geo_codes(&staged).unwrap();
        assert_eq!(codes, ["GOOGLE", "PRIVATE", "TORRENT"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_stage_at_removes_staged_geo_files() {
        let uid = unsafe { libc::getuid() };
        let root = temp_root();
        let dir = stage_config_at(&root, uid, "xray-geo01", "{}").unwrap();
        for name in ["geoip.dat", "geosite.dat"] {
            write_private_file(&dir.join(name), b"dat").unwrap();
        }
        cleanup_stage_at(&root, uid, "xray-geo01").unwrap();
        assert!(!dir.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_identity_parser_handles_parentheses() {
        let stat = "123 (xray (worker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 8675309 21";
        assert_eq!(parse_starttime(stat), Some(8675309));
        assert_eq!(parse_starttime("bad"), None);
    }

    #[test]
    fn launch_arguments_never_run_tun_test() {
        let args = xray_args(Path::new(
            "/run/network-orchestrator/1000/xray-abcd/config.json",
        ));
        assert_eq!(args[0], "run");
        assert!(!args.iter().any(|arg| arg == "-test"));
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn unsupported_architecture_rejects_managed_xray_without_starting_it() {
        assert_eq!(
            trusted_binary().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn install_managed_package_drops_stale_tree_and_rejects_bad_hash() {
        let root = temp_root();
        let stale = net_manager_core::managed_xray::linux_managed_version_dir(&root);
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("xray"), b"leftover").unwrap();
        let err = install_managed_package_at(&root, b"not a zip").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!stale.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn install_managed_package_rejects_oversized_archive() {
        let root = temp_root();
        let archive = vec![0u8; net_manager_core::managed_xray::MAX_XRAY_ARCHIVE_BYTES + 1];
        assert_eq!(
            install_managed_package_at(&root, &archive)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn remove_managed_package_reports_whether_tree_existed() {
        let root = temp_root();
        assert!(!remove_managed_package_at(&root).unwrap());
        let version = net_manager_core::managed_xray::linux_managed_version_dir(&root);
        fs::create_dir_all(&version).unwrap();
        assert!(remove_managed_package_at(&root).unwrap());
        assert!(!version.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn geo_assets_must_not_be_writable_by_unprivileged_users() {
        let root = temp_root();
        let geo = root.join("geoip.dat");
        fs::write(&geo, b"fake").unwrap();
        let owner = unsafe { libc::getuid() };
        fs::set_permissions(&geo, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!safe_owned_file(&geo, owner, false));
        fs::set_permissions(&geo, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(safe_owned_file(&geo, owner, false));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn statsquery_output_parses_tun_inbound_counters() {
        let output = "inbound>>>tun-in>>>traffic>>>uplink	2048
\
                      inbound>>>tun-in>>>traffic>>>downlink   1024
\
                      inbound>>>api-in>>>traffic>>>uplink	10
\
                      outbound>>>proxy>>>traffic>>>uplink	2048
";
        assert_eq!(parse_statsquery(output), (1024, 2048));
        assert_eq!(parse_statsquery(""), (0, 0));
        assert_eq!(
            parse_statsquery(
                "inbound>>>tun-in>>>traffic>>>uplink: 7
"
            ),
            (0, 7)
        );
    }
}
