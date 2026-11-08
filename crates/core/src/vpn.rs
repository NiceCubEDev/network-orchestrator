use crate::models::{
    AnalyzedRoute, Profile, ProtocolHealth, ProtocolHealthState, TunnelBackend, TunnelState,
    TunnelStatus,
};
use crate::windows_job::ChildJob;
use ipnet::{IpNet, Ipv4Net};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsString;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::fs;
use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use windows::core::{HRESULT, PCWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
#[cfg(windows)]
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOPPED,
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
struct ServiceHandle(SC_HANDLE);

#[cfg(windows)]
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn wireguard_service_running(profile: &Profile) -> io::Result<bool> {
    let service_name = wireguard_service_name(profile)?;
    let wide: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let scm = ServiceHandle(
            OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
                .map_err(|e| io::Error::from_raw_os_error(e.code().0))?,
        );
        let service =
            match OpenServiceW(scm.0, PCWSTR::from_raw(wide.as_ptr()), SERVICE_QUERY_STATUS) {
                Ok(handle) => ServiceHandle(handle),
                Err(e) if e.code() == HRESULT::from_win32(ERROR_SERVICE_DOES_NOT_EXIST.0) => {
                    return Ok(false);
                }
                Err(e) => return Err(io::Error::from_raw_os_error(e.code().0)),
            };
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        let buffer = core::slice::from_raw_parts_mut(
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            core::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(buffer), &mut needed)
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(status.dwCurrentState != SERVICE_STOPPED)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
}

fn wireguard_connect_spec(exe: &Path, profile: &Profile) -> io::Result<CommandSpec> {
    // Always inject `Table = off` into a transient copy so the WireGuard tunnel
    // service does not install its own routes from AllowedIPs. The app is the
    // sole route installer via IP Helper API — it derives routes from
    // AllowedIPs (when `profile.routes` is empty) or from explicit policy
    // routes, and installs them through `PolicyManager`. When policy routes
    // are set, the transient config's `AllowedIPs` is expanded to cover them,
    // ensuring WireGuard cryptokey routing accepts all policy-routed traffic.
    // The transient file is cleaned up on disconnect by
    // `TunnelManager::cleanup_wireguard_transient`.
    let routes: Vec<IpNet> = profile.routes.iter().map(|r| r.destination).collect();
    let config_path = wireguard_table_off_config(&profile.config_path, &profile.id, &routes)?;
    Ok(CommandSpec {
        program: exe.to_path_buf(),
        args: vec![
            OsString::from("/installtunnelservice"),
            config_path.into_os_string(),
        ],
    })
}

/// Create a transient copy of `source` with `Table = off` appended to the
/// `[Interface]` section. If `routes` is non-empty, the first `[Peer]`'s
/// `AllowedIPs` is expanded to include any policy route destinations not
/// already covered, ensuring WireGuard cryptokey routing accepts all
/// application-managed traffic. The copy is placed next to the original (in
/// the managed vault revision directory) under a `.table-off.conf` name so it
/// inherits the vault's ACL protection. Returns the path to the transient
/// file.
fn wireguard_table_off_config(
    source: &Path,
    profile_id: &str,
    routes: &[IpNet],
) -> io::Result<PathBuf> {
    let text = std::fs::read_to_string(source).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot read WireGuard config for Table=off injection: {err}"),
        )
    })?;
    let with_table_off = inject_table_off(&text);
    let injected = if routes.is_empty() {
        with_table_off
    } else {
        expand_allowedips(&with_table_off, routes)
    };
    let dir = source
        .parent()
        .ok_or_else(|| invalid_data("WireGuard config path has no parent directory"))?;
    let safe = crate::config_vault::sanitize_profile_id(profile_id)?;
    let transient = dir.join(format!("{safe}.table-off.conf"));
    std::fs::write(&transient, injected)?;
    crate::config_security::protect_path(&transient)?;
    Ok(transient)
}

/// Expand the `AllowedIPs` of the first `[Peer]` section to include any policy
/// route destinations that are not already covered by existing AllowedIPs.
/// This ensures WireGuard cryptokey routing accepts traffic for all
/// application-managed policy routes. Routes already covered by an existing
/// AllowedIPs prefix are skipped (no duplication). If there is no `[Peer]`
/// section or no `AllowedIPs` line, the config is returned unchanged.
fn expand_allowedips(text: &str, routes: &[IpNet]) -> String {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut in_peer = false;
    let mut peer_allowedips_line: Option<usize> = None;
    let mut existing: Vec<IpNet> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_peer = trimmed.eq_ignore_ascii_case("[peer]");
            continue;
        }
        if in_peer {
            let lower = trimmed.to_lowercase();
            if lower.starts_with("allowedips") && peer_allowedips_line.is_none() {
                peer_allowedips_line = Some(i);
                if let Some(rest) = trimmed.split('=').nth(1) {
                    for part in rest.split(',') {
                        if let Ok(net) = part.trim().parse::<IpNet>() {
                            existing.push(net);
                        }
                    }
                }
            }
        }
    }
    let Some(line_idx) = peer_allowedips_line else {
        return lines.join("\n");
    };

    // Collect routes not already covered by existing AllowedIPs.
    let mut to_add: Vec<IpNet> = Vec::new();
    for route in routes {
        if existing.iter().any(|net| net.contains(route)) {
            continue;
        }
        if to_add.iter().any(|net| net == route) {
            continue;
        }
        to_add.push(*route);
    }
    if to_add.is_empty() {
        return lines.join("\n");
    }

    existing.extend(to_add);
    existing.sort_by_key(|net| net.prefix_len());
    let rendered = existing
        .iter()
        .map(|net| net.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    lines[line_idx] = format!("AllowedIPs = {rendered}");
    lines.join("\n")
}

/// Append `Table = off` to the `[Interface]` section of a WireGuard config.
/// If `[Interface]` already contains a `Table` directive, it is replaced.
/// If there is no `[Interface]` section, one is prepended.
fn inject_table_off(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut in_interface = false;
    let mut table_seen = false;
    let mut interface_start: Option<usize> = None;
    let mut table_line: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_interface = trimmed.eq_ignore_ascii_case("[interface]");
            if in_interface && interface_start.is_none() {
                interface_start = Some(i);
            }
            continue;
        }
        if in_interface {
            let lower = trimmed.to_lowercase();
            if lower.starts_with("table") {
                table_line = Some(i);
            }
        }
    }
    if let Some(i) = table_line {
        lines[i] = "Table = off".to_string();
        table_seen = true;
    }
    if !table_seen {
        if let Some(start) = interface_start {
            lines.insert(start + 1, "Table = off".to_string());
        } else {
            lines.insert(0, "[Interface]".to_string());
            lines.insert(1, "Table = off".to_string());
            lines.insert(2, String::new());
        }
    }
    lines.join("\n")
}

fn wireguard_disconnect_spec(exe: &Path, profile: &Profile) -> io::Result<CommandSpec> {
    Ok(CommandSpec {
        program: exe.to_path_buf(),
        args: vec![
            OsString::from("/uninstalltunnelservice"),
            OsString::from(wireguard_tunnel_name(&profile.config_path)?),
        ],
    })
}

fn openvpn_connect_spec(exe: &Path, profile: &Profile) -> io::Result<CommandSpec> {
    // Always pass `--route-nopull` so OpenVPN does not install server-pushed
    // routes itself. The app is the sole route installer — it reads pushed
    // routes from the OpenVPN log after handshake (via
    // `openvpn_pushed_routes`) and installs them through `PolicyManager`.
    let mut args = vec![
        OsString::from("--config"),
        std::path::absolute(&profile.config_path)?.into_os_string(),
        OsString::from("--route-nopull"),
    ];
    let _ = &mut args; // silence unused-mut when no extra args are added
    Ok(CommandSpec {
        program: exe.to_path_buf(),
        args,
    })
}

#[cfg(any(windows, test))]
fn wireguard_service_name(profile: &Profile) -> io::Result<String> {
    Ok(format!(
        "WireGuardTunnel${}",
        wireguard_tunnel_name(&profile.config_path)?
    ))
}

pub fn wireguard_tunnel_name(config_path: &Path) -> io::Result<String> {
    let file_name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_data("config path has no usable file name"))?;
    let lower = file_name.to_lowercase();
    let suffix_len = if lower.ends_with(".conf.dpapi") {
        ".conf.dpapi".len()
    } else if lower.ends_with(".conf") {
        ".conf".len()
    } else {
        return Err(invalid_data(format!(
            "unsupported WireGuard config name '{file_name}' (expected .conf or .conf.dpapi)"
        )));
    };
    let stem = &file_name[..file_name.len() - suffix_len];
    if stem.is_empty() {
        return Err(invalid_data("WireGuard config name has no tunnel name"));
    }
    Ok(stem.to_string())
}

pub fn resolve_wireguard_executable(configured: Option<&Path>) -> io::Result<PathBuf> {
    resolve_executable(
        configured,
        "wireguard.exe",
        "WireGuard",
        &wireguard_standard_paths(),
    )
}

#[cfg(windows)]
const OPENVPN_EXE_NAME: &str = "openvpn.exe";
#[cfg(not(windows))]
const OPENVPN_EXE_NAME: &str = "openvpn";

#[cfg(windows)]
const XRAY_EXE_NAME: &str = "xray.exe";
#[cfg(not(windows))]
const XRAY_EXE_NAME: &str = "xray";

pub fn resolve_openvpn_executable(configured: Option<&Path>) -> io::Result<PathBuf> {
    resolve_executable(
        configured,
        OPENVPN_EXE_NAME,
        "OpenVPN",
        &openvpn_standard_paths(),
    )
}

pub fn resolve_xray_executable(configured: Option<&Path>) -> io::Result<PathBuf> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        resolve_xray_executable_with_package_root(
            configured,
            Path::new(crate::managed_xray::LINUX_XRAY_PACKAGE_ROOT),
            crate::managed_xray::verify_managed_linux_executable,
        )
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        resolve_executable(configured, XRAY_EXE_NAME, "Xray", &xray_standard_paths())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn resolve_xray_executable_with_package_root(
    configured: Option<&Path>,
    root: &Path,
    verify: impl Fn(&Path, &Path) -> io::Result<()>,
) -> io::Result<PathBuf> {
    if configured.is_none() {
        if let Some(package) = verified_package_xray_at(root, verify)? {
            return Ok(package);
        }
    }
    resolve_executable(configured, XRAY_EXE_NAME, "Xray", &xray_standard_paths())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn verified_package_xray_at(
    root: &Path,
    verify: impl Fn(&Path, &Path) -> io::Result<()>,
) -> io::Result<Option<PathBuf>> {
    let executable = crate::managed_xray::linux_managed_version_dir(root).join("xray");
    match fs::symlink_metadata(&executable) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packaged Xray is unavailable",
            ))
        }
        Ok(_) => {}
    }
    verify(root, &executable).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "packaged Xray failed integrity verification",
        )
    })?;
    Ok(Some(executable))
}

fn resolve_executable(
    configured: Option<&Path>,
    exe_name: &str,
    display_name: &str,
    standard_paths: &[PathBuf],
) -> io::Result<PathBuf> {
    if let Some(path) = configured {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "configured {display_name} executable '{}' is not an existing file",
                path.display()
            ),
        ));
    }
    for candidate in standard_paths {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{display_name} executable '{exe_name}' not found; install {display_name} or configure its path"
        ),
    ))
}

#[cfg(windows)]
fn wireguard_standard_paths() -> Vec<PathBuf> {
    env::var_os("ProgramFiles")
        .map(|root| vec![PathBuf::from(root).join("WireGuard").join("wireguard.exe")])
        .unwrap_or_default()
}

#[cfg(not(windows))]
fn wireguard_standard_paths() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(windows)]
fn openvpn_standard_paths() -> Vec<PathBuf> {
    env::var_os("ProgramFiles")
        .map(|root| {
            vec![PathBuf::from(root)
                .join("OpenVPN")
                .join("bin")
                .join("openvpn.exe")]
        })
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn openvpn_standard_paths() -> Vec<PathBuf> {
    [
        "/usr/bin/openvpn",
        "/usr/sbin/openvpn",
        "/usr/local/bin/openvpn",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(not(any(windows, target_os = "linux")))]
fn openvpn_standard_paths() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(windows)]
fn xray_standard_paths() -> Vec<PathBuf> {
    env::var_os("ProgramFiles")
        .map(|root| vec![PathBuf::from(root).join("Xray").join("xray.exe")])
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn xray_standard_paths() -> Vec<PathBuf> {
    ["/usr/bin/xray", "/usr/local/bin/xray", "/opt/xray/xray"]
        .into_iter()
        .map(PathBuf::from)
        .collect()
}

#[cfg(not(any(windows, target_os = "linux")))]
fn xray_standard_paths() -> Vec<PathBuf> {
    Vec::new()
}

fn xray_command_spec(exe: &Path, test_only: bool) -> CommandSpec {
    let mut args = vec![OsString::from("run")];
    if test_only {
        args.push(OsString::from("-test"));
    }
    args.push(OsString::from("-config"));
    args.push(OsString::from("stdin:"));
    CommandSpec {
        program: exe.to_path_buf(),
        args,
    }
}

/// Profile config with routing policies applied, without any TUN inbound.
/// The macOS TUN flow validates this form unprivileged (`xray run -test`
/// with a tun inbound would create a real device), then injects the
/// fd-mode TUN inbound before handing the config to the privileged helper.
pub fn prepare_xray_config_base(profile: &Profile) -> io::Result<Vec<u8>> {
    let with_policies = prepared_routing_config(profile)?;
    serde_json::to_vec(&with_policies).map_err(|err| {
        invalid_data(format!(
            "failed to serialize xray config for '{}': {err}",
            profile.config_path.display()
        ))
    })
}

fn prepared_routing_config(profile: &Profile) -> io::Result<serde_json::Value> {
    let raw = crate::config_security::read_xray_config(&profile.config_path, &profile.id)?;
    let base: serde_json::Value = serde_json::from_slice(&raw).map_err(|err| {
        invalid_data(format!(
            "profile config '{}' is not valid JSON: {err}",
            profile.config_path.display()
        ))
    })?;
    crate::xray::apply_profile_routing(
        &base,
        &profile.domain_policies,
        &crate::xray::ProfileRoutingOptions::from(profile),
    )
    .map_err(|_| invalid_data("failed to apply Xray routing policies"))
}

fn prepare_xray_config(profile: &Profile) -> io::Result<Vec<u8>> {
    let with_policies = prepared_routing_config(profile)?;
    let merged = if profile.xray_mode == crate::models::XrayMode::Tun {
        crate::xray::apply_tun_inbound(
            &with_policies,
            profile.xray_tun_interface.as_deref(),
            profile.xray_tun_ip.as_deref(),
        )
        .map_err(|err| {
            invalid_data(format!(
                "failed to apply TUN inbound to '{}': {err}",
                profile.config_path.display()
            ))
        })?
    } else {
        with_policies
    };
    serde_json::to_vec(&merged).map_err(|err| {
        invalid_data(format!(
            "failed to serialize xray config for '{}': {err}",
            profile.config_path.display()
        ))
    })
}

/// `xray run -test` on `config` (stdin); the error carries Xray's own message.
pub fn run_xray_validation(exe: &Path, config: &[u8]) -> io::Result<()> {
    run_xray_validation_with_assets(exe, config, None)
}

/// Points Xray at a directory holding its `geoip.dat`/`geosite.dat`.
fn use_asset_dir(command: &mut Command, asset_dir: Option<&Path>) {
    if let Some(dir) = asset_dir {
        command.env("XRAY_LOCATION_ASSET", dir);
    }
}

/// [`run_xray_validation`] with the geo data the connection will run with.
pub fn run_xray_validation_with_assets(
    exe: &Path,
    config: &[u8],
    asset_dir: Option<&Path>,
) -> io::Result<()> {
    let spec = xray_command_spec(exe, true);
    let mut command = Command::new(&spec.program);
    use_asset_dir(&mut command, asset_dir);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(config) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    let message = if detail.is_empty() {
        format!("'{}' exited with {}", spec.program.display(), output.status)
    } else {
        detail
    };
    Err(io::Error::other(message))
}

/// Linux counterpart of `ChildJob`: SIGTERM the child when the thread that
/// spawned it dies. Spawns run on long-lived UI runtime threads, so a crashed
/// or killed UI no longer orphans its local Xray/OpenVPN processes.
#[cfg(target_os = "linux")]
fn terminate_with_parent(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the hook only calls prctl, which is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn spawn_xray(
    exe: &Path,
    config: &[u8],
    asset_dir: Option<&Path>,
    stdout: Stdio,
    stderr: Stdio,
) -> io::Result<Child> {
    let spec = xray_command_spec(exe, false);
    let mut command = Command::new(&spec.program);
    use_asset_dir(&mut command, asset_dir);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(stderr);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    #[cfg(target_os = "linux")]
    terminate_with_parent(&mut command);
    let mut child = command.spawn()?;
    match child.stdin.take() {
        Some(mut stdin) => {
            if let Err(err) = stdin.write_all(config) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("failed to open xray stdin"));
        }
    }
    Ok(child)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn status_for(profile_id: &str, state: TunnelState, message: Option<String>) -> TunnelStatus {
    TunnelStatus {
        profile_id: profile_id.to_string(),
        state,
        message,
        interface_name: None,
        failover: None,
        watchdog: None,
    }
}

fn run_service_command(spec: &CommandSpec) -> io::Result<()> {
    let output = Command::new(&spec.program).args(&spec.args).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    let message = if detail.is_empty() {
        format!("'{}' exited with {}", spec.program.display(), output.status)
    } else {
        detail
    };
    Err(io::Error::other(message))
}

const LOG_TAIL_BYTES: usize = 16 * 1024;
const SENSITIVE_KEYS: &[&str] = &["privatekey", "password", "token", "authorization"];

fn starts_with_ascii_ci(bytes: &[u8], i: usize, pattern: &str) -> bool {
    let pat = pattern.as_bytes();
    i + pat.len() <= bytes.len()
        && bytes[i..i + pat.len()]
            .iter()
            .zip(pat)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

pub fn redact_runtime_log(text: &str) -> String {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        if starts_with_ascii_ci(bytes, i, "vless://") {
            let mut j = i + "vless://".len();
            while j < n && !bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            out.push_str("[redacted]");
            i = j;
            continue;
        }
        let mut redacted = false;
        for key in SENSITIVE_KEYS {
            if starts_with_ascii_ci(bytes, i, key)
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            {
                let mut j = i + key.len();
                while j < n && matches!(bytes[j], b' ' | b'\t') {
                    j += 1;
                }
                if j < n && matches!(bytes[j], b'=' | b':') {
                    j += 1;
                    while j < n && matches!(bytes[j], b' ' | b'\t') {
                        j += 1;
                    }
                    let mut k = j;
                    while k < n && bytes[k] != b'\n' && bytes[k] != b'\r' {
                        k += 1;
                    }
                    out.push_str(&text[i..j]);
                    out.push_str("[redacted]");
                    i = k;
                    redacted = true;
                    break;
                }
            }
        }
        if redacted {
            continue;
        }
        if is_uuid_at(bytes, i)
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            && (i + 36 >= n || !bytes[i + 36].is_ascii_alphanumeric())
        {
            out.push_str("[redacted]");
            i += 36;
            continue;
        }
        let len = utf8_len(bytes[i]);
        out.push_str(&text[i..i + len]);
        i += len;
    }
    // Second pass: mask public IPs and hostnames — runtimes log remote
    // endpoints freely, and a surfaced tail should not reveal them.
    crate::log_sanitize::sanitize_log_text(&out)
}

fn utf8_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead < 0xE0 {
        2
    } else if lead < 0xF0 {
        3
    } else {
        4
    }
}

fn is_uuid_at(bytes: &[u8], i: usize) -> bool {
    if i + 36 > bytes.len() {
        return false;
    }
    for (offset, b) in bytes[i..i + 36].iter().enumerate() {
        let expected_dash = matches!(offset, 8 | 13 | 18 | 23);
        if expected_dash {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn health(state: ProtocolHealthState, summary: impl Into<String>) -> ProtocolHealth {
    ProtocolHealth {
        state,
        summary: summary.into(),
        last_handshake_unix: None,
        rx_bytes: None,
        tx_bytes: None,
        log_tail: None,
        pushed_routes: Vec::new(),
    }
}

fn openvpn_health(
    status: &TunnelStatus,
    log: Option<String>,
    pushed_routes: Vec<AnalyzedRoute>,
) -> ProtocolHealth {
    let tail = log.filter(|t| !t.trim().is_empty());
    let state = match status.state {
        TunnelState::Stopped => return health(ProtocolHealthState::Unknown, "not running"),
        TunnelState::Failed => ProtocolHealthState::Failed,
        TunnelState::Running => match &tail {
            Some(t) if t.contains("AUTH_FAILED") => ProtocolHealthState::Failed,
            Some(t) if t.contains("Initialization Sequence Completed") => {
                ProtocolHealthState::Healthy
            }
            _ => ProtocolHealthState::Degraded,
        },
    };
    let summary = match state {
        ProtocolHealthState::Failed => status
            .message
            .clone()
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "authentication or startup failure (see runtime log)".into()),
        ProtocolHealthState::Healthy => "initialization sequence completed".into(),
        ProtocolHealthState::Degraded => "process running; connection not confirmed".into(),
        ProtocolHealthState::Unknown => "not running".into(),
    };
    ProtocolHealth {
        state,
        summary,
        log_tail: tail,
        pushed_routes,
        ..health(state, "")
    }
}

/// Extract server-pushed routes from OpenVPN log text by parsing `PUSH_REPLY`
/// control messages. OpenVPN logs lines like:
///   `PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.255.255.0,route-ipv6 fd00::/64,...'`
/// The directives inside the quotes are comma-separated; `route <net> <mask>`
/// and `route-ipv6 <prefix>` are the route directives we extract.
pub fn parse_openvpn_pushed_reply(text: &str) -> Vec<AnalyzedRoute> {
    let mut routes = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let Some(payload) = extract_push_reply_payload(line) else {
            continue;
        };
        for directive in payload.split(',') {
            let trimmed = directive.trim();
            if let Some(route) = parse_pushed_route_directive(trimmed) {
                if seen.insert(route.destination) {
                    routes.push(route);
                }
            }
        }
    }
    routes
}

fn extract_push_reply_payload(line: &str) -> Option<&str> {
    let start = line.find("PUSH_REPLY")?;
    let rest = &line[start..];
    // The opening quote is before PUSH_REPLY in the log line; the closing
    // quote (or end-of-line) delimits the payload. Take everything after
    // "PUSH_REPLY" up to the next quote or end of line.
    let payload_start = rest.find(',').map(|i| i + 1).unwrap_or(rest.len());
    let payload = &rest[payload_start..];
    let end = payload
        .find('\'')
        .or_else(|| payload.find('"'))
        .unwrap_or(payload.len());
    Some(payload[..end].trim_end())
}

fn parse_pushed_route_directive(directive: &str) -> Option<AnalyzedRoute> {
    let tokens: Vec<&str> = directive.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    match tokens[0] {
        "route" => {
            let net = tokens.get(1)?;
            if let Ok(ipnet) = net.parse::<IpNet>() {
                return Some(AnalyzedRoute {
                    destination: ipnet,
                    source: "OpenVPN pushed".to_string(),
                    metric: None,
                });
            }
            let addr = net.parse::<Ipv4Addr>().ok()?;
            let prefix = match tokens.get(2) {
                Some(mask) => {
                    let mask = mask.parse::<Ipv4Addr>().ok()?;
                    Ipv4Net::with_netmask(addr, mask).ok()?.prefix_len()
                }
                None => 32,
            };
            Ipv4Net::new(addr, prefix)
                .ok()
                .map(IpNet::V4)
                .map(|destination| AnalyzedRoute {
                    destination,
                    source: "OpenVPN pushed".to_string(),
                    metric: None,
                })
        }
        "route-ipv6" => tokens
            .get(1)
            .and_then(|t| t.parse::<IpNet>().ok())
            .filter(|net| matches!(net, IpNet::V6(_)))
            .map(|destination| AnalyzedRoute {
                destination,
                source: "OpenVPN pushed".to_string(),
                metric: None,
            }),
        _ => None,
    }
}

fn xray_health(status: &TunnelStatus, log: Option<String>) -> ProtocolHealth {
    let tail = log.filter(|t| !t.trim().is_empty());
    let (state, summary) = match status.state {
        TunnelState::Stopped => return health(ProtocolHealthState::Unknown, "not running"),
        TunnelState::Failed => (
            ProtocolHealthState::Failed,
            status
                .message
                .clone()
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "xray process failed".into()),
        ),
        TunnelState::Running => (
            ProtocolHealthState::Degraded,
            "process running; outbound connectivity is not handshake-verified".to_string(),
        ),
    };
    ProtocolHealth {
        state,
        summary,
        log_tail: tail,
        ..health(state, "")
    }
}

fn parse_wg_dump(dump: &str) -> (u64, u64, u64) {
    let mut max_handshake = 0u64;
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in dump.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 7 {
            continue;
        }
        if let Ok(handshake) = fields[4].trim().parse::<u64>() {
            max_handshake = max_handshake.max(handshake);
        }
        rx = rx.saturating_add(fields[5].trim().parse::<u64>().unwrap_or(0));
        tx = tx.saturating_add(fields[6].trim().parse::<u64>().unwrap_or(0));
    }
    (max_handshake, rx, tx)
}

fn wireguard_health_from_dump(dump: &str) -> ProtocolHealth {
    let (handshake, rx, tx) = parse_wg_dump(dump);
    let (state, summary) = if handshake > 0 {
        (
            ProtocolHealthState::Healthy,
            format!("latest handshake at unix {handshake}"),
        )
    } else {
        (
            ProtocolHealthState::Degraded,
            "no WireGuard handshake recorded yet".to_string(),
        )
    };
    ProtocolHealth {
        state,
        summary,
        last_handshake_unix: (handshake > 0).then_some(handshake),
        rx_bytes: Some(rx),
        tx_bytes: Some(tx),
        log_tail: None,
        pushed_routes: Vec::new(),
    }
}

/// An input-only local-runtime snapshot. Never log or persist its configuration.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedXrayConnection {
    executable: PathBuf,
    config: Vec<u8>,
    assets: Option<PathBuf>,
}

impl PreparedXrayConnection {
    pub fn analyze(&self, profile: &Profile) -> io::Result<crate::models::ConfigAnalysis> {
        crate::analysis::analyze_xray_snapshot(profile, &self.config)
    }
}

pub struct TunnelManager {
    wireguard_exe: Option<PathBuf>,
    openvpn_exe: Option<PathBuf>,
    xray_exe: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    wireguard_services: HashSet<String>,
    wireguard_transient_configs: HashMap<String, PathBuf>,
    static_route_profiles: HashSet<String>,
    openvpn_children: HashMap<String, Child>,
    xray_children: HashMap<String, Child>,
    /// Per-profile geo data directories (`XRAY_LOCATION_ASSET`).
    xray_asset_dirs: HashMap<String, PathBuf>,
    failures: HashMap<String, String>,
    child_job: Option<ChildJob>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self::with_all_executables(None, None, None)
    }

    pub fn with_log_dir(log_dir: PathBuf) -> Self {
        Self::with_all_executables_and_log_dir(None, None, None, log_dir)
    }

    pub fn with_all_executables_and_log_dir(
        wireguard: Option<PathBuf>,
        openvpn: Option<PathBuf>,
        xray: Option<PathBuf>,
        log_dir: PathBuf,
    ) -> Self {
        let mut manager = Self::with_all_executables(wireguard, openvpn, xray);
        manager.log_dir = Some(log_dir);
        manager
    }

    pub fn set_executable(&mut self, backend: TunnelBackend, path: Option<PathBuf>) {
        match backend {
            TunnelBackend::None => {}
            TunnelBackend::WireGuard => self.wireguard_exe = path,
            TunnelBackend::OpenVpn => self.openvpn_exe = path,
            TunnelBackend::Xray => self.xray_exe = path,
        }
    }

    pub fn with_executables(wireguard: Option<PathBuf>, openvpn: Option<PathBuf>) -> Self {
        Self::with_all_executables(wireguard, openvpn, None)
    }

    pub fn with_all_executables(
        wireguard: Option<PathBuf>,
        openvpn: Option<PathBuf>,
        xray: Option<PathBuf>,
    ) -> Self {
        Self {
            wireguard_exe: wireguard,
            openvpn_exe: openvpn,
            xray_exe: xray,
            log_dir: None,
            wireguard_services: HashSet::new(),
            wireguard_transient_configs: HashMap::new(),
            static_route_profiles: HashSet::new(),
            openvpn_children: HashMap::new(),
            xray_children: HashMap::new(),
            xray_asset_dirs: HashMap::new(),
            failures: HashMap::new(),
            child_job: None,
        }
    }

    /// Run `profile_id`'s Xray with the geo data in `dir` (`None`: the files
    /// next to the executable). Takes effect at the next connect.
    pub fn set_xray_asset_dir(&mut self, profile_id: &str, dir: Option<PathBuf>) {
        match dir {
            Some(dir) => self.xray_asset_dirs.insert(profile_id.to_string(), dir),
            None => self.xray_asset_dirs.remove(profile_id),
        };
    }

    /// PID of an Xray child this manager owns, for identity-checked recovery.
    pub fn xray_child_pid(&self, profile_id: &str) -> Option<u32> {
        self.xray_children.get(profile_id).map(Child::id)
    }

    fn child_log_stdio(&self, profile_id: &str, tag: &str) -> io::Result<(Stdio, Stdio)> {
        let Some(dir) = &self.log_dir else {
            return Ok((Stdio::null(), Stdio::null()));
        };
        std::fs::create_dir_all(dir)?;
        crate::config_security::protect_path(dir)?;
        let path = dir.join(format!(
            "{}-{tag}.log",
            crate::config_vault::sanitize_profile_id(profile_id)?
        ));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        crate::config_security::protect_path(&path)?;
        let err = file.try_clone()?;
        Ok((Stdio::from(file), Stdio::from(err)))
    }

    fn log_tail_for_tag(
        &self,
        profile_id: &str,
        tag: &str,
        max_bytes: usize,
    ) -> io::Result<Option<String>> {
        if max_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_bytes must be nonzero",
            ));
        }
        let Some(dir) = &self.log_dir else {
            return Ok(None);
        };
        let safe = crate::config_vault::sanitize_profile_id(profile_id)?;
        let path = dir.join(format!("{safe}-{tag}.log"));
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let mut slice = &bytes[bytes.len().saturating_sub(max_bytes)..];
        while !slice.is_empty() && (slice[0] & 0b1100_0000) == 0b1000_0000 {
            slice = &slice[1..];
        }
        let text = String::from_utf8_lossy(slice);
        if text.trim().is_empty() {
            Ok(None)
        } else {
            Ok(Some(redact_runtime_log(&text)))
        }
    }

    pub fn log_tail(&self, profile_id: &str, max_bytes: usize) -> io::Result<Option<String>> {
        let mut combined = String::new();
        for tag in ["openvpn", "xray"] {
            if let Some(tail) = self.log_tail_for_tag(profile_id, tag, max_bytes)? {
                if !combined.is_empty() {
                    combined.push('\n');
                }
                combined.push_str(&tail);
            }
        }
        if combined.is_empty() {
            Ok(None)
        } else {
            Ok(Some(combined))
        }
    }

    /// Read the full OpenVPN log for `profile_id` and extract server-pushed
    /// routes from `PUSH_REPLY` lines. Unlike `log_tail_for_tag`, this reads
    /// the entire log file because `PUSH_REPLY` appears during the handshake,
    /// not at the tail.
    pub fn openvpn_pushed_routes(&self, profile_id: &str) -> Vec<AnalyzedRoute> {
        let Some(dir) = &self.log_dir else {
            return Vec::new();
        };
        let Ok(safe) = crate::config_vault::sanitize_profile_id(profile_id) else {
            return Vec::new();
        };
        let path = dir.join(format!("{safe}-openvpn.log"));
        match std::fs::read_to_string(&path) {
            Ok(text) => parse_openvpn_pushed_reply(&text),
            Err(_) => Vec::new(),
        }
    }

    pub fn protocol_health(&mut self, profile: &Profile) -> ProtocolHealth {
        let status = self.status(profile);
        match profile.backend {
            TunnelBackend::None => match status.state {
                TunnelState::Running => {
                    health(ProtocolHealthState::Healthy, "static routes active")
                }
                TunnelState::Stopped => health(ProtocolHealthState::Unknown, "not active"),
                TunnelState::Failed => health(ProtocolHealthState::Failed, "failed"),
            },
            TunnelBackend::OpenVpn => {
                let log = self
                    .log_tail_for_tag(&profile.id, "openvpn", LOG_TAIL_BYTES)
                    .ok()
                    .flatten();
                let pushed = self.openvpn_pushed_routes(&profile.id);
                openvpn_health(&status, log, pushed)
            }
            TunnelBackend::Xray => {
                let log = self
                    .log_tail_for_tag(&profile.id, "xray", LOG_TAIL_BYTES)
                    .ok()
                    .flatten();
                xray_health(&status, log)
            }
            TunnelBackend::WireGuard => match status.state {
                TunnelState::Stopped => health(ProtocolHealthState::Unknown, "not running"),
                TunnelState::Failed => ProtocolHealth {
                    state: ProtocolHealthState::Failed,
                    summary: status
                        .message
                        .unwrap_or_else(|| "wireguard service check failed".into()),
                    ..health(ProtocolHealthState::Failed, "")
                },
                TunnelState::Running => match self.wg_dump(profile) {
                    Ok(dump) => wireguard_health_from_dump(&dump),
                    Err(err) => health(
                        ProtocolHealthState::Degraded,
                        format!("WireGuard statistics unavailable: {err}"),
                    ),
                },
            },
        }
    }

    fn wg_dump(&self, profile: &Profile) -> io::Result<String> {
        let exe = self.wg_query_exe()?;
        let name = wireguard_tunnel_name(&profile.config_path)?;
        let output = Command::new(&exe)
            .args([
                OsString::from("show"),
                OsString::from(&name),
                OsString::from("dump"),
            ])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "wg show failed with {}",
                output.status
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| invalid_data("wg dump output was not valid UTF-8"))
    }

    fn wg_query_exe(&self) -> io::Result<PathBuf> {
        #[cfg(windows)]
        {
            if let Ok(service_exe) = resolve_wireguard_executable(self.wireguard_exe.as_deref()) {
                if let Some(dir) = service_exe.parent() {
                    let sibling = dir.join("wg.exe");
                    if sibling.is_file() {
                        return Ok(sibling);
                    }
                }
            }
            if let Some(root) = env::var_os("ProgramFiles") {
                let candidate = PathBuf::from(root).join("WireGuard").join("wg.exe");
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
            if let Some(path_var) = env::var_os("PATH") {
                for dir in env::split_paths(&path_var) {
                    let candidate = dir.join("wg.exe");
                    if candidate.is_file() {
                        return Ok(candidate);
                    }
                }
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "wg.exe not found next to wireguard.exe, in Program Files, or on PATH",
            ))
        }
        #[cfg(not(windows))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WireGuard statistics query is only supported on Windows",
            ))
        }
    }

    fn ensure_child_job(&mut self) -> io::Result<&ChildJob> {
        if self.child_job.is_none() {
            self.child_job = Some(ChildJob::new()?);
        }
        Ok(self.child_job.as_ref().unwrap())
    }

    fn reap_child_if_exited(
        children: &mut HashMap<String, Child>,
        profile_id: &str,
    ) -> io::Result<bool> {
        let Some(child) = children.get_mut(profile_id) else {
            return Ok(false);
        };
        match child.try_wait() {
            Ok(None) => Ok(false),
            Ok(Some(_)) => {
                children.remove(profile_id);
                Ok(true)
            }
            Err(err) => {
                children.remove(profile_id);
                Err(err)
            }
        }
    }

    fn ensure_not_running(&mut self, profile: &Profile) -> io::Result<()> {
        Self::reap_child_if_exited(&mut self.openvpn_children, &profile.id)?;
        Self::reap_child_if_exited(&mut self.xray_children, &profile.id)?;
        if self.wireguard_services.contains(&profile.id)
            || self.openvpn_children.contains_key(&profile.id)
            || self.xray_children.contains_key(&profile.id)
            || self.static_route_profiles.contains(&profile.id)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("profile '{}' is already running", profile.id),
            ));
        }
        Ok(())
    }

    pub fn prepare_xray_connection(&self, profile: &Profile) -> io::Result<PreparedXrayConnection> {
        if profile.backend != TunnelBackend::Xray {
            return Err(invalid_data(
                "prepared Xray connection requires an Xray profile",
            ));
        }
        let executable = resolve_xray_executable(self.xray_exe.as_deref())?;
        let config = prepare_xray_config(profile)?;
        let assets = self.xray_asset_dirs.get(&profile.id).cloned();
        run_xray_validation_with_assets(&executable, &config, assets.as_deref())?;
        Ok(PreparedXrayConnection {
            executable,
            config,
            assets,
        })
    }

    /// Revalidate private IPC input against the current approved executable and assets.
    pub fn connect_prepared_xray(
        &mut self,
        profile: &Profile,
        prepared: &PreparedXrayConnection,
    ) -> io::Result<TunnelStatus> {
        self.ensure_not_running(profile)?;
        crate::profiles::validate_profile(profile)?;
        profile.check_role().map_err(invalid_data)?;
        if profile.backend != TunnelBackend::Xray
            || prepared.executable != resolve_xray_executable(self.xray_exe.as_deref())?
            || prepared.assets.as_ref() != self.xray_asset_dirs.get(&profile.id)
        {
            return Err(invalid_data("prepared Xray executable or assets changed"));
        }
        run_xray_validation_with_assets(
            &prepared.executable,
            &prepared.config,
            prepared.assets.as_deref(),
        )?;
        self.spawn_prepared_xray(profile, prepared)
    }

    fn spawn_prepared_xray(
        &mut self,
        profile: &Profile,
        prepared: &PreparedXrayConnection,
    ) -> io::Result<TunnelStatus> {
        let executable = resolve_xray_executable(self.xray_exe.as_deref())?;
        if executable != prepared.executable {
            return Err(invalid_data("prepared Xray executable changed"));
        }
        let (out, err) = self.child_log_stdio(&profile.id, "xray")?;
        let mut child = spawn_xray(
            &executable,
            &prepared.config,
            prepared.assets.as_deref(),
            out,
            err,
        )?;
        if let Err(err) = self.ensure_child_job().and_then(|job| job.assign(&child)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
        self.xray_children.insert(profile.id.clone(), child);
        self.failures.remove(&profile.id);
        Ok(status_for(&profile.id, TunnelState::Running, None))
    }

    pub fn connect(&mut self, profile: &Profile) -> io::Result<TunnelStatus> {
        self.ensure_not_running(profile)?;
        if profile.backend == TunnelBackend::None {
            if profile.routes.is_empty() && profile.endpoint_bypasses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "static-routes profile has no routes or endpoint bypasses to apply",
                ));
            }
            self.static_route_profiles.insert(profile.id.clone());
            self.failures.remove(&profile.id);
            return Ok(status_for(&profile.id, TunnelState::Running, None));
        }
        if !profile.config_path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "profile config '{}' does not exist",
                    profile.config_path.display()
                ),
            ));
        }
        match profile.backend {
            TunnelBackend::WireGuard => {
                let exe = resolve_wireguard_executable(self.wireguard_exe.as_deref())?;
                if self.query_wireguard_service(profile)? {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "WireGuard tunnel service for profile '{}' is already installed",
                            profile.id
                        ),
                    ));
                }
                let spec = wireguard_connect_spec(&exe, profile)?;
                // `wireguard_connect_spec` always produces a transient config
                // (Table = off), so always record it for cleanup on disconnect.
                let transient_path = spec.args.get(1).and_then(|a| a.to_str().map(PathBuf::from));
                run_service_command(&spec)?;
                self.wireguard_services.insert(profile.id.clone());
                if let Some(path) = transient_path {
                    self.wireguard_transient_configs
                        .insert(profile.id.clone(), path);
                }
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Running, None))
            }
            TunnelBackend::OpenVpn => {
                let exe = resolve_openvpn_executable(self.openvpn_exe.as_deref())?;
                let spec = openvpn_connect_spec(&exe, profile)?;
                let (out, err) = self.child_log_stdio(&profile.id, "openvpn")?;
                let mut command = Command::new(&spec.program);
                command
                    .args(&spec.args)
                    .stdin(Stdio::null())
                    .stdout(out)
                    .stderr(err);
                #[cfg(windows)]
                command.creation_flags(CREATE_NO_WINDOW);
                #[cfg(target_os = "linux")]
                terminate_with_parent(&mut command);
                let mut child = command.spawn()?;
                if let Err(err) = self.ensure_child_job().and_then(|job| job.assign(&child)) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(err);
                }
                self.openvpn_children.insert(profile.id.clone(), child);
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Running, None))
            }
            TunnelBackend::Xray => {
                let prepared = self.prepare_xray_connection(profile)?;
                self.spawn_prepared_xray(profile, &prepared)
            }
            TunnelBackend::None => unreachable!("None handled before config_path check"),
        }
    }

    pub fn disconnect(&mut self, profile: &Profile) -> io::Result<TunnelStatus> {
        match profile.backend {
            TunnelBackend::None => {
                self.static_route_profiles.remove(&profile.id);
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Stopped, None))
            }
            TunnelBackend::WireGuard => {
                let exe = resolve_wireguard_executable(self.wireguard_exe.as_deref())?;
                let spec = wireguard_disconnect_spec(&exe, profile)?;
                run_service_command(&spec)?;
                self.wireguard_services.remove(&profile.id);
                self.cleanup_wireguard_transient(&profile.id);
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Stopped, None))
            }
            TunnelBackend::OpenVpn => {
                Self::disconnect_child(&mut self.openvpn_children, &mut self.failures, profile)
            }
            TunnelBackend::Xray => {
                Self::disconnect_child(&mut self.xray_children, &mut self.failures, profile)
            }
        }
    }

    /// Remove the transient `Table = off` config created for `profile_id` if
    /// one exists. Errors are ignored — the file is best-effort cleanup and
    /// its absence does not affect the already-stopped tunnel.
    fn cleanup_wireguard_transient(&mut self, profile_id: &str) {
        if let Some(path) = self.wireguard_transient_configs.remove(profile_id) {
            let _ = std::fs::remove_file(&path);
        }
    }

    fn disconnect_child(
        children: &mut HashMap<String, Child>,
        failures: &mut HashMap<String, String>,
        profile: &Profile,
    ) -> io::Result<TunnelStatus> {
        let mut child = children.remove(&profile.id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("profile '{}' is not running", profile.id),
            )
        })?;
        child.kill()?;
        child.wait()?;
        failures.remove(&profile.id);
        Ok(status_for(&profile.id, TunnelState::Stopped, None))
    }

    fn query_wireguard_service(&self, profile: &Profile) -> io::Result<bool> {
        #[cfg(windows)]
        let running = wireguard_service_running(profile);
        #[cfg(not(windows))]
        let running = Ok(self.wireguard_services.contains(&profile.id));
        running
    }

    pub fn status(&mut self, profile: &Profile) -> TunnelStatus {
        match profile.backend {
            TunnelBackend::None => {
                if self.static_route_profiles.contains(&profile.id) {
                    status_for(&profile.id, TunnelState::Running, None)
                } else {
                    status_for(&profile.id, TunnelState::Stopped, None)
                }
            }
            TunnelBackend::WireGuard => match self.query_wireguard_service(profile) {
                Ok(true) => status_for(&profile.id, TunnelState::Running, None),
                Ok(false) => {
                    self.wireguard_services.remove(&profile.id);
                    self.cleanup_wireguard_transient(&profile.id);
                    status_for(&profile.id, TunnelState::Stopped, None)
                }
                Err(err) => status_for(&profile.id, TunnelState::Failed, Some(err.to_string())),
            },
            TunnelBackend::OpenVpn => Self::child_status(
                &mut self.openvpn_children,
                &mut self.failures,
                &profile.id,
                "openvpn",
            ),
            TunnelBackend::Xray => Self::child_status(
                &mut self.xray_children,
                &mut self.failures,
                &profile.id,
                "xray",
            ),
        }
    }

    fn child_status(
        children: &mut HashMap<String, Child>,
        failures: &mut HashMap<String, String>,
        profile_id: &str,
        name: &str,
    ) -> TunnelStatus {
        if let Some(child) = children.get_mut(profile_id) {
            match child.try_wait() {
                Ok(None) => {
                    return status_for(profile_id, TunnelState::Running, None);
                }
                Ok(Some(exit)) => {
                    let message = format!("{name} exited with {exit}");
                    children.remove(profile_id);
                    failures.insert(profile_id.to_string(), message.clone());
                    return status_for(profile_id, TunnelState::Failed, Some(message));
                }
                Err(err) => {
                    let message = format!("failed to query {name} process: {err}");
                    children.remove(profile_id);
                    failures.insert(profile_id.to_string(), message.clone());
                    return status_for(profile_id, TunnelState::Failed, Some(message));
                }
            }
        }
        if let Some(message) = failures.get(profile_id) {
            return status_for(profile_id, TunnelState::Failed, Some(message.clone()));
        }
        status_for(profile_id, TunnelState::Stopped, None)
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        for (_, mut child) in self
            .openvpn_children
            .drain()
            .chain(self.xray_children.drain())
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DomainPolicy, DomainRouteTarget, PolicyRoute};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-vpn-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepared_xray_uses_retained_bytes_after_source_revision_changes_or_disappears() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        for remove_source in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("xray");
            let captured = directory.path().join("captured.json");
            fs::write(&executable, format!("#!/bin/sh\ncase \" $* \" in *\" -test \"*) /bin/cat >/dev/null; exit 0;; esac\n/bin/cat >'{}'\nexec /bin/sleep 30\n", captured.display())).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
            let path = directory.path().join("config.json");
            fs::write(
                &path,
                br#"{"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}"#,
            )
            .unwrap();
            let mut profile = xray_profile();
            profile.config_path = path.clone();
            let mut manager = TunnelManager::with_all_executables(None, None, Some(executable));
            let prepared = manager.prepare_xray_connection(&profile).unwrap();
            if remove_source {
                fs::remove_file(&path).unwrap();
            } else {
                fs::write(&path, br#"{"outbounds":[],"changed":true}"#).unwrap();
            }
            let result = manager.connect_prepared_xray(&profile, &prepared);
            assert!(
                result.is_ok(),
                "a retained validated snapshot must not reread its mutable source: {result:?}"
            );
            assert_eq!(result.unwrap().state, TunnelState::Running);
            let deadline = Instant::now() + Duration::from_secs(2);
            while fs::metadata(&captured)
                .map(|metadata| metadata.len())
                .unwrap_or(0)
                != prepared.config.len() as u64
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(fs::read(&captured).unwrap(), prepared.config);
            manager.disconnect(&profile).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_xray_child_is_terminated_when_its_spawning_thread_dies() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::ExitStatusExt;
        use std::time::{Duration, Instant};

        let dir = unique_dir("pdeathsig");
        let exe = dir.join("xray");
        fs::write(&exe, "#!/bin/sh\nexec sleep 30\n").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();

        let spawner = exe.clone();
        let mut child = std::thread::spawn(move || {
            spawn_xray(&spawner, b"{}", None, Stdio::null(), Stdio::null()).unwrap()
        })
        .join()
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        fs::remove_dir_all(dir).unwrap();
        assert_eq!(status.and_then(|s| s.signal()), Some(libc::SIGTERM));
    }

    #[test]
    fn set_executable_replaces_backend_path() {
        let mut manager = TunnelManager::new();

        manager.set_executable(
            TunnelBackend::Xray,
            Some(PathBuf::from(r"C:\custom\xray.exe")),
        );
        assert_eq!(manager.xray_exe, Some(PathBuf::from(r"C:\custom\xray.exe")));
        assert_eq!(manager.wireguard_exe, None);
        assert_eq!(manager.openvpn_exe, None);

        manager.set_executable(
            TunnelBackend::WireGuard,
            Some(PathBuf::from(r"C:\custom\wireguard.exe")),
        );
        assert_eq!(
            manager.wireguard_exe,
            Some(PathBuf::from(r"C:\custom\wireguard.exe"))
        );

        manager.set_executable(TunnelBackend::Xray, None);
        assert_eq!(manager.xray_exe, None);
    }

    #[test]
    fn with_all_executables_and_log_dir_sets_paths_and_log_dir() {
        let dir = unique_dir("exelog");
        let manager = TunnelManager::with_all_executables_and_log_dir(
            Some(PathBuf::from(r"C:\bin\wireguard.exe")),
            Some(PathBuf::from(r"C:\bin\openvpn.exe")),
            Some(PathBuf::from(r"C:\bin\xray.exe")),
            dir.clone(),
        );
        assert_eq!(
            manager.wireguard_exe,
            Some(PathBuf::from(r"C:\bin\wireguard.exe"))
        );
        assert_eq!(
            manager.openvpn_exe,
            Some(PathBuf::from(r"C:\bin\openvpn.exe"))
        );
        assert_eq!(manager.xray_exe, Some(PathBuf::from(r"C:\bin\xray.exe")));
        assert_eq!(manager.log_dir, Some(dir));
        fs::remove_dir_all(manager.log_dir.clone().unwrap()).unwrap();
    }

    // Windows treats `/` as a valid separator alongside `\`, so a forward-
    // slash literal like "C:/configs/work.conf" parses identically on
    // Windows and portably (as a plain absolute-looking path) elsewhere,
    // letting these fixtures run cross-platform. `\`-only literals used to
    // break `file_name()`/`std::path::absolute()` derived assertions on
    // non-Windows, where `\` is just an ordinary filename character.
    #[cfg(windows)]
    fn sample_absolute_path(file: &str) -> PathBuf {
        PathBuf::from(format!("C:/configs/{file}"))
    }
    #[cfg(not(windows))]
    fn sample_absolute_path(file: &str) -> PathBuf {
        PathBuf::from(format!("/configs/{file}"))
    }

    fn wg_profile() -> Profile {
        Profile {
            id: "work-wg".into(),
            name: "Work WireGuard".into(),
            backend: TunnelBackend::WireGuard,
            config_path: sample_absolute_path("work.conf"),
            interface_name: "wg-work".into(),
            ..Default::default()
        }
    }

    fn xray_profile() -> Profile {
        Profile {
            id: "work-xray".into(),
            name: "Work Xray".into(),
            backend: TunnelBackend::Xray,
            config_path: sample_absolute_path("node.json"),
            interface_name: String::new(),
            xray_socks_port: Some(10808),
            ..Default::default()
        }
    }

    fn ovpn_profile() -> Profile {
        Profile {
            id: "home-ovpn".into(),
            name: "Home OpenVPN".into(),
            backend: TunnelBackend::OpenVpn,
            config_path: sample_absolute_path("home.ovpn"),
            interface_name: "ovpn-home".into(),
            ..Default::default()
        }
    }

    #[test]
    fn tunnel_name_strips_conf_and_conf_dpapi_case_insensitively() {
        assert_eq!(
            wireguard_tunnel_name(Path::new("C:/c/work.conf")).unwrap(),
            "work"
        );
        assert_eq!(
            wireguard_tunnel_name(Path::new("C:/c/work.conf.dpapi")).unwrap(),
            "work"
        );
        assert_eq!(
            wireguard_tunnel_name(Path::new("C:/c/WORK.CONF.DPAPI")).unwrap(),
            "WORK"
        );
    }

    #[test]
    fn wireguard_connect_spec_is_install_service_with_config_path() {
        // `wireguard_connect_spec` always reads the config to inject
        // `Table = off`, so the config file must exist on disk.
        let dir = std::env::temp_dir().join(format!(
            "netmgr-spec-install-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("work.conf");
        std::fs::write(&config_path, "[Interface]\nPrivateKey = abc\n").unwrap();

        let mut profile = wg_profile();
        profile.config_path = config_path.clone();

        let spec = wireguard_connect_spec(Path::new(r"C:\wg\wireguard.exe"), &profile).unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\wg\wireguard.exe"));
        assert_eq!(spec.args[0], OsString::from("/installtunnelservice"));
        let used_path: PathBuf = spec.args[1].clone().into();
        assert!(used_path.to_string_lossy().ends_with(".table-off.conf"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_disconnect_spec_is_uninstall_service_with_tunnel_name() {
        let spec =
            wireguard_disconnect_spec(Path::new(r"C:\wg\wireguard.exe"), &wg_profile()).unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\wg\wireguard.exe"));
        assert_eq!(
            spec.args,
            vec![
                OsString::from("/uninstalltunnelservice"),
                OsString::from("work"),
            ]
        );
    }

    #[test]
    fn openvpn_spec_always_appends_route_nopull() {
        let spec =
            openvpn_connect_spec(Path::new(r"C:\ovpn\openvpn.exe"), &ovpn_profile()).unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\ovpn\openvpn.exe"));
        // --route-nopull is always passed: the app is the sole route installer.
        assert_eq!(
            spec.args,
            vec![
                OsString::from("--config"),
                sample_absolute_path("home.ovpn").into_os_string(),
                OsString::from("--route-nopull"),
            ]
        );
    }

    #[test]
    fn openvpn_spec_appends_route_nopull_when_routes_exist() {
        let mut profile = ovpn_profile();
        profile.routes = vec![PolicyRoute {
            destination: "10.8.0.0/24".parse().unwrap(),
            metric: 10,
            via: None,
        }];
        let spec = openvpn_connect_spec(Path::new(r"C:\ovpn\openvpn.exe"), &profile).unwrap();
        assert_eq!(
            spec.args,
            vec![
                OsString::from("--config"),
                sample_absolute_path("home.ovpn").into_os_string(),
                OsString::from("--route-nopull"),
            ]
        );
    }

    #[test]
    fn tunnel_name_rejects_unsupported_or_missing_name() {
        assert!(wireguard_tunnel_name(Path::new(r"C:\c\work.txt")).is_err());
        assert!(wireguard_tunnel_name(Path::new(r"C:\c\")).is_err());
        assert!(wireguard_tunnel_name(Path::new(".conf")).is_err());
        let mut bad = wg_profile();
        bad.config_path = PathBuf::from(r"C:\configs\work.txt");
        assert!(wireguard_disconnect_spec(Path::new(r"C:\wg\wireguard.exe"), &bad).is_err());
    }

    #[test]
    fn connect_reaps_stale_exited_openvpn_child() {
        let dir = unique_dir("reap-stale");
        let mut profile = ovpn_profile();
        profile.config_path = dir.join("definitely-absent.ovpn");
        let mut manager = TunnelManager::with_executables(None, Some(dir.join("openvpn.exe")));

        #[cfg(windows)]
        let child = {
            let mut command = Command::new("cmd");
            command
                .args(["/C", "exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            command.spawn().unwrap()
        };
        #[cfg(not(windows))]
        let child = Command::new("sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        manager.openvpn_children.insert(profile.id.clone(), child);

        for _ in 0..20 {
            let exited = manager
                .openvpn_children
                .get_mut(&profile.id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some();
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let err = manager.connect(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!manager.openvpn_children.contains_key(&profile.id));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_service_name_wraps_tunnel_name() {
        assert_eq!(
            wireguard_service_name(&wg_profile()).unwrap(),
            "WireGuardTunnel$work"
        );
        let mut dpapi = wg_profile();
        dpapi.config_path = sample_absolute_path("site.conf.dpapi");
        assert_eq!(
            wireguard_service_name(&dpapi).unwrap(),
            "WireGuardTunnel$site"
        );
        let mut bad = wg_profile();
        bad.config_path = PathBuf::from(r"C:\configs\work.txt");
        assert!(wireguard_service_name(&bad).is_err());
    }

    #[test]
    fn openvpn_status_persists_failure_after_child_exit() {
        let dir = unique_dir("persist-fail");
        let profile = ovpn_profile();
        let mut manager = TunnelManager::with_executables(None, None);

        #[cfg(windows)]
        let child = {
            let mut command = Command::new("cmd");
            command
                .args(["/C", "exit 7"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            command.spawn().unwrap()
        };
        #[cfg(not(windows))]
        let child = Command::new("sh")
            .args(["-c", "exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        manager.openvpn_children.insert(profile.id.clone(), child);

        for _ in 0..20 {
            let exited = manager
                .openvpn_children
                .get_mut(&profile.id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some();
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let first = manager.status(&profile);
        assert_eq!(first.state, TunnelState::Failed);
        assert!(!first.message.as_deref().unwrap_or_default().is_empty());
        assert!(!manager.openvpn_children.contains_key(&profile.id));

        let second = manager.status(&profile);
        assert_eq!(second.state, TunnelState::Failed);
        assert_eq!(second.message, first.message);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_asset_dir_is_set_only_when_given() {
        let mut plain = Command::new("xray");
        use_asset_dir(&mut plain, None);
        assert!(plain.get_envs().next().is_none());
        let mut custom = Command::new("xray");
        use_asset_dir(&mut custom, Some(Path::new("/geo")));
        let envs: Vec<_> = custom.get_envs().collect();
        assert_eq!(
            envs,
            [(
                std::ffi::OsStr::new("XRAY_LOCATION_ASSET"),
                Some(std::ffi::OsStr::new("/geo"))
            )]
        );
    }

    #[test]
    fn a_profiles_asset_dir_can_be_set_and_cleared() {
        let mut manager = TunnelManager::new();
        manager.set_xray_asset_dir("a", Some(PathBuf::from("/geo")));
        assert_eq!(
            manager.xray_asset_dirs.get("a"),
            Some(&PathBuf::from("/geo"))
        );
        manager.set_xray_asset_dir("a", None);
        assert!(manager.xray_asset_dirs.is_empty());
    }

    #[test]
    fn xray_command_spec_uses_run_and_stdin_config() {
        let validation = xray_command_spec(Path::new(r"C:\xray\xray.exe"), true);
        assert_eq!(validation.program, PathBuf::from(r"C:\xray\xray.exe"));
        assert_eq!(
            validation.args,
            vec![
                OsString::from("run"),
                OsString::from("-test"),
                OsString::from("-config"),
                OsString::from("stdin:"),
            ]
        );

        let runtime = xray_command_spec(Path::new(r"C:\xray\xray.exe"), false);
        assert_eq!(
            runtime.args,
            vec![
                OsString::from("run"),
                OsString::from("-config"),
                OsString::from("stdin:"),
            ]
        );
    }

    #[test]
    fn prepare_xray_config_applies_domain_policies() {
        let dir = unique_dir("xray-prepare");
        let path = dir.join("node.json");
        fs::write(
            &path,
            r#"{"outbounds":[{"tag":"proxy","protocol":"vless"}],"routing":{"rules":[]}}"#,
        )
        .unwrap();
        let mut profile = xray_profile();
        profile.config_path = path.clone();
        profile.domain_policies = vec![
            DomainPolicy {
                domains: vec![" example.com ".into()],
                target: DomainRouteTarget::Proxy,
            },
            DomainPolicy {
                domains: vec!["internal.lan".into()],
                target: DomainRouteTarget::Direct,
            },
        ];

        let bytes = prepare_xray_config(&profile).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let rules = doc["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["domain"], serde_json::json!(["example.com"]));
        assert_eq!(rules[0]["outboundTag"], "proxy");
        assert_eq!(rules[1]["outboundTag"], "network-orchestrator-direct");
        assert_eq!(
            rules[2]["ip"],
            serde_json::json!(["224.0.0.0/4", "ff00::/8"])
        );
        assert!(!String::from_utf8_lossy(&bytes).contains(&path.display().to_string()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prepare_xray_config_applies_private_lan_preset_after_user_rules() {
        let dir = unique_dir("xray-private-lan");
        let path = dir.join("node.json");
        fs::write(&path, r#"{"outbounds":[{"tag":"proxy","protocol":"vless"},{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]}}"#).unwrap();
        let mut profile = xray_profile();
        profile.config_path = path;
        profile.private_lan_direct = true;
        profile.domain_policies = vec![DomainPolicy {
            domains: vec!["geoip:us".into()],
            target: DomainRouteTarget::Block,
        }];
        let config: serde_json::Value =
            serde_json::from_slice(&prepare_xray_config(&profile).unwrap()).unwrap();
        assert_eq!(
            config["routing"]["rules"][0]["ip"],
            serde_json::json!(["geoip:us"])
        );
        assert_eq!(
            config["routing"]["rules"][1]["ip"],
            serde_json::json!(["224.0.0.0/4", "ff00::/8"])
        );
        assert_eq!(config["routing"]["rules"][2]["ip"][0], "10.0.0.0/8");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prepare_xray_config_base_applies_policies_without_tun_inbound() {
        let dir = unique_dir("xray-base");
        let path = dir.join("node.json");
        fs::write(
            &path,
            r#"{"inbounds":[{"tag":"socks-in","protocol":"socks","port":10808}],"outbounds":[{"tag":"proxy","protocol":"vless"}],"routing":{"rules":[]}}"#,
        )
        .unwrap();
        let mut profile = xray_profile();
        profile.config_path = path;
        profile.xray_mode = crate::models::XrayMode::Tun;
        profile.domain_policies = vec![DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Direct,
        }];

        let doc: serde_json::Value =
            serde_json::from_slice(&prepare_xray_config_base(&profile).unwrap()).unwrap();
        // Policies are applied but no TUN inbound: the macOS flow validates
        // this form unprivileged, then injects the fd-mode TUN inbound.
        assert!(!crate::xray::has_tun_inbound(&doc));
        assert_eq!(doc["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(doc["inbounds"][0]["protocol"], "socks");
        assert_eq!(
            doc["routing"]["rules"][0]["domain"],
            serde_json::json!(["a.com"])
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prepare_xray_config_rejects_malformed_json_without_echoing_content() {
        let dir = unique_dir("xray-badjson");
        let path = dir.join("node.json");
        let sentinel = "UUID-SENTINEL-12345";
        fs::write(&path, format!("{{\"id\":\"{sentinel}\",broken")).unwrap();
        let mut profile = xray_profile();
        profile.config_path = path.clone();

        let err = prepare_xray_config(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("node.json"));
        assert!(!err.to_string().contains(sentinel));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn prepare_xray_config_decrypts_dpapi_config() {
        let dir = unique_dir("xray-dpapi-prepare");
        let path = dir.join("node.json.dpapi");
        let ciphertext = crate::config_security::protect_user_data(
            br#"{"outbounds":[{"tag":"proxy","protocol":"vless"}],"routing":{"rules":[]}}"#,
            &crate::config_security::xray_context("node-dpapi"),
        )
        .unwrap();
        fs::write(&path, &ciphertext).unwrap();
        let mut profile = xray_profile();
        profile.id = "node-dpapi".into();
        profile.config_path = path;

        let bytes = prepare_xray_config(&profile).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["outbounds"][0]["protocol"], "vless");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_standard_paths_use_unsuffixed_binary_names() {
        for path in xray_standard_paths() {
            assert_eq!(path.file_name().unwrap(), "xray");
        }
        for path in openvpn_standard_paths() {
            assert_eq!(path.file_name().unwrap(), "openvpn");
        }
    }

    #[test]
    fn resolve_xray_executable_rejects_missing_configured_path() {
        let dir = unique_dir("xray-exe");
        let err = resolve_xray_executable(Some(&dir.join("missing-xray.exe"))).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn package_xray_candidate_is_used_only_after_verification() {
        let dir = unique_dir("xray-package-candidate");
        let root = dir.join("xray");
        let candidate = root
            .join(crate::managed_xray::LINUX_XRAY_VERSION)
            .join("xray");
        fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        fs::write(&candidate, b"synthetic binary").unwrap();
        let verified = verified_package_xray_at(&root, |_, path| {
            assert_eq!(path, candidate);
            Ok(())
        })
        .unwrap();
        assert_eq!(verified, Some(candidate.clone()));
        let err = verified_package_xray_at(&root, |_, _| {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tampered secret",
            ))
        })
        .unwrap_err();
        assert!(!err.to_string().contains("tampered secret"));
        assert!(!err.to_string().contains(&dir.display().to_string()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn xray_auto_detect_prefers_verified_package_but_respects_explicit_path() {
        let dir = unique_dir("xray-package-priority");
        let root = dir.join("xray");
        let package = root
            .join(crate::managed_xray::LINUX_XRAY_VERSION)
            .join("xray");
        fs::create_dir_all(package.parent().unwrap()).unwrap();
        fs::write(&package, b"package").unwrap();
        let explicit = dir.join("configured-xray");
        fs::write(&explicit, b"configured").unwrap();
        assert_eq!(
            resolve_xray_executable_with_package_root(None, &root, |_, _| Ok(())).unwrap(),
            package
        );
        assert_eq!(
            resolve_xray_executable_with_package_root(Some(&explicit), &root, |_, _| panic!(
                "package verifier must not run for configured path"
            ))
            .unwrap(),
            explicit
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_connect_rejects_missing_config_before_process() {
        let dir = unique_dir("xray-missing-config");
        let fake_exe = dir.join("xray.exe");
        fs::write(&fake_exe, b"not a real exe").unwrap();
        let mut profile = xray_profile();
        profile.config_path = dir.join("definitely-absent.json");

        let mut manager = TunnelManager::with_all_executables(None, None, Some(fake_exe));
        let err = manager.connect(&profile).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("definitely-absent.json"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_status_persists_failure_after_child_exit() {
        let dir = unique_dir("xray-persist-fail");
        let profile = xray_profile();
        let mut manager = TunnelManager::with_all_executables(None, None, None);

        #[cfg(windows)]
        let child = {
            let mut command = Command::new("cmd");
            command
                .args(["/C", "exit 8"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            command.spawn().unwrap()
        };
        #[cfg(not(windows))]
        let child = Command::new("sh")
            .args(["-c", "exit 8"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        manager.xray_children.insert(profile.id.clone(), child);

        for _ in 0..20 {
            let exited = manager
                .xray_children
                .get_mut(&profile.id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some();
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let first = manager.status(&profile);
        assert_eq!(first.state, TunnelState::Failed);
        assert!(!first.message.as_deref().unwrap_or_default().is_empty());
        assert!(!manager.xray_children.contains_key(&profile.id));

        let second = manager.status(&profile);
        assert_eq!(second.state, TunnelState::Failed);
        assert_eq!(second.message, first.message);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn connect_rejects_missing_config_before_spawning() {
        let dir = unique_dir("missing-config");
        let fake_exe = dir.join("wireguard.exe");
        fs::write(&fake_exe, b"not a real exe").unwrap();
        let mut profile = wg_profile();
        profile.config_path = dir.join("definitely-absent.conf");

        let mut manager = TunnelManager::with_executables(Some(fake_exe), None);
        let err = manager.connect(&profile).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn redact_runtime_log_strips_all_secret_classes() {
        let text = concat!(
            "connecting vless://550e8400-e29b-41d4-a716-446655440000@host:443?sni=x ok\n",
            "password=hunter2 end\n",
            "PASSWORD: hunter3\n",
            "PrivateKey = PRIVVAL-1\n",
            "Authorization: Bearer SECRET-TOKEN-9\n",
            "plain uuid 123e4567-e89b-12d3-a456-426614174000 tail\n",
            "useful line kept\n",
        );
        let out = redact_runtime_log(text);
        for sentinel in [
            "550e8400-e29b-41d4-a716-446655440000",
            "hunter2",
            "hunter3",
            "PRIVVAL-1",
            "SECRET-TOKEN-9",
            "123e4567-e89b-12d3-a456-426614174000",
            "vless://",
        ] {
            assert!(!out.contains(sentinel), "leaked {sentinel}: {out}");
        }
        assert!(out.contains("[redacted]"));
        assert!(out.contains("useful line kept"));
        assert!(out.contains("password=[redacted]"));
    }

    #[test]
    fn redact_runtime_log_preserves_unicode_and_still_redacts() {
        let text = concat!(
            "Привет ✓ İ юникод ✓ password=секрет-ЗНАЧ\n",
            "vless://550e8400-e29b-41d4-a716-446655440000@хост:443\n",
            "uuid 123e4567-e89b-12d3-a456-426614174000 ✓\n",
        );
        let out = redact_runtime_log(text);
        for sentinel in [
            "секрет-ЗНАЧ",
            "550e8400-e29b-41d4-a716-446655440000",
            "123e4567-e89b-12d3-a456-426614174000",
            "vless://",
        ] {
            assert!(!out.contains(sentinel), "leaked {sentinel}: {out}");
        }
        assert!(out.contains("Привет ✓ İ юникод ✓"));
        assert!(out.contains("✓\n"));
    }

    #[test]
    fn child_log_stdio_creates_protected_log_file() {
        let dir = unique_dir("logs");
        let manager = TunnelManager::with_log_dir(dir.join("logs"));
        let (out, err) = manager.child_log_stdio("p1", "openvpn").unwrap();
        drop((out, err));
        let path = dir.join("logs").join("p1-openvpn.log");
        assert!(path.is_file());
        #[cfg(windows)]
        {
            let protection = crate::config_security::inspect_path_protection(&path).unwrap();
            assert!(protection.protected_dacl && protection.current_user);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_tail_returns_redacted_tail() {
        let dir = unique_dir("tail");
        let logs = dir.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("p1-openvpn.log"),
            "line1\npassword=sentinel-x\nline3",
        )
        .unwrap();
        let manager = TunnelManager::with_log_dir(logs);

        let tail = manager.log_tail("p1", 1024).unwrap().unwrap();
        assert!(!tail.contains("sentinel-x"));
        assert!(tail.contains("line3"));

        let short = manager.log_tail("p1", 5).unwrap().unwrap();
        assert!(!short.contains("line1"));

        assert!(manager.log_tail("p1", 0).is_err());
        assert!(manager.log_tail("nobody", 100).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn openvpn_health_maps_status_and_log_markers() {
        let running = status_for("p", TunnelState::Running, None);
        assert_eq!(
            openvpn_health(
                &running,
                Some("note\nInitialization Sequence Completed".into()),
                Vec::new()
            )
            .state,
            ProtocolHealthState::Healthy
        );
        assert_eq!(
            openvpn_health(
                &running,
                Some("Initialization Sequence Completed\nAUTH_FAILED".into()),
                Vec::new()
            )
            .state,
            ProtocolHealthState::Failed
        );
        assert_eq!(
            openvpn_health(&running, Some("connecting...".into()), Vec::new()).state,
            ProtocolHealthState::Degraded
        );
        assert_eq!(
            openvpn_health(&running, None, Vec::new()).state,
            ProtocolHealthState::Degraded
        );
        let failed = status_for("p", TunnelState::Failed, Some("exited".into()));
        assert_eq!(
            openvpn_health(&failed, Some("tail".into()), Vec::new()).state,
            ProtocolHealthState::Failed
        );
        let stopped = status_for("p", TunnelState::Stopped, None);
        assert_eq!(
            openvpn_health(&stopped, None, Vec::new()).state,
            ProtocolHealthState::Unknown
        );
    }

    #[test]
    fn xray_health_uses_not_handshake_verified_wording() {
        let running = status_for("p", TunnelState::Running, None);
        let health = xray_health(&running, Some("tail".into()));
        assert_eq!(health.state, ProtocolHealthState::Degraded);
        assert_eq!(
            health.summary,
            "process running; outbound connectivity is not handshake-verified"
        );
        assert_eq!(health.log_tail.as_deref(), Some("tail"));
        assert_eq!(
            xray_health(&status_for("p", TunnelState::Stopped, None), None).state,
            ProtocolHealthState::Unknown
        );
        let failed = status_for("p", TunnelState::Failed, Some("xray exited".into()));
        let health = xray_health(&failed, Some("tail".into()));
        assert_eq!(health.state, ProtocolHealthState::Failed);
        assert!(health.summary.contains("xray exited"));
    }

    #[test]
    fn parse_wg_dump_sums_peers_without_echoing_keys() {
        let dump = concat!(
            "IFACEKEY\tPUB\t9000\t0\n",
            "PEERKEY-ONE\tpsk\t(none)\t10.0.0.0/24\t1700000000\t100\t200\toff\n",
            "PEERKEY-TWO\tpsk\t10.1.2.3:51820\t10.1.0.0/24\t1700000100\t300\t400\toff\n",
        );
        let (handshake, rx, tx) = parse_wg_dump(dump);
        assert_eq!(handshake, 1700000100);
        assert_eq!(rx, 400);
        assert_eq!(tx, 600);

        let health = wireguard_health_from_dump(dump);
        assert_eq!(health.state, ProtocolHealthState::Healthy);
        assert_eq!(health.last_handshake_unix, Some(1700000100));
        assert_eq!(health.rx_bytes, Some(400));
        assert!(!health.summary.contains("PEERKEY"));
        assert!(!health.summary.contains("10.1.2.3"));

        let zero = "IFACE\tPUB\t0\t0\nPEER\tpsk\t(none)\tip\t0\t0\t0\toff\n";
        assert_eq!(
            wireguard_health_from_dump(zero).state,
            ProtocolHealthState::Degraded
        );
        assert_eq!(
            wireguard_health_from_dump("garbage\n\n").state,
            ProtocolHealthState::Degraded
        );
    }

    #[test]
    fn log_tail_for_tag_reads_only_matching_backend_log() {
        let dir = unique_dir("tag-logs");
        let logs = dir.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("p-openvpn.log"), "AUTH_FAILED: bad creds\n").unwrap();
        fs::write(logs.join("p-xray.log"), "xray started\n").unwrap();
        let manager = TunnelManager::with_log_dir(logs);

        let xray_tail = manager
            .log_tail_for_tag("p", "xray", 1024)
            .unwrap()
            .unwrap();
        assert!(!xray_tail.contains("AUTH_FAILED"), "{xray_tail}");
        let openvpn_tail = manager
            .log_tail_for_tag("p", "openvpn", 1024)
            .unwrap()
            .unwrap();
        assert!(openvpn_tail.contains("AUTH_FAILED"));
        let combined = manager.log_tail("p", 4096).unwrap().unwrap();
        assert!(combined.contains("AUTH_FAILED"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn protocol_health_uses_backend_specific_log() {
        let dir = unique_dir("health-logs");
        let logs = dir.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("p-openvpn.log"), "AUTH_FAILED\n").unwrap();
        fs::write(logs.join("p-xray.log"), "xray started\n").unwrap();
        let mut manager = TunnelManager::with_log_dir(logs);

        let mut xray = xray_profile();
        xray.id = "p".into();
        let child = Command::new("cmd")
            .args(["/C", "ping", "-n", "30", "127.0.0.1", ">NUL"])
            .spawn()
            .unwrap();
        manager.xray_children.insert("p".into(), child);
        let health = manager.protocol_health(&xray);
        assert_ne!(health.state, ProtocolHealthState::Failed);
        let tail = health.log_tail.unwrap_or_default();
        assert!(!tail.contains("AUTH_FAILED"), "{tail}");

        let mut ovpn = ovpn_profile();
        ovpn.id = "p".into();
        let child = Command::new("cmd")
            .args(["/C", "ping", "-n", "30", "127.0.0.1", ">NUL"])
            .spawn()
            .unwrap();
        manager.openvpn_children.insert("p".into(), child);
        let health = manager.protocol_health(&ovpn);
        assert_eq!(health.state, ProtocolHealthState::Failed);
        assert!(health.log_tail.unwrap().contains("AUTH_FAILED"));

        fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod pushed_route_tests {
    use super::*;

    #[test]
    fn parses_ipv4_routes_with_netmask() {
        let log = "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.255.255.0,route 192.168.1.0 255.255.255.0,ifconfig 10.8.0.2 255.255.255.0'";
        let routes = parse_openvpn_pushed_reply(log);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, "10.0.0.0/24".parse().unwrap());
        assert_eq!(routes[1].destination, "192.168.1.0/24".parse().unwrap());
        assert_eq!(routes[0].source, "OpenVPN pushed");
    }

    #[test]
    fn parses_host_route_without_netmask() {
        let log = "PUSH: Received control message: 'PUSH_REPLY,route 10.8.0.1'";
        let routes = parse_openvpn_pushed_reply(log);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "10.8.0.1/32".parse().unwrap());
    }

    #[test]
    fn parses_ipv6_routes() {
        let log = "PUSH: Received control message: 'PUSH_REPLY,route-ipv6 fd00::/64,route-ipv6 2001:db8::/32'";
        let routes = parse_openvpn_pushed_reply(log);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, "fd00::/64".parse().unwrap());
        assert_eq!(routes[1].destination, "2001:db8::/32".parse().unwrap());
    }

    #[test]
    fn deduplicates_repeated_routes() {
        let log = "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.255.255.0,route 10.0.0.0 255.255.255.0'";
        let routes = parse_openvpn_pushed_reply(log);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn ignores_non_route_directives() {
        let log = "PUSH: Received control message: 'PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,route-gateway 10.8.0.1,dhcp-option DNS 8.8.8.8'";
        let routes = parse_openvpn_pushed_reply(log);
        assert!(routes.is_empty());
    }

    #[test]
    fn handles_multiple_push_reply_lines() {
        let log = "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.255.255.0'\nSome other line\nPUSH: Received control message: 'PUSH_REPLY,route 192.168.1.0 255.255.255.0'";
        let routes = parse_openvpn_pushed_reply(log);
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn returns_empty_when_no_push_reply() {
        let log = "Initialization Sequence Completed\nSome warning\nAUTH_FAILED";
        let routes = parse_openvpn_pushed_reply(log);
        assert!(routes.is_empty());
    }

    #[test]
    fn handles_double_quoted_payload() {
        let log = "PUSH: Received control message: \"PUSH_REPLY,route 10.0.0.0 255.255.255.0\"";
        let routes = parse_openvpn_pushed_reply(log);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "10.0.0.0/24".parse().unwrap());
    }

    #[test]
    fn handles_cidr_format_route() {
        let log = "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0/24'";
        let routes = parse_openvpn_pushed_reply(log);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "10.0.0.0/24".parse().unwrap());
    }

    #[test]
    fn openvpn_pushed_routes_reads_full_log() {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-pushed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let logs = dir.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("testprof-openvpn.log"),
            "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.255.255.0,route 10.8.0.1'\nInitialization Sequence Completed\n",
        )
        .unwrap();
        let manager = TunnelManager::with_log_dir(logs);
        let routes = manager.openvpn_pushed_routes("testprof");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, "10.0.0.0/24".parse().unwrap());
        assert_eq!(routes[1].destination, "10.8.0.1/32".parse().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn openvpn_pushed_routes_returns_empty_without_log_dir() {
        let manager = TunnelManager::new();
        let routes = manager.openvpn_pushed_routes("any");
        assert!(routes.is_empty());
    }
}

#[cfg(test)]
mod table_off_tests {
    use super::*;
    use crate::models::{PolicyRoute, Profile, TunnelBackend};
    use std::path::PathBuf;

    fn wg_profile_with_routes(routes: Vec<PolicyRoute>) -> Profile {
        Profile {
            id: "test-wg".into(),
            name: "Test WG".into(),
            backend: TunnelBackend::WireGuard,
            config_path: PathBuf::from(r"C:\configs\test.conf"),
            interface_name: "wg-test".into(),
            routes,
            ..Default::default()
        }
    }

    #[test]
    fn inject_table_off_appends_to_interface_section() {
        let config =
            "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 10.0.0.0/24\n";
        let result = inject_table_off(config);
        assert!(result.contains("Table = off"));
        assert!(result.contains("[Interface]"));
        assert!(result.contains("PrivateKey = abc"));
        assert!(result.contains("[Peer]"));
        assert!(result.contains("AllowedIPs = 10.0.0.0/24"));
    }

    #[test]
    fn inject_table_off_replaces_existing_table_directive() {
        let config = "[Interface]\nPrivateKey = abc\nTable = auto\n\n[Peer]\nPublicKey = def\n";
        let result = inject_table_off(config);
        assert!(result.contains("Table = off"));
        assert!(!result.contains("Table = auto"));
    }

    #[test]
    fn inject_table_off_prepends_interface_if_missing() {
        let config = "[Peer]\nPublicKey = def\nAllowedIPs = 10.0.0.0/24\n";
        let result = inject_table_off(config);
        assert!(result.starts_with("[Interface]"));
        assert!(result.contains("Table = off"));
        assert!(result.contains("[Peer]"));
    }

    #[test]
    fn inject_table_off_preserves_comments() {
        let config = "[Interface]\n# my private key\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\n";
        let result = inject_table_off(config);
        assert!(result.contains("# my private key"));
        assert!(result.contains("Table = off"));
    }

    #[test]
    fn expand_allowedips_adds_uncovered_routes_to_first_peer() {
        let config =
            "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 10.0.0.0/8\n";
        let routes = vec!["192.168.50.0/24".parse().unwrap()];
        let result = expand_allowedips(config, &routes);
        assert!(result.contains("AllowedIPs = 10.0.0.0/8, 192.168.50.0/24"));
    }

    #[test]
    fn expand_allowedips_skips_already_covered_routes() {
        let config =
            "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 10.0.0.0/8\n";
        // 10.20.0.0/16 is already inside 10.0.0.0/8 — no expansion needed.
        let routes = vec!["10.20.0.0/16".parse().unwrap()];
        let result = expand_allowedips(config, &routes);
        assert!(result.contains("AllowedIPs = 10.0.0.0/8"));
        assert!(!result.contains("10.20.0.0/16"));
    }

    #[test]
    fn expand_allowedips_handles_default_route_no_expansion() {
        // 0.0.0.0/0 already covers everything — no expansion needed.
        let config =
            "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 0.0.0.0/0\n";
        let routes = vec!["192.168.50.0/24".parse().unwrap()];
        let result = expand_allowedips(config, &routes);
        assert!(result.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(!result.contains("192.168.50.0/24"));
    }

    #[test]
    fn expand_allowedips_preserves_ipv6_and_deduplicates() {
        let config = "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 10.0.0.0/8, ::/0\n";
        let routes = vec![
            "192.168.50.0/24".parse().unwrap(),
            "10.20.0.0/16".parse().unwrap(), // already covered
        ];
        let result = expand_allowedips(config, &routes);
        assert!(result.contains("10.0.0.0/8"));
        assert!(result.contains("::/0"));
        assert!(result.contains("192.168.50.0/24"));
        assert!(!result.contains("10.20.0.0/16"));
    }

    #[test]
    fn expand_allowedips_no_peer_section_is_noop() {
        let config = "[Interface]\nPrivateKey = abc\n";
        let routes = vec!["192.168.50.0/24".parse().unwrap()];
        let result = expand_allowedips(config, &routes);
        // No [Peer] section — no AllowedIPs to expand. Config content is
        // preserved (lines are rejoined without a trailing newline).
        assert!(result.contains("[Interface]"));
        assert!(result.contains("PrivateKey = abc"));
        assert!(!result.contains("AllowedIPs"));
        assert!(!result.contains("192.168.50.0/24"));
    }

    #[test]
    fn wireguard_connect_spec_uses_transient_when_routes_nonempty() {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-tableoff-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("test.conf");
        std::fs::write(
            &config_path,
            "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 10.0.0.0/24\n",
        )
        .unwrap();

        let mut profile = wg_profile_with_routes(vec![PolicyRoute {
            destination: "10.20.0.0/16".parse().unwrap(),
            metric: 5,
            via: None,
        }]);
        profile.config_path = config_path.clone();

        let spec = wireguard_connect_spec(Path::new(r"C:\wg\wireguard.exe"), &profile).unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\wg\wireguard.exe"));
        assert_eq!(spec.args[0], OsString::from("/installtunnelservice"));
        let transient_path: PathBuf = spec.args[1].clone().into();
        assert!(transient_path
            .to_string_lossy()
            .ends_with(".table-off.conf"));
        assert!(transient_path.is_file(), "transient config should exist");
        let content = std::fs::read_to_string(&transient_path).unwrap();
        assert!(content.contains("Table = off"));
        assert!(content.contains("PrivateKey = abc"));
        // Policy route 10.20.0.0/16 is not inside 10.0.0.0/24, so AllowedIPs
        // is expanded to include it for cryptokey routing. The expanded line
        // contains both prefixes (sorted by prefix length).
        assert!(content.contains("AllowedIPs = "));
        assert!(content.contains("10.0.0.0/24"));
        assert!(content.contains("10.20.0.0/16"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_connect_spec_always_uses_transient() {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-tableoff-always-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("test.conf");
        std::fs::write(&config_path, "[Interface]\nPrivateKey = abc\n").unwrap();

        // Even with no policy routes, the app is the sole route installer, so
        // a transient Table = off config is always produced.
        let mut profile = wg_profile_with_routes(vec![]);
        profile.config_path = config_path.clone();

        let spec = wireguard_connect_spec(Path::new(r"C:\wg\wireguard.exe"), &profile).unwrap();
        let used_path: PathBuf = spec.args[1].clone().into();
        assert!(
            used_path.to_string_lossy().ends_with(".table-off.conf"),
            "expected transient Table = off config, got {used_path:?}"
        );
        assert!(used_path.is_file(), "transient config should exist");
        let content = std::fs::read_to_string(&used_path).unwrap();
        assert!(content.contains("Table = off"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_table_off_config_creates_protected_file() {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-tableoff-protect-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.conf");
        std::fs::write(&source, "[Interface]\nPrivateKey = abc\n").unwrap();

        let transient = wireguard_table_off_config(&source, "test-prof", &[]).unwrap();
        assert!(transient.is_file());
        assert!(transient
            .to_string_lossy()
            .ends_with("test-prof.table-off.conf"));
        let content = std::fs::read_to_string(&transient).unwrap();
        assert!(content.contains("Table = off"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cleanup_wireguard_transient_removes_file() {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-tableoff-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let transient = dir.join("test.table-off.conf");
        std::fs::write(&transient, "[Interface]\nTable = off\n").unwrap();

        let mut manager = TunnelManager::new();
        manager
            .wireguard_transient_configs
            .insert("test".into(), transient.clone());
        assert!(transient.is_file());
        manager.cleanup_wireguard_transient("test");
        assert!(!transient.is_file());
        assert!(!manager.wireguard_transient_configs.contains_key("test"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn static_routes_profile(id: &str, routes: Vec<PolicyRoute>) -> Profile {
        Profile {
            id: id.into(),
            name: id.into(),
            backend: TunnelBackend::None,
            config_path: PathBuf::new(),
            interface_name: "Ethernet".into(),
            routes,
            ..Default::default()
        }
    }

    #[test]
    fn static_routes_connect_requires_routes() {
        let mut manager = TunnelManager::new();
        let profile = static_routes_profile("static", vec![]);
        let err = manager.connect(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn static_routes_connect_and_disconnect_lifecycle() {
        let mut manager = TunnelManager::new();
        let profile = static_routes_profile(
            "static",
            vec![PolicyRoute {
                destination: "10.0.0.0/24".parse().unwrap(),
                metric: 10,
                via: None,
            }],
        );
        let status = manager.connect(&profile).unwrap();
        assert_eq!(status.state, TunnelState::Running);
        assert!(manager.static_route_profiles.contains("static"));

        let status = manager.status(&profile);
        assert_eq!(status.state, TunnelState::Running);

        let status = manager.disconnect(&profile).unwrap();
        assert_eq!(status.state, TunnelState::Stopped);
        assert!(!manager.static_route_profiles.contains("static"));

        let status = manager.status(&profile);
        assert_eq!(status.state, TunnelState::Stopped);
    }

    #[test]
    fn static_routes_protocol_health_reports_active_state() {
        let mut manager = TunnelManager::new();
        let profile = static_routes_profile(
            "static",
            vec![PolicyRoute {
                destination: "10.0.0.0/24".parse().unwrap(),
                metric: 10,
                via: None,
            }],
        );
        let health = manager.protocol_health(&profile);
        assert_eq!(health.state, ProtocolHealthState::Unknown);

        manager.connect(&profile).unwrap();
        let health = manager.protocol_health(&profile);
        assert_eq!(health.state, ProtocolHealthState::Healthy);
        assert_eq!(health.summary, "static routes active");

        manager.disconnect(&profile).unwrap();
        let health = manager.protocol_health(&profile);
        assert_eq!(health.state, ProtocolHealthState::Unknown);
    }
}
