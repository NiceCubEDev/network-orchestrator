//! Darwin IO only. Policy/parsing lives in the portable parent module.
use super::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

const MAX_COMMAND_BYTES: u64 = 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(6);

/// Bound both output and elapsed time, including children retaining stdout.
pub(super) fn read_command(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
) -> std::io::Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(input) = input {
        let result = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("missing stdin"))?
            .write_all(input);
        if let Err(error) = result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("missing stdout"))?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(MAX_COMMAND_BYTES + 1)
            .read_to_end(&mut bytes)
            .and_then(|_| {
                if bytes.len() as u64 > MAX_COMMAND_BYTES {
                    Err(std::io::Error::other("command output is too large"))
                } else {
                    Ok(String::from_utf8_lossy(&bytes).into_owned())
                }
            });
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return Err(std::io::Error::other("command failed")),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(match result {
                    Err(error) => error,
                    _ => std::io::Error::new(std::io::ErrorKind::TimedOut, "command timed out"),
                });
            }
        }
    }
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "command output timed out")
        })?
}

struct Scutil;
impl macos_vpn::ScutilRunner for Scutil {
    fn run(&mut self, args: &[&str]) -> std::io::Result<String> {
        read_command("/usr/sbin/scutil", args, None)
    }
}

fn routes() -> Result<Vec<RouteEntry>, String> {
    static RUNTIME: LazyLock<Result<tokio::runtime::Runtime, std::io::Error>> =
        LazyLock::new(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
        });
    let read = || {
        RUNTIME
            .as_ref()
            .map_err(|_| "Network reader is unavailable".to_string())?
            .block_on(net_manager_core::explorer::list_routes())
            .map_err(|_| "The route table could not be read".to_string())
    };
    // A synchronous caller can itself be inside a runtime; never nest block_on.
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|scope| {
            scope
                .spawn(read)
                .join()
                .map_err(|_| "Network reader is unavailable".to_string())?
        })
    } else {
        read()
    }
}

impl NetworkBackend for SystemNetwork {
    fn user_network_settings(&self) -> Result<UserNetworkSettings, String> {
        Ok(inventory::read())
    }
    fn interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        net_manager_core::explorer::list_interfaces()
            .map_err(|_| "Network interfaces could not be read. Try refreshing.".into())
    }
    fn routes(&self) -> Result<Vec<RouteEntry>, String> {
        routes()
    }
    fn dns_config(&self) -> Result<DnsConfig, String> {
        read_command("/usr/sbin/scutil", &["--dns"], None)
            .map(|text| dns_diag::parse_scutil_dns(&text))
            .map_err(|_| "The DNS configuration could not be read".into())
    }
    fn dns_query(
        &self,
        hostname: &str,
        target: SocketAddr,
        family: DnsFamily,
    ) -> Result<DnsProbeResult, String> {
        dns_probe::probe(hostname, target, family, Duration::from_secs(3)).map_err(|error| {
            match error.kind() {
                std::io::ErrorKind::InvalidInput => "Enter a valid host name".into(),
                std::io::ErrorKind::TimedOut => "The DNS server did not answer in time".into(),
                _ => "The DNS query could not be sent".into(),
            }
        })
    }
    fn external_vpns(&self) -> Result<Vec<ExternalVpn>, String> {
        macos_vpn::list(&mut Scutil)
            .map(|services| services.into_iter().map(ExternalVpn::from).collect())
            .map_err(|_| "VPN services could not be listed".into())
    }
    fn set_external_vpn(&self, id: &str, connect: bool) -> Result<(), String> {
        macos_vpn::set_connected(&mut Scutil, id, connect)
            .map_err(|_| "The VPN service could not be switched".into())
    }
    fn netbird_status(&self, runtime: &Path) -> Result<NetBirdState, String> {
        decode_netbird(net_manager_core::netbird::NetBird::detect().status_in(runtime))
    }
    fn netbird_up(
        &self,
        runtime: &Path,
        options: &NetBirdConnectOptions,
    ) -> Result<NetBirdState, String> {
        let value = net_manager_core::netbird::NetBird::detect().up(
            runtime,
            options
                .management_url
                .as_deref()
                .filter(|value| !value.is_empty()),
            options
                .setup_key
                .as_deref()
                .filter(|value| !value.is_empty()),
        )?;
        decode_netbird(value)
    }
    fn netbird_down(&self, runtime: &Path) -> Result<NetBirdState, String> {
        decode_netbird(net_manager_core::netbird::NetBird::detect().down_in(runtime)?)
    }
    fn netbird_log(&self, runtime: &Path) -> Result<String, String> {
        let mut file = match std::fs::File::open(runtime.join("netbird/up.log")) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
            Err(_) => return Err("The NetBird log could not be read".into()),
        };
        let length = file
            .metadata()
            .map_err(|_| "The NetBird log could not be read")?
            .len();
        let start = length.saturating_sub(64 * 1024);
        file.seek(SeekFrom::Start(start))
            .map_err(|_| "The NetBird log could not be read")?;
        let mut bytes = Vec::new();
        file.take(64 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|_| "The NetBird log could not be read")?;
        let text = String::from_utf8_lossy(&bytes);
        let text = if start > 0 {
            text.split_once('\n').map(|(_, rest)| rest).unwrap_or("")
        } else {
            &text
        };
        let lines: Vec<_> = text.lines().collect();
        Ok(lines[lines.len().saturating_sub(40)..].join("\n"))
    }
    fn tailscale_status(&self) -> Result<TailscaleState, String> {
        decode_tailscale(crate::tailscale::Tailscale::detect().status())
    }
    fn tailscale_control(&self, connect: bool) -> Result<TailscaleState, String> {
        let tailscale = crate::tailscale::Tailscale::detect();
        decode_tailscale(if connect {
            tailscale.up()?
        } else {
            tailscale.down()?
        })
    }
    fn primary_interface(&self) -> Result<Option<String>, String> {
        read_command(
            "/usr/sbin/scutil",
            &[],
            Some(b"show State:/Network/Global/IPv4\nquit\n"),
        )
        .map(|text| parse_primary_interface(&text))
        .map_err(|_| "The primary network interface could not be read".into())
    }
}
