//! OpenVPN and Xray lifecycle presentation over the common runtime service.
use super::{auth, commands::Output, ctx::Ctx};
use clap::Subcommand;
use net_manager_core::daemon_protocol::OpenVpnCredentials;
use net_manager_core::models::TunnelBackend;
use net_manager_engine::linux_runtime;
use std::io::Read;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum OpenVpnCommand {
    /// Show the daemon's deterministic resource plan without starting a tunnel.
    Plan { profile: String },
    /// Probe server-pushed routes without installing routes or DNS.
    Probe { profile: String },
    /// Connect using the same Secret Service and stdin protocol as `up`.
    Connect {
        profile: String,
        #[arg(long, conflicts_with_all = ["auth_stdin", "passphrase_stdin"])]
        credentials_file: Option<PathBuf>,
        #[arg(long)]
        auth_stdin: bool,
        #[arg(long)]
        passphrase_stdin: bool,
        #[arg(long)]
        remember: bool,
    },
    Credentials {
        #[command(subcommand)]
        command: CredentialsCommand,
    },
}

#[derive(Subcommand)]
pub enum CredentialsCommand {
    Forget { profile: String },
}

fn output(value: impl serde::Serialize, text: &str) -> Result<Output, String> {
    Ok((
        serde_json::to_value(value).map_err(|_| "Cannot encode runtime result")?,
        text.into(),
    ))
}

pub fn run_openvpn(ctx: &Ctx, command: OpenVpnCommand) -> Result<Output, String> {
    match command {
        OpenVpnCommand::Plan { profile } => {
            let profile = ctx.find(&profile)?;
            output(
                linux_runtime::openvpn_plan(&ctx.engine, &ctx.vault(), &profile, ctx)?,
                "OpenVPN resource plan",
            )
        }
        OpenVpnCommand::Probe { profile } => {
            let profile = ctx.find(&profile)?;
            output(
                auth::run(ctx.root_user, || {
                    linux_runtime::openvpn_probe(&ctx.engine, &ctx.vault(), &profile, ctx)
                })?,
                "OpenVPN pushed routes",
            )
        }
        OpenVpnCommand::Connect {
            profile,
            credentials_file,
            auth_stdin,
            passphrase_stdin,
            remember,
        } => {
            if ctx.root_user {
                return Err("Use `netorch up PROFILE --foreground` when connecting as root".into());
            }
            let profile = ctx.find(&profile)?;
            if profile.backend != TunnelBackend::OpenVpn {
                return Err("Profile is not OpenVPN".into());
            }
            let store = ctx.credentials()?;
            let run = |credentials: Option<OpenVpnCredentials>| {
                auth::run(ctx.root_user, || {
                    linux_runtime::connect_with_credentials(
                        &net_manager_engine::linux_runtime::Context {
                            engine: &ctx.engine,
                            root: &ctx.root,
                            vault: &ctx.vault(),
                            store: &ctx.store(),
                        },
                        &profile.id,
                        credentials.clone(),
                        ctx,
                        Some(store),
                        remember,
                    )
                })
            };
            let collect = || {
                let requirements =
                    net_manager_engine::linux::openvpn_requirements(&ctx.vault(), &profile)?;
                crate::prompt::collect(
                    requirements.user_pass,
                    requirements.key_passphrase,
                    auth_stdin,
                    passphrase_stdin,
                )
            };
            let status = if let Some(path) = credentials_file {
                run(Some(read_credentials(&path)?))?
            } else if auth_stdin || passphrase_stdin {
                run(collect()?)?
            } else {
                match run(None) {
                    Err(error)
                        if error == net_manager_engine::linux_engine::CREDENTIALS_REQUIRED =>
                    {
                        run(collect()?)?
                    }
                    result => result?,
                }
            };
            output(status, "OpenVPN connected")
        }
        OpenVpnCommand::Credentials {
            command: CredentialsCommand::Forget { profile },
        } => {
            let profile = ctx.find(&profile)?;
            linux_runtime::forget_credentials(&ctx.vault(), ctx.credentials()?, &profile)?;
            output(
                serde_json::json!({"forgotten": true, "profileId": profile.id}),
                "Remembered OpenVPN credentials removed",
            )
        }
    }
}

fn read_credentials(path: &std::path::Path) -> Result<OpenVpnCredentials, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Cannot open credentials file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect credentials file")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("Credentials file must be private and owned by this user".into());
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read credentials file")?;
    if bytes.len() > 16 * 1024 {
        return Err("Credentials file exceeds its size bound".into());
    }
    let credentials = serde_json::from_slice(&bytes).map_err(|_| "Credentials file is invalid")?;
    net_manager_core::openvpn_management::validate_openvpn_credentials(&credentials)
        .map_err(|_| "Credentials file is invalid")?;
    Ok(credentials)
}

pub fn run_reload(ctx: &Ctx, profile: String) -> Result<Output, String> {
    let profile = ctx.find(&profile)?;
    output(
        auth::run(ctx.root_user, || {
            linux_runtime::reload(&ctx.engine, &ctx.vault(), &profile)
        })?,
        "Xray profile reloaded",
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn credentials_fifo_is_rejected_without_blocking() {
        const CHILD_FIFO: &str = "NETORCH_RUNTIME_TEST_CREDENTIAL_FIFO";
        if let Some(path) = std::env::var_os(CHILD_FIFO) {
            let path = PathBuf::from(path);
            assert!(std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_fifo());
            let error =
                read_credentials(&path).expect_err("a FIFO is not a regular credential file");
            assert_eq!(
                error,
                "Credentials file must be private and owned by this user"
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("credentials.fifo");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a live NUL-terminated string, and mkfifo does not retain it.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "linux::runtime::tests::credentials_fifo_is_rejected_without_blocking",
                "--nocapture",
            ])
            .env(CHILD_FIFO, &fifo)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "credential FIFO rejection failed in child: {status}"
                );
                return;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("credentials FIFO read blocked before regular-file validation");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
