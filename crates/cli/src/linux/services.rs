use super::{commands::Output, ctx::Ctx};
use clap::{Subcommand, ValueEnum};
use net_manager_core::daemon_protocol::{AlwaysOnKind, ConditionalRouteRule};
use net_manager_engine::linux_services as services;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum ServiceCommand {
    Nm {
        #[command(subcommand)]
        command: NmCommand,
    },
    Tailscale {
        #[command(subcommand)]
        command: TailscaleCommand,
    },
    Netbird {
        #[command(subcommand)]
        command: NetbirdCommand,
    },
}

#[derive(Subcommand)]
pub enum NmCommand {
    List,
    Set { uuid: String, state: Switch },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Switch {
    On,
    Off,
}

#[derive(Subcommand)]
pub enum TailscaleCommand {
    Status,
    Up,
    Down,
}

#[derive(Subcommand)]
pub enum NetbirdCommand {
    Status,
    Up {
        #[arg(long)]
        management_url: Option<String>,
        #[arg(long, conflicts_with_all = ["setup_key_stdin", "setup_key_env"])]
        setup_key_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "setup_key_env")]
        setup_key_stdin: bool,
        /// Name of the environment variable containing the setup key.
        #[arg(long)]
        setup_key_env: Option<String>,
    },
    Down,
}

#[derive(Subcommand)]
pub enum AlwaysOnCommand {
    List,
    Set {
        profile: String,
    },
    Remove {
        kind: EnrollmentKind,
        profile_id: String,
    },
    Resume,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum EnrollmentKind {
    #[value(name = "wireguard", alias = "wireGuard", alias = "wg")]
    WireGuard,
    #[value(name = "static-routes", alias = "staticRoutes", alias = "static")]
    StaticRoutes,
}

#[derive(Subcommand)]
pub enum ConditionCommand {
    List,
    Put {
        #[arg(long)]
        file: PathBuf,
    },
    Remove {
        id: String,
    },
}

fn output(value: impl Serialize) -> Result<Output, String> {
    let value = serde_json::to_value(value).map_err(|_| "Could not encode the service result")?;
    let text =
        serde_json::to_string_pretty(&value).map_err(|_| "Could not encode the service result")?;
    Ok((value, text))
}

fn read_key(path: &Path) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "The setup key file could not be opened")?;
    let metadata = file
        .metadata()
        .map_err(|_| "The setup key file could not be read")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 1024
    {
        return Err("The setup key file must be an owned private regular file".into());
    }
    let mut text = String::new();
    file.take(1025)
        .read_to_string(&mut text)
        .map_err(|_| "The setup key file could not be read")?;
    if text.len() > 1024 {
        return Err("The setup key is too large".into());
    }
    Ok(text.trim_end_matches(['\r', '\n']).to_string())
}

pub fn run_service(ctx: &Ctx, command: ServiceCommand) -> Result<Output, String> {
    match command {
        ServiceCommand::Nm {
            command: NmCommand::List,
        } => output(services::nm_list(&ctx.engine)?),
        ServiceCommand::Nm {
            command: NmCommand::Set { uuid, state },
        } => {
            services::nm_set_active(&ctx.engine, &uuid, matches!(state, Switch::On))?;
            output(serde_json::json!({"updated": true}))
        }
        ServiceCommand::Tailscale { command } => output(match command {
            TailscaleCommand::Status => services::tailscale_status(&ctx.engine)?,
            TailscaleCommand::Up => services::tailscale_set_running(&ctx.engine, true)?,
            TailscaleCommand::Down => services::tailscale_set_running(&ctx.engine, false)?,
        }),
        ServiceCommand::Netbird { command } => output(match command {
            NetbirdCommand::Status => services::netbird_status(&ctx.root)?,
            NetbirdCommand::Down => services::netbird_down(&ctx.root)?,
            NetbirdCommand::Up {
                management_url,
                setup_key_file,
                setup_key_stdin,
                setup_key_env,
            } => {
                if ctx.root_user {
                    return Err("Run NetBird control as your own user, without sudo".into());
                }
                let key = if let Some(file) = setup_key_file {
                    Some(read_key(&file)?)
                } else if setup_key_stdin {
                    use std::io::Read;
                    let mut key = String::new();
                    std::io::stdin()
                        .take(1025)
                        .read_to_string(&mut key)
                        .map_err(|_| "Could not read the setup key from stdin")?;
                    if key.len() > 1024 {
                        return Err("The setup key is too large".into());
                    }
                    Some(key.trim_end_matches(['\r', '\n']).to_string())
                } else if let Some(variable) = setup_key_env {
                    Some(
                        std::env::var(variable)
                            .map_err(|_| "The setup key environment variable is unavailable")?,
                    )
                } else {
                    None
                };
                services::netbird_up(&ctx.root, management_url.as_deref(), key.as_deref())?
            }
        }),
    }
}

pub fn run_always_on(ctx: &Ctx, command: AlwaysOnCommand) -> Result<Output, String> {
    match command {
        AlwaysOnCommand::List => output(services::always_on_list(&ctx.engine)?),
        AlwaysOnCommand::Set { profile } => output(services::always_on_set(
            &ctx.engine,
            &ctx.vault(),
            &ctx.find(&profile)?,
        )?),
        AlwaysOnCommand::Remove { kind, profile_id } => output(services::always_on_remove(
            &ctx.engine,
            match kind {
                EnrollmentKind::WireGuard => AlwaysOnKind::WireGuard,
                EnrollmentKind::StaticRoutes => AlwaysOnKind::StaticRoutes,
            },
            &profile_id,
        )?),
        AlwaysOnCommand::Resume => output(services::always_on_resume(&ctx.engine)?),
    }
}

pub fn run_condition(ctx: &Ctx, command: ConditionCommand) -> Result<Output, String> {
    match command {
        ConditionCommand::List => output(services::condition_list(&ctx.engine)?),
        ConditionCommand::Put { file } => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(file)
                .map_err(|_| "The conditional rule file could not be opened")?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "The conditional rule file could not be read")?;
            if bytes.len() > 1024 * 1024 {
                return Err("The conditional rule file is too large".into());
            }
            let rule: ConditionalRouteRule = serde_json::from_slice(&bytes)
                .map_err(|_| "The conditional rule file is invalid")?;
            output(services::condition_put(&ctx.engine, rule)?)
        }
        ConditionCommand::Remove { id } => output(services::condition_remove(&ctx.engine, &id)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn setup_key_input_requires_a_private_regular_non_symlink_file() {
        let root = std::env::temp_dir().join(format!("netorch-service-key-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let key = root.join("key");
        std::fs::write(&key, "ABCD-1234-EFGH\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_key(&key).unwrap(), "ABCD-1234-EFGH");
        let link = root.join("link");
        symlink(&key, &link).unwrap();
        assert!(read_key(&link).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_key(&key).unwrap_err();
        assert!(!error.contains("ABCD-1234-EFGH"));
        assert!(read_key(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
