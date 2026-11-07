//! System and managed-backend commands over the shared Linux services.
use super::{commands::Output, ctx::Ctx};
use clap::{Subcommand, ValueEnum};
use net_manager_core::daemon_protocol::VpnAuthMode;
use net_manager_core::models::TunnelBackend;
use net_manager_engine::{linux_runtime, linux_system as service};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum SystemCommand {
    Elevated,
    DaemonStatus,
    Capabilities,
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Autostart {
        #[command(subcommand)]
        command: AutostartCommand,
    },
    AutoConnect {
        #[command(subcommand)]
        command: AutoConnectCommand,
    },
}
#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    Status,
}
#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    Get,
    Set {
        #[arg(value_enum)]
        mode: AuthMode,
    },
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AuthMode {
    NoPrompt,
    FullTunnelOnly,
    Always,
}
#[derive(Debug, Subcommand)]
pub enum AutostartCommand {
    Get,
    Set {
        #[arg(value_enum)]
        enabled: Toggle,
    },
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Toggle {
    On,
    Off,
}
#[derive(Debug, Subcommand)]
pub enum AutoConnectCommand {
    Run,
    Result,
}
#[derive(Debug, Subcommand)]
pub enum BackendCommand {
    List,
    Path {
        #[command(subcommand)]
        command: PathCommand,
    },
    Xray {
        #[command(subcommand)]
        command: XrayCommand,
    },
}
#[derive(Debug, Subcommand)]
pub enum PathCommand {
    Set {
        #[arg(value_enum)]
        backend: Backend,
        path: PathBuf,
    },
    Reset {
        #[arg(value_enum)]
        backend: Backend,
    },
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Backend {
    Wireguard,
    Openvpn,
    Xray,
}
impl From<Backend> for TunnelBackend {
    fn from(value: Backend) -> Self {
        match value {
            Backend::Wireguard => Self::WireGuard,
            Backend::Openvpn => Self::OpenVpn,
            Backend::Xray => Self::Xray,
        }
    }
}
#[derive(Debug, Subcommand)]
pub enum XrayCommand {
    Offer,
    Install,
    Cancel,
    Remove,
}
fn output(value: impl serde::Serialize) -> Result<Output, String> {
    let value = serde_json::to_value(value).map_err(|_| "Cannot encode system response")?;
    let text = serde_json::to_string_pretty(&value).map_err(|_| "Cannot render system response")?;
    Ok((value, text))
}
fn completed() -> Result<Output, String> {
    output(serde_json::json!({"ok": true}))
}

pub fn run_system(ctx: &Ctx, command: SystemCommand) -> Result<Output, String> {
    match command {
        SystemCommand::Elevated => output(service::is_elevated()),
        SystemCommand::DaemonStatus => output(service::daemon_status(&ctx.engine)?),
        SystemCommand::Capabilities => output(service::platform_capabilities()),
        SystemCommand::Proxy {
            command: ProxyCommand::Status,
        } => output(service::system_proxy_status(
            &ctx.engine,
            &ctx.root,
            &ctx.store(),
        )?),
        SystemCommand::Auth {
            command: AuthCommand::Get,
        } => output(service::vpn_auth_mode(&ctx.engine)?),
        SystemCommand::Auth {
            command: AuthCommand::Set { mode },
        } => {
            service::set_vpn_auth_mode(
                &ctx.engine,
                match mode {
                    AuthMode::NoPrompt => VpnAuthMode::NoPrompt,
                    AuthMode::FullTunnelOnly => VpnAuthMode::FullTunnelOnly,
                    AuthMode::Always => VpnAuthMode::Always,
                },
            )?;
            completed()
        }
        SystemCommand::Autostart {
            command: AutostartCommand::Get,
        } => output(service::login_autostart()?),
        SystemCommand::Autostart {
            command: AutostartCommand::Set { enabled },
        } => output(service::set_login_autostart(matches!(enabled, Toggle::On))?),
        SystemCommand::AutoConnect {
            command: AutoConnectCommand::Result,
        } => output(linux_runtime::auto_connect_result(&ctx.root)?),
        SystemCommand::AutoConnect {
            command: AutoConnectCommand::Run,
        } => output(linux_runtime::run_auto_connect(
            &ctx.engine,
            &ctx.root,
            &ctx.vault(),
            &ctx.store(),
            ctx,
        )?),
    }
}

pub fn run_backend(ctx: &Ctx, command: BackendCommand) -> Result<Output, String> {
    match command {
        BackendCommand::List => output(service::backend_availability(&ctx.engine, &ctx.root)?),
        BackendCommand::Path {
            command: PathCommand::Set { backend, path },
        } => {
            service::set_backend_executable(
                &ctx.engine,
                &ctx.root,
                &ctx.store(),
                backend.into(),
                &path,
            )?;
            completed()
        }
        BackendCommand::Path {
            command: PathCommand::Reset { backend },
        } => {
            service::reset_backend_executable(
                &ctx.engine,
                &ctx.root,
                &ctx.store(),
                backend.into(),
            )?;
            completed()
        }
        BackendCommand::Xray {
            command: XrayCommand::Offer,
        } => output(service::managed_xray_offer()),
        BackendCommand::Xray {
            command: XrayCommand::Install,
        } => {
            tokio::runtime::Runtime::new()
                .map_err(|_| "Cannot start download runtime")?
                .block_on(service::install_managed_xray(
                    &ctx.engine,
                    &ctx.root,
                    &ctx.store(),
                    &|progress| {
                        if let Some(total) = progress.total {
                            eprintln!(
                                "Xray {}: {}/{} bytes",
                                progress.stage, progress.downloaded, total
                            );
                        } else {
                            eprintln!("Xray {}: {} bytes", progress.stage, progress.downloaded);
                        }
                    },
                ))?;
            completed()
        }
        BackendCommand::Xray {
            command: XrayCommand::Cancel,
        } => {
            service::cancel_managed_xray_install(&ctx.root)?;
            completed()
        }
        BackendCommand::Xray {
            command: XrayCommand::Remove,
        } => {
            service::remove_managed_xray(&ctx.engine, &ctx.root, &ctx.store())?;
            completed()
        }
    }
}
