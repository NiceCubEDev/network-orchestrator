use super::commands::Output;
use super::ctx::Ctx;
use clap::{Subcommand, ValueEnum};
use net_manager_engine::linux_diagnostics as shared;
use serde::Serialize;
use std::future::Future;

#[derive(Debug, Subcommand)]
pub enum DiagnosticsCommand {
    Inspect {
        #[arg(required_unless_present = "all")]
        profile: Option<String>,
        #[arg(long, conflicts_with = "profile")]
        all: bool,
    },
    Diagnose {
        profile: String,
    },
    Stats {
        profile: String,
    },
    ExitIp,
    Proxies,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Level {
    Info,
    Warn,
    Error,
}
impl From<Level> for shared::LogLevel {
    fn from(level: Level) -> Self {
        match level {
            Level::Info => Self::Info,
            Level::Warn => Self::Warn,
            Level::Error => Self::Error,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum LogsCommand {
    Show {
        #[arg(long)]
        level: Option<Level>,
        #[arg(long)]
        contains: Option<String>,
    },
    Clear,
    Daemon {
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=500))]
        lines: u32,
    },
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    Report,
    Cleanup,
}

fn output(value: impl Serialize) -> Result<Output, String> {
    let value = serde_json::to_value(value).map_err(|_| "Cannot encode diagnostics")?;
    let text = serde_json::to_string_pretty(&value).map_err(|_| "Cannot encode diagnostics")?;
    Ok((value, text))
}

fn run_async<T>(future: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::runtime::Runtime::new()
        .map_err(|_| "Cannot start diagnostics worker")?
        .block_on(future)
}

pub fn run_diagnostics(ctx: &Ctx, command: DiagnosticsCommand) -> Result<Output, String> {
    match command {
        DiagnosticsCommand::Inspect { all: true, .. } => {
            output(run_async(shared::inspect_all(&ctx.vault(), &ctx.store()))?)
        }
        DiagnosticsCommand::Inspect {
            profile: Some(query),
            ..
        } => {
            let profile = ctx.find(&query)?;
            output(run_async(shared::inspect(
                &ctx.vault(),
                &ctx.store(),
                &profile.id,
            ))?)
        }
        DiagnosticsCommand::Inspect { .. } => Err("A profile or --all is required".into()),
        DiagnosticsCommand::Diagnose { profile: query } => {
            let profile = ctx.find(&query)?;
            output(run_async(shared::diagnose(
                &ctx.engine,
                &ctx.root,
                &ctx.vault(),
                &ctx.store(),
                &profile.id,
            ))?)
        }
        DiagnosticsCommand::Stats { profile: query } => {
            output(shared::stats(&ctx.engine, &ctx.find(&query)?)?)
        }
        DiagnosticsCommand::Proxies => output(run_async(shared::scan_local_proxies())?),
        DiagnosticsCommand::ExitIp => {
            let entries = std::sync::Mutex::new(Vec::new());
            run_async(shared::check_exit_ips(&|entry| {
                entries
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(entry)
            }))?;
            output(
                entries
                    .into_inner()
                    .map_err(|_| "Exit-IP results unavailable")?,
            )
        }
    }
}

pub fn run_logs(ctx: &Ctx, command: LogsCommand) -> Result<Output, String> {
    match command {
        LogsCommand::Show { level, contains } => output(shared::filtered_logs(
            &ctx.root,
            level.map(Into::into),
            contains.as_deref(),
        )?),
        LogsCommand::Clear => {
            if ctx.root_user {
                return Err("Run log mutations as your own user, never root".into());
            }
            shared::clear_logs(&ctx.root)?;
            output(serde_json::json!({"cleared": true}))
        }
        LogsCommand::Daemon { lines } => output(run_async(shared::daemon_log_tail(lines))?),
    }
}

pub fn run_recovery(ctx: &Ctx, command: RecoveryCommand) -> Result<Output, String> {
    match command {
        RecoveryCommand::Report => output(run_async(shared::recovery_report(
            &ctx.engine,
            &ctx.root,
            &ctx.vault(),
            &ctx.store(),
        ))?),
        RecoveryCommand::Cleanup => output(run_async(shared::cleanup_recovery(
            &ctx.engine,
            &ctx.root,
            &ctx.vault(),
            &ctx.store(),
        ))?),
    }
}
