//! `netorch` on Linux: a client of the network daemon, like the app.
//! Plan: docs/plans/2026-10-28-linux-netorch-cli.md.
//!
//! Compiled on Linux, and in macOS test builds so the commands are tested on
//! the development machine (the engine's Linux client is pure).
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod args;
mod auth;
mod checks;
mod commands;
mod compat;
mod ctx;
mod endpoints;
mod hold;
mod library;
mod migrate;
mod observe;
mod proxy;
mod route;

use args::{Cli, Command};
use clap::{CommandFactory, Parser};
use std::process::ExitCode;

pub fn main() -> ExitCode {
    let private_command = std::env::args_os().find_map(|arg| match arg.to_str() {
        Some("checks") => Some("checks"),
        Some("proxy") => Some("proxy"),
        _ => None,
    });
    let json_requested = std::env::args_os().any(|arg| arg == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if json_requested
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) =>
        {
            eprintln!(
                "{}",
                serde_json::json!({"error":{"kind":"usage","message":"Invalid arguments; use --help for usage."}})
            );
            return ExitCode::from(2);
        }
        Err(error)
            if private_command.is_some()
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) =>
        {
            let command = private_command.unwrap_or("proxy");
            eprintln!("netorch: invalid {command} arguments; use `netorch {command} --help`");
            return ExitCode::from(2);
        }
        Err(error) => error.exit(),
    };
    if let Command::Completions { shell } = &cli.command {
        clap_complete::generate(
            *shell,
            &mut Cli::command(),
            "netorch",
            &mut std::io::stdout(),
        );
        return ExitCode::SUCCESS;
    }
    let json = cli.json;
    let recovery_cleanup = matches!(&cli.command, Command::Recover { cleanup: true });
    let watch = matches!(&cli.command, Command::Watch { .. });
    let result = cli
        .data_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(ctx::default_root)
        .and_then(|root| {
            ctx::Ctx::new(
                root,
                net_manager_engine::linux_engine::LinuxEngine::new(format!(
                    "netorch/{}",
                    compat::CLIENT_VERSION
                )),
            )
        })
        .and_then(|ctx| run(&ctx, cli.command, json));
    match result {
        Ok((value, text)) => {
            if !(value.is_null() && text.is_empty()) {
                print_output(json, &value, &text);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if json {
                let message = if (recovery_cleanup
                    && (error.starts_with("local cleanup or proxy restoration failed")
                        || error.starts_with("daemon cleanup failed")))
                    || (watch
                        && [
                            observe::WATCH_UNSUPPORTED,
                            observe::WATCH_INCOMPATIBLE,
                            observe::WATCH_PROTOCOL,
                        ]
                        .contains(&error.as_str()))
                {
                    error.as_str()
                } else {
                    "The operation failed."
                };
                eprintln!(
                    "{}",
                    serde_json::json!({"error":{"kind":"operation","message":message}})
                );
            } else {
                eprintln!("netorch: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn print_output(json: bool, value: &serde_json::Value, text: &str) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".into())
        );
    } else if !text.is_empty() {
        println!("{text}");
    }
}

/// Commands that call the network daemon: the daemon is checked first.
fn needs_daemon(ctx: &ctx::Ctx, command: &Command) -> bool {
    use net_manager_engine::linux_engine::LinuxEngine;
    let target = match command {
        Command::Up(args) => Some(args.target.as_str()),
        Command::Status { target } | Command::Down { target, .. } => target.as_deref(),
        Command::Switch { target, .. }
        | Command::Use { target, .. }
        | Command::Refresh { target }
        | Command::Rm { target } => Some(target.as_str()),
        _ => None,
    };
    if let Some(target) = target {
        if ctx
            .find(target)
            .is_ok_and(|profile| !LinuxEngine::requires_daemon(&profile))
        {
            return false;
        }
    } else if matches!(
        command,
        Command::Status { .. } | Command::Down { all: true, .. }
    ) && ctx.profiles().is_ok_and(|profiles| {
        !profiles.is_empty()
            && profiles
                .iter()
                .all(|profile| !LinuxEngine::requires_daemon(profile))
    }) {
        return false;
    }
    matches!(
        command,
        Command::Status { .. }
            | Command::Up(_)
            | Command::Down { .. }
            | Command::Switch { .. }
            | Command::Use { .. }
            | Command::Refresh { .. }
            | Command::Rm { .. }
            | Command::Proxy(args::ProxyArgs {
                command: args::ProxyCommand::Run(_),
                ..
            })
    )
}

fn run(ctx: &ctx::Ctx, command: Command, json: bool) -> Result<commands::Output, String> {
    if needs_daemon(ctx, &command) {
        compat::guard(ctx)?;
    }
    match command {
        #[cfg(target_os = "linux")]
        Command::Serve => net_manager_engine::linux_session::serve(
            ctx.root.clone(),
            net_manager_engine::linux_engine::daemon_socket(),
        )
        .map(|_| (serde_json::Value::Null, String::new())),
        Command::Version => compat::version(ctx),
        Command::Ls => commands::ls(ctx),
        Command::Status { target } => commands::status(ctx, target.as_deref()),
        Command::Watch { target } => observe::watch(ctx, target.as_deref(), json),
        Command::Diagnose { target } => observe::diagnose(ctx, target.as_deref()),
        Command::Recover { cleanup } => observe::recover(ctx, cleanup),
        Command::Add(args) => library::add(ctx, &args.input, args.name.as_deref()),
        Command::Rm { target } => library::rm(ctx, &target),
        Command::Rename { target, name } => library::rename(ctx, &target, &name),
        Command::Endpoints { target } => endpoints::list(ctx, &target),
        Command::Use { target, server } => endpoints::use_endpoint(ctx, &target, server.as_deref()),
        Command::Switch { target, server } => endpoints::switch(ctx, &target, server.as_deref()),
        Command::Route(command) => route::run(ctx, command),
        Command::Backup(command) => endpoints::backup(ctx, command),
        Command::Migrate(command) => migrate::run(ctx, command),
        Command::Checks(command) => checks::run(ctx, command),
        Command::Proxy(args) => proxy::run(ctx, args, json),
        Command::Refresh { target } => endpoints::refresh(ctx, &target),
        Command::Test(args) => endpoints::test(
            ctx,
            &args.target,
            args.server.as_deref(),
            args.all,
            args.top,
        ),
        Command::Up(args) => up(ctx, &args, json),
        Command::Down { target, all } => commands::down(ctx, target.as_deref(), all),
        Command::Completions { .. } => unreachable!("handled before the data directory is read"),
    }
}

/// Foreground mode disconnects when this terminal receives a termination signal.
fn up(ctx: &ctx::Ctx, args: &args::UpArgs, json: bool) -> Result<commands::Output, String> {
    let (value, mut text) = commands::up(ctx, args)?;
    if args.foreground {
        let profile = ctx.find(value["id"].as_str().unwrap_or_default())?;
        print_output(json, &value, &text);
        let message = hold::run_foreground(ctx, &profile)?;
        return Ok((
            serde_json::json!({"id": profile.id, "state": "stopped"}),
            message,
        ));
    }
    text.push_str("\nUse `netorch down` to disconnect.");
    Ok((value, text))
}
