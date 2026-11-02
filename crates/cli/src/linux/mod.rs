//! `netorch` on Linux: a client of the network daemon, like the app.
//! Plan: docs/plans/2026-10-28-linux-netorch-cli.md.
//!
//! Compiled on Linux, and in macOS test builds so the commands are tested on
//! the development machine (the engine's Linux client is pure).
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod args;
mod auth;
mod commands;
mod compat;
mod ctx;
mod endpoints;
mod hold;
mod library;
mod migrate;
mod route;

use args::{Cli, Command};
use clap::{CommandFactory, Parser};
use std::process::ExitCode;

pub fn main() -> ExitCode {
    let cli = Cli::parse();
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
            print_output(json, &value, &text);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("netorch: {error}");
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
fn needs_daemon(command: &Command) -> bool {
    matches!(
        command,
        Command::Status { .. }
            | Command::Up(_)
            | Command::Down { .. }
            | Command::Switch { .. }
            | Command::Use { .. }
            | Command::Refresh { .. }
            | Command::Rm { .. }
    )
}

fn run(ctx: &ctx::Ctx, command: Command, json: bool) -> Result<commands::Output, String> {
    if needs_daemon(&command) {
        compat::guard(ctx)?;
    }
    match command {
        Command::Version => compat::version(ctx),
        Command::Ls => commands::ls(ctx),
        Command::Status { target } => commands::status(ctx, target.as_deref()),
        Command::Add(args) => library::add(ctx, &args.input, args.name.as_deref()),
        Command::Rm { target } => library::rm(ctx, &target),
        Command::Rename { target, name } => library::rename(ctx, &target, &name),
        Command::Endpoints { target } => endpoints::list(ctx, &target),
        Command::Use { target, server } => endpoints::use_endpoint(ctx, &target, server.as_deref()),
        Command::Switch { target, server } => {
            let (value, text) = endpoints::switch(ctx, &target, server.as_deref())?;
            // A reconnected profile needs its keeper again.
            if value["connected"] == true {
                if let Some(id) = value["id"].as_str() {
                    let _ = hold::ensure_keeper(ctx, &ctx.find(id)?);
                }
            }
            Ok((value, text))
        }
        Command::Route(command) => route::run(ctx, command),
        Command::Backup(command) => endpoints::backup(ctx, command),
        Command::Migrate(command) => migrate::run(ctx, command),
        Command::Refresh { target } => endpoints::refresh(ctx, &target),
        Command::Test(args) => endpoints::test(
            ctx,
            &args.target,
            args.server.as_deref(),
            args.all,
            args.top,
        ),
        Command::Up(args) => up(ctx, &args, json),
        Command::Hold { target } => {
            hold::run_keeper(ctx, &ctx.find(&target)?)?;
            Ok((serde_json::Value::Null, String::new()))
        }
        Command::Down { target, all } => commands::down(ctx, target.as_deref(), all),
        Command::Completions { .. } => unreachable!("handled before the data directory is read"),
    }
}

/// Connects, then keeps the connection: in this terminal with `--foreground`,
/// otherwise through a background keeper, because the daemon removes a tunnel
/// 30 s after the last client process of the user has exited.
fn up(ctx: &ctx::Ctx, args: &args::UpArgs, json: bool) -> Result<commands::Output, String> {
    let (value, mut text) = commands::up(ctx, args)?;
    let profile = ctx.find(value["id"].as_str().unwrap_or_default())?;
    if args.foreground {
        print_output(json, &value, &text);
        let message = hold::run_foreground(ctx, &profile)?;
        return Ok((
            serde_json::json!({"id": profile.id, "state": "stopped"}),
            message,
        ));
    }
    match hold::ensure_keeper(ctx, &profile) {
        Ok(pid) => text.push_str(&format!(
            "\nKept up by background process {pid}; `netorch down` disconnects."
        )),
        Err(error) => text.push_str(&format!(
            "\nWarning: {error}. The daemon will remove the tunnel about 30 s after this \
             command exits; use `netorch up --foreground` to keep it."
        )),
    }
    Ok((value, text))
}
