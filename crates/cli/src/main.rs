//! `netorch`: one command for VPN profiles, tunnels and routing.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    all(unix, feature = "macos-cli")
)))]
fn main() {
    eprintln!("netorch requires macOS or Linux");
    std::process::exit(1);
}

#[cfg(all(target_os = "linux", not(feature = "macos-cli")))]
fn main() -> std::process::ExitCode {
    linux::main()
}
#[cfg(any(
    all(target_os = "linux", not(feature = "macos-cli")),
    all(target_os = "macos", test)
))]
mod linux;
#[cfg(unix)]
mod prompt;
#[cfg(unix)]
mod render;
#[cfg(unix)]
mod target;

#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod args;
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod business;
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod connect;
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod ctx;
#[cfg(target_os = "macos")]
mod inproc;
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod input;
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod library;
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod route;
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod service;
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
mod system;

#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
fn main() -> std::process::ExitCode {
    use args::{Cli, Command};
    use clap::{CommandFactory, Parser};
    let cli = Cli::parse();
    if let Command::Completions { shell } = &cli.command {
        clap_complete::generate(
            *shell,
            &mut Cli::command(),
            "netorch",
            &mut std::io::stdout(),
        );
        return std::process::ExitCode::SUCCESS;
    }
    let result = match cli.command {
        Command::Service(command) => system::service(cli.json, command),
        command => cli
            .data_dir
            .map(Ok)
            .unwrap_or_else(ctx::default_root)
            .and_then(|root| ctx::Ctx::new(root, cli.json))
            .and_then(|ctx| run(&ctx, command)),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "netorch: {}",
                net_manager_core::log_sanitize::sanitize_log_text(&error)
            );
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(any(target_os = "macos", all(unix, feature = "macos-cli")))]
fn run(ctx: &ctx::Ctx, command: args::Command) -> Result<(), String> {
    use args::Command;
    match command {
        Command::Ls => library::ls(ctx),
        Command::Status { target } => library::status(ctx, target.as_deref()),
        Command::Add(args) => library::add(ctx, args),
        Command::Rm { target } => library::rm(ctx, &target),
        Command::Rename { target, name } => library::rename(ctx, &target, &name),
        Command::Up(args) => connect::up(ctx, args),
        Command::Down { target, all } => connect::down(ctx, target.as_deref(), all),
        Command::Logs { target } => library::logs(ctx, &target),
        Command::Test(args) => library::test(ctx, args),
        Command::Route(command) => route::run(ctx, command),
        Command::Doctor => system::doctor(ctx),
        Command::Backend(command) => system::backend(ctx, command),
        Command::Service(command) => system::service(ctx.json, command),
        Command::Serve => connect::serve(ctx),
        Command::Completions { .. } => Ok(()),
        other => business::run(ctx, other),
    }
}
