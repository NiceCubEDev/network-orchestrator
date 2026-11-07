//! Typed network operations; authorization and ownership remain daemon-side.
use super::commands::Output;
use super::ctx::Ctx;
use clap::{Subcommand, ValueEnum};
use net_manager_core::daemon_protocol::{IpFamily, NetDnsProbeParams};
use net_manager_engine::linux_network as network;
use serde::Serialize;
use std::future::Future;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Subcommand)]
pub enum Command {
    Interfaces,
    Routes,
    Interface {
        name: String,
        #[arg(value_enum)]
        state: LinkState,
    },
    StopExternal {
        name: String,
    },
    Tables,
    Route {
        #[command(subcommand)]
        command: EditCommand,
    },
    Rule {
        #[command(subcommand)]
        command: EditCommand,
    },
    Lookup {
        destination: IpAddr,
    },
    Map {
        #[arg(long)]
        include_inactive: bool,
    },
    Explain,
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },
    Intent {
        #[command(subcommand)]
        command: IntentCommand,
    },
    ImportCidrs {
        #[arg(long)]
        file: PathBuf,
    },
    ImportHapp {
        #[arg(long)]
        file: PathBuf,
    },
    TestRoute {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LinkState {
    Up,
    Down,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Family {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Subcommand)]
pub enum EditCommand {
    List,
    Add {
        #[arg(long)]
        file: PathBuf,
    },
    #[command(alias = "del")]
    Delete {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum DnsCommand {
    Status,
    Probe {
        hostname: String,
        #[arg(long)]
        server: Option<IpAddr>,
        #[arg(long, value_enum, default_value = "ipv4")]
        family: Family,
    },
}

#[derive(Debug, Subcommand)]
pub enum IntentCommand {
    List,
    Set {
        #[arg(long)]
        file: PathBuf,
    },
    #[command(alias = "del")]
    Delete {
        id: String,
    },
}

fn input(path: &Path) -> Result<String, String> {
    const MAX_BYTES: u64 = 1024 * 1024;
    let file = std::fs::File::open(path).map_err(|_| "Could not open network input file")?;
    if !file
        .metadata()
        .map_err(|_| "Could not inspect network input file")?
        .is_file()
    {
        return Err("Network input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read network input file")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("Network input exceeds 1 MiB".into());
    }
    String::from_utf8(bytes).map_err(|_| "Network input must be UTF-8".into())
}

fn document<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_str(&input(path)?).map_err(|_| "Invalid network input document".into())
}

fn output(value: impl Serialize) -> Result<Output, String> {
    let value = serde_json::to_value(value).map_err(|_| "Could not encode network result")?;
    let text =
        serde_json::to_string_pretty(&value).map_err(|_| "Could not encode network result")?;
    Ok((value, text))
}

fn block_on<T>(future: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Could not start the network runtime")?
        .block_on(future)
}

pub fn run(ctx: &Ctx, command: Command) -> Result<Output, String> {
    let engine = &ctx.engine;
    match command {
        Command::Interfaces => output(network::interfaces()?),
        Command::Routes => output(block_on(network::routes())?),
        Command::Interface { name, state } => {
            network::set_interface_state(engine, &name, matches!(state, LinkState::Up))?;
            output(serde_json::json!({"name": name, "up": matches!(state, LinkState::Up)}))
        }
        Command::StopExternal { name } => {
            network::stop_external_tunnel(engine, &name)?;
            output(serde_json::json!({"name": name, "stopped": true}))
        }
        Command::Tables => output(network::tables(engine)?),
        Command::Route { command } => match command {
            EditCommand::List => output(network::tables(engine)?.routes),
            EditCommand::Add { file } => {
                network::route_add(engine, document(&file)?)?;
                output(serde_json::json!({"added": true}))
            }
            EditCommand::Delete { file } => {
                output(network::route_delete(engine, document(&file)?)?)
            }
        },
        Command::Rule { command } => match command {
            EditCommand::List => output(network::tables(engine)?.rules),
            EditCommand::Add { file } => {
                network::rule_add(engine, document(&file)?)?;
                output(serde_json::json!({"added": true}))
            }
            EditCommand::Delete { file } => output(network::rule_delete(engine, document(&file)?)?),
        },
        Command::Lookup { destination } => output(block_on(network::lookup(destination))?),
        Command::Map { include_inactive } => output(block_on(network::route_map(
            engine,
            &ctx.store(),
            include_inactive,
        ))?),
        Command::Explain => output(network::explain(engine)?),
        Command::Dns { command } => match command {
            DnsCommand::Status => output(network::dns_status(engine)?),
            DnsCommand::Probe {
                hostname,
                server,
                family,
            } => output(network::dns_probe(
                engine,
                NetDnsProbeParams {
                    hostname,
                    server,
                    family: Some(match family {
                        Family::Ipv4 => IpFamily::Ipv4,
                        Family::Ipv6 => IpFamily::Ipv6,
                    }),
                },
            )?),
        },
        Command::Intent { command } => match command {
            IntentCommand::List => output(network::intent_list(engine)?),
            IntentCommand::Set { file } => output(network::intent_set(engine, document(&file)?)?),
            IntentCommand::Delete { id } => output(network::intent_delete(engine, &id)?),
        },
        Command::ImportCidrs { file } => output(network::parse_bulk_cidrs(&input(&file)?)?),
        Command::ImportHapp { file } => output(network::parse_happ_routing(&input(&file)?)?),
        Command::TestRoute { file } => output(network::test_route(&ctx.root, document(&file)?)?),
    }
}
