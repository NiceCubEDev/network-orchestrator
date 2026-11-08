//! Connection-set commands use the same store and lifecycle as the GUI.
use super::{auth, commands::Output, ctx::Ctx};
use clap::Subcommand;
use net_manager_core::connection_sets::{self, ConnectionSet};
use net_manager_engine::linux_sets;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum Command {
    List,
    #[command(alias = "show")]
    Get {
        id: String,
    },
    Put {
        #[arg(long)]
        file: PathBuf,
    },
    #[command(alias = "delete")]
    Remove {
        id: String,
    },
    Import {
        #[arg(long)]
        file: PathBuf,
    },
    Capture {
        id: String,
        #[arg(long)]
        name: String,
    },
    Apply {
        id: String,
        /// Private JSON map keyed by profile ID, with credentials and optional remember.
        #[arg(long)]
        credentials_file: Option<PathBuf>,
    },
    Down {
        id: String,
    },
}

fn output(value: &impl Serialize, text: String) -> Result<Output, String> {
    Ok((
        serde_json::to_value(value).map_err(|_| "Cannot encode connection sets")?,
        text,
    ))
}

fn describe(ctx: &Ctx, sets: &[ConnectionSet]) -> Result<String, String> {
    let profiles = ctx.profiles()?;
    Ok(sets
        .iter()
        .map(|set| {
            let missing = connection_sets::missing_members(set, &profiles);
            let suffix = if missing.is_empty() {
                String::new()
            } else {
                format!(" — missing: {}", missing.join(", "))
            };
            format!(
                "{}\t{}\t{} members{suffix}",
                set.id,
                set.name,
                set.profile_ids.len()
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub fn run(ctx: &Ctx, command: Command) -> Result<Output, String> {
    if ctx.root_user {
        return Err("Run connection sets as your own user, without sudo".into());
    }
    match command {
        Command::List => {
            let sets = connection_sets::list(&ctx.root)?;
            output(&sets, describe(ctx, &sets)?)
        }
        Command::Get { id } => {
            let set = connection_sets::get(&ctx.root, &id)?;
            let text = describe(ctx, std::slice::from_ref(&set))?;
            output(&set, text)
        }
        Command::Put { file } => {
            let set = serde_json::from_slice(&connection_sets::read_input(&file)?)
                .map_err(|_| "Invalid connection-set JSON")?;
            let set = connection_sets::put(&ctx.root, &ctx.store(), set)?;
            output(&set, format!("Saved connection set {}", set.id))
        }
        Command::Remove { id } => {
            connection_sets::delete(&ctx.root, &id)?;
            output(
                &serde_json::json!({"removed": id}),
                format!("Removed connection set {id}"),
            )
        }
        Command::Import { file } => {
            let incoming: Vec<ConnectionSet> =
                serde_json::from_slice(&connection_sets::read_input(&file)?)
                    .map_err(|_| "Invalid legacy connection-set JSON")?;
            let sets = connection_sets::import(&ctx.root, incoming)?;
            output(&sets, describe(ctx, &sets)?)
        }
        Command::Capture { id, name } => {
            let set = linux_sets::capture(&ctx.engine, &ctx.root, &ctx.store(), id, name)?;
            output(&set, format!("Captured connection set {}", set.id))
        }
        Command::Apply {
            id,
            credentials_file,
        } => {
            let inputs = if let Some(path) = credentials_file {
                connection_sets::read_credentials_file(&path)?
            } else {
                connection_sets::CredentialInputs::new()
            };
            lifecycle(auth::run(ctx.root_user, || {
                linux_sets::apply(
                    &net_manager_engine::linux_runtime::Context {
                        engine: &ctx.engine,
                        root: &ctx.root,
                        vault: &ctx.vault(),
                        store: &ctx.store(),
                    },
                    &id,
                    ctx,
                    &inputs,
                    Some(ctx.credentials()?),
                )
            })?)
        }
        Command::Down { id } => lifecycle(linux_sets::down(
            &net_manager_engine::linux_runtime::Context {
                engine: &ctx.engine,
                root: &ctx.root,
                vault: &ctx.vault(),
                store: &ctx.store(),
            },
            &id,
        )?),
    }
}

fn lifecycle(result: linux_sets::SetApplyResult) -> Result<Output, String> {
    let text = serde_json::to_string_pretty(&result)
        .map_err(|_| "Cannot encode connection-set outcomes")?;
    output(&result, text)
}
