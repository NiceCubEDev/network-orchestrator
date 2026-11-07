//! Adding, removing and renaming saved profiles. The import code is the same
//! `net-manager-core` code the app runs; nothing here starts a tunnel.
use super::commands::Output;
use super::ctx::Ctx;
use crate::render::row_of;
use crate::target::{self, Input};
use net_manager_core::daemon_protocol::{method, AlwaysOnListResult};
use net_manager_core::models::{Profile, TunnelBackend, TunnelState};
use net_manager_core::profile_import;
use net_manager_core::subscription::{self, SubscriptionImport};
use net_manager_engine::linux_engine::LinuxEngine;
use serde_json::json;
use std::collections::HashSet;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;

fn loopback_port_available(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

fn random_suffix() -> Result<String, String> {
    let mut bytes = [0u8; 3];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|_| "No random source")?,
        &mut bytes,
    )
    .map_err(|_| "No random source".to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The machine's stable id, hashed into the HWID subscription panels expect.
/// It differs from the app's HWID, so a panel counts the CLI as its own device.
fn hwid() -> String {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .map(|id| id.trim().to_string())
        .find(|id| !id.is_empty())
        .map(|id| subscription::derive_hwid(&id))
        .unwrap_or_default()
}

/// Commands that write the app's data must not run as root: the files would
/// become root-owned and the app could no longer change them.
pub fn require_user(ctx: &Ctx) -> Result<(), String> {
    if ctx.root_user {
        Err("This command changes your Network Orchestrator data; run it without sudo".into())
    } else {
        Ok(())
    }
}

fn io_message(error: std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::AlreadyExists => error.to_string(),
        _ => "The profile could not be saved. Check the input and file permissions.".into(),
    }
}

fn new_since(ctx: &Ctx, before: &HashSet<String>) -> Result<Vec<Profile>, String> {
    Ok(ctx
        .profiles()?
        .into_iter()
        .filter(|profile| !before.contains(&profile.id))
        .collect())
}

fn rename_to(ctx: &Ctx, id: &str, name: &str) -> Result<Profile, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 128 || name.contains(['\r', '\n']) {
        return Err("The name must be 1-128 characters on one line".into());
    }
    let document = ctx
        .store()
        .update_profile(id, |profile| {
            profile.name = name.to_string();
            Ok(())
        })
        .map_err(|_| "The profile could not be saved".to_string())?;
    Ok(document
        .profiles
        .into_iter()
        .find(|profile| profile.id == id)
        .expect("updated profile remains in its document"))
}

/// Saves what `input` points at: a share link, a subscription URL or a
/// `.conf` / `.ovpn` / `.json` file. A subscription can add several profiles.
pub fn add_input(ctx: &Ctx, input: &str, name: Option<&str>) -> Result<Vec<Profile>, String> {
    require_user(ctx)?;
    let before: HashSet<String> = ctx.profiles()?.into_iter().map(|p| p.id).collect();
    let suffix = random_suffix()?;
    match target::classify(input, |path| path.is_file()) {
        Input::Saved(_) => {
            return Err(
                "That is not a vless:// / hysteria2:// link, an https:// subscription \
                        URL or an existing .conf / .ovpn / .json file."
                    .into(),
            )
        }
        Input::ShareLink(link) => {
            let name = name
                .map(str::to_string)
                .or_else(|| target::link_name(&link))
                .unwrap_or_else(|| "Imported".into());
            let id = target::make_id(&name, &suffix);
            profile_import::import_share_link(
                &ctx.vault(),
                &ctx.store(),
                &id,
                &name,
                &link,
                loopback_port_available,
            )
            .map_err(io_message)?;
        }
        Input::Subscription(url) => {
            let hwid = hwid();
            let id = target::make_id("subscription", &suffix);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "Could not start the network runtime".to_string())?;
            let fetched = runtime
                .block_on(async {
                    let client = subscription::http_client()?;
                    subscription::fetch(&client, &url, &hwid).await
                })
                .map_err(|error| error.to_string())?;
            subscription::import_body(
                &ctx.vault(),
                &ctx.store(),
                &SubscriptionImport {
                    id: &id,
                    url: &url,
                    hwid: &hwid,
                    name: "",
                    refresh_interval_minutes: None,
                },
                &fetched.body,
                fetched.meta,
                loopback_port_available,
            )
            .map_err(io_message)?;
        }
        Input::File { path, .. } => import_file(ctx, &path)?,
    }
    let added = new_since(ctx, &before)?;
    if added.is_empty() {
        return Err("Nothing was imported".into());
    }
    match (name, added.as_slice()) {
        (Some(name), [one]) => Ok(vec![rename_to(ctx, &one.id, name)?]),
        _ => Ok(added),
    }
}

fn import_file(ctx: &Ctx, path: &Path) -> Result<(), String> {
    let path = path
        .canonicalize()
        .map_err(|_| "The file could not be read".to_string())?;
    let result = profile_import::import_configs_into(
        &ctx.vault(),
        &ctx.store(),
        &[path.to_string_lossy().into_owned()],
        None,
    )
    .map_err(io_message)?;
    match result.errors.first() {
        Some(error) => Err(error.error.clone()),
        None => Ok(()),
    }
}

pub fn add(ctx: &Ctx, input: &str, name: Option<&str>) -> Result<Output, String> {
    let added = add_input(ctx, input, name)?;
    let rows: Vec<_> = added.iter().map(row_of).collect();
    let text = added
        .iter()
        .map(|profile| format!("Saved \"{}\" ({})", profile.name, profile.id))
        .collect::<Vec<_>>()
        .join("\n");
    Ok((
        serde_json::to_value(rows).map_err(|_| "Could not encode the result")?,
        text,
    ))
}

pub fn rename(ctx: &Ctx, target: &str, name: &str) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = ctx.find(target)?;
    let profile = rename_to(ctx, &profile.id, name)?;
    Ok((
        json!({"id": profile.id, "name": profile.name}),
        format!("Renamed to \"{}\"", profile.name),
    ))
}

/// A running tunnel, or a profile enrolled in always-on, must be stopped
/// first, exactly as in the app.
fn ensure_removable(ctx: &Ctx, profile: &Profile) -> Result<(), String> {
    if LinuxEngine::handles(profile) && ctx.engine.status(profile)?.state != TunnelState::Stopped {
        return Err(format!(
            "\"{}\" is connected; run `netorch down` first",
            profile.name
        ));
    }
    if matches!(
        profile.backend,
        TunnelBackend::WireGuard | TunnelBackend::None
    ) {
        let list: AlwaysOnListResult = ctx
            .engine
            .privileged()
            .call(method::ALWAYS_ON_LIST, serde_json::Value::Null)
            .map_err(net_manager_engine::linux_engine::daemon_error)?;
        if list
            .profiles
            .iter()
            .any(|item| item.profile_id == profile.id)
        {
            return Err("Disable always-on for this profile in the app first".into());
        }
    }
    Ok(())
}

pub fn rm(ctx: &Ctx, target: &str) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = ctx.find(target)?;
    ensure_removable(ctx, &profile)?;
    ctx.store()
        .delete(&profile.id)
        .map_err(|_| "The profile could not be deleted".to_string())?;
    ctx.vault().remove_profile(&profile.id).map_err(|_| {
        "Profile deleted, but its stored config could not be cleaned up".to_string()
    })?;
    Ok((
        json!({"removed": profile.id}),
        format!("Removed \"{}\"", profile.name),
    ))
}
