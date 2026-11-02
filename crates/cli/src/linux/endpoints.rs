//! The servers inside a subscription: list them, pick one, switch the running
//! connection to another, refresh the list and measure delays. The app keeps
//! the same data (`subscription.json` in the vault); share links never reach
//! the terminal, only the names the provider gave them.
use super::auth;
use super::commands::{self, Output};
use super::ctx::Ctx;
use super::library;
use net_manager_core::backend_settings::BackendSettingsStore;
use net_manager_core::config_vault::SubscriptionEndpoint;
use net_manager_core::models::{
    NodePoolFilter, NodePoolSettings, Profile, SubscriptionEndpointInfo, TunnelBackend, TunnelState,
};
use net_manager_core::{node_pool, subscription, vpn, xray};
use net_manager_engine::linux_engine::LinuxEngine;
use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal, Write};

/// How many delay probes run at once; each starts its own Xray.
const PROBE_PARALLELISM: usize = 8;
/// Servers shown in a text ranking unless `--all`.
pub const DEFAULT_TOP: usize = 10;
/// Lines of the interactive list before it asks to narrow down.
const PICKER_LINES: usize = 20;

/// One server as listed: 1-based number, display name, protocol, active flag,
/// stable node key, backup-chain position and missing marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub number: usize,
    pub name: String,
    pub protocol: String,
    pub active: bool,
    /// Stable 16-hex identity of the node; never the share-link URL.
    pub key: String,
    /// 1-based position in the ordered backup chain.
    pub backup: Option<usize>,
    /// 1-based position in the opt-in filtered pool (after manual backups).
    pub pool: Option<usize>,
    /// Kept for a backup or a pin but gone from the subscription list.
    pub missing: bool,
}

/// Provider names carry stray spaces around flags; collapse them for display.
fn clean(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn rows(infos: &[SubscriptionEndpointInfo]) -> Vec<Row> {
    let mut backups = 0usize;
    infos
        .iter()
        .enumerate()
        .map(|(index, info)| {
            let backup = info.is_backup.then(|| {
                backups += 1;
                backups
            });
            Row {
                number: index + 1,
                name: clean(&info.name),
                protocol: info.protocol.clone().unwrap_or_default(),
                active: info.active,
                key: info.key.clone(),
                backup,
                missing: info.is_missing,
                pool: None,
            }
        })
        .collect()
}

/// The role column of the server list: primary, ordered backup or missing.
fn role(row: &Row) -> String {
    if row.active {
        "primary".into()
    } else if let Some(order) = row.backup {
        format!("backup {order}")
    } else if let Some(order) = row.pool.filter(|_| !row.missing) {
        format!("pool {order}")
    } else if row.missing {
        "missing".into()
    } else {
        String::new()
    }
}

/// Every endpoint as the clients see it: real servers first in subscription
/// order, then the remembered keys that left the list ("missing").
pub fn list_rows(ctx: &Ctx, profile: &Profile) -> Result<Vec<Row>, String> {
    let mut rows = rows(
        &subscription::list_endpoints(&ctx.vault(), &ctx.store(), &profile.id)
            .map_err(|_| "The subscription's server list could not be read".to_string())?,
    );
    if let Some(meta) = &profile.subscription {
        for row in &mut rows {
            row.backup = meta
                .backup_keys
                .iter()
                .position(|node| node.key == row.key)
                .map(|index| index + 1);
        }
        for row in &mut rows {
            row.pool = meta
                .pool_keys
                .iter()
                .filter(|_| meta.node_pool.is_some())
                .position(|node| node.key == row.key)
                .map(|index| index + 1);
        }
    }
    Ok(rows)
}

fn subscription_profile(ctx: &Ctx, target: &str) -> Result<Profile, String> {
    let profile = ctx.find(target)?;
    if profile.subscription.is_none() {
        return Err(format!("\"{}\" is not a subscription", profile.name));
    }
    Ok(profile)
}

fn read_endpoints(ctx: &Ctx, profile: &Profile) -> Result<Vec<SubscriptionEndpoint>, String> {
    ctx.vault()
        .read_subscription_endpoints(&profile.id)
        .map_err(|_| "The subscription's server list could not be read".to_string())
}

/// The active server's name, for profiles that are subscriptions.
pub fn active_name(ctx: &Ctx, profile: &Profile) -> Option<String> {
    profile.subscription.as_ref()?;
    let infos = subscription::list_endpoints(&ctx.vault(), &ctx.store(), &profile.id).ok()?;
    infos
        .iter()
        .find(|info| info.active)
        .map(|info| clean(&info.name))
}

/// The display name of one node key, missing nodes included (their last
/// known names stay in the backup refs).
pub fn node_name(ctx: &Ctx, profile: &Profile, key: &str) -> Option<String> {
    let infos = subscription::list_endpoints(&ctx.vault(), &ctx.store(), &profile.id).ok()?;
    infos
        .iter()
        .find(|info| info.key == key)
        .map(|info| clean(&info.name))
}

/// A server by 1-based number, exact name or unique part of a name (any case).
pub fn pick(rows: &[Row], query: &str) -> Result<usize, String> {
    let query = query.trim();
    if let Ok(number) = query.parse::<usize>() {
        return match rows.iter().find(|row| row.number == number) {
            Some(row) => Ok(row.number - 1),
            None => Err(format!("There is no server number {number}")),
        };
    }
    let lower = query.to_lowercase();
    if lower.is_empty() {
        return Err("Name a server or give its number".into());
    }
    let exact: Vec<&Row> = rows
        .iter()
        .filter(|row| row.name.to_lowercase() == lower)
        .collect();
    if let [one] = exact.as_slice() {
        return Ok(one.number - 1);
    }
    let found: Vec<&Row> = rows
        .iter()
        .filter(|row| row.name.to_lowercase().contains(&lower))
        .collect();
    match found.as_slice() {
        [] => Err(format!("No server matches \"{query}\"")),
        [one] => Ok(one.number - 1),
        many => Err(format!(
            "\"{query}\" matches {} servers; give a number or more of the name:\n{}",
            many.len(),
            many.iter()
                .take(10)
                .map(|row| format!("  {:>3}  {}", row.number, row.name))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

/// Asks on the terminal: a number picks, text narrows the list, a single match
/// is taken at once, Enter keeps the current server, `q` cancels.
pub fn choose(
    rows: &[Row],
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<usize, String> {
    let active = rows.iter().position(|row| row.active).unwrap_or(0);
    let mut filter = String::new();
    loop {
        let shown: Vec<&Row> = rows
            .iter()
            .filter(|row| row.name.to_lowercase().contains(&filter.to_lowercase()))
            .collect();
        if shown.is_empty() {
            let _ = writeln!(out, "No server matches \"{filter}\".");
            filter.clear();
            continue;
        }
        for row in shown.iter().take(PICKER_LINES) {
            let _ = writeln!(
                out,
                "{} {:>3}  {}{}",
                if row.active { "*" } else { " " },
                row.number,
                row.name,
                if row.protocol.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", row.protocol)
                }
            );
        }
        if shown.len() > PICKER_LINES {
            let _ = writeln!(
                out,
                "  … {} more: type part of a name to narrow the list",
                shown.len() - PICKER_LINES
            );
        }
        let _ = write!(
            out,
            "Number or text to filter (Enter keeps {}, q cancels): ",
            rows[active].number
        );
        let _ = out.flush();
        let mut line = String::new();
        let read = input
            .read_line(&mut line)
            .map_err(|_| "Could not read from the terminal".to_string())?;
        let answer = line.trim();
        if read == 0 || answer.eq_ignore_ascii_case("q") {
            return Err("Cancelled".into());
        }
        if answer.is_empty() {
            return Ok(active);
        }
        if let Ok(number) = answer.parse::<usize>() {
            if rows.iter().any(|row| row.number == number) {
                return Ok(number - 1);
            }
            let _ = writeln!(out, "There is no server number {number}.");
            continue;
        }
        filter = answer.to_string();
        let narrowed: Vec<&Row> = rows
            .iter()
            .filter(|row| row.name.to_lowercase().contains(&filter.to_lowercase()))
            .collect();
        if let [one] = narrowed.as_slice() {
            return Ok(one.number - 1);
        }
    }
}

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The server the user means: the argument, or a question on a terminal.
fn select(rows: &[Row], query: Option<&str>) -> Result<usize, String> {
    match query {
        Some(query) => pick(rows, query),
        None if interactive() => choose(rows, &mut std::io::stdin().lock(), &mut std::io::stderr()),
        None => Err("Name a server or give its number (`netorch endpoints` lists them)".into()),
    }
}

pub fn list(ctx: &Ctx, target: &str) -> Result<Output, String> {
    let profile = subscription_profile(ctx, target)?;
    let rows = list_rows(ctx, &profile)?;
    let value = Value::Array(
        rows.iter()
            .map(|row| {
                json!({"number": row.number, "name": row.name, "key": row.key,
                    "protocol": row.protocol, "active": row.active,
                    "backup": row.backup, "missing": row.missing,
                    "inPool": row.pool.is_some(), "pool": row.pool})
            })
            .collect(),
    );
    let text = crate::render::table(
        &["", "NO", "SERVER", "PROTOCOL", "ROLE"],
        &rows
            .iter()
            .map(|row| {
                vec![
                    if row.active { "*" } else { "" }.into(),
                    row.number.to_string(),
                    row.name.clone(),
                    row.protocol.clone(),
                    role(row),
                ]
            })
            .collect::<Vec<_>>(),
    );
    Ok((value, text))
}

fn is_running(ctx: &Ctx, profile: &Profile) -> Result<bool, String> {
    Ok(LinuxEngine::handles(profile) && ctx.engine.status(profile)?.state != TunnelState::Stopped)
}

/// Makes `key` the profile's primary server; the connection must be down.
fn apply(ctx: &Ctx, profile: &Profile, key: &str) -> Result<Profile, String> {
    subscription::switch_endpoint_key(&ctx.vault(), &ctx.store(), &profile.id, key, |port| {
        profile.xray_mode == net_manager_core::models::XrayMode::Tun
            || std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
    })
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => error.to_string(),
        _ => "The server could not be switched. Check file permissions.".into(),
    })?;
    ctx.find(&profile.id)
}

fn chosen(ctx: &Ctx, profile: &Profile, query: Option<&str>) -> Result<(usize, Vec<Row>), String> {
    // Only servers still in the subscription can become the primary; the
    // remembered-but-gone ones are listed for backup management only.
    let rows: Vec<Row> = list_rows(ctx, profile)?
        .into_iter()
        .filter(|row| !row.missing)
        .collect();
    let index = select(&rows, query)?;
    Ok((index, rows))
}

pub fn use_endpoint(ctx: &Ctx, target: &str, query: Option<&str>) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let (index, rows) = chosen(ctx, &profile, query)?;
    if is_running(ctx, &profile)? {
        return Err(format!(
            "\"{}\" is connected; use `netorch switch` to change the server and reconnect",
            profile.name
        ));
    }
    let row = &rows[index];
    if !row.active {
        apply(ctx, &profile, &row.key)?;
    }
    Ok((
        json!({"id": profile.id, "server": row.name, "number": index + 1,
            "key": row.key}),
        format!("\"{}\" now uses {}", profile.name, row.name),
    ))
}

/// Changes the primary server and, when the connection was up, reconnects;
/// if the new server does not come up the previous one is restored.
pub fn switch(ctx: &Ctx, target: &str, query: Option<&str>) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let (index, rows) = chosen(ctx, &profile, query)?;
    let previous_key = rows
        .iter()
        .find(|row| row.active)
        .map(|row| row.key.clone());
    let was_running = is_running(ctx, &profile)?;
    if was_running {
        auth::run(ctx.root_user, || ctx.engine.disconnect(&profile))?;
    }
    let outcome = apply(ctx, &profile, &rows[index].key).and_then(|updated| {
        if was_running {
            commands::connect(ctx, &updated, None).map(|_| ())
        } else {
            Ok(())
        }
    });
    if let Err(error) = outcome {
        // Put the old server back, and the connection with it.
        if let Some(key) = previous_key {
            if let Ok(restored) = apply(ctx, &profile, &key) {
                if was_running {
                    let _ = commands::connect(ctx, &restored, None);
                }
            }
        }
        return Err(format!("{error}. The previous server was restored"));
    }
    let name = rows[index].name.clone();
    Ok((
        json!({"id": profile.id, "server": name, "number": index + 1,
            "key": rows[index].key, "connected": was_running}),
        if was_running {
            format!("Switched \"{}\" to {name} and reconnected", profile.name)
        } else {
            format!("\"{}\" now uses {name}", profile.name)
        },
    ))
}

/// One node argument for `backup` commands: a number, part of a name, or a
/// raw 16-hex key — the only way to name a node that left the subscription.
pub fn backup_key(rows: &[Row], query: &str) -> Result<String, String> {
    let query = query.trim();
    if query.len() == 16 && query.chars().all(|c| c.is_ascii_hexdigit()) {
        return match rows.iter().find(|row| row.key == query) {
            Some(row) => Ok(row.key.clone()),
            None => Ok(query.to_string()),
        };
    }
    let index = pick(rows, query)?;
    Ok(rows[index].key.clone())
}

/// `true` when the profile runs right now: changes to the failover plan are
/// stored but reach the tunnel only on the next connect.
fn apply_note(running: bool) -> &'static str {
    if running {
        "\nSaved; reconnect to apply (`netorch down` then `netorch up`)."
    } else {
        ""
    }
}

fn backup_state(ctx: &Ctx, profile: &Profile) -> Result<(Vec<Row>, bool), String> {
    let rows = list_rows(ctx, profile)?;
    let auto_return = profile
        .subscription
        .as_ref()
        .and_then(|meta| meta.auto_return_primary)
        .unwrap_or(true);
    Ok((rows, auto_return))
}

pub fn backup_show(ctx: &Ctx, target: &str) -> Result<Output, String> {
    let profile = subscription_profile(ctx, target)?;
    let (rows, auto_return) = backup_state(ctx, &profile)?;
    let mut chain: Vec<&Row> = rows
        .iter()
        .filter(|row| row.active || row.backup.is_some())
        .collect();
    chain.sort_by_key(|row| {
        if row.active {
            0
        } else {
            row.backup.unwrap_or(usize::MAX)
        }
    });
    let value = json!({
        "id": profile.id,
        "autoReturn": auto_return,
        "primary": rows.iter().find(|row| row.active).map(|row| json!({
            "number": row.number, "name": row.name, "key": row.key})),
        "backups": chain.iter().filter(|row| !row.active).map(|row| json!({
            "number": row.number, "name": row.name, "key": row.key,
            "order": row.backup, "missing": row.missing})).collect::<Vec<_>>(),
        "pool": pool_json(&profile),
        "pinned": pinned_routes_of(ctx, &profile),
    });
    let mut text = format!("\"{}\" failover plan\n", profile.name);
    match chain.first() {
        Some(primary) => text.push_str(&format!(
            "  primary:    {} {}\n",
            primary.number, primary.name
        )),
        None => text.push_str("  primary:    (none saved)\n"),
    }
    for row in chain.iter().skip(1) {
        text.push_str(&format!(
            "  backup {}:  {} {}{}\n",
            row.backup.unwrap_or_default(),
            row.number,
            row.name,
            if row.missing {
                " (gone from the subscription)"
            } else {
                ""
            }
        ));
    }
    if chain.len() == 1 {
        text.push_str("  no backups — `netorch backup add` picks them\n");
    }
    let pool_rows: Vec<&Row> = rows.iter().filter(|row| row.pool.is_some()).collect();
    if pool_rows.is_empty() {
        if profile
            .subscription
            .as_ref()
            .is_some_and(|m| m.node_pool.is_some())
        {
            text.push_str("  pool:      on, no members yet (`netorch backup pool rebuild`)\n");
        }
    } else {
        for row in pool_rows {
            text.push_str(&format!(
                "  pool {}:    {} {}{}\n",
                row.pool.unwrap_or_default(),
                row.number,
                row.name,
                if row.missing {
                    " (gone from the subscription)"
                } else {
                    ""
                }
            ));
        }
    }
    text.push_str(&format!(
        "  auto-return to primary: {}",
        if auto_return { "on" } else { "off" }
    ));
    Ok((value, text))
}

/// The domain selectors pinned to each node, shown in `backup show`.
fn pinned_routes_of(ctx: &Ctx, profile: &Profile) -> Value {
    let mut names = std::collections::HashMap::new();
    for row in list_rows(ctx, profile).unwrap_or_default() {
        names.insert(row.key.clone(), (row.name.clone(), row.missing));
    }
    Value::Array(
        profile
            .pinned_policies
            .iter()
            .map(|route| {
                let (name, missing) = names
                    .get(&route.endpoint_key)
                    .cloned()
                    .unwrap_or_else(|| (route.endpoint_key.clone(), true));
                json!({"endpointKey": route.endpoint_key, "server": name,
                    "missing": missing, "selectors": route.selectors})
            })
            .collect(),
    )
}

/// Replaces or extends the ordered backup chain. `keys` that resolve to the
/// primary are rejected — the primary is never its own backup.
fn save_backups(ctx: &Ctx, profile: &Profile, keys: &[String]) -> Result<Vec<Row>, String> {
    subscription::set_backup_endpoints(&ctx.vault(), &ctx.store(), &profile.id, keys).map_err(
        |error| match error.kind() {
            std::io::ErrorKind::InvalidInput => error.to_string(),
            _ => "The backups could not be saved. Check file permissions.".into(),
        },
    )?;
    let updated = ctx.find(&profile.id)?;
    let mut rows = list_rows(ctx, &updated)?;
    rows.sort_by_key(|row| row.backup.unwrap_or(usize::MAX));
    Ok(rows)
}

fn backup_set(ctx: &Ctx, target: &str, servers: &[String]) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let rows = list_rows(ctx, &profile)?;
    let mut keys = Vec::new();
    for server in servers {
        let key = backup_key(&rows, server)?;
        if rows.iter().any(|row| row.key == key && row.active) {
            return Err("The primary cannot be its own backup".into());
        }
        if keys.contains(&key) {
            return Err(format!("\"{server}\" is listed twice"));
        }
        keys.push(key);
    }
    let running = is_running(ctx, &profile).unwrap_or(true);
    let rows = save_backups(ctx, &profile, &keys)?;
    let names: Vec<String> = rows
        .iter()
        .filter(|row| row.backup.is_some())
        .map(|row| row.name.clone())
        .collect();
    Ok((
        json!({"id": profile.id, "backups": names, "requiresReconnect": running}),
        format!(
            "\"{}\" tries {} after the primary{}",
            profile.name,
            names.join(", then "),
            apply_note(running)
        ),
    ))
}

fn backup_add(ctx: &Ctx, target: &str, server: &str) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let rows = list_rows(ctx, &profile)?;
    let key = backup_key(&rows, server)?;
    let row = rows
        .iter()
        .find(|row| row.key == key)
        .ok_or_else(|| "The endpoint is not part of this subscription".to_string())?;
    if row.active {
        return Err("The primary cannot be its own backup".into());
    }
    if let Some(order) = row.backup {
        return Err(format!("{} is already backup {}", row.name, order));
    }
    let mut keys: Vec<String> = profile
        .subscription
        .as_ref()
        .expect("subscription checked")
        .backup_keys
        .iter()
        .map(|node| node.key.clone())
        .collect();
    keys.push(key);
    let running = is_running(ctx, &profile).unwrap_or(true);
    save_backups(ctx, &profile, &keys)?;
    Ok((
        json!({"id": profile.id, "added": row.name, "requiresReconnect": running}),
        format!(
            "{} is backup {} of \"{}\"{}",
            row.name,
            keys.len(),
            profile.name,
            apply_note(running)
        ),
    ))
}

fn backup_rm(ctx: &Ctx, target: &str, server: &str) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let rows = list_rows(ctx, &profile)?;
    let key = backup_key(&rows, server)?;
    let name = rows
        .iter()
        .find(|row| row.key == key)
        .map(|row| row.name.clone())
        .unwrap_or_else(|| key.clone());
    let keys: Vec<String> = profile
        .subscription
        .as_ref()
        .expect("subscription checked")
        .backup_keys
        .iter()
        .filter(|node| node.key != key)
        .map(|node| node.key.clone())
        .collect();
    if keys.len() == rows.iter().filter(|row| row.backup.is_some()).count() {
        return Err(format!("{name} is not in the backup chain"));
    }
    let running = is_running(ctx, &profile).unwrap_or(true);
    save_backups(ctx, &profile, &keys)?;
    Ok((
        json!({"id": profile.id, "removed": name, "requiresReconnect": running}),
        format!(
            "{name} left the backup chain of \"{}\"{}",
            profile.name,
            apply_note(running)
        ),
    ))
}

fn backup_clear(ctx: &Ctx, target: &str) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let running = is_running(ctx, &profile).unwrap_or(true);
    save_backups(ctx, &profile, &[])?;
    Ok((
        json!({"id": profile.id, "backups": Vec::<String>::new(), "requiresReconnect": running}),
        format!(
            "\"{}\" has no backups now{}",
            profile.name,
            apply_note(running)
        ),
    ))
}

fn backup_auto(ctx: &Ctx, target: &str, on: bool) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let running = is_running(ctx, &profile).unwrap_or(true);
    subscription::set_auto_return_primary(&ctx.store(), &profile.id, on).map_err(|error| {
        match error.kind() {
            std::io::ErrorKind::InvalidInput => error.to_string(),
            _ => "The setting could not be saved. Check file permissions.".into(),
        }
    })?;
    Ok((
        json!({"id": profile.id, "autoReturn": on, "requiresReconnect": running}),
        format!(
            "Auto-return to primary is {} for \"{}\"{}",
            if on { "on" } else { "off" },
            profile.name,
            apply_note(running)
        ),
    ))
}

pub fn backup(ctx: &Ctx, command: super::args::BackupCommand) -> Result<Output, String> {
    use super::args::{BackupCommand::*, BoolOnOff};
    match command {
        Show { profile } => backup_show(ctx, &profile),
        Set { profile, servers } => backup_set(ctx, &profile, &servers),
        Add { profile, server } => backup_add(ctx, &profile, &server),
        Rm { profile, server } => backup_rm(ctx, &profile, &server),
        Clear { profile } => backup_clear(ctx, &profile),
        Auto { profile, enabled } => backup_auto(ctx, &profile, matches!(enabled, BoolOnOff::On)),
        Pool(command) => pool(ctx, command),
        Verify { profile } => verify(ctx, &profile),
    }
}

/// `CC:word|word…` or a bare word: one pool filter. A `CC:` prefix means
/// "this exit country only" — a country-less filter pairs with
/// `--no-verify` (checked here, not by the store).
fn pool_filter(spec: &str, verify: bool) -> Result<NodePoolFilter, String> {
    let spec = spec.trim();
    let (exit_country, words) = match spec.split_once(':') {
        Some((country, words)) if verify => {
            let country = node_pool::normalize_country_code(country).ok_or_else(|| {
                "Use a two-letter exit-country code, for example DE:German".to_string()
            })?;
            (Some(country), words.trim())
        }
        Some(_) => {
            return Err("--no-verify accepts name filters only; remove the country prefix".into());
        }
        None if verify => {
            return Err(
                "Verified filters require CC:words or CC:; use --no-verify for name-only filters"
                    .into(),
            );
        }
        None => (None, spec),
    };

    let name_contains = if words.is_empty() {
        Vec::new()
    } else {
        let terms = words.split('|').map(str::trim).collect::<Vec<_>>();
        if terms
            .iter()
            .any(|term| term.is_empty() || term.chars().count() > node_pool::MAX_POOL_NAME_TERM_LEN)
        {
            return Err("Each pool name term must contain 1-64 characters".into());
        }
        terms.into_iter().map(str::to_string).collect()
    };

    if name_contains.len() > node_pool::MAX_POOL_NAME_TERMS {
        return Err("A pool filter accepts at most four name terms".into());
    }
    if !verify && name_contains.is_empty() {
        return Err("An unverified pool filter requires at least one name term".into());
    }

    Ok(NodePoolFilter {
        name_contains,
        exit_country,
    })
}

fn save_pool(
    ctx: &Ctx,
    profile: &Profile,
    settings: Option<NodePoolSettings>,
) -> Result<(), String> {
    node_pool::set_node_pool(&ctx.store(), &profile.id, settings).map_err(|error| {
        match error.kind() {
            std::io::ErrorKind::InvalidInput => error.to_string(),
            _ => "The pool settings could not be saved. Check file permissions.".into(),
        }
    })?;
    Ok(())
}

fn pool_set(ctx: &Ctx, target: &str, specs: &[String], no_verify: bool) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let verify = !no_verify;
    if specs.is_empty() || specs.len() > node_pool::MAX_POOL_FILTERS {
        return Err("A node pool requires 1-8 filters".into());
    }
    let mut filters = Vec::new();
    for spec in specs {
        filters.push(pool_filter(spec, verify)?);
    }
    let settings = NodePoolSettings {
        filters,
        verify_exit_country: verify,
    };
    let running = is_running(ctx, &profile).unwrap_or(true);
    save_pool(ctx, &profile, Some(settings.clone()))?;
    let filter_text = settings
        .filters
        .iter()
        .map(|filter| {
            format!(
                "{}{}",
                filter
                    .exit_country
                    .as_deref()
                    .map(|cc| format!("{cc}:"))
                    .unwrap_or_default(),
                filter.name_contains.join("|")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    Ok((
        json!({"id": profile.id, "pool": settings, "requiresReconnect": running}),
        format!(
            "\"{}\" pools matching servers after its backups ({}; {}){}\n\
             `netorch backup pool rebuild` fills it now, a refresh does it too.",
            profile.name,
            filter_text,
            if verify {
                "exit-country proof required during rebuild"
            } else {
                "name match only"
            },
            apply_note(running)
        ),
    ))
}

fn pool_clear(ctx: &Ctx, target: &str) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let meta = profile.subscription.as_ref().expect("checked");
    if meta.node_pool.is_none() && meta.pool_keys.is_empty() {
        return Err(format!("\"{}\" has no pool", profile.name));
    }
    let running = is_running(ctx, &profile).unwrap_or(true);
    save_pool(ctx, &profile, None)?;
    Ok((
        json!({"id": profile.id, "pool": Value::Null, "requiresReconnect": running}),
        format!(
            "\"{}\" has no pool now{}",
            profile.name,
            apply_note(running)
        ),
    ))
}

/// Filters + kept members for `pool show` and `backup show`.
fn pool_json(profile: &Profile) -> Value {
    let meta = profile.subscription.as_ref().expect("subscription checked");
    json!({
        "settings": meta.node_pool,
        "members": meta.pool_keys.iter().map(|node| json!({
            "key": node.key, "name": node.name,
        })).collect::<Vec<_>>(),
    })
}

fn pool_show(ctx: &Ctx, target: &str) -> Result<Output, String> {
    let profile = subscription_profile(ctx, target)?;
    let meta = profile.subscription.as_ref().expect("checked");
    let mut text = format!("\"{}\" pool\n", profile.name);
    match &meta.node_pool {
        None => text.push_str("  off — `netorch backup pool set` picks filters\n"),
        Some(settings) => {
            for filter in &settings.filters {
                text.push_str(&format!(
                    "  filter:   {}{}\n",
                    filter
                        .exit_country
                        .as_deref()
                        .map(|cc| format!("{cc}:"))
                        .unwrap_or_default(),
                    filter.name_contains.join("|")
                ));
            }
            text.push_str(&format!(
                "  country proof: {}\n",
                if settings.verify_exit_country {
                    "on"
                } else {
                    "off"
                }
            ));
        }
    }
    if meta.pool_keys.is_empty() {
        text.push_str("  members:  none kept (rebuild fills it)");
    } else {
        for (index, node) in meta.pool_keys.iter().enumerate() {
            text.push_str(&format!("  pool {}:   {}\n", index + 1, node.name));
        }
    }
    Ok((pool_json(&profile), text.trim_end_matches('\n').to_string()))
}

fn verdict_word(verdict: &node_pool::NodePoolVerdict) -> &'static str {
    use node_pool::NodePoolVerdict::*;
    match verdict {
        Member => "member",
        Skipped => "skipped",
        Explicit => "explicit",
        Unreachable => "unreachable",
        WrongCountry => "wrong country",
    }
}

fn report_json(report: &node_pool::NodePoolReport) -> Result<Value, String> {
    serde_json::to_value(report).map_err(|_| "The pool report could not be encoded".to_string())
}

fn report_text(report: &node_pool::NodePoolReport) -> String {
    let mut text = String::new();
    for entry in &report.entries {
        text.push_str(&format!(
            "  {:<12} {}{}\n",
            verdict_word(&entry.verdict),
            entry.name,
            entry
                .exit_country
                .as_deref()
                .map(|cc| format!("  → {cc}"))
                .unwrap_or_default()
        ));
    }
    if report.entries.is_empty() {
        text.push_str("  no candidates matched the filters\n");
    }
    text.push_str(if report.pool_changed {
        "pool rebuilt"
    } else if report.kept_previous {
        "no usable members found — the previous pool stays"
    } else {
        "pool unchanged"
    });
    text
}

/// `pool rebuild`: probe candidates through a temporary Xray and keep the
/// members the filters plus real exit countries allow.
fn pool_rebuild(ctx: &Ctx, target: &str) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    if profile
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.node_pool.as_ref())
        .is_none()
    {
        return Err("Set backup-pool filters before rebuilding the pool".into());
    }

    let verify = profile
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.node_pool.as_ref())
        .is_some_and(|pool| pool.verify_exit_country);
    let executable = verify.then(|| xray_executable(ctx)).transpose()?;
    if verify {
        eprintln!(
            "Exit-country probes contact api.country.is and ipinfo.io through each candidate."
        );
    }
    let running = is_running(ctx, &profile).unwrap_or(true);
    let vault = ctx.vault();
    let store = ctx.store();

    let report = block_on(node_pool::rebuild_node_pool(
        &vault,
        &store,
        &profile.id,
        &node_pool::EXIT_COUNTRY_PROBES,
        node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
        move |_| {
            executable
                .as_ref()
                .ok_or_else(|| std::io::Error::other("Xray executable unavailable"))
                .map(tokio::process::Command::new)
        },
    ))?
    .map_err(|_| {
        "The backup pool could not be rebuilt; the previously stored pool was not replaced"
            .to_string()
    })?;

    let mut value = report_json(&report)?;
    value["requiresReconnect"] = json!(running);
    Ok((
        value,
        format!("{}{}", report_text(&report), apply_note(running)),
    ))
}

/// The country the node's flag emoji names, if any: regional indicators
/// pair up to an ISO code (🇷🇺 → RU). A name is not proof — `verify`
/// compares it with the real exit and flags a mismatch.
pub(crate) fn flag_country(name: &str) -> Option<String> {
    let mut code = String::new();
    for ch in name.chars() {
        let value = ch as u32;
        if (0x1F1E6..=0x1F1FF).contains(&value) {
            code.push(char::from_u32(value - 0x1F1E6 + 'A' as u32)?);
        }
    }
    (code.len() == 2).then_some(code)
}

/// `backup verify`: every failover candidate — primary, manual backups and
/// pool members — is probed through its own temporary Xray and reports the
/// country it really exits in. Nodes missing from the subscription are
/// reported as such, never probed.
pub fn verify(ctx: &Ctx, target: &str) -> Result<Output, String> {
    if ctx.root_user {
        return Err("Run exit verification as your own user, without sudo".into());
    }

    let profile = subscription_profile(ctx, target)?;
    let rows = list_rows(ctx, &profile)?;
    let vault = ctx.vault();
    let (nodes, _) = subscription::failover_plan(&vault, &profile)
        .map_err(|_| "The failover endpoints could not be resolved".to_string())?;
    if nodes.is_empty() {
        return Err("The profile has no failover candidates".into());
    }

    let expected_nodes = nodes.clone();
    let executable = xray_executable(ctx)?;
    eprintln!(
        "Verifying {} servers through temporary Xray proxies. \
         api.country.is and ipinfo.io will see each candidate's exit IP.",
        nodes.len()
    );

    let results = block_on(async move {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(
            node_pool::POOL_PROBE_PARALLELISM,
        ));
        let mut tasks = tokio::task::JoinSet::new();

        for (index, endpoint) in nodes.into_iter().enumerate() {
            let gate = gate.clone();
            let executable = executable.clone();
            tasks.spawn(async move {
                let _permit = gate
                    .acquire_owned()
                    .await
                    .map_err(|_| "Exit verification was cancelled".to_string())?;
                let key = subscription::endpoint_key(&endpoint.url);
                let mut command = tokio::process::Command::new(&executable);
                command.args(["run", "-config", "stdin:"]);

                let result = node_pool::measure_exit_country(
                    &endpoint.url,
                    command,
                    &node_pool::EXIT_COUNTRY_PROBES,
                    node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
                )
                .await;

                Ok::<_, String>((index, key, endpoint.name, result))
            });
        }

        let mut results = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(error)) => {
                    tasks.abort_all();
                    return Err(error);
                }
                Err(_) => {
                    tasks.abort_all();
                    return Err("An exit-verification worker failed".to_string());
                }
            }
        }
        results.sort_by_key(|(index, _, _, _)| *index);
        Ok::<_, String>(results)
    })??;

    if ctx.find(&profile.id)? != profile {
        return Err("The profile changed during verification; verify again".into());
    }
    let (current_nodes, _) = subscription::failover_plan(&vault, &profile)
        .map_err(|_| "The current failover endpoints could not be read".to_string())?;
    if current_nodes != expected_nodes {
        return Err("The subscription endpoints changed during verification; verify again".into());
    }

    let roles = rows
        .iter()
        .map(|row| (row.key.as_str(), role(row)))
        .collect::<std::collections::HashMap<_, _>>();

    let mut entries = Vec::with_capacity(results.len());
    let mut lines = Vec::with_capacity(results.len());
    for (_, key, name, outcome) in results {
        let name = clean(&name);
        let named_country = flag_country(&name);
        let role = roles
            .get(key.as_str())
            .map(String::as_str)
            .unwrap_or("node");
        let (exit_country, exit_ip, error) = match outcome {
            Ok(exit) => (Some(exit.country), Some(exit.ip), None),
            Err(_) => (
                None,
                None,
                Some("Exit-country verification failed".to_string()),
            ),
        };
        let mismatch =
            named_country.is_some() && exit_country.is_some() && named_country != exit_country;

        lines.push(format!(
            "  {role:<9} {name}  named={} exit={}{}",
            named_country.as_deref().unwrap_or("?"),
            exit_country.as_deref().unwrap_or("unreachable"),
            if mismatch { "  MISMATCH" } else { "" },
        ));
        entries.push(json!({
            "key": key,
            "name": name,
            "role": role,
            "namedCountry": named_country,
            "exitCountry": exit_country,
            "exitIp": exit_ip,
            "mismatch": mismatch,
            "error": error,
        }));
    }

    Ok((
        json!({"id": profile.id, "checks": entries}),
        lines.join("\n"),
    ))
}

fn pool(ctx: &Ctx, command: super::args::PoolCommand) -> Result<Output, String> {
    use super::args::PoolCommand::*;
    match command {
        Show { profile } => pool_show(ctx, &profile),
        Set {
            profile,
            filters,
            no_verify,
        } => pool_set(ctx, &profile, &filters, no_verify),
        Clear { profile } => pool_clear(ctx, &profile),
        Rebuild { profile } => pool_rebuild(ctx, &profile),
    }
}

pub fn refresh(ctx: &Ctx, target: &str) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    if is_running(ctx, &profile)? {
        return Err("Disconnect the profile before refreshing its subscription".into());
    }

    let subscription = profile
        .subscription
        .as_ref()
        .ok_or_else(|| "Not a subscription profile".to_string())?;
    let fetched = block_on(subscription::fetch(
        &subscription::http_client()
            .map_err(|_| "The subscription HTTP client could not be created".to_string())?,
        &subscription.url,
        &subscription.hwid,
    ))?
    .map_err(|_| "The subscription could not be fetched".to_string())?;

    if ctx.find(&profile.id)? != profile {
        return Err("The profile changed during subscription refresh; refresh again".into());
    }

    let vault = ctx.vault();
    let store = ctx.store();
    let outcome = subscription::refresh_body(
        &vault,
        &store,
        &profile.id,
        &fetched.body,
        fetched.meta,
        |port| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok(),
    )
    .map_err(|_| "The subscription could not be saved".to_string())?;

    let updated = ctx.find(&profile.id)?;
    let mut pool_report = None;
    if updated
        .subscription
        .as_ref()
        .is_some_and(|subscription| subscription.node_pool.is_some())
    {
        let rebuilt = (|| {
            let verify = updated
                .subscription
                .as_ref()
                .and_then(|subscription| subscription.node_pool.as_ref())
                .is_some_and(|pool| pool.verify_exit_country);
            let executable = verify.then(|| xray_executable(ctx)).transpose()?;
            if verify {
                eprintln!("Exit-country probes contact api.country.is and ipinfo.io through each candidate.");
            }
            block_on(node_pool::rebuild_node_pool(
                &vault,
                &store,
                &profile.id,
                &node_pool::EXIT_COUNTRY_PROBES,
                node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
                move |_| {
                    executable
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("Xray executable unavailable"))
                        .map(tokio::process::Command::new)
                },
            ))?
            .map_err(|_| "Backup-pool rebuild failed".to_string())
        })();

        match rebuilt {
            Ok(report) => pool_report = Some(report),
            Err(_) => {
                let recorded = store.update_profile(&profile.id, |current| {
                    if current.subscription != updated.subscription {
                        return Err(std::io::Error::other("Subscription changed after refresh"));
                    }
                    let subscription = current.subscription.as_mut().ok_or_else(|| {
                        std::io::Error::other("Profile is no longer a subscription")
                    })?;
                    subscription.last_refresh_error = Some(
                        "Subscription refreshed, but the backup pool could not be rebuilt"
                            .to_string(),
                    );
                    Ok(())
                });
                return Err(if recorded.is_ok() {
                    "Subscription refreshed, but backup-pool rebuild failed; \
                     the previously stored pool was not replaced"
                        .into()
                } else {
                    "Subscription refreshed, but backup-pool rebuild failed; \
                     its failure notice could not be saved"
                        .into()
                });
            }
        }
    }

    let pool_text = pool_report
        .as_ref()
        .map(|report| format!("\n{}", report_text(report)))
        .unwrap_or_default();
    let pool_value = pool_report.as_ref().map(report_json).transpose()?;

    Ok((
        json!({
            "id": profile.id,
            "servers": outcome.endpoint_count,
            "skipped": outcome.skipped_count,
            "fallbackUsed": outcome.fallback_used,
            "cleanupFailed": outcome.cleanup_failed,
            "poolReport": pool_value,
        }),
        format!(
            "Refreshed \"{}\": {} servers; {} unsupported skipped{}{}{}",
            profile.name,
            outcome.endpoint_count,
            outcome.skipped_count,
            if outcome.fallback_used {
                "\nThe previous primary disappeared; a replacement primary was selected."
            } else {
                ""
            },
            if outcome.cleanup_failed {
                "\nThe subscription was saved, but old managed-config cleanup failed."
            } else {
                ""
            },
            pool_text,
        ),
    ))
}

fn block_on<F: std::future::Future>(future: F) -> Result<F::Output, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Could not start the network runtime".to_string())
        .map(|runtime| runtime.block_on(future))
}

/// The Xray `test` runs probes with: the configured or managed one.
fn xray_executable(ctx: &Ctx) -> Result<std::path::PathBuf, String> {
    let setting = BackendSettingsStore::new(ctx.root.join("backend-settings.json"))
        .get(TunnelBackend::Xray)
        .map_err(|_| "The backend settings could not be read".to_string())?;
    vpn::resolve_xray_executable(setting.as_ref().map(|s| s.path.as_path()))
        .map_err(|_| "Xray was not found. Install it in the Network Orchestrator app.".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub number: usize,
    pub name: String,
    pub delay_ms: Option<u64>,
    /// Why there is no delay (never contains the share link).
    pub error: Option<String>,
}

/// Fastest first; servers that did not answer go last in list order.
pub fn rank(mut probes: Vec<Probe>) -> Vec<Probe> {
    probes.sort_by_key(|probe| (probe.delay_ms.is_none(), probe.delay_ms, probe.number));
    probes
}

/// Which servers `test` measures: those matching `query`, else all.
fn select_for_test(rows: &[Row], query: Option<&str>) -> Result<Vec<usize>, String> {
    let Some(query) = query else {
        return Ok((0..rows.len()).collect());
    };
    let lower = query.trim().to_lowercase();
    let found: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.name.to_lowercase().contains(&lower))
        .map(|(index, _)| index)
        .collect();
    if found.is_empty() {
        return Err(format!("No server matches \"{query}\""));
    }
    Ok(found)
}

/// The config a probe runs: for a profile the daemon runs, the reduced one a
/// connection would send, so the result says whether the server can work.
fn probe_config(url: &str, port: u16, as_tunnel: bool) -> Result<Value, String> {
    let config = xray::generate_share_link_config(url, port)
        .map_err(|_| "invalid subscription endpoint".to_string())?;
    if as_tunnel {
        xray::tun_compatible_config(&config).map_err(str::to_string)
    } else {
        Ok(config)
    }
}

pub fn test(
    ctx: &Ctx,
    target: &str,
    query: Option<&str>,
    all: bool,
    top: usize,
) -> Result<Output, String> {
    if ctx.root_user {
        return Err("Run server measurement as your own user, without sudo".into());
    }
    let profile = subscription_profile(ctx, target)?;
    let endpoints = read_endpoints(ctx, &profile)?;
    let rows: Vec<Row> = list_rows(ctx, &profile)?
        .into_iter()
        .filter(|row| !row.missing)
        .collect();
    let indexes = select_for_test(&rows, query)?;
    let executable = xray_executable(ctx)?;
    eprintln!("Measuring {} servers...", indexes.len());
    let as_tunnel = LinuxEngine::handles(&profile);
    let jobs: Vec<(usize, String)> = indexes
        .iter()
        .map(|&index| (index, endpoints[index].url.clone()))
        .collect();
    let results = block_on(async move {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(PROBE_PARALLELISM));
        let mut set = tokio::task::JoinSet::new();
        for (index, url) in jobs {
            let gate = gate.clone();
            let executable = executable.clone();
            set.spawn(async move {
                let _permit = gate.acquire_owned().await;
                let mut command = tokio::process::Command::new(&executable);
                command.args(["run", "-config", "stdin:"]);
                let delay = subscription::measure_delay_with_config(
                    |port| probe_config(&url, port, as_tunnel),
                    command,
                    subscription::DELAY_PROBE_URL,
                    subscription::DELAY_PROBE_TIMEOUT,
                )
                .await;
                (index, delay)
            });
        }
        let mut done = Vec::new();
        while let Some(result) = set.join_next().await {
            match result {
                Ok(result) => done.push(result),
                Err(_) => {
                    set.abort_all();
                    return Err("A delay-measurement worker failed".to_string());
                }
            }
        }
        Ok::<_, String>(done)
    })??;
    let probes = rank(
        results
            .into_iter()
            .map(|(index, result)| Probe {
                number: index + 1,
                name: rows[index].name.clone(),
                delay_ms: result.as_ref().ok().copied(),
                error: result.err(),
            })
            .collect(),
    );
    Ok(render_probes(&probes, all, top))
}

pub fn render_probes(probes: &[Probe], all: bool, top: usize) -> Output {
    let value = Value::Array(
        probes
            .iter()
            .map(|probe| {
                json!({"number": probe.number, "name": probe.name,
                "delayMs": probe.delay_ms, "error": probe.error})
            })
            .collect(),
    );
    let answered = probes.iter().filter(|p| p.delay_ms.is_some()).count();
    let shown: Vec<&Probe> = if all {
        probes.iter().collect()
    } else {
        probes.iter().take(top).collect()
    };
    let mut text = crate::render::table(
        &["NO", "SERVER", "DELAY"],
        &shown
            .iter()
            .map(|probe| {
                vec![
                    probe.number.to_string(),
                    probe.name.clone(),
                    probe
                        .delay_ms
                        .map(|ms| format!("{ms} ms"))
                        .unwrap_or_else(|| {
                            probe.error.clone().unwrap_or_else(|| "no answer".into())
                        }),
                ]
            })
            .collect::<Vec<_>>(),
    );
    text.push_str(&format!(
        "\n{answered} of {} answered. `netorch switch <profile> <NO>` picks one.",
        probes.len()
    ));
    (value, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample() -> Vec<Row> {
        [
            "  🇩🇪 ⚡ Германия",
            "🇳🇱 ⚡ Нидерланды",
            "🇩🇪 Hysteria 2 | Германия",
            "🇵🇱 Польша",
        ]
        .iter()
        .enumerate()
        .map(|(i, name)| Row {
            number: i + 1,
            name: clean(name),
            protocol: "VLESS".into(),
            active: i == 1,
            key: format!("{i:016x}"),
            backup: (i == 2).then_some(1),
            pool: (i == 3).then_some(1),
            missing: false,
        })
        .collect()
    }

    #[test]
    fn display_names_lose_their_stray_spaces() {
        assert_eq!(clean("  🇩🇪 ⚡  Германия "), "🇩🇪 ⚡ Германия");
    }

    #[test]
    fn a_number_or_a_unique_part_of_a_name_picks_a_server() {
        let rows = sample();
        assert_eq!(pick(&rows, "2"), Ok(1));
        assert_eq!(pick(&rows, "польш"), Ok(3));
        assert_eq!(pick(&rows, "НИДЕР"), Ok(1));
        assert!(pick(&rows, "9").is_err());
        assert!(pick(&rows, "").is_err());
    }

    #[test]
    fn an_ambiguous_name_lists_the_candidates_instead_of_guessing() {
        let error = pick(&sample(), "герман").unwrap_err();
        assert!(error.contains("matches 2 servers"), "{error}");
        assert!(error.contains("Hysteria"), "{error}");
    }

    #[test]
    fn an_exact_name_wins_over_longer_names_containing_it() {
        let rows = vec![
            Row {
                number: 1,
                name: "Poland".into(),
                protocol: String::new(),
                active: false,
                key: "000000000000000a".into(),
                backup: None,
                pool: None,
                missing: false,
            },
            Row {
                number: 2,
                name: "Poland 2".into(),
                protocol: String::new(),
                active: false,
                key: "000000000000000b".into(),
                backup: None,
                pool: None,
                missing: false,
            },
        ];
        assert_eq!(pick(&rows, "poland"), Ok(0));
    }

    #[test]
    fn the_picker_takes_a_number_a_single_match_or_keeps_the_current_server() {
        let rows = sample();
        let mut out = Vec::new();
        assert_eq!(choose(&rows, &mut Cursor::new("3\n"), &mut out), Ok(2));
        assert_eq!(choose(&rows, &mut Cursor::new("польша\n"), &mut out), Ok(3));
        assert_eq!(choose(&rows, &mut Cursor::new("\n"), &mut out), Ok(1));
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("*   2  🇳🇱 ⚡ Нидерланды"), "{shown}");
    }

    #[test]
    fn the_picker_narrows_by_text_then_picks_and_can_be_cancelled() {
        let rows = sample();
        let mut out = Vec::new();
        assert_eq!(
            choose(&rows, &mut Cursor::new("герман\n3\n"), &mut out),
            Ok(2)
        );
        assert!(choose(&rows, &mut Cursor::new("q\n"), &mut out).is_err());
        assert!(choose(&rows, &mut Cursor::new(""), &mut out).is_err());
        assert!(choose(&rows, &mut Cursor::new("99\nq\n"), &mut out).is_err());
    }

    #[test]
    fn the_ranking_puts_fast_servers_first_and_silent_ones_last() {
        let probe = |number, delay_ms| Probe {
            number,
            name: format!("s{number}"),
            delay_ms,
            error: None,
        };
        let ranked = rank(vec![
            probe(1, None),
            probe(2, Some(300)),
            probe(3, Some(80)),
            probe(4, None),
        ]);
        let order: Vec<usize> = ranked.iter().map(|p| p.number).collect();
        assert_eq!(order, [3, 2, 1, 4]);
        let (value, text) = render_probes(&ranked, false, 2);
        assert_eq!(value.as_array().unwrap().len(), 4);
        assert!(text.contains("80 ms") && !text.contains("no answer"));
        assert!(text.contains("2 of 4 answered"));
    }

    #[test]
    fn a_raw_hex_key_or_a_name_resolves_a_backup_node() {
        let rows = sample();
        assert_eq!(
            backup_key(&rows, "0000000000000002"),
            Ok("0000000000000002".into())
        );
        assert_eq!(backup_key(&rows, "польш"), Ok("0000000000000003".into()));
        // An unknown but well-formed key is kept: a node may reappear.
        assert_eq!(
            backup_key(&rows, "deadbeefdeadbeef"),
            Ok("deadbeefdeadbeef".into())
        );
        assert!(backup_key(&rows, "9").is_err());
    }

    #[test]
    fn the_role_column_marks_primary_backups_and_gone_nodes() {
        let mut rows = sample();
        rows[3].missing = true;
        assert_eq!(role(&rows[1]), "primary");
        assert_eq!(role(&rows[2]), "backup 1");
        assert_eq!(role(&rows[3]), "missing");
        assert_eq!(role(&rows[0]), "");
    }

    #[test]
    fn test_filters_servers_by_text_and_rejects_no_match() {
        let rows = sample();
        assert_eq!(select_for_test(&rows, None), Ok(vec![0, 1, 2, 3]));
        assert_eq!(select_for_test(&rows, Some("герман")), Ok(vec![0, 2]));
        assert!(select_for_test(&rows, Some("zzz")).is_err());
    }
}
