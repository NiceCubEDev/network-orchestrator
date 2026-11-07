//! Named proxy exits of a connected Xray TUN profile. `list`, `set` and
//! `remove` only read or write the saved profiles — they never start or
//! probe anything; a connected profile applies an edited list on its next
//! connect. `netorch proxy NAME -- COMMAND` replaces this process with
//! COMMAND (same pid, same terminal, native exit status and signals) after
//! pointing its proxy environment at the exit's loopback listeners. Nothing
//! connects, reloads or restarts the tunnel here; a saved name whose
//! listener is not running — or now binds another target — refuses.
use super::args::{ProxyArgs, ProxyCommand};
use super::commands::Output;
use super::ctx::Ctx;
use super::endpoints;
use super::library::require_user;
use net_manager_core::models::{NamedProxyExit, Profile, ProxyTarget, TunnelBackend, XrayMode};
use net_manager_core::proxy_exits::valid_proxy_exit_name;
use serde_json::{json, Value};
use std::ffi::{OsStr, OsString};
use std::io::ErrorKind;
use std::os::unix::process::CommandExt;

pub fn run(ctx: &Ctx, args: ProxyArgs, json: bool) -> Result<Output, String> {
    let nested_profile = match &args.command {
        ProxyCommand::List { profile }
        | ProxyCommand::Set { profile, .. }
        | ProxyCommand::Remove { profile, .. } => profile.as_ref(),
        ProxyCommand::Run(_) => None,
    };
    if args.profile.is_some() && nested_profile.is_some() {
        return Err("Specify --profile only once".into());
    }
    match args.command {
        ProxyCommand::List { profile } => list(ctx, profile.or(args.profile)),
        ProxyCommand::Set {
            name,
            profile,
            rules,
            via,
            pool,
            direct,
            no_proxy,
        } => set(
            ctx,
            required_profile(profile.or(args.profile), "set")?,
            &name,
            rules,
            via,
            pool,
            direct,
            no_proxy,
        ),
        ProxyCommand::Remove { name, profile } => remove(
            ctx,
            required_profile(profile.or(args.profile), "remove")?,
            &name,
        ),
        ProxyCommand::Run(argv) => {
            if json {
                return Err("`netorch proxy NAME -- COMMAND` runs the command in this \
                            terminal; --json is not supported"
                    .into());
            }
            launch(ctx, args.profile, &argv)
        }
    }
}

/// `set`/`remove` always name their profile: `--profile` may stand before
/// or after the subcommand, but it may not be missing — or given twice.
fn required_profile(profile: Option<String>, word: &str) -> Result<String, String> {
    profile.ok_or_else(|| format!("`netorch proxy {word}` needs --profile"))
}

fn list(ctx: &Ctx, profile: Option<String>) -> Result<Output, String> {
    let profiles = match profile {
        Some(query) => vec![ctx.find(&query)?],
        None => ctx.profiles()?,
    };
    let items: Vec<Value> = profiles
        .iter()
        .flat_map(|profile| {
            profile
                .xray_proxy_exits
                .iter()
                .map(move |exit| exit_json(ctx, profile, exit))
        })
        .collect();
    if items.is_empty() {
        return Ok((
            json!([]),
            "No named exits. `netorch proxy set NAME --profile PROFILE --rules|--via NODE|--pool NODE...|--direct` adds one."
                .into(),
        ));
    }
    let mut text = String::new();
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            text.push('\n');
        }
        let mut line = format!(
            "{}  (profile \"{}\" {}): {}",
            item["name"].as_str().unwrap_or_default(),
            item["profileName"].as_str().unwrap_or_default(),
            item["profile"].as_str().unwrap_or_default(),
            item["targetText"].as_str().unwrap_or_default(),
        );
        let bypass = item["noProxy"].as_array().map_or(0, Vec::len);
        if bypass > 0 {
            line.push_str(&format!("; {bypass} bypass entries"));
        }
        text.push_str(&line);
    }
    Ok((json!(items), text))
}

/// One exit as the commands report it: names and keys, never a share link.
fn exit_json(ctx: &Ctx, profile: &Profile, exit: &NamedProxyExit) -> Value {
    json!({
        "name": exit.name,
        "profile": profile.id,
        "profileName": profile.name,
        "target": serde_json::to_value(&exit.target).unwrap_or(Value::Null),
        "targetText": target_text(ctx, profile, &exit.target),
        "noProxy": exit.no_proxy,
    })
}

/// Human-readable target: server names where the subscription still knows
/// them, raw keys for the ones it has forgotten.
fn target_text(ctx: &Ctx, profile: &Profile, target: &ProxyTarget) -> String {
    let node =
        |key: &str| endpoints::node_name(ctx, profile, key).unwrap_or_else(|| key.to_string());
    match target {
        ProxyTarget::Rules => "profile rules".into(),
        ProxyTarget::Node { endpoint_key } => format!("via {}", node(endpoint_key)),
        ProxyTarget::Pool { endpoint_keys } => {
            format!(
                "pool [{}]",
                endpoint_keys
                    .iter()
                    .map(|k| node(k))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        ProxyTarget::Direct => "direct".into(),
    }
}

/// One node argument — number, name part or raw 16-hex key — resolved the
/// `backup`/`route pin` way, so a node that left the subscription keeps its
/// valid raw key instead of failing the save.
fn node_key(ctx: &Ctx, profile: &Profile, query: &str) -> Result<String, String> {
    if profile.subscription.is_none() {
        return Err("Server targets need a subscription profile".into());
    }
    endpoints::backup_key(&endpoints::list_rows(ctx, profile)?, query)
}

fn target_of(
    ctx: &Ctx,
    profile: &Profile,
    rules: bool,
    via: Option<String>,
    pool: Option<Vec<String>>,
    direct: bool,
) -> Result<ProxyTarget, String> {
    if rules {
        return Ok(ProxyTarget::Rules);
    }
    if let Some(node) = via {
        return Ok(ProxyTarget::Node {
            endpoint_key: node_key(ctx, profile, &node)?,
        });
    }
    if let Some(nodes) = pool {
        if nodes.len() > 8 {
            return Err("A pool takes at most 8 servers".into());
        }
        let mut keys = Vec::with_capacity(nodes.len());
        for node in &nodes {
            let key = node_key(ctx, profile, node)?;
            if keys.contains(&key) {
                return Err("A pool takes each server once".into());
            }
            keys.push(key);
        }
        return Ok(ProxyTarget::Pool {
            endpoint_keys: keys,
        });
    }
    if direct {
        return Ok(ProxyTarget::Direct);
    }
    Err("Choose the exit's target: --rules, --via NODE, --pool NODE... or --direct".into())
}

#[cfg(not(target_os = "linux"))]
fn save_error(error: std::io::Error) -> String {
    match error.kind() {
        ErrorKind::InvalidInput | ErrorKind::AlreadyExists => error.to_string(),
        _ => {
            "The profile could not be updated. Check permissions and reload its saved state.".into()
        }
    }
}

const APPLY_NOTE: &str = "Reconnect an active profile to apply listener changes; no-proxy changes apply to the next command.";

#[allow(clippy::too_many_arguments)]
fn set(
    ctx: &Ctx,
    query: String,
    name: &str,
    rules: bool,
    via: Option<String>,
    pool: Option<Vec<String>>,
    direct: bool,
    no_proxy: Vec<String>,
) -> Result<Output, String> {
    require_user(ctx)?;
    if !valid_proxy_exit_name(name) {
        return Err("Invalid or reserved proxy exit name; use 1-32 lowercase letters, digits, - or _, starting with a letter or digit".into());
    }
    let profile = ctx.find(&query)?;
    if profile.backend != TunnelBackend::Xray {
        return Err("Named exits are available for Xray profiles".into());
    }
    let target = target_of(ctx, &profile, rules, via, pool, direct)?;
    let no_proxy: Vec<String> = no_proxy
        .iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect();
    let exit = NamedProxyExit {
        name: name.to_string(),
        target,
        no_proxy,
    };
    #[cfg(target_os = "linux")]
    let document = net_manager_engine::linux_profiles::ProfileService::new(
        ctx.root.clone(),
        ctx.engine.clone(),
    )
    .upsert_proxy_exit(&profile.id, exit)?;
    #[cfg(not(target_os = "linux"))]
    let document = ctx
        .store()
        .update_profile(&profile.id, |current| {
            match current
                .xray_proxy_exits
                .iter_mut()
                .find(|saved| saved.name == name)
            {
                Some(saved) => *saved = exit,
                None => current.xray_proxy_exits.push(exit),
            }
            Ok(())
        })
        .map_err(save_error)?;
    let current = document
        .profiles
        .iter()
        .find(|saved| saved.id == profile.id)
        .ok_or_else(|| "The saved profile is unavailable".to_string())?;
    let saved = current
        .xray_proxy_exits
        .iter()
        .find(|exit| exit.name == name)
        .map(|exit| exit_json(ctx, current, exit));
    Ok((
        json!({"saved":saved}),
        format!("Saved exit \"{name}\". {APPLY_NOTE}"),
    ))
}

fn remove(ctx: &Ctx, query: String, name: &str) -> Result<Output, String> {
    require_user(ctx)?;
    if !valid_proxy_exit_name(name) {
        return Err("Invalid or reserved proxy exit name".into());
    }
    let profile = ctx.find(&query)?;
    #[cfg(target_os = "linux")]
    net_manager_engine::linux_profiles::ProfileService::new(ctx.root.clone(), ctx.engine.clone())
        .remove_proxy_exit(&profile.id, name)?;
    #[cfg(not(target_os = "linux"))]
    ctx.store()
        .update_profile(&profile.id, |current| {
            let before = current.xray_proxy_exits.len();
            current.xray_proxy_exits.retain(|exit| exit.name != name);
            if current.xray_proxy_exits.len() == before {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "The named exit was not found",
                ));
            }
            Ok(())
        })
        .map_err(save_error)?;
    Ok((
        json!({"removed": name}),
        format!("Removed exit \"{name}\". {APPLY_NOTE}"),
    ))
}

/// The saved exit a `proxy NAME` launch means: with `--profile` the name
/// must be on that profile; without it the name must exist on exactly one
/// profile so a shared name can never pick an arbitrary tunnel.
fn find_exit(
    ctx: &Ctx,
    name: &str,
    query: Option<&str>,
) -> Result<(Profile, NamedProxyExit), String> {
    if let Some(query) = query {
        let profile = ctx.find(query)?;
        let exit = profile
            .xray_proxy_exits
            .iter()
            .find(|exit| exit.name == name)
            .cloned()
            .ok_or_else(|| format!("\"{name}\" is not an exit of \"{}\"", profile.name))?;
        return Ok((profile, exit));
    }
    unique_exit(&ctx.profiles()?, name)
}

/// The only profile that saved an exit called `name`, or why there is none.
fn unique_exit(profiles: &[Profile], name: &str) -> Result<(Profile, NamedProxyExit), String> {
    let found: Vec<(&Profile, &NamedProxyExit)> = profiles
        .iter()
        .filter_map(|profile| {
            profile
                .xray_proxy_exits
                .iter()
                .find(|exit| exit.name == name)
                .map(|exit| (profile, exit))
        })
        .collect();
    match found.as_slice() {
        [(profile, exit)] => Ok(((*profile).clone(), (*exit).clone())),
        [] => Err(format!(
            "\"{name}\" is not a saved exit. `netorch proxy list` shows them."
        )),
        many => Err(format!(
            "\"{name}\" is an exit of {} profiles: {}. Give --profile.",
            many.len(),
            many.iter()
                .map(|(profile, _)| format!("\"{}\"", profile.name))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The saved `--` separation: clap's external capture hands over
/// `NAME -- COMMAND ARGS...` verbatim, and only that shape may launch —
/// never a bare name (a shell default) or another separator.
fn split_launch(argv: &[OsString]) -> Result<(&str, &[OsString]), String> {
    let name = argv
        .first()
        .and_then(|arg| arg.to_str())
        .ok_or_else(|| "The exit name must be text".to_string())?;
    if !valid_proxy_exit_name(name) {
        return Err("Invalid or reserved proxy exit name".into());
    }
    if argv.get(1).map(OsString::as_os_str) != Some(OsStr::new("--")) {
        return Err("Use `netorch proxy [--profile PROFILE] NAME -- COMMAND [ARGS...]` (the -- is required)".into());
    }
    let command = &argv[2..];
    if command.is_empty() {
        return Err("No command; use `netorch proxy NAME -- COMMAND [ARGS...]`".into());
    }
    Ok((name, command))
}

/// exec can only fail before the program exists; the message names no path
/// or argument — the command line may carry secrets.
fn launch_error(error: std::io::Error) -> String {
    match error.kind() {
        ErrorKind::NotFound => "The command was not found".into(),
        ErrorKind::PermissionDenied => "The command is not executable".into(),
        _ => match error.raw_os_error() {
            Some(code) => format!("The command could not be started (os error {code})"),
            None => "The command could not be started".into(),
        },
    }
}

/// `netorch proxy [--profile PROFILE] NAME -- COMMAND [ARGS...]`. The
/// binding is checked against the saved exit — name and target — so an exit
/// saved after the tunnel connected, or one whose listener now means
/// something else, refuses instead of running somewhere unexpected. Only
/// then does this process become COMMAND.
fn launch(ctx: &Ctx, profile: Option<String>, argv: &[OsString]) -> Result<Output, String> {
    require_user(ctx)?;
    let (name, command) = split_launch(argv)?;
    let (profile, exit) = find_exit(ctx, name, profile.as_deref())?;
    if profile.backend != TunnelBackend::Xray || profile.xray_mode != XrayMode::Tun {
        return Err(format!(
            "\"{name}\" needs the connected Xray TUN profile \"{}\"",
            profile.name
        ));
    }
    let bindings = ctx.engine.named_proxy_exits(&profile.id)?;
    let binding = bindings
        .iter()
        .find(|binding| binding.name == exit.name)
        .ok_or_else(|| {
            format!(
                "Exit \"{name}\" is not running on \"{}\": connect the profile (`netorch up`) or reconnect it to apply saved exits",
                profile.name
            )
        })?;
    if binding.target != exit.target {
        return Err(format!(
            "Exit \"{name}\" changed since \"{}\" connected; `netorch down` then `netorch up` applies it",
            profile.name
        ));
    }
    if let ProxyTarget::Pool { endpoint_keys } = &exit.target {
        let healthy = binding
            .pool
            .as_ref()
            .is_some_and(|pool| endpoint_keys.contains(&pool.active_key));
        if !healthy {
            return Err(format!(
                "Exit \"{name}\" has no healthy server; not running the command"
            ));
        }
    }
    let mut process = std::process::Command::new(&command[0]);
    process.args(&command[1..]);
    let http = format!("http://127.0.0.1:{}", binding.http_port);
    let socks = format!("socks5h://127.0.0.1:{}", binding.socks_port);
    let bypass = exit.no_proxy.join(",");
    // Replace both case spellings, including inherited NO_PROXY=*.
    process.envs([
        ("HTTP_PROXY", http.as_str()),
        ("http_proxy", http.as_str()),
        ("HTTPS_PROXY", http.as_str()),
        ("https_proxy", http.as_str()),
        ("ALL_PROXY", socks.as_str()),
        ("all_proxy", socks.as_str()),
        ("NO_PROXY", bypass.as_str()),
        ("no_proxy", bypass.as_str()),
    ]);
    Err(launch_error(process.exec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn launch_argv_needs_the_literal_separator() {
        let argv = os(&["nl", "--", "curl", "-s"]);
        let (name, command) = split_launch(&argv).unwrap();
        assert_eq!(name, "nl");
        assert_eq!(command, [OsString::from("curl"), OsString::from("-s")]);

        // Without the separator nothing runs: there is no shell default.
        assert!(split_launch(&os(&["nl", "curl"])).is_err());
        assert!(split_launch(&os(&["nl"])).is_err());
        // The separator alone is not a command.
        assert!(split_launch(&os(&["nl", "--"])).is_err());
        // Options between the name and `--` belong to no one: refuse.
        assert!(split_launch(&os(&["nl", "-x", "--", "curl"])).is_err());
        // An extra `--` inside the command is argv, not another separator.
        let argv = os(&["nl", "--", "prog", "--"]);
        let (_, command) = split_launch(&argv).unwrap();
        assert_eq!(command.len(), 2);
    }

    #[test]
    fn an_unnamed_profile_is_matched_only_with_profile() {
        let exit = |name: &str| NamedProxyExit {
            name: name.into(),
            target: ProxyTarget::Direct,
            no_proxy: Vec::new(),
        };
        let profile = |id: &str, name: &str| Profile {
            id: id.into(),
            name: name.into(),
            xray_proxy_exits: vec![exit("nl")],
            ..Profile::default()
        };
        let profiles = vec![profile("a", "One"), profile("b", "Two")];
        // The same name on two profiles refuses without --profile.
        assert!(unique_exit(&profiles, "nl").is_err());
        let (found, _) = unique_exit(&profiles[..1], "nl").unwrap();
        assert_eq!(found.id, "a");
        // A missing name fails.
        assert!(unique_exit(&profiles, "de").is_err());
    }

    #[cfg(target_os = "linux")]
    fn named_exit(name: &str) -> NamedProxyExit {
        NamedProxyExit {
            name: name.into(),
            target: ProxyTarget::Direct,
            no_proxy: vec!["preserve.invalid".into()],
        }
    }

    #[cfg(target_os = "linux")]
    fn proxy_sandbox(exits: Vec<NamedProxyExit>) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let vault = net_manager_core::config_vault::ConfigVault::new(root.path().join("configs"));
        let imported = vault
            .store_generated_xray("named-race", br#"{"inbounds":[],"outbounds":[]}"#)
            .unwrap();
        net_manager_core::profiles::ProfileStore::new(root.path().join("profiles.json"))
            .upsert(Profile {
                id: "named-race".into(),
                name: "Named exit concurrency".into(),
                backend: TunnelBackend::Xray,
                xray_mode: XrayMode::Socks,
                config_path: imported.config_path,
                xray_proxy_exits: exits,
                ..Profile::default()
            })
            .unwrap();
        root
    }

    #[cfg(target_os = "linux")]
    fn concurrent_mutations(
        root: &std::path::Path,
        first: impl FnOnce(&Ctx) -> Result<Output, String> + Send + 'static,
        second: impl FnOnce(&Ctx) -> Result<Output, String> + Send + 'static,
    ) {
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;

        let lock_path = root.join("profile-operations.lock");
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        lock.lock().unwrap();
        // Each CLI consumer opens this lock only after reading its profile.
        // Observe the opens separately so inotify cannot coalesce them; both
        // readers then remain blocked before either can commit a mutation.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        let mut watch = unsafe { std::fs::File::from_raw_fd(fd) };
        let path = std::ffi::CString::new(lock_path.as_os_str().as_bytes()).unwrap();
        assert!(
            unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_OPEN) } >= 0,
            "{}",
            std::io::Error::last_os_error()
        );
        let mut wait_for_open = || {
            let mut poll = libc::pollfd {
                fd: watch.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe { libc::poll(&mut poll, 1, 10_000) },
                1,
                "CLI consumer did not reach the mutation boundary"
            );
            let mut event = [0u8; std::mem::size_of::<libc::inotify_event>()];
            watch.read_exact(&mut event).unwrap();
            let mask = u32::from_ne_bytes(event[4..8].try_into().unwrap());
            assert_ne!(mask & libc::IN_OPEN, 0);
        };
        fn spawn_mutation(
            root: &std::path::Path,
            operation: impl FnOnce(&Ctx) -> Result<Output, String> + Send + 'static,
        ) -> std::thread::JoinHandle<Result<Output, String>> {
            let root = root.to_path_buf();
            std::thread::spawn(move || {
                let engine = net_manager_engine::linux_engine::LinuxEngine::for_socket(
                    root.join("unused-daemon.sock"),
                    "proxy-concurrency-test",
                );
                let ctx = Ctx::new(root, engine).unwrap();
                operation(&ctx)
            })
        }
        let first = spawn_mutation(root, first);
        wait_for_open();
        let second = spawn_mutation(root, second);
        wait_for_open();
        drop(lock);
        assert!(first.join().unwrap().is_ok(), "first named mutation failed");
        assert!(
            second.join().unwrap().is_ok(),
            "second named mutation failed"
        );
    }

    #[cfg(target_os = "linux")]
    fn saved_exits(root: &std::path::Path) -> Vec<NamedProxyExit> {
        net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"))
            .load()
            .unwrap()
            .profiles
            .into_iter()
            .find(|profile| profile.id == "named-race")
            .unwrap()
            .xray_proxy_exits
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_proxy_sets_preserve_distinct_names() {
        let root = proxy_sandbox(vec![named_exit("kept")]);
        concurrent_mutations(
            root.path(),
            |ctx| {
                set(
                    ctx,
                    "named-race".into(),
                    "alpha",
                    false,
                    None,
                    None,
                    true,
                    Vec::new(),
                )
            },
            |ctx| {
                set(
                    ctx,
                    "named-race".into(),
                    "bravo",
                    true,
                    None,
                    None,
                    false,
                    Vec::new(),
                )
            },
        );
        let mut actual = saved_exits(root.path());
        actual.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            actual,
            vec![
                NamedProxyExit {
                    name: "alpha".into(),
                    target: ProxyTarget::Direct,
                    no_proxy: Vec::new()
                },
                NamedProxyExit {
                    name: "bravo".into(),
                    target: ProxyTarget::Rules,
                    no_proxy: Vec::new()
                },
                named_exit("kept"),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_proxy_remove_and_set_preserve_both_changes() {
        let root = proxy_sandbox(vec![named_exit("kept"), named_exit("remove-me")]);
        concurrent_mutations(
            root.path(),
            |ctx| remove(ctx, "named-race".into(), "remove-me"),
            |ctx| {
                set(
                    ctx,
                    "named-race".into(),
                    "added",
                    false,
                    None,
                    None,
                    true,
                    Vec::new(),
                )
            },
        );
        let mut actual = saved_exits(root.path());
        actual.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            actual,
            vec![
                NamedProxyExit {
                    name: "added".into(),
                    target: ProxyTarget::Direct,
                    no_proxy: Vec::new()
                },
                named_exit("kept"),
            ]
        );
    }
}
