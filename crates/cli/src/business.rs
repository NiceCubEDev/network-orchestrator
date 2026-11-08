//! Business command consumers. JSON is a presentation/file format, never a dispatcher.
use crate::{
    args::*,
    ctx::{self, Ctx},
    input,
};
use net_manager_core::{
    connection_sets::{self, ConnectionSet, CredentialInputs},
    models::TunnelBackend,
};
use net_manager_engine::{
    macos_services::{self, BatchItemOutcome, BatchOutcome, StartPolicy},
    macos_state::{AppMode as SharedMode, SettingsStore},
};
use serde_json::json;
use std::path::Path;

pub fn batch(ctx: &Ctx, outcome: BatchOutcome) -> Result<(), String> {
    let failed = outcome.items.iter().any(|i| {
        matches!(
            i.outcome,
            BatchItemOutcome::Failed
                | BatchItemOutcome::CredentialsRequired
                | BatchItemOutcome::Unavailable
        )
    });
    ctx.output(&outcome)?;
    if failed {
        Err("Some operations failed, were unavailable, or require credentials; see per-profile results".into())
    } else {
        Ok(())
    }
}
fn credentials(path: Option<&Path>) -> Result<CredentialInputs, String> {
    path.map(|p| input::json(p, true))
        .transpose()
        .map(Option::unwrap_or_default)
}
fn backend(b: Backend) -> TunnelBackend {
    match b {
        Backend::Xray => TunnelBackend::Xray,
        Backend::Wireguard => TunnelBackend::WireGuard,
        Backend::Openvpn => TunnelBackend::OpenVpn,
        Backend::Static => TunnelBackend::None,
    }
}
fn require_mutation(ctx: &Ctx) -> Result<(), String> {
    ctx.require_user()
}
fn on(state: Switch) -> bool {
    matches!(state, Switch::Up)
}
fn now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "System clock is before Unix epoch".into())
}

pub fn run(ctx: &Ctx, command: Command) -> Result<(), String> {
    let services = ctx.services()?;
    let engine = ctx.engine();
    let network = ctx.network();
    match command {
        Command::Import {
            file,
            backend: b,
            name,
        } => {
            ctx.require_user()?;
            let name = name.unwrap_or_else(|| {
                file.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("Imported")
                    .to_string()
            });
            let id = crate::target::make_id(&name, &ctx::random_suffix()?);
            let profile = services.import_config(macos_services::ConfigImport {
                id,
                name,
                backend: backend(b),
                path: file,
            })?;
            ctx.output(&crate::render::row_of(&profile))
        }
        Command::Edit(args) => {
            ctx.require_user()?;
            let p = ctx.find(&args.target)?;
            crate::connect::apply_settings(
                ctx,
                &p,
                args.mode,
                args.role,
                args.networks.as_deref(),
                args.dns_domains.as_deref(),
            )?;
            if let Some(name) = args.name {
                services.rename_profile(&p.id, &name)?;
            }
            if let Some(v) = args.auto_connect {
                services.set_auto_connect(&p.id, v)?;
            }
            if let Some(v) = args.wait_for_interface {
                services.set_wait_for_interface(&p.id, v)?;
            }
            if let Some(v) = args.refresh_interval {
                services.set_subscription_refresh_interval(
                    &p.id,
                    if v == 0 { None } else { Some(v) },
                )?;
            }
            let p = services
                .public_profiles()?
                .into_iter()
                .find(|v| v.id == p.id)
                .ok_or("Profile disappeared during edit")?;
            ctx.output(&crate::render::row_of(&p))
        }
        Command::Static { file } => {
            ctx.require_user()?;
            let p = services.create_static(input::json(&file, false)?)?;
            ctx.output(&crate::render::row_of(&p))
        }
        Command::Reorder {
            backend: b,
            profiles,
        } => {
            ctx.require_user()?;
            let ids = profiles
                .iter()
                .map(|q| ctx.find(q).map(|p| p.id))
                .collect::<Result<Vec<_>, _>>()?;
            let profiles = services.reorder_profiles(backend(b), &ids)?;
            ctx.output(
                &profiles
                    .iter()
                    .map(crate::render::row_of)
                    .collect::<Vec<_>>(),
            )
        }
        Command::Inspect { target } => {
            ctx.output(&services.inspect_profile(&ctx.find(&target)?.id)?)
        }
        Command::Diagnose { target } => {
            ctx.output(&services.diagnose_profile(&ctx.find(&target)?.id)?)
        }
        Command::Subscription(command) => match command {
            SubscriptionCommand::Endpoints { target } => {
                ctx.output(&services.subscription_endpoints(&ctx.find(&target)?.id)?)
            }
            SubscriptionCommand::Switch { target, index } => {
                ctx.require_user()?;
                let p = services.switch_subscription_endpoint(&ctx.find(&target)?.id, index)?;
                ctx.output(&crate::render::row_of(&p))
            }
            SubscriptionCommand::Refresh { target } => {
                ctx.require_user()?;
                ctx.output(&services.refresh_subscription(&ctx.find(&target)?.id)?)
            }
            SubscriptionCommand::RefreshAll { due } => {
                ctx.require_user()?;
                batch(ctx, services.refresh_subscriptions(due, now()?)?)
            }
            SubscriptionCommand::ImportLog => {
                let log = services.subscription_import_log();
                ctx.emit(json!({"log":log}), || log);
                Ok(())
            }
            SubscriptionCommand::Hwid => {
                ctx.require_user()?;
                ctx.output(&json!({"hwid":services.generate_subscription_hwid()?}))
            }
        },
        Command::Sets(command) => sets(ctx, command),
        Command::Mode(command) => {
            let store = SettingsStore::new(&ctx.root);
            match command {
                AppModeCommand::Show => ctx.output(&store.load()?),
                AppModeCommand::Set { mode } => {
                    ctx.require_user()?;
                    ctx.output(&store.set_app_mode(match mode {
                        AppMode::Combined => SharedMode::Combined,
                        AppMode::Orchestrator => SharedMode::Orchestrator,
                        AppMode::Manager => SharedMode::Manager,
                    })?)
                }
                AppModeCommand::Eligibility { target } => ctx.output(
                    &StartPolicy::current()
                        .eligibility(store.load()?.app_mode, &ctx.find(&target)?),
                ),
            }
        }
        Command::AutoConnect { credentials_file } => {
            ctx.require_user()?;
            batch(
                ctx,
                services.auto_connect(
                    &StartPolicy::current(),
                    &credentials(credentials_file.as_deref())?,
                    &services.native_credential_store()?,
                )?,
            )
        }
        Command::Credentials(CredentialCommand::Forget { target }) => {
            ctx.require_user()?;
            ctx.output(
                &services
                    .native_credential_store()?
                    .forget(&ctx.find(&target)?.id)?,
            )
        }
        Command::Credentials(CredentialCommand::Requirements { target }) => {
            let needs = engine.credential_requirements(&ctx.find(&target)?)?;
            ctx.output(&json!({"userPass":needs.user_pass,"keyPassphrase":needs.key_passphrase}))
        }
        Command::Network(command) => match command {
            NetworkCommand::Settings => ctx.output(&network.user_network_settings()?),
            NetworkCommand::Interfaces => ctx.output(&network.interfaces()?),
            NetworkCommand::Routes => ctx.output(&network.routes()?),
            NetworkCommand::Lookup { address } => ctx.output(&network.lookup_route(address)?),
            NetworkCommand::Dns => ctx.output(&network.dns_status()?),
            NetworkCommand::DnsProbe {
                hostname,
                server,
                ipv6,
            } => ctx.output(&network.dns_probe(
                &net_manager_engine::macos_network::DnsProbeRequest {
                    hostname,
                    server,
                    family: if ipv6 {
                        net_manager_core::dns_probe::DnsFamily::Aaaa
                    } else {
                        net_manager_core::dns_probe::DnsFamily::A
                    },
                },
            )?),
            NetworkCommand::ProxyEffect => {
                let profiles = ctx.profiles()?;
                let snapshot = engine.snapshot(&profiles)?;
                let owned = snapshot
                    .statuses
                    .into_iter()
                    .filter(|s| s.state == net_manager_core::models::TunnelState::Running)
                    .filter_map(|s| s.interface_name)
                    .collect::<Vec<_>>();
                ctx.output(&network.proxy_override(&owned)?)
            }
            NetworkCommand::Interface { name, state } => {
                ctx.require_user()?;
                engine.set_interface_state(&name, on(state))?;
                ctx.output(&ctx::ok_json())
            }
        },
        Command::Netbird(command) => match command {
            NetbirdCommand::Status => ctx.output(&engine.netbird_status()?),
            NetbirdCommand::Down => {
                ctx.require_user()?;
                ctx.output(&engine.netbird_down()?)
            }
            NetbirdCommand::Log => {
                let log = network.netbird_log()?;
                ctx.emit(json!({"log":log}), || log.clone());
                Ok(())
            }
            NetbirdCommand::Up {
                management_url,
                setup_key_stdin,
                setup_key_file,
            } => {
                ctx.require_user()?;
                let setup_key = if setup_key_stdin {
                    Some(
                        input::text(Path::new("-"), true)?
                            .trim_end_matches(['\r', '\n'])
                            .to_string(),
                    )
                } else {
                    setup_key_file
                        .as_deref()
                        .map(|p| {
                            input::text(p, true)
                                .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
                        })
                        .transpose()?
                };
                ctx.output(&engine.netbird_up(
                    &net_manager_engine::macos_network::NetBirdConnectOptions {
                        management_url,
                        setup_key,
                    },
                )?)
            }
        },
        Command::Tailscale(command) => match command {
            TailscaleCommand::Status => {
                let mut status = engine.tailscale_status()?;
                status.auth_url = None;
                ctx.output(&status)
            }
            TailscaleCommand::Up => {
                ctx.require_user()?;
                let mut outcome = engine.tailscale_up()?;
                outcome.status.auth_url = None;
                ctx.output(&outcome)
            }
            TailscaleCommand::Down => {
                ctx.require_user()?;
                let mut outcome = engine.tailscale_down()?;
                outcome.status.auth_url = None;
                ctx.output(&outcome)
            }
            TailscaleCommand::Sync => {
                ctx.require_user()?;
                ctx.output(&engine.sync_tailscale()?)
            }
        },
        Command::Vpn(command) => match command {
            VpnCommand::List => ctx.output(&network.external_vpns()?),
            VpnCommand::Set { id, state } => {
                ctx.require_user()?;
                ctx.output(&engine.set_external_vpn(&id, on(state))?)
            }
        },
        Command::Intents(command) => match command {
            IntentCommand::List => ctx.output(&engine.intents()?),
            IntentCommand::Put { file } => {
                require_mutation(ctx)?;
                engine.set_intent(input::json(&file, false)?)?;
                ctx.output(&ctx::ok_json())
            }
            IntentCommand::Delete { id } => {
                require_mutation(ctx)?;
                engine.delete_intent(&id)?;
                ctx.output(&ctx::ok_json())
            }
            IntentCommand::Doctor => ctx.output(&services.intent_suggestions()?),
            IntentCommand::Apply { file } => {
                require_mutation(ctx)?;
                let outcome = services.apply_intent_fixes(&input::json::<
                    Vec<net_manager_core::daemon_protocol::NetIntentSetParams>,
                >(&file, false)?)?;
                let failed = outcome.error.is_some();
                ctx.output(&outcome)?;
                if failed {
                    Err("Intent fixes stopped at first failure".into())
                } else {
                    Ok(())
                }
            }
        },
        Command::Conditions(command) => match command {
            ConditionCommand::List => ctx.output(&engine.cond_rules()?),
            ConditionCommand::Put { file } => {
                require_mutation(ctx)?;
                ctx.output(&engine.put_cond_rule(input::json(&file, false)?)?)
            }
            ConditionCommand::Delete { id } => {
                require_mutation(ctx)?;
                ctx.output(&json!({"removed":engine.remove_cond_rule(&id)?}))
            }
        },
        Command::Recovery(command) => match command {
            RecoveryCommand::Report => ctx.output(&engine.recovery_report(&ctx.profiles()?)?),
            RecoveryCommand::Cleanup => {
                ctx.require_user()?;
                ctx.output(&engine.recovery_cleanup(&ctx.profiles()?)?)
            }
        },
        Command::Proxy(command) => match command {
            ProxyCommand::Set { target, state } => {
                ctx.require_user()?;
                engine.set_system_proxy(&ctx.find(&target)?, &ctx.profiles()?, on(state))?;
                ctx.output(&ctx::ok_json())
            }
            ProxyCommand::Env { target } => {
                let exports = services.proxy_exports(&ctx.find(&target)?.id)?;
                if ctx.json {
                    ctx.output(&exports)
                } else {
                    println!("{}", exports.shell);
                    Ok(())
                }
            }
            ProxyCommand::Browser { target } => {
                ctx.require_user()?;
                services.open_browser(&ctx.find(&target)?.id)?;
                ctx.output(&ctx::ok_json())
            }
        },
        Command::Capabilities => {
            let mut result = macos_services::capabilities();
            result.version = env!("NETORCH_VERSION");
            ctx.output(&result)
        }
        Command::Snapshot => ctx.output(&services.network_snapshot()?),
        _ => Err("Command was routed to the wrong handler".into()),
    }
}
fn sets(ctx: &Ctx, command: SetCommand) -> Result<(), String> {
    ctx.require_user()?;
    let services = ctx.services()?;
    match command {
        SetCommand::List => ctx.output(&connection_sets::list(&ctx.root)?),
        SetCommand::Capture { id, name } => {
            ctx.output(&services.capture_set(&id, name.as_deref().unwrap_or("Connection set"))?)
        }
        SetCommand::Put { id, name, profiles } => {
            let profile_ids = profiles
                .iter()
                .map(|q| ctx.find(q).map(|p| p.id))
                .collect::<Result<Vec<_>, _>>()?;
            let set = net_manager_engine::macos_transaction::with_root_lock(&ctx.root, || {
                connection_sets::put(
                    &ctx.root,
                    &ctx.store(),
                    ConnectionSet {
                        id,
                        name,
                        profile_ids,
                    },
                )
            })?;
            ctx.output(&set)
        }
        SetCommand::Import { file } => {
            let sets: Vec<ConnectionSet> = input::json(&file, false)?;
            ctx.output(&net_manager_engine::macos_transaction::with_root_lock(
                &ctx.root,
                || connection_sets::import(&ctx.root, sets),
            )?)
        }
        SetCommand::Delete { id } => {
            net_manager_engine::macos_transaction::with_root_lock(&ctx.root, || {
                connection_sets::delete(&ctx.root, &id)
            })?;
            ctx.output(&ctx::ok_json())
        }
        SetCommand::Apply {
            id,
            credentials_file,
        } => {
            let set = connection_sets::get(&ctx.root, &id)?;
            let missing = connection_sets::missing_members(&set, &ctx.profiles()?);
            if !missing.is_empty() {
                eprintln!("Missing members ignored: {}", missing.join(", "));
            }
            batch(
                ctx,
                services.apply_set(
                    &set,
                    &StartPolicy::current(),
                    &credentials(credentials_file.as_deref())?,
                    &services.native_credential_store()?,
                )?,
            )
        }
        SetCommand::Down { id } => batch(
            ctx,
            services.disconnect_set(&connection_sets::get(&ctx.root, &id)?)?,
        ),
    }
}
