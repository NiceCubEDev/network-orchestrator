//! Detached connections and generation-scoped foreground leases.
use crate::{
    args::{CredentialArgs, Mode, Role, UpArgs},
    ctx::Ctx,
    library, prompt,
    target::{self, Input},
};
use net_manager_core::daemon_protocol::OpenVpnCredentials;
use net_manager_core::models::{Profile, TunnelBackend, TunnelRole, XrayMode};
use net_manager_engine::macos_credentials::{
    ConnectOutcome, CredentialRequirements, CredentialResolution,
};
use net_manager_engine::macos_services::ConnectProfileOutcome;
use serde_json::json;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
    net_manager_engine::macos_session::request_stop();
}
fn install_signal_handlers() {
    STOP.store(false, Ordering::SeqCst);
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe { libc::signal(signal, on_signal as *const () as libc::sighandler_t) };
    }
}

pub fn apply_settings(
    ctx: &Ctx,
    profile: &Profile,
    mode: Option<Mode>,
    role: Option<Role>,
    networks: Option<&str>,
    dns_domains: Option<&str>,
) -> Result<(), String> {
    if mode.is_none() && role.is_none() && networks.is_none() && dns_domains.is_none() {
        return Ok(());
    }
    ctx.require_user()?;
    let services = ctx.services()?;
    if let Some(mode) = mode {
        let wanted = match mode {
            Mode::Socks => XrayMode::Socks,
            Mode::Tun => XrayMode::Tun,
        };
        if profile.backend != TunnelBackend::Xray || profile.xray_mode != wanted {
            services.set_xray_mode(&profile.id, wanted)?;
        }
    }
    if let Some(role) = role {
        let wanted = match role {
            Role::Primary => TunnelRole::Primary,
            Role::Secondary => TunnelRole::Secondary,
        };
        if profile.backend == TunnelBackend::None || profile.tunnel_role != wanted {
            services.set_tunnel_role(&profile.id, wanted)?;
        }
    }
    if networks.is_some() || dns_domains.is_some() {
        let networks = match networks {
            Some(v) => net_manager_core::models::parse_networks(v)?,
            None => profile.tunnel_networks.clone(),
        };
        let domains = match dns_domains {
            Some(v) => net_manager_core::models::parse_dns_domains(v)?,
            None => profile.tunnel_dns_domains.clone(),
        };
        services.set_tunnel_networks(&profile.id, networks, domains)?;
    }
    Ok(())
}
fn supplied(args: &CredentialArgs) -> Result<Option<OpenVpnCredentials>, String> {
    args.credentials_file
        .as_deref()
        .map(|p| crate::input::json(p, true))
        .transpose()
}
fn collect(
    ctx: &Ctx,
    p: &Profile,
    args: &CredentialArgs,
) -> Result<Option<OpenVpnCredentials>, String> {
    if args.credentials_file.is_some() {
        return supplied(args);
    }
    if p.backend != TunnelBackend::OpenVpn {
        return Ok(None);
    }
    let needs = ctx.engine().credential_requirements(p)?;
    prompt::collect(
        needs.user_pass,
        needs.key_passphrase,
        args.auth_stdin,
        args.passphrase_stdin,
    )
}
fn requested_credentials(
    ctx: &Ctx,
    p: &Profile,
    args: &CredentialArgs,
    prompt: &net_manager_engine::macos_credentials::CredentialPrompt,
) -> Result<Option<OpenVpnCredentials>, String> {
    if let Some(notice) = prompt.notice {
        ctx.note(notice.message());
    }
    let explicit = args.credentials_file.is_some() || args.auth_stdin || args.passphrase_stdin;
    if explicit || !std::io::stdin().is_terminal() {
        if ctx.json {
            ctx.output(&json!({"state":"credentialsRequired","prompt":prompt}))?;
        }
        return Err(if explicit{"Supplied credentials do not satisfy this profile's requirements"}else{"This connection needs credentials; use --auth-stdin, --passphrase-stdin or --credentials-file"}.into());
    }
    collect(ctx, p, args)
}
pub fn up(ctx: &Ctx, args: UpArgs) -> Result<(), String> {
    if crate::ctx::is_root() {
        return up_as_root(ctx, args);
    }
    let p = match target::classify(&args.target, |p| p.is_file()) {
        Input::Saved(q) => ctx.find(&q)?,
        _ => library::add_input(ctx, &args.target, args.name.as_deref(), None)?,
    };
    if ctx.engine().is_running(&p)? {
        return Err("The connection is already running".into());
    }
    apply_settings(
        ctx,
        &p,
        args.mode,
        args.role,
        args.networks.as_deref(),
        args.dns_domains.as_deref(),
    )?;
    let p = ctx.find(&p.id)?;
    let engine = ctx.engine();
    let services = ctx.services()?;
    if args.system_proxy && !crate::route::runs_locally(&p) {
        return Err("--system-proxy applies to Xray --mode socks".into());
    }
    // Enforce persisted start mode before an optional backend installation.
    net_manager_engine::macos_state::ensure_start_allowed(&ctx.root, p.backend)?;
    if p.backend == TunnelBackend::Xray && engine.managed_executable().is_none() {
        engine.install_xray(None)?;
    }
    let credentials = services.native_credential_store()?;
    let mut supplied = supplied(&args.credentials)?;
    if supplied.is_none() && (args.credentials.auth_stdin || args.credentials.passphrase_stdin) {
        supplied = collect(ctx, &p, &args.credentials)?;
    }
    let needs = if p.backend == TunnelBackend::OpenVpn {
        let needs = engine.credential_requirements(&p)?;
        CredentialRequirements {
            user_pass: needs.user_pass,
            key_passphrase: needs.key_passphrase,
        }
    } else {
        CredentialRequirements::default()
    };
    let rejected = p.backend == TunnelBackend::OpenVpn
        && engine
            .snapshot(std::slice::from_ref(&p))?
            .statuses
            .iter()
            .any(|s| {
                s.profile_id == p.id
                    && s.message.as_deref() == Some("OpenVPN authentication failed")
            });
    let mut resolution =
        credentials.resolve(&p.id, needs, supplied, args.credentials.remember, rejected)?;
    if let CredentialResolution::Required(prompt) = &resolution {
        resolution = credentials.resolve(
            &p.id,
            needs,
            requested_credentials(ctx, &p, &args.credentials, prompt)?,
            args.credentials.remember,
            false,
        )?;
    }
    let CredentialResolution::Ready(attempt) = resolution else {
        return Err("Required credentials were not supplied".into());
    };
    install_signal_handlers();
    let lease = match engine.connect_foreground(&ctx.store(), &p, attempt.credentials().cloned()) {
        Ok(lease) => lease,
        Err(error) => {
            let rejected = error == "OpenVPN authentication failed";
            let outcome = attempt.complete(if rejected {
                ConnectOutcome::AuthenticationRejected
            } else {
                ConnectOutcome::Failed
            });
            if let Some(notice) = outcome.notice {
                ctx.note(notice.message());
            }
            return Err(error);
        }
    };
    if args.system_proxy {
        if let Err(error) = lease.set_system_proxy(true) {
            let cleanup = lease.disconnect();
            attempt.complete(ConnectOutcome::Failed);
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; activation cleanup failed: {cleanup}"),
            });
        }
    }
    if STOP.load(Ordering::SeqCst) {
        let cleanup = lease.disconnect();
        attempt.complete(ConnectOutcome::Failed);
        cleanup?;
        return Err("Connection startup cancelled".into());
    }
    if !args.foreground {
        lease.detach()?;
        let outcome = attempt.complete(ConnectOutcome::ConfirmedSuccess);
        if let Some(notice) = outcome.notice {
            ctx.note(notice.message());
        }
        return ctx.output(&json!({"id":p.id,"state":"running","foreground":false,"result":ConnectProfileOutcome::Connected{credentials:outcome}}));
    }
    let credential_outcome = attempt.complete(ConnectOutcome::ConfirmedSuccess);
    if let Some(notice) = credential_outcome.notice {
        ctx.note(notice.message());
    }
    ctx.emit(json!({"id":p.id,"state":"running","generation":lease.generation(),"foreground":true,"credentials":credential_outcome}),||format!("Connected \"{}\". Press Ctrl+C to disconnect this activation.",p.name));
    while !STOP.load(Ordering::SeqCst) && lease.is_running()? {
        std::thread::sleep(Duration::from_millis(250));
    }
    if STOP.load(Ordering::SeqCst) {
        lease.disconnect()?;
        Ok(())
    } else {
        Err("This activation stopped or was replaced".into())
    }
}
pub fn down(ctx: &Ctx, target: Option<&str>, all: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if crate::ctx::is_root() {
        let profile = target.map(|q| ctx.find(q)).transpose()?;
        if !all && profile.is_none() {
            return Err("Name a connection or use --all".into());
        }
        crate::inproc::stop(profile.as_ref().map(|p| p.id.as_str()))?;
        return ctx.output(&json!({"stopped":true}));
    }
    ctx.require_user()?;
    if all {
        return crate::business::batch(ctx, ctx.services()?.disconnect_all()?);
    }
    let p = ctx.find(target.ok_or("Name a connection or use --all")?)?;
    let engine = ctx.engine();
    if !engine.is_running(&p)? {
        return Err(format!("\"{}\" is not running", p.name));
    }
    engine.disconnect(&p, &ctx.profiles()?)?;
    ctx.output(&json!({"stopped":[p.id]}))
}
pub fn serve(ctx: &Ctx) -> Result<(), String> {
    ctx.require_user()?;
    install_signal_handlers();
    net_manager_engine::macos_session::serve(&ctx.root, &net_manager_engine::helper_socket())
}
#[cfg(not(target_os = "macos"))]
fn up_as_root(_: &Ctx, _: UpArgs) -> Result<(), String> {
    Err("The sudo in-process executor requires macOS".into())
}
#[cfg(target_os = "macos")]
fn up_as_root(ctx: &Ctx, args: UpArgs) -> Result<(), String> {
    use crate::inproc::{InProcess, RunControl};
    use net_manager_engine::Engine;
    use std::sync::Arc;
    if args.mode.is_some()
        || args.role.is_some()
        || args.networks.is_some()
        || args.dns_domains.is_some()
        || args.system_proxy
        || args.credentials.remember
    {
        return Err("Change settings and remembered credentials without sudo first".into());
    }
    let Input::Saved(q) = target::classify(&args.target, |p| p.is_file()) else {
        return Err("Import without sudo first (`netorch add ...`)".into());
    };
    let p = ctx.find(&q)?;
    if crate::route::runs_locally(&p) || p.backend == TunnelBackend::None {
        return Err("This connection runs as your user: run without sudo".into());
    }
    net_manager_engine::macos_state::ensure_start_allowed_for_user(
        &ctx.root,
        p.backend,
        net_manager_engine::macos_session::console_user_uid()?,
    )?;
    let inproc = Arc::new(InProcess::start(&net_manager_engine::helper_socket())?);
    let engine = Engine::with_privileged(&ctx.root, inproc.clone());
    if p.backend == TunnelBackend::Xray && engine.managed_executable().is_none() {
        return Err("Install Xray without sudo first (`netorch backend install`)".into());
    }
    let mut control = RunControl::new(&p.id)?;
    install_signal_handlers();
    if let Err(error) = engine.connect(&ctx.store(), &p, collect(ctx, &p, &args.credentials)?) {
        inproc.shutdown();
        return Err(error);
    }
    ctx.emit(
        json!({"id":p.id,"state":"running","foreground":true}),
        || {
            format!(
                "Connected \"{}\" in sudo foreground mode. Ctrl+C disconnects.",
                p.name
            )
        },
    );
    let mut requested = false;
    while !STOP.load(Ordering::SeqCst) && engine.is_running(&p)? {
        if control.stop_requested()? {
            requested = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let result = engine.disconnect(&p, &ctx.profiles()?);
    inproc.shutdown();
    control.complete();
    result?;
    if STOP.load(Ordering::SeqCst) || requested {
        Ok(())
    } else {
        Err("The connection stopped unexpectedly".into())
    }
}
