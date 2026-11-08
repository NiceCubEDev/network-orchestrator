//! Profile presentation over the shared typed macOS business services.
use crate::args::{AddArgs, TestArgs};
use crate::ctx::{self, Ctx};
use crate::render::{row_of, table};
use crate::target::{self, Input};
use net_manager_core::models::Profile;
use net_manager_engine::macos_services::{
    ConfigImport, ExitIpVia, ShareLinkImport, SubscriptionImportRequest,
};
use serde_json::{json, Value};

pub fn ls(ctx: &Ctx) -> Result<(), String> {
    let rows: Vec<_> = ctx
        .services()?
        .public_profiles()?
        .iter()
        .map(row_of)
        .collect();
    ctx.emit(
        serde_json::to_value(&rows).map_err(|_| "Could not encode the list")?,
        || {
            if rows.is_empty() {
                return "No profiles yet. `netorch add <link|url|file>` saves one.".into();
            }
            table(
                &["ID", "NAME", "KIND", "ROLE"],
                &rows
                    .iter()
                    .map(|r| vec![r.id.clone(), r.name.clone(), r.kind.into(), r.role.into()])
                    .collect::<Vec<_>>(),
            )
        },
    );
    Ok(())
}
pub fn add_input(
    ctx: &Ctx,
    input: &str,
    name: Option<&str>,
    hwid: Option<&str>,
) -> Result<Profile, String> {
    ctx.require_user()?;
    let suffix = ctx::random_suffix()?;
    let services = ctx.services()?;
    match target::classify(input,|path|path.is_file()) {
        Input::Saved(_)=>Err("That is not a vless:// / hysteria2:// link, an https:// subscription URL or an existing .conf / .ovpn file.".into()),
        Input::ShareLink(link)=>{
            let name=name.map(str::to_string).or_else(||target::link_name(&link)).unwrap_or_else(||"Imported".into());
            let id=target::make_id(&name,&suffix);
            services.import_share_link(ShareLinkImport{id:id.clone(),name,link})?;ctx.find(&id)
        }
        Input::Subscription(url)=>{
            let name=name.unwrap_or("Subscription").to_string();let id=target::make_id(&name,&suffix);
            let hwid=hwid.map(str::to_string).map(Ok).unwrap_or_else(||services.generate_subscription_hwid())?;
            let outcome=services.import_subscription(SubscriptionImportRequest{id:id.clone(),name,url,hwid})?;
            if outcome.skipped_count>0{ctx.note(&format!("{} entries were skipped (unsupported).",outcome.skipped_count));}ctx.find(&id)
        }
        Input::File{path,backend}=>{
            let name=name.map(str::to_string).unwrap_or_else(||path.file_stem().and_then(|s|s.to_str()).unwrap_or("Imported").to_string());
            let id=target::make_id(&name,&suffix);
            services.import_config(ConfigImport{id:id.clone(),name,backend,path})?;ctx.find(&id)
        }
    }
}
pub fn add(ctx: &Ctx, args: AddArgs) -> Result<(), String> {
    let profile = add_input(ctx, &args.input, args.name.as_deref(), args.hwid.as_deref())?;
    ctx.emit(
        serde_json::to_value(row_of(&profile)).map_err(|_| "Could not encode the profile")?,
        || format!("Saved \"{}\" ({})", profile.name, profile.id),
    );
    Ok(())
}
pub fn rm(ctx: &Ctx, target: &str) -> Result<(), String> {
    ctx.require_user()?;
    let p = ctx.find(target)?;
    if ctx.engine().is_running(&p)? {
        return Err("The connection is running. `netorch down` first.".into());
    }
    ctx.services()?.delete_profile(&p.id)?;
    ctx.emit(ctx::ok_json(), || format!("Removed \"{}\"", p.name));
    Ok(())
}
pub fn rename(ctx: &Ctx, target: &str, name: &str) -> Result<(), String> {
    ctx.require_user()?;
    let p = ctx.find(target)?;
    ctx.services()?.rename_profile(&p.id, name)?;
    ctx.emit(ctx::ok_json(), || format!("Renamed to \"{}\"", name.trim()));
    Ok(())
}
pub fn status(ctx: &Ctx, target: Option<&str>) -> Result<(), String> {
    let profiles = match target {
        Some(q) => vec![ctx.find(q)?],
        None => ctx.profiles()?,
    };
    let snapshot = ctx.engine().snapshot(&profiles)?;
    let states:Vec<_>=profiles.iter().map(|p|{
        let status=snapshot.statuses.iter().find(|s|s.profile_id==p.id);
        json!({"id":p.id,"name":p.name,"kind":crate::render::kind_of(p),
            "state":status.map(|s|s.state).unwrap_or(net_manager_core::models::TunnelState::Stopped),
            "interface":status.and_then(|s|s.interface_name.clone()),
            "message":status.and_then(|s|s.message.clone())})
    }).collect();
    ctx.emit(Value::Array(states.clone()), || {
        if states.is_empty() {
            return "No profiles yet.".into();
        }
        table(
            &["ID", "NAME", "STATE", "DETAIL"],
            &states
                .iter()
                .map(|s| {
                    vec![
                        s["id"].as_str().unwrap_or_default().into(),
                        s["name"].as_str().unwrap_or_default().into(),
                        s["state"].as_str().unwrap_or_default().into(),
                        s["interface"]
                            .as_str()
                            .or_else(|| s["message"].as_str())
                            .unwrap_or_default()
                            .into(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    });
    Ok(())
}
pub fn logs(ctx: &Ctx, target: &str) -> Result<(), String> {
    let p = ctx.find(target)?;
    let log = ctx.engine().log(&p)?;
    let log = net_manager_core::log_sanitize::sanitize_log_text(&log);
    ctx.emit(json!({"log":log}), || log.clone());
    Ok(())
}
pub fn test(ctx: &Ctx, args: TestArgs) -> Result<(), String> {
    let services = ctx.services()?;
    if let Some(target) = args.target.as_deref().filter(|_| !args.ip) {
        let p = ctx.find(target)?;
        let endpoints = services.subscription_endpoints(&p.id)?;
        let delays = match args.index {
            Some(i) => vec![services.measure_subscription_delay(&p.id, i)?],
            None => services.measure_subscription_delays(&p.id)?,
        };
        let endpoints =
            serde_json::to_value(&endpoints).map_err(|_| "Could not encode endpoints")?;
        let rows:Vec<_>=delays.into_iter().map(|d|json!({"index":d.index,"name":endpoints[d.index]["name"],"protocol":endpoints[d.index]["protocol"],"active":endpoints[d.index]["active"],"delayMs":d.delay_ms})).collect();
        return ctx.output(&rows);
    }
    if args.index.is_some() {
        return Err("--index requires a subscription target".into());
    }
    let via = match args.target {
        Some(q) => ExitIpVia::Profile(ctx.find(&q)?.id),
        None => ExitIpVia::Direct,
    };
    ctx.output(&services.check_exit_ip(via)?)
}
