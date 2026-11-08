//! Profile metadata and subscription input. Secret values are accepted only from
//! private input files (or `-` for stdin), never command-line arguments or output.
use super::commands::Output;
use super::ctx::Ctx;
use super::library::require_user;
use clap::Subcommand;
use net_manager_core::models::{Profile, TunnelBackend, TunnelRole, WireGuardFields};
use net_manager_core::subscription::{SubscriptionImport, MAX_SUBSCRIPTION_BODY_BYTES};
use net_manager_engine::linux_profiles::{self, ProfileService, ProfileSource};
use serde_json::{json, Value};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List saved settings without credentials or managed paths
    List,
    /// Show all saved settings, without credentials, sensitive URLs or config paths
    Show { profile: String },
    /// Create from JSON settings and an optional config/share-link/WireGuard source
    Create {
        /// Name, when not supplied by the JSON document
        profile: Option<String>,
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        #[arg(long, conflicts_with_all = ["share_link_file", "wireguard_file"])]
        source: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["source", "wireguard_file"])]
        share_link_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["source", "share_link_file"])]
        wireguard_file: Option<PathBuf>,
    },
    /// Apply a partial JSON object atomically; omitted settings remain unchanged
    Edit {
        profile: String,
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
    /// Delete an inactive profile and its managed configuration
    Delete { profile: String },
    /// Set primary or secondary connection role
    Role {
        profile: String,
        #[arg(value_parser = parse_role)]
        role: TunnelRole,
    },
    /// Set the connection's carried networks and split-DNS suffixes together
    Networks {
        profile: String,
        #[arg(long)]
        networks: String,
        #[arg(long, default_value = "")]
        dns_domains: String,
    },
    /// Save a structured profile with a private share-link input
    SaveLink {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        link_file: PathBuf,
    },
    /// Save a structured profile with private WireGuard fields
    SaveWireguard {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        fields_file: PathBuf,
    },
    /// Import multiple source configurations into the managed vault
    ImportConfigs {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long, value_parser = parse_backend)]
        backend: Option<TunnelBackend>,
    },
    /// Import one share link from private input
    ImportLink {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// Reorder every profile of one backend; other backend groups keep their positions
    Reorder {
        #[arg(value_parser = parse_backend)]
        backend: TunnelBackend,
        #[arg(required = true)]
        profiles: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct RefreshInterval(Option<u32>);

fn parse_interval(value: &str) -> Result<RefreshInterval, String> {
    match value {
        "off" => Ok(RefreshInterval(None)),
        "15" => Ok(RefreshInterval(Some(15))),
        "60" => Ok(RefreshInterval(Some(60))),
        "360" => Ok(RefreshInterval(Some(360))),
        _ => Err("Use off, 15, 60 or 360".into()),
    }
}

fn parse_backend(value: &str) -> Result<TunnelBackend, String> {
    match value {
        "none" | "static" => Ok(TunnelBackend::None),
        "wireguard" | "wireGuard" | "wg" => Ok(TunnelBackend::WireGuard),
        "openvpn" | "openVpn" => Ok(TunnelBackend::OpenVpn),
        "xray" => Ok(TunnelBackend::Xray),
        _ => Err("Use none, wireguard, openvpn or xray".into()),
    }
}

fn parse_role(value: &str) -> Result<TunnelRole, String> {
    match value {
        "primary" => Ok(TunnelRole::Primary),
        "secondary" => Ok(TunnelRole::Secondary),
        _ => Err("Use primary or secondary".into()),
    }
}

#[derive(Debug, Subcommand)]
pub enum SubscriptionCommand {
    /// Import with the original provider HWID. A cache file never contacts the provider.
    Import {
        #[arg(long, value_name = "FILE")]
        url_file: PathBuf,
        #[arg(long, value_name = "FILE")]
        hwid_file: PathBuf,
        #[arg(long, value_name = "FILE")]
        cache_file: Option<PathBuf>,
        #[arg(long)]
        name: String,
        #[arg(long = "interval", alias = "refresh-interval", default_value = "off", value_parser = parse_interval)]
        refresh_interval: RefreshInterval,
    },
    /// Refresh an inactive subscription using its original URL and HWID
    Refresh {
        profile: String,
        #[arg(long, value_name = "FILE")]
        cache_file: Option<PathBuf>,
    },
    /// Set automatic refresh to off, 15, 60 or 360 minutes
    #[command(alias = "refresh-interval", alias = "set-refresh-interval")]
    Interval {
        profile: String,
        #[arg(value_parser = parse_interval)]
        interval: RefreshInterval,
    },
    /// List endpoint identities and roles without exposing their share links
    Endpoints { profile: String },
    /// Measure one endpoint or the complete subscription
    Test {
        profile: String,
        server: Option<String>,
    },
    /// Change endpoint, reconnecting and restoring the old selection on failure
    Switch { profile: String, server: String },
}

fn service(ctx: &Ctx) -> ProfileService {
    ProfileService::new(ctx.root.clone(), ctx.engine.clone())
}
fn find(ctx: &Ctx, query: &str) -> Result<Profile, String> {
    ctx.find(query)
        .map_err(|_| "The requested profile could not be selected".into())
}
fn output(profile: &Profile) -> Result<Output, String> {
    let value = linux_profiles::metadata(profile);
    let text =
        serde_json::to_string_pretty(&value).map_err(|_| "Could not encode profile metadata")?;
    Ok((value, text))
}
fn saved(
    document: net_manager_core::profiles::ProfileDocument,
    id: &str,
) -> Result<Output, String> {
    let profile = document
        .profiles
        .iter()
        .find(|profile| profile.id == id)
        .ok_or("The saved profile could not be selected")?;
    output(profile)
}

fn current_revision(service: &ProfileService, id: &str) -> Result<Option<String>, String> {
    service
        .profiles()?
        .iter()
        .find(|profile| profile.id == id)
        .map(net_manager_core::profiles::profile_edit_revision)
        .transpose()
        .map_err(|_| "Could not read the profile revision".into())
}

pub fn run_profile(ctx: &Ctx, command: ProfileCommand) -> Result<Output, String> {
    let service = service(ctx);
    match command {
        ProfileCommand::List => {
            let value = Value::Array(
                service
                    .profiles()?
                    .iter()
                    .map(linux_profiles::metadata)
                    .collect(),
            );
            let text = serde_json::to_string_pretty(&value)
                .map_err(|_| "Could not encode profile metadata")?;
            Ok((value, text))
        }
        ProfileCommand::Role { profile, role } => {
            require_user(ctx)?;
            let profile = find(ctx, &profile)?;
            saved(service.set_role(&profile.id, role)?, &profile.id)
        }
        ProfileCommand::Networks {
            profile,
            networks,
            dns_domains,
        } => {
            require_user(ctx)?;
            let profile = find(ctx, &profile)?;
            saved(
                service.set_networks(&profile.id, &networks, &dns_domains)?,
                &profile.id,
            )
        }
        ProfileCommand::SaveLink { file, link_file } => {
            require_user(ctx)?;
            reject_multiple_stdin(&[&file, &link_file])?;
            let mut profile = profile_input(&file)?;
            profile.backend = TunnelBackend::Xray;
            let link = read_input(&link_file, MAX_SUBSCRIPTION_BODY_BYTES)?;
            let id = profile.id.clone();
            let revision = current_revision(&service, &id)?;
            saved(
                service.save_form(
                    profile,
                    Some(ProfileSource::ShareLink(link)),
                    revision.as_deref(),
                )?,
                &id,
            )
        }
        ProfileCommand::SaveWireguard { file, fields_file } => {
            require_user(ctx)?;
            reject_multiple_stdin(&[&file, &fields_file])?;
            let mut profile = profile_input(&file)?;
            profile.backend = TunnelBackend::WireGuard;
            let fields = serde_json::from_value(json_input(&fields_file)?)
                .map_err(|_| "Invalid structured WireGuard settings")?;
            let id = profile.id.clone();
            let revision = current_revision(&service, &id)?;
            saved(
                service.save_form(
                    profile,
                    Some(ProfileSource::WireGuard(fields)),
                    revision.as_deref(),
                )?,
                &id,
            )
        }
        ProfileCommand::ImportConfigs { paths, backend } => {
            require_user(ctx)?;
            let paths = paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            let result = service.import_configs(&paths, backend)?;
            let value = json!({"profiles": result.profiles.iter().map(linux_profiles::metadata).collect::<Vec<_>>(),
                "skipped": result.errors.len()});
            let text = format!(
                "Imported configuration batch; {} skipped",
                result.errors.len()
            );
            Ok((value, text))
        }
        ProfileCommand::ImportLink { file, name } => {
            require_user(ctx)?;
            let link = read_input(&file, MAX_SUBSCRIPTION_BODY_BYTES)?;
            let id = linux_profiles::new_id()?;
            saved(
                service.import_link(
                    &id,
                    name.as_deref().unwrap_or("Imported profile"),
                    link.trim(),
                )?,
                &id,
            )
        }
        ProfileCommand::Show { profile } => output(&find(ctx, &profile)?),
        ProfileCommand::Edit { profile, file } => {
            require_user(ctx)?;
            let profile = find(ctx, &profile)?;
            let patch = json_input(&file)?;
            saved(service.patch(&profile.id, &patch)?, &profile.id)
        }
        ProfileCommand::Create {
            profile,
            file,
            source,
            share_link_file,
            wireguard_file,
        } => {
            require_user(ctx)?;
            let mut inputs: Vec<&Path> = vec![&file];
            inputs.extend(share_link_file.as_deref());
            inputs.extend(wireguard_file.as_deref());
            reject_multiple_stdin(&inputs)?;
            let mut settings = json_input(&file)?;
            let object = settings
                .as_object_mut()
                .ok_or("Profile settings must be a JSON object")?;
            let embedded_link = object
                .remove("shareLink")
                .or_else(|| object.remove("vlessUrl"));
            let embedded_wireguard = object
                .remove("wireguard")
                .or_else(|| object.remove("wireGuard"));
            let mut defaults = serde_json::to_value(Profile::default())
                .map_err(|_| "Could not prepare settings")?;
            defaults
                .as_object_mut()
                .expect("profile is an object")
                .extend(std::mem::take(object));
            let mut created: Profile =
                serde_json::from_value(defaults).map_err(|_| "Invalid profile settings")?;
            if created.name.trim().is_empty() {
                created.name = profile.ok_or("Supply a profile name in JSON or as an argument")?;
            }
            if created.id.is_empty() {
                created.id = linux_profiles::new_id()?;
            }
            let mut sources = Vec::new();
            if let Some(path) = source {
                sources.push(ProfileSource::Config(path));
            }
            if let Some(path) = share_link_file {
                sources.push(ProfileSource::ShareLink(read_input(
                    &path,
                    MAX_SUBSCRIPTION_BODY_BYTES,
                )?));
            }
            if let Some(path) = wireguard_file {
                let fields: WireGuardFields = serde_json::from_value(json_input(&path)?)
                    .map_err(|_| "Invalid structured WireGuard settings")?;
                sources.push(ProfileSource::WireGuard(fields));
            }
            if let Some(value) = embedded_link {
                sources.push(ProfileSource::ShareLink(
                    value
                        .as_str()
                        .ok_or("Invalid share-link input")?
                        .to_string(),
                ));
            }
            if let Some(value) = embedded_wireguard {
                sources.push(ProfileSource::WireGuard(
                    serde_json::from_value(value)
                        .map_err(|_| "Invalid structured WireGuard settings")?,
                ));
            }
            if sources.len() > 1 {
                return Err("Choose exactly one profile source".into());
            }
            let source = sources.pop();
            match source.as_ref() {
                Some(ProfileSource::ShareLink(_)) => created.backend = TunnelBackend::Xray,
                Some(ProfileSource::WireGuard(_)) => created.backend = TunnelBackend::WireGuard,
                _ => {}
            }
            let id = created.id.clone();
            saved(service.create(created, source)?, &id)
        }
        ProfileCommand::Delete { profile } => {
            require_user(ctx)?;
            let profile = find(ctx, &profile)?;
            service.delete(&profile.id)?;
            Ok((
                json!({"removed": profile.id}),
                format!("Removed {}", profile.name),
            ))
        }
        ProfileCommand::Reorder { backend, profiles } => {
            require_user(ctx)?;
            let ids = profiles
                .iter()
                .map(|query| find(ctx, query).map(|profile| profile.id))
                .collect::<Result<Vec<_>, _>>()?;
            let document = service.reorder(backend, &ids)?;
            let value = Value::Array(
                document
                    .profiles
                    .iter()
                    .map(linux_profiles::metadata)
                    .collect(),
            );
            Ok((value, "Profile order saved".into()))
        }
    }
}

pub fn run_subscription(ctx: &Ctx, command: SubscriptionCommand) -> Result<Output, String> {
    require_user(ctx)?;
    let service = service(ctx);
    match command {
        SubscriptionCommand::Import {
            url_file,
            hwid_file,
            cache_file,
            name,
            refresh_interval,
        } => {
            let stdin_count = [&url_file, &hwid_file]
                .into_iter()
                .chain(cache_file.as_ref())
                .filter(|path| path.as_os_str() == "-")
                .count();
            if stdin_count > 1 {
                return Err(
                    "Only one input may read stdin; use private files for the others".into(),
                );
            }
            let url = read_input(&url_file, 16 * 1024)?;
            let hwid = read_input(&hwid_file, 16 * 1024)?;
            let url = url.trim();
            let hwid = hwid.trim();
            if url.is_empty() || hwid.is_empty() || hwid.contains(['\r', '\n']) {
                return Err("Supply a subscription URL and original single-line HWID".into());
            }
            let cached = cache_file
                .as_ref()
                .map(|path| read_input(path, MAX_SUBSCRIPTION_BODY_BYTES))
                .transpose()?;
            let id = linux_profiles::new_id()?;
            let request = SubscriptionImport {
                id: &id,
                url,
                hwid,
                name: &name,
                refresh_interval_minutes: refresh_interval.0,
            };
            let result =
                runtime()?.block_on(service.import_subscription(&request, cached.as_deref()))?;
            let profile = result
                .profiles
                .iter()
                .find(|profile| profile.id == id)
                .ok_or("The imported profile could not be selected")?;
            // Core import diagnostics contain only generated entry numbers and fixed
            // messages. Do not output provider names, unsupported schemes or sources.
            let diagnostics: Vec<_> = result.errors.iter().enumerate().map(|(index, _)| {
                json!({"entry": index + 1, "message": "Invalid or unsupported subscription entries skipped"})
            }).collect();
            let value =
                json!({"profile": linux_profiles::metadata(profile), "diagnostics": diagnostics});
            let text = format!(
                "Saved {} ({})\n{} skip diagnostic(s)",
                profile.name,
                profile.id,
                diagnostics.len()
            );
            Ok((value, text))
        }
        SubscriptionCommand::Interval { profile, interval } => {
            let profile = find(ctx, &profile)?;
            saved(
                service.set_refresh_interval(&profile.id, interval.0)?,
                &profile.id,
            )
        }
        SubscriptionCommand::Refresh {
            profile,
            cache_file,
        } => {
            let profile = find(ctx, &profile)?;
            let cached = cache_file
                .as_ref()
                .map(|path| read_input(path, MAX_SUBSCRIPTION_BODY_BYTES))
                .transpose()?;
            let result = runtime()?
                .block_on(service.refresh_subscription(&profile.id, cached.as_deref()))?;
            let text = format!(
                "Refreshed {} endpoint(s); {} skipped",
                result.endpoint_count, result.skipped_count
            );
            Ok((
                serde_json::to_value(result).map_err(|_| "Could not encode refresh result")?,
                text,
            ))
        }
        SubscriptionCommand::Endpoints { profile } => {
            let profile = find(ctx, &profile)?;
            let infos = service.subscription_endpoints(&profile.id)?;
            let value = serde_json::to_value(infos)
                .map_err(|_| "Could not encode subscription metadata")?;
            let text = serde_json::to_string_pretty(&value)
                .map_err(|_| "Could not encode subscription metadata")?;
            Ok((value, text))
        }
        SubscriptionCommand::Test { profile, server } => {
            let profile = find(ctx, &profile)?;
            let infos = service.subscription_endpoints(&profile.id)?;
            let indices = if let Some(query) = server {
                vec![endpoint_index(&infos, &query)?]
            } else {
                infos
                    .iter()
                    .enumerate()
                    .filter(|(_, info)| !info.is_missing)
                    .map(|(index, _)| index)
                    .collect()
            };
            let results =
                runtime()?.block_on(service.measure_endpoint_delays(&profile.id, &indices))?;
            let value = json!(results
                .into_iter()
                .map(|(index, result)| json!({
                    "number": index + 1, "key": infos[index].key,
                    "delayMs": result.delay_ms, "error": result.error,
                }))
                .collect::<Vec<_>>());
            let text = serde_json::to_string_pretty(&value)
                .map_err(|_| "Could not encode delay results")?;
            Ok((value, text))
        }
        SubscriptionCommand::Switch { profile, server } => {
            let profile = find(ctx, &profile)?;
            let infos = service.subscription_endpoints(&profile.id)?;
            let index = endpoint_index(&infos, &server)?;
            let outcome = super::auth::run(ctx.root_user, || {
                service.switch_endpoint_live(&profile.id, &infos[index].key, ctx)
            })?;
            Ok((
                json!({"id": outcome.profile.id, "key": infos[index].key, "connected": outcome.was_running}),
                "Subscription endpoint selected".into(),
            ))
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Could not start the subscription runtime".into())
}
fn json_input(path: &Path) -> Result<Value, String> {
    let input = read_input(path, MAX_SUBSCRIPTION_BODY_BYTES)?;
    serde_json::from_str(&input).map_err(|_| "The input is not valid JSON".into())
}

fn profile_input(path: &Path) -> Result<Profile, String> {
    let mut input = json_input(path)?;
    let object = input
        .as_object_mut()
        .ok_or("Profile settings must be a JSON object")?;
    let mut defaults =
        serde_json::to_value(Profile::default()).map_err(|_| "Could not prepare settings")?;
    defaults
        .as_object_mut()
        .expect("profile is an object")
        .extend(std::mem::take(object));
    let mut profile: Profile =
        serde_json::from_value(defaults).map_err(|_| "Invalid profile settings")?;
    if profile.id.is_empty() {
        profile.id = linux_profiles::new_id()?;
    }
    Ok(profile)
}

fn reject_multiple_stdin(paths: &[&Path]) -> Result<(), String> {
    if paths.iter().filter(|path| path.as_os_str() == "-").count() > 1 {
        Err("Only one input may read stdin; use private files for the others".into())
    } else {
        Ok(())
    }
}

fn endpoint_index(
    infos: &[net_manager_core::models::SubscriptionEndpointInfo],
    query: &str,
) -> Result<usize, String> {
    let query = query.trim();
    if query.is_empty() {
        return Err("Choose an endpoint by number, name or key".into());
    }
    let key_match = infos
        .iter()
        .position(|info| !info.is_missing && info.key == query);
    if let Some(index) = key_match {
        return Ok(index);
    }
    if let Ok(number) = query.parse::<usize>() {
        return number
            .checked_sub(1)
            .filter(|index| infos.get(*index).is_some_and(|info| !info.is_missing))
            .ok_or_else(|| "The endpoint number is not available".into());
    }
    let query = query.to_lowercase();
    let mut exact = infos
        .iter()
        .enumerate()
        .filter(|(_, info)| !info.is_missing && info.name.to_lowercase() == query);
    let selected = exact.next().map(|(index, _)| index);
    if exact.next().is_some() {
        return Err("The endpoint name is ambiguous; use its number or key".into());
    }
    if let Some(index) = selected {
        return Ok(index);
    }
    let mut matches = infos.iter().enumerate().filter(|(_, info)| {
        !info.is_missing
            && (info.name.to_lowercase().contains(&query) || info.key.starts_with(&query))
    });
    let index = matches
        .next()
        .map(|(index, _)| index)
        .ok_or("The endpoint selection is not available")?;
    if matches.next().is_some() {
        return Err("The endpoint selection is ambiguous; use its number or key".into());
    }
    Ok(index)
}

fn read_input(path: &Path, max: usize) -> Result<String, String> {
    let error =
        || "Input must be a private regular file owned by your user, or '-' for stdin".to_string();
    let mut bytes = Vec::new();
    if path.as_os_str() == "-" {
        std::io::stdin()
            .lock()
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error())?;
    } else {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| error())?;
        let metadata = file.metadata().map_err(|_| error())?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > max as u64
        {
            return Err(error());
        }
        file.take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error())?;
    }
    if bytes.len() > max {
        return Err("The input exceeds the size limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "Input must be UTF-8".into())
}
