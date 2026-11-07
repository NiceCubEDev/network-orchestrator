//! Saved profile and subscription orchestration shared by the Linux GUI and CLI.
//! Input/configuration errors deliberately omit source text, paths and provider credentials.
use crate::linux_engine::LinuxEngine;
use net_manager_core::config_vault::{ConfigImport, ConfigVault};
use net_manager_core::models::*;
use net_manager_core::profiles::{self, ProfileDocument, ProfileStore};
use net_manager_core::{config_security, profile_import, subscription};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub enum ProfileSource {
    Config(PathBuf),
    ShareLink(String),
    WireGuard(WireGuardFields),
}

#[derive(Clone)]
pub struct ProfileService {
    root: PathBuf,
    engine: LinuxEngine,
}

fn failed(_: impl std::fmt::Display) -> String {
    "The profile operation could not be completed; check the input and file permissions".into()
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn available(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl ProfileService {
    pub fn new(root: PathBuf, engine: LinuxEngine) -> Self {
        Self {
            engine: engine.with_data_root(root.clone()),
            root,
        }
    }

    pub fn store(&self) -> ProfileStore {
        ProfileStore::new(self.root.join("profiles.json"))
    }
    pub fn vault(&self) -> ConfigVault {
        ConfigVault::new(self.root.join("configs"))
    }
    pub fn profiles(&self) -> Result<Vec<Profile>, String> {
        self.store().load().map(|doc| doc.profiles).map_err(failed)
    }
    pub fn profile(&self, id: &str) -> Result<Profile, String> {
        self.profiles()?
            .into_iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "The requested profile could not be selected".into())
    }

    // The store has its own atomic transaction lock. This second, cross-process
    // lock also covers vault revisions and endpoint files, shared by both frontends.
    fn mutation(&self) -> Result<File, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run profile changes as your own user, without sudo".into());
        }
        fs::create_dir_all(&self.root).map_err(failed)?;
        config_security::protect_path(&self.root).map_err(failed)?;
        let path = self.root.join("profile-operations.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(failed)?;
        config_security::protect_path(&path).map_err(failed)?;
        file.lock().map_err(failed)?;
        Ok(file)
    }

    pub fn ensure_editable(&self, profile: &Profile) -> Result<(), String> {
        if self
            .engine
            .status(profile)
            .map_err(|_| "Could not check the connection state".to_string())?
            .state
            != TunnelState::Stopped
        {
            return Err(
                "The profile is active; disconnect it before editing or deleting it".into(),
            );
        }
        crate::linux_services::ensure_not_enrolled(&self.engine, profile)?;
        Ok(())
    }

    pub fn patch(&self, id: &str, patch: &Value) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let expected = self.profile(id)?;
        self.ensure_editable(&expected)?;
        self.store()
            .update_profile(id, |stored| {
                if stored != &expected {
                    return Err(invalid("Profile changed; retry the edit"));
                }
                let merged = merge_profile(stored, patch)?;
                validate(&merged)?;
                *stored = merged;
                Ok(())
            })
            .map_err(failed)
    }

    /// GUI forms own only their existing editable fields. Canonical subscription
    /// state and dedicated endpoint/check/exit settings remain store-owned.
    pub fn save_form(
        &self,
        mut profile: Profile,
        source: Option<ProfileSource>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let stored = self.profiles()?.into_iter().find(|p| p.id == profile.id);
        if let Some(existing) = &stored {
            self.ensure_editable(existing)?;
            preserve_form_settings(&mut profile, existing, source.is_none());
        } else {
            profile.subscription = None;
            profile.pinned_policies.clear();
            profile.xray_service_checks.clear();
            profile.xray_proxy_exits.clear();
        }
        self.save_locked(profile, source, stored.as_ref())
    }

    pub fn create(
        &self,
        mut profile: Profile,
        source: Option<ProfileSource>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        if profile.id.is_empty() {
            profile.id = new_id()?;
        }
        if self.profiles()?.iter().any(|p| p.id == profile.id) {
            return Err("A profile with that identifier already exists".into());
        }
        if profile.subscription.is_some()
            || !profile.pinned_policies.is_empty()
            || !profile.xray_service_checks.is_empty()
            || !profile.xray_proxy_exits.is_empty()
        {
            return Err("Use subscription, routing, checks and proxy commands for canonical endpoint settings".into());
        }
        self.save_locked(profile, source, None)
    }

    fn save_locked(
        &self,
        mut profile: Profile,
        source: Option<ProfileSource>,
        stored: Option<&Profile>,
    ) -> Result<ProfileDocument, String> {
        net_manager_core::config_vault::sanitize_profile_id(&profile.id).map_err(failed)?;
        let vault = self.vault();
        let source = source.or_else(|| {
            (profile.backend != TunnelBackend::None && !vault.is_managed_path(&profile.config_path))
                .then(|| ProfileSource::Config(profile.config_path.clone()))
        });
        // Validate everything before writing a new revision. A temporary extension
        // permits structured builders whose config path has not been assigned yet.
        let mut validation = profile.clone();
        if source.is_some() {
            validation.config_path = match profile.backend {
                TunnelBackend::WireGuard => "source.conf".into(),
                TunnelBackend::OpenVpn => "source.ovpn".into(),
                TunnelBackend::Xray => "source.json".into(),
                TunnelBackend::None => PathBuf::new(),
            };
        }
        if matches!(&source, Some(ProfileSource::ShareLink(_))) {
            validation.xray_socks_port = Some(10808);
            validation.xray_http_port = Some(10809);
        }
        validate(&validation).map_err(failed)?;
        if source.is_none()
            && profile.backend != TunnelBackend::None
            && (!vault.is_managed_profile_path(&profile.id, &profile.config_path)
                || stored.is_none_or(|p| {
                    p.config_path != profile.config_path || p.backend != profile.backend
                }))
        {
            return Err(
                "Select an existing profile's current managed revision or import a source".into(),
            );
        }
        let imported: Option<ConfigImport> = match source {
            Some(ProfileSource::Config(path)) => {
                if vault.is_managed_path(&path) {
                    return Err(
                        "A managed revision cannot be imported as another profile's source".into(),
                    );
                }
                Some(
                    vault
                        .import(&profile.id, profile.backend, &path)
                        .map_err(failed)?,
                )
            }
            Some(ProfileSource::ShareLink(link)) => {
                if profile.backend != TunnelBackend::Xray {
                    return Err("Share-link fields require an Xray profile".into());
                }
                let all = self.profiles()?;
                let used = profile_import::profile_listener_ports(&all, &profile.id);
                let (socks, http) = profile_import::select_generated_ports(
                    profile.xray_socks_port,
                    profile.xray_http_port,
                    &used,
                    available,
                )
                .map_err(failed)?;
                let config = net_manager_core::xray::generate_share_link_config_with_http(
                    link.trim(),
                    socks,
                    http,
                )
                .map_err(failed)?;
                let body = serde_json::to_vec_pretty(&config).map_err(failed)?;
                profile.xray_socks_port = Some(socks);
                profile.xray_http_port = Some(http);
                Some(
                    vault
                        .store_generated_xray(&profile.id, &body)
                        .map_err(failed)?,
                )
            }
            Some(ProfileSource::WireGuard(fields)) => {
                if profile.backend != TunnelBackend::WireGuard {
                    return Err("WireGuard fields require a WireGuard profile".into());
                }
                let body = render_wireguard_config(&fields)?;
                Some(
                    vault
                        .store_wireguard_config(&profile.id, body.as_bytes())
                        .map_err(failed)?,
                )
            }
            None => None,
        };
        if let Some(imported) = &imported {
            profile.config_path = imported.config_path.clone();
        }
        let new_path = profile.config_path.clone();
        let result = match stored {
            Some(expected) => self.store().update_profile(&profile.id.clone(), |current| {
                if current != expected {
                    return Err(invalid("Profile changed; retry the edit"));
                }
                validate(&profile)?;
                *current = profile;
                Ok(())
            }),
            None => validate(&profile).and_then(|()| self.store().upsert(profile)),
        };
        let document = match result {
            Ok(document) => document,
            Err(error) => {
                if imported.is_some() {
                    let _ = vault.remove_revision_for_config(&new_path);
                }
                return Err(failed(error));
            }
        };
        if let Some(old) = stored {
            if old.config_path != new_path
                && vault.is_managed_profile_path(&old.id, &old.config_path)
            {
                vault
                    .remove_revision_for_config(&old.config_path)
                    .map_err(|_| {
                        "Profile saved, but the old managed revision could not be removed"
                            .to_string()
                    })?;
            }
        }
        Ok(document)
    }

    pub fn delete(&self, id: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let profile = self.profile(id)?;
        self.ensure_editable(&profile)?;
        let document = self.store().delete(id).map_err(failed)?;
        self.vault().remove_profile(id).map_err(|_| {
            "Profile deleted, but its managed configuration could not be removed".to_string()
        })?;
        if profile.backend == TunnelBackend::OpenVpn {
            crate::linux_credentials::OpenVpnCredentialStore::new(Box::new(
                crate::linux_credentials::SecretServiceStore,
            ))
            .forget(id, None)?;
        }
        Ok(document)
    }

    pub fn reorder(
        &self,
        backend: TunnelBackend,
        ids: &[String],
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.store().reorder(backend, ids).map_err(failed)
    }

    pub async fn import_subscription(
        &self,
        request: &subscription::SubscriptionImport<'_>,
        cached: Option<&str>,
    ) -> Result<BatchImportResult, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run subscription changes as your own user, without sudo".into());
        }
        validate_interval(request.refresh_interval_minutes)?;
        let fetched;
        let (body, meta) = if let Some(body) = cached {
            (body, subscription::response_meta(&[], body))
        } else {
            let client = subscription::http_client().map_err(failed)?;
            fetched = subscription::fetch(&client, request.url, request.hwid)
                .await
                .map_err(failed)?;
            (fetched.body.as_str(), fetched.meta.clone())
        };
        let _lock = self.mutation()?;
        subscription::import_body(&self.vault(), &self.store(), request, body, meta, available)
            .map_err(failed)
    }

    pub fn import_subscription_body(
        &self,
        request: &subscription::SubscriptionImport<'_>,
        body: &str,
        meta: subscription::ResponseMeta,
    ) -> Result<BatchImportResult, String> {
        let _lock = self.mutation()?;
        validate_interval(request.refresh_interval_minutes)?;
        subscription::import_body(&self.vault(), &self.store(), request, body, meta, available)
            .map_err(failed)
    }

    pub async fn refresh_subscription(
        &self,
        id: &str,
        cached: Option<&str>,
    ) -> Result<SubscriptionRefreshResult, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run subscription changes as your own user, without sudo".into());
        }
        let expected = self.subscription_profile(id)?;
        let meta = expected
            .subscription
            .as_ref()
            .expect("subscription checked");
        self.ensure_editable(&expected)?;
        let refreshed = async {
            let fetched;
            let (body, response_meta) = if let Some(body) = cached {
                (body, subscription::response_meta(&[], body))
            } else {
                let client = subscription::http_client().map_err(failed)?;
                fetched = subscription::fetch(&client, &meta.url, &meta.hwid)
                    .await
                    .map_err(failed)?;
                (fetched.body.as_str(), fetched.meta.clone())
            };
            let _lock = self.mutation()?;
            if self.profile(id)? != expected {
                return Err("The subscription changed during refresh; retry".into());
            }
            self.ensure_editable(&expected)?;
            subscription::refresh_body(
                &self.vault(),
                &self.store(),
                id,
                body,
                response_meta,
                available,
            )
            .map_err(failed)
        }
        .await;
        let outcome = match refreshed {
            Ok(outcome) => outcome,
            Err(error) => {
                self.store()
                    .update_profile(id, |current| {
                        if current.subscription != expected.subscription {
                            return Err(invalid("Subscription changed during refresh"));
                        }
                        let meta = current
                            .subscription
                            .as_mut()
                            .ok_or_else(|| invalid("Profile is no longer a subscription"))?;
                        meta.last_refresh_at_unix = Some(now());
                        meta.last_refresh_error = Some("Subscription refresh failed".into());
                        Ok(())
                    })
                    .map_err(|_| {
                        "Subscription refresh failed, and its failure notice could not be saved"
                            .to_string()
                    })?;
                return Err(error);
            }
        };
        let refreshed = self.subscription_profile(id)?;
        let pool_report = match self.rebuild_node_pool(id).await {
            Ok(report) => report,
            Err(_) => {
                let recorded = self.store().update_profile(id, |current| {
                    if current.subscription != refreshed.subscription {
                        return Err(invalid("Subscription changed after refresh"));
                    }
                    let meta = current
                        .subscription
                        .as_mut()
                        .ok_or_else(|| invalid("Profile is no longer a subscription"))?;
                    meta.last_refresh_error = Some(
                        "Subscription refreshed, but the backup pool could not be rebuilt".into(),
                    );
                    Ok(())
                });
                return Err(if recorded.is_ok() {
                    "Subscription refreshed, but backup-pool rebuild failed; the previously stored pool was not replaced"
                } else {
                    "Subscription refreshed, but backup-pool rebuild failed; its failure notice could not be saved"
                }.into());
            }
        };
        Ok(SubscriptionRefreshResult {
            endpoint_count: outcome.endpoint_count,
            active_index: outcome.active_index,
            skipped_count: outcome.skipped_count,
            fallback_used: outcome.fallback_used,
            cleanup_failed: outcome.cleanup_failed,
            pool_report,
        })
    }

    pub fn set_refresh_interval(
        &self,
        id: &str,
        minutes: Option<u32>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        validate_interval(minutes)?;
        self.store()
            .update_profile(id, |profile| {
                if profile.backend != TunnelBackend::Xray {
                    return Err(invalid("Profile is not a subscription"));
                }
                let meta = profile
                    .subscription
                    .as_mut()
                    .ok_or_else(|| invalid("Profile is not a subscription"))?;
                meta.refresh_interval_minutes = minutes;
                meta.last_refresh_at_unix = Some(now());
                Ok(())
            })
            .map_err(failed)
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 128 || name.contains(['\r', '\n']) {
            return Err("The name must be 1-128 characters on one line".into());
        }
        self.store()
            .update_profile(id, |profile| {
                profile.name = name.into();
                Ok(())
            })
            .map_err(failed)
    }

    fn update_xray(
        &self,
        id: &str,
        update: impl FnOnce(&mut Profile),
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.store()
            .update_profile(id, |profile| {
                if profile.backend != TunnelBackend::Xray {
                    return Err(invalid("This setting requires an Xray profile"));
                }
                update(profile);
                validate(profile)
            })
            .map_err(failed)
    }

    pub fn set_routing(
        &self,
        id: &str,
        policies: Vec<DomainPolicy>,
        private_lan_direct: bool,
    ) -> Result<ProfileDocument, String> {
        self.update_xray(id, |profile| {
            profile.domain_policies = policies;
            profile.private_lan_direct = private_lan_direct;
        })
    }

    pub fn set_quic(&self, id: &str, enabled: bool) -> Result<ProfileDocument, String> {
        self.update_xray(id, |profile| profile.xray_quic_reject = enabled)
    }

    pub fn set_proxy_exits(
        &self,
        id: &str,
        exits: Vec<NamedProxyExit>,
    ) -> Result<ProfileDocument, String> {
        self.update_xray(id, |profile| profile.xray_proxy_exits = exits)
    }

    pub fn upsert_proxy_exit(
        &self,
        id: &str,
        exit: NamedProxyExit,
    ) -> Result<ProfileDocument, String> {
        self.update_xray(id, |profile| {
            match profile
                .xray_proxy_exits
                .iter_mut()
                .find(|saved| saved.name == exit.name)
            {
                Some(saved) => *saved = exit,
                None => profile.xray_proxy_exits.push(exit),
            }
        })
    }

    pub fn remove_proxy_exit(&self, id: &str, name: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.store()
            .update_profile(id, |profile| {
                if profile.backend != TunnelBackend::Xray {
                    return Err(invalid("Named exits require an Xray profile"));
                }
                let before = profile.xray_proxy_exits.len();
                profile.xray_proxy_exits.retain(|exit| exit.name != name);
                if profile.xray_proxy_exits.len() == before {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "The named exit was not found",
                    ));
                }
                validate(profile)
            })
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    "The named exit was not found".into()
                } else {
                    failed(error)
                }
            })
    }

    pub fn set_role(&self, id: &str, role: TunnelRole) -> Result<ProfileDocument, String> {
        if self.profile(id)?.backend == TunnelBackend::None {
            return Err("Static routes do not create a tunnel".into());
        }
        self.patch(id, &json!({"tunnelRole": role}))
    }

    pub fn set_networks(
        &self,
        id: &str,
        networks: &str,
        dns_domains: &str,
    ) -> Result<ProfileDocument, String> {
        if self.profile(id)?.backend == TunnelBackend::None {
            return Err("Static routes do not create a tunnel".into());
        }
        let networks =
            parse_networks(networks).map_err(|_| "Invalid connection networks".to_string())?;
        let domains =
            parse_dns_domains(dns_domains).map_err(|_| "Invalid split-DNS domains".to_string())?;
        self.patch(
            id,
            &json!({"tunnelNetworks": networks, "tunnelDnsDomains": domains}),
        )
    }

    pub fn import_configs(
        &self,
        paths: &[String],
        backend: Option<TunnelBackend>,
    ) -> Result<BatchImportResult, String> {
        let _lock = self.mutation()?;
        profile_import::import_configs_into(&self.vault(), &self.store(), paths, backend)
            .map(|mut result| {
                for (index, error) in result.errors.iter_mut().enumerate() {
                    error.path = format!("Input {}", index + 1);
                    error.error = "The configuration could not be imported".into();
                }
                result
            })
            .map_err(failed)
    }

    pub fn import_link(&self, id: &str, name: &str, link: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        profile_import::import_share_link(&self.vault(), &self.store(), id, name, link, available)
            .map_err(failed)
    }

    pub fn subscription_profile(&self, id: &str) -> Result<Profile, String> {
        let profile = self.profile(id)?;
        if profile.backend != TunnelBackend::Xray || profile.subscription.is_none() {
            return Err("The profile is not an Xray subscription".into());
        }
        Ok(profile)
    }

    pub fn subscription_endpoints(
        &self,
        id: &str,
    ) -> Result<Vec<SubscriptionEndpointInfo>, String> {
        subscription::list_endpoints(&self.vault(), &self.store(), id).map_err(failed)
    }

    fn endpoints(
        &self,
        profile: &Profile,
    ) -> Result<Vec<net_manager_core::config_vault::SubscriptionEndpoint>, String> {
        if profile.subscription.is_none() {
            return Ok(Vec::new());
        }
        self.vault()
            .read_subscription_endpoints(&profile.id)
            .map_err(failed)
    }

    pub fn xray_executable(&self) -> Result<PathBuf, String> {
        crate::linux_system::backend_executable(&self.root, TunnelBackend::Xray)
    }

    pub async fn measure_endpoint_delay(
        &self,
        id: &str,
        index: usize,
    ) -> Result<SubscriptionDelayResult, String> {
        let expected = self.subscription_profile(id)?;
        let endpoints = self.endpoints(&expected)?;
        let endpoint = endpoints
            .get(index)
            .ok_or("The endpoint index is out of range")?;
        let result = subscription::measure_endpoint_delay(
            &self.xray_executable()?,
            &endpoint.url,
            subscription::DELAY_PROBE_TIMEOUT,
        )
        .await;
        if self.profile(id)? != expected || self.endpoints(&expected)? != endpoints {
            return Err("The profile or endpoint selection changed; repeat the probe".into());
        }
        Ok(match result {
            Ok(delay_ms) => SubscriptionDelayResult {
                delay_ms: Some(delay_ms),
                error: None,
            },
            Err(_) => SubscriptionDelayResult {
                delay_ms: None,
                error: Some("Endpoint delay probe failed".into()),
            },
        })
    }

    pub async fn measure_endpoint_delays(
        &self,
        id: &str,
        indices: &[usize],
    ) -> Result<Vec<(usize, SubscriptionDelayResult)>, String> {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
        let mut tasks = tokio::task::JoinSet::new();
        for (order, &index) in indices.iter().enumerate() {
            let gate = gate.clone();
            let service = self.clone();
            let id = id.to_string();
            tasks.spawn(async move {
                let _permit = gate
                    .acquire_owned()
                    .await
                    .map_err(|_| "Endpoint probes were cancelled".to_string())?;
                let result = service.measure_endpoint_delay(&id, index).await?;
                Ok::<_, String>((order, index, result))
            });
        }
        let mut results = Vec::with_capacity(indices.len());
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(result)) => results.push(result),
                _ => {
                    tasks.abort_all();
                    return Err("Endpoint probes could not be completed".into());
                }
            }
        }
        results.sort_by_key(|(order, _, _)| *order);
        Ok(results
            .into_iter()
            .map(|(_, index, result)| (index, result))
            .collect())
    }

    pub fn switch_endpoint(&self, id: &str, key: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.ensure_editable(&self.subscription_profile(id)?)?;
        subscription::switch_endpoint_key(&self.vault(), &self.store(), id, key, available)
            .map_err(failed)
    }

    pub fn switch_endpoint_live(
        &self,
        id: &str,
        key: &str,
        remembered: &dyn crate::linux::CredentialSource,
    ) -> Result<SwitchOutcome, String> {
        let _lock = self.mutation()?;
        let profiles = self.profiles()?;
        let profile = profiles
            .iter()
            .find(|profile| {
                profile.id == id
                    && profile.backend == TunnelBackend::Xray
                    && profile.subscription.is_some()
            })
            .cloned()
            .ok_or("The profile is not an Xray subscription")?;
        crate::linux_services::ensure_not_enrolled(&self.engine, &profile)?;
        let vault = self.vault();
        let endpoints = self.endpoints(&profile)?;
        let was_running = self.engine.status(&profile)?.state != TunnelState::Stopped;
        let original_prepared = if was_running {
            Some(
                self.engine
                    .prepare_connection(&vault, &profile, None, remembered, false)?,
            )
        } else {
            None
        };
        let candidate = subscription::prepare_endpoint_switch(&vault, &profiles, id, key, |port| {
            was_running || profile.xray_mode == XrayMode::Tun || available(port)
        })
        .map_err(failed)?;
        let candidate_path = candidate.config_path.clone();
        let discard_candidate = || vault.remove_revision_for_config(&candidate_path).is_ok();
        let before_start_failure = |error: String| {
            if discard_candidate() {
                error
            } else {
                format!("{error}; temporary managed configuration could not be removed")
            }
        };
        let preparation = validate(&candidate).map_err(failed).and_then(|()| {
            if was_running {
                self.engine
                    .prepare_connection(&vault, &candidate, None, remembered, false)
                    .map(Some)
            } else {
                Ok(None)
            }
        });
        let candidate_prepared = match preparation {
            Ok(prepared) => prepared,
            Err(error) => return Err(before_start_failure(error)),
        };
        if was_running {
            let teardown = self.engine.disconnect(&profile).and_then(|status| {
                if status.state == TunnelState::Stopped {
                    Ok(())
                } else {
                    Err("The previous connection did not stop; selection was not changed".into())
                }
            });
            if let Err(error) = teardown {
                // The candidate never started. Its profile ID is also the old
                // connection's ID, so candidate teardown could kill a healthy old session.
                let detail = match self.engine.status(&profile).map(|status| status.state) {
                    Ok(TunnelState::Running) => {
                        "the previous connection is still running; selection was not changed"
                    }
                    Ok(TunnelState::Stopped | TunnelState::Failed) => {
                        let previous = original_prepared.as_ref().expect("rollback was prepared");
                        if self.engine.execute_prepared(previous)
                            .is_ok_and(|status| status.state == TunnelState::Running)
                        {
                            "the previous server and connection state were restored"
                        } else {
                            "restoring the previous connection was not confirmed; its original managed revision was retained"
                        }
                    }
                    Err(_) => {
                        "restoring the previous connection was not confirmed; its original managed revision was retained"
                    }
                };
                return Err(before_start_failure(format!("{error}; {detail}")));
            }
        }
        let rollback_failure = || {
            let next = candidate_prepared
                .as_ref()
                .expect("a running switch was prepared");
            let previous = original_prepared.as_ref().expect("rollback was prepared");
            let stopped = self
                .engine
                .disconnect(next.profile())
                .is_ok_and(|status| status.state == TunnelState::Stopped);
            if stopped
                && self
                    .engine
                    .execute_prepared(previous)
                    .is_ok_and(|status| status.state == TunnelState::Running)
            {
                if discard_candidate() {
                    "The server switch failed; the previous server and connection state were restored".into()
                } else {
                    "The server switch failed; the previous server and connection state were restored, but temporary managed configuration could not be removed".into()
                }
            } else {
                // Either process may still need its prepared revision.
                "The server switch failed; restoring the previous server or connection was not confirmed; managed revisions were retained".into()
            }
        };
        if let Some(prepared) = &candidate_prepared {
            if !self
                .engine
                .execute_prepared(prepared)
                .is_ok_and(|status| status.state == TunnelState::Running)
            {
                return Err(rollback_failure());
            }
        }
        // Until this CAS succeeds, the original profile and its exact managed
        // revision remain canonical and available for rollback.
        let saved = self.store().update_profile(id, |current| {
            if current != &profile || self.endpoints(current).map_err(invalid_owned)? != endpoints {
                return Err(invalid(
                    "The profile or endpoint selection changed during switching",
                ));
            }
            *current = candidate;
            Ok(())
        });
        let document = match saved {
            Ok(document) => document,
            Err(_) if was_running => return Err(rollback_failure()),
            Err(_) => {
                return Err(before_start_failure(
                    "The profile changed; selection was not saved".into(),
                ))
            }
        };
        if vault.is_managed_profile_path(id, &profile.config_path) {
            vault
                .remove_revision_for_config(&profile.config_path)
                .map_err(|_| {
                    "The endpoint switched, but its previous managed revision could not be removed"
                        .to_string()
                })?;
        }
        let profile = document
            .profiles
            .into_iter()
            .find(|profile| profile.id == id)
            .expect("the transaction retained the switched profile");
        Ok(SwitchOutcome {
            profile,
            was_running,
        })
    }

    pub fn set_backups(&self, id: &str, keys: &[String]) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.subscription_profile(id)?;
        subscription::set_backup_endpoints(&self.vault(), &self.store(), id, keys).map_err(failed)
    }

    pub fn set_auto_return(&self, id: &str, enabled: bool) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.subscription_profile(id)?;
        subscription::set_auto_return_primary(&self.store(), id, enabled).map_err(failed)
    }

    pub fn sync_background(
        &self,
        profile: &Profile,
        checks: &[ServiceCheck],
    ) -> Result<(), String> {
        if profile.xray_mode != XrayMode::Tun
            || (!profile
                .xray_service_checks
                .iter()
                .any(|check| check.background)
                && !checks.iter().any(|check| check.background))
        {
            return Ok(());
        }
        let checks = checks
            .iter()
            .filter(|check| {
                check.background
                    && net_manager_core::service_checks::service_check_is_bound(
                        profile,
                        &check.endpoint_key,
                    )
            })
            .cloned()
            .collect();
        if self
            .engine
            .set_xray_service_checks(&profile.id, checks)
            .is_ok()
            || self
                .engine
                .status(profile)
                .is_ok_and(|status| status.state == TunnelState::Stopped)
        {
            Ok(())
        } else {
            Err(
                "The daemon did not confirm the diagnostic change; configuration was not saved"
                    .into(),
            )
        }
    }

    pub fn set_pinned_routes(
        &self,
        id: &str,
        routes: Vec<PinnedRoute>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let expected = self.subscription_profile(id)?;
        let mut candidate = expected.clone();
        candidate.pinned_policies = routes.clone();
        profiles::validate_profile(&candidate).map_err(failed)?;
        self.sync_background(&candidate, &candidate.xray_service_checks)?;
        let saved = subscription::set_pinned_routes(&self.vault(), &self.store(), id, routes);
        if saved.is_err() {
            self.sync_background(&candidate, &[])?;
        }
        saved.map_err(failed)
    }

    pub fn set_service_checks(
        &self,
        id: &str,
        checks: Vec<ServiceCheck>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let expected = self.subscription_profile(id)?;
        let endpoints = self.endpoints(&expected)?;
        net_manager_core::service_checks::validate_service_checks(&checks).map_err(failed)?;
        for check in &checks {
            let retained = expected.xray_service_checks.iter().any(|previous| {
                previous.id == check.id && previous.endpoint_key == check.endpoint_key
            });
            if !retained
                && !net_manager_core::service_checks::service_check_is_bound(
                    &expected,
                    &check.endpoint_key,
                )
            {
                return Err("The selected endpoint is not explicitly pinned".into());
            }
        }
        let mut candidate = expected.clone();
        candidate.xray_service_checks = checks.clone();
        profiles::validate_profile(&candidate).map_err(failed)?;
        self.sync_background(&expected, &checks)?;
        let result = self.store().update_profile(id, |current| {
            if current != &expected || self.endpoints(current).map_err(invalid_owned)? != endpoints
            {
                return Err(invalid("The profile or endpoint selection changed"));
            }
            current.xray_service_checks = checks;
            Ok(())
        });
        if result.is_err() {
            let prior = if expected
                .xray_service_checks
                .iter()
                .any(|check| check.background)
            {
                &expected
            } else {
                &candidate
            };
            return Err(if self.sync_background(prior, &[]).is_ok() {
                "Checks were not saved; background diagnostics are stopped."
            } else {
                "Checks were not saved; the daemon did not confirm background cancellation."
            }
            .into());
        }
        result.map_err(failed)
    }

    pub async fn run_service_checks(
        &self,
        id: &str,
        ids: Option<&[String]>,
    ) -> Result<Vec<ServiceCheckResult>, String> {
        let (expected, endpoints) = {
            let _lock = self.mutation()?;
            let profile = self.subscription_profile(id)?;
            let endpoints = self.endpoints(&profile)?;
            (profile, endpoints)
        };
        let executable = std::sync::OnceLock::<Result<PathBuf, String>>::new();
        let results = net_manager_core::service_checks::check_profile_services(
            &self.vault(),
            &expected,
            ids,
            || {
                let path = executable
                    .get_or_init(|| self.xray_executable())
                    .as_ref()
                    .map_err(Clone::clone)?;
                Ok(tokio::process::Command::new(path))
            },
        )
        .await
        .map_err(failed)?;
        if self.profile(id)? != expected || self.endpoints(&expected)? != endpoints {
            return Err("The profile or endpoint selection changed; run the checks again".into());
        }
        Ok(results)
    }

    pub fn set_node_pool(
        &self,
        id: &str,
        pool: Option<NodePoolSettings>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.subscription_profile(id)?;
        net_manager_core::node_pool::set_node_pool(&self.store(), id, pool).map_err(failed)
    }

    pub async fn rebuild_node_pool(
        &self,
        id: &str,
    ) -> Result<Option<net_manager_core::node_pool::NodePoolReport>, String> {
        drop(self.mutation()?);
        let profile = self.subscription_profile(id)?;
        let Some(pool) = profile
            .subscription
            .as_ref()
            .and_then(|meta| meta.node_pool.as_ref())
        else {
            return Ok(None);
        };
        let executable = pool
            .verify_exit_country
            .then(|| self.xray_executable())
            .transpose()?;
        // Core rechecks the snapshot before its transactional pool update.
        net_manager_core::node_pool::rebuild_node_pool(
            &self.vault(),
            &self.store(),
            id,
            &net_manager_core::node_pool::EXIT_COUNTRY_PROBES,
            net_manager_core::node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
            move |_| {
                executable
                    .as_ref()
                    .ok_or_else(|| invalid("Xray executable unavailable"))
                    .map(tokio::process::Command::new)
            },
        )
        .await
        .map(Some)
        .map_err(failed)
    }

    pub fn plan_migration(
        &self,
        id: &str,
        path: &std::path::Path,
    ) -> Result<
        (
            net_manager_core::xray_migrate::XrayPolicyMigration,
            Vec<net_manager_core::config_vault::SubscriptionEndpoint>,
        ),
        String,
    > {
        use std::io::Read;
        let profile = self.profile(id)?;
        if profile.backend != TunnelBackend::Xray {
            return Err("Policy migration requires an Xray profile".into());
        }
        let mut body = Vec::new();
        File::open(path)
            .and_then(|file| file.take(512 * 1024 + 1).read_to_end(&mut body))
            .map_err(failed)?;
        if body.len() > 512 * 1024 {
            return Err("The selected Xray policy exceeds 512 KiB".into());
        }
        let source: Value = serde_json::from_slice(&body).map_err(failed)?;
        let endpoints = self.endpoints(&profile)?;
        let primary = profile.subscription.as_ref().and_then(|meta| {
            meta.active_key.clone().or_else(|| {
                endpoints
                    .get(meta.active_index)
                    .map(|endpoint| subscription::endpoint_key(&endpoint.url))
            })
        });
        let migration = net_manager_core::xray_migrate::plan_xray_policy_migration(
            &source,
            primary.as_deref(),
            net_manager_core::xray_migrate::subscription_outbound_resolver(
                &endpoints,
                primary.as_deref(),
            ),
        )
        .map_err(failed)?;
        Ok((migration, endpoints))
    }

    pub fn preview_migration(
        &self,
        id: &str,
        path: &std::path::Path,
    ) -> Result<XrayPolicyPreview, String> {
        self.plan_migration(id, path)
            .map(|(migration, _)| preview_of(&migration))
    }

    pub fn apply_migration(
        &self,
        id: &str,
        path: &std::path::Path,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let expected = self.profile(id)?;
        self.ensure_editable(&expected)?;
        let (migration, endpoints) = self.plan_migration(id, path)?;
        if !migration.refused.is_empty() {
            return Err(format!(
                "Policy migration refused {} source construct(s); nothing was changed",
                migration.refused.len()
            ));
        }
        self.store()
            .update_profile(id, |current| {
                if current != &expected
                    || self.endpoints(current).map_err(invalid_owned)? != endpoints
                {
                    return Err(invalid("The profile or endpoint selection changed"));
                }
                net_manager_core::xray_migrate::apply_xray_policy_migration(current, migration)
                    .map_err(|_| invalid("Policy could not be applied"))?;
                let live: std::collections::HashSet<_> = endpoints
                    .iter()
                    .map(|endpoint| subscription::endpoint_key(&endpoint.url))
                    .collect();
                for pin in &mut current.pinned_policies {
                    pin.missing = !live.contains(&pin.endpoint_key);
                }
                validate(current)
            })
            .map_err(failed)
    }

    pub async fn verify_subscription_exits(
        &self,
        id: &str,
    ) -> Result<Vec<SubscriptionExitCheck>, String> {
        let profile = self.subscription_profile(id)?;
        let (nodes, _) = subscription::failover_plan(&self.vault(), &profile).map_err(failed)?;
        if nodes.is_empty() {
            return Err("The profile has no failover candidates".into());
        }
        let expected_nodes = nodes.clone();
        let executable = self.xray_executable()?;
        let infos = self.subscription_endpoints(id)?;
        let roles: std::collections::HashMap<_, _> = infos
            .iter()
            .map(|info| {
                let role = if info.active {
                    "primary"
                } else if info.is_backup {
                    "backup"
                } else if info.in_pool {
                    "pool"
                } else {
                    "node"
                };
                (info.key.clone(), role)
            })
            .collect();
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(
            net_manager_core::node_pool::POOL_PROBE_PARALLELISM,
        ));
        let mut tasks = tokio::task::JoinSet::new();
        for (index, endpoint) in nodes.into_iter().enumerate() {
            let gate = gate.clone();
            let executable = executable.clone();
            tasks.spawn(async move {
                let _permit = gate
                    .acquire_owned()
                    .await
                    .map_err(|_| "Exit verification was cancelled")?;
                let key = subscription::endpoint_key(&endpoint.url);
                let mut command = tokio::process::Command::new(executable);
                command.args(["run", "-config", "stdin:"]);
                let outcome = net_manager_core::node_pool::measure_exit_country(
                    &endpoint.url,
                    command,
                    &net_manager_core::node_pool::EXIT_COUNTRY_PROBES,
                    net_manager_core::node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
                )
                .await;
                Ok::<_, &str>((index, key, endpoint.name, outcome))
            });
        }
        let mut results = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(result)) => results.push(result),
                _ => {
                    tasks.abort_all();
                    return Err("An exit-verification worker failed".into());
                }
            }
        }
        if self.profile(id)? != profile
            || subscription::failover_plan(&self.vault(), &profile)
                .map_err(failed)?
                .0
                != expected_nodes
        {
            return Err("The profile or endpoint selection changed; verify again".into());
        }
        results.sort_by_key(|(index, _, _, _)| *index);
        Ok(results
            .into_iter()
            .map(|(_, key, name, outcome)| {
                let role = roles.get(&key).copied().unwrap_or("node").to_string();
                let named_country = flag_country(&name);
                let (exit_country, exit_ip, error) = match outcome {
                    Ok(exit) => (Some(exit.country), Some(exit.ip), None),
                    Err(_) => (None, None, Some("Exit-country verification failed".into())),
                };
                let mismatch = named_country.is_some()
                    && exit_country.is_some()
                    && named_country != exit_country;
                SubscriptionExitCheck {
                    key,
                    name: name.trim().into(),
                    role,
                    named_country,
                    exit_country,
                    exit_ip,
                    mismatch,
                    error,
                }
            })
            .collect())
    }
}

pub fn new_id() -> Result<String, String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(failed)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(40);
    id.push_str("profile-");
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(id)
}

pub fn validate_interval(minutes: Option<u32>) -> Result<(), String> {
    if minutes.is_some_and(|minutes| !matches!(minutes, 15 | 60 | 360)) {
        Err("Refresh interval must be off, 15, 60 or 360 minutes".into())
    } else {
        Ok(())
    }
}

fn validate(profile: &Profile) -> io::Result<()> {
    if profile.backend == TunnelBackend::None
        && (profile.tunnel_role != TunnelRole::Primary
            || !profile.tunnel_networks.is_empty()
            || !profile.tunnel_dns_domains.is_empty())
    {
        return Err(invalid("Static routes do not create a tunnel"));
    }
    if profile.tunnel_role == TunnelRole::Secondary {
        validate_secondary(
            profile.tunnel_role,
            &profile.secondary_routes(),
            &profile.tunnel_dns_domains,
        )
        .map_err(|_| invalid("Invalid connection networks or DNS scope"))?;
    }
    if !profile
        .tunnel_dns_domains
        .iter()
        .all(|domain| valid_dns_suffix(domain))
    {
        return Err(invalid("Invalid split-DNS domain"));
    }
    if profile.backend == TunnelBackend::Xray {
        if profile.xray_mode == XrayMode::Tun
            && (profile.xray_socks_port.is_none() || profile.xray_http_port.is_none())
        {
            return Err(invalid("Xray TUN requires a generated share-link profile"));
        }
        for url in [
            profile.xray_geoip_url.as_deref(),
            profile.xray_geosite_url.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            crate::linux_geo_assets::validate_geo_asset_url(url)
                .map_err(|_| invalid("Invalid geo asset URL"))?;
        }
    }
    profiles::validate_profile(profile)
}

fn merge_profile(profile: &Profile, patch: &Value) -> io::Result<Profile> {
    let object = patch
        .as_object()
        .ok_or_else(|| invalid("A profile patch must be a JSON object"))?;
    let mut value = serde_json::to_value(profile).map_err(|_| invalid("Invalid profile"))?;
    let target = value.as_object_mut().expect("profile is an object");
    // Optional fields omitted by serde are still editable.
    const OPTIONAL: &[&str] = &[
        "xrayServiceChecks",
        "xrayProxyExits",
        "xrayGeoipUrl",
        "xrayGeositeUrl",
        "xrayDomainStrategy",
        "xrayDomainMatcher",
        "xrayDns",
        "xraySockopts",
        "xrayTrafficRules",
        "xrayInterfaceRoutes",
        "xrayConnectionIdleSecs",
        "xrayTunMtu",
        "xrayTunDnsServers",
        "xrayDirectDomainStrategy",
        "tunnelRole",
        "tunnelDnsDomains",
        "tunnelNetworks",
    ];
    for (key, value) in object {
        if matches!(
            key.as_str(),
            "id" | "backend"
                | "configPath"
                | "subscription"
                | "pinnedPolicies"
                | "xrayServiceChecks"
                | "xrayProxyExits"
                | "xraySocksPort"
                | "xrayHttpPort"
        ) {
            return Err(invalid(
                "This field is owned by a source or dedicated endpoint command",
            ));
        }
        if !target.contains_key(key) && !OPTIONAL.contains(&key.as_str()) {
            return Err(invalid("Unknown profile setting"));
        }
        merge_value(target.entry(key.clone()).or_insert(Value::Null), value);
    }
    serde_json::from_value(value).map_err(|_| invalid("Invalid profile settings"))
}

fn merge_value(target: &mut Value, patch: &Value) {
    if let (Some(target), Some(patch)) = (target.as_object_mut(), patch.as_object()) {
        for (key, value) in patch {
            merge_value(target.entry(key.clone()).or_insert(Value::Null), value);
        }
    } else {
        *target = patch.clone();
    }
}

fn preserve_form_settings(profile: &mut Profile, stored: &Profile, same_source: bool) {
    if profile.backend != TunnelBackend::Xray || stored.backend != TunnelBackend::Xray {
        profile.subscription = None;
        profile.pinned_policies.clear();
        profile.xray_service_checks.clear();
        profile.xray_proxy_exits.clear();
        if profile.backend != TunnelBackend::Xray {
            profile.xray_sockopts = None;
            profile.xray_traffic_rules.clear();
            profile.xray_interface_routes.clear();
            profile.xray_connection_idle_secs = None;
            profile.xray_tun_mtu = None;
            profile.xray_tun_dns_servers.clear();
            profile.xray_direct_domain_strategy = None;
            profile.xray_quic_reject = false;
        }
        return;
    }
    profile.subscription = stored.subscription.clone();
    profile.pinned_policies = stored.pinned_policies.clone();
    profile.xray_service_checks = stored.xray_service_checks.clone();
    profile.xray_proxy_exits = stored.xray_proxy_exits.clone();
    profile.xray_sockopts = stored.xray_sockopts.clone();
    profile.xray_traffic_rules = stored.xray_traffic_rules.clone();
    profile.xray_interface_routes = stored.xray_interface_routes.clone();
    profile.xray_connection_idle_secs = stored.xray_connection_idle_secs;
    profile.xray_tun_mtu = stored.xray_tun_mtu;
    profile.xray_tun_dns_servers = stored.xray_tun_dns_servers.clone();
    profile.xray_direct_domain_strategy = stored.xray_direct_domain_strategy.clone();
    profile.endpoint_bypasses = stored.endpoint_bypasses.clone();
    if same_source && profile.config_path == stored.config_path {
        profile.xray_socks_port = stored.xray_socks_port;
        profile.xray_http_port = stored.xray_http_port;
    }
}

pub fn render_wireguard_config(fields: &WireGuardFields) -> Result<String, String> {
    for value in [
        &fields.private_key,
        &fields.address,
        &fields.peer_public_key,
        &fields.peer_endpoint,
        &fields.allowed_ips,
    ] {
        if value.trim().is_empty() || value.contains(['\r', '\n']) {
            return Err("Required WireGuard fields must be nonempty single-line values".into());
        }
    }
    if fields.dns.contains(['\r', '\n']) || fields.preshared_key.contains(['\r', '\n']) {
        return Err("WireGuard fields must be single-line values".into());
    }
    let mut result = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\n",
        fields.private_key.trim(),
        fields.address.trim()
    );
    if !fields.dns.trim().is_empty() {
        result.push_str(&format!("DNS = {}\n", fields.dns.trim()));
    }
    result.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\n",
        fields.peer_public_key.trim(),
        fields.peer_endpoint.trim(),
        fields.allowed_ips.trim()
    ));
    if !fields.preshared_key.trim().is_empty() {
        result.push_str(&format!("PresharedKey = {}\n", fields.preshared_key.trim()));
    }
    if let Some(keepalive) = fields.persistent_keepalive {
        result.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
    }
    Ok(result)
}

/// Full saved settings, with credentials, provider-supplied prose, sensitive URLs
/// and managed source paths removed. This is presentation only, never persisted.
pub fn metadata(profile: &Profile) -> Value {
    let mut value = serde_json::to_value(profile).expect("profile metadata is JSON-compatible");
    if let Some(object) = value.as_object_mut() {
        object.remove("configPath");
        for key in ["xrayGeoipUrl", "xrayGeositeUrl"] {
            if object.contains_key(key) {
                object.insert(key.into(), json!("<redacted>"));
            }
        }
        if let Some(meta) = object
            .get_mut("subscription")
            .and_then(Value::as_object_mut)
        {
            for key in [
                "url",
                "hwid",
                "probeUrl",
                "supportUrl",
                "webPageUrl",
                "announce",
                "providerTitle",
                "lastRefreshError",
                "skippedProtocols",
            ] {
                meta.remove(key);
            }
        }
        if let Some(checks) = object
            .get_mut("xrayServiceChecks")
            .and_then(Value::as_array_mut)
        {
            for check in checks {
                if let Some(check) = check.as_object_mut() {
                    check.remove("url");
                }
            }
        }
    }
    value
}

#[derive(Debug)]
pub struct SwitchOutcome {
    pub profile: Profile,
    pub was_running: bool,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRefreshResult {
    pub endpoint_count: usize,
    pub active_index: usize,
    pub skipped_count: usize,
    pub fallback_used: bool,
    pub cleanup_failed: bool,
    pub pool_report: Option<net_manager_core::node_pool::NodePoolReport>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionDelayResult {
    pub delay_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionExitCheck {
    pub key: String,
    pub name: String,
    pub role: String,
    pub named_country: Option<String>,
    pub exit_country: Option<String>,
    pub exit_ip: Option<String>,
    pub mismatch: bool,
    pub error: Option<String>,
}

fn flag_country(name: &str) -> Option<String> {
    let mut code = String::new();
    for ch in name.chars() {
        let value = ch as u32;
        if (0x1F1E6..=0x1F1FF).contains(&value) {
            code.push((b'A' + (value - 0x1F1E6) as u8) as char);
        }
    }
    (code.len() == 2).then_some(code)
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrayPolicyPreview {
    pub direct: usize,
    pub proxy: usize,
    pub block: usize,
    pub pinned_count: usize,
    pub private_lan_direct: bool,
    pub quic_reject: bool,
    pub domain_strategy: Option<XrayDomainStrategy>,
    pub domain_matcher: Option<XrayDomainMatcher>,
    pub endpoint_bypass_count: usize,
    pub has_geoip_override: bool,
    pub has_geosite_override: bool,
    pub has_dns: bool,
    pub has_sockopts: bool,
    pub traffic_rule_count: usize,
    pub interface_route_count: usize,
    pub dns_server_count: usize,
    pub dns_host_count: usize,
    pub dns_rewrite_rule_count: usize,
    pub tun_dns_server_count: usize,
    pub tun_mtu: Option<u32>,
    pub connection_idle_secs: Option<u32>,
    pub direct_domain_strategy: Option<String>,
    pub dns_enable_parallel_query: Option<bool>,
    pub has_dns_outbound: bool,
    pub backup_count: Option<usize>,
    pub skipped: Vec<String>,
    pub refused: Vec<String>,
}

pub fn preview_of(
    migration: &net_manager_core::xray_migrate::XrayPolicyMigration,
) -> XrayPolicyPreview {
    let count = |target| {
        migration
            .domain_policies
            .iter()
            .filter(|policy| policy.target == target)
            .map(|policy| policy.domains.len())
            .sum()
    };
    XrayPolicyPreview {
        direct: count(DomainRouteTarget::Direct),
        proxy: count(DomainRouteTarget::Proxy),
        block: count(DomainRouteTarget::Block),
        pinned_count: migration.pinned_routes.len(),
        private_lan_direct: migration.private_lan_direct,
        quic_reject: migration.quic_reject,
        domain_strategy: migration.domain_strategy,
        domain_matcher: migration.domain_matcher,
        endpoint_bypass_count: migration.endpoint_bypasses.len(),
        has_geoip_override: migration.geoip_url.is_some(),
        has_geosite_override: migration.geosite_url.is_some(),
        has_dns: !migration.dns.is_empty(),
        has_sockopts: migration.sockopts.is_some(),
        traffic_rule_count: migration.traffic_rules.len(),
        interface_route_count: migration.interface_routes.len(),
        dns_server_count: migration.dns.servers.len(),
        dns_host_count: migration.dns.hosts.len(),
        dns_rewrite_rule_count: migration
            .dns
            .outbound
            .as_ref()
            .map_or(0, |outbound| outbound.rules.len()),
        tun_dns_server_count: migration.tun_dns_servers.len(),
        tun_mtu: migration.tun_mtu,
        connection_idle_secs: migration.connection_idle_secs,
        direct_domain_strategy: migration.direct_domain_strategy.clone(),
        dns_enable_parallel_query: migration.dns.enable_parallel_query,
        has_dns_outbound: migration.dns.outbound.is_some(),
        backup_count: migration.backup_keys.as_ref().map(Vec::len),
        skipped: migration
            .skipped
            .iter()
            .map(|item| item.reason.clone())
            .collect(),
        refused: migration
            .refused
            .iter()
            .map(|item| item.reason.clone())
            .collect(),
    }
}
