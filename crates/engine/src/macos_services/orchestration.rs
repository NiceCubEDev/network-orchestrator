use super::*;
use crate::macos_credentials::{
    ConnectOutcome, CredentialOutcome, CredentialPrompt, CredentialResolution,
    OpenVpnCredentialStore,
};
use crate::macos_state::{
    start_eligibility, AppMode, SettingsStore, StartAvailability, StartEligibility,
};
use net_manager_core::{
    analysis,
    connection_sets::{self, ConnectionSet, CredentialInputs},
    intent_doctor::{self, IntentSuggestion, KnownEndpoint},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPolicy {
    pub proxy_connections: bool,
    pub helper_capabilities: Vec<String>,
}
impl StartPolicy {
    pub fn current() -> Self {
        let helper = helper_status();
        Self {
            proxy_connections: capabilities().proxy_connections,
            helper_capabilities: if helper.reachable {
                helper.capabilities
            } else {
                vec![]
            },
        }
    }
    pub fn eligibility(&self, mode: AppMode, profile: &Profile) -> StartEligibility {
        let capability = match profile.backend {
            TunnelBackend::None => "net.intent.set",
            TunnelBackend::WireGuard => "wireguard.connect",
            TunnelBackend::OpenVpn => "openvpn.connect",
            TunnelBackend::Xray => "xray.connect",
        };
        start_eligibility(
            mode,
            profile.backend,
            profile.xray_mode,
            StartAvailability {
                proxy_connections: self.proxy_connections,
                helper_serves: self.helper_capabilities.iter().any(|c| c == capability),
            },
        )
    }
}
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum ConnectProfileOutcome {
    Connected { credentials: CredentialOutcome },
    CredentialsRequired { prompt: CredentialPrompt },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BatchAction {
    Connect,
    Disconnect,
    Refresh,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BatchItemOutcome {
    Succeeded,
    SkippedRunning,
    Unavailable,
    CredentialsRequired,
    Failed,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchItem {
    pub profile_id: String,
    pub action: BatchAction,
    pub outcome: BatchItemOutcome,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_prompt: Option<CredentialPrompt>,
}
#[derive(Debug, Default, Serialize)]
pub struct BatchOutcome {
    pub items: Vec<BatchItem>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSnapshot {
    pub profiles: Vec<Profile>,
    pub interfaces: Vec<NetworkInterface>,
    pub routes: Vec<RouteEntry>,
    pub route_map: RouteMap,
    pub network_error: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentFixOutcome {
    pub applied: usize,
    pub error: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyExports {
    pub http_proxy: String,
    pub https_proxy: String,
    pub all_proxy: String,
    pub no_proxy: String,
    pub shell: String,
}

impl<R: BusinessRuntime> MacosServices<R> {
    pub fn native_credential_store(&self) -> Result<OpenVpnCredentialStore, String> {
        OpenVpnCredentialStore::native(&self.root, &production_root()?)
    }
    pub fn connect_profile(
        &self,
        id: &str,
        supplied: Option<OpenVpnCredentials>,
        remember: bool,
        credentials: &OpenVpnCredentialStore,
    ) -> Result<ConnectProfileOutcome, String> {
        let profile = self.profile(id)?;
        crate::macos_state::ensure_start_allowed(&self.root, profile.backend)?;
        let needs = self.runtime.credential_requirements(&self.root, &profile)?;
        let rejected = profile.backend == TunnelBackend::OpenVpn
            && self.runtime.authentication_rejected(&self.root, &profile)?;
        let attempt = match credentials.resolve(id, needs, supplied, remember, rejected)? {
            CredentialResolution::Required(prompt) => {
                return Ok(ConnectProfileOutcome::CredentialsRequired { prompt })
            }
            CredentialResolution::Ready(attempt) => attempt,
        };
        match self.runtime.connect(
            &self.root,
            &self.store(),
            &profile,
            attempt.credentials().cloned(),
        ) {
            Ok(()) => Ok(ConnectProfileOutcome::Connected {
                credentials: attempt.complete(ConnectOutcome::ConfirmedSuccess),
            }),
            Err(error) => {
                attempt.complete(if error == "OpenVPN authentication failed" {
                    ConnectOutcome::AuthenticationRejected
                } else {
                    ConnectOutcome::Failed
                });
                Err(error)
            }
        }
    }
    pub fn capture_set(&self, id: &str, name: &str) -> Result<ConnectionSet, String> {
        self.locked(|| {
            let profiles = self.profiles()?;
            let mut profile_ids = Vec::new();
            for profile in &profiles {
                if self.runtime.is_running(&self.root, profile)? {
                    profile_ids.push(profile.id.clone());
                }
            }
            if profile_ids.is_empty() {
                return Err("Start at least one connection before capturing a set".into());
            }
            let set = ConnectionSet {
                id: id.into(),
                name: required(name)?.into(),
                profile_ids,
            };
            connection_sets::put(&self.root, &self.store(), set.clone())?;
            Ok(set)
        })
    }
    pub fn apply_set(
        &self,
        set: &ConnectionSet,
        policy: &StartPolicy,
        inputs: &CredentialInputs,
        credentials: &OpenVpnCredentialStore,
    ) -> Result<BatchOutcome, String> {
        connection_sets::validate(set)?;
        let profiles = self.profiles()?;
        let mode = SettingsStore::new(&self.root).load()?.app_mode;
        let mut result = BatchOutcome::default();
        for profile in &profiles {
            let wanted = set.profile_ids.contains(&profile.id);
            let running = match self.runtime.is_running(&self.root, profile) {
                Ok(v) => v,
                Err(error) => {
                    result.items.push(item(
                        profile,
                        if wanted {
                            BatchAction::Connect
                        } else {
                            BatchAction::Disconnect
                        },
                        Err(error),
                    ));
                    continue;
                }
            };
            if wanted == running {
                continue;
            }
            let action = if wanted {
                BatchAction::Connect
            } else {
                BatchAction::Disconnect
            };
            // Native sets skip profiles the client cannot start, including stops.
            // A running managed tunnel remains stoppable in orchestrator mode.
            if !policy
                .eligibility(if running { AppMode::Combined } else { mode }, profile)
                .can_start
            {
                result
                    .items
                    .push(skipped(profile, action, BatchItemOutcome::Unavailable));
                continue;
            }
            if wanted {
                result
                    .items
                    .push(self.connect_batch(profile, inputs, credentials));
            } else {
                result.items.push(item(
                    profile,
                    action,
                    self.runtime.disconnect(&self.root, profile, &profiles),
                ));
            }
        }
        Ok(result)
    }
    pub fn auto_connect(
        &self,
        policy: &StartPolicy,
        inputs: &CredentialInputs,
        credentials: &OpenVpnCredentialStore,
    ) -> Result<BatchOutcome, String> {
        let profiles = self.profiles()?;
        let mode = SettingsStore::new(&self.root).load()?.app_mode;
        let mut result = BatchOutcome::default();
        for profile in profiles.iter().filter(|p| p.auto_connect) {
            match self.runtime.is_running(&self.root, profile) {
                Ok(true) => result.items.push(skipped(
                    profile,
                    BatchAction::Connect,
                    BatchItemOutcome::SkippedRunning,
                )),
                Err(error) => result
                    .items
                    .push(item(profile, BatchAction::Connect, Err(error))),
                Ok(false) => {
                    if policy.eligibility(mode, profile).can_start {
                        result
                            .items
                            .push(self.connect_batch(profile, inputs, credentials));
                    } else {
                        result.items.push(skipped(
                            profile,
                            BatchAction::Connect,
                            BatchItemOutcome::Unavailable,
                        ));
                    }
                }
            }
        }
        Ok(result)
    }
    fn connect_batch(
        &self,
        profile: &Profile,
        inputs: &CredentialInputs,
        credentials: &OpenVpnCredentialStore,
    ) -> BatchItem {
        let supplied = inputs.get(&profile.id);
        match self.connect_profile(
            &profile.id,
            supplied.map(|i| i.credentials.clone()),
            supplied.is_some_and(|i| i.remember),
            credentials,
        ) {
            Ok(ConnectProfileOutcome::Connected { .. }) => {
                item(profile, BatchAction::Connect, Ok(()))
            }
            Ok(ConnectProfileOutcome::CredentialsRequired { prompt }) => {
                let mut result = skipped(
                    profile,
                    BatchAction::Connect,
                    BatchItemOutcome::CredentialsRequired,
                );
                result.credential_prompt = Some(prompt);
                result
            }
            Err(error) => item(profile, BatchAction::Connect, Err(error)),
        }
    }
    pub fn disconnect_all(&self) -> Result<BatchOutcome, String> {
        let profiles = self.profiles()?;
        let mut result = BatchOutcome::default();
        for profile in &profiles {
            match self.runtime.is_running(&self.root, profile) {
                Ok(false) => {}
                Ok(true) => result.items.push(item(
                    profile,
                    BatchAction::Disconnect,
                    self.runtime.disconnect(&self.root, profile, &profiles),
                )),
                Err(error) => result
                    .items
                    .push(item(profile, BatchAction::Disconnect, Err(error))),
            }
        }
        Ok(result)
    }
    pub fn refresh_subscriptions(&self, due_only: bool, now: u64) -> Result<BatchOutcome, String> {
        let profiles = self.profiles()?;
        let mut result = BatchOutcome::default();
        for profile in &profiles {
            let Some(meta) = &profile.subscription else {
                continue;
            };
            if due_only {
                if !net_manager_core::subscription::refresh_due(meta, now) {
                    continue;
                }
                match self.runtime.is_running(&self.root, profile) {
                    Ok(true) => {
                        result.items.push(skipped(
                            profile,
                            BatchAction::Refresh,
                            BatchItemOutcome::SkippedRunning,
                        ));
                        continue;
                    }
                    Err(error) => {
                        result
                            .items
                            .push(item(profile, BatchAction::Refresh, Err(error)));
                        continue;
                    }
                    Ok(false) => {}
                }
            }
            result.items.push(item(
                profile,
                BatchAction::Refresh,
                self.refresh_subscription(&profile.id).map(|_| ()),
            ));
        }
        Ok(result)
    }
    pub fn network_snapshot(&self) -> Result<NetworkSnapshot, String> {
        let profiles = self.profiles()?;
        let interfaces = self.network.interfaces();
        let routes = self.network.routes();
        let network_error = (interfaces.is_err() || routes.is_err())
            .then(|| "Some network information could not be read. Try refreshing.".into());
        let interfaces = interfaces.unwrap_or_default();
        let routes = routes.unwrap_or_default();
        let planned = profiles
            .iter()
            .cloned()
            .map(|p| (p, false))
            .collect::<Vec<_>>();
        let route_map = net_manager_core::route_plan::build_route_map(&planned, &routes);
        Ok(NetworkSnapshot {
            profiles: redact_profiles(profiles),
            interfaces,
            routes,
            route_map,
            network_error,
        })
    }
    pub fn diagnose_profile(&self, id: &str) -> Result<ProfileDiagnostics, String> {
        let profile = self.profile(id)?;
        let others = self
            .profiles()?
            .into_iter()
            .filter(|p| p.id != id)
            .collect::<Vec<_>>();
        let vault = self.vault();
        self.runtime.diagnose(
            &self.root,
            &profile,
            crate::DiagnosticsContext {
                others: &others,
                os_routes: self.network.routes(),
                interfaces: self.network.interfaces(),
                vault: &vault,
            },
        )
    }
    pub fn intent_suggestions(&self) -> Result<Vec<IntentSuggestion>, String> {
        let profiles = self.profiles()?;
        let routes = self.network.routes()?;
        let interfaces = self.network.interfaces().unwrap_or_default();
        let intents = self.runtime.intents(&self.root)?;
        Ok(intent_doctor::analyze(
            &intents,
            &routes,
            &interfaces,
            &known_endpoints(&profiles),
        ))
    }
    pub fn apply_intent_fixes(
        &self,
        fixes: &[NetIntentSetParams],
    ) -> Result<IntentFixOutcome, String> {
        for (index, fix) in fixes.iter().enumerate() {
            if let Err(error) = self.runtime.set_intent(&self.root, fix.clone()) {
                return Ok(IntentFixOutcome {
                    applied: index,
                    error: Some(error),
                });
            }
        }
        Ok(IntentFixOutcome {
            applied: fixes.len(),
            error: None,
        })
    }
    pub fn proxy_exports(&self, id: &str) -> Result<ProxyExports, String> {
        let profile = self.profile(id)?;
        let socks = profile
            .xray_socks_port
            .ok_or("This connection has no local proxy port")?;
        let http = profile
            .xray_http_port
            .map(|p| format!("http://127.0.0.1:{p}"))
            .unwrap_or_else(|| format!("socks5h://127.0.0.1:{socks}"));
        let all = format!("socks5h://127.0.0.1:{socks}");
        let no = "localhost,127.0.0.1,.local".to_string();
        Ok(ProxyExports {
            shell: format!(
                "export HTTP_PROXY={http} HTTPS_PROXY={http} ALL_PROXY={all} NO_PROXY={no}"
            ),
            http_proxy: http.clone(),
            https_proxy: http,
            all_proxy: all,
            no_proxy: no,
        })
    }
    pub fn open_browser(&self, id: &str) -> Result<(), String> {
        let profile = self.profile(id)?;
        let port = profile
            .xray_socks_port
            .ok_or("This connection has no local proxy port")?;
        net_manager_core::config_vault::sanitize_profile_id(id).map_err(store_error)?;
        #[cfg(target_os = "macos")]
        {
            let data = self.root.join("browser").join(id);
            std::fs::create_dir_all(&data)
                .map_err(|_| "The browser profile could not be created".to_string())?;
            std::process::Command::new("/usr/bin/open")
                .args(["-na", "Google Chrome", "--args"])
                .arg(format!("--user-data-dir={}", data.display()))
                .arg(format!("--proxy-server=socks5://127.0.0.1:{port}"))
                .args(["--no-first-run", "https://www.youtube.com/"])
                .spawn()
                .map_err(|_| "The browser could not be opened".to_string())?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = port;
            Err("Opening a browser needs macOS".into())
        }
    }
}
fn skipped(profile: &Profile, action: BatchAction, outcome: BatchItemOutcome) -> BatchItem {
    BatchItem {
        profile_id: profile.id.clone(),
        action,
        outcome,
        error: None,
        credential_prompt: None,
    }
}
fn item(profile: &Profile, action: BatchAction, result: Result<(), String>) -> BatchItem {
    match result {
        Ok(()) => skipped(profile, action, BatchItemOutcome::Succeeded),
        Err(error) => BatchItem {
            profile_id: profile.id.clone(),
            action,
            outcome: BatchItemOutcome::Failed,
            error: Some(error),
            credential_prompt: None,
        },
    }
}
/// Never resolves hostnames: the doctor only reasons about literal endpoints.
pub fn known_endpoints(profiles: &[Profile]) -> Vec<KnownEndpoint> {
    let mut found = Vec::new();
    for profile in profiles {
        let label = if profile.name.is_empty() {
            &profile.id
        } else {
            &profile.name
        };
        let mut add = |text: &str| {
            if let Ok(ip) = text.trim().parse() {
                found.push(KnownEndpoint {
                    ip,
                    profile: label.clone(),
                });
            }
        };
        profile.endpoint_bypasses.iter().for_each(|v| add(v));
        if let Ok(analysis) = analysis::analyze_profile(profile) {
            analysis.endpoints.iter().for_each(|e| add(&e.address));
        }
    }
    found
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileStartEligibility {
    pub profile_id: String,
    pub can_start: bool,
    pub can_try_start: bool,
    pub mode_blocked: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyStateOutcome {
    pub settings: crate::macos_state::AppSettings,
    pub sets: Vec<ConnectionSet>,
    pub imported: bool,
}
pub fn production_root() -> Result<PathBuf, String> {
    Ok(
        PathBuf::from(std::env::var_os("HOME").ok_or("The user home directory is unavailable")?)
            .join("Library/Application Support/com.netmanager.app.macos"),
    )
}
impl<R: BusinessRuntime> MacosServices<R> {
    pub fn start_eligibilities(&self) -> Result<Vec<ProfileStartEligibility>, String> {
        self.start_eligibilities_with_policy(&StartPolicy::current())
    }
    pub fn start_eligibilities_with_policy(
        &self,
        policy: &StartPolicy,
    ) -> Result<Vec<ProfileStartEligibility>, String> {
        let mode = SettingsStore::new(&self.root).load()?.app_mode;
        self.profiles()?
            .into_iter()
            .map(|profile| {
                let running = self.runtime.is_running(&self.root, &profile)?;
                let eligibility =
                    policy.eligibility(if running { AppMode::Combined } else { mode }, &profile);
                Ok(ProfileStartEligibility {
                    profile_id: profile.id,
                    can_start: eligibility.can_start,
                    can_try_start: eligibility.can_try_start,
                    mode_blocked: eligibility.mode_blocked,
                })
            })
            .collect()
    }
    pub fn disconnect_set(&self, set: &ConnectionSet) -> Result<BatchOutcome, String> {
        connection_sets::validate(set)?;
        let profiles = self.profiles()?;
        let mut result = BatchOutcome::default();
        for profile in profiles.iter().filter(|p| set.profile_ids.contains(&p.id)) {
            match self.runtime.is_running(&self.root, profile) {
                Ok(false) => {}
                Ok(true) => result.items.push(item(
                    profile,
                    BatchAction::Disconnect,
                    self.runtime.disconnect(&self.root, profile, &profiles),
                )),
                Err(error) => result
                    .items
                    .push(item(profile, BatchAction::Disconnect, Err(error))),
            }
        }
        Ok(result)
    }
    pub fn import_legacy_state(
        &self,
        production_root: &Path,
        app_mode: Option<&str>,
        sets: Vec<ConnectionSet>,
    ) -> Result<LegacyStateOutcome, String> {
        let settings =
            SettingsStore::new(&self.root).import_legacy_app_mode(production_root, app_mode)?;
        let root = crate::macos_transaction::canonical_root(&self.root, false)?;
        let production = crate::macos_transaction::canonical_root(production_root, false)?;
        let sets = if root.is_some() && root == production {
            self.locked(|| connection_sets::import_legacy_once(&self.root, sets))?
        } else {
            connection_sets::list(&self.root)?
        };
        Ok(LegacyStateOutcome {
            settings: settings.settings,
            sets,
            imported: settings.imported,
        })
    }
}

impl<R: BusinessRuntime> MacosServices<R> {
    pub fn list_sets(&self) -> Result<Vec<ConnectionSet>, String> {
        connection_sets::list(&self.root)
    }
    pub fn get_set(&self, id: &str) -> Result<ConnectionSet, String> {
        connection_sets::get(&self.root, id)
    }
    pub fn put_set(&self, set: ConnectionSet) -> Result<Vec<ConnectionSet>, String> {
        self.locked(|| {
            connection_sets::put(&self.root, &self.store(), set)?;
            connection_sets::list(&self.root)
        })
    }
    pub fn delete_set(&self, id: &str) -> Result<Vec<ConnectionSet>, String> {
        self.locked(|| {
            connection_sets::delete(&self.root, id)?;
            connection_sets::list(&self.root)
        })
    }
    pub fn import_sets(&self, sets: Vec<ConnectionSet>) -> Result<Vec<ConnectionSet>, String> {
        self.locked(|| connection_sets::import(&self.root, sets))
    }
    pub fn proxy_override(&self) -> Result<crate::macos_network::ProxyOverrideStatus, String> {
        let profiles = self.profiles()?;
        self.network
            .proxy_override(&self.runtime.running_interfaces(&self.root, &profiles)?)
    }
}
