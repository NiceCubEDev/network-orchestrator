use super::*;
use net_manager_core::subscription::{self, FetchedSubscription, RefreshOutcome};
use std::sync::LazyLock;

pub struct SubscriptionImportRequest {
    pub id: String,
    pub name: String,
    pub url: String,
    pub hwid: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionImportOutcome {
    pub profiles: Vec<Profile>,
    pub skipped_count: usize,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointDelay {
    pub index: usize,
    pub delay_ms: Option<u64>,
}
pub enum ExitIpVia {
    Direct,
    Profile(String),
    ProfileSocks(String),
}
static NETWORK_RUNTIME: LazyLock<Result<tokio::runtime::Runtime, std::io::Error>> =
    LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
    });
fn executor() -> Result<&'static tokio::runtime::Runtime, String> {
    NETWORK_RUNTIME
        .as_ref()
        .map_err(|_| "Network reader could not start".into())
}
fn subscription_error(error: std::io::Error) -> String {
    if matches!(
        error.kind(),
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Other
    ) {
        error.to_string()
    } else {
        store_error(error)
    }
}
fn fetch(url: &str, hwid: &str) -> Result<FetchedSubscription, String> {
    let client = subscription::http_client().map_err(subscription_error)?;
    executor()?
        .block_on(subscription::fetch(&client, url, hwid))
        .map_err(subscription_error)
}
fn summary(fetched: &FetchedSubscription) -> String {
    format!(
        "{} headers: {}",
        subscription::summarize_subscription_body(&fetched.body, fetched.content_type.as_deref()),
        fetched.header_names.join(",")
    )
}

impl<R: BusinessRuntime> MacosServices<R> {
    pub fn import_subscription(
        &self,
        request: SubscriptionImportRequest,
    ) -> Result<SubscriptionImportOutcome, String> {
        required(&request.id)?;
        required(&request.url)?;
        // HTTP must not block unrelated root mutations. Core validates the id and
        // duplicate check again while the operation lock protects the commit.
        let fetched = fetch(&request.url, &request.hwid)?;
        self.locked(|| {
            let summary = summary(&fetched);
            let imported = subscription::import_body(
                &self.vault(),
                &self.store(),
                &subscription::SubscriptionImport {
                    id: &request.id,
                    name: &request.name,
                    url: &request.url,
                    hwid: &request.hwid,
                    refresh_interval_minutes: None,
                },
                &fetched.body,
                fetched.meta,
                XrayMode::Socks,
                local_port_available,
            );
            log_import(
                &self.root,
                &summary,
                !request.hwid.is_empty(),
                imported.is_ok(),
            );
            let imported = imported.map_err(|error| {
                let message = subscription_error(error);
                if message == "Subscription contained no supported share links" {
                    format!("{message} ({summary})")
                } else {
                    message
                }
            })?;
            let skipped_count = imported
                .errors
                .iter()
                .map(|e| {
                    if e.path == "Subscription" {
                        e.error
                            .split_whitespace()
                            .next()
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0)
                    } else {
                        1
                    }
                })
                .sum();
            Ok(SubscriptionImportOutcome {
                profiles: redact_profiles(imported.profiles),
                skipped_count,
            })
        })
    }
    pub fn refresh_subscription(&self, id: &str) -> Result<RefreshOutcome, String> {
        let meta = self
            .profile(id)?
            .subscription
            .ok_or("Profile is not a subscription")?;
        let record_failure = || {
            let _ = self.locked(|| {
                let current = self
                    .profile(id)?
                    .subscription
                    .ok_or("Profile is not a subscription")?;
                if current.url == meta.url && current.hwid == meta.hwid {
                    subscription::record_refresh_failure(&self.store(), id, unix_now())
                        .map_err(store_error)?;
                }
                Ok(())
            });
        };
        let fetched = match fetch(&meta.url, &meta.hwid) {
            Ok(f) => f,
            Err(error) => {
                record_failure();
                return Err(error);
            }
        };
        let summary = summary(&fetched);
        let result = self
            .runtime
            .restart_around(&self.root, &self.store(), id, || {
                let current = self
                    .profile(id)?
                    .subscription
                    .ok_or("Profile is not a subscription")?;
                if current.url != meta.url || current.hwid != meta.hwid {
                    return Err("The subscription changed while it was refreshing".into());
                }
                let outcome = subscription::refresh_body(
                    &self.vault(),
                    &self.store(),
                    id,
                    &fetched.body,
                    fetched.meta,
                    local_port_available,
                );
                log_import(&self.root, &summary, !meta.hwid.is_empty(), outcome.is_ok());
                outcome.map_err(subscription_error)
            });
        if result.is_err() {
            record_failure();
        }
        result
    }
    pub fn subscription_endpoints(
        &self,
        id: &str,
    ) -> Result<Vec<SubscriptionEndpointInfo>, String> {
        let meta = self
            .profile(id)?
            .subscription
            .ok_or("Profile is not a subscription")?;
        Ok(self
            .vault()
            .read_subscription_endpoints(id)
            .map_err(store_error)?
            .into_iter()
            .enumerate()
            .map(|(index, endpoint)| SubscriptionEndpointInfo {
                protocol: net_manager_core::xray::endpoint_protocol(&endpoint.url),
                key: subscription::endpoint_key(&endpoint.url),
                is_backup: false,
                is_missing: false,
                in_pool: false,
                name: endpoint.name,
                active: index == meta.active_index,
            })
            .collect())
    }
    pub fn switch_subscription_endpoint(&self, id: &str, index: usize) -> Result<Profile, String> {
        self.runtime
            .restart_around(&self.root, &self.store(), id, || {
                subscription::switch_endpoint(
                    &self.vault(),
                    &self.store(),
                    id,
                    index,
                    local_port_available,
                )
                .map_err(subscription_error)?;
                self.public_profile(id)
            })
    }
    pub fn set_subscription_refresh_interval(
        &self,
        id: &str,
        minutes: Option<u32>,
    ) -> Result<Profile, String> {
        self.locked(|| {
            subscription::set_refresh_interval(&self.store(), id, minutes, unix_now())
                .map_err(subscription_error)?;
            self.public_profile(id)
        })
    }
    fn subscription_uris(&self, id: &str) -> Result<Vec<String>, String> {
        if self.profile(id)?.subscription.is_none() {
            return Err("Delay checks are available for subscriptions".into());
        }
        Ok(self
            .vault()
            .read_subscription_endpoints(id)
            .map_err(store_error)?
            .into_iter()
            .map(|e| e.url)
            .collect())
    }
    pub fn measure_subscription_delay(
        &self,
        id: &str,
        index: usize,
    ) -> Result<EndpointDelay, String> {
        let uri = self
            .subscription_uris(id)?
            .into_iter()
            .nth(index)
            .ok_or("Invalid endpoint index")?;
        let executable = self
            .runtime
            .managed_executable(&self.root)
            .ok_or("Install Xray to start this connection")?;
        let delay = executor()?.block_on(subscription::measure_endpoint_delay(
            &executable,
            &uri,
            std::time::Duration::from_secs(6),
        ));
        Ok(EndpointDelay {
            index,
            delay_ms: delay.ok(),
        })
    }
    pub fn measure_subscription_delays(&self, id: &str) -> Result<Vec<EndpointDelay>, String> {
        let uris = self.subscription_uris(id)?;
        let executable = self
            .runtime
            .managed_executable(&self.root)
            .ok_or("Install Xray to start this connection")?;
        executor()?.block_on(async move {
            let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
            let mut tasks = tokio::task::JoinSet::new();
            for (index, uri) in uris.into_iter().enumerate() {
                let permits = permits.clone();
                let executable = executable.clone();
                tasks.spawn(async move {
                    let _permit = permits.acquire_owned().await;
                    EndpointDelay {
                        index,
                        delay_ms: subscription::measure_endpoint_delay(
                            &executable,
                            &uri,
                            std::time::Duration::from_secs(6),
                        )
                        .await
                        .ok(),
                    }
                });
            }
            let mut results = Vec::new();
            while let Some(result) = tasks.join_next().await {
                results.push(result.map_err(|_| "Delay checks could not complete".to_string())?);
            }
            results.sort_by_key(|v| v.index);
            Ok(results)
        })
    }
    pub fn check_exit_ip(
        &self,
        via: ExitIpVia,
    ) -> Result<Vec<net_manager_core::exit_ip::ExitIpEntry>, String> {
        let socks = match via {
            ExitIpVia::Direct => None,
            ExitIpVia::Profile(id) => {
                let profile = self.profile(&id)?;
                if !self.runtime.is_running(&self.root, &profile)? {
                    return Err("Start the connection first".into());
                }
                profile.xray_socks_port
            }
            ExitIpVia::ProfileSocks(id) => {
                let profile = self.profile(&id)?;
                if !self.runtime.is_running(&self.root, &profile)? {
                    return Err("Start the connection first".into());
                }
                Some(
                    profile
                        .xray_socks_port
                        .ok_or("This connection has no local proxy port")?,
                )
            }
        };
        let client = net_manager_core::exit_ip::client(socks)
            .map_err(|_| "Exit IP check could not start".to_string())?;
        Ok(executor()?.block_on(net_manager_core::exit_ip::check_all(client)))
    }
    pub fn subscription_import_log(&self) -> String {
        let text = std::fs::read_to_string(self.root.join("runtime/logs/subscription-import.log"))
            .unwrap_or_default();
        let lines: Vec<_> = text.lines().collect();
        lines[lines.len().saturating_sub(64)..].join("\n")
    }
    pub fn generate_subscription_hwid(&self) -> Result<String, String> {
        self.locked(|| Ok(subscription::derive_hwid(&machine_seed(&self.root)?)))
    }
}
fn log_import(root: &Path, summary: &str, with_hwid: bool, success: bool) {
    // Never persist raw errors: upstream failures can contain provider-controlled
    // strings. Format/header names and a fixed outcome are sufficient here.
    let dir = root.join("runtime/logs");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("subscription-import.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let line = format!(
            "{} hwid={} {summary} result={}\n",
            unix_now(),
            if with_hwid { "sent" } else { "none" },
            if success { "ok" } else { "failed" }
        );
        let _ = std::io::Write::write_all(&mut file, line.as_bytes());
        let _ = net_manager_core::config_security::protect_path(&path);
    }
}
fn machine_seed(root: &Path) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    if let Ok(output) = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
    {
        if let Some(uuid) = String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|l| l.contains("\"IOPlatformUUID\""))
            .and_then(|l| l.rsplit('"').nth(1))
            .filter(|v| !v.is_empty())
        {
            return Ok(uuid.into());
        }
    }
    let path = root.join("device-id");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if !existing.trim().is_empty() {
            return Ok(existing.trim().into());
        }
    }
    let mut bytes = [0u8; 16];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|_| "Device ID unavailable")?,
        &mut bytes,
    )
    .map_err(|_| "Device ID unavailable")?;
    let seed: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::create_dir_all(root).map_err(store_error)?;
    let temp = root.join("device-id.tmp");
    std::fs::write(&temp, &seed).map_err(store_error)?;
    net_manager_core::config_security::protect_path(&temp).map_err(store_error)?;
    std::fs::rename(&temp, &path).map_err(store_error)?;
    Ok(seed)
}
