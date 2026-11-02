//! Opt-in auto candidate pool: subscription endpoints selected by display-name
//! filters and admitted only after their *real* exit country is verified
//! through a temporary unprivileged Xray (same loopback-SOCKS plumbing as the
//! delay probe). A node name is never proof of country — with
//! [`NodePoolSettings::verify_exit_country`] on, an exit-country mismatch
//! rejects the node even when the TLS handshake is healthy.
//!
//! The pool is opt-in (`SubscriptionMeta::node_pool`), bounded in filters,
//! candidates, concurrency, probe time and response body, and performs no
//! network traffic unless enabled. Members land in
//! `SubscriptionMeta::pool_keys` and join the ordered failover list after the
//! manual backups — never random selection, never the primary or pinned
//! nodes.
use crate::{
    config_vault::{ConfigVault, SubscriptionEndpoint},
    models::{EndpointRef, NodePoolSettings},
    profiles::{ProfileDocument, ProfileStore},
    subscription, xray,
};
use std::{
    future::Future,
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn failure(message: &str) -> io::Error {
    io::Error::other(message)
}

/// At most this many pool filters per subscription.
pub const MAX_POOL_FILTERS: usize = 8;
/// At most this many name substrings per filter.
pub const MAX_POOL_NAME_TERMS: usize = 4;
/// Longest accepted name substring.
pub const MAX_POOL_NAME_TERM_LEN: usize = 64;
/// Most endpoints a rebuild will probe in one pass.
pub const MAX_POOL_CANDIDATES: usize = 32;
/// Parallel exit probes during a rebuild.
pub const POOL_PROBE_PARALLELISM: usize = 4;
/// Per-endpoint probe budget (spawn + every attempt/endpoint URL).
pub const EXIT_COUNTRY_PROBE_TIMEOUT: Duration = Duration::from_secs(12);
/// Whole-rebuild deadline; on expiry the previous pool is kept.
pub const POOL_REBUILD_DEADLINE: Duration = Duration::from_secs(240);
/// Exit-country JSON responses are tiny; anything larger is rejected.
const MAX_EXIT_BODY_BYTES: usize = 16 * 1024;
/// First request warms the outbound; a second attempt covers cold starts.
const EXIT_PROBE_ATTEMPTS: usize = 2;

/// One external country-proof endpoint queried *through* the tunnel. Two
/// independent providers are probed in order; each yields an ISO-3166
/// alpha-2 `country` plus the observed exit `ip`.
///
/// These are the only third-party calls the pool feature ever makes, only
/// while an opted-in pool is rebuilt, and only through the candidate's own
/// loopback proxy — never directly and never at startup.
pub struct ExitCountryProbe {
    pub url: &'static str,
    pub country_field: &'static str,
    pub ip_field: &'static str,
}

/// Default providers, same pair the manual `~/vpn update` script used.
pub const EXIT_COUNTRY_PROBES: [ExitCountryProbe; 2] = [
    ExitCountryProbe {
        url: "https://api.country.is",
        country_field: "country",
        ip_field: "ip",
    },
    ExitCountryProbe {
        url: "https://ipinfo.io/json",
        country_field: "country",
        ip_field: "ip",
    },
];

/// Verified exit identity of one probed endpoint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitCountry {
    /// ISO-3166 alpha-2 code, upper case.
    pub country: String,
    /// Observed exit IP (diagnostics only; not persisted).
    pub ip: String,
}

/// Outcome for one name-matched endpoint during a rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NodePoolVerdict {
    /// Verified (and country-proven when required) — pool member.
    Member,
    /// Name matched but the node is the primary, a manual backup or a
    /// pinned endpoint: explicit choices are never swept into the pool.
    Explicit,
    /// Probe failed — node could not be reached through a temporary Xray.
    Unreachable,
    /// TLS/probe healthy but the observed exit country matches none of the
    /// filter's `exit_country` codes.
    WrongCountry,
    /// Beyond [`MAX_POOL_CANDIDATES`]; not probed.
    Skipped,
}

/// Per-candidate row of a [`NodePoolReport`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolProbeEntry {
    /// [`subscription::endpoint_key`] of the endpoint.
    pub key: String,
    pub name: String,
    pub verdict: NodePoolVerdict,
    /// Observed exit country when the probe answered.
    pub exit_country: Option<String>,
}

/// Result of a [`rebuild_node_pool`] run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodePoolReport {
    pub probed_at_unix: u64,
    /// Members written to `pool_keys` (or the members that would be
    /// written — `pool_changed`/`kept_previous` say which).
    pub members: Vec<EndpointRef>,
    /// Every name-matched candidate and its verdict, in subscription order.
    pub entries: Vec<PoolProbeEntry>,
    /// `pool_keys` actually changed.
    pub pool_changed: bool,
    /// No verified member was found; the previous pool is kept intact so a
    /// working pool is never replaced by an empty one.
    pub kept_previous: bool,
}

/// Country codes must be ISO-3166 alpha-2 (`CA`, `RU`, `DE`, …).
pub fn normalize_country_code(code: &str) -> Option<String> {
    let code = code.trim();
    if code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic()) {
        Some(code.to_ascii_uppercase())
    } else {
        None
    }
}

/// Validate pool settings: bounded counts, non-empty bounded terms, and —
/// while country verification is on — every filter declares the exit
/// country it accepts so a name alone can never admit a node. With
/// verification off at least one name term is required; a verify-less
/// match-everything pool would sweep the whole subscription into failover.
fn validate_pool_settings(settings: &NodePoolSettings) -> io::Result<()> {
    if settings.filters.is_empty() || settings.filters.len() > MAX_POOL_FILTERS {
        return Err(invalid("A node pool needs 1-8 filters"));
    }
    for filter in &settings.filters {
        if filter.name_contains.len() > MAX_POOL_NAME_TERMS {
            return Err(invalid("A pool filter takes at most 4 name terms"));
        }
        for term in &filter.name_contains {
            if term.trim().is_empty() || term.chars().count() > MAX_POOL_NAME_TERM_LEN {
                return Err(invalid("Pool name terms must be 1-64 characters"));
            }
        }
        if settings.verify_exit_country {
            match filter
                .exit_country
                .as_deref()
                .and_then(normalize_country_code)
            {
                Some(_) => {}
                None => return Err(invalid(
                    "Each pool filter needs an exit country (e.g. CA, RU) while verification is on",
                )),
            }
        }
        if !settings.verify_exit_country
            && (filter.name_contains.is_empty() || filter.exit_country.is_some())
        {
            return Err(invalid(
                "Unverified pool filters need names and cannot filter by exit country",
            ));
        }
    }
    Ok(())
}

/// Enable (or with `None` disable) the auto candidate pool. Disabling also
/// drops the stored members so nothing keeps failing over silently.
/// Validation is fail-closed; nothing is probed here — the next rebuild
/// does the work.
pub fn set_node_pool(
    store: &ProfileStore,
    id: &str,
    settings: Option<NodePoolSettings>,
) -> io::Result<ProfileDocument> {
    if let Some(settings) = &settings {
        validate_pool_settings(settings)?;
    }
    store.update_profile(id, |profile| {
        let subscription = profile
            .subscription
            .as_mut()
            .ok_or_else(|| invalid("Profile is not a subscription"))?;
        if settings.is_none() || subscription.node_pool != settings {
            subscription.pool_keys.clear();
        }
        subscription.node_pool = settings;
        Ok(())
    })
}

/// Which filters a display name matches; an empty `name_contains` matches
/// every name (used with `exit_country` for "any node egressing via CC").
fn matching_filters<'a>(
    endpoint: &SubscriptionEndpoint,
    settings: &'a NodePoolSettings,
) -> Vec<&'a crate::models::NodePoolFilter> {
    let name = endpoint.name.to_lowercase();
    settings
        .filters
        .iter()
        .filter(|filter| {
            filter.name_contains.is_empty()
                || filter
                    .name_contains
                    .iter()
                    .any(|term| name.contains(&term.to_lowercase()))
        })
        .collect()
}

/// Exit countries a matched filter set accepts (deduped, normalized).
fn expected_countries(filters: &[&crate::models::NodePoolFilter]) -> Vec<String> {
    let mut expected: Vec<String> = Vec::new();
    for filter in filters {
        if let Some(code) = filter
            .exit_country
            .as_deref()
            .and_then(normalize_country_code)
        {
            if !expected.contains(&code) {
                expected.push(code);
            }
        }
    }
    expected
}

/// Keys that must never be swept into the pool: the explicit primary, the
/// manual backups and every pinned endpoint.
fn explicit_keys(
    profile: &crate::models::Profile,
    endpoints: &[SubscriptionEndpoint],
) -> std::collections::HashSet<String> {
    let mut explicit: std::collections::HashSet<String> = profile
        .pinned_policies
        .iter()
        .map(|route| route.endpoint_key.clone())
        .collect();
    if let Some(key) = &profile.xray_dns.outbound_key {
        explicit.insert(key.clone());
    }
    if let Some(subscription) = profile.subscription.as_ref() {
        for backup in &subscription.backup_keys {
            explicit.insert(backup.key.clone());
        }
        if let Some(key) = subscription
            .active_key
            .clone()
            .filter(|key| subscription::valid_endpoint_key(key))
            .or_else(|| {
                endpoints
                    .get(subscription.active_index)
                    .map(|endpoint| subscription::endpoint_key(&endpoint.url))
            })
        {
            explicit.insert(key);
        }
    }
    explicit
}

/// Parse a country-probe response: `{"country": "cc", "ip": "a.b.c.d"}`.
/// Anything else (missing fields, malformed code/IP) is a miss.
pub fn parse_exit_country(body: &str, country_field: &str, ip_field: &str) -> Option<ExitCountry> {
    let value: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let country = normalize_country_code(value.get(country_field)?.as_str()?)?;
    let ip = value.get(ip_field)?.as_str()?;
    ip.parse::<std::net::IpAddr>().ok()?;
    Some(ExitCountry {
        country,
        ip: ip.to_string(),
    })
}

/// One bounded attempt against a probe URL through the proxied client.
async fn probe_once(
    client: &reqwest::Client,
    probe: &ExitCountryProbe,
    timeout: Duration,
) -> Option<ExitCountry> {
    let mut response = client.get(probe.url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut body = Vec::new();
    let read = async {
        while let Some(chunk) = response.chunk().await.ok()? {
            if chunk.len() > MAX_EXIT_BODY_BYTES - body.len() {
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        Some(body)
    };
    let body = tokio::time::timeout(timeout, read).await.ok()??;
    parse_exit_country(
        std::str::from_utf8(&body).ok()?,
        probe.country_field,
        probe.ip_field,
    )
}

/// Measure the real exit country of one subscription endpoint through a
/// temporary unprivileged Xray on a free loopback port. `command` must run
/// `xray run -config stdin:`; nothing reaches the network except the probe
/// URLs, through the candidate itself. Tries each [`ExitCountryProbe`] in
/// order, twice — the first request warms the outbound.
pub async fn measure_exit_country(
    uri: &str,
    command: tokio::process::Command,
    probes: &[ExitCountryProbe],
    timeout: Duration,
) -> Result<ExitCountry, String> {
    if probes.is_empty() {
        return Err("no exit-country probes configured".into());
    }
    measure_exit_country_with_config(
        |socks_port| {
            xray::generate_share_link_config(uri, socks_port)
                .map_err(|_| "invalid subscription endpoint".to_string())
        },
        command,
        probes,
        timeout,
    )
    .await
}

/// Like [`measure_exit_country`], with the probe config built by the caller
/// for the reserved SOCKS port so the probe runs the very config a
/// connection would use.
pub async fn measure_exit_country_with_config(
    build_config: impl FnOnce(u16) -> Result<serde_json::Value, String>,
    command: tokio::process::Command,
    probes: &[ExitCountryProbe],
    timeout: Duration,
) -> Result<ExitCountry, String> {
    if probes.is_empty() {
        return Err("no exit-country probes configured".into());
    }
    let mut process = None;
    let result = tokio::time::timeout(timeout, async {
        let client =
            subscription::temporary_socks_client(build_config, command, timeout, &mut process)
                .await?;
        let per_request = timeout
            .checked_div(2)
            .unwrap_or(timeout)
            .max(Duration::from_secs(1));
        for _ in 0..EXIT_PROBE_ATTEMPTS {
            for probe in probes {
                if let Some(exit) = probe_once(&client, probe, per_request).await {
                    return Ok(exit);
                }
            }
        }
        Err("exit-country probe failed".to_string())
    })
    .await;
    if let Some(mut process) = process {
        process.stop().await?;
    }
    result.map_err(|_| "exit-country probe timed out".to_string())?
}

/// Rebuild the auto candidate pool for a subscription profile.
///
/// Name-matched endpoints that are not already explicit choices (primary,
/// manual backup, pinned) are probed with a temporary Xray; with
/// `verify_exit_country` the observed country must match a filter's
/// `exit_country`. Members are stored — in subscription order — into
/// `pool_keys`. If no usable candidate answers, eligible previous members are
/// retained; fresh country mismatches and newly explicit nodes are removed.
/// Selection changes during probing refuse the atomic profile update.
///
/// `spawn` supplies the probe command per endpoint (real caller:
/// `xray run -config stdin:`); tests inject a fake runner — no network.
pub async fn rebuild_node_pool(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    probes: &[ExitCountryProbe],
    timeout: Duration,
    spawn: impl Fn(&SubscriptionEndpoint) -> io::Result<tokio::process::Command> + Sync,
) -> io::Result<NodePoolReport> {
    rebuild_node_pool_with(vault, store, id, |endpoint| {
        let command = spawn(endpoint);
        let url = endpoint.url.clone();
        async move {
            let mut command = command.map_err(|_| "Xray executable unavailable".to_string())?;
            command.args(["run", "-config", "stdin:"]);
            measure_exit_country(&url, command, probes, timeout).await
        }
    })
    .await
}

/// [`rebuild_node_pool`] with the per-endpoint probe injected — tests
/// supply a deterministic probe and never touch the network.
pub async fn rebuild_node_pool_with<Probe, ProbeFuture>(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    probe: Probe,
) -> io::Result<NodePoolReport>
where
    Probe: Fn(&SubscriptionEndpoint) -> ProbeFuture + Sync,
    ProbeFuture: Future<Output = Result<ExitCountry, String>> + Send,
{
    let document = store.load()?;
    let profile = document
        .profiles
        .iter()
        .find(|p| p.id == id && p.subscription.is_some())
        .cloned()
        .ok_or_else(|| invalid("Profile is not a subscription"))?;
    let subscription = profile.subscription.clone().expect("checked above");
    let settings = subscription
        .node_pool
        .clone()
        .ok_or_else(|| invalid("Node pool is not enabled for this subscription"))?;
    validate_pool_settings(&settings)?;

    let endpoints = vault.read_subscription_endpoints(id)?;
    let explicit = explicit_keys(&profile, &endpoints);

    // Collect name-matched candidates in subscription order. Endpoints the
    // filters do not name are invisible to the pool; explicit matches are
    // reported, never swept.
    let mut entries: Vec<PoolProbeEntry> = Vec::new();
    let mut candidates: Vec<(SubscriptionEndpoint, Vec<String>)> = Vec::new();
    let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for endpoint in &endpoints {
        let key = subscription::endpoint_key(&endpoint.url);
        if !seen_keys.insert(key.clone()) {
            continue;
        }
        let filters = matching_filters(endpoint, &settings);
        if filters.is_empty() {
            continue;
        }
        if explicit.contains(&key) {
            entries.push(PoolProbeEntry {
                key,
                name: endpoint.name.clone(),
                verdict: NodePoolVerdict::Explicit,
                exit_country: None,
            });
            continue;
        }
        if candidates.len() >= MAX_POOL_CANDIDATES {
            entries.push(PoolProbeEntry {
                key,
                name: endpoint.name.clone(),
                verdict: NodePoolVerdict::Skipped,
                exit_country: None,
            });
            continue;
        }
        candidates.push((endpoint.clone(), expected_countries(&filters)));
    }

    // Probe with bounded concurrency and a whole-run deadline. Each future
    // resolves to its candidate index plus verdict.
    use futures::stream::{self, StreamExt};
    let verify = settings.verify_exit_country;
    let probe_futures = candidates
        .into_iter()
        .enumerate()
        .map(|(index, (endpoint, expected))| {
            let probing = verify.then(|| probe(&endpoint));
            let key = subscription::endpoint_key(&endpoint.url);
            let name = endpoint.name;
            async move {
                let (verdict, exit_country) = match probing {
                    None => (NodePoolVerdict::Member, None),
                    Some(probing) => match probing.await {
                        Ok(exit)
                            if verify && !expected.iter().any(|code| code == &exit.country) =>
                        {
                            (NodePoolVerdict::WrongCountry, Some(exit.country))
                        }
                        Ok(exit) => (NodePoolVerdict::Member, Some(exit.country)),
                        Err(_) => (NodePoolVerdict::Unreachable, None),
                    },
                };
                (
                    index,
                    PoolProbeEntry {
                        key,
                        name,
                        verdict,
                        exit_country,
                    },
                )
            }
        });
    let mut results: Vec<(usize, PoolProbeEntry)> = match tokio::time::timeout(
        POOL_REBUILD_DEADLINE,
        stream::iter(probe_futures)
            .buffer_unordered(POOL_PROBE_PARALLELISM)
            .collect::<Vec<_>>(),
    )
    .await
    {
        Ok(results) => results,
        Err(_) => {
            return Err(failure(
                "node pool rebuild timed out; the previous pool is kept",
            ))
        }
    };
    results.sort_by_key(|(index, _)| *index);
    let mut members: Vec<EndpointRef> = Vec::new();
    let reserved = 1 + subscription.backup_keys.len();
    let capacity = subscription::MAX_FAILOVER_NODES.saturating_sub(reserved);
    for (_, mut entry) in results {
        if entry.verdict == NodePoolVerdict::Member && members.len() >= capacity {
            entry.verdict = NodePoolVerdict::Skipped;
        }
        if entry.verdict == NodePoolVerdict::Member {
            members.push(EndpointRef {
                key: entry.key.clone(),
                name: entry.name.clone(),
            });
        }
        entries.push(entry);
    }

    let previous = subscription.pool_keys.clone();
    let mut kept_previous = false;
    if members.is_empty() {
        // Preserve unavailable candidates, not newly explicit or positively
        // disproved members. Missing transports may return on refresh.
        let mut retained = std::collections::HashSet::new();
        members = previous
            .iter()
            .filter(|node| {
                subscription::valid_endpoint_key(&node.key)
                    && !explicit.contains(&node.key)
                    && retained.insert(node.key.clone())
                    && !entries.iter().any(|entry| {
                        entry.key == node.key && entry.verdict == NodePoolVerdict::WrongCountry
                    })
                    && endpoints
                        .iter()
                        .find(|endpoint| subscription::endpoint_key(&endpoint.url) == node.key)
                        .is_none_or(|endpoint| !matching_filters(endpoint, &settings).is_empty())
            })
            .take(capacity)
            .cloned()
            .collect();
        kept_previous = !members.is_empty();
    }
    let report = NodePoolReport {
        probed_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        members: members.clone(),
        entries,
        pool_changed: false,
        kept_previous,
    };
    if members == previous {
        return Ok(report);
    }
    store.update_profile(id, |current| {
        let current_subscription = current
            .subscription
            .as_mut()
            .ok_or_else(|| invalid("Profile is no longer a subscription"))?;
        if current_subscription.node_pool.as_ref() != Some(&settings)
            || current_subscription.url != subscription.url
            || current_subscription.active_key != subscription.active_key
            || current_subscription.active_index != subscription.active_index
            || current_subscription.backup_keys != subscription.backup_keys
            || current.pinned_policies != profile.pinned_policies
            || current.xray_dns.outbound_key != profile.xray_dns.outbound_key
        {
            return Err(failure(
                "Node selection changed during probing; rebuild the pool again",
            ));
        }
        current_subscription.pool_keys = members;
        Ok(())
    })?;
    Ok(NodePoolReport {
        pool_changed: true,
        ..report
    })
}

#[cfg(test)]
mod tests;
