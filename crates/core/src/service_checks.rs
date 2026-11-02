//! Explicit, user-configured HTTPS HEAD transport checks.
//!
//! Checks never select nodes, mutate routing, or request tunnel recovery.
//! Manual checks run only through current explicitly pinned endpoints.
//! Results contain configured names, stable identifiers, and bounded
//! diagnostics, but never URLs, response bodies, or raw errors.

use crate::{
    config_vault::{ConfigVault, SubscriptionEndpoint},
    models::{
        Profile, ServiceCheck, ServiceCheckOutcome, ServiceCheckResult, TunnelBackend, XraySockopts,
    },
    subscription, xray,
};
use futures::{stream::FuturesUnordered, StreamExt};
use std::{
    collections::HashSet,
    io,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const SERVICE_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
pub const SERVICE_CHECK_INTERVAL: Duration = Duration::from_secs(60);
pub const MAX_SERVICE_CHECKS: usize = 16;
pub const SERVICE_CHECK_FAILURE_THRESHOLD: u32 = 3;

const MAX_URL_BYTES: usize = 2048;
const MAX_ENDPOINT_WORKERS: usize = 4;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parse without exposing either the input or the parser's error.
///
/// Query strings are allowed by the shared contract. Configuration editors
/// must warn against secrets and side-effect/webhook destinations.
fn service_url(value: &str) -> io::Result<url::Url> {
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
        || value.contains('\\')
    {
        return Err(invalid("Invalid service check URL"));
    }

    // Check the original authority as well as the parsed URL. This rejects
    // empty userinfo and special-scheme normalization of an absent authority.
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .ok_or_else(|| invalid("Invalid service check URL"))?;

    let url = url::Url::parse(value).map_err(|_| invalid("Invalid service check URL"))?;

    if url.scheme() != "https"
        || authority.is_empty()
        || authority.contains('@')
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default().is_none_or(|port| port == 0)
    {
        return Err(invalid(
            "Service checks require HTTPS with a host and without credentials or fragments",
        ));
    }

    Ok(url)
}

pub fn validate_service_checks(checks: &[ServiceCheck]) -> io::Result<()> {
    if checks.len() > MAX_SERVICE_CHECKS {
        return Err(invalid("A profile supports at most 16 service checks"));
    }

    let mut ids = HashSet::with_capacity(checks.len());
    for check in checks {
        if check.id.is_empty()
            || check.id.len() > 64
            || !check
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !ids.insert(check.id.as_str())
        {
            return Err(invalid("Service check IDs must be valid and unique"));
        }

        if check.name.trim().is_empty()
            || check.name.chars().count() > 80
            || check.name.chars().any(char::is_control)
        {
            return Err(invalid(
                "Service check names must contain 1-80 characters without controls",
            ));
        }

        service_url(&check.url)?;

        if !subscription::valid_endpoint_key(&check.endpoint_key) {
            return Err(invalid("Invalid service check endpoint key"));
        }
    }

    Ok(())
}

/// Static validation only: never reads endpoint sidecars or resolves Xray.
///
/// A saved check may outlive its explicit pin or subscription endpoint.
/// Such a check remains valid configuration but cannot be probed.
pub fn validate_profile_service_checks(profile: &Profile) -> io::Result<()> {
    validate_service_checks(&profile.xray_service_checks)?;

    if !profile.xray_service_checks.is_empty()
        && (profile.backend != TunnelBackend::Xray || profile.subscription.is_none())
    {
        return Err(invalid(
            "Service checks require an Xray subscription profile",
        ));
    }

    Ok(())
}

pub fn service_probe_client(socks_port: u16) -> Result<reqwest::Client, String> {
    if socks_port == 0 {
        return Err("Service check proxy is unavailable".into());
    }

    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
        .map_err(|_| "Service check proxy is unavailable".to_string())?;

    reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(SERVICE_CHECK_TIMEOUT)
        .timeout(SERVICE_CHECK_TIMEOUT)
        .build()
        .map_err(|_| "Service check client is unavailable".to_string())
}

fn observation(
    check: &ServiceCheck,
    outcome: ServiceCheckOutcome,
    http_status: Option<u16>,
    latency_ms: Option<u64>,
) -> ServiceCheckResult {
    record_service_check(
        None,
        ServiceCheckResult {
            id: check.id.clone(),
            name: check.name.clone(),
            endpoint_key: check.endpoint_key.clone(),
            outcome,
            http_status,
            latency_ms,
            checked_at_unix: now_unix(),
            consecutive_failures: 0,
            degraded: false,
        },
    )
}

/// Incorporate exactly one fresh observation.
///
/// The caller owns configuration identity: discard prior observations when
/// the configured URL changes. Results intentionally do not contain URLs.
pub fn record_service_check(
    previous: Option<&ServiceCheckResult>,
    mut current: ServiceCheckResult,
) -> ServiceCheckResult {
    use ServiceCheckOutcome::*;

    match current.outcome {
        Http => {
            current.consecutive_failures = 0;
            current.degraded = false;
        }
        Unavailable => {
            current.http_status = None;
            current.latency_ms = None;
            current.consecutive_failures = 0;
            current.degraded = false;
        }
        Timeout | TlsError | TransportError => {
            let previous_failures = previous
                .filter(|previous| {
                    previous.id == current.id
                        && previous.endpoint_key == current.endpoint_key
                        && matches!(previous.outcome, Timeout | TlsError | TransportError)
                })
                .map_or(0, |previous| previous.consecutive_failures);

            current.http_status = None;
            current.latency_ms = None;
            current.consecutive_failures = previous_failures.saturating_add(1);
            current.degraded = current.consecutive_failures >= SERVICE_CHECK_FAILURE_THRESHOLD;
        }
    }

    current
}

/// HEAD only. The client must come from service_probe_client() or the
/// dedicated temporary_socks_client() path below, both redirect-disabled.
///
/// No request authentication, cookies, custom headers, body, or retries.
pub async fn probe_service_check(
    check: &ServiceCheck,
    client: &reqwest::Client,
) -> ServiceCheckResult {
    let url = match service_url(&check.url) {
        Ok(url) => url,
        Err(_) => {
            return observation(check, ServiceCheckOutcome::TransportError, None, None);
        }
    };

    send_head(check, client, url).await
}

fn transport_outcome(error: &reqwest::Error) -> ServiceCheckOutcome {
    if error.is_timeout() {
        return ServiceCheckOutcome::Timeout;
    }
    let mut cause: &(dyn std::error::Error + 'static) = error;
    loop {
        if cause.is::<rustls::Error>() {
            return ServiceCheckOutcome::TlsError;
        }
        // io::Error::source skips the boxed error itself. Inspect get_ref
        // before following source, preserving typed rustls certificate errors.
        if let Some(inner) = cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            cause = inner;
        } else if let Some(source) = cause.source() {
            cause = source;
        } else {
            break;
        }
    }
    // SOCKS remote DNS failures cannot reliably be separated from transport errors.
    ServiceCheckOutcome::TransportError
}

/// Kept separate so synthetic loopback tests can exercise the actual HEAD
/// transport without weakening production HTTPS validation.
async fn send_head(
    check: &ServiceCheck,
    client: &reqwest::Client,
    url: url::Url,
) -> ServiceCheckResult {
    let started = Instant::now();

    match tokio::time::timeout(SERVICE_CHECK_TIMEOUT, client.head(url).send()).await {
        Ok(Ok(response)) => observation(
            check,
            ServiceCheckOutcome::Http,
            Some(response.status().as_u16()),
            Some(started.elapsed().as_millis().min(u64::MAX as u128) as u64),
        ),
        Ok(Err(error)) => observation(check, transport_outcome(&error), None, None),
        Err(_) => observation(check, ServiceCheckOutcome::Timeout, None, None),
    }
}

pub fn service_check_is_bound(profile: &Profile, key: &str) -> bool {
    profile
        .pinned_policies
        .iter()
        .any(|pin| pin.endpoint_key == key && !pin.selectors.is_empty())
        || profile.xray_dns.outbound_key.as_deref() == Some(key)
}

/// Build a dedicated single-node config from the current endpoint.
///
/// Reuse the existing endpoint reduction and profile sockopt helpers, but
/// never apply profile routing policies. Imported routing, DNS, balancers,
/// direct outbounds, and observatories cannot influence these requests.
fn node_probe_config(
    uri: &str,
    socks_port: u16,
    sockopts: Option<&XraySockopts>,
) -> Result<serde_json::Value, String> {
    use serde_json::json;

    let mut outbound = xray::multinode_outbound(uri, "service-check-node")
        .map_err(|_| "Service check endpoint is invalid".to_string())?;

    if !matches!(outbound["protocol"].as_str(), Some("vless" | "hysteria")) {
        return Err("Service check endpoint is invalid".into());
    }

    // Keep no imported outbound-chaining references. The selected endpoint
    // itself is the only possible application-traffic outbound.
    let object = outbound
        .as_object_mut()
        .ok_or_else(|| "Service check endpoint is invalid".to_string())?;
    object.remove("proxySettings");

    if let Some(stream) = object.get_mut("streamSettings") {
        let stream = stream
            .as_object_mut()
            .ok_or_else(|| "Service check endpoint is invalid".to_string())?;
        if let Some(options) = stream.get_mut("sockopt") {
            let options = options
                .as_object_mut()
                .ok_or_else(|| "Service check endpoint is invalid".to_string())?;
            options.remove("dialerProxy");
        }
    }

    if let Some(sockopts) = sockopts {
        xray::apply_stream_sockopts(&mut outbound, sockopts)
            .map_err(|_| "Service check socket settings are invalid".to_string())?;
    }

    Ok(json!({
        "log": { "loglevel": "none" },
        "inbounds": [{
            "tag": "service-check-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": false
            }
        }],
        "outbounds": [outbound],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{
                "type": "field",
                "inboundTag": ["service-check-in"],
                "network": "tcp",
                "outboundTag": "service-check-node"
            }]
        }
    }))
}

struct EndpointGroup<'a> {
    endpoint: &'a SubscriptionEndpoint,
    checks: Vec<(usize, &'a ServiceCheck)>,
}

fn endpoint_groups<'a>(
    profile: &Profile,
    selected: &[&'a ServiceCheck],
    endpoints: &'a [SubscriptionEndpoint],
) -> Vec<EndpointGroup<'a>> {
    let mut groups: Vec<EndpointGroup<'a>> = Vec::new();

    for (result_index, &check) in selected.iter().enumerate() {
        if !service_check_is_bound(profile, &check.endpoint_key) {
            continue;
        }

        let Some(endpoint_index) = subscription::key_index(endpoints, &check.endpoint_key) else {
            continue;
        };
        let endpoint = &endpoints[endpoint_index];

        if let Some(group) = groups
            .iter_mut()
            .find(|group| std::ptr::eq(group.endpoint, endpoint))
        {
            group.checks.push((result_index, check));
        } else {
            groups.push(EndpointGroup {
                endpoint,
                checks: vec![(result_index, check)],
            });
        }
    }

    groups
}

fn group_failures(
    group: &EndpointGroup<'_>,
    outcome: ServiceCheckOutcome,
) -> Vec<(usize, ServiceCheckResult)> {
    group
        .checks
        .iter()
        .map(|&(index, check)| (index, observation(check, outcome, None, None)))
        .collect()
}

/// One temporary child per endpoint; serial requests within that child.
///
/// The child guard is outside every timeout. Startup timeout cancellation
/// releases its mutable borrow before bounded stop() is awaited. Cancelling
/// the whole worker still invokes TemporaryXray's cancellation guard.
async fn run_endpoint_group(
    group: EndpointGroup<'_>,
    sockopts: Option<&XraySockopts>,
    spawn: &(impl Fn() -> Result<tokio::process::Command, String> + Sync),
    startup_timeout: Duration,
) -> Result<Vec<(usize, ServiceCheckResult)>, String> {
    let mut command = match spawn() {
        Ok(command) => command,
        Err(_) => {
            return Ok(group_failures(&group, ServiceCheckOutcome::TransportError));
        }
    };
    command.args(["run", "-config", "stdin:"]);

    let mut process = None;
    let startup = tokio::time::timeout(
        startup_timeout,
        subscription::temporary_socks_client(
            |port| node_probe_config(&group.endpoint.url, port, sockopts),
            command,
            SERVICE_CHECK_TIMEOUT,
            &mut process,
        ),
    )
    .await;

    let results = match startup {
        Ok(Ok(client)) => {
            let mut results = Vec::with_capacity(group.checks.len());
            for &(index, check) in &group.checks {
                results.push((index, probe_service_check(check, &client).await));
            }
            results
        }
        Ok(Err(_)) => group_failures(&group, ServiceCheckOutcome::TransportError),
        Err(_) => group_failures(&group, ServiceCheckOutcome::Timeout),
    };

    if let Some(mut process) = process {
        process
            .stop()
            .await
            .map_err(|_| "Service check Xray cleanup failed".to_string())?;
    }

    Ok(results)
}

/// Run all configured checks, or an explicit selected subset.
///
/// - Empty configuration/selection does not read the vault or resolve Xray.
/// - Unknown IDs are rejected before any network/process work.
/// - Unbound or missing pins return Unavailable without resolving Xray.
/// - Only current endpoints referenced by explicit domain/DNS pins run.
/// - At most four endpoint workers run concurrently.
/// - Startup is bounded; every HEAD has its own five-second deadline.
/// - Results preserve configured check order, independent of worker order.
///
/// `spawn` returns a bare, unprivileged executable command. This module
/// appends `run -config stdin:` exactly once.
pub async fn check_profile_services(
    vault: &ConfigVault,
    profile: &Profile,
    check_ids: Option<&[String]>,
    spawn: impl Fn() -> Result<tokio::process::Command, String> + Sync,
) -> Result<Vec<ServiceCheckResult>, String> {
    if check_ids.is_some_and(|ids| ids.is_empty()) {
        return Ok(Vec::new());
    }

    if let Some(ids) = check_ids {
        if ids.iter().any(|id| {
            !profile
                .xray_service_checks
                .iter()
                .any(|check| check.id == *id)
        }) {
            return Err("Unknown service check selection".into());
        }
    }

    if profile.xray_service_checks.is_empty() {
        return Ok(Vec::new());
    }

    validate_profile_service_checks(profile)
        .map_err(|_| "Invalid service check configuration".to_string())?;

    let selected: Vec<_> = profile
        .xray_service_checks
        .iter()
        .filter(|check| check_ids.is_none_or(|ids| ids.iter().any(|id| id == &check.id)))
        .collect();

    if selected.is_empty() {
        return Ok(Vec::new());
    }

    let mut results: Vec<_> = selected
        .iter()
        .map(|check| observation(check, ServiceCheckOutcome::Unavailable, None, None))
        .collect();

    if !selected
        .iter()
        .any(|check| service_check_is_bound(profile, &check.endpoint_key))
    {
        return Ok(results);
    }

    let endpoints = vault
        .read_subscription_endpoints(&profile.id)
        .map_err(|_| "Service check endpoints are unavailable".to_string())?;
    let groups = endpoint_groups(profile, &selected, &endpoints);
    let spawn = &spawn;
    let sockopts = profile.xray_sockopts.as_ref();

    // Collect all workers before propagating cleanup errors. This prevents
    // an early error from cancelling siblings instead of awaiting their stop.
    let mut queued = groups.into_iter();
    let mut workers = FuturesUnordered::new();
    let mut completed = Vec::new();
    loop {
        while workers.len() < MAX_ENDPOINT_WORKERS {
            let Some(group) = queued.next() else { break };
            workers.push(run_endpoint_group(
                group,
                sockopts,
                spawn,
                SERVICE_CHECK_TIMEOUT,
            ));
        }
        let Some(result) = workers.next().await else {
            break;
        };
        completed.push(result);
    }

    for group in completed {
        for (index, result) in group? {
            results[index] = result;
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{PinnedRoute, SubscriptionMeta},
        profiles::{ProfileDocument, ProfileStore, PROFILE_DOCUMENT_VERSION},
    };

    fn endpoint(host: &str) -> SubscriptionEndpoint {
        SubscriptionEndpoint {
            url: format!("vless://synthetic-id@{host}:443?security=tls#Synthetic"),
            name: "Synthetic node".into(),
        }
    }

    fn check(id: &str, key: &str) -> ServiceCheck {
        ServiceCheck {
            id: id.into(),
            name: "Synthetic availability".into(),
            url: "https://service.example.test/status".into(),
            endpoint_key: key.into(),
            background: false,
        }
    }

    fn subscription() -> SubscriptionMeta {
        serde_json::from_value(serde_json::json!({
            "url": "https://subscription.example.test/synthetic",
            "hwid": "",
            "endpointCount": 1,
            "activeIndex": 0
        }))
        .unwrap()
    }

    fn profile(checks: Vec<ServiceCheck>) -> Profile {
        Profile {
            id: "service-checks".into(),
            name: "Synthetic checks".into(),
            backend: TunnelBackend::Xray,
            config_path: "service-checks.json".into(),
            subscription: Some(subscription()),
            xray_service_checks: checks,
            ..Default::default()
        }
    }

    fn pin(profile: &mut Profile, key: &str) {
        profile.pinned_policies.push(PinnedRoute {
            selectors: vec!["domain:service.example.test".into()],
            endpoint_key: key.into(),
            missing: false,
        });
    }

    #[test]
    fn url_safety_rejects_unsafe_forms_without_echoing_input() {
        for url in [
            "http://example.test/private-secret",
            "file:///private-secret",
            "https://user:private-secret@example.test/",
            "https://@example.test/private-secret",
            "https:///private-secret",
            "https://example.test/#private-secret",
            "https://example.test:0/private-secret",
            "https://example.test:70000/private-secret",
            "https://example.test/\nprivate-secret",
            " https://example.test/private-secret",
            "https:\\\\example.test\\private-secret",
            "private-secret",
        ] {
            let mut check = check("one", "1111111111111111");
            check.url = url.into();
            let error = validate_service_checks(&[check]).unwrap_err();
            assert!(!error.to_string().contains("private-secret"));
        }

        let mut check = check("one", "1111111111111111");
        check.url = "https://example.test/status?region=synthetic".into();
        validate_service_checks(&[check]).unwrap();
    }

    #[test]
    fn validation_enforces_actual_boundaries_and_control_rejection() {
        let mut boundary = check(&"a".repeat(64), "1111111111111111");
        boundary.name = "n".repeat(80);
        let prefix = "https://example.test/";
        boundary.url = format!("{prefix}{}", "x".repeat(MAX_URL_BYTES - prefix.len()));
        validate_service_checks(std::slice::from_ref(&boundary)).unwrap();

        let mut invalid_id = boundary.clone();
        invalid_id.id.push('a');
        assert!(validate_service_checks(&[invalid_id]).is_err());

        let mut invalid_name = boundary.clone();
        invalid_name.name.push('n');
        assert!(validate_service_checks(&[invalid_name]).is_err());

        let mut invalid_url = boundary.clone();
        invalid_url.url.push('x');
        assert!(validate_service_checks(&[invalid_url]).is_err());

        for name in [" ", "name\nvalue", "name\u{7f}value"] {
            let mut invalid_name = boundary.clone();
            invalid_name.name = name.into();
            assert!(validate_service_checks(&[invalid_name]).is_err());
        }

        for id in ["", "contains space", "nonascii-é", "contains/slash"] {
            let mut invalid_id = boundary.clone();
            invalid_id.id = id.into();
            assert!(validate_service_checks(&[invalid_id]).is_err());
        }

        for key in ["", "ABCDEF0123456789", "111111111111111", "not-a-key"] {
            let mut invalid_key = boundary.clone();
            invalid_key.endpoint_key = key.into();
            assert!(validate_service_checks(&[invalid_key]).is_err());
        }

        let sixteen: Vec<_> = (0..MAX_SERVICE_CHECKS)
            .map(|index| check(&format!("check-{index}"), "1111111111111111"))
            .collect();
        validate_service_checks(&sixteen).unwrap();

        let mut seventeen = sixteen;
        seventeen.push(check("seventeenth", "1111111111111111"));
        assert!(validate_service_checks(&seventeen).is_err());

        let duplicate = check("duplicate", "1111111111111111");
        assert!(validate_service_checks(&[duplicate.clone(), duplicate]).is_err());
    }

    #[test]
    fn https_checks_persist_and_invalid_save_preserves_existing_document() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let valid = profile(vec![check("one", "1111111111111111")]);

        let saved = store.upsert(valid.clone()).unwrap();
        assert_eq!(store.load().unwrap(), saved);

        let mut invalid_document = saved.clone();
        invalid_document.profiles[0].xray_service_checks[0].url =
            "http://example.test/private-secret".into();
        let error = store.save(&invalid_document).unwrap_err();
        assert!(!error.to_string().contains("private-secret"));
        assert_eq!(store.load().unwrap(), saved);

        // Empty checks remain legal on non-Xray and legacy profiles.
        let mut other_backend = valid;
        other_backend.backend = TunnelBackend::WireGuard;
        assert!(validate_profile_service_checks(&other_backend).is_err());
        other_backend.xray_service_checks.clear();
        validate_profile_service_checks(&other_backend).unwrap();
    }

    #[test]
    fn invalid_service_configuration_is_rejected_on_load_and_before_new_save() {
        let dir = tempfile::tempdir().unwrap();
        let mut invalid_profile = profile(vec![check("one", "1111111111111111")]);
        invalid_profile.xray_service_checks[0].url = "http://example.test/private-secret".into();
        let document = ProfileDocument {
            version: PROFILE_DOCUMENT_VERSION,
            profiles: vec![invalid_profile],
        };

        let new_parent = dir.path().join("not-created");
        let new_store = ProfileStore::new(new_parent.join("profiles.json"));
        assert!(new_store.save(&document).is_err());
        assert!(!new_parent.exists());

        let path = dir.path().join("invalid.json");
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let error = ProfileStore::new(path).load().unwrap_err();
        assert!(!error.to_string().contains("private-secret"));
    }

    #[tokio::test]
    async fn empty_selection_and_unbound_checks_never_resolve_xray_or_read_vault() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("not-created");
        let vault = ConfigVault::new(&root);

        let empty = check_profile_services(&vault, &Profile::default(), None, || {
            panic!("empty configuration must not resolve Xray")
        })
        .await
        .unwrap();
        assert!(empty.is_empty());

        let profile = profile(vec![check("one", "1111111111111111")]);
        let selection: Vec<String> = Vec::new();
        assert!(
            check_profile_services(&vault, &profile, Some(&selection), || panic!(
                "empty selection must not resolve Xray"
            ),)
            .await
            .unwrap()
            .is_empty()
        );

        let results = check_profile_services(&vault, &profile, None, || {
            panic!("unbound check must not resolve Xray")
        })
        .await
        .unwrap();
        assert_eq!(results[0].outcome, ServiceCheckOutcome::Unavailable);
        assert_eq!(results[0].consecutive_failures, 0);
        assert!(!results[0].degraded);
        assert!(!root.exists());

        let unknown = vec!["unknown".into()];
        assert!(
            check_profile_services(&vault, &profile, Some(&unknown), || panic!(
                "unknown selection must not resolve Xray"
            ),)
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn missing_pin_does_not_retarget_to_existing_active_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let active = endpoint("active.example.test");
        let missing = endpoint("missing.example.test");
        let missing_key = subscription::endpoint_key(&missing.url);

        let mut profile = profile(vec![check("missing", &missing_key)]);
        pin(&mut profile, &missing_key);
        vault
            .store_subscription_endpoints(&profile.id, &[active])
            .unwrap();

        let results = check_profile_services(&vault, &profile, None, || {
            panic!("missing endpoint must not resolve Xray")
        })
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].endpoint_key, missing_key);
        assert_eq!(results[0].outcome, ServiceCheckOutcome::Unavailable);
        assert_eq!(results[0].http_status, None);
    }

    #[test]
    fn node_config_has_one_proxy_no_direct_route_and_preserves_sockopts() {
        let endpoint = endpoint("selected.example.test");
        let sockopts = XraySockopts {
            tcp_keep_alive_idle: Some(30),
            tcp_keep_alive_interval: Some(10),
            tcp_user_timeout: Some(5000),
            tcp_no_delay: true,
        };
        let config = node_probe_config(&endpoint.url, 12345, Some(&sockopts)).unwrap();

        let outbounds = config["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 1);
        assert_eq!(outbounds[0]["protocol"], "vless");
        assert_eq!(outbounds[0]["tag"], "service-check-node");
        assert_eq!(
            outbounds[0]["streamSettings"]["sockopt"],
            serde_json::json!({
                "tcpKeepAliveIdle": 30,
                "tcpKeepAliveInterval": 10,
                "tcpUserTimeout": 5000,
                "tcpNoDelay": true
            })
        );
        assert!(outbounds[0].get("proxySettings").is_none());
        assert_eq!(
            config["routing"]["rules"][0]["outboundTag"],
            "service-check-node"
        );
        assert!(config["routing"].get("balancers").is_none());
        assert!(config.get("dns").is_none());
        assert!(config.get("observatory").is_none());
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["settings"]["udp"], false);
    }

    #[test]
    fn streaks_degrade_at_three_reset_on_http_or_unavailable_and_saturate() {
        let check = check("one", "1111111111111111");
        let first = observation(&check, ServiceCheckOutcome::TransportError, None, None);
        assert_eq!(first.consecutive_failures, 1);
        assert!(!first.degraded);

        let second = record_service_check(
            Some(&first),
            observation(&check, ServiceCheckOutcome::Timeout, None, None),
        );
        assert_eq!(second.consecutive_failures, 2);
        assert!(!second.degraded);

        let third = record_service_check(
            Some(&second),
            observation(&check, ServiceCheckOutcome::TlsError, None, None),
        );
        assert_eq!(third.consecutive_failures, 3);
        assert!(third.degraded);

        let http = record_service_check(
            Some(&third),
            observation(&check, ServiceCheckOutcome::Http, Some(403), Some(7)),
        );
        assert_eq!(http.http_status, Some(403));
        assert_eq!(http.consecutive_failures, 0);
        assert!(!http.degraded);

        let unavailable = record_service_check(
            Some(&third),
            observation(&check, ServiceCheckOutcome::Unavailable, None, None),
        );
        assert_eq!(unavailable.consecutive_failures, 0);
        assert!(!unavailable.degraded);
        assert_eq!(unavailable.http_status, None);

        let mut saturated = third;
        saturated.consecutive_failures = u32::MAX;
        let saturated = record_service_check(
            Some(&saturated),
            observation(&check, ServiceCheckOutcome::Timeout, None, None),
        );
        assert_eq!(saturated.consecutive_failures, u32::MAX);

        let mut rebound = check.clone();
        rebound.endpoint_key = "2222222222222222".into();
        let rebound = record_service_check(
            Some(&second),
            observation(&rebound, ServiceCheckOutcome::Timeout, None, None),
        );
        assert_eq!(rebound.consecutive_failures, 1);
    }

    #[tokio::test]
    async fn head_accepts_403_and_302_without_body_auth_or_redirect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for status in [403, 302] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = url::Url::parse(&format!(
                "http://{}/synthetic",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let (release, released) = tokio::sync::oneshot::channel::<()>();

            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut bytes = [0_u8; 512];
                    let count = stream.read(&mut bytes).await.unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&bytes[..count]);
                    assert!(request.len() <= 8192);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                }

                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("HEAD /synthetic HTTP/1.1\r\n"));
                let lower = request.to_ascii_lowercase();
                assert!(!lower.contains("\r\nauthorization:"));
                assert!(!lower.contains("\r\nproxy-authorization:"));
                assert!(!lower.contains("\r\ncookie:"));
                assert!(request.ends_with("\r\n\r\n"));

                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} Synthetic\r\n\
                             Location: http://127.0.0.1:1/never-follow\r\n\
                             Content-Length: 999999\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();

                // No body and no EOF until the HEAD operation completes.
                let _ = released.await;
            });

            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap();
            let check = check("one", "1111111111111111");

            let result = send_head(&check, &client, url).await;
            let _ = release.send(());
            server.await.unwrap();

            assert_eq!(result.outcome, ServiceCheckOutcome::Http);
            assert_eq!(result.http_status, Some(status));
            assert!(result.latency_ms.is_some());
            assert_eq!(result.consecutive_failures, 0);
            assert!(!result.degraded);
        }
    }

    #[tokio::test]
    async fn invalid_https_spec_is_rejected_before_client_network_use() {
        let mut check = check("one", "1111111111111111");
        check.url = "http://127.0.0.1:1/private-secret".into();
        let client = service_probe_client(1).unwrap();

        let result = probe_service_check(&check, &client).await;
        assert_eq!(result.outcome, ServiceCheckOutcome::TransportError);
        let result = serde_json::to_string(&result).unwrap();
        assert!(!result.contains("private-secret"));
        assert!(!result.contains("127.0.0.1"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn actual_temporary_child_startup_is_bounded_and_cleanup_is_awaited() {
        let endpoint = endpoint("selected.example.test");
        let check = check("one", &subscription::endpoint_key(&endpoint.url));
        let group = EndpointGroup {
            endpoint: &endpoint,
            checks: vec![(0, &check)],
        };
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("probe.pid");
        let spawn = || {
            let mut command = tokio::process::Command::new("sh");
            // exec ensures there is no unmanaged descendant.
            command
                .args([
                    "-c",
                    "printf '%s' \"$$\" > \"$1\"; exec sleep 60",
                    "service-probe-test",
                ])
                .arg(&pid_file);
            Ok(command)
        };

        let started = Instant::now();
        let results = run_endpoint_group(group, None, &spawn, Duration::from_millis(500))
            .await
            .unwrap();

        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1.outcome, ServiceCheckOutcome::Timeout);
        assert_eq!(results[0].1.http_status, None);
        let pid = std::fs::read_to_string(pid_file)
            .unwrap()
            .parse::<libc::pid_t>()
            .unwrap();
        // SAFETY: signal zero only tests this synthetic child's existence.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
}
