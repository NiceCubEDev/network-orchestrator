//! Bounded subscription loading and managed import shared by desktop clients.
use crate::{
    config_vault::{ConfigVault, SubscriptionEndpoint},
    models::*,
    profile_import::{profile_listener_ports, select_generated_ports},
    profiles::{ProfileDocument, ProfileStore},
    xray,
};
use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Panels that serve full Xray JSON configs send ~20–40 KiB per server.
pub const MAX_SUBSCRIPTION_BODY_BYTES: usize = 4 * 1024 * 1024;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn failure(message: &str) -> io::Error {
    io::Error::other(message)
}

/// Subscription panels (Remnawave, Marzban, …) pick the response format by
/// User-Agent and answer unknown clients with a placeholder server. v2rayN is
/// universally recognized and receives the Base64 list of share links.
pub const SUBSCRIPTION_USER_AGENT: &str = "v2rayN/7.13.8";

pub const UNSUPPORTED_CLIENT_MESSAGE: &str =
    "The subscription server returned a placeholder instead of servers. It may not recognize this app or require an HWID.";

/// Stable, privacy-preserving device HWID for the `X-HWID` header. Panels with
/// a device limit (e.g. Remnawave) refuse subscriptions without one; deriving
/// it from a machine identifier keeps it identical across imports on this
/// device while never revealing the identifier itself.
pub fn derive_hwid(machine_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("network-orchestrator-hwid-v1:{machine_id}").as_bytes());
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// True when every link is a panel placeholder such as "App not supported".
pub fn is_unsupported_client_placeholder(urls: &[String]) -> bool {
    const MARKERS: [&str; 4] = [
        "not supported",
        "unsupported",
        "не поддерживается",
        "обновите приложение",
    ];
    !urls.is_empty()
        && urls.iter().all(|url| {
            crate::xray::share_link_name(url).is_some_and(|name| {
                let name = name.to_lowercase();
                MARKERS.iter().any(|marker| name.contains(marker))
            })
        })
}

/// Supported entries of a subscription body (share links or full Xray JSON
/// configs), the number of unsupported entries, and their distinct schemes.
pub fn parse_subscription_body_detailed(body: &str) -> (Vec<String>, usize, Vec<String>) {
    let decoded = base64_decode(body.trim()).unwrap_or_else(|| body.to_string());
    let mut urls = Vec::new();
    let mut skipped = 0;
    let mut schemes: Vec<String> = Vec::new();
    let mut note = |scheme: &str| {
        if !schemes.iter().any(|known| known == scheme) {
            schemes.push(scheme.to_string());
        }
    };
    let trimmed = decoded.trim();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let configs = match value {
                serde_json::Value::Array(items) => items,
                other => vec![other],
            };
            for config in &configs {
                match crate::xray::xray_json_entry(config) {
                    Ok(entry) => urls.push(entry),
                    Err(_) => {
                        skipped += 1;
                        note("json");
                    }
                }
            }
            return (urls, skipped, schemes);
        }
    }
    for line in decoded
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if line.starts_with("vless://")
            || line.starts_with("hysteria2://")
            || line.starts_with("hy2://")
        {
            urls.push(line.to_string());
        } else {
            skipped += 1;
            note(
                line.split_once("://")
                    .map(|(scheme, _)| scheme)
                    .unwrap_or("unknown"),
            );
        }
    }
    (urls, skipped, schemes)
}

/// Supported entries and the distinct schemes of skipped lines.
pub fn parse_subscription_body(body: &str) -> (Vec<String>, Vec<String>) {
    let (urls, _, schemes) = parse_subscription_body_detailed(body);
    (urls, schemes)
}

pub fn parse_subscription_userinfo(value: &str) -> Option<SubscriptionUserInfo> {
    if value.len() > 512 {
        return None;
    }
    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;
    for field in value.split(';').take(16) {
        let Some((key, raw)) = field.trim().split_once('=') else {
            continue;
        };
        if !matches!(key.trim(), "upload" | "download" | "total" | "expire") {
            continue;
        }
        let number = raw.trim().parse::<u64>().ok()?;
        if number > 9_007_199_254_740_991 {
            return None;
        }
        match key.trim() {
            "upload" => upload = Some(number),
            "download" => download = Some(number),
            "total" => total = Some(number),
            "expire" => expire = Some(number),
            _ => {}
        }
    }
    Some(SubscriptionUserInfo {
        upload_bytes: upload?,
        download_bytes: download?,
        total_bytes: total.filter(|total| *total > 0),
        expires_at_unix: expire.filter(|expire| *expire > 0 && *expire <= 253_402_300_799),
    })
}

/// Best-effort standard base64 decoder that tolerates missing padding and
/// whitespace. Returns `None` if the input is not valid base64.
pub fn base64_decode(input: &str) -> Option<String> {
    use base64::Engine;
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| {
            engine
                .decode(&cleaned)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
}

pub fn http_client() -> io::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(SUBSCRIPTION_USER_AGENT)
        .build()
        .map_err(|_| failure("Could not create the subscription HTTP client"))
}
pub fn validate_url(value: &str) -> io::Result<reqwest::Url> {
    let url = reqwest::Url::parse(value.trim())
        .map_err(|_| invalid("Enter a valid HTTP or HTTPS subscription URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid("Enter a valid HTTP or HTTPS subscription URL"));
    }
    Ok(url)
}
pub struct FetchedSubscription {
    pub body: String,
    pub content_type: Option<String>,
    /// Response header names only (never values), for diagnostics.
    pub header_names: Vec<String>,
    pub meta: ResponseMeta,
}

/// Optional metadata a subscription response announces alongside the body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseMeta {
    pub user_info: Option<SubscriptionUserInfo>,
    pub provider_title: Option<String>,
    pub announce: Option<String>,
    pub support_url: Option<String>,
    pub web_page_url: Option<String>,
    pub update_interval_hours: Option<u32>,
}

/// Decode a textual subscription header (`Profile-Title`, `Announce`): plain,
/// percent-encoded or `base64:`-prefixed. Rejects oversized values and control
/// characters; only announcements may contain newlines.
pub fn parse_text_header(value: &str, max_chars: usize, allow_newlines: bool) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_chars * 2 {
        return None;
    }
    let decoded = if let Some(encoded) = trimmed.strip_prefix("base64:") {
        base64_decode(encoded.trim())?
    } else {
        xray::percent_decode(trimmed)
    };
    let text = decoded.trim();
    if text.is_empty() || text.chars().count() > max_chars {
        return None;
    }
    if text
        .chars()
        .any(|c| char::is_control(c) && !(allow_newlines && c == '\n'))
    {
        return None;
    }
    Some(text.to_string())
}

pub fn parse_provider_title(value: &str) -> Option<String> {
    parse_text_header(value, 200, false)
}

/// Accept only http(s) links for `Support-Url` / `Profile-Web-Page-Url`;
/// they end up behind clickable links in the UI.
pub fn parse_url_header(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 300 {
        return None;
    }
    let url = reqwest::Url::parse(trimmed).ok()?;
    matches!(url.scheme(), "https" | "http").then(|| trimmed.to_string())
}

/// Collect every supported metadata header, falling back to `#key: value`
/// comment lines in the body for panels that announce metadata there.
pub fn response_meta(headers: &[(String, String)], body: &str) -> ResponseMeta {
    let decoded = base64_decode(body.trim()).unwrap_or_else(|| body.to_string());
    let get = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
            .or_else(|| {
                decoded.lines().find_map(|line| {
                    let rest = line.trim().strip_prefix('#')?.trim_start();
                    let (key, value) = rest.split_once(':')?;
                    key.trim()
                        .eq_ignore_ascii_case(name)
                        .then(|| value.trim().to_string())
                })
            })
    };
    ResponseMeta {
        user_info: get("subscription-userinfo")
            .as_deref()
            .and_then(parse_subscription_userinfo),
        provider_title: get("profile-title")
            .as_deref()
            .and_then(parse_provider_title),
        announce: get("announce")
            .as_deref()
            .and_then(|value| parse_text_header(value, 2000, true)),
        support_url: get("support-url").as_deref().and_then(parse_url_header),
        web_page_url: get("profile-web-page-url")
            .as_deref()
            .and_then(parse_url_header),
        update_interval_hours: get("profile-update-interval")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|hours| (1..=24 * 365).contains(hours)),
    }
}

/// [`response_meta`] for a reqwest header map.
pub fn response_meta_from_headers(
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> ResponseMeta {
    let pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
        })
        .collect();
    response_meta(&pairs, body)
}

/// Compose the profile display name as `{provider} · {endpoint}`. When the
/// endpoint name already carries the provider prefix (with any separator)
/// it is re-joined with ` · `.
pub fn subscription_profile_name(provider_title: Option<&str>, endpoint_name: &str) -> String {
    let Some(title) = provider_title
        .map(str::trim)
        .filter(|title| !title.is_empty())
    else {
        return endpoint_name.to_string();
    };
    if let Some(rest) = endpoint_name.strip_prefix(title) {
        let rest = rest.trim_start();
        if rest.starts_with(['-', '–', '—', '|', '·', '•']) {
            let stripped = rest
                .trim_start_matches(['-', '–', '—', '|', '·', '•', ' '])
                .trim();
            return if stripped.is_empty() {
                title.to_string()
            } else {
                format!("{title} · {stripped}")
            };
        }
    }
    if endpoint_name == title {
        return title.to_string();
    }
    format!("{title} · {endpoint_name}")
}

/// The last ` · ` / ` - ` / ` – ` / ` — ` / ` | `-delimited segment of an
/// endpoint name — "AcmeVPN · ⚡ NL" → "⚡ NL". Returns the whole name when
/// no separator is present.
fn endpoint_tail(endpoint_name: &str) -> &str {
    for sep in [" · ", " • ", " - ", " – ", " — ", " | "] {
        if let Some((_, tail)) = endpoint_name.rsplit_once(sep) {
            let tail = tail.trim();
            if !tail.is_empty() {
                return tail;
            }
        }
    }
    endpoint_name
}

/// True when `profile_name` is the auto-generated name of `endpoint_name` —
/// bare, provider-prefixed, or the provider-less tail of a prefixed name.
/// Separator-insensitive, so names from older releases still follow the
/// selected server.
fn auto_profile_name_matches(
    provider_title: Option<&str>,
    endpoint_name: &str,
    profile_name: &str,
) -> bool {
    endpoint_name == profile_name
        || subscription_profile_name(provider_title, endpoint_name) == profile_name
        || endpoint_tail(endpoint_name) == profile_name
        || subscription_profile_name(provider_title, profile_name)
            == subscription_profile_name(provider_title, endpoint_name)
}

/// A profile name the app generated from one of its servers (optionally with
/// the provider prefix); such names follow the selected server, a name the
/// user typed is kept.
fn is_generated_name(
    name: &str,
    provider_title: Option<&str>,
    endpoints: &[SubscriptionEndpoint],
) -> bool {
    endpoints
        .iter()
        .any(|endpoint| auto_profile_name_matches(provider_title, &endpoint.name, name))
}

/// Secret-free description of a subscription response for diagnostics:
/// format, size, line count and share-link schemes. Never includes hosts,
/// credentials, names or any other part of the body.
pub fn summarize_subscription_body(body: &str, content_type: Option<&str>) -> String {
    let trimmed = body.trim();
    let decoded = base64_decode(trimmed);
    let text = decoded.as_deref().unwrap_or(trimmed);
    let format = if decoded.is_some() {
        "base64"
    } else if trimmed.starts_with('{') || trimmed.starts_with('[') {
        "json"
    } else if trimmed.to_ascii_lowercase().starts_with("<!doctype")
        || trimmed.to_ascii_lowercase().starts_with("<html")
    {
        "html"
    } else if text.lines().any(|line| line.starts_with("proxies:")) {
        "yaml"
    } else {
        "plain"
    };
    let mut schemes = std::collections::BTreeMap::<String, usize>::new();
    let mut lines = 0;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        lines += 1;
        let scheme = line
            .split_once("://")
            .map(|(scheme, _)| scheme)
            .filter(|scheme| {
                !scheme.is_empty()
                    && scheme.len() <= 16
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-')
            })
            .map(|scheme| scheme.to_ascii_lowercase())
            .unwrap_or_else(|| "other".into());
        *schemes.entry(scheme).or_default() += 1;
    }
    let schemes = schemes
        .iter()
        .map(|(scheme, count)| format!("{scheme}×{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    let content_type = content_type
        .map(|value| value.split(';').next().unwrap_or("").trim().to_string())
        .filter(|value| {
            value.len() <= 64
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/+-.".contains(c))
        })
        .unwrap_or_else(|| "-".into());
    format!(
        "format={format} bytes={} lines={lines} content-type={content_type} schemes: {}",
        body.len(),
        if schemes.is_empty() { "-" } else { &schemes }
    )
}
pub async fn fetch(
    client: &reqwest::Client,
    source: &str,
    hwid: &str,
) -> io::Result<FetchedSubscription> {
    tokio::time::timeout(Duration::from_secs(30), fetch_inner(client, source, hwid))
        .await
        .map_err(|_| failure("Subscription request timed out"))?
}
async fn fetch_inner(
    client: &reqwest::Client,
    source: &str,
    hwid: &str,
) -> io::Result<FetchedSubscription> {
    let original = validate_url(source)?;
    let mut url = original.clone();
    let mut forward_hwid = true;
    for redirect in 0..=5 {
        let mut request = client.get(url.clone());
        if forward_hwid && !hwid.is_empty() {
            let mut header = reqwest::header::HeaderValue::from_str(hwid)
                .map_err(|_| invalid("Invalid subscription HWID"))?;
            header.set_sensitive(true);
            request = request.header("X-HWID", header);
        }
        let mut response = request.send().await.map_err(|_| {
            failure("Could not fetch the subscription. Check the URL and network connection.")
        })?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            if redirect == 5 {
                return Err(failure("Subscription redirected too many times"));
            }
            let next = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|location| url.join(location).ok())
                .ok_or_else(|| invalid("Invalid subscription redirect"))?;
            validate_url(next.as_str())?;
            if url.scheme() == "https" && next.scheme() != "https" {
                return Err(invalid("Insecure subscription redirect was rejected"));
            }
            forward_hwid &= next.origin() == original.origin();
            url = next;
            continue;
        }
        if !response.status().is_success() {
            return Err(failure(&format!(
                "Subscription server returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let header_names: Vec<String> = response
            .headers()
            .keys()
            .map(|name| name.as_str().to_string())
            .collect();
        let headers = response.headers().clone();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| failure("Could not read the subscription response"))?
        {
            if chunk.len() > MAX_SUBSCRIPTION_BODY_BYTES - bytes.len() {
                return Err(invalid("Subscription response exceeds the 4 MiB limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let body =
            String::from_utf8(bytes).map_err(|_| invalid("Subscription response is not UTF-8"))?;
        let meta = response_meta_from_headers(&headers, &body);
        return Ok(FetchedSubscription {
            body,
            content_type,
            header_names,
            meta,
        });
    }
    Err(failure("Subscription redirected too many times"))
}

pub struct SubscriptionImport<'a> {
    pub id: &'a str,
    pub url: &'a str,
    pub hwid: &'a str,
    pub name: &'a str,
    pub refresh_interval_minutes: Option<u32>,
}
pub fn import_body(
    vault: &ConfigVault,
    store: &ProfileStore,
    request: &SubscriptionImport<'_>,
    body: &str,
    meta: ResponseMeta,
    available: impl Fn(u16) -> bool,
) -> io::Result<BatchImportResult> {
    crate::config_vault::sanitize_profile_id(request.id)?;
    validate_url(request.url)?;
    if body.len() > MAX_SUBSCRIPTION_BODY_BYTES {
        return Err(invalid("Subscription response exceeds the 4 MiB limit"));
    }
    if request
        .refresh_interval_minutes
        .is_some_and(|m| !matches!(m, 15 | 60 | 360))
    {
        return Err(invalid("unsupported subscription refresh interval"));
    }
    let document = store.load()?;
    if document.profiles.iter().any(|p| p.id == request.id) {
        return Err(invalid("A profile with this identifier already exists"));
    }
    let (urls, unsupported, skipped_protocols) = parse_subscription_body_detailed(body);
    if urls.is_empty() {
        return Err(invalid("Subscription contained no supported share links"));
    }
    if is_unsupported_client_placeholder(&urls) {
        return Err(invalid(UNSUPPORTED_CLIENT_MESSAGE));
    }
    let used = profile_listener_ports(&document.profiles, "");
    let (socks, http) = select_generated_ports(None, None, &used, available)?;
    let mut errors = Vec::new();
    if unsupported != 0 {
        errors.push(BatchImportError {
            path: "Subscription".into(),
            error: format!("{unsupported} unsupported share link(s) skipped"),
        });
    }
    let mut endpoints = Vec::new();
    let mut first_config = None;
    for (index, uri) in urls.into_iter().enumerate() {
        match xray::generate_share_link_config_with_http(&uri, socks, http) {
            Ok(config) => {
                if first_config.is_none() {
                    first_config = Some(config);
                }
                let name = xray::share_link_name(&uri)
                    .unwrap_or_else(|| format!("Endpoint {}", endpoints.len() + 1));
                endpoints.push(SubscriptionEndpoint { url: uri, name });
            }
            Err(_) => errors.push(BatchImportError {
                path: format!("Endpoint {}", index + 1),
                error: "Invalid or unsupported share link".into(),
            }),
        }
    }
    let first_config =
        first_config.ok_or_else(|| invalid("Subscription contained no valid share links"))?;
    let body = serde_json::to_vec_pretty(&first_config)?;
    let imported = vault.store_generated_xray(request.id, &body)?;
    let result = (|| {
        vault.store_subscription_endpoints(request.id, &endpoints)?;
        let profile = Profile {
            id: request.id.into(),
            name: if request.name.trim().is_empty() {
                subscription_profile_name(meta.provider_title.as_deref(), &endpoints[0].name)
            } else {
                request.name.trim().into()
            },
            backend: TunnelBackend::Xray,
            config_path: imported.config_path,
            xray_socks_port: Some(socks),
            xray_http_port: Some(http),
            xray_mode: XrayMode::platform_default(),
            subscription: Some(SubscriptionMeta {
                url: request.url.trim().into(),
                hwid: request.hwid.into(),
                endpoint_count: endpoints.len(),
                active_index: 0,
                refresh_interval_minutes: request.refresh_interval_minutes,
                last_refresh_at_unix: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                last_refresh_error: None,
                user_info: meta.user_info,
                provider_title: meta.provider_title,
                announce: meta.announce,
                support_url: meta.support_url,
                web_page_url: meta.web_page_url,
                update_interval_hours: meta.update_interval_hours,
                skipped_protocols,
                active_key: Some(endpoint_key(&endpoints[0].url)),
                backup_keys: Vec::new(),
                auto_return_primary: None,
                probe_url: None,
                node_pool: None,
                pool_keys: Vec::new(),
            }),
            ..Profile::default()
        };
        store.upsert(profile)
    })();
    match result {
        Ok(document) => Ok(BatchImportResult {
            profiles: document.profiles,
            errors,
        }),
        Err(error) => {
            let _ = vault.remove_profile(request.id);
            Err(error)
        }
    }
}

pub fn switch_endpoint(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    index: usize,
    available: impl Fn(u16) -> bool,
) -> io::Result<ProfileDocument> {
    let endpoints = vault.read_subscription_endpoints(id)?;
    let key = endpoint_key(
        &endpoints
            .get(index)
            .ok_or_else(|| invalid("Invalid endpoint index"))?
            .url,
    );
    switch_endpoint_key(vault, store, id, &key, available)
}

/// Select the primary endpoint by its stable key (see [`endpoint_key`]).
/// The key must resolve to a current endpoint — a key the refresh dropped
/// is rejected instead of retargeted to whatever took its position.
pub fn switch_endpoint_key(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    key: &str,
    available: impl Fn(u16) -> bool,
) -> io::Result<ProfileDocument> {
    if !valid_endpoint_key(key) {
        return Err(invalid("Invalid endpoint key"));
    }
    let document = store.load()?;
    let mut profile = document
        .profiles
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| invalid("Profile not found"))?;
    let subscription = profile
        .subscription
        .as_mut()
        .ok_or_else(|| invalid("Profile is not a subscription"))?;
    let endpoints = vault.read_subscription_endpoints(id)?;
    let index = key_index(&endpoints, key)
        .ok_or_else(|| invalid("Endpoint is no longer part of the subscription"))?;
    let endpoint = &endpoints[index];
    let used = profile_listener_ports(&document.profiles, id);
    let (socks, http) = select_generated_ports(
        profile.xray_socks_port,
        profile.xray_http_port,
        &used,
        available,
    )?;
    let config = xray::generate_share_link_config_with_http(&endpoint.url, socks, http)
        .map_err(|_| invalid("Invalid or unsupported share link"))?;
    let imported = vault.store_generated_xray(id, &serde_json::to_vec_pretty(&config)?)?;
    let old_path = profile.config_path;
    profile.config_path = imported.config_path.clone();
    profile.xray_socks_port = Some(socks);
    profile.xray_http_port = Some(http);
    // Generated names follow the selection; a user-chosen name is kept.
    let title = subscription.provider_title.clone();
    if is_generated_name(&profile.name, title.as_deref(), &endpoints) {
        profile.name = subscription_profile_name(title.as_deref(), &endpoint.name);
    }
    subscription.active_index = index;
    subscription.active_key = Some(key.to_string());
    subscription.endpoint_count = endpoints.len();
    match store.upsert(profile) {
        Ok(document) => {
            if vault.is_managed_profile_path(id, &old_path) {
                vault.remove_revision_for_config(&old_path)?;
            }
            Ok(document)
        }
        Err(error) => {
            let _ = vault.remove_revision_for_config(&imported.config_path);
            Err(error)
        }
    }
}

/// Endpoint rows for clients: real endpoints first (key + flags), then one
/// `is_missing` row per stored backup key the refresh no longer returns so
/// the UI can show — and clear — the dangling choice.
pub fn list_endpoints(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
) -> io::Result<Vec<SubscriptionEndpointInfo>> {
    let profile = subscription_profile(store, id)?;
    let subscription = profile.subscription.as_ref().expect("checked above");
    let endpoints = vault.read_subscription_endpoints(id)?;
    let active_key = stored_active_key(&profile).or_else(|| {
        endpoints
            .get(subscription.active_index)
            .map(|endpoint| endpoint_key(&endpoint.url))
    });
    let backup: std::collections::HashSet<&str> = subscription
        .backup_keys
        .iter()
        .map(|backup| backup.key.as_str())
        .collect();
    let named = profile.named_exit_keys();
    let pooled: std::collections::HashSet<&str> = subscription
        .pool_keys
        .iter()
        .filter(|member| {
            subscription.node_pool.is_some()
                && active_key.as_deref() != Some(member.key.as_str())
                && !backup.contains(member.key.as_str())
                && !profile
                    .pinned_policies
                    .iter()
                    .any(|pin| pin.endpoint_key == member.key)
                && profile.xray_dns.outbound_key.as_deref() != Some(member.key.as_str())
                && !named.contains(member.key.as_str())
        })
        .map(|member| member.key.as_str())
        .collect();
    let mut rows: Vec<SubscriptionEndpointInfo> = endpoints
        .iter()
        .map(|endpoint| {
            let key = endpoint_key(&endpoint.url);
            SubscriptionEndpointInfo {
                name: endpoint.name.clone(),
                active: active_key.as_deref() == Some(key.as_str()),
                protocol: xray::endpoint_protocol(&endpoint.url),
                key: key.clone(),
                is_backup: backup.contains(key.as_str()),
                is_missing: false,
                in_pool: pooled.contains(key.as_str()),
            }
        })
        .collect();
    for stored in subscription.backup_keys.iter().chain(
        subscription
            .pool_keys
            .iter()
            .filter(|member| pooled.contains(member.key.as_str())),
    ) {
        if key_index(&endpoints, &stored.key).is_none()
            && !rows.iter().any(|row| row.key == stored.key)
        {
            rows.push(SubscriptionEndpointInfo {
                name: stored.name.clone(),
                active: false,
                protocol: None,
                key: stored.key.clone(),
                is_backup: backup.contains(stored.key.as_str()),
                is_missing: true,
                in_pool: pooled.contains(stored.key.as_str()),
            });
        }
    }
    Ok(rows)
}

/// Ordered failover candidates behind the primary. Well-formed keys that do
/// not resolve are kept (`EndpointRef.name` keeps the last known name):
/// they may reappear, and dropping them would silently lose a user choice.
/// The primary's own key inside the list is ignored.
pub fn set_backup_endpoints(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    keys: &[String],
) -> io::Result<ProfileDocument> {
    if keys.len() >= MAX_FAILOVER_NODES {
        return Err(invalid("At most seven backup endpoints can be selected"));
    }
    let mut profile = subscription_profile(store, id)?;
    let endpoints = vault.read_subscription_endpoints(id)?;
    let mut refs = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for key in keys {
        if !valid_endpoint_key(key) {
            return Err(invalid("Invalid endpoint key"));
        }
        if !seen.insert(key.as_str()) {
            return Err(invalid("Duplicate failover endpoint"));
        }
        let name = key_index(&endpoints, key)
            .map(|index| endpoints[index].name.clone())
            .unwrap_or_else(|| key.clone());
        refs.push(EndpointRef {
            key: key.clone(),
            name,
        });
    }
    let active = stored_active_key(&profile).or_else(|| {
        profile
            .subscription
            .as_ref()
            .and_then(|subscription| endpoints.get(subscription.active_index))
            .map(|endpoint| endpoint_key(&endpoint.url))
    });
    refs.retain(|reference| Some(reference.key.as_str()) != active.as_deref());
    profile
        .subscription
        .as_mut()
        .expect("checked above")
        .backup_keys = refs;
    store.upsert(profile)
}

/// Whether the daemon steers the tunnel back to the primary once it probes
/// healthy again after a failover.
pub fn set_auto_return_primary(
    store: &ProfileStore,
    id: &str,
    enabled: bool,
) -> io::Result<ProfileDocument> {
    let mut profile = subscription_profile(store, id)?;
    profile
        .subscription
        .as_mut()
        .expect("checked above")
        .auto_return_primary = Some(enabled);
    store.upsert(profile)
}

/// Replace the profile's pinned routes wholesale. Keys are validated for
/// shape only: a pinned node that left the subscription stays configured
/// and fail-closed (marked `missing`), never rerouted. Selector syntax is
/// the same as `DomainPolicy` domain rules — no IP selectors.
pub fn set_pinned_routes(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    routes: Vec<PinnedRoute>,
) -> io::Result<ProfileDocument> {
    let mut profile = subscription_profile(store, id)?;
    let endpoints = vault.read_subscription_endpoints(id)?;
    for route in &routes {
        if !valid_endpoint_key(&route.endpoint_key) {
            return Err(invalid("Invalid pinned endpoint key"));
        }
        if route.selectors.is_empty() || route.selectors.len() > 128 {
            return Err(invalid("A pinned route needs 1-128 selectors"));
        }
        xray::validate_routing_policy_selectors(&[DomainPolicy {
            domains: route.selectors.clone(),
            target: DomainRouteTarget::Direct,
        }])?;
        for selector in &route.selectors {
            if let Some(("ip", _)) = xray::classify_routing_selector(selector)? {
                return Err(invalid("Pinned routes take domain selectors only"));
            }
        }
    }
    profile.pinned_policies = routes;
    sync_endpoint_refs(&mut profile, &endpoints);
    store.upsert(profile)
}

/// Ordered failover candidates for a connect: the primary first, then the
/// stored backups that still resolve, then the verified auto-pool members
/// (the pool extends the ordered list, never reorders it). Missing backups
/// are skipped (they are kept in `backup_keys`/`pool_keys` and may
/// reappear); pinned routes are returned separately with their missing
/// flag refreshed.
pub fn failover_plan(
    vault: &ConfigVault,
    profile: &Profile,
) -> io::Result<(Vec<SubscriptionEndpoint>, Vec<PinnedRoute>)> {
    let subscription = profile
        .subscription
        .as_ref()
        .ok_or_else(|| invalid("Profile is not a subscription"))?;
    let endpoints = vault.read_subscription_endpoints(&profile.id)?;
    let active_key = stored_active_key(profile).or_else(|| {
        endpoints
            .get(subscription.active_index)
            .map(|endpoint| endpoint_key(&endpoint.url))
    });
    let primary_index = active_key
        .as_deref()
        .and_then(|key| key_index(&endpoints, key))
        .ok_or_else(|| invalid("The selected endpoint left the subscription"))?;
    let mut nodes = vec![endpoints[primary_index].clone()];
    let named = profile.named_exit_keys();
    for backup in subscription
        .backup_keys
        .iter()
        .chain(subscription.pool_keys.iter().filter(|node| {
            subscription.node_pool.is_some()
                && !profile
                    .pinned_policies
                    .iter()
                    .any(|pin| pin.endpoint_key == node.key)
                && profile.xray_dns.outbound_key.as_deref() != Some(node.key.as_str())
                && !named.contains(node.key.as_str())
        }))
    {
        if nodes.len() == MAX_FAILOVER_NODES {
            break;
        }
        if let Some(index) = key_index(&endpoints, &backup.key) {
            if !nodes
                .iter()
                .any(|node| endpoint_key(&node.url) == endpoint_key(&endpoints[index].url))
            {
                nodes.push(endpoints[index].clone());
            }
        }
    }
    let mut pinned = profile.pinned_policies.clone();
    for route in &mut pinned {
        route.missing = key_index(&endpoints, &route.endpoint_key).is_none();
    }
    Ok((nodes, pinned))
}

/// Maximum failover candidates (primary + backups): bounds the loopback
/// probe listeners the daemon creates per tunnel.
pub const MAX_FAILOVER_NODES: usize = 8;

/// Auto-refresh cadences the clients offer, in minutes.
pub const REFRESH_INTERVALS: [u32; 3] = [15, 60, 360];

/// Whether an auto-refreshing subscription is due (its interval elapsed since
/// the last attempt, successful or not).
pub fn refresh_due(subscription: &SubscriptionMeta, now: u64) -> bool {
    let Some(minutes) = subscription.refresh_interval_minutes else {
        return false;
    };
    REFRESH_INTERVALS.contains(&minutes)
        && subscription
            .last_refresh_at_unix
            .is_none_or(|last| now.saturating_sub(last) >= u64::from(minutes) * 60)
}

fn subscription_profile(store: &ProfileStore, id: &str) -> io::Result<Profile> {
    store
        .load()?
        .profiles
        .into_iter()
        .find(|p| p.id == id && p.subscription.is_some())
        .ok_or_else(|| invalid("Profile is not a subscription"))
}

/// Set (or clear) the auto-refresh interval; the clock restarts now.
pub fn set_refresh_interval(
    store: &ProfileStore,
    id: &str,
    minutes: Option<u32>,
    now: u64,
) -> io::Result<ProfileDocument> {
    if minutes.is_some_and(|m| !REFRESH_INTERVALS.contains(&m)) {
        return Err(invalid("unsupported subscription refresh interval"));
    }
    let mut profile = subscription_profile(store, id)?;
    let subscription = profile.subscription.as_mut().expect("checked above");
    subscription.refresh_interval_minutes = minutes;
    subscription.last_refresh_at_unix = Some(now);
    store.upsert(profile)
}

/// Remember a failed refresh so auto-refresh waits a full interval.
pub fn record_refresh_failure(store: &ProfileStore, id: &str, now: u64) -> io::Result<()> {
    let mut profile = subscription_profile(store, id)?;
    let subscription = profile.subscription.as_mut().expect("checked above");
    subscription.last_refresh_at_unix = Some(now);
    subscription.last_refresh_error = Some("Refresh failed".into());
    store.upsert(profile).map(|_| ())
}

/// Key format: 16 lowercase hex characters of a SHA-256 digest.
pub fn valid_endpoint_key(key: &str) -> bool {
    key.len() == 16
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn key_digest(identity: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(identity.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Secret-safe identity of an endpoint across refreshes and credential
/// rotation: the transport the client actually dials, never the display
/// name and never the userinfo (`uuid`/password) — rotating credentials
/// keeps the same node while a genuinely different server or transport
/// produces a different key. Two entries that hash identically are the
/// same transport (duplicate lines collapse to the first match).
///
/// Share links reduce to `scheme|host:port|sorted query` (transport
/// parameters like `sni`, `pbk`, `type` are part of the identity; a panel
/// that rotates them yields a new, unavailable key rather than a silent
/// retarget). Whole-config `xray-json:` entries reduce to
/// `protocol|address:port|network|security` of their first outbound.
pub fn endpoint_key(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.starts_with(xray::XRAY_JSON_PREFIX) {
        let identity = xray::xray_json_identity(trimmed).unwrap_or_else(|| trimmed.to_string());
        return key_digest(&identity);
    }
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return key_digest(trimmed);
    };
    let rest = rest.split_once('#').map(|(link, _)| link).unwrap_or(rest);
    let (authority, query) = match rest.split_once('?') {
        Some((authority, query)) => (authority, query),
        None => (rest, ""),
    };
    // Userinfo is stripped at the last '@' (a '@' inside it is always
    // percent-encoded), leaving `host:port` only.
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let mut params: Vec<&str> = query.split('&').filter(|part| !part.is_empty()).collect();
    params.sort_unstable();
    key_digest(&format!(
        "{}|{}|{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase(),
        params.join("&")
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshOutcome {
    pub endpoint_count: usize,
    pub active_index: usize,
    pub skipped_count: usize,
    pub fallback_used: bool,
    pub cleanup_failed: bool,
}

/// Replace a subscription's endpoints with a freshly fetched body, keeping
/// the selected server when it still exists. Placeholder-only bodies are
/// rejected and every write is rolled back on failure.
pub fn refresh_body(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    body: &str,
    meta: ResponseMeta,
    available: impl Fn(u16) -> bool,
) -> io::Result<RefreshOutcome> {
    if body.len() > MAX_SUBSCRIPTION_BODY_BYTES {
        return Err(invalid("Subscription response exceeds the 4 MiB limit"));
    }
    let document = store.load()?;
    let mut profile = document
        .profiles
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| invalid("Profile not found"))?;
    let old_index = profile
        .subscription
        .as_ref()
        .ok_or_else(|| invalid("Profile is not a subscription"))?
        .active_index;
    let used = profile_listener_ports(&document.profiles, id);
    let (socks, http) = select_generated_ports(
        profile.xray_socks_port,
        profile.xray_http_port,
        &used,
        available,
    )?;
    let previous = vault.read_subscription_endpoints(id)?;
    // The stored key wins; a profile saved before `active_key` existed
    // resolves its index against the previous endpoint list instead.
    let selected = stored_active_key(&profile)
        .or_else(|| previous.get(old_index).map(|e| endpoint_key(&e.url)));

    let (urls, mut skipped_count, skipped_protocols) = parse_subscription_body_detailed(body);
    if is_unsupported_client_placeholder(&urls) {
        return Err(invalid(UNSUPPORTED_CLIENT_MESSAGE));
    }
    let mut endpoints = Vec::new();
    let mut configs = Vec::new();
    for uri in urls {
        match xray::generate_share_link_config_with_http(&uri, socks, http) {
            Ok(config) => {
                let name = xray::share_link_name(&uri)
                    .unwrap_or_else(|| format!("Endpoint {}", endpoints.len() + 1));
                endpoints.push(SubscriptionEndpoint { url: uri, name });
                configs.push(config);
            }
            Err(_) => skipped_count += 1,
        }
    }
    if endpoints.is_empty() {
        return Err(invalid(&format!(
            "subscription refresh contained no valid share links ({skipped_count} skipped)"
        )));
    }
    // Duplicate transports collapse to the first match — the key identifies
    // a node, not a list position, so two identical entries can never steer
    // the selection to a different server.
    let new_index = selected.as_ref().and_then(|key| key_index(&endpoints, key));
    let fallback_used = new_index.is_none();
    let active_index = new_index.unwrap_or(0);
    let imported =
        vault.store_generated_xray(id, &serde_json::to_vec_pretty(&configs[active_index])?)?;
    let new_path = imported.config_path;
    let rollback = || {
        let restored = vault
            .read_subscription_endpoints(id)
            .is_ok_and(|current| current == previous)
            || vault.store_subscription_endpoints(id, &previous).is_ok();
        let removed = vault.remove_revision_for_config(&new_path).is_ok();
        restored && removed
    };
    let failure_message = |message: &str| {
        if rollback() {
            invalid(message)
        } else {
            failure("subscription refresh failed; rollback incomplete")
        }
    };
    if vault.store_subscription_endpoints(id, &endpoints).is_err() {
        return Err(failure_message("failed to store refreshed endpoints"));
    }
    let old_path = profile.config_path.clone();
    // Missing headers keep the stored provider metadata.
    let stored_title = profile
        .subscription
        .as_ref()
        .and_then(|s| s.provider_title.clone());
    let title = meta.provider_title.clone().or(stored_title.clone());
    if is_generated_name(&profile.name, stored_title.as_deref(), &previous) {
        profile.name = subscription_profile_name(title.as_deref(), &endpoints[active_index].name);
    }
    profile.config_path = new_path.clone();
    profile.xray_socks_port = Some(socks);
    profile.xray_http_port = Some(http);
    let subscription = profile.subscription.as_mut().expect("checked above");
    subscription.endpoint_count = endpoints.len();
    subscription.active_index = active_index;
    subscription.active_key = Some(endpoint_key(&endpoints[active_index].url));
    subscription.last_refresh_at_unix = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    subscription.last_refresh_error = None;
    if meta.user_info.is_some() {
        subscription.user_info = meta.user_info;
    }
    if meta.provider_title.is_some() {
        subscription.provider_title = meta.provider_title;
    }
    if meta.announce.is_some() {
        subscription.announce = meta.announce;
    }
    if meta.support_url.is_some() {
        subscription.support_url = meta.support_url;
    }
    if meta.web_page_url.is_some() {
        subscription.web_page_url = meta.web_page_url;
    }
    if meta.update_interval_hours.is_some() {
        subscription.update_interval_hours = meta.update_interval_hours;
    }
    subscription.skipped_protocols = skipped_protocols;
    sync_endpoint_refs(&mut profile, &endpoints);
    if store.upsert(profile).is_err() {
        return Err(failure_message("failed to store refreshed profile"));
    }
    let cleanup_failed = vault.is_managed_profile_path(id, &old_path)
        && vault.remove_revision_for_config(&old_path).is_err();
    Ok(RefreshOutcome {
        endpoint_count: endpoints.len(),
        active_index,
        skipped_count,
        fallback_used,
        cleanup_failed,
    })
}
/// Index of the endpoint with this key; duplicates collapse to the first.
pub fn key_index(endpoints: &[SubscriptionEndpoint], key: &str) -> Option<usize> {
    endpoints
        .iter()
        .position(|endpoint| endpoint_key(&endpoint.url) == key)
}

/// The stored `active_key` when it is a well-formed key (legacy profiles
/// fall back to `active_index`).
fn stored_active_key(profile: &Profile) -> Option<String> {
    profile
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.active_key.clone())
        .filter(|key| valid_endpoint_key(key))
}

/// Reconcile stored key references with a fresh endpoint list: backup refs
/// take the names the panel sent, pinned routes learn whether their node
/// still exists. Missing keys stay stored — a refresh must never silently
/// retarget or drop a user choice.
fn sync_endpoint_refs(profile: &mut Profile, endpoints: &[SubscriptionEndpoint]) {
    if let Some(subscription) = profile.subscription.as_mut() {
        for backup in subscription
            .backup_keys
            .iter_mut()
            .chain(subscription.pool_keys.iter_mut())
        {
            if let Some(index) = key_index(endpoints, &backup.key) {
                backup.name = endpoints[index].name.clone();
            }
        }
    }
    for pinned in &mut profile.pinned_policies {
        pinned.missing = key_index(endpoints, &pinned.endpoint_key).is_none();
    }
}

pub const DELAY_PROBE_URL: &str = "https://connectivitycheck.gstatic.com/generate_204";
pub const DELAY_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct TemporaryXray(tokio::process::Child);

impl TemporaryXray {
    pub(crate) async fn stop(&mut self) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(2), self.0.kill())
            .await
            .map_err(|_| "temporary Xray cleanup timed out".to_string())?
            .map_err(|_| "temporary Xray cleanup failed".to_string())
    }
}

impl Drop for TemporaryXray {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

/// Spawn a temporary unprivileged Xray serving the caller's config on a
/// free loopback SOCKS port, wait for the listener and return a proxied
/// client. The caller retains ownership across timeouts and awaits stop before
/// returning; Drop still kills on cancellation. Errors never echo configuration.
/// Shared by delay, exit-country and explicit service probes.
pub(crate) async fn temporary_socks_client(
    build_config: impl FnOnce(u16) -> Result<serde_json::Value, String>,
    mut command: tokio::process::Command,
    timeout: std::time::Duration,
    process: &mut Option<TemporaryXray>,
) -> Result<reqwest::Client, String> {
    use tokio::io::AsyncWriteExt;

    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| "failed to reserve delay probe port".to_string())?;
    let socks_port = listener
        .local_addr()
        .map_err(|_| "failed to reserve delay probe port".to_string())?
        .port();
    let config = build_config(socks_port)?;
    let config = serde_json::to_vec(&config)
        .map_err(|_| "failed to encode delay probe config".to_string())?;
    drop(listener);

    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    *process = Some(TemporaryXray(
        command
            .spawn()
            .map_err(|_| "failed to start delay probe".to_string())?,
    ));
    let child = &mut process.as_mut().expect("probe process was assigned").0;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to send delay probe config".to_string())?;
    stdin
        .write_all(&config)
        .await
        .map_err(|_| "failed to send delay probe config".to_string())?;
    drop(stdin);
    loop {
        if tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, socks_port))
            .await
            .is_ok()
        {
            break;
        }
        if child
            .try_wait()
            .map_err(|_| "delay probe process failed".to_string())?
            .is_some()
        {
            return Err("delay probe process exited before proxy was ready".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
        .map_err(|_| "failed to configure delay probe proxy".to_string())?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(timeout)
        .build()
        .map_err(|_| "failed to build delay probe client".to_string())?;
    Ok(client)
}

/// Measure HTTP latency through a temporary Xray that runs one endpoint on a
/// free loopback SOCKS port; the process is always reaped, errors never echo
/// the share link.
pub async fn measure_delay_with_command(
    uri: &str,
    command: tokio::process::Command,
    probe_url: &str,
    timeout: std::time::Duration,
) -> Result<u64, String> {
    measure_delay_with_config(
        |socks_port| {
            xray::generate_share_link_config(uri, socks_port)
                .map_err(|_| "invalid subscription endpoint".to_string())
        },
        command,
        probe_url,
        timeout,
    )
    .await
}

/// Like [`measure_delay_with_command`], with the probe's config built by the
/// caller for the reserved SOCKS port, so the probe can run the very config a
/// connection will use.
pub async fn measure_delay_with_config(
    build_config: impl FnOnce(u16) -> Result<serde_json::Value, String>,
    command: tokio::process::Command,
    probe_url: &str,
    timeout: std::time::Duration,
) -> Result<u64, String> {
    let mut process = None;
    let result = tokio::time::timeout(timeout, async {
        let client = temporary_socks_client(build_config, command, timeout, &mut process).await?;
        let started = std::time::Instant::now();
        let response = client
            .get(probe_url)
            .send()
            .await
            .map_err(|_| "delay probe request failed".to_string())?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err("delay probe returned an unexpected status".into());
        }
        Ok(started.elapsed().as_millis().max(1) as u64)
    })
    .await;
    if let Some(mut process) = process {
        process.stop().await?;
    }
    result.map_err(|_| "delay probe timed out".to_string())?
}

/// Delay to one endpoint using the given Xray executable.
pub async fn measure_endpoint_delay(
    executable: &std::path::Path,
    uri: &str,
    timeout: Duration,
) -> Result<u64, String> {
    let mut command = tokio::process::Command::new(executable);
    command.args(["run", "-config", "stdin:"]);
    measure_delay_with_command(uri, command, DELAY_PROBE_URL, timeout).await
}

pub fn public_profiles(mut profiles: Vec<Profile>) -> Vec<Profile> {
    for profile in &mut profiles {
        if let Some(subscription) = &mut profile.subscription {
            subscription.url.clear();
            subscription.hwid.clear();
        }
    }
    profiles
}

#[cfg(test)]
mod tests {
    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn response_meta_reads_headers_and_decodes_base64_values() {
        use base64::Engine;
        let announce =
            base64::engine::general_purpose::STANDARD.encode("Привет!\nСерверы обновлены.");
        let meta = response_meta(
            &headers(&[
                ("Profile-Title", "My%20panel"),
                ("announce", &format!("base64:{announce}")),
                ("support-url", "https://t.me/support"),
                ("profile-web-page-url", "javascript:alert(1)"),
                ("profile-update-interval", "12"),
            ]),
            "vless://id@h:1#A",
        );
        assert_eq!(meta.provider_title.as_deref(), Some("My panel"));
        assert_eq!(
            meta.announce.as_deref(),
            Some("Привет!\nСерверы обновлены.")
        );
        assert_eq!(meta.support_url.as_deref(), Some("https://t.me/support"));
        assert_eq!(meta.web_page_url, None);
        assert_eq!(meta.update_interval_hours, Some(12));
    }

    #[test]
    fn response_meta_falls_back_to_body_comments_and_rejects_bad_text() {
        let body = "#profile-title: Body title\n#announce: bad\u{7}text\nvless://id@h:1#A\n";
        let meta = response_meta(&[], body);
        assert_eq!(meta.provider_title.as_deref(), Some("Body title"));
        assert_eq!(meta.announce, None);
        assert_eq!(
            response_meta(&[], "vless://id@h:1#A"),
            ResponseMeta::default()
        );
    }

    #[test]
    fn comment_lines_are_not_counted_as_skipped_links() {
        let (urls, skipped) =
            parse_subscription_body("#announce: hi\nvless://id@h:1#A\ntrojan://x@h:1\nss://y@h:1");
        assert_eq!(urls.len(), 1);
        assert_eq!(skipped, vec!["trojan", "ss"]);
    }

    #[test]
    fn provider_metadata_is_stored_and_kept_when_refresh_omits_it() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let request = SubscriptionImport {
            id: "panel",
            url: "https://sub.example.test/token",
            hwid: "",
            name: "",
            refresh_interval_minutes: None,
        };
        let meta = ResponseMeta {
            provider_title: Some("Panel".into()),
            announce: Some("News".into()),
            ..Default::default()
        };
        import_body(
            &vault,
            &store,
            &request,
            &panel_body(&["NL", "DE"]),
            meta,
            |_| true,
        )
        .unwrap();
        let profile = store.load().unwrap().profiles.remove(0);
        assert_eq!(profile.name, "Panel · NL");
        let subscription = profile.subscription.unwrap();
        assert_eq!(subscription.provider_title.as_deref(), Some("Panel"));
        assert_eq!(subscription.announce.as_deref(), Some("News"));
        switch_endpoint(&vault, &store, "panel", 1, |_| true).unwrap();
        assert_eq!(store.load().unwrap().profiles[0].name, "Panel · DE");
        refresh_body(
            &vault,
            &store,
            "panel",
            &panel_body(&["NL", "DE"]),
            ResponseMeta::default(),
            |_| true,
        )
        .unwrap();
        let profile = store.load().unwrap().profiles.remove(0);
        assert_eq!(profile.name, "Panel · DE");
        assert_eq!(
            profile.subscription.unwrap().announce.as_deref(),
            Some("News")
        );
    }

    fn panel_body(names: &[&str]) -> String {
        serde_json::Value::Array(
            names
                .iter()
                .map(|name| {
                    serde_json::json!({
                        "remarks": name,
                        "outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {"n": name}}]
                    })
                })
                .collect(),
        )
        .to_string()
    }

    fn import_panel(dir: &std::path::Path, names: &[&str]) -> (ConfigVault, ProfileStore) {
        let vault = ConfigVault::new(dir.join("configs"));
        let store = ProfileStore::new(dir.join("profiles.json"));
        let request = SubscriptionImport {
            id: "panel",
            url: "https://sub.example.test/token",
            hwid: "hwid",
            name: "My VPN",
            refresh_interval_minutes: None,
        };
        import_body(
            &vault,
            &store,
            &request,
            &panel_body(names),
            ResponseMeta::default(),
            |_| true,
        )
        .unwrap();
        (vault, store)
    }

    #[test]
    fn endpoint_keys_survive_credentials_and_name_changes_but_not_server_changes() {
        let old = endpoint_key("vless://old@one.test:443?security=tls&type=tcp#Old");
        assert_eq!(
            old,
            endpoint_key("vless://new@one.test:443?type=tcp&security=tls#Renamed")
        );
        assert_ne!(
            old,
            endpoint_key("vless://new@two.test:443?type=tcp&security=tls#Renamed")
        );
        assert_ne!(
            old,
            endpoint_key("vless://new@one.test:443?type=ws&security=tls#Renamed")
        );
        assert!(valid_endpoint_key(&old));
    }

    #[test]
    fn json_hysteria_identity_survives_password_rotation() {
        let entry = |password: &str| {
            crate::xray::xray_json_entry(&serde_json::json!({
            "remarks": "Node",
            "outbounds": [{"protocol": "hysteria", "settings": {"address": "one.test", "port": 443},
                "streamSettings": {"network": "hysteria", "security": "tls",
                    "hysteriaSettings": {"auth": password}}}]
        })).unwrap()
        };
        assert_eq!(
            endpoint_key(&entry("old-password")),
            endpoint_key(&entry("new-password"))
        );
    }

    #[test]
    fn refresh_keeps_backup_order_and_marks_missing_pins_without_retargeting() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let links = [
            "vless://old@one.test:443?security=tls#Primary",
            "vless://old@two.test:443?security=tls#Backup",
            "vless://old@three.test:443?security=tls#Pinned",
        ];
        import_body(
            &vault,
            &store,
            &SubscriptionImport {
                id: "nodes",
                url: "https://example.test/sub",
                hwid: "",
                name: "Nodes",
                refresh_interval_minutes: None,
            },
            &links.join("\n"),
            ResponseMeta::default(),
            |_| true,
        )
        .unwrap();
        let backup = endpoint_key(links[1]);
        let pinned = endpoint_key(links[2]);
        set_backup_endpoints(&vault, &store, "nodes", &[pinned.clone(), backup.clone()]).unwrap();
        set_pinned_routes(
            &vault,
            &store,
            "nodes",
            vec![PinnedRoute {
                selectors: vec!["domain:private.example".into()],
                endpoint_key: pinned.clone(),
                missing: false,
            }],
        )
        .unwrap();
        refresh_body(&vault, &store, "nodes",
            "vless://new@two.test:443?security=tls#Renamed\nvless://new@one.test:443?security=tls#Primary",
            ResponseMeta::default(), |_| true).unwrap();
        let profile = store.load().unwrap().profiles.remove(0);
        let meta = profile.subscription.as_ref().unwrap();
        assert_eq!(
            meta.backup_keys
                .iter()
                .map(|node| node.key.as_str())
                .collect::<Vec<_>>(),
            [pinned.as_str(), backup.as_str()]
        );
        assert_eq!(meta.backup_keys[1].name, "Renamed");
        assert_eq!(profile.pinned_policies[0].endpoint_key, pinned);
        assert!(profile.pinned_policies[0].missing);
        let (candidates, pins) = failover_plan(&vault, &profile).unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(|node| endpoint_key(&node.url))
                .collect::<Vec<_>>(),
            [endpoint_key(links[0]), backup]
        );
        assert!(pins[0].missing);
    }

    #[test]
    fn backup_plan_cannot_exceed_daemon_candidate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, store) = import_panel(dir.path(), &["Primary"]);
        let keys = (0..MAX_FAILOVER_NODES)
            .map(|index| format!("{index:016x}"))
            .collect::<Vec<_>>();
        assert!(set_backup_endpoints(&vault, &store, "panel", &keys).is_err());
    }

    #[test]
    fn named_proxy_keys_leave_the_auto_pool_but_keep_manual_backups() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, store) = import_panel(dir.path(), &["Primary", "Named", "Reserve"]);
        let endpoints = vault.read_subscription_endpoints("panel").unwrap();
        let named_key = endpoint_key(&endpoints[1].url);
        let reserve_key = endpoint_key(&endpoints[2].url);
        // The auto pool holds both nodes plus a manual backup on one of
        // them; the named exit pins the same node the backup uses.
        set_backup_endpoints(&vault, &store, "panel", std::slice::from_ref(&named_key)).unwrap();
        store
            .update_profile("panel", |profile| {
                let subscription = profile.subscription.as_mut().unwrap();
                subscription.node_pool = Some(NodePoolSettings {
                    filters: vec![NodePoolFilter {
                        name_contains: Vec::new(),
                        exit_country: Some("NL".into()),
                    }],
                    verify_exit_country: false,
                });
                subscription.pool_keys = vec![
                    EndpointRef {
                        key: named_key.clone(),
                        name: "Named".into(),
                    },
                    EndpointRef {
                        key: reserve_key.clone(),
                        name: "Reserve".into(),
                    },
                ];
                profile.xray_proxy_exits = vec![NamedProxyExit {
                    name: "work".into(),
                    target: ProxyTarget::Pool {
                        endpoint_keys: vec![named_key.clone()],
                    },
                    no_proxy: Vec::new(),
                }];
                Ok(())
            })
            .unwrap();
        let profile = store.load().unwrap().profiles.remove(0);
        let (candidates, _) = failover_plan(&vault, &profile).unwrap();
        let keys: Vec<String> = candidates
            .iter()
            .map(|node| endpoint_key(&node.url))
            .collect();
        // Primary + the manual backup stay; the named key is never also an
        // auto-pool member while an unrelated pooled node still joins.
        assert_eq!(
            keys.iter().map(String::as_str).collect::<Vec<_>>(),
            [
                endpoint_key(&endpoints[0].url).as_str(),
                named_key.as_str(),
                reserve_key.as_str()
            ]
        );
        let rows = list_endpoints(&vault, &store, "panel").unwrap();
        let named_row = rows.iter().find(|row| row.key == named_key).unwrap();
        let reserve_row = rows.iter().find(|row| row.key == reserve_key).unwrap();
        assert!(!named_row.in_pool);
        assert!(reserve_row.in_pool);
    }

    #[test]
    fn refresh_keeps_selected_server_and_profile_name() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, store) = import_panel(dir.path(), &["NL", "DE", "FI"]);
        switch_endpoint(&vault, &store, "panel", 1, |_| true).unwrap();
        let outcome = refresh_body(
            &vault,
            &store,
            "panel",
            &panel_body(&["FI", "US", "DE", "NL"]),
            ResponseMeta::default(),
            |_| true,
        )
        .unwrap();
        assert_eq!(outcome.endpoint_count, 4);
        assert_eq!(outcome.active_index, 2);
        assert!(!outcome.fallback_used);
        let profile = store.load().unwrap().profiles.remove(0);
        assert_eq!(profile.name, "My VPN");
        assert_eq!(profile.subscription.unwrap().active_index, 2);
    }

    #[test]
    fn refresh_rejects_placeholder_and_keeps_existing_servers() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, store) = import_panel(dir.path(), &["NL", "DE"]);
        let stub = "vless://id@0.0.0.0:1?security=none#App%20not%20supported";
        let error = refresh_body(
            &vault,
            &store,
            "panel",
            stub,
            ResponseMeta::default(),
            |_| true,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), UNSUPPORTED_CLIENT_MESSAGE);
        assert_eq!(vault.read_subscription_endpoints("panel").unwrap().len(), 2);
    }

    fn panel_json_body() -> String {
        serde_json::json!([
            {"remarks": "🇳🇱 Netherlands", "outbounds": [{"tag": "proxy", "protocol": "vless"}]},
            {"remarks": "🇩🇪 Germany", "outbounds": [{"tag": "proxy", "protocol": "vless"}]},
            {"remarks": "broken"},
        ])
        .to_string()
    }

    #[test]
    fn json_subscription_body_yields_one_entry_per_config() {
        let (urls, skipped) = parse_subscription_body(&panel_json_body());
        assert_eq!(urls.len(), 2);
        assert_eq!(skipped, vec!["json"]);
        assert_eq!(
            crate::xray::share_link_name(&urls[1]).as_deref(),
            Some("🇩🇪 Germany")
        );
    }

    #[test]
    fn json_subscription_imports_per_country_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let request = SubscriptionImport {
            id: "panel",
            url: "https://sub.example.test/token",
            hwid: "hwid",
            name: "",
            refresh_interval_minutes: None,
        };
        let result = import_body(
            &vault,
            &store,
            &request,
            &panel_json_body(),
            ResponseMeta::default(),
            |_| true,
        )
        .unwrap();
        let profile = &result.profiles[0];
        assert_eq!(profile.subscription.as_ref().unwrap().endpoint_count, 2);
        let names: Vec<String> = vault
            .read_subscription_endpoints("panel")
            .unwrap()
            .into_iter()
            .map(|endpoint| endpoint.name)
            .collect();
        assert_eq!(names, vec!["🇳🇱 Netherlands", "🇩🇪 Germany"]);
    }

    #[test]
    fn subscription_body_limit_fits_large_panel_json() {
        assert_eq!(MAX_SUBSCRIPTION_BODY_BYTES, 4 * 1024 * 1024);
    }

    #[test]
    fn body_summary_counts_schemes_without_leaking_secrets() {
        let links = "trojan://SECRET-PASSWORD@nl.test:443#NL\nss://U0VDUkVU@de.test:8388#DE\nvless://SECRET-UUID@fi.test:443#FI\n";
        let encoded = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(links)
        };
        let summary = summarize_subscription_body(&encoded, Some("text/plain"));
        assert!(summary.contains("format=base64"), "{summary}");
        assert!(summary.contains("lines=3"), "{summary}");
        assert!(summary.contains("trojan×1"), "{summary}");
        assert!(summary.contains("ss×1"), "{summary}");
        assert!(summary.contains("vless×1"), "{summary}");
        assert!(summary.contains("content-type=text/plain"), "{summary}");
        for secret in ["SECRET", "nl.test", "U0VDUkVU", "NL"] {
            assert!(!summary.contains(secret), "leaked {secret}: {summary}");
        }
        let json = summarize_subscription_body(r#"[{"outbounds":[{"protocol":"vless"}]}]"#, None);
        assert!(json.contains("format=json"), "{json}");
        let yaml = summarize_subscription_body("proxies:\n  - name: a\n", None);
        assert!(yaml.contains("format=yaml"), "{yaml}");
    }

    #[test]
    fn derived_hwid_is_stable_uuid_shaped_and_hides_the_seed() {
        let first = derive_hwid("4C4C4544-0000-1000-8000-B7C04F4B3332");
        assert_eq!(first, derive_hwid("4C4C4544-0000-1000-8000-B7C04F4B3332"));
        assert_ne!(first, derive_hwid("another-machine"));
        assert_eq!(first.len(), 36);
        let groups: Vec<usize> = first.split('-').map(str::len).collect();
        assert_eq!(groups, vec![8, 4, 4, 4, 12]);
        assert!(first.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        assert!(!first.to_uppercase().contains("4C4C4544"));
        // Valid as an X-HWID header value.
        assert!(reqwest::header::HeaderValue::from_str(&first).is_ok());
    }

    #[test]
    fn client_identifies_as_a_recognized_subscription_app() {
        // Panels such as Remnawave/Marzban answer unknown User-Agents with a
        // single placeholder server instead of the real per-country list.
        assert!(SUBSCRIPTION_USER_AGENT.starts_with("v2rayN/"));
    }

    #[test]
    fn placeholder_only_subscription_is_detected() {
        let stub = vec!["vless://00000000-0000-4000-8000-000000000000@0.0.0.0:1?security=none#App%20not%20supported".to_string()];
        assert!(is_unsupported_client_placeholder(&stub));
        let russian = vec!["vless://id@h:1?security=none#%D0%9F%D1%80%D0%B8%D0%BB%D0%BE%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5%20%D0%BD%D0%B5%20%D0%BF%D0%BE%D0%B4%D0%B4%D0%B5%D1%80%D0%B6%D0%B8%D0%B2%D0%B0%D0%B5%D1%82%D1%81%D1%8F".to_string()];
        assert!(is_unsupported_client_placeholder(&russian));
        let real = vec![
            "vless://id@nl.test:443?security=tls#Netherlands".to_string(),
            "vless://id@de.test:443?security=tls#Germany".to_string(),
        ];
        assert!(!is_unsupported_client_placeholder(&real));
        assert!(!is_unsupported_client_placeholder(&[]));
    }

    #[test]
    fn import_rejects_placeholder_subscription_with_a_clear_message() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let request = SubscriptionImport {
            id: "stub",
            url: "https://sub.example.test/token",
            hwid: "",
            name: "",
            refresh_interval_minutes: None,
        };
        let body = "vless://00000000-0000-4000-8000-000000000000@0.0.0.0:1?security=none#App%20not%20supported";
        let error = import_body(
            &vault,
            &store,
            &request,
            body,
            ResponseMeta::default(),
            |_| true,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), UNSUPPORTED_CLIENT_MESSAGE);
        assert!(store.load().unwrap().profiles.is_empty());
    }

    use super::*;
    use base64::Engine;
    const BODY: &str = "vless://synthetic-id@one.test:443?security=tls#First\nhy2://synthetic-password@two.test:443#Second";

    #[test]
    fn imports_plain_and_unpadded_base64_and_preserves_private_metadata() {
        for body in [
            BODY.to_string(),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(BODY),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(BODY),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let vault = ConfigVault::new(dir.path().join("configs"));
            let store = ProfileStore::new(dir.path().join("profiles.json"));
            let request = SubscriptionImport {
                id: "sub",
                url: "https://example.test/private-token",
                hwid: "private-hwid",
                name: "Custom name",
                refresh_interval_minutes: Some(60),
            };
            let result = import_body(
                &vault,
                &store,
                &request,
                &body,
                ResponseMeta::default(),
                |_| true,
            )
            .unwrap();
            let profile = &result.profiles[0];
            assert_eq!(profile.name, "Custom name");
            assert_eq!(profile.xray_mode, XrayMode::platform_default());
            assert_eq!(profile.subscription.as_ref().unwrap().endpoint_count, 2);
            assert_eq!(profile.subscription.as_ref().unwrap().url, request.url);
            assert_eq!(
                profile
                    .subscription
                    .as_ref()
                    .unwrap()
                    .refresh_interval_minutes,
                Some(60)
            );
            assert!(
                !profile.auto_connect && !profile.use_system_proxy && profile.routes.is_empty()
            );
            let first_ports = (profile.xray_socks_port, profile.xray_http_port);
            let public = serde_json::to_string(&public_profiles(result.profiles)).unwrap();
            assert!(!public.contains("private-token") && !public.contains("private-hwid"));
            let switched = switch_endpoint(&vault, &store, "sub", 1, |_| true).unwrap();
            assert_eq!(
                switched.profiles[0]
                    .subscription
                    .as_ref()
                    .unwrap()
                    .active_index,
                1
            );
            assert_eq!(
                (
                    switched.profiles[0].xray_socks_port,
                    switched.profiles[0].xray_http_port
                ),
                first_ports
            );
        }
    }

    #[test]
    fn invalid_bodies_and_save_failures_leave_no_subscription_data() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let request = SubscriptionImport {
            id: "sub",
            url: "https://example.test/sub",
            hwid: "",
            name: "",
            refresh_interval_minutes: None,
        };
        for body in [
            "",
            "trojan://private-secret@node.test:443",
            "vless://private-secret@:443",
            "<html>not a subscription</html>",
        ] {
            assert!(import_body(
                &vault,
                &store,
                &request,
                body,
                ResponseMeta::default(),
                |_| true
            )
            .is_err());
            assert!(!dir.path().join("configs").exists());
        }
        std::fs::create_dir(dir.path().join("profiles.json.tmp")).unwrap();
        assert!(import_body(
            &vault,
            &store,
            &request,
            BODY,
            ResponseMeta::default(),
            |_| true
        )
        .is_err());
        assert!(!vault.root().join("sub").exists());
    }

    #[test]
    fn url_validation_rejects_files_credentials_and_invalid_urls_without_echoing_them() {
        for url in [
            "file:///private-secret",
            "vless://private-secret@node.test:443",
            "https://private-user:private-secret@node.test/sub",
            "not a URL",
        ] {
            let error = validate_url(url).unwrap_err();
            assert!(!error.to_string().contains("private-secret"));
        }
        assert!(validate_url(" https://example.test/sub ").is_ok());
    }

    async fn fake_response(response: String) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/private-token", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let received = stream.read(&mut bytes).await.unwrap();
            assert!(received > 0);
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (url, task)
    }

    #[tokio::test]
    async fn bounded_http_errors_are_redacted_and_oversized_responses_rejected() {
        for response in [
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                MAX_SUBSCRIPTION_BODY_BYTES + 1,
                "x".repeat(MAX_SUBSCRIPTION_BODY_BYTES + 1)
            ),
        ] {
            let (url, server) = fake_response(response).await;
            let error = fetch(&http_client().unwrap(), &url, "private-hwid")
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("private-token") && !error.contains("private-hwid"));
            assert!(error.contains("HTTP 403") || error.contains("4 MiB"));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn cross_origin_redirect_does_not_forward_hwid() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_url = format!("http://{}/sub", destination.local_addr().unwrap());
        let target = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let size = stream.read(&mut bytes).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes[..size])
                .to_ascii_lowercase()
                .contains("x-hwid"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let (url, source) = fake_response(format!("HTTP/1.1 302 Found\r\nLocation: {destination_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await;
        assert_eq!(
            fetch(&http_client().unwrap(), &url, "private-hwid")
                .await
                .unwrap()
                .body,
            "ok"
        );
        source.await.unwrap();
        target.await.unwrap();
    }
}
