//! `geoip.dat`/`geosite.dat` overrides.
//!
//! Shared by the clients (the macOS engine; `src-tauri` still carries its
//! own copy). The helper/daemon never downloads anything.
//!
//! The app downloads the files over HTTPS into a bounded cache keyed by the
//! URL pair (`<data>/geoassets/<sha256(urls)[:16]>/`) — profiles sharing the
//! same URLs reuse one copy. On connect the bytes are sent inline in the
//! daemon request (the sandboxed unit cannot read `/home`), decoded into
//! the root-owned xray runtime directory, and `XRAY_LOCATION_ASSET` points
//! there — the privileged process never consumes user-writable paths. A
//! stale cache is preferred over a failed refresh — a dat file is data, not
//! an executable. Refresh probes the `<url>.sha256` sidecar when published
//! and verifies the downloaded payload against it.

use crate::models::Profile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

pub const MAX_GEO_ASSET_BYTES: usize = 64 * 1024 * 1024;
const REFRESH_AFTER_SECS: u64 = 24 * 60 * 60;
const META_FILE: &str = "meta.json";

pub type Fetch =
    dyn Fn(&str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>> + Send + Sync;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeoAssetMeta {
    geoip_url: Option<String>,
    geosite_url: Option<String>,
    fetched_at_unix: Option<u64>,
    /// SHA-256 of the cached `geoip.dat`, recorded after each download or
    /// taken from a `<url>.sha256` sidecar.
    #[serde(default)]
    geoip_sha256: Option<String>,
    #[serde(default)]
    geosite_sha256: Option<String>,
}

pub fn validate_geo_asset_url(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() || url.len() > 2048 || url.chars().any(char::is_control) {
        return Err("geo asset URL is invalid".into());
    }
    if !url.starts_with("https://") {
        return Err("geo asset URL must use https".into());
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalized_url(value: Option<&str>) -> Option<&str> {
    match value.map(str::trim) {
        Some("") | None => None,
        Some(url) => Some(url),
    }
}

/// Cache directory keyed by the geoip+geosite URL pair: profiles pointing
/// at the same asset set share one copy instead of duplicating ~20 MiB per
/// profile.
fn asset_dir_key(geoip_url: Option<&str>, geosite_url: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(geoip_url.unwrap_or("").as_bytes());
    hasher.update(b"\x00");
    hasher.update(geosite_url.unwrap_or("").as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    digest[..16].to_string()
}

pub fn profile_asset_dir(
    root: &Path,
    geoip_url: Option<&str>,
    geosite_url: Option<&str>,
) -> PathBuf {
    root.join(asset_dir_key(geoip_url, geosite_url))
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Parses a `<url>.sha256` sidecar body: either a bare 64-hex digest or
/// the `<digest>  <filename>` form produced by GitHub releases.
fn parse_sha256_sidecar(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    let token = text.split_whitespace().next()?;
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(token.to_ascii_lowercase())
    } else {
        None
    }
}

fn load_meta(dir: &Path) -> GeoAssetMeta {
    std::fs::read_to_string(dir.join(META_FILE))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write_meta(dir: &Path, meta: &GeoAssetMeta) -> Result<(), String> {
    let tmp = dir.join(format!("{META_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec(meta).map_err(|e| e.to_string())?)
        .map_err(|_| "geo asset metadata write failed".to_string())?;
    std::fs::rename(&tmp, dir.join(META_FILE))
        .map_err(|_| "geo asset metadata write failed".to_string())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|_| "geo asset write failed".to_string())?;
    std::fs::rename(&tmp, path).map_err(|_| "geo asset write failed".to_string())
}

/// Whether the cached `file` still matches `url` and is fresh enough.
fn cache_is_fresh(dir: &Path, file: &str, url: &str, meta: &GeoAssetMeta) -> bool {
    let known_url = match file {
        "geoip.dat" => meta.geoip_url.as_deref(),
        _ => meta.geosite_url.as_deref(),
    };
    known_url == Some(url)
        && dir.join(file).is_file()
        && meta
            .fetched_at_unix
            .is_some_and(|ts| now_unix().saturating_sub(ts) < REFRESH_AFTER_SECS)
}

fn note_stale(notes: &mut Vec<String>, err: &str) {
    notes.push(format!(
        "geo asset refresh failed, using cached copy: {err}"
    ));
}

pub async fn ensure_with_fetch(
    notes: &mut Vec<String>,
    root: &Path,
    profile: &Profile,
    fetch: &Fetch,
) -> Result<Option<PathBuf>, String> {
    let geoip_url = normalized_url(profile.xray_geoip_url.as_deref());
    let geosite_url = normalized_url(profile.xray_geosite_url.as_deref());
    if geoip_url.is_none() && geosite_url.is_none() {
        // Managed bundled assets are used; the shared cache is left in
        // place — other profiles may point at the same URL pair.
        return Ok(None);
    }
    for url in [geoip_url, geosite_url].into_iter().flatten() {
        validate_geo_asset_url(url)?;
    }
    let dir = profile_asset_dir(root, geoip_url, geosite_url);
    std::fs::create_dir_all(&dir).map_err(|_| "geo asset directory is unavailable".to_string())?;
    let mut meta = load_meta(&dir);

    for (file, url, key) in [
        ("geoip.dat", geoip_url, "geoip"),
        ("geosite.dat", geosite_url, "geosite"),
    ] {
        let target = dir.join(file);
        let Some(url) = url else { continue };
        if cache_is_fresh(&dir, file, url, &meta) {
            continue;
        }
        // Cheap freshness probe: a `<url>.sha256` sidecar answers "did the
        // asset change" without re-downloading ~20 MiB. A failed probe is
        // not fatal — fall through to the plain refresh path.
        let known_digest = match key {
            "geoip" => meta.geoip_sha256.as_deref(),
            _ => meta.geosite_sha256.as_deref(),
        };
        let sidecar = fetch(&format!("{url}.sha256"))
            .await
            .ok()
            .and_then(|bytes| parse_sha256_sidecar(&bytes));
        if let (Some(expected), Some(known)) = (sidecar.as_deref(), known_digest) {
            if expected == known && target.is_file() {
                meta.fetched_at_unix = Some(now_unix());
                continue;
            }
        }
        match fetch(url).await {
            Ok(bytes) => {
                if let Some(expected) = sidecar.as_deref() {
                    if sha256_hex(&bytes) != expected {
                        let err = "geo asset digest mismatch".to_string();
                        if target.is_file() {
                            note_stale(notes, &err);
                            continue;
                        }
                        return Err(err);
                    }
                }
                write_atomic(&target, &bytes)?;
                let digest = sidecar.unwrap_or_else(|| sha256_hex(&bytes));
                match key {
                    "geoip" => {
                        meta.geoip_url = Some(url.to_string());
                        meta.geoip_sha256 = Some(digest);
                    }
                    _ => {
                        meta.geosite_url = Some(url.to_string());
                        meta.geosite_sha256 = Some(digest);
                    }
                }
                meta.fetched_at_unix = Some(now_unix());
            }
            Err(err) if target.is_file() => note_stale(notes, &err),
            Err(err) => return Err(err),
        }
    }
    write_meta(&dir, &meta)?;
    let has_any = ["geoip.dat", "geosite.dat"]
        .iter()
        .any(|name| dir.join(name).is_file());
    if has_any {
        Ok(Some(dir))
    } else {
        Err("geo asset download failed".into())
    }
}

/// Encodes the cached dat files for inline daemon transport: each present
/// file becomes a base64 field, absent files stay `None` so the daemon falls
/// back to its managed copy for that file.
pub fn protocol_geo_assets(dir: &Path) -> Result<crate::daemon_protocol::XrayGeoAssets, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let encode_file = |name: &str| -> Result<Option<String>, String> {
        let path = dir.join(name);
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|_| "geo asset is unreadable".to_string())?;
        if bytes.is_empty() || bytes.len() > MAX_GEO_ASSET_BYTES {
            return Err("geo asset is invalid".into());
        }
        Ok(Some(engine.encode(bytes)))
    };
    Ok(crate::daemon_protocol::XrayGeoAssets {
        geoip_dat_b64: encode_file("geoip.dat")?,
        geosite_dat_b64: encode_file("geosite.dat")?,
    })
}

/// Read already prepared overrides without downloading, writing an overlay, or
/// following user-controlled links. The privileged in-process CLI supplies the
/// console user's non-root UID; it must never copy root-owned files as geo data.
#[cfg(unix)]
pub fn cached_protocol_geo_assets(
    root: &Path,
    profile: &Profile,
    expected_uid: u32,
) -> Result<Option<crate::daemon_protocol::XrayGeoAssets>, String> {
    use base64::Engine;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    const UNAVAILABLE: &str =
        "Custom geo data is not safely cached; prepare it as your own user without sudo";
    let geoip_url = normalized_url(profile.xray_geoip_url.as_deref());
    let geosite_url = normalized_url(profile.xray_geosite_url.as_deref());
    if geoip_url.is_none() && geosite_url.is_none() {
        return Ok(None);
    }
    if expected_uid == 0 {
        return Err(UNAVAILABLE.into());
    }
    for url in [geoip_url, geosite_url].into_iter().flatten() {
        validate_geo_asset_url(url)?;
    }
    let directory = profile_asset_dir(root, geoip_url, geosite_url);
    for path in [root, directory.as_path()] {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| UNAVAILABLE)?;
        if !metadata.is_dir() || metadata.uid() != expected_uid {
            return Err(UNAVAILABLE.into());
        }
    }
    let read = |name: &str, requested: bool| -> Result<Option<String>, String> {
        if !requested {
            return Ok(None);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(name))
            .map_err(|_| UNAVAILABLE)?;
        let metadata = file.metadata().map_err(|_| UNAVAILABLE)?;
        if !metadata.is_file()
            || metadata.uid() != expected_uid
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_GEO_ASSET_BYTES as u64
        {
            return Err(UNAVAILABLE.into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
        file.take(MAX_GEO_ASSET_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| UNAVAILABLE)?;
        if bytes.is_empty() || bytes.len() > MAX_GEO_ASSET_BYTES {
            return Err(UNAVAILABLE.into());
        }
        Ok(Some(
            base64::engine::general_purpose::STANDARD.encode(bytes),
        ))
    };
    Ok(Some(crate::daemon_protocol::XrayGeoAssets {
        geoip_dat_b64: read("geoip.dat", geoip_url.is_some())?,
        geosite_dat_b64: read("geosite.dat", geosite_url.is_some())?,
    }))
}

/// Builds `target` for an Xray that runs as the user: each file of `cache`
/// is laid over the managed copy in `managed` (providers ship minimal
/// overlays), and a file the cache lacks is the managed copy as it is.
pub fn overlay_dir(cache: &Path, managed: &Path, target: &Path) -> Result<(), String> {
    let read = |path: PathBuf| -> Option<Vec<u8>> {
        let bytes = std::fs::read(path).ok()?;
        (!bytes.is_empty() && bytes.len() <= MAX_GEO_ASSET_BYTES).then_some(bytes)
    };
    std::fs::create_dir_all(target)
        .map_err(|_| "geo asset directory is unavailable".to_string())?;
    for name in ["geoip.dat", "geosite.dat"] {
        let stock = read(managed.join(name));
        let bytes = match (stock, read(cache.join(name))) {
            (Some(stock), Some(overlay)) => {
                crate::geo_list::merge_geo_list(&stock, &overlay).unwrap_or(overlay)
            }
            (None, Some(overlay)) => overlay,
            (Some(stock), None) => stock,
            (None, None) => return Err("a geo data file is unreadable".into()),
        };
        write_atomic(&target.join(name), &bytes)?;
    }
    Ok(())
}

/// The production downloader: HTTPS only (callers validate the URL), bounded
/// in size and time, with errors that never carry the URL.
pub fn http_fetch() -> Result<Box<Fetch>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|_| "geo asset client is unavailable".to_string())?;
    Ok(Box::new(move |url: &str| {
        let url = url.to_string();
        let client = client.clone();
        Box::pin(async move {
            let mut response = client
                .get(&url)
                .send()
                .await
                .map_err(|_| "geo asset download failed".to_string())?;
            if !response.status().is_success() {
                return Err(format!(
                    "geo asset download returned HTTP {}",
                    response.status()
                ));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "geo asset download failed".to_string())?
            {
                if bytes.len() + chunk.len() > MAX_GEO_ASSET_BYTES {
                    return Err("geo asset exceeds size limit".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            if bytes.is_empty() {
                return Err("geo asset is empty".into());
            }
            Ok(bytes)
        }) as Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>>
    }))
}

/// Downloads configured overrides into the per-profile cache and returns the
/// directory holding them for inline transport, or `None` when the profile
/// uses the managed geo data.
pub async fn ensure_geo_assets(
    notes: &mut Vec<String>,
    root: &Path,
    profile: &Profile,
) -> Result<Option<PathBuf>, String> {
    let fetch = http_fetch()?;
    ensure_with_fetch(notes, root, profile, &fetch).await
}

/// Whether the profile asks for custom geo data at all.
pub fn wants_overrides(profile: &Profile) -> bool {
    normalized_url(profile.xray_geoip_url.as_deref()).is_some()
        || normalized_url(profile.xray_geosite_url.as_deref()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Mutex;

    fn profile_with_urls(geoip: Option<&str>, geosite: Option<&str>) -> Profile {
        Profile {
            id: "prof-1".into(),
            xray_geoip_url: geoip.map(str::to_string),
            xray_geosite_url: geosite.map(str::to_string),
            ..Profile::default()
        }
    }

    fn fetcher(
        map: HashMap<String, Result<Vec<u8>, String>>,
    ) -> (Box<Fetch>, std::sync::Arc<Mutex<Vec<String>>>) {
        let calls = std::sync::Arc::new(Mutex::new(Vec::new()));
        let calls2 = calls.clone();
        (
            Box::new(move |url: &str| {
                calls2.lock().unwrap().push(url.to_string());
                let result = map
                    .get(url)
                    .cloned()
                    .unwrap_or_else(|| Err("unexpected url".into()));
                Box::pin(async move { result })
            }),
            calls,
        )
    }

    #[test]
    fn url_validation_requires_https() {
        assert!(validate_geo_asset_url("https://cdn.example/geosite.dat").is_ok());
        assert!(validate_geo_asset_url("http://cdn.example/x.dat").is_err());
        assert!(validate_geo_asset_url("").is_err());
        assert!(validate_geo_asset_url("ftp://x/y").is_err());
    }

    #[test]
    fn protocol_geo_assets_encodes_present_files_only() {
        use base64::Engine;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("geoip.dat"), b"ip-bytes").unwrap();
        let assets = protocol_geo_assets(&dir).unwrap();
        let decode = base64::engine::general_purpose::STANDARD;
        assert_eq!(
            decode.decode(assets.geoip_dat_b64.unwrap()).unwrap(),
            b"ip-bytes"
        );
        assert!(assets.geosite_dat_b64.is_none());
        std::fs::write(dir.join("geoip.dat"), b"").unwrap();
        assert!(protocol_geo_assets(&dir).is_err());
    }

    #[tokio::test]
    async fn no_urls_means_managed_assets() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let (fetch, calls) = fetcher(HashMap::new());
        let result = ensure_with_fetch(
            &mut Vec::new(),
            &dir,
            &profile_with_urls(None, None),
            &fetch,
        )
        .await
        .unwrap();
        assert!(result.is_none());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn downloads_both_files_and_caches_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let mut map = HashMap::new();
        map.insert("https://a/geoip.dat".to_string(), Ok(b"ip".to_vec()));
        map.insert("https://a/geosite.dat".to_string(), Ok(b"site".to_vec()));
        let (fetch, calls) = fetcher(map);
        let profile = profile_with_urls(Some("https://a/geoip.dat"), Some("https://a/geosite.dat"));
        let result = ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(result.join("geoip.dat")).unwrap(), b"ip");
        assert_eq!(std::fs::read(result.join("geosite.dat")).unwrap(), b"site");
        // Two sidecar probes (miss → plain refresh) + two downloads.
        assert_eq!(calls.lock().unwrap().len(), 4);

        // Second call with fresh cache must not refetch.
        let result2 = ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result2, result);
        assert_eq!(calls.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn url_pair_cache_is_shared_between_profiles() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let mut map = HashMap::new();
        map.insert("https://a/geoip.dat".to_string(), Ok(b"ip".to_vec()));
        let (fetch, calls) = fetcher(map);
        let first = profile_with_urls(Some("https://a/geoip.dat"), None);
        let mut second = first.clone();
        second.id = "another-profile".into();
        let dir1 = ensure_with_fetch(&mut Vec::new(), &dir, &first, &fetch)
            .await
            .unwrap()
            .unwrap();
        let dir2 = ensure_with_fetch(&mut Vec::new(), &dir, &second, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dir1, dir2);
        // One download + one sidecar probe total; the second profile reused
        // the fresh cache.
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_stale_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let url = "https://a/geoip.dat";
        let mut map = HashMap::new();
        map.insert(url.to_string(), Ok(b"v1".to_vec()));
        let (fetch, _) = fetcher(map);
        let profile = profile_with_urls(Some(url), None);
        let asset_dir = ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(asset_dir.join("geoip.dat")).unwrap(), b"v1");

        // Force staleness, then make every fetch fail.
        std::fs::write(
            asset_dir.join(META_FILE),
            serde_json::to_vec(&GeoAssetMeta {
                fetched_at_unix: Some(0),
                geoip_url: Some(url.into()),
                geoip_sha256: Some(sha256_hex(b"v1")),
                ..GeoAssetMeta::default()
            })
            .unwrap(),
        )
        .unwrap();
        let (fetch, _) = fetcher(HashMap::new());
        let result = ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .unwrap();
        assert!(result.is_some());
        assert_eq!(std::fs::read(asset_dir.join("geoip.dat")).unwrap(), b"v1");
    }

    #[tokio::test]
    async fn matching_sha256_sidecar_skips_redownload() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let url = "https://a/geoip.dat";
        let asset_dir = profile_asset_dir(&dir, Some(url), None);
        std::fs::create_dir_all(&asset_dir).unwrap();
        std::fs::write(asset_dir.join("geoip.dat"), b"v1").unwrap();
        std::fs::write(
            asset_dir.join(META_FILE),
            serde_json::to_vec(&GeoAssetMeta {
                fetched_at_unix: Some(0), // stale on purpose
                geoip_url: Some(url.into()),
                geoip_sha256: Some(sha256_hex(b"v1")),
                ..GeoAssetMeta::default()
            })
            .unwrap(),
        )
        .unwrap();
        let mut map = HashMap::new();
        // Sidecar answers the cached digest → the dat file itself is never
        // requested (it is absent from the map and would error).
        map.insert(
            format!("{url}.sha256"),
            Ok(format!("{}  geoip.dat", sha256_hex(b"v1")).into_bytes()),
        );
        let (fetch, calls) = fetcher(map);
        let profile = profile_with_urls(Some(url), None);
        let result = ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, asset_dir);
        assert_eq!(calls.lock().unwrap().as_slice(), &[format!("{url}.sha256")]);
    }

    #[tokio::test]
    async fn digest_mismatch_keeps_stale_cache_and_errors_without_one() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let url = "https://a/geoip.dat";
        let expected = sha256_hex(b"upstream-v2");
        let mut map = HashMap::new();
        map.insert(format!("{url}.sha256"), Ok(expected.into_bytes()));
        map.insert(url.to_string(), Ok(b"forged".to_vec()));

        // No cached copy → mismatch is a hard error.
        let (fetch, _) = fetcher(map.clone());
        let profile = profile_with_urls(Some(url), None);
        assert!(ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .is_err());

        // With a cached copy the stale bytes win over a bad refresh.
        let asset_dir = profile_asset_dir(&dir, Some(url), None);
        std::fs::create_dir_all(&asset_dir).unwrap();
        std::fs::write(asset_dir.join("geoip.dat"), b"v1").unwrap();
        let (fetch, _) = fetcher(map);
        let result = ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(result.join("geoip.dat")).unwrap(), b"v1");
    }

    #[tokio::test]
    async fn verified_download_records_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let url = "https://a/geoip.dat";
        let mut map = HashMap::new();
        map.insert(format!("{url}.sha256"), Ok(sha256_hex(b"v1").into_bytes()));
        map.insert(url.to_string(), Ok(b"v1".to_vec()));
        let (fetch, _) = fetcher(map);
        let profile = profile_with_urls(Some(url), None);
        let asset_dir = ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        let meta = load_meta(&asset_dir);
        assert_eq!(
            meta.geoip_sha256.as_deref(),
            Some(sha256_hex(b"v1").as_str())
        );
    }

    #[tokio::test]
    async fn failed_download_without_cache_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let (fetch, _) = fetcher(HashMap::new());
        let profile = profile_with_urls(Some("https://a/geoip.dat"), None);
        assert!(ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cleared_urls_use_managed_assets_and_keep_shared_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let mut map = HashMap::new();
        map.insert("https://a/geoip.dat".to_string(), Ok(b"v1".to_vec()));
        let (fetch, _) = fetcher(map);
        let profile = profile_with_urls(Some("https://a/geoip.dat"), None);
        let asset_dir = ensure_with_fetch(&mut Vec::new(), &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert!(asset_dir.join("geoip.dat").is_file());

        // Cleared URLs fall back to the managed assets; the shared cache
        // dir stays for other profiles pointing at the same pair.
        let cleared = profile_with_urls(None, None);
        assert!(ensure_with_fetch(&mut Vec::new(), &dir, &cleared, &fetch)
            .await
            .unwrap()
            .is_none());
        assert!(asset_dir.join("geoip.dat").exists());
    }

    #[test]
    fn asset_dir_key_is_path_safe_and_pair_scoped() {
        let a = asset_dir_key(Some("https://a/geoip.dat"), Some("https://a/geosite.dat"));
        assert_eq!(
            a,
            asset_dir_key(Some("https://a/geoip.dat"), Some("https://a/geosite.dat"))
        );
        assert_ne!(
            a,
            asset_dir_key(Some("https://b/geoip.dat"), Some("https://a/geosite.dat"))
        );
        assert_ne!(a, asset_dir_key(Some("https://a/geoip.dat"), None));
        assert_eq!(a.len(), 16);
        assert!(a
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && b.is_ascii_lowercase() || b.is_ascii_digit()));
    }

    #[test]
    fn parse_sha256_sidecar_accepts_bare_and_sums_formats() {
        let digest = "0ff7bd198654a0e922030e9cde7513b8b2ae1503335592e1db7811fcaa2d9a9a";
        assert_eq!(
            parse_sha256_sidecar(digest.as_bytes()).as_deref(),
            Some(digest)
        );
        assert_eq!(
            parse_sha256_sidecar(format!("{digest}  geoip.dat\n").as_bytes()).as_deref(),
            Some(digest)
        );
        assert!(parse_sha256_sidecar(b"short").is_none());
        assert!(parse_sha256_sidecar(b"").is_none());
        assert!(parse_sha256_sidecar(&[0xff, 0xfe]).is_none());
    }

    #[test]
    fn overlay_dir_takes_the_cache_where_it_has_a_file_and_the_managed_copy_elsewhere() {
        let tmp = tempfile::tempdir().unwrap();
        let (cache, managed, out) = (
            tmp.path().join("cache"),
            tmp.path().join("managed"),
            tmp.path().join("out"),
        );
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&managed).unwrap();
        std::fs::write(managed.join("geoip.dat"), b"stock-ip").unwrap();
        std::fs::write(managed.join("geosite.dat"), b"stock-site").unwrap();
        // Not parseable as a geo list, so the cached file replaces the stock one.
        std::fs::write(cache.join("geoip.dat"), b"custom-ip").unwrap();
        overlay_dir(&cache, &managed, &out).unwrap();
        assert_eq!(std::fs::read(out.join("geoip.dat")).unwrap(), b"custom-ip");
        assert_eq!(
            std::fs::read(out.join("geosite.dat")).unwrap(),
            b"stock-site"
        );
        // With nothing to build from, it says so rather than leaving a hole.
        std::fs::remove_file(managed.join("geosite.dat")).unwrap();
        assert!(overlay_dir(&cache, &managed, &tmp.path().join("again")).is_err());
    }
}
