//! What the user typed after `netorch up` / `netorch add`: a share link, a
//! subscription URL, a config file or the name of a saved profile.
// The Linux client resolves saved profiles only until it can import.
#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
use net_manager_core::models::{Profile, TunnelBackend};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    ShareLink(String),
    Subscription(String),
    File {
        path: PathBuf,
        backend: TunnelBackend,
    },
    Saved(String),
}

const SHARE_SCHEMES: [&str; 3] = ["vless://", "hysteria2://", "hy2://"];

/// Classify without touching the network; a path counts only when the file
/// exists, so a typo in a profile name never reads as a file.
pub fn classify(input: &str, exists: impl Fn(&Path) -> bool) -> Input {
    let input = input.trim();
    let lower = input.to_ascii_lowercase();
    if SHARE_SCHEMES.iter().any(|scheme| lower.starts_with(scheme)) {
        return Input::ShareLink(input.to_string());
    }
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return Input::Subscription(input.to_string());
    }
    let path = PathBuf::from(input);
    if exists(&path) {
        match path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("conf") => {
                return Input::File {
                    path,
                    backend: TunnelBackend::WireGuard,
                }
            }
            Some("ovpn") => {
                return Input::File {
                    path,
                    backend: TunnelBackend::OpenVpn,
                }
            }
            Some("json") => {
                return Input::File {
                    path,
                    backend: TunnelBackend::Xray,
                }
            }
            _ => {}
        }
    }
    Input::Saved(input.to_string())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    Found(&'a Profile),
    Missing,
    Ambiguous(Vec<&'a Profile>),
}

/// Exact id, then exact name (any case), then a unique id or name prefix.
pub fn resolve<'a>(profiles: &'a [Profile], query: &str) -> Lookup<'a> {
    let query = query.trim();
    if let Some(profile) = profiles.iter().find(|profile| profile.id == query) {
        return Lookup::Found(profile);
    }
    let lower = query.to_lowercase();
    let by_name: Vec<&Profile> = profiles
        .iter()
        .filter(|profile| profile.name.to_lowercase() == lower)
        .collect();
    match by_name.len() {
        1 => return Lookup::Found(by_name[0]),
        n if n > 1 => return Lookup::Ambiguous(by_name),
        _ => {}
    }
    let by_prefix: Vec<&Profile> = profiles
        .iter()
        .filter(|profile| {
            !lower.is_empty()
                && (profile.id.to_lowercase().starts_with(&lower)
                    || profile.name.to_lowercase().starts_with(&lower))
        })
        .collect();
    match by_prefix.len() {
        0 => Lookup::Missing,
        1 => Lookup::Found(by_prefix[0]),
        _ => Lookup::Ambiguous(by_prefix),
    }
}

/// The `#fragment` of a share link, percent-decoded: the name its author gave.
pub fn link_name(link: &str) -> Option<String> {
    let (_, fragment) = link.split_once('#')?;
    let bytes = fragment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 3 <= bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    let name = String::from_utf8_lossy(&out).trim().to_string();
    (!name.is_empty()).then_some(name)
}

/// A vault-safe profile id from a display name plus a random suffix.
pub fn make_id(name: &str, suffix: &str) -> String {
    let mut slug = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-');
    let slug: String = slug.chars().take(24).collect();
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() {
        format!("profile-{suffix}")
    } else {
        format!("{slug}-{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(id: &str, name: &str) -> Profile {
        Profile {
            id: id.into(),
            name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn links_urls_and_files_are_told_apart_without_the_network() {
        let never = |_: &Path| false;
        assert_eq!(
            classify("vless://abc@host:443?x=y#n", never),
            Input::ShareLink("vless://abc@host:443?x=y#n".into())
        );
        assert!(matches!(classify("HY2://x", never), Input::ShareLink(_)));
        assert_eq!(
            classify("https://sub.example/s/1", never),
            Input::Subscription("https://sub.example/s/1".into())
        );
        let always = |_: &Path| true;
        assert_eq!(
            classify("/tmp/home.conf", always),
            Input::File {
                path: "/tmp/home.conf".into(),
                backend: TunnelBackend::WireGuard
            }
        );
        assert!(matches!(
            classify("office.OVPN", always),
            Input::File {
                backend: TunnelBackend::OpenVpn,
                ..
            }
        ));
        assert_eq!(
            classify("/tmp/local.JSON", always),
            Input::File {
                path: "/tmp/local.JSON".into(),
                backend: TunnelBackend::Xray,
            }
        );
    }

    #[test]
    fn a_missing_file_or_unknown_extension_reads_as_a_saved_profile_name() {
        assert_eq!(
            classify("home.conf", |_: &Path| false),
            Input::Saved("home.conf".into())
        );
        assert_eq!(
            classify("notes.txt", |_: &Path| true),
            Input::Saved("notes.txt".into())
        );
    }

    #[test]
    fn profiles_resolve_by_id_then_name_then_unique_prefix() {
        let profiles = vec![
            profile("home-1a2b", "Home"),
            profile("work-3c4d", "Work VPN"),
            profile("work-9f9f", "Workshop"),
        ];
        assert!(matches!(resolve(&profiles, "home-1a2b"), Lookup::Found(p) if p.name == "Home"));
        assert!(matches!(resolve(&profiles, "home"), Lookup::Found(p) if p.id == "home-1a2b"));
        assert!(matches!(resolve(&profiles, "work vpn"), Lookup::Found(p) if p.id == "work-3c4d"));
        assert!(matches!(resolve(&profiles, "work"), Lookup::Ambiguous(found) if found.len() == 2));
        assert_eq!(resolve(&profiles, "nope"), Lookup::Missing);
        assert_eq!(resolve(&profiles, ""), Lookup::Missing);
    }

    #[test]
    fn a_link_fragment_is_the_name_percent_decoded() {
        assert_eq!(
            link_name("vless://x@h:1?a=b#My%20Server%20%F0%9F%87%A9%F0%9F%87%AA").as_deref(),
            Some("My Server 🇩🇪")
        );
        assert_eq!(link_name("vless://x@h:1").as_deref(), None);
        assert_eq!(link_name("vless://x@h:1#").as_deref(), None);
        assert_eq!(link_name("vless://x@h:1#100%").as_deref(), Some("100%"));
        assert_eq!(link_name("vless://x@h:1#a%zzb").as_deref(), Some("a%zzb"));
    }

    #[test]
    fn ids_are_slugs_the_vault_accepts() {
        assert_eq!(make_id("My Home / VPN!", "ab12"), "my-home-vpn-ab12");
        assert_eq!(make_id("???", "ab12"), "profile-ab12");
        assert_eq!(make_id("Привет", "ab12"), "profile-ab12");
        let id = make_id(&"a".repeat(80), "ab12");
        assert!(id.len() <= 24 + 5);
        net_manager_core::config_vault::sanitize_profile_id(&id).unwrap();
    }
}
