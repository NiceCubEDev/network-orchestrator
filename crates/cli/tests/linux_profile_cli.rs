//! Real Linux CLI consumers against a temporary vault and a stopped fake daemon.
#![cfg(all(target_os = "linux", not(feature = "macos-cli")))]

use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::{
    encode_line, method, ErrorCode, HelloResult, RequestFrame, ResponseFrame, PROTOCOL_VERSION,
    SOCKET_ENV,
};
use net_manager_core::models::{
    DomainPolicy, DomainRouteTarget, NamedProxyExit, PinnedRoute, Profile, ProxyTarget,
    ServiceCheck, TunnelRole, XrayMode,
};
use net_manager_core::profiles::ProfileStore;
use net_manager_core::subscription::{self, ResponseMeta, SubscriptionImport};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

const PROFILE_ID: &str = "saved-subscription";
const URL: &str =
    "https://subscription.invalid/device/fixture-subscription-token?auth=fixture-query-token";
const HWID: &str = "original-fixture-hwid-97c82d18";
const FIRST: &str = "vless://11111111-2222-4333-8444-555555555555@first.invalid:443?type=tcp&security=tls&sni=first.invalid#First";
const SECOND: &str = "vless://aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee@second.invalid:443?type=tcp&security=tls&sni=second.invalid#Second";

struct Sandbox {
    dir: tempfile::TempDir,
    stop: Arc<AtomicBool>,
    daemon: Option<JoinHandle<()>>,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let daemon = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap() != 0 {
                    let request: RequestFrame = serde_json::from_str(&line).unwrap();
                    // Only read-only stopped-state guards are allowed in this fixture.
                    let response = match request.method.as_str() {
                        method::HELLO => ResponseFrame::ok(
                            request.id,
                            serde_json::to_value(HelloResult {
                                protocol: PROTOCOL_VERSION,
                                daemon_version: net_manager_core::VERSION.into(),
                                uid: unsafe { libc::geteuid() },
                                capabilities: method::CAPABILITIES
                                    .iter()
                                    .map(|name| (*name).into())
                                    .collect(),
                                tools: Default::default(),
                            })
                            .unwrap(),
                        ),
                        method::XRAY_STATUS => ResponseFrame::ok(
                            request.id,
                            json!({
                                "profileId": request.params["profileId"],
                                "state": "stopped",
                                "interfaceName": null,
                                "dnsApplied": false,
                                "ipv4Covered": false,
                                "ipv6Covered": false,
                            }),
                        ),
                        _ => ResponseFrame::error(
                            request.id,
                            ErrorCode::NotAuthorized,
                            "Fixture permits read-only guards only",
                        ),
                    };
                    stream.write_all(&encode_line(&response).unwrap()).unwrap();
                    line.clear();
                }
            }
        });
        Self {
            dir,
            stop,
            daemon: Some(daemon),
        }
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn store(&self) -> ProfileStore {
        ProfileStore::new(self.root().join("profiles.json"))
    }

    fn vault(&self) -> ConfigVault {
        ConfigVault::new(self.root().join("configs"))
    }

    fn file(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_netorch"))
            .arg("--data-dir")
            .arg(self.root())
            .args(args)
            .env("HOME", self.dir.path())
            .env("XDG_DATA_HOME", self.dir.path().join("xdg-data"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("xdg-config"))
            .env("XDG_CACHE_HOME", self.dir.path().join("xdg-cache"))
            .env("XDG_RUNTIME_DIR", self.dir.path())
            .env(SOCKET_ENV, self.dir.path().join("daemon.sock"))
            .env(
                "NETORCH_HELPER_SOCKET",
                self.dir.path().join("missing-helper.sock"),
            )
            .env_remove("SUDO_UID")
            .env_remove("SUDO_USER")
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            combined(&output)
        );
        output
    }

    fn profile(&self, id: &str) -> Profile {
        self.store()
            .load()
            .unwrap()
            .profiles
            .into_iter()
            .find(|p| p.id == id)
            .unwrap()
    }

    fn seed(&self) -> Profile {
        let imported = subscription::import_body(
            &self.vault(),
            &self.store(),
            &SubscriptionImport {
                id: PROFILE_ID,
                url: URL,
                hwid: HWID,
                name: "Saved subscription",
                refresh_interval_minutes: Some(60),
            },
            &format!("{FIRST}\n{SECOND}\n"),
            ResponseMeta::default(),
            net_manager_core::models::XrayMode::platform_default(),
            |_| true,
        )
        .unwrap();
        assert!(imported.errors.is_empty());
        let key = subscription::endpoint_key(FIRST);
        let mut profile = self.profile(PROFILE_ID);
        profile.xray_mode = XrayMode::Tun;
        profile.private_lan_direct = true;
        profile.xray_split_default = true;
        profile.xray_quic_reject = true;
        profile.xray_tun_mtu = Some(1360);
        profile.domain_policies = vec![DomainPolicy {
            target: DomainRouteTarget::Direct,
            domains: vec!["domain:office.invalid".into()],
        }];
        profile.pinned_policies = vec![PinnedRoute {
            selectors: vec!["domain:pinned.invalid".into()],
            endpoint_key: key.clone(),
            missing: false,
        }];
        profile.xray_service_checks = vec![ServiceCheck {
            id: "fixture-check".into(),
            name: "Fixture health".into(),
            url: "https://health.invalid/check?token=fixture-check-token".into(),
            endpoint_key: key.clone(),
            background: false,
        }];
        profile.xray_proxy_exits = vec![NamedProxyExit {
            name: "office".into(),
            target: ProxyTarget::Node { endpoint_key: key },
            no_proxy: vec!["localhost".into()],
        }];
        self.store().upsert(profile.clone()).unwrap();
        self.store()
            .upsert(Profile {
                id: "untouched".into(),
                name: "Unrelated profile".into(),
                ..Profile::default()
            })
            .unwrap();
        profile
    }

    fn edit(&self, patch: Value) -> Output {
        let file = self.file("patch.json", serde_json::to_vec(&patch).unwrap());
        self.run(&[
            "profile",
            "edit",
            PROFILE_ID,
            "--file",
            file.to_str().unwrap(),
        ])
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(self.dir.path().join("daemon.sock"));
        self.daemon.take().unwrap().join().unwrap();
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_redacted(output: &Output) {
    let text = combined(output);
    for secret in [
        URL,
        HWID,
        FIRST,
        SECOND,
        "fixture-subscription-token",
        "fixture-query-token",
        "fixture-check-token",
        "11111111-2222-4333-8444-555555555555",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "subscription.invalid",
        "first.invalid",
        "second.invalid",
        "vless://",
        "\"outbounds\"",
        "\"inbounds\"",
    ] {
        assert!(
            !text.contains(secret),
            "CLI output exposed fixture secret {secret:?}"
        );
    }
}

fn assert_private(path: &Path) {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o077,
        0,
        "{} is accessible to other users",
        path.display()
    );
}

#[test]
fn cached_subscription_import_preserves_original_hwid_and_only_valid_endpoints() {
    let sandbox = Sandbox::new();
    let url = sandbox.file("url.txt", format!("{URL}\n"));
    let hwid = sandbox.file("hwid.txt", format!("{HWID}\n"));
    let cache = sandbox.file(
        "nodes.txt",
        format!("vless://malformed\n{FIRST}\nss://unsupported-fixture\n{SECOND}\n"),
    );
    let output = sandbox.ok(&[
        "subscription",
        "import",
        "--url-file",
        url.to_str().unwrap(),
        "--hwid-file",
        hwid.to_str().unwrap(),
        "--cache-file",
        cache.to_str().unwrap(),
        "--name",
        "Offline subscription",
    ]);
    assert_redacted(&output);
    let document = sandbox.store().load().unwrap();
    assert_eq!(document.profiles.len(), 1);
    let profile = &document.profiles[0];
    assert_eq!(profile.name, "Offline subscription");
    let meta = profile.subscription.as_ref().unwrap();
    assert_eq!(meta.url, URL);
    assert_eq!(meta.hwid, HWID);
    assert_eq!(meta.endpoint_count, 2);
    let endpoints = sandbox
        .vault()
        .read_subscription_endpoints(&profile.id)
        .unwrap();
    assert_eq!(
        endpoints.iter().map(|e| e.url.as_str()).collect::<Vec<_>>(),
        [FIRST, SECOND]
    );
    assert_eq!(
        meta.active_key.as_deref(),
        Some(subscription::endpoint_key(FIRST).as_str())
    );
    let config: Value = serde_json::from_slice(&fs::read(&profile.config_path).unwrap()).unwrap();
    assert_eq!(
        config["outbounds"][0]["settings"]["vnext"][0]["address"],
        "first.invalid"
    );
    assert_eq!(
        config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"],
        "11111111-2222-4333-8444-555555555555"
    );
    assert!(sandbox
        .vault()
        .is_managed_profile_path(&profile.id, &profile.config_path));
    for path in [
        sandbox.root(),
        sandbox.root().join("profiles.json"),
        sandbox.vault().root().to_path_buf(),
        profile.config_path.clone(),
        profile.config_path.parent().unwrap().to_path_buf(),
        sandbox.vault().root().join(&profile.id),
        sandbox
            .vault()
            .root()
            .join(&profile.id)
            .join("subscription.json"),
    ] {
        assert_private(&path);
    }
}

#[test]
fn profile_show_redacts_subscription_credentials_and_raw_config_in_text_and_json() {
    let sandbox = Sandbox::new();
    let profile = sandbox.seed();
    let before = fs::read(sandbox.root().join("profiles.json")).unwrap();
    for args in [
        vec!["profile", "show", PROFILE_ID],
        vec!["--json", "profile", "show", PROFILE_ID],
    ] {
        let output = sandbox.ok(&args);
        assert_redacted(&output);
        assert!(!combined(&output).contains(profile.config_path.to_str().unwrap()));
        if args[0] == "--json" {
            let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(shown["id"], PROFILE_ID);
            assert_eq!(shown["name"], "Saved subscription");
        } else {
            assert!(String::from_utf8_lossy(&output.stdout).contains("Saved subscription"));
        }
    }
    assert_eq!(
        fs::read(sandbox.root().join("profiles.json")).unwrap(),
        before
    );
}

#[test]
fn profile_partial_edit_preserves_canonical_subscription_pins_checks_and_named_exits() {
    let sandbox = Sandbox::new();
    let mut expected = sandbox.seed();
    let mut document = sandbox.store().load().unwrap();
    let config = fs::read(&expected.config_path).unwrap();
    let endpoints = sandbox
        .vault()
        .read_subscription_endpoints(PROFILE_ID)
        .unwrap();
    let output = sandbox.edit(json!({"name": "Renamed offline", "autoConnect": true}));
    assert!(
        output.status.success(),
        "partial edit failed: {}",
        combined(&output)
    );
    assert_redacted(&output);
    expected.name = "Renamed offline".into();
    expected.auto_connect = true;
    *document
        .profiles
        .iter_mut()
        .find(|p| p.id == PROFILE_ID)
        .unwrap() = expected.clone();
    assert_eq!(sandbox.store().load().unwrap(), document);
    assert_eq!(fs::read(&expected.config_path).unwrap(), config);
    assert_eq!(
        sandbox
            .vault()
            .read_subscription_endpoints(PROFILE_ID)
            .unwrap(),
        endpoints
    );
}

#[test]
fn profile_role_edits_validate_the_merged_profile_and_reject_atomically() {
    let sandbox = Sandbox::new();
    sandbox.seed();
    let output = sandbox.edit(json!({
        "tunnelRole": "secondary", "tunnelNetworks": ["10.42.0.0/16", "fd42::/64"],
        "tunnelDnsDomains": ["corp.invalid"],
    }));
    assert!(
        output.status.success(),
        "valid secondary edit failed: {}",
        combined(&output)
    );
    let profile = sandbox.profile(PROFILE_ID);
    assert_eq!(profile.tunnel_role, TunnelRole::Secondary);
    assert_eq!(
        profile
            .tunnel_networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.42.0.0/16", "fd42::/64"]
    );
    assert_eq!(profile.tunnel_dns_domains, ["corp.invalid"]);
    let before = fs::read(sandbox.root().join("profiles.json")).unwrap();
    let config = fs::read(&profile.config_path).unwrap();
    let endpoints = sandbox
        .vault()
        .read_subscription_endpoints(PROFILE_ID)
        .unwrap();
    for invalid in [
        json!({"name": "Must not commit", "tunnelNetworks": []}),
        json!({"name": "Must not commit", "tunnelNetworks": ["0.0.0.0/0"]}),
        json!({"name": "Must not commit", "tunnelNetworks": ["::/0"]}),
        json!({"name": "Must not commit", "tunnelNetworks": ["not-a-network"]}),
        json!({"name": "Must not commit", "tunnelDnsDomains": ["https://bad.invalid/path"]}),
    ] {
        let output = sandbox.edit(invalid);
        assert!(
            !output.status.success(),
            "invalid secondary patch was saved"
        );
        assert_redacted(&output);
        assert_eq!(
            fs::read(sandbox.root().join("profiles.json")).unwrap(),
            before
        );
        assert_eq!(fs::read(&profile.config_path).unwrap(), config);
        assert_eq!(
            sandbox
                .vault()
                .read_subscription_endpoints(PROFILE_ID)
                .unwrap(),
            endpoints
        );
    }
}
