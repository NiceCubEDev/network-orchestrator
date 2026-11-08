//! Exercise the actual macOS command tree and typed services on Unix.
#![cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(unix, feature = "macos-cli")
))]
use serde_json::Value;
use std::process::{Command, Output};

struct Sandbox(tempfile::TempDir);
impl Sandbox {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_netorch"))
            .arg("--data-dir")
            .arg(self.0.path().join("data"))
            .args(args)
            .env("NETORCH_HELPER_SOCKET", self.0.path().join("none.sock"))
            .output()
            .unwrap()
    }
    fn json(&self, args: &[&str]) -> Value {
        let mut argv = vec!["--json"];
        argv.extend_from_slice(args);
        let out = self.run(&argv);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
}
const LINK: &str =
    "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls#Portable";

#[test]
fn actual_business_edits_routing_and_mode_round_trip() {
    let s = Sandbox::new();
    s.json(&["add", LINK]);
    s.json(&[
        "edit",
        "portable",
        "--name",
        "Work",
        "--auto-connect",
        "true",
        "--wait-for-interface",
        "true",
        "--mode",
        "tun",
        "--role",
        "secondary",
        "--networks",
        "10.0.0.0/8",
        "--dns-domains",
        "corp.example",
    ]);
    let rows = s.json(&["ls"]);
    assert_eq!(rows[0]["name"], "Work");
    s.json(&["route", "set", "work", "--block", "domain:ads.example"]);
    let verdict = s.json(&["route", "check", "ads.example", "--profile", "work"]);
    assert_eq!(verdict["outbound"], "block");
    assert_eq!(
        s.json(&["mode", "set", "orchestrator"])["appMode"],
        "orchestrator"
    );
    assert_eq!(s.json(&["mode", "show"])["appMode"], "orchestrator");
    assert_eq!(s.json(&["status", "work"])[0]["state"], "stopped");
    for args in [&["ls"][..], &["status"], &["inspect", "work"]] {
        let out = s.run(args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!text.contains("11111111-2222"));
        assert!(!text.contains("vless://"));
    }
}
#[test]
fn connection_sets_use_shared_store_and_report_missing_members() {
    let s = Sandbox::new();
    s.json(&["add", LINK]);
    let id = s.json(&["ls"])[0]["id"].as_str().unwrap().to_string();
    s.json(&["sets", "put", "work", "--name", "Work", &id]);
    assert_eq!(s.json(&["sets", "list"])[0]["profileIds"][0], id);
    s.json(&["sets", "delete", "work"]);
    assert!(s.json(&["sets", "list"]).as_array().unwrap().is_empty());
    let legacy = s.0.path().join("legacy.json");
    std::fs::write(
        &legacy,
        r#"[{"id":"legacy","name":"Legacy","profileIds":["missing-member"]}]"#,
    )
    .unwrap();
    s.json(&["sets", "import", legacy.to_str().unwrap()]);
    assert_eq!(
        s.json(&["sets", "list"])[0]["profileIds"],
        serde_json::json!(["missing-member"])
    );
    let applied = s.run(&["--json", "sets", "apply", "legacy"]);
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(String::from_utf8_lossy(&applied.stderr).contains("missing-member"));
    assert_eq!(
        serde_json::from_slice::<Value>(&applied.stdout).unwrap()["items"],
        serde_json::json!([])
    );
}
#[test]
fn errors_are_nonzero_and_native_operations_are_not_fake_successes() {
    let s = Sandbox::new();
    for args in [
        &["edit", "missing", "--name", "x"][..],
        &["sets", "apply", "missing"],
        &["route", "lookup", "not-an-ip"],
    ] {
        let out = s.run(args);
        assert!(!out.status.success());
        assert!(!out.stderr.is_empty());
    }
    #[cfg(not(target_os = "macos"))]
    {
        let out = s.run(&["network", "interfaces"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("macOS"));
    }
}
#[test]
fn concurrent_clients_preserve_all_profile_writes() {
    let s = Sandbox::new();
    std::thread::scope(|scope| {
        let joins: Vec<_> = (0..8)
            .map(|i| {
                let s = &s;
                scope.spawn(move || s.run(&["add", LINK, "--name", &format!("Profile {i}")]))
            })
            .collect();
        for join in joins {
            let out = join.join().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    });
    let rows = s.json(&["ls"]);
    let mut names: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "Profile 0",
            "Profile 1",
            "Profile 2",
            "Profile 3",
            "Profile 4",
            "Profile 5",
            "Profile 6",
            "Profile 7"
        ]
    );
}
#[test]
fn credential_values_are_not_accepted_in_arguments() {
    let s = Sandbox::new();
    for flag in ["--password", "--passphrase", "--setup-key"] {
        assert!(!s
            .run(&["up", "saved", flag, "must-not-be-accepted"])
            .status
            .success());
    }
}

#[test]
fn static_and_advanced_routing_documents_use_real_services() {
    let s = Sandbox::new();
    let static_file = s.0.path().join("static.json");
    std::fs::write(&static_file,r#"{"id":"corp-routes","name":"Corp routes","interfaceName":"en0","routes":[{"destination":"10.0.0.0/8","metric":5}],"endpointBypasses":[]}"#).unwrap();
    s.json(&["static", static_file.to_str().unwrap()]);
    assert_eq!(s.json(&["ls"])[0]["kind"], "static");
    s.json(&["add", LINK]);
    let advanced = s.0.path().join("advanced.json");
    std::fs::write(
        &advanced,
        r#"{"domainStrategy":"asIs","domainMatcher":"hybrid","dns":{"fakeDns":true}}"#,
    )
    .unwrap();
    s.json(&[
        "route",
        "set",
        "portable",
        "--direct",
        "domain:corp.example",
        "--advanced",
        advanced.to_str().unwrap(),
    ]);
    let happ = s.0.path().join("happ.json");
    std::fs::write(&happ, r#"{"BlockSites":["domain:ads.example"]}"#).unwrap();
    s.json(&["route", "import", "portable", happ.to_str().unwrap()]);
    let routing = s.json(&["route", "show", "portable"]);
    assert_eq!(routing["domainStrategy"], "asIs");
    assert_eq!(routing["domainMatcher"], "hybrid");
    assert_eq!(routing["dns"]["fakeDns"], true);
    assert_eq!(
        s.json(&["route", "check", "ads.example", "--profile", "portable"])["outbound"],
        "block"
    );
}

#[test]
fn start_policy_rejects_before_installing_or_starting_backend() {
    let s = Sandbox::new();
    s.json(&["add", LINK]);
    s.json(&["mode", "set", "orchestrator"]);
    let out = s.run(&["up", "portable"]);
    assert!(!out.status.success());
    assert!(!s.0.path().join("data/runtime").exists());
    assert!(!s.0.path().join("data/xray").exists());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("11111111"));
}

#[test]
fn profile_lookup_errors_do_not_echo_endpoint_credentials() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["inspect", LINK]);
    assert!(!output.status.success());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(!diagnostic.contains("11111111-2222-3333-4444-555555555555"));
    assert!(!diagnostic.contains("vless://"));
}

#[test]
fn helper_status_does_not_require_a_home_or_profile_directory() {
    let sandbox = Sandbox::new();
    let output = Command::new(env!("CARGO_BIN_EXE_netorch"))
        .env_remove("HOME")
        .env_remove("NETORCH_MACOS_DATA_DIR")
        .env(
            "NETORCH_HELPER_SOCKET",
            sandbox.0.path().join("missing.sock"),
        )
        .args(["--json", "service", "status"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["name"], "helper");
    assert_eq!(report["level"], "warn");
}

#[test]
fn secret_terminal_stdin_is_rejected_before_consuming_input_or_starting_a_runtime() {
    use std::os::fd::FromRawFd;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let sandbox = Sandbox::new();
    sandbox.json(&["add", LINK]);
    sandbox.json(&["sets", "put", "work", "--name", "Work", "portable"]);
    for args in [
        &["netbird", "up", "--setup-key-stdin"][..],
        &["sets", "apply", "work", "--credentials-file", "-"][..],
    ] {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let mut child = Command::new(env!("CARGO_BIN_EXE_netorch"))
            .arg("--data-dir")
            .arg(sandbox.0.path().join("data"))
            .args(args)
            .env("NETORCH_HELPER_SOCKET", sandbox.0.path().join("none.sock"))
            .stdin(slave)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let exited = loop {
            if child.try_wait().unwrap().is_some() {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if !exited {
            child.kill().unwrap();
        }
        let output = child.wait_with_output().unwrap();
        drop(master);
        assert!(exited, "secret command waited for terminal input: {args:?}");
        assert!(!output.status.success());
        assert!(!sandbox.0.path().join("data/runtime").exists());
    }
}
