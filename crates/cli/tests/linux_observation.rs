#![cfg(all(target_os = "linux", not(feature = "macos-cli")))]
use serde_json::Value;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netorch"));
    cmd.env("NETORCH_DATA_DIR", dir.join("data"))
        .env("NETWORK_ORCHESTRATOR_SOCKET", dir.join("missing.sock"));
    cmd
}

fn save_local_profile(dir: &std::path::Path, name: &str) {
    use net_manager_core::models::{Profile, TunnelBackend, XrayMode};
    use net_manager_core::profiles::{ProfileDocument, ProfileStore, PROFILE_DOCUMENT_VERSION};
    let profile = Profile {
        id: "local".into(),
        name: name.into(),
        backend: TunnelBackend::Xray,
        xray_mode: XrayMode::Socks,
        ..Profile::default()
    };
    ProfileStore::new(dir.join("data/profiles.json"))
        .save(&ProfileDocument {
            version: PROFILE_DOCUMENT_VERSION,
            profiles: vec![profile],
        })
        .unwrap();
}

#[test]
fn diagnose_reports_unavailable_daemon_without_exposing_socket_path() {
    let dir = tempfile::tempdir().unwrap();
    let output = command(dir.path())
        .args(["--json", "diagnose"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["daemon"]["available"], false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(dir.path().to_str().unwrap()));
}

#[test]
fn watch_starts_with_snapshot_even_when_daemon_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = ChildGuard(
        command(dir.path())
            .args(["--json", "watch"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let event: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(event["type"], "snapshot");
    assert_eq!(event["daemon"], "unavailable");
    assert!(event["profiles"].is_array());
}

#[test]
fn json_usage_errors_have_structured_output_and_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    let output = command(dir.path())
        .args(["--json", "not-a-command"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "usage");
}

#[test]
fn watch_resync_and_reconnect_refresh_local_profile_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    save_local_profile(dir.path(), "Before");
    let listener = UnixListener::bind(&socket).unwrap();
    let (tx, rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        for turn in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"1\",\"uid\":1000,\"capabilities\":[\"subscribe\"]}}\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            stream
                .write_all(b"{\"id\":2,\"ok\":true,\"result\":null}\n")
                .unwrap();
            if turn == 0 {
                rx.recv().unwrap();
                stream.write_all(b"{\"event\":\"resync\"}\n").unwrap();
                rx.recv().unwrap();
            }
        }
    });
    let mut child = ChildGuard(
        command(dir.path())
            .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
            .args(["--json", "watch"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut read_event = || {
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let initial = read_event();
    assert_eq!(initial["reason"], "initial");
    assert_eq!(initial["profiles"][0]["name"], "Before");
    save_local_profile(dir.path(), "After");
    tx.send(()).unwrap();
    let changed = loop {
        let event = read_event();
        if event["reason"] == "resync" {
            break event;
        }
        assert_eq!(event["reason"], "change");
    };
    assert_eq!(changed["profiles"][0]["name"], "After");
    tx.send(()).unwrap();
    let disconnected = read_event();
    assert_eq!(disconnected["reason"], "disconnected");
    assert_eq!(disconnected["daemon"], "unavailable");
    save_local_profile(dir.path(), "Reconnected");
    let reconnected = loop {
        let event = read_event();
        if event["reason"] == "reconnected" {
            break event;
        }
        assert_eq!(event["reason"], "change");
        assert_eq!(event["daemon"], "unavailable");
    };
    assert_eq!(reconnected["profiles"][0]["name"], "Reconnected");
    server.join().unwrap();
}

#[test]
fn diagnose_reports_missing_subscription_capability() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        stream.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"1\",\"uid\":1000,\"capabilities\":[]}}\n").unwrap();
    });
    let output = command(dir.path())
        .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
        .args(["--json", "diagnose"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["daemon"]["available"], true);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["code"] == "subscribe_unavailable"));
    server.join().unwrap();
}

#[test]
fn watch_observes_local_profile_changes_without_daemon() {
    let dir = tempfile::tempdir().unwrap();
    save_local_profile(dir.path(), "Local");
    let mut child = ChildGuard(
        command(dir.path())
            .args(["--json", "watch"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let first: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(first["daemon"], "unavailable");
    assert_eq!(first["profiles"][0]["name"], "Local");
    save_local_profile(dir.path(), "Changed");
    line.clear();
    output.read_line(&mut line).unwrap();
    let next: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(next["reason"], "change");
    assert_eq!(next["profiles"][0]["name"], "Changed");
}

#[test]
fn watch_reports_stalled_daemon_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        thread::sleep(std::time::Duration::from_secs(3));
    });
    let mut child = ChildGuard(
        command(dir.path())
            .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
            .args(["--json", "watch"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let start = std::time::Instant::now();
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
    let event: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(event["daemon"], "unavailable");
    assert!(event["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["state"] != "running"));
    server.join().unwrap();
}

#[test]
fn daemon_resync_and_reconnect_replace_backend_status() {
    use net_manager_core::models::{Profile, TunnelBackend};
    use net_manager_core::profiles::{ProfileDocument, ProfileStore, PROFILE_DOCUMENT_VERSION};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let dir = tempfile::tempdir().unwrap();
    let profile = Profile {
        id: "routes".into(),
        name: "Routes".into(),
        backend: TunnelBackend::None,
        ..Profile::default()
    };
    ProfileStore::new(dir.path().join("data/profiles.json"))
        .save(&ProfileDocument {
            version: PROFILE_DOCUMENT_VERSION,
            profiles: vec![profile],
        })
        .unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let running = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let server = {
        let running = running.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let running = running.clone();
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let mut reader = BufReader::new(stream.try_clone().unwrap());
                            let mut line = String::new();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            if stream.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"1\",\"uid\":1000,\"capabilities\":[\"subscribe\",\"owned.list\"]}}\n").is_err() { return; }
                            line.clear();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            let request: Value = serde_json::from_str(&line).unwrap();
                            if request["method"] == "subscribe" {
                                stream
                                    .write_all(b"{\"id\":2,\"ok\":true,\"result\":null}\n")
                                    .unwrap();
                                tx.send(stream).unwrap();
                            } else {
                                let owners = if running.load(Ordering::Relaxed) {
                                    serde_json::json!([{"owner":"routes","state":"applied","resources":[]}])
                                } else {
                                    serde_json::json!([])
                                };
                                let response = serde_json::json!({"id":2,"ok":true,"result":{"owners":owners}});
                                let _ = writeln!(stream, "{response}");
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        })
    };
    let mut child = ChildGuard(
        command(dir.path())
            .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
            .args(["--json", "watch"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut read_event = || {
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let mut subscription = rx.recv().unwrap();
    assert_eq!(read_event()["profiles"][0]["state"], "stopped");
    running.store(true, Ordering::Relaxed);
    subscription.write_all(b"{\"event\":\"resync\"}\n").unwrap();
    let event = loop {
        let event = read_event();
        if event["reason"] == "resync" {
            break event;
        }
    };
    assert_eq!(event["profiles"][0]["state"], "running");
    drop(subscription);
    let disconnected = loop {
        let event = read_event();
        if event["reason"] == "disconnected" {
            break event;
        }
    };
    assert_eq!(disconnected["profiles"][0]["state"], "unknown");
    running.store(false, Ordering::Relaxed);
    let _new_subscription = rx.recv().unwrap();
    let reconnected = loop {
        let event = read_event();
        if event["reason"] == "reconnected" {
            break event;
        }
    };
    assert_eq!(reconnected["profiles"][0]["state"], "stopped");
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
}

#[test]
fn json_operation_error_is_redacted_and_exit_one() {
    let dir = tempfile::tempdir().unwrap();
    let output = command(dir.path())
        .args(["--json", "diagnose", "sensitive-input"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "operation");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("sensitive-input"));
}

#[test]
fn recovery_cleanup_attempts_daemon_even_when_local_recovery_fails() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        stream.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"1\",\"uid\":1000,\"capabilities\":[\"recovery.cleanup\"]}}\n").unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["method"], "recovery.cleanup");
        stream.write_all(b"{\"id\":2,\"ok\":true,\"result\":{\"removedOwners\":[],\"failed\":[\"orphan\"]}}\n").unwrap();
    });
    let output = command(dir.path())
        .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
        .env("XDG_RUNTIME_DIR", dir.path().join("missing-runtime"))
        .args(["recover", "--cleanup"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("local"), "{error}");
    assert!(error.contains("daemon"), "{error}");
    server.join().unwrap();
}

#[test]
fn recover_without_cleanup_reports_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let output = command(dir.path())
        .args(["--json", "recover"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["daemon"]["available"], false);
}

#[test]
fn recover_reports_orphan_owner_identity_and_state() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        for call in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"1\",\"uid\":1000,\"capabilities\":[\"owned.list\"]}}\n").unwrap();
            if call == 1 {
                line.clear();
                reader.read_line(&mut line).unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["method"], "owned.list");
                stream.write_all(b"{\"id\":2,\"ok\":true,\"result\":{\"owners\":[{\"owner\":\"orphan-42\",\"state\":\"stale\",\"resources\":[]}]}}\n").unwrap();
            }
        }
    });
    let output = command(dir.path())
        .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
        .args(["--json", "recover"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["recovery"]["daemonOwners"][0]["state"], "stale");
    assert_eq!(report["recovery"]["proxyOwnership"], "absent");
    assert_eq!(report["recovery"]["daemonOwners"][0]["owner"], "orphan-42");
    server.join().unwrap();
}

#[test]
fn recover_reports_persisted_proxy_without_revealing_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let state = serde_json::json!({"version":1,"ownership":{
        "profileId":"orphan","snapshot":{"proxyEnable":null,"proxyServer":"secret-proxy","proxyOverride":null},
        "appliedServer":"secret-proxy","appliedOverride":""
    }});
    std::fs::write(data.join("proxy-state.json"), state.to_string()).unwrap();
    net_manager_core::config_security::protect_path(&data.join("proxy-state.json")).unwrap();
    let output = command(dir.path())
        .args(["--json", "recover"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["recovery"]["proxyOwnership"], "present");
    assert!(!text.contains("secret-proxy"));
    assert!(data.join("proxy-state.json").exists());
}

#[test]
fn diagnose_reports_failed_profile() {
    use net_manager_core::models::{Profile, TunnelBackend};
    use net_manager_core::profiles::{ProfileDocument, ProfileStore, PROFILE_DOCUMENT_VERSION};
    let dir = tempfile::tempdir().unwrap();
    ProfileStore::new(dir.path().join("data/profiles.json"))
        .save(&ProfileDocument {
            version: PROFILE_DOCUMENT_VERSION,
            profiles: vec![Profile {
                id: "routes".into(),
                name: "Routes".into(),
                backend: TunnelBackend::None,
                ..Profile::default()
            }],
        })
        .unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        for call in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"1\",\"uid\":1000,\"capabilities\":[\"owned.list\"]}}\n").unwrap();
            if call == 1 {
                line.clear();
                reader.read_line(&mut line).unwrap();
                stream.write_all(b"{\"id\":2,\"ok\":true,\"result\":{\"owners\":[{\"owner\":\"routes\",\"state\":\"stale\",\"resources\":[]}]}}\n").unwrap();
            }
        }
    });
    let output = command(dir.path())
        .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
        .args(["--json", "diagnose", "Routes"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["profiles"][0]["state"], "failed");
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["code"] == "profile_failed" && finding["level"] == "error"));
    server.join().unwrap();
}

#[test]
fn recovery_json_errors_retain_failed_component_names() {
    let dir = tempfile::tempdir().unwrap();
    let output = command(dir.path())
        .env("XDG_RUNTIME_DIR", dir.path().join("missing-runtime"))
        .args(["--json", "recover", "--cleanup"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    let message = error["error"]["message"].as_str().unwrap();
    assert!(message.contains("local"));
    assert!(message.contains("daemon"));
    assert!(!message.contains(dir.path().to_str().unwrap()));
}

#[test]
fn watch_fails_explicitly_when_daemon_cannot_subscribe() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        stream.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"1\",\"uid\":1000,\"capabilities\":[]}}\n").unwrap();
    });
    let mut child = ChildGuard(
        command(dir.path())
            .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
            .args(["--json", "watch"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        thread::sleep(std::time::Duration::from_millis(20));
    };
    assert_eq!(
        status.and_then(|status| status.code()),
        Some(1),
        "watch must not silently retry unsupported subscription"
    );
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.0.stderr.take().unwrap(), &mut stderr).unwrap();
    let error: Value = serde_json::from_str(&stderr).unwrap();
    assert_eq!(error["error"]["kind"], "operation");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Update"));
    server.join().unwrap();
}

#[test]
fn watch_fails_if_reconnected_daemon_lacks_subscription() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        for turn in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let capabilities = if turn == 0 { "[\"subscribe\"]" } else { "[]" };
            writeln!(stream, "{{\"id\":1,\"ok\":true,\"result\":{{\"protocol\":1,\"daemonVersion\":\"1\",\"uid\":1000,\"capabilities\":{capabilities}}}}}").unwrap();
            if turn == 0 {
                line.clear();
                reader.read_line(&mut line).unwrap();
                stream
                    .write_all(b"{\"id\":2,\"ok\":true,\"result\":null}\n")
                    .unwrap();
            }
        }
    });
    let mut child = ChildGuard(
        command(dir.path())
            .env("NETWORK_ORCHESTRATOR_SOCKET", &socket)
            .args(["--json", "watch"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        thread::sleep(std::time::Duration::from_millis(20));
    };
    assert_eq!(status.and_then(|status| status.code()), Some(1));
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.0.stderr.take().unwrap(), &mut stderr).unwrap();
    let error: Value = serde_json::from_str(&stderr).unwrap();
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Update"));
    server.join().unwrap();
}

#[test]
fn watch_exits_cleanly_when_consumer_closes_pipe() {
    let dir = tempfile::tempdir().unwrap();
    save_local_profile(dir.path(), "Before");
    let mut child = ChildGuard(
        command(dir.path())
            .args(["--json", "watch"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["type"],
        "snapshot"
    );
    drop(output);
    save_local_profile(dir.path(), "After");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        thread::sleep(std::time::Duration::from_millis(20));
    };
    assert_eq!(status.and_then(|status| status.code()), Some(0));
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.0.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(!stderr.contains("panicked"), "{stderr}");
}
