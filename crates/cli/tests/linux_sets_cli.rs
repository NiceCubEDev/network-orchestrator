//! Real CLI consumers of the shared connection-set store. All data is temporary;
//! daemon sockets point inside the sandbox and no tunnel is started.
#![cfg(all(target_os = "linux", not(feature = "macos-cli")))]

use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::SOCKET_ENV;
use net_manager_core::models::{Profile, TunnelBackend, XrayMode};
use net_manager_core::profiles::ProfileStore;
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Barrier};
use std::time::Duration;

const FIRST: &str = "managed-first";
const SECOND: &str = "managed-second";

struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        let vault = ConfigVault::new(sandbox.root().join("configs"));
        for (id, name) in [(FIRST, "First fixture"), (SECOND, "Second fixture")] {
            let config = vault
                .store_generated_xray(
                    id,
                    br#"{"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}"#,
                )
                .unwrap();
            sandbox
                .store()
                .upsert(Profile {
                    id: id.into(),
                    name: name.into(),
                    backend: TunnelBackend::Xray,
                    config_path: config.config_path,
                    xray_mode: XrayMode::Tun,
                    ..Profile::default()
                })
                .unwrap();
        }
        sandbox
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn store(&self) -> ProfileStore {
        ProfileStore::new(self.root().join("profiles.json"))
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("daemon.sock")
    }

    fn file(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_netorch"));
        command
            .arg("--data-dir")
            .arg(self.root())
            .env("HOME", self.dir.path())
            .env("XDG_DATA_HOME", self.dir.path().join("xdg-data"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("xdg-config"))
            .env("XDG_CACHE_HOME", self.dir.path().join("xdg-cache"))
            .env("XDG_RUNTIME_DIR", self.dir.path())
            .env("NETORCH_DATA_DIR", self.root())
            .env(SOCKET_ENV, self.socket())
            .env(
                "NETORCH_HELPER_SOCKET",
                self.dir.path().join("missing-helper.sock"),
            )
            .env_remove("SUDO_UID")
            .env_remove("SUDO_USER");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert_success(args, &output);
        output
    }

    fn list(&self) -> Vec<Value> {
        let output = self.ok(&["--json", "sets", "list"]);
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut sets = value
            .as_array()
            .expect("sets list returns an array")
            .clone();
        sets.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        sets
    }

    fn put(&self, name: &str, value: &Value) {
        let file = self.file(name, value);
        self.ok(&["sets", "put", "--file", file.to_str().unwrap()]);
    }

    fn import(&self, file: &Path) -> Output {
        self.ok(&["sets", "import", "--file", file.to_str().unwrap()])
    }

    fn sets_bytes(&self) -> Vec<u8> {
        fs::read(self.root().join("connection-sets.json")).unwrap()
    }

    fn profile_bytes(&self) -> Vec<u8> {
        fs::read(self.root().join("profiles.json")).unwrap()
    }
}

fn connection_set(id: &str, name: &str, members: &[&str]) -> Value {
    json!({"id": id, "name": name, "profileIds": members})
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_success(args: &[&str], output: &Output) {
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        combined(output)
    );
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
fn sets_persist_across_processes_and_put_updates_only_the_selected_set() {
    let sandbox = Sandbox::new();
    let profiles_before = sandbox.profile_bytes();
    assert!(sandbox.list().is_empty());
    let work = connection_set("work", "Work", &[FIRST, SECOND]);
    let home = connection_set("home", "Home", &[SECOND]);
    sandbox.put("work.json", &work);
    sandbox.put("home.json", &home);
    assert_eq!(sandbox.list(), vec![home.clone(), work]);

    let revised = connection_set("work", "Work revised", &[FIRST]);
    sandbox.put("work-revised.json", &revised);
    assert_eq!(sandbox.list(), vec![home, revised.clone()]);
    sandbox.ok(&["sets", "remove", "home"]);
    assert_eq!(sandbox.list(), vec![revised]);
    sandbox.ok(&["sets", "remove", "work"]);
    assert!(sandbox.list().is_empty());
    assert_eq!(sandbox.profile_bytes(), profiles_before);

    let path = sandbox.root().join("connection-sets.json");
    let document: Value = serde_json::from_slice(&sandbox.sets_bytes()).unwrap();
    assert!(
        document["version"].as_u64().is_some(),
        "store must be versioned"
    );
    assert_private(&sandbox.root());
    assert_private(&path);
    assert!(
        Sandbox::new().list().is_empty(),
        "data roots must be isolated"
    );
}

#[test]
fn legacy_import_is_idempotent_and_never_replaces_newer_or_unrelated_shared_sets() {
    let sandbox = Sandbox::new();
    let unrelated = connection_set("unrelated", "Shared independently", &[SECOND]);
    sandbox.put("unrelated.json", &unrelated);
    let legacy = connection_set("legacy", "Old browser snapshot", &[FIRST]);
    let file = sandbox.file("legacy.json", &json!([legacy.clone()]));
    sandbox.import(&file);
    assert_eq!(sandbox.list(), vec![legacy.clone(), unrelated.clone()]);
    sandbox.import(&file);
    assert_eq!(sandbox.list(), vec![legacy, unrelated.clone()]);

    let newer = connection_set("legacy", "Edited after migration", &[SECOND]);
    let added = connection_set("added", "Saved by another frontend", &[FIRST, SECOND]);
    sandbox.put("newer.json", &newer);
    sandbox.put("added.json", &added);
    sandbox.import(&file);
    assert_eq!(sandbox.list(), vec![added, newer, unrelated]);
}

#[test]
fn concurrent_imports_and_puts_merge_without_losing_successful_writes() {
    let sandbox = Sandbox::new();
    assert!(sandbox.list().is_empty());
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    let mut expected = Vec::new();
    for worker in 0..4 {
        let imported: Vec<_> = (0..12)
            .map(|item| {
                connection_set(
                    &format!("import-{worker}-{item:02}"),
                    &format!("Imported {worker} {item}"),
                    &[FIRST],
                )
            })
            .collect();
        let file = sandbox.file(&format!("import-{worker}.json"), &json!(imported));
        expected.extend(imported);
        let mut command = sandbox.command();
        command.args(["sets", "import", "--file"]).arg(file);
        let start = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            start.wait();
            command.output().unwrap()
        }));

        let saved = connection_set(&format!("put-{worker}"), "Independent save", &[SECOND]);
        let file = sandbox.file(&format!("put-{worker}.json"), &saved);
        expected.push(saved);
        let mut command = sandbox.command();
        command.args(["sets", "put", "--file"]).arg(file);
        let start = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            start.wait();
            command.output().unwrap()
        }));
    }
    for worker in workers {
        assert_success(&["concurrent sets write"], &worker.join().unwrap());
    }
    expected.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    assert_eq!(sandbox.list(), expected);
}

#[test]
fn invalid_puts_leave_existing_sets_and_profiles_byte_for_byte_unchanged() {
    let sandbox = Sandbox::new();
    let original = connection_set("saved", "Saved", &[FIRST]);
    sandbox.put("saved.json", &original);
    let sets_before = sandbox.sets_bytes();
    let profiles_before = sandbox.profile_bytes();
    let invalid = [
        connection_set("saved", "Unknown member", &[FIRST, "unknown-profile"]),
        connection_set("saved", "Duplicate members", &[FIRST, FIRST]),
        connection_set("saved", "Blank member", &[""]),
        connection_set("saved", "", &[FIRST]),
        connection_set("saved", " \t\n ", &[FIRST]),
        connection_set("saved", "Invalid\nname", &[FIRST]),
        connection_set("", "Blank set ID", &[FIRST]),
    ];
    for (index, value) in invalid.iter().enumerate() {
        let file = sandbox.file(&format!("invalid-put-{index}.json"), value);
        let output = sandbox.run(&["sets", "put", "--file", file.to_str().unwrap()]);
        assert!(!output.status.success(), "invalid put {index} succeeded");
        assert_eq!(
            sandbox.sets_bytes(),
            sets_before,
            "put {index} modified the store"
        );
        assert_eq!(sandbox.profile_bytes(), profiles_before);
        assert_eq!(sandbox.list(), vec![original.clone()]);
    }
}

#[test]
fn invalid_legacy_batches_reject_atomically_including_duplicate_set_ids() {
    let sandbox = Sandbox::new();
    let original = connection_set("saved", "Saved", &[FIRST]);
    sandbox.put("saved.json", &original);
    let sets_before = sandbox.sets_bytes();
    let profiles_before = sandbox.profile_bytes();
    let valid = connection_set("new", "Valid first entry", &[SECOND]);
    let invalid_batches = [
        json!([valid.clone(), connection_set("bad", "", &[FIRST])]),
        json!([valid.clone(), connection_set("bad", " \t ", &[FIRST])]),
        json!([valid.clone(), connection_set("bad", "Bad\nname", &[FIRST])]),
        json!([
            valid.clone(),
            connection_set("bad", "Duplicate members", &[FIRST, FIRST])
        ]),
        json!([valid.clone(), connection_set("bad", "Blank member", &[""])]),
        json!([
            valid.clone(),
            connection_set("new", "Conflicting ID", &[FIRST])
        ]),
        json!([valid.clone(), valid.clone()]),
    ];
    for (index, batch) in invalid_batches.iter().enumerate() {
        let file = sandbox.file(&format!("invalid-import-{index}.json"), batch);
        let output = sandbox.run(&["sets", "import", "--file", file.to_str().unwrap()]);
        assert!(!output.status.success(), "invalid import {index} succeeded");
        assert_eq!(
            sandbox.sets_bytes(),
            sets_before,
            "import {index} partially committed"
        );
        assert_eq!(sandbox.profile_bytes(), profiles_before);
        assert_eq!(sandbox.list(), vec![original.clone()]);
    }
}

#[test]
fn missing_legacy_members_are_preserved_reported_and_reject_apply_before_daemon_contact() {
    let sandbox = Sandbox::new();
    let missing_id = "departed-member";
    let legacy = connection_set("legacy", "Needs repair", &[FIRST, missing_id]);
    let file = sandbox.file("legacy-missing.json", &json!([legacy.clone()]));
    let imported = sandbox.import(&file);
    let report = combined(&imported).to_lowercase();
    assert!(
        report.contains(missing_id),
        "import must identify unresolved membership"
    );
    assert!(
        report.contains("missing") || report.contains("unresolved") || report.contains("not found"),
        "import must report missing members, not silently retain them: {report}"
    );
    assert_eq!(sandbox.list(), vec![legacy.clone()]);
    let sets_before = sandbox.sets_bytes();
    let profiles_before = sandbox.profile_bytes();
    let configs_before: Vec<_> = sandbox
        .store()
        .load()
        .unwrap()
        .profiles
        .iter()
        .map(|profile| {
            (
                profile.config_path.clone(),
                fs::read(&profile.config_path).unwrap(),
            )
        })
        .collect();

    // A connection trap is not a daemon: it returns no synthetic runtime state.
    // It closes any request immediately and records whether preflight contacted it.
    let listener = UnixListener::bind(sandbox.socket()).unwrap();
    let trap = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0];
        stream.read(&mut byte).unwrap_or(0) != 0
    });
    let output = sandbox.run(&["sets", "apply", "legacy"]);
    // Release the trap when correct fail-closed preflight never opened a socket.
    drop(UnixStream::connect(sandbox.socket()));
    let contacted_daemon = trap.join().unwrap();
    assert!(
        !output.status.success(),
        "unresolved membership must fail apply"
    );
    assert!(
        combined(&output).contains(missing_id),
        "apply must identify the missing member: {}",
        combined(&output)
    );
    assert!(
        !contacted_daemon,
        "missing-member preflight reached the daemon"
    );
    assert_eq!(sandbox.sets_bytes(), sets_before);
    assert_eq!(sandbox.profile_bytes(), profiles_before);
    for (path, bytes) in configs_before {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert_eq!(sandbox.list(), vec![legacy]);
}
