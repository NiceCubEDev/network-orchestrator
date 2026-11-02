//! Interface-scoped QUIC rejection. Never flushes a caller's firewall tables.
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub trait QuicRejectExecutor: Send {
    fn ensure(&mut self, uid: u32, name: &str) -> io::Result<()>;
    fn remove(&mut self, uid: u32, name: &str) -> io::Result<()>;
}

pub struct TrustedQuicReject;

struct Owner {
    table: String,
    marker: String,
    interface: String,
}

impl Owner {
    fn new(uid: u32, name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid QUIC rejection interface",
            ));
        }
        Ok(Self {
            table: format!("netorch_quic_{uid}_{name}"),
            marker: format!("network-orchestrator:xray:{uid}:{name}"),
            interface: name.into(),
        })
    }

    fn expr(&self) -> Value {
        json!([
            {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": self.interface}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 443}},
            // ICMPX_PORT_UNREACH: numeric output is stable under nft --numeric.
            {"reject": {"type": "icmpx", "expr": 1}}
        ])
    }

    fn batch(&self, replace: bool) -> Value {
        let mut commands = Vec::with_capacity(4);
        if replace {
            commands.push(json!({"delete": {"table": {"family": "inet", "name": self.table}}}));
        }
        commands.extend([
            json!({"add": {"table": {"family": "inet", "name": self.table, "comment": self.marker}}}),
            json!({"add": {"chain": {"family": "inet", "table": self.table, "name": "output", "type": "filter", "hook": "output", "prio": -10, "policy": "accept"}}}),
            json!({"add": {"rule": {"family": "inet", "table": self.table, "chain": "output", "expr": self.expr()}}}),
        ]);
        json!({"nftables": commands})
    }

    /// A comment is an ownership boundary, not merely a convenient name.
    fn intact(&self, document: &Value) -> io::Result<bool> {
        let objects = objects(document)?;
        let table = objects
            .iter()
            .filter_map(|v| v.get("table"))
            .find(|v| {
                v.get("family").and_then(Value::as_str) == Some("inet")
                    && v.get("name").and_then(Value::as_str) == Some(self.table.as_str())
            })
            .ok_or_else(unavailable)?;
        if table.get("comment").and_then(Value::as_str) != Some(self.marker.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "QUIC firewall table is owned by another manager",
            ));
        }
        let chains: Vec<_> = objects.iter().filter_map(|v| v.get("chain")).collect();
        let rules: Vec<_> = objects.iter().filter_map(|v| v.get("rule")).collect();
        let chain_ok = chains.len() == 1
            && chains[0].get("name").and_then(Value::as_str) == Some("output")
            && chains[0].get("type").and_then(Value::as_str) == Some("filter")
            && chains[0].get("hook").and_then(Value::as_str) == Some("output")
            && chains[0].get("prio").and_then(Value::as_i64) == Some(-10)
            && chains[0].get("policy").and_then(Value::as_str) == Some("accept");
        Ok(chain_ok
            && table
                .get("flags")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            && rules.len() == 1
            && rules[0].get("chain").and_then(Value::as_str) == Some("output")
            && rules[0].get("expr") == Some(&self.expr()))
    }
}

fn objects(document: &Value) -> io::Result<&Vec<Value>> {
    document
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(unavailable)
}

fn unavailable() -> io::Error {
    io::Error::other("owned QUIC firewall operation failed")
}

fn trusted_nft() -> io::Result<PathBuf> {
    for candidate in ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"] {
        let Ok(path) = std::fs::canonicalize(candidate) else {
            continue;
        };
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
        {
            continue;
        }
        let parents_safe = path.parent().is_some_and(|parent| {
            parent.ancestors().all(|ancestor| {
                std::fs::metadata(ancestor)
                    .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0)
            })
        });
        if parents_safe {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "trusted nftables binary is unavailable; install nftables",
    ))
}

/// Generated input is below PIPE_BUF; output and process lifetime are bounded.
fn run(binary: &Path, args: &[&str], input: Option<&Value>) -> io::Result<Output> {
    const LIMIT: u64 = 256 * 1024;
    let bytes = input
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| unavailable())?;
    if bytes.as_ref().is_some_and(|v| v.len() > 4096) {
        return Err(unavailable());
    }
    let mut child = Command::new(binary)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| unavailable())?;
    let reader = child.stdout.take().map(|stdout| {
        std::thread::spawn(move || {
            let mut stdout = stdout;
            let mut bytes = Vec::new();
            stdout.by_ref().take(LIMIT + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > LIMIT {
                // Continue draining without allocating, so the parent can reap the child.
                io::copy(&mut stdout, &mut io::sink())?;
                return Err(unavailable());
            }
            Ok(bytes)
        })
    });
    if let Some(bytes) = bytes {
        let result = child
            .stdin
            .take()
            .ok_or_else(unavailable)
            .and_then(|mut stdin| stdin.write_all(&bytes));
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(reader) = reader {
                let _ = reader.join();
            }
            return Err(unavailable());
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(reader) = reader {
                    let _ = reader.join();
                }
                return Err(io::Error::new(
                    if result.is_err() {
                        io::ErrorKind::Other
                    } else {
                        io::ErrorKind::TimedOut
                    },
                    "owned QUIC firewall command failed",
                ));
            }
        }
    };
    let stdout = reader
        .ok_or_else(unavailable)?
        .join()
        .map_err(|_| unavailable())??;
    Ok(Output {
        status,
        stdout,
        stderr: Vec::new(),
    })
}

fn inspect(binary: &Path, owner: &Owner) -> io::Result<Option<bool>> {
    let tables = run(binary, &["-n", "-j", "list", "tables"], None)?;
    if !tables.status.success() {
        return Err(unavailable());
    }
    let document: Value = serde_json::from_slice(&tables.stdout).map_err(|_| unavailable())?;
    let exists = objects(&document)?
        .iter()
        .filter_map(|v| v.get("table"))
        .any(|v| {
            v.get("family").and_then(Value::as_str) == Some("inet")
                && v.get("name").and_then(Value::as_str) == Some(owner.table.as_str())
        });
    if !exists {
        return Ok(None);
    }
    let table = run(
        binary,
        &["-n", "-j", "list", "table", "inet", &owner.table],
        None,
    )?;
    if !table.status.success() {
        return Err(unavailable());
    }
    let document = serde_json::from_slice(&table.stdout).map_err(|_| unavailable())?;
    owner.intact(&document).map(Some)
}

impl QuicRejectExecutor for TrustedQuicReject {
    fn ensure(&mut self, uid: u32, name: &str) -> io::Result<()> {
        let owner = Owner::new(uid, name)?;
        let binary = trusted_nft()?;
        let state = inspect(&binary, &owner)?;
        if state == Some(true) {
            return Ok(());
        }
        let result = run(
            &binary,
            &["-j", "-f", "-"],
            Some(&owner.batch(state.is_some())),
        )?;
        if !result.status.success() {
            return Err(unavailable());
        }
        Ok(())
    }

    fn remove(&mut self, uid: u32, name: &str) -> io::Result<()> {
        let owner = Owner::new(uid, name)?;
        let binary = trusted_nft()?;
        if inspect(&binary, &owner)?.is_none() {
            return Ok(());
        }
        let result = run(&binary, &["delete", "table", "inet", &owner.table], None)?;
        if !result.status.success() {
            return Err(unavailable());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(owner: &Owner) -> Value {
        // Canonical `nft --numeric --json list table` from the real kernel:
        // UDP payload implies l4proto, and icmpx uses its numeric code.
        json!({"nftables": [
            {"table": {"family": "inet", "name": owner.table, "comment": owner.marker, "handle": 1}},
            {"chain": {"family": "inet", "table": owner.table, "name": "output", "type": "filter", "hook": "output", "prio": -10, "policy": "accept", "handle": 1}},
            {"rule": {"family": "inet", "table": owner.table, "chain": "output", "handle": 2, "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": owner.interface}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 443}},
                {"reject": {"type": "icmpx", "expr": 1}}
            ]}}
        ]})
    }

    #[test]
    fn ownership_collision_cannot_authorize_replacement_or_removal() {
        let owner = Owner::new(1001, "xray-test").unwrap();
        let mut table = installed(&owner);
        table["nftables"][0]["table"]["comment"] = json!("another-manager");
        assert_eq!(
            owner.intact(&table).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        table["nftables"][0]["table"]
            .as_object_mut()
            .unwrap()
            .remove("comment");
        assert_eq!(
            owner.intact(&table).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn missing_or_disabled_reject_rule_needs_atomic_repair() {
        let owner = Owner::new(1001, "xray-test").unwrap();
        let baseline = installed(&owner);
        assert!(owner.intact(&baseline).unwrap());
        let mut missing = baseline.clone();
        missing["nftables"].as_array_mut().unwrap().pop();
        assert!(!owner.intact(&missing).unwrap());
        let mut disabled = baseline.clone();
        disabled["nftables"][0]["table"]["flags"] = json!(["dormant"]);
        assert!(!owner.intact(&disabled).unwrap());
        let mut wrong_port = baseline;
        wrong_port["nftables"][2]["rule"]["expr"][1]["match"]["right"] = json!(8443);
        assert!(!owner.intact(&wrong_port).unwrap());
    }

    #[test]
    fn caller_cannot_escape_owned_interface_scope() {
        for name in [
            "",
            "x\"; flush ruleset",
            "../eth0",
            "abcdefghijklmnop",
            "tun\n",
        ] {
            assert_eq!(
                Owner::new(1001, name).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let user = Owner::new(1001, "xray-test").unwrap();
        let other = Owner::new(1002, "xray-test").unwrap();
        assert_ne!(user.table, other.table);
        assert_eq!(
            other.intact(&installed(&user)).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }
}
