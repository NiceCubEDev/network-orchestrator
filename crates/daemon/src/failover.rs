//! Multinode failover supervision for one Xray tunnel.
//!
//! A dedicated thread — never the daemon core, which only reads the shared
//! status — probes every failover candidate through its own loopback SOCKS
//! inbound (`probe-<key>`, injected by [`crate::xray::prepare_xray`]), so a
//! node's health path really traverses that node. The first healthy
//! candidate in `nodes` order is pinned to the `failover` balancer with a
//! bounded `xray api bo` subprocess; when every candidate fails the
//! balancer moves to the `unavailable` blackhole — default traffic drops,
//! it is never sent direct and never silently rerouted. Probes and
//! subprocesses are bounded: 5 s request timeout, 3 s API call cap, ≤64 KiB
//! probe body, interval clamped by validation.

use net_manager_core::daemon_protocol::XrayFailoverParams;
use net_manager_core::models::{FailoverStatus, NodeHealth};
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_BODY_LIMIT: u64 = 64 * 1024;
const API_TIMEOUT: Duration = Duration::from_secs(3);
/// Flips need two consecutive agreeing probes; the first observation of a
/// node is taken at face value so a fresh tunnel converges in one round.
const STREAK_REQUIRED: i8 = 2;
/// Worker sleep while it waits out the probe interval.
const TICK: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeSample {
    healthy: bool,
    latency_ms: Option<u32>,
}

struct TrackedNode {
    key: String,
    probe_port: u16,
    /// Last committed verdict after streak smoothing; `None` = unprobed.
    committed: Option<bool>,
    /// Signed streak toward the opposite verdict (+ healthy, − failing).
    streak: i8,
    last_probe_unix: Option<u64>,
    latency_ms: Option<u32>,
}

impl TrackedNode {
    fn observe(&mut self, sample: ProbeSample) {
        self.last_probe_unix = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        self.latency_ms = sample.latency_ms;
        match self.committed {
            None => self.committed = Some(sample.healthy),
            Some(committed) if committed == sample.healthy => self.streak = 0,
            Some(_) => {
                self.streak += if sample.healthy { 1 } else { -1 };
                if self.streak.abs() >= STREAK_REQUIRED {
                    self.committed = Some(sample.healthy);
                    self.streak = 0;
                }
            }
        }
    }

    fn health(&self) -> NodeHealth {
        NodeHealth {
            key: self.key.clone(),
            healthy: self.committed,
            last_probe_unix: self.last_probe_unix,
            latency_ms: self.latency_ms,
        }
    }
}

/// Which tag the `failover` balancer must select.
///
/// `healthy[i]` is the committed verdict for `candidates[i]` (primary
/// first); `current` is the tag the balancer already selects, so
/// `auto_return = false` can keep a healthy backup instead of snapping
/// back to the primary. Returns a `node-<key>` tag or `unavailable`; the
/// balancer can never point anywhere else.
fn select_tag(
    candidates: &[String],
    healthy: &[Option<bool>],
    current: Option<&str>,
    auto_return: bool,
) -> String {
    let node = |key: &str| net_manager_core::xray::node_tag(key);
    // Without auto-return a running backup stays selected while healthy —
    // but never beyond its own failure (primary then wins back).
    if !auto_return {
        if let Some(current) = current {
            if let Some(index) = candidates.iter().position(|key| node(key) == current) {
                if healthy.get(index) == Some(&Some(true)) && index > 0 {
                    return current.to_string();
                }
            }
        }
    }
    candidates
        .iter()
        .zip(healthy)
        .find(|(_, health)| **health == Some(true))
        .map(|(key, _)| node(key))
        .unwrap_or_else(|| net_manager_core::xray::UNAVAILABLE_TAG.to_string())
}

/// Status snapshot the daemon exposes over `xray.status`.
pub type SharedStatus = Arc<Mutex<FailoverStatus>>;

pub struct FailoverSupervisor {
    stop: Arc<AtomicBool>,
    status: SharedStatus,
    handle: Option<thread::JoinHandle<()>>,
    api_child: Arc<Mutex<Option<Child>>>,
}

impl FailoverSupervisor {
    /// Spawn the probe worker. `apply` runs `xray api bo`; injectable for
    /// tests. Returns `Err` when the thread cannot be spawned — the caller
    /// treats it as degraded (the balancer still holds its safe default).
    pub fn spawn(
        params: XrayFailoverParams,
        api_port: u16,
        probe_port_of: impl Fn(usize) -> u16,
    ) -> std::io::Result<Self> {
        let nodes: Vec<TrackedNode> = params
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| TrackedNode {
                key: node.key.clone(),
                probe_port: probe_port_of(index),
                committed: None,
                streak: 0,
                last_probe_unix: None,
                latency_ms: None,
            })
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let api_child = Arc::new(Mutex::new(None));
        let status: SharedStatus = Arc::new(Mutex::new(FailoverStatus {
            primary_key: params.primary_key.clone(),
            active_key: net_manager_core::xray::UNAVAILABLE_TAG.to_string(),
            auto_return_primary: params.auto_return_primary,
            failover_active: false,
            nodes: nodes.iter().map(TrackedNode::health).collect(),
        }));
        let worker = {
            let stop = Arc::clone(&stop);
            let status = Arc::clone(&status);
            let api_child = Arc::clone(&api_child);
            thread::Builder::new()
                .name("xray-failover".into())
                .spawn(move || run(params, api_port, nodes, stop, status, api_child))?
        };
        Ok(Self {
            stop,
            status,
            handle: Some(worker),
            api_child,
        })
    }

    pub fn status(&self) -> FailoverStatus {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Cancel before core replaces Xray, including any in-flight API command.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(child) = self
            .api_child
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_mut()
        {
            let _ = child.kill();
        }
    }
}

impl Drop for FailoverSupervisor {
    fn drop(&mut self) {
        self.stop();
        // Worker reaps its API child off-core; bounded probes check stop
        // before starting another operation. Never join under the core lock.
        self.handle.take();
    }
}

fn run(
    params: XrayFailoverParams,
    api_port: u16,
    mut nodes: Vec<TrackedNode>,
    stop: Arc<AtomicBool>,
    status: SharedStatus,
    api_child: Arc<Mutex<Option<Child>>>,
) {
    let interval = Duration::from_secs(u64::from(params.interval_secs.max(1)));
    let mut applied: Option<String> = None;
    let mut next_round = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        if Instant::now() >= next_round {
            for node in &mut nodes {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                node.observe(probe(node.probe_port, &params.probe_url));
            }
            let healthy: Vec<Option<bool>> = nodes.iter().map(|node| node.committed).collect();
            let keys: Vec<String> = nodes.iter().map(|node| node.key.clone()).collect();
            let wanted = select_tag(
                &keys,
                &healthy,
                applied.as_deref(),
                params.auto_return_primary,
            );
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let changed = applied.as_deref() != Some(wanted.as_str());
            if changed {
                match api_override(api_port, &wanted, &stop, &api_child) {
                    Ok(()) => applied = Some(wanted.clone()),
                    Err(err) => {
                        eprintln!("network-orchestrator-daemon: failover override failed: {err}")
                    }
                }
            }
            let report = FailoverStatus {
                primary_key: params.primary_key.clone(),
                active_key: applied
                    .as_deref()
                    .map(|tag| tag.strip_prefix("node-").unwrap_or(tag).to_string())
                    .unwrap_or_else(|| net_manager_core::xray::UNAVAILABLE_TAG.to_string()),
                auto_return_primary: params.auto_return_primary,
                failover_active: applied.as_deref().is_some_and(|tag| {
                    tag != net_manager_core::xray::UNAVAILABLE_TAG
                        && tag != net_manager_core::xray::node_tag(&params.primary_key)
                }),
                nodes: nodes.iter().map(TrackedNode::health).collect(),
            };
            if let Ok(mut guard) = status.lock() {
                *guard = report;
            }
            next_round = Instant::now() + interval;
        }
        thread::sleep(TICK);
    }
}

/// One HTTPS GET through the node's loopback SOCKS inbound. `socks5h` keeps
/// DNS on the node side: the URL's host is resolved by Xray itself, so a
/// probe cannot be steered at a daemon-local address by its own resolver.
fn probe(probe_port: u16, url: &str) -> ProbeSample {
    let started = Instant::now();
    let client = match reqwest::blocking::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{probe_port}"))
                .expect("loopback proxy"),
        )
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return ProbeSample {
                healthy: false,
                latency_ms: None,
            }
        }
    };
    let response = match client.get(url).send() {
        Ok(response) => response,
        Err(_) => {
            return ProbeSample {
                healthy: false,
                latency_ms: None,
            }
        }
    };
    // Any completed HTTP(S) exchange under 400 counts: the node carried a
    // real TLS session. The body is capped — a hostile endpoint cannot
    // stall the worker on a stream.
    let healthy = response.status().as_u16() < 400
        && std::io::copy(&mut response.take(PROBE_BODY_LIMIT), &mut std::io::sink()).is_ok();
    ProbeSample {
        healthy,
        latency_ms: Some(started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32),
    }
}

/// `xray api bo -b failover <tag>` against the tunnel's loopback API —
/// bounded like the statsquery helper; a hang can never wedge the worker.
fn api_override(
    api_port: u16,
    tag: &str,
    stop: &AtomicBool,
    slot: &Mutex<Option<Child>>,
) -> std::io::Result<()> {
    let binary = crate::xray_process::trusted_binary()?;
    let mut command = Command::new(binary);
    command
        .args([
            "api",
            "bo",
            "-server",
            &format!("127.0.0.1:{api_port}"),
            "-t",
            "3",
            "-b",
            net_manager_core::xray::FAILOVER_BALANCER,
            tag,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    run_api_command(command, stop, slot)
}

fn run_api_command(
    mut command: Command,
    stop: &AtomicBool,
    slot: &Mutex<Option<Child>>,
) -> std::io::Result<()> {
    let cancelled = || {
        std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Xray API controller stopped",
        )
    };
    {
        let mut owned = slot.lock().unwrap_or_else(|error| error.into_inner());
        if stop.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        *owned = Some(
            command
                .spawn()
                .map_err(|_| std::io::Error::other("Xray API launch failed"))?,
        );
    }
    let deadline = Instant::now() + API_TIMEOUT;
    loop {
        let mut owned = slot.lock().unwrap_or_else(|error| error.into_inner());
        let stopped = stop.load(Ordering::Relaxed);
        if stopped || Instant::now() >= deadline {
            let mut child = owned.take().expect("worker owns API command");
            let _ = child.kill();
            drop(owned);
            let _ = child.wait();
            return Err(if stopped {
                cancelled()
            } else {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Xray API timed out")
            });
        }
        match owned.as_mut().expect("worker owns API command").try_wait() {
            Ok(Some(status)) => {
                owned.take();
                return if status.success() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "Xray API override failed",
                    ))
                };
            }
            Ok(None) => {}
            Err(_) => {
                let mut child = owned.take().expect("worker owns API command");
                let _ = child.kill();
                drop(owned);
                let _ = child.wait();
                return Err(std::io::Error::other("Xray API wait failed"));
            }
        }
        drop(owned);
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracked(key: &str, committed: Option<bool>) -> TrackedNode {
        TrackedNode {
            key: key.into(),
            probe_port: 0,
            committed,
            streak: 0,
            last_probe_unix: None,
            latency_ms: None,
        }
    }

    #[test]
    fn first_observation_commits_immediately() {
        let mut node = tracked("aaaaaaaabbbbbbbb", None);
        node.observe(ProbeSample {
            healthy: true,
            latency_ms: Some(7),
        });
        assert_eq!(node.committed, Some(true));
        node = tracked("aaaaaaaabbbbbbbb", None);
        node.observe(ProbeSample {
            healthy: false,
            latency_ms: None,
        });
        assert_eq!(node.committed, Some(false));
    }

    #[test]
    fn flips_need_two_consecutive_probes() {
        let mut node = tracked("aaaaaaaabbbbbbbb", Some(true));
        node.observe(ProbeSample {
            healthy: false,
            latency_ms: None,
        });
        assert_eq!(node.committed, Some(true), "one failure is a blip");
        node.observe(ProbeSample {
            healthy: false,
            latency_ms: None,
        });
        assert_eq!(node.committed, Some(false));
        node.observe(ProbeSample {
            healthy: true,
            latency_ms: Some(3),
        });
        assert_eq!(node.committed, Some(false));
        node.observe(ProbeSample {
            healthy: true,
            latency_ms: Some(3),
        });
        assert_eq!(node.committed, Some(true));
    }

    #[test]
    fn selection_is_strictly_ordered_primary_first() {
        let keys = vec![
            "aaaaaaaabbbbbbbb".to_string(),
            "ccccccccdddddddd".to_string(),
        ];
        assert_eq!(
            select_tag(&keys, &[Some(true), Some(true)], None, true),
            "node-aaaaaaaabbbbbbbb"
        );
        assert_eq!(
            select_tag(&keys, &[Some(false), Some(true)], None, true),
            "node-ccccccccdddddddd"
        );
        assert_eq!(
            select_tag(&keys, &[Some(false), Some(false)], None, true),
            "unavailable"
        );
        // Unprobed nodes never win — the balancer stays on the blackhole.
        assert_eq!(select_tag(&keys, &[None, None], None, true), "unavailable");
    }

    #[test]
    fn all_down_selects_blackhole_never_direct() {
        let keys = vec!["aaaaaaaabbbbbbbb".to_string()];
        let tag = select_tag(&keys, &[Some(false)], None, true);
        assert_eq!(tag, "unavailable");
        assert!(!tag.starts_with("node-"));
    }
    #[test]
    fn without_auto_return_a_healthy_backup_keeps_the_tunnel() {
        let keys = vec![
            "aaaaaaaabbbbbbbb".to_string(),
            "ccccccccdddddddd".to_string(),
        ];
        // Failover already moved to the backup; primary recovers but
        // auto-return is off — stay put.
        assert_eq!(
            select_tag(
                &keys,
                &[Some(true), Some(true)],
                Some("node-ccccccccdddddddd"),
                false,
            ),
            "node-ccccccccdddddddd"
        );
        // Backup then fails: the healthy primary wins back even with
        // auto-return off (it is the first healthy candidate).
        assert_eq!(
            select_tag(
                &keys,
                &[Some(true), Some(false)],
                Some("node-ccccccccdddddddd"),
                false,
            ),
            "node-aaaaaaaabbbbbbbb"
        );
        // With auto-return on the primary always takes over immediately.
        assert_eq!(
            select_tag(
                &keys,
                &[Some(true), Some(true)],
                Some("node-ccccccccdddddddd"),
                true,
            ),
            "node-aaaaaaaabbbbbbbb"
        );
    }

    #[test]
    fn disconnect_does_not_wait_for_an_inflight_network_probe() {
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let (finished, completion) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = blocked.recv();
        });
        let supervisor = FailoverSupervisor {
            stop: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(FailoverStatus::default())),
            handle: Some(worker),
            api_child: Arc::new(Mutex::new(None)),
        };
        let disconnect = thread::spawn(move || {
            drop(supervisor);
            finished.send(()).unwrap();
        });
        let returned = completion.recv_timeout(Duration::from_secs(2)).is_ok();
        let _ = release.send(());
        disconnect.join().unwrap();
        assert!(
            returned,
            "disconnect waited for a network probe under the core lock"
        );
    }
}
