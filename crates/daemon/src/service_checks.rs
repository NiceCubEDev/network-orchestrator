//! Diagnostic-only worker. It has no route, process-recovery or daemon-core handle.
use net_manager_core::models::{ServiceCheck, ServiceCheckOutcome, ServiceCheckResult};
use net_manager_core::service_checks::{
    probe_service_check, record_service_check, service_probe_client, SERVICE_CHECK_INTERVAL,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::task::{JoinHandle, JoinSet};

pub struct ServiceCheckSupervisor {
    task: JoinHandle<()>,
    results: Arc<Mutex<Vec<ServiceCheckResult>>>,
}

impl ServiceCheckSupervisor {
    pub fn spawn(
        checks: Vec<ServiceCheck>,
        ports: &HashMap<String, u16>,
        runtime: &tokio::runtime::Handle,
    ) -> Option<Self> {
        let mut clients = HashMap::new();
        let targets: Vec<_> = checks
            .into_iter()
            .filter(|check| check.background)
            .map(|check| {
                let client = ports.get(&check.endpoint_key).and_then(|port| {
                    clients
                        .entry(*port)
                        .or_insert_with(|| service_probe_client(*port).ok())
                        .clone()
                });
                (check, client)
            })
            .collect();
        if targets.is_empty() {
            return None;
        }
        let targets = Arc::new(targets);
        let results = Arc::new(Mutex::new(Vec::<ServiceCheckResult>::new()));
        let published = Arc::clone(&results);
        let task = runtime.spawn(async move {
            // Saving/enabling never sends a remote request immediately.
            let mut ticks = tokio::time::interval_at(
                tokio::time::Instant::now() + SERVICE_CHECK_INTERVAL,
                SERVICE_CHECK_INTERVAL,
            );
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                let mut round = Vec::with_capacity(targets.len());
                for start in (0..targets.len()).step_by(4) {
                    let mut workers = JoinSet::new();
                    for index in start..(start + 4).min(targets.len()) {
                        let targets = Arc::clone(&targets);
                        workers.spawn(async move {
                            let (check, client) = &targets[index];
                            let result = match client {
                                Some(client) => probe_service_check(check, client).await,
                                None => ServiceCheckResult {
                                    id: check.id.clone(),
                                    name: check.name.clone(),
                                    endpoint_key: check.endpoint_key.clone(),
                                    outcome: ServiceCheckOutcome::Unavailable,
                                    http_status: None,
                                    latency_ms: None,
                                    checked_at_unix: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map_or(0, |time| time.as_secs()),
                                    consecutive_failures: 0,
                                    degraded: false,
                                },
                            };
                            (index, result)
                        });
                    }
                    while let Some(result) = workers.join_next().await {
                        if let Ok(result) = result {
                            round.push(result);
                        }
                    }
                }
                round.sort_unstable_by_key(|(index, _)| *index);
                if let Ok(mut previous) = published.lock() {
                    let next = round
                        .into_iter()
                        .map(|(_, result)| {
                            let old = previous.iter().find(|old| old.id == result.id);
                            let current = record_service_check(old, result);
                            if old.is_some_and(|old| old.degraded) != current.degraded {
                                eprintln!(
                                    "network-orchestrator-daemon: service check {:?} endpoint={} outcome={:?} degraded={}",
                                    current.name, current.endpoint_key, current.outcome, current.degraded,
                                );
                            }
                            current
                        })
                        .collect();
                    *previous = next;
                }
            }
        });
        Some(Self { task, results })
    }

    pub fn status(&self) -> Vec<ServiceCheckResult> {
        self.results
            .lock()
            .map(|results| results.clone())
            .unwrap_or_default()
    }
}

impl Drop for ServiceCheckSupervisor {
    fn drop(&mut self) {
        // Aborting also drops the round's JoinSet and cancels in-flight requests.
        self.task.abort();
    }
}
