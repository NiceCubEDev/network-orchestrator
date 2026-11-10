use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::watch;

const MAX_BATCHES: usize = 64;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const CANCELLED: &str = "Subscription delay measurement was cancelled";

struct Batch {
    id: String,
    sequence: u64,
    cancelled: watch::Sender<bool>,
}

#[derive(Default)]
pub(crate) struct SubscriptionMeasurements {
    batches: Mutex<HashMap<String, Batch>>,
}

impl SubscriptionMeasurements {
    pub(crate) fn start(&self, profile_id: &str) -> String {
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let id = format!("{}-{sequence}", std::process::id());
        let (cancelled, _) = watch::channel(false);
        let mut batches = self
            .batches
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(previous) = batches.insert(
            profile_id.to_owned(),
            Batch {
                id: id.clone(),
                sequence,
                cancelled,
            },
        ) {
            previous.cancelled.send_replace(true);
        }
        if batches.len() > MAX_BATCHES {
            if let Some(profile) = batches
                .iter()
                .min_by_key(|(_, batch)| batch.sequence)
                .map(|(profile, _)| profile.clone())
            {
                if let Some(previous) = batches.remove(&profile) {
                    previous.cancelled.send_replace(true);
                }
            }
        }
        id
    }

    pub(crate) fn receiver(
        &self,
        profile_id: &str,
        id: &str,
    ) -> Result<watch::Receiver<bool>, String> {
        let batches = self
            .batches
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        batches
            .get(profile_id)
            .filter(|batch| batch.id == id)
            .map(|batch| batch.cancelled.subscribe())
            .ok_or_else(|| CANCELLED.to_string())
    }

    pub(crate) fn cancel(&self, id: &str) {
        let mut batches = self
            .batches
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let profile = batches
            .iter()
            .find(|(_, batch)| batch.id == id)
            .map(|(profile, _)| profile.clone());
        if let Some(previous) = profile.and_then(|profile| batches.remove(&profile)) {
            previous.cancelled.send_replace(true);
        }
    }

    pub(crate) fn cancel_all(&self) {
        let mut batches = self
            .batches
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for batch in batches.values() {
            batch.cancelled.send_replace(true);
        }
        batches.clear();
    }
}

impl Drop for SubscriptionMeasurements {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

pub(crate) async fn cancellable_measurement<T>(
    cancelled: Option<watch::Receiver<bool>>,
    measurement: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let Some(mut cancelled) = cancelled else {
        return measurement.await;
    };
    if *cancelled.borrow_and_update() {
        return Err(CANCELLED.to_string());
    }
    tokio::select! {
        biased;
        _ = cancelled.changed() => Err(CANCELLED.to_string()),
        result = measurement => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn cancellation_before_or_after_registration_rejects_late_requests() {
        for registered in [false, true] {
            let measurements = SubscriptionMeasurements::default();
            let id = measurements.start("profile");
            let receiver = registered.then(|| measurements.receiver("profile", &id).unwrap());
            measurements.cancel(&id);
            assert!(measurements.receiver("profile", &id).is_err());
            if let Some(receiver) = receiver {
                assert!(*receiver.borrow() || receiver.has_changed().is_err());
            }
        }
    }

    #[test]
    fn batch_ids_are_profile_bound_and_replacing_cancels_the_old_batch() {
        let measurements = SubscriptionMeasurements::default();
        let old = measurements.start("profile");
        let receiver = measurements.receiver("profile", &old).unwrap();
        assert!(measurements.receiver("other-profile", &old).is_err());
        assert!(measurements.receiver("profile", "unknown-id").is_err());
        let current = measurements.start("profile");
        assert_ne!(old, current);
        assert!(measurements.receiver("profile", &old).is_err());
        assert!(*receiver.borrow() || receiver.has_changed().is_err());
        measurements.cancel(&old);
        assert!(measurements.receiver("profile", &current).is_ok());
    }

    #[tokio::test]
    async fn an_already_cancelled_batch_never_polls_its_probe() {
        for already_cancelled in [true, false] {
            let (sender, receiver) = watch::channel(already_cancelled);
            let _sender = if already_cancelled {
                Some(sender)
            } else {
                drop(sender);
                None
            };
            let polled = AtomicBool::new(false);
            let result = cancellable_measurement(Some(receiver), async {
                polled.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;
            assert!(result.is_err());
            assert!(!polled.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn cancellation_drops_an_active_probe_future() {
        struct Probe(Arc<AtomicBool>);
        impl Drop for Probe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let probe = Probe(dropped.clone());
        let started = Arc::new(tokio::sync::Notify::new());
        let observed = started.clone();
        let (sender, receiver) = watch::channel(false);
        let mut task = tokio::spawn(cancellable_measurement(Some(receiver), async move {
            let _probe = probe;
            started.notify_one();
            std::future::pending::<Result<(), String>>().await
        }));
        tokio::time::timeout(Duration::from_secs(1), observed.notified())
            .await
            .unwrap();
        sender.send_replace(true);
        let result = tokio::time::timeout(Duration::from_millis(500), &mut task).await;
        if result.is_err() {
            task.abort();
        }
        assert!(result.unwrap().unwrap().is_err());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn registry_is_bounded_and_shutdown_cancels_receivers() {
        let measurements = SubscriptionMeasurements::default();
        let oldest = measurements.start("first-profile");
        let receiver = measurements.receiver("first-profile", &oldest).unwrap();
        for index in 0..MAX_BATCHES {
            measurements.start(&format!("profile-{index}"));
        }
        assert!(measurements.receiver("first-profile", &oldest).is_err());
        assert!(receiver.has_changed().is_err());
        assert_eq!(measurements.batches.lock().unwrap().len(), MAX_BATCHES);
        let id = measurements.start("last-profile");
        let receiver = measurements.receiver("last-profile", &id).unwrap();
        drop(measurements);
        assert!(receiver.has_changed().is_err());
    }
}
