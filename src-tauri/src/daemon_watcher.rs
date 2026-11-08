use net_manager_core::daemon_protocol::event;
use net_manager_engine::linux_events::Subscription;
use std::time::Duration;
use tauri::Emitter;

/// Events invalidate frontend snapshots; reconnect and event gaps always refresh.
/// Local children still use the frontend's existing bounded status polling.
pub(crate) fn watch(app: tauri::AppHandle) {
    let socket = net_manager_engine::linux_engine::daemon_socket();
    let mut unavailable_notified = false;
    loop {
        if let Ok(mut subscription) = Subscription::connect(&socket, Duration::from_secs(1)) {
            unavailable_notified = false;
            let _ = app.emit("route-changed", ());
            loop {
                match subscription.next_event() {
                    Ok(Some(frame)) => {
                        if frame.event == event::OWNED_CHANGED || frame.event == event::RESYNC {
                            let _ = app.emit("route-changed", ());
                        }
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        }
        if !unavailable_notified {
            // Consumers re-query and display the actual backend error, not a cached Running.
            let _ = app.emit("route-changed", ());
            unavailable_notified = true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
