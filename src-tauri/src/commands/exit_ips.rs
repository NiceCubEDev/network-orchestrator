//! Exit-IP checkers: concurrent HTTPS requests to IP-echo services.
//!
//! Each request traverses normal OS routing, so when a TUN profile is up the
//! tunnel's split rules classify every checker domain — the returned IP shows
//! which outbound actually served it (proxy exit vs ISP), which is the whole
//! point of the panel. Results stream to the frontend over a channel as each
//! checker resolves; a best-effort `ipwho.is` lookup annotates the exit IP
//! with a country code.

#[cfg(not(target_os = "linux"))]
use net_manager_core::exit_ip::{check_one, TIMEOUT};
use net_manager_core::exit_ip::{ExitIpEntry, CHECKERS};
use serde::Serialize;
use tauri::ipc::Channel;

/// Channel events: `Pending` lists checker names up front so rows render
/// instantly; `Result` arrives per checker as it completes.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum ExitIpEvent {
    Pending { names: Vec<String> },
    Result { entry: ExitIpEntry },
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn check_exit_ips(on_event: Channel<ExitIpEvent>) -> Result<(), String> {
    let _ = on_event.send(ExitIpEvent::Pending {
        names: CHECKERS.iter().map(|(name, _)| name.to_string()).collect(),
    });
    net_manager_engine::linux_diagnostics::check_exit_ips(&|entry| {
        let _ = on_event.send(ExitIpEvent::Result { entry });
    })
    .await
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn check_exit_ips(on_event: Channel<ExitIpEvent>) {
    let Ok(client) = reqwest::Client::builder().timeout(TIMEOUT).build() else {
        for (name, _) in CHECKERS {
            let _ = on_event.send(ExitIpEvent::Result {
                entry: ExitIpEntry {
                    name: name.to_string(),
                    ip: None,
                    country: None,
                    error: Some("client unavailable".to_string()),
                },
            });
        }
        return;
    };
    let _ = on_event.send(ExitIpEvent::Pending {
        names: CHECKERS.iter().map(|(name, _)| name.to_string()).collect(),
    });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ExitIpEntry>();
    for &(name, urls) in CHECKERS {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(check_one(client, name, urls).await);
        });
    }
    drop(tx);
    while let Some(entry) = rx.recv().await {
        let _ = on_event.send(ExitIpEvent::Result { entry });
    }
}
