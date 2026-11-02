use crate::state::AppState;
use serde::{Deserialize, Serialize};
use tauri::State;

/// In-memory ring-buffer capacity for app-side log events.
const LOG_CAPACITY: usize = 500;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogSource {
    App,
    Daemon,
}

/// One entry in the Logs view. `tsUnix` is seconds since the epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    pub ts_unix: u64,
    pub level: LogLevel,
    pub source: LogSource,
    pub message: String,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append an app-side event. Never fails: a poisoned buffer is recovered and
/// logging must not break tunnel operations.
pub(crate) fn record_log(state: &AppState, level: LogLevel, message: impl Into<String>) {
    let mut log = state.log.lock().unwrap_or_else(|e| e.into_inner());
    if log.len() >= LOG_CAPACITY {
        log.pop_front();
    }
    log.push_back(LogEvent {
        ts_unix: now_unix(),
        level,
        source: LogSource::App,
        message: message.into(),
    });
}

/// Convenience for tunnel lifecycle entries: "connect 'wg-kzn2': running
/// (wg-kzn2-7e76)" / "disconnect 'wg-kzn2': failed — <reason>".
pub(crate) fn record_tunnel_result(
    state: &AppState,
    action: &str,
    profile_name: &str,
    result: &Result<net_manager_core::models::TunnelStatus, String>,
) {
    match result {
        Ok(status) => {
            let detail = match (
                status.state,
                status.interface_name.as_deref(),
                status.message.as_deref(),
            ) {
                (state_, iface, Some(msg)) => {
                    format!("{:?}{} — {}", state_, iface_part(iface), msg).to_lowercase()
                }
                (state_, iface, None) => {
                    format!("{:?}{}", state_, iface_part(iface)).to_lowercase()
                }
            };
            let level = match status.state {
                net_manager_core::models::TunnelState::Failed => LogLevel::Error,
                _ => LogLevel::Info,
            };
            record_log(state, level, format!("{action} '{profile_name}': {detail}"));
        }
        Err(err) => record_log(
            state,
            LogLevel::Error,
            format!("{action} '{profile_name}': {err}"),
        ),
    }

    fn iface_part(name: Option<&str>) -> String {
        name.map(|n| format!(" on {n}")).unwrap_or_default()
    }
}

/// Best-effort display name for log lines; falls back to the profile id.
pub(crate) fn profile_label(state: &AppState, id: &str) -> String {
    state
        .profiles
        .load()
        .ok()
        .and_then(|doc| doc.profiles.into_iter().find(|p| p.id == id))
        .map(|p| p.name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| id.to_string())
}

#[tauri::command]
pub(crate) fn get_logs(state: State<'_, AppState>) -> Vec<LogEvent> {
    state
        .log
        .lock()
        .map(|log| log.iter().cloned().collect())
        .unwrap_or_default()
}

#[tauri::command]
pub(crate) fn clear_logs(state: State<'_, AppState>) {
    if let Ok(mut log) = state.log.lock() {
        log.clear();
    }
}

/// Last `lines` journal entries of the privileged daemon unit. On Linux the
/// daemon logs to the systemd journal; members of `wheel`/`systemd-journal`
/// can read it without elevation. Other platforms return an empty list.
#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn daemon_log_tail(lines: u32) -> Result<Vec<LogEvent>, String> {
    let lines = lines.clamp(1, 500);
    let output = tokio::process::Command::new("journalctl")
        .args([
            "-u",
            "network-orchestrator.service",
            "-b",
            "--no-pager",
            "-n",
            &lines.to_string(),
            "-o",
            "json",
        ])
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("journalctl unavailable: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "journalctl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    #[derive(Deserialize)]
    struct Row {
        #[serde(rename = "__REALTIME_TIMESTAMP")]
        ts: Option<String>,
        #[serde(rename = "MESSAGE")]
        message: Option<String>,
        #[serde(rename = "PRIORITY")]
        priority: Option<String>,
    }
    let events = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Row>(line).ok())
        .map(|row| LogEvent {
            ts_unix: row
                .ts
                .and_then(|ts| ts.parse::<u64>().ok())
                .map(|micros| micros / 1_000_000)
                .unwrap_or_default(),
            level: match row.priority.as_deref() {
                Some("0" | "1" | "2" | "3") => LogLevel::Error,
                Some("4") => LogLevel::Warn,
                _ => LogLevel::Info,
            },
            source: LogSource::Daemon,
            message: row.message.unwrap_or_default(),
        })
        .collect();
    Ok(events)
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn daemon_log_tail(_lines: u32) -> Result<Vec<LogEvent>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{app_state, unique_dir};
    use net_manager_core::models::{TunnelState, TunnelStatus};

    fn status(state: TunnelState, iface: Option<&str>, message: Option<&str>) -> TunnelStatus {
        TunnelStatus {
            profile_id: "p1".into(),
            state,
            message: message.map(str::to_string),
            interface_name: iface.map(str::to_string),
            failover: None,
            watchdog: None,
        }
    }

    #[test]
    fn event_log_serializes_camel_case() {
        let event = LogEvent {
            ts_unix: 42,
            level: LogLevel::Warn,
            source: LogSource::App,
            message: "connect 'home': failed".into(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["tsUnix"], 42);
        assert_eq!(json["level"], "warn");
        assert_eq!(json["source"], "app");
        assert_eq!(json["message"], "connect 'home': failed");
    }

    #[test]
    fn ring_buffer_drops_oldest_beyond_capacity() {
        let dir = unique_dir("log-capacity");
        let state = app_state(&dir);
        for i in 0..(LOG_CAPACITY + 50) {
            record_log(&state, LogLevel::Info, format!("event {i}"));
        }
        let log = state.log.lock().unwrap();
        assert_eq!(log.len(), LOG_CAPACITY);
        assert_eq!(log.front().unwrap().message, "event 50");
        assert_eq!(
            log.back().unwrap().message,
            format!("event {}", LOG_CAPACITY + 49)
        );
    }

    #[test]
    fn tunnel_result_ok_running_logs_iface_name() {
        let dir = unique_dir("log-tunnel-ok");
        let state = app_state(&dir);
        record_tunnel_result(
            &state,
            "connect",
            "wg-kzn2",
            &Ok(status(TunnelState::Running, Some("wg-kzn2-7e76"), None)),
        );
        let log = state.log.lock().unwrap();
        let ev = log.back().unwrap();
        assert_eq!(ev.level, LogLevel::Info);
        assert!(ev.message.contains("wg-kzn2"));
        assert!(ev.message.contains("wg-kzn2-7e76"));
    }

    #[test]
    fn tunnel_result_err_and_failed_state_log_as_errors() {
        let dir = unique_dir("log-tunnel-err");
        let state = app_state(&dir);
        record_tunnel_result(
            &state,
            "disconnect",
            "home",
            &Err("daemon unreachable".to_string()),
        );
        record_tunnel_result(
            &state,
            "connect",
            "home",
            &Ok(status(TunnelState::Failed, None, Some("xray exited"))),
        );
        let log = state.log.lock().unwrap();
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|e| e.level == LogLevel::Error));
        assert!(log[0].message.contains("daemon unreachable"));
        assert!(log[1].message.contains("xray exited"));
    }

    #[test]
    fn clear_empties_buffer() {
        let dir = unique_dir("log-clear");
        let state = app_state(&dir);
        record_log(&state, LogLevel::Warn, "something");
        assert_eq!(state.log.lock().unwrap().len(), 1);
        state.log.lock().unwrap().clear();
        assert!(state.log.lock().unwrap().is_empty());
    }
}
