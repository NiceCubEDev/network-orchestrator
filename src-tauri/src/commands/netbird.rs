//! NetBird next to the managed tunnels: the app drives the user's own NetBird
//! daemon through its CLI (`netbird status|up|down`), exactly as a terminal
//! would. The installed daemon owns privileged network changes; the setup key
//! goes to the CLI through a private file, never the command line, and is not
//! stored.

use crate::state::AppState;
use serde_json::Value;
use tauri::State;

#[cfg(all(unix, not(target_os = "linux")))]
fn runtime_dir(state: &AppState) -> std::path::PathBuf {
    // `$XDG_RUNTIME_DIR` is per-user and tmpfs-backed; fall back to the data dir.
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| std::path::PathBuf::from(dir).join("network-orchestrator"))
        .unwrap_or_else(|| {
            state
                .managed_xray_root
                .ancestors()
                .nth(2)
                .map(|dir| dir.join("runtime"))
                .unwrap_or_else(std::env::temp_dir)
        })
}

#[cfg(windows)]
fn runtime_dir(state: &AppState) -> std::path::PathBuf {
    state
        .config_vault
        .root()
        .parent()
        .expect("config vault is under the application data directory")
        .join("runtime")
}

#[cfg(any(unix, windows))]
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| "NetBird task failed".to_string())
}

/// Summary of the NetBird daemon: installed, state, address, peers. A missing
/// CLI or stopped daemon is a state, not an error.
#[tauri::command]
pub(crate) async fn netbird_status(state: State<'_, AppState>) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = state.data_dir().to_path_buf();
        blocking(move || net_manager_engine::linux_services::netbird_status(&root)).await?
    }
    #[cfg(any(windows, all(unix, not(target_os = "linux"))))]
    {
        let _ = state;
        blocking(|| net_manager_core::netbird::NetBird::detect().status()).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = state;
        Ok(serde_json::json!({"installed": false, "state": "notInstalled"}))
    }
}

/// `netbird up`; a browser sign-in is handled by the CLI itself. The optional
/// management address and setup key apply to this connection only.
#[tauri::command]
pub(crate) async fn netbird_up(
    management_url: Option<String>,
    setup_key: Option<String>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = state.data_dir().to_path_buf();
        blocking(move || {
            net_manager_engine::linux_services::netbird_up(
                &root,
                management_url.as_deref(),
                setup_key.as_deref(),
            )
        })
        .await?
    }
    #[cfg(any(windows, all(unix, not(target_os = "linux"))))]
    {
        let runtime = runtime_dir(&state);
        blocking(move || {
            let url = management_url.as_deref().filter(|text| !text.is_empty());
            let key = setup_key.as_deref().filter(|text| !text.is_empty());
            net_manager_core::netbird::NetBird::detect().up(&runtime, url, key)
        })
        .await?
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (management_url, setup_key, state);
        Err("NetBird control is not available on this platform".into())
    }
}

#[tauri::command]
pub(crate) async fn netbird_down(state: State<'_, AppState>) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = state.data_dir().to_path_buf();
        blocking(move || net_manager_engine::linux_services::netbird_down(&root)).await?
    }
    #[cfg(any(windows, all(unix, not(target_os = "linux"))))]
    {
        let _ = state;
        blocking(|| net_manager_core::netbird::NetBird::detect().down()).await?
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = state;
        Err("NetBird control is not available on this platform".into())
    }
}
