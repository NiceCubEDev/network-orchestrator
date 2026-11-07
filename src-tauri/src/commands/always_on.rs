use crate::state::AppState;
use net_manager_core::daemon_protocol::{
    AlwaysOnKind, AlwaysOnListResult, AlwaysOnRemoveResult, AlwaysOnResumeResult, AlwaysOnSetResult,
};
#[cfg(target_os = "linux")]
use net_manager_engine::{linux_engine::LinuxEngine, linux_services};
use tauri::State;

#[tauri::command]
pub(crate) async fn get_always_on_profiles() -> Result<AlwaysOnListResult, String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            linux_services::always_on_list(&LinuxEngine::new("network-orchestrator"))
        })
        .await
        .map_err(|_| "Always-on task failed".to_string())?
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(AlwaysOnListResult {
            profiles: Vec::new(),
            paused: false,
            supported_kinds: Vec::new(),
        })
    }
}

#[tauri::command]
pub(crate) async fn set_always_on_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<AlwaysOnSetResult, String> {
    #[cfg(target_os = "linux")]
    {
        let profile = crate::state::find_profile(&state.profiles, &id)?;
        let vault = net_manager_core::config_vault::ConfigVault::new(
            state.config_vault.root().to_path_buf(),
        );
        tauri::async_runtime::spawn_blocking(move || {
            linux_services::always_on_set(
                &LinuxEngine::new("network-orchestrator"),
                &vault,
                &profile,
            )
        })
        .await
        .map_err(|_| "Always-on task failed".to_string())?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (id, state);
        Err("always-on is available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn remove_always_on_profile(
    kind: AlwaysOnKind,
    profile_id: String,
) -> Result<AlwaysOnRemoveResult, String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(move || {
            linux_services::always_on_remove(
                &LinuxEngine::new("network-orchestrator"),
                kind,
                &profile_id,
            )
        })
        .await
        .map_err(|_| "Always-on task failed".to_string())?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (kind, profile_id);
        Err("always-on is available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn resume_always_on() -> Result<AlwaysOnResumeResult, String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            linux_services::always_on_resume(&LinuxEngine::new("network-orchestrator"))
        })
        .await
        .map_err(|_| "Always-on task failed".to_string())?
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("always-on is available on Linux only".into())
    }
}
