//! Thin adapters over the shared connection-set store and Linux runtime.
use crate::state::AppState;
#[cfg(target_os = "linux")]
use net_manager_engine::{linux_engine::LinuxEngine, linux_sets};
use serde_json::Value;
use tauri::State;

#[cfg(target_os = "linux")]
fn root(state: &AppState) -> std::path::PathBuf {
    state.data_dir().to_path_buf()
}

#[cfg(target_os = "linux")]
fn encode(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|_| "Cannot encode connection sets".into())
}

#[tauri::command]
pub(crate) async fn list_connection_sets(state: State<'_, AppState>) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = root(&state);
        tauri::async_runtime::spawn_blocking(move || encode(linux_sets::list(&root)?))
            .await
            .map_err(|_| "Connection-set task failed")?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state;
        Err("Shared connection sets are available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn get_connection_set(
    id: String,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = root(&state);
        tauri::async_runtime::spawn_blocking(move || encode(linux_sets::get(&root, &id)?))
            .await
            .map_err(|_| "Connection-set task failed")?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (id, state);
        Err("Shared connection sets are available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn put_connection_set(
    set: Value,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = root(&state);
        tauri::async_runtime::spawn_blocking(move || {
            let set = serde_json::from_value(set).map_err(|_| "Invalid connection set")?;
            let store = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"));
            encode(linux_sets::put(&root, &store, set)?)
        })
        .await
        .map_err(|_| "Connection-set task failed")?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (set, state);
        Err("Shared connection sets are available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn delete_connection_set(
    id: String,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = root(&state);
        tauri::async_runtime::spawn_blocking(move || {
            linux_sets::delete(&root, &id)?;
            Ok(Value::Null)
        })
        .await
        .map_err(|_| "Connection-set task failed")?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (id, state);
        Err("Shared connection sets are available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn import_connection_sets(
    sets: Value,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = root(&state);
        tauri::async_runtime::spawn_blocking(move || {
            let sets =
                serde_json::from_value(sets).map_err(|_| "Invalid legacy connection sets")?;
            encode(linux_sets::import(&root, sets)?)
        })
        .await
        .map_err(|_| "Connection-set task failed")?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sets, state);
        Err("Shared connection sets are available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn capture_connection_set(
    id: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = root(&state);
        tauri::async_runtime::spawn_blocking(move || {
            let store = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"));
            let engine = LinuxEngine::new("network-orchestrator").with_data_root(root.clone());
            encode(linux_sets::capture(&engine, &root, &store, id, name)?)
        })
        .await
        .map_err(|_| "Connection-set task failed")?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (id, name, state);
        Err("Shared connection sets are available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn apply_connection_set(
    id: String,
    credential_inputs: Option<Value>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    lifecycle(id, state, false, credential_inputs).await
}

#[tauri::command]
pub(crate) async fn down_connection_set(
    id: String,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    lifecycle(id, state, true, None).await
}

async fn lifecycle(
    id: String,
    state: State<'_, AppState>,
    down: bool,
    credential_inputs: Option<Value>,
) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        let root = root(&state);
        let credentials = state.openvpn_credentials.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let inputs: linux_sets::CredentialInputs = if let Some(value) = credential_inputs {
                serde_json::from_value(value)
                    .map_err(|_| "Invalid connection-set credential inputs")?
            } else {
                linux_sets::CredentialInputs::new()
            };
            let store = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"));
            let vault = net_manager_core::config_vault::ConfigVault::new(root.join("configs"));
            let engine = LinuxEngine::new("network-orchestrator").with_data_root(root.clone());
            encode(if down {
                linux_sets::down(
                    &net_manager_engine::linux_runtime::Context {
                        engine: &engine,
                        root: &root,
                        vault: &vault,
                        store: &store,
                    },
                    &id,
                )?
            } else {
                linux_sets::apply(
                    &net_manager_engine::linux_runtime::Context {
                        engine: &engine,
                        root: &root,
                        vault: &vault,
                        store: &store,
                    },
                    &id,
                    credentials.as_ref(),
                    &inputs,
                    Some(credentials.as_ref()),
                )?
            })
        })
        .await
        .map_err(|_| "Connection-set task failed")?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (id, state, down, credential_inputs);
        Err("Shared connection sets are available on Linux only".into())
    }
}
