use net_manager_core::daemon_protocol::{
    CondRulesListResult, CondRulesPutResult, CondRulesRemoveResult, ConditionalRouteRule,
};

#[cfg(target_os = "linux")]
use net_manager_engine::{linux_engine::LinuxEngine, linux_services};

/// Per-user conditional rules with live evaluation status. Linux daemon
/// only; other platforms report an empty list.
#[tauri::command]
pub(crate) async fn list_conditional_rules() -> Result<CondRulesListResult, String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            linux_services::condition_list(&LinuxEngine::new("network-orchestrator"))
        })
        .await
        .map_err(|_| "Conditional rule task failed".to_string())?
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(CondRulesListResult { rules: Vec::new() })
    }
}

/// Create or replace a rule; the daemon re-evaluates it immediately and
/// returns the fresh status.
#[tauri::command]
pub(crate) async fn put_conditional_rule(
    rule: ConditionalRouteRule,
) -> Result<CondRulesPutResult, String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(move || {
            linux_services::condition_put(&LinuxEngine::new("network-orchestrator"), rule)
        })
        .await
        .map_err(|_| "Conditional rule task failed".to_string())?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = rule;
        Err("conditional rules are available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn remove_conditional_rule(
    rule_id: String,
) -> Result<CondRulesRemoveResult, String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(move || {
            linux_services::condition_remove(&LinuxEngine::new("network-orchestrator"), &rule_id)
        })
        .await
        .map_err(|_| "Conditional rule task failed".to_string())?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = rule_id;
        Err("conditional rules are available on Linux only".into())
    }
}
