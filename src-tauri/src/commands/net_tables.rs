//! Kernel routing inventory (`ip route`/`ip rule` equivalent) plus the
//! manual edit and explainability surface, read/driven through the
//! privileged daemon's rtnetlink socket. Linux only — other platforms
//! report `available: false` or return the daemon error.

#[cfg(target_os = "linux")]
use net_manager_core::daemon_protocol::NetDnsProbeParams;
use net_manager_core::daemon_protocol::{
    NetDnsProbeResult, NetDnsStatusResult, NetEditResult, NetExplainResult, NetIntentListResult,
    NetIntentResult, NetIntentSetParams, NetRouteAddParams, NetRuleAddParams, NetTablesResult,
    SystemRoute, SystemRule,
};

#[cfg(target_os = "linux")]
fn engine() -> net_manager_engine::linux_engine::LinuxEngine {
    net_manager_engine::linux_engine::LinuxEngine::new("netmanager-gui")
}

#[tauri::command]
pub(crate) async fn get_net_tables() -> Result<NetTablesResult, String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::tables(&engine())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NetTablesResult {
            routes: Vec::new(),
            rules: Vec::new(),
            available: false,
        })
    }
}

/// `net.route.add`: install a daemon-owned unicast route (journaled under
/// the `manual` owner, reconciled, reverted by its removal).
#[tauri::command]
pub(crate) async fn net_route_add(params: NetRouteAddParams) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::route_add(&engine(), params)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Err("route editing is not supported on this platform".into())
    }
}

/// `net.route.del`: remove a route exactly as `get_net_tables` reported
/// it. Foreign routes are suppressed (journaled, restored on revert);
/// tunnel-owned routes are refused by the daemon.
#[tauri::command]
pub(crate) async fn net_route_del(route: SystemRoute) -> Result<NetEditResult, String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::route_delete(&engine(), route)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = route;
        Err("route editing is not supported on this platform".into())
    }
}

/// `net.rule.add`: install a daemon-owned `lookup` policy rule.
#[tauri::command]
pub(crate) async fn net_rule_add(params: NetRuleAddParams) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::rule_add(&engine(), params)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Err("rule editing is not supported on this platform".into())
    }
}

/// `net.rule.del`: remove a policy rule; foreign rules are suppressed
/// (journaled for restore), priority 0 is refused.
#[tauri::command]
pub(crate) async fn net_rule_del(rule: SystemRule) -> Result<NetEditResult, String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::rule_delete(&engine(), rule)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = rule;
        Err("rule editing is not supported on this platform".into())
    }
}

/// `net.explain`: per-owner reconciliation status of every journaled
/// intent (effective / deferred / conflicted / missing / suppressed).
#[tauri::command]
pub(crate) async fn net_explain() -> Result<NetExplainResult, String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::explain(&engine())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NetExplainResult {
            entries: Vec::new(),
            available: false,
        })
    }
}

/// `net.dns.status`: per-link resolver inventory (systemd-resolved) plus
/// the /etc/resolv.conf stub view.
#[tauri::command]
pub(crate) async fn net_dns_status() -> Result<NetDnsStatusResult, String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::dns_status(&engine())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NetDnsStatusResult {
            links: Vec::new(),
            available: false,
            resolv_conf: Vec::new(),
        })
    }
}

/// `net.dns.probe`: one real DNS query to the selected resolver plus the
/// egress route the kernel picked for it.
#[tauri::command]
pub(crate) async fn net_dns_probe(
    hostname: String,
    server: Option<String>,
    family: Option<String>,
) -> Result<NetDnsProbeResult, String> {
    #[cfg(target_os = "linux")]
    {
        use net_manager_core::daemon_protocol::IpFamily;
        let server = match server.as_deref().map(str::trim) {
            Some("") | None => None,
            Some(text) => Some(
                text.parse()
                    .map_err(|_| "invalid resolver address".to_string())?,
            ),
        };
        let family = match family.as_deref() {
            None | Some("ipv4") => Some(IpFamily::Ipv4),
            Some("ipv6") => Some(IpFamily::Ipv6),
            Some(_) => return Err("invalid DNS record family".into()),
        };
        net_manager_engine::linux_network::dns_probe(
            &engine(),
            NetDnsProbeParams {
                hostname,
                server,
                family,
            },
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (hostname, server, family);
        Err("DNS probing is not supported on this platform".into())
    }
}

/// `net.intent.list`: stored routing intents with their live status.
#[tauri::command]
pub(crate) async fn net_intent_list() -> Result<NetIntentListResult, String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::intent_list(&engine())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NetIntentListResult {
            intents: Vec::new(),
        })
    }
}

/// `net.intent.set`: upsert a routing intent — destinations routed via an
/// interface or pinned to the physical uplink, enforced by reconcile.
#[tauri::command]
pub(crate) async fn net_intent_set(params: NetIntentSetParams) -> Result<NetIntentResult, String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::intent_set(&engine(), params)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Err("routing intents are not supported on this platform".into())
    }
}

/// `net.intent.del`: remove the intent and withdraw its routes.
#[tauri::command]
pub(crate) async fn net_intent_del(id: String) -> Result<NetIntentResult, String> {
    #[cfg(target_os = "linux")]
    {
        net_manager_engine::linux_network::intent_delete(&engine(), &id)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = id;
        Err("routing intents are not supported on this platform".into())
    }
}
