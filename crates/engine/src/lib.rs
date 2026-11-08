//! Connection engine: the order of checks, starts, rollbacks and helper
//! requests behind "connect this profile". Typed API, no UI and no FFI; the
//! native client reaches it through `macos-bridge`, the `netorch` CLI directly
//! (`docs/plans/2026-10-15-19-netorch-cli.md`).
//!
//! Linux and macOS frontends share typed services and one unprivileged
//! runtime per data directory; privileged mutations stay in the OS helper.
use std::path::PathBuf;

#[cfg(unix)]
mod diagnose;
#[cfg(unix)]
mod geo;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux_compat;
#[cfg(target_os = "linux")]
pub mod linux_credentials;
#[cfg(target_os = "linux")]
pub mod linux_diagnostics;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux_engine;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux_events;
#[cfg(target_os = "linux")]
pub mod linux_geo_assets;
#[cfg(target_os = "linux")]
pub mod linux_network;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux_paths;
#[cfg(target_os = "linux")]
pub mod linux_profiles;
#[cfg(target_os = "linux")]
pub mod linux_runtime;
#[cfg(target_os = "linux")]
pub mod linux_services;
#[cfg(target_os = "linux")]
pub mod linux_session;
#[cfg(target_os = "linux")]
pub mod linux_sets;
#[cfg(target_os = "linux")]
pub mod linux_system;
#[cfg(unix)]
pub mod macos_credentials;
#[cfg(unix)]
pub mod macos_network;
#[cfg(unix)]
pub mod macos_services;
#[cfg(unix)]
pub mod macos_session;
#[cfg(unix)]
pub mod macos_state;
#[cfg(unix)]
pub mod macos_transaction;
#[cfg(unix)]
pub mod privileged;
#[cfg(unix)]
mod recovery;
#[cfg(unix)]
mod runtime;
#[cfg(unix)]
mod static_routes;
#[cfg(unix)]
pub mod tailscale;
#[cfg(unix)]
mod vpn_backends;

#[cfg(unix)]
pub use diagnose::DiagnosticsContext;
#[cfg(unix)]
pub use privileged::Privileged;
#[cfg(unix)]
pub use runtime::{find_profile, Engine, Snapshot, TailscaleGuard, TailscaleGuardState};

/// Text the client matches to ask the user for OpenVPN credentials.
#[cfg(unix)]
pub use vpn_backends::CREDENTIALS_REQUIRED;

/// Socket of the privileged helper; QA runs may point it elsewhere.
pub fn helper_socket() -> PathBuf {
    std::env::var_os("NETORCH_HELPER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| net_manager_core::daemon_protocol::MACOS_SOCKET_PATH.into())
}

#[cfg(unix)]
pub(crate) fn helper_error(error: net_manager_core::helper_client::HelperError) -> String {
    use net_manager_core::helper_client::HelperError;
    match error {
        HelperError::Unreachable(_) => {
            "The privileged helper is not running. Install it in Settings.".into()
        }
        HelperError::Rejected(body) => body.message,
        HelperError::Protocol(_) => "The privileged helper answered unexpectedly".into(),
    }
}
