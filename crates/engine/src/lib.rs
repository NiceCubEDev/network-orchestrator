//! Connection engine: the order of checks, starts, rollbacks and helper
//! requests behind "connect this profile". Typed API, no UI and no FFI; the
//! native client reaches it through `macos-bridge`, the `netorch` CLI directly
//! (`docs/plans/2026-10-15-19-netorch-cli.md`).
//!
//! macOS only for now: Windows and Linux orchestration still lives in
//! `src-tauri` and is moved here by implementing the platform traits there.
//! Privileged work stays in the launchd helper; this crate only asks it.
use std::path::PathBuf;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod diagnose;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod geo;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux_compat;
#[cfg(target_os = "linux")]
pub mod linux_credentials;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux_engine;
#[cfg(target_os = "linux")]
pub mod linux_geo_assets;
#[cfg(any(target_os = "linux", feature = "linux-engine"))]
pub mod linux_paths;
#[cfg(target_os = "linux")]
pub mod linux_session;
#[cfg(unix)]
pub mod privileged;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod recovery;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod runtime;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod static_routes;
#[cfg(unix)]
pub mod tailscale;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vpn_backends;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use diagnose::DiagnosticsContext;
#[cfg(unix)]
pub use privileged::Privileged;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use runtime::{find_profile, Engine, Snapshot};

/// Text the client matches to ask the user for OpenVPN credentials.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use vpn_backends::CREDENTIALS_REQUIRED;

/// Socket of the privileged helper; QA runs may point it elsewhere.
pub fn helper_socket() -> PathBuf {
    std::env::var_os("NETORCH_HELPER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| net_manager_core::daemon_protocol::MACOS_SOCKET_PATH.into())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
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
