//! `network-orchestrator-daemon`: the privileged Linux service that owns
//! routes and links on behalf of the app. Platform-neutral modules compile
//! (and are tested) everywhere; kernel/D-Bus glue is Linux-only.

#[cfg(target_os = "linux")]
pub mod always_on;
pub mod auth;
#[cfg(target_os = "linux")]
pub mod cond_rules;
// Tunnel orchestration depends on Linux DNS and kernel resource executors.
#[cfg(target_os = "linux")]
pub mod core;
#[cfg(target_os = "linux")]
pub mod dns;
#[cfg(target_os = "linux")]
pub mod dns_status;
#[cfg(target_os = "linux")]
pub mod egress;
#[cfg(target_os = "linux")]
pub mod failover;
#[cfg(target_os = "linux")]
pub mod intents;
pub mod link_names;
#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod nm;
pub mod openvpn;
#[cfg(target_os = "linux")]
pub mod openvpn_process;
#[cfg(target_os = "linux")]
pub mod peer;
#[cfg(target_os = "linux")]
pub mod quic_reject;
#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod service_checks;
pub mod settings;
pub mod tailscale;
pub mod validate;
#[cfg(target_os = "linux")]
pub mod watchdog;
pub mod wireguard;
pub mod xray;
#[cfg(target_os = "linux")]
pub mod xray_process;
