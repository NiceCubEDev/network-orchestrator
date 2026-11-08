//! Collects what the diagnostics checks need from the privileged helper and
//! this process, then hands it to `core::diagnostics` (the rules live there).
use crate::privileged::Privileged;
use crate::runtime::Engine;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::{
    method, OpenVpnStatusResult, OwnedListResult, WireGuardStatusResult, XrayStatusResult,
};
use net_manager_core::diagnostics::{self, HelperView, ProfileChecksInput, TunnelDetail};
use net_manager_core::models::{
    NetworkInterface, Profile, ProfileDiagnostics, ProtocolHealth, RouteEntry, TunnelBackend,
    TunnelStatus,
};
use serde_json::json;

/// What the caller already read from the system (the engine has no async
/// runtime for routes) and the other profiles to compare with.
pub struct DiagnosticsContext<'a> {
    pub others: &'a [Profile],
    pub os_routes: Result<Vec<RouteEntry>, String>,
    pub interfaces: Result<Vec<NetworkInterface>, String>,
    pub vault: &'a ConfigVault,
}

/// The helper capability a profile's backend needs.
fn capability(profile: &Profile) -> &'static str {
    match profile.backend {
        TunnelBackend::WireGuard => method::WIREGUARD_CONNECT,
        TunnelBackend::OpenVpn => method::OPENVPN_CONNECT,
        _ => method::XRAY_CONNECT,
    }
}

/// Everything the helper can say about one of its profiles.
struct HelperSide {
    view: HelperView,
    owns: Option<bool>,
    detail: TunnelDetail,
    health: ProtocolHealth,
}

fn helper_side(privileged: &dyn Privileged, profile: &Profile) -> HelperSide {
    let (view, reachable) = match privileged.hello() {
        Ok(hello) => (
            HelperView {
                reachable: true,
                offers_capability: hello.capabilities.iter().any(|c| c == capability(profile)),
                version: hello.daemon_version,
            },
            true,
        ),
        Err(_) => (
            HelperView {
                reachable: false,
                offers_capability: false,
                version: String::new(),
            },
            false,
        ),
    };
    if !reachable || !view.offers_capability {
        return HelperSide {
            view,
            owns: None,
            detail: TunnelDetail::default(),
            health: diagnostics::failed_health("the privileged helper cannot report this tunnel"),
        };
    }
    let params = json!({ "profileId": profile.id });
    let (detail, health) = match profile.backend {
        TunnelBackend::WireGuard => privileged
            .call::<_, WireGuardStatusResult>(method::WIREGUARD_STATUS, params)
            .map(|s| {
                (
                    diagnostics::wireguard_detail(&s),
                    diagnostics::wireguard_health(&s),
                )
            }),
        TunnelBackend::OpenVpn => privileged
            .call::<_, OpenVpnStatusResult>(method::OPENVPN_STATUS, params)
            .map(|s| (TunnelDetail::default(), diagnostics::openvpn_health(&s))),
        _ => privileged
            .call::<_, XrayStatusResult>(method::XRAY_STATUS, params)
            .map(|s| {
                (
                    diagnostics::xray_tun_detail(&s),
                    diagnostics::xray_tun_health(&s),
                )
            }),
    }
    .unwrap_or_else(|_| {
        (
            TunnelDetail::default(),
            diagnostics::failed_health("the privileged helper did not answer the status request"),
        )
    });
    let suffix = format!(":{}", profile.id);
    let owns = privileged
        .call::<_, OwnedListResult>(method::OWNED_LIST, json!({}))
        .ok()
        .map(|list| {
            list.owners
                .iter()
                .any(|entry| entry.owner.ends_with(&suffix))
        });
    HelperSide {
        view,
        owns,
        detail,
        health,
    }
}

impl Engine {
    /// Every check for `profile`. A profile the helper runs asks the helper;
    /// loopback Xray reads this process's own session.
    pub fn diagnose(
        &self,
        profile: &Profile,
        context: DiagnosticsContext<'_>,
    ) -> Result<ProfileDiagnostics, String> {
        let routes = context.os_routes.as_deref().unwrap_or(&[]);
        let (inspection, inspection_error) = match diagnostics::build_profile_inspection(
            profile,
            context.others,
            routes,
            context.vault,
        ) {
            Ok(inspection) => (Some(inspection), None),
            Err(error) => (None, Some(error)),
        };
        let xray = if profile.backend == TunnelBackend::Xray {
            self.managed_executable()
                .ok_or_else(|| "Install Xray to start this connection".to_string())
        } else {
            Ok(std::path::PathBuf::new())
        };
        let (status, helper, helper_owns, detail, protocol_health, proxy_owner): (
            TunnelStatus,
            Option<HelperView>,
            Option<bool>,
            TunnelDetail,
            ProtocolHealth,
            Option<String>,
        ) = if diagnostics::runs_in_helper(profile) {
            let side = helper_side(self.privileged(), profile);
            let status = self
                .remote_status(profile)
                .ok_or("This connection has no helper status")?;
            let proxy_owner = self.system_proxy_owner()?;
            (
                status,
                Some(side.view),
                side.owns,
                side.detail,
                side.health,
                proxy_owner,
            )
        } else {
            let (status, health, proxy_owner) = self.loopback_state(profile)?;
            (
                status,
                None,
                None,
                TunnelDetail::default(),
                health,
                proxy_owner,
            )
        };
        let input = ProfileChecksInput {
            profile: profile.clone(),
            status: status.clone(),
            inspection: inspection.clone(),
            inspection_error,
            xray,
            helper,
            helper_owns,
            detail,
            protocol_health,
            interfaces: context.interfaces,
            os_routes: context.os_routes,
            proxy_owner,
        };
        Ok(ProfileDiagnostics {
            profile_id: profile.id.clone(),
            status,
            inspection,
            checks: diagnostics::profile_checks(&input),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{
        ErrorBody, ErrorCode, HelloResult, OwnedEntry, OwnedState,
    };
    use net_manager_core::helper_client::HelperError;
    use net_manager_core::models::{ProtocolHealthState, TunnelState};
    use serde_json::Value;
    use std::path::PathBuf;

    struct Fake {
        reachable: bool,
        capabilities: Vec<&'static str>,
        wg_state: &'static str,
        owns: bool,
        status_fails: bool,
    }

    impl Fake {
        fn ready() -> Self {
            Self {
                reachable: true,
                capabilities: vec![method::WIREGUARD_CONNECT, method::OWNED_LIST],
                wg_state: "running",
                owns: true,
                status_fails: false,
            }
        }
    }

    impl Privileged for Fake {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            if !self.reachable {
                return Err(HelperError::Unreachable(std::io::Error::other("no socket")));
            }
            Ok(HelloResult {
                protocol: net_manager_core::daemon_protocol::PROTOCOL_VERSION,
                daemon_version: "0.9.1".into(),
                uid: 501,
                capabilities: self.capabilities.iter().map(|c| c.to_string()).collect(),
                tools: Default::default(),
            })
        }
        fn call_raw(&self, name: &str, _params: Value) -> Result<Value, HelperError> {
            if !self.reachable {
                return Err(HelperError::Unreachable(std::io::Error::other("no socket")));
            }
            Ok(match name {
                method::WIREGUARD_STATUS if self.status_fails => {
                    return Err(HelperError::Rejected(ErrorBody {
                        code: ErrorCode::UnsupportedMethod,
                        message: "no".into(),
                    }))
                }
                method::WIREGUARD_STATUS => json!({
                    "profileId": "wg1", "state": self.wg_state, "interfaceName": "utun5",
                    "latestHandshake": 1_700_000_000u64, "rxBytes": 10, "txBytes": 20,
                    "dnsApplied": true, "warnings": ["ipv6NotCovered"],
                }),
                method::OWNED_LIST => serde_json::to_value(OwnedListResult {
                    owners: if self.owns {
                        vec![OwnedEntry {
                            owner: "wireguard:wg1".into(),
                            state: OwnedState::Applied,
                            resources: Vec::new(),
                        }]
                    } else {
                        Vec::new()
                    },
                })
                .unwrap(),
                _ => return Err(HelperError::Protocol("unexpected".into())),
            })
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    fn wg() -> Profile {
        Profile {
            id: "wg1".into(),
            backend: TunnelBackend::WireGuard,
            ..Default::default()
        }
    }

    #[test]
    fn a_ready_helper_gives_handshake_health_ownership_and_notes() {
        let side = helper_side(&Fake::ready(), &wg());
        assert!(side.view.reachable && side.view.offers_capability);
        assert_eq!(side.view.version, "0.9.1");
        assert_eq!(side.owns, Some(true));
        assert_eq!(side.health.state, ProtocolHealthState::Healthy);
        assert_eq!(side.health.last_handshake_unix, Some(1_700_000_000));
        assert_eq!(side.detail.dns_applied, Some(true));
        assert_eq!(side.detail.notes.len(), 1);
    }

    #[test]
    fn a_helper_that_is_down_or_too_old_is_reported_without_further_requests() {
        let down = Fake {
            reachable: false,
            ..Fake::ready()
        };
        let side = helper_side(&down, &wg());
        assert!(!side.view.reachable && side.owns.is_none());
        assert_eq!(side.health.state, ProtocolHealthState::Failed);

        let old = Fake {
            capabilities: vec![method::OWNED_LIST],
            ..Fake::ready()
        };
        let side = helper_side(&old, &wg());
        assert!(side.view.reachable && !side.view.offers_capability);
        assert_eq!(side.owns, None);
    }

    #[test]
    fn a_status_the_helper_refuses_reads_as_failed_health_not_a_crash() {
        let refusing = Fake {
            status_fails: true,
            ..Fake::ready()
        };
        let side = helper_side(&refusing, &wg());
        assert_eq!(side.health.state, ProtocolHealthState::Failed);
        assert!(side.health.summary.contains("did not answer"));
        assert_eq!(side.owns, Some(true));
    }

    #[test]
    fn ownership_is_matched_by_profile_id_not_by_substring() {
        let mut other = Fake::ready();
        other.owns = false;
        assert_eq!(helper_side(&other, &wg()).owns, Some(false));
        // `wireguard:wg10` must not count for `wg1`.
        struct Wg10(Fake);
        impl Privileged for Wg10 {
            fn hello(&self) -> Result<HelloResult, HelperError> {
                self.0.hello()
            }
            fn call_raw(&self, name: &str, params: Value) -> Result<Value, HelperError> {
                if name == method::OWNED_LIST {
                    return Ok(serde_json::to_value(OwnedListResult {
                        owners: vec![OwnedEntry {
                            owner: "wireguard:wg10".into(),
                            state: OwnedState::Applied,
                            resources: Vec::new(),
                        }],
                    })
                    .unwrap());
                }
                self.0.call_raw(name, params)
            }
            fn log_dir(&self) -> PathBuf {
                PathBuf::new()
            }
        }
        assert_eq!(helper_side(&Wg10(Fake::ready()), &wg()).owns, Some(false));
    }

    #[test]
    fn the_capability_follows_the_backend() {
        assert_eq!(capability(&wg()), method::WIREGUARD_CONNECT);
        let ovpn = Profile {
            backend: TunnelBackend::OpenVpn,
            ..Default::default()
        };
        assert_eq!(capability(&ovpn), method::OPENVPN_CONNECT);
        let tun = Profile {
            backend: TunnelBackend::Xray,
            ..Default::default()
        };
        assert_eq!(capability(&tun), method::XRAY_CONNECT);
    }

    #[test]
    fn helper_only_diagnostics_do_not_create_a_user_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let engine = Engine::with_privileged(
            dir.path(),
            std::sync::Arc::new(Fake {
                reachable: false,
                ..Fake::ready()
            }),
        );
        let report = engine
            .diagnose(
                &wg(),
                DiagnosticsContext {
                    others: &[],
                    os_routes: Ok(Vec::new()),
                    interfaces: Ok(Vec::new()),
                    vault: &vault,
                },
            )
            .unwrap();
        assert_eq!(report.profile_id, "wg1");
        assert_eq!(report.status.state, TunnelState::Stopped);
        assert!(!dir.path().join("runtime").exists());
    }
}
