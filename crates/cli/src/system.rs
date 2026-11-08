//! `doctor`, `backend` and `service`.
use crate::args::{BackendCommand, ServiceCommand};
use crate::ctx::Ctx;
use crate::render::table;
use crate::service;
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
}

fn check(name: &'static str, level: Level, detail: impl Into<String>) -> Check {
    Check {
        name,
        level,
        detail: detail.into(),
    }
}

/// Shared typed helper observation, without starting a runtime owner.
pub fn helper_check() -> Check {
    let status = net_manager_engine::macos_services::helper_status();
    if status.reachable {
        check(
            "helper",
            Level::Ok,
            format!(
                "version {}, {} methods",
                status.version,
                status.capabilities.len()
            ),
        )
    } else if status.denied {
        check(
            "helper",
            Level::Fail,
            "the helper refuses this program; reinstall it from the app's Settings",
        )
    } else if status.protocol_error {
        check(
            "helper",
            Level::Fail,
            "the helper protocol is incompatible; reinstall the matching helper",
        )
    } else {
        check(
            "helper",
            Level::Warn,
            "not running: helper-backed tunnels are unavailable",
        )
    }
}

pub fn checks(ctx: &Ctx) -> Vec<Check> {
    let mut out = Vec::new();
    out.push(match std::fs::metadata(&ctx.root) {
        Ok(metadata) if metadata.is_dir() => check("data", Level::Ok, "the data directory exists"),
        Ok(_) => check("data", Level::Fail, "the data location is not a directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            check("data", Level::Warn, "no saved data yet")
        }
        Err(_) => check("data", Level::Fail, "the data directory could not be read"),
    });
    out.push(match ctx.profiles() {
        Ok(profiles) => check("profiles", Level::Ok, format!("{} saved", profiles.len())),
        Err(error) => check("profiles", Level::Fail, error),
    });
    out.push(match ctx.engine().managed_executable() {
        Some(_) => check(
            "xray",
            Level::Ok,
            format!(
                "installed ({})",
                net_manager_core::managed_xray::MACOS_XRAY_VERSION
            ),
        ),
        None => check(
            "xray",
            Level::Warn,
            "not installed: `netorch backend install` (or `netorch up` does it)",
        ),
    });
    out.push(helper_check());
    // SAFETY: geteuid never fails.
    if unsafe { libc::geteuid() } == 0 {
        out.push(check("privileges", Level::Ok, "running as root"));
    }
    out.push(match ctx.engine().system_proxy_owner() {
        Ok(Some(owner)) => check("proxy", Level::Ok, format!("held by {owner}")),
        Ok(None) => check("proxy", Level::Ok, "the system proxy is not ours"),
        Err(_) => check("proxy", Level::Warn, "the proxy owner could not be read"),
    });
    out
}

pub fn doctor(ctx: &Ctx) -> Result<(), String> {
    let checks = checks(ctx);
    let failed = checks.iter().any(|check| check.level == Level::Fail);
    let value = serde_json::to_value(&checks).map_err(|_| "Could not encode the report")?;
    ctx.emit(value, || {
        table(
            &["CHECK", "RESULT", "DETAIL"],
            &checks
                .iter()
                .map(|check| {
                    vec![
                        check.name.to_string(),
                        match check.level {
                            Level::Ok => "ok",
                            Level::Warn => "warn",
                            Level::Fail => "FAIL",
                        }
                        .to_string(),
                        check.detail.clone(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    });
    if failed {
        Err("Some checks failed".into())
    } else {
        Ok(())
    }
}

pub fn backend(ctx: &Ctx, command: BackendCommand) -> Result<(), String> {
    match command {
        BackendCommand::Install { archive } => {
            ctx.require_user()?;
            let engine = ctx.engine();
            if engine.managed_executable().is_none() {
                ctx.note("Installing the pinned Xray (hash-checked)...");
            }
            engine.install_xray(archive.as_deref().and_then(|path| path.to_str()))?;
            ctx.emit(json!({"installed": true}), || "Xray is installed.".into());
            Ok(())
        }
    }
}

fn installer() -> service::Installer<'static> {
    service::Installer {
        prefix: std::path::PathBuf::from("/"),
        launchctl: &service::SystemLaunchctl,
    }
}

fn need_root() -> Result<(), String> {
    if crate::ctx::is_root() {
        Ok(())
    } else {
        Err("This changes the system: run it with sudo".into())
    }
}

/// Alive means it answered, even if it refused us (root is refused).
fn helper_alive() -> bool {
    let status = net_manager_engine::macos_services::helper_status();
    status.reachable || status.denied || status.protocol_error
}

pub fn service(json: bool, command: ServiceCommand) -> Result<(), String> {
    match command {
        ServiceCommand::Log => {
            let log = net_manager_engine::macos_services::helper_log();
            crate::ctx::emit(json, json!({"log": log}), || log);
            Ok(())
        }
        ServiceCommand::Install => {
            if !cfg!(target_os = "macos") {
                return Err("Standalone helper installation requires macOS".into());
            }
            need_root()?;
            let exe = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map_err(|_| "netorch could not locate itself".to_string())?;
            let layout = service::layout_of(&exe)?;
            let installer = installer();
            if helper_alive() {
                return Err(if installer.is_installed() {
                    "The helper is already installed and running".into()
                } else {
                    "A helper is already running (installed by the app). \
                     Remove it in the app's Settings first"
                        .to_string()
                });
            }
            installer.install(&layout, true)?;
            for _ in 0..25 {
                if helper_alive() {
                    crate::ctx::emit(json, json!({"installed": true}), || {
                        "The helper is installed and running.".into()
                    });
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err("The helper was registered but did not start; see /var/log/network-orchestrator-helper.log".into())
        }
        ServiceCommand::Remove => {
            if !cfg!(target_os = "macos") {
                return Err("Standalone helper removal requires macOS".into());
            }
            need_root()?;
            let removed = installer().remove()?;
            crate::ctx::emit(json, json!({"removed": removed}), || {
                if removed {
                    "The helper is removed.".into()
                } else {
                    "No helper installed by netorch was found.".into()
                }
            });
            Ok(())
        }
        ServiceCommand::Status => {
            let result = helper_check();
            let failed = result.level == Level::Fail;
            crate::ctx::emit(
                json,
                serde_json::to_value(&result).map_err(|_| "Could not encode the result")?,
                || format!("{}: {}", result.name, result.detail),
            );
            if failed {
                Err("The helper is not usable".into())
            } else {
                Ok(())
            }
        }
    }
}
