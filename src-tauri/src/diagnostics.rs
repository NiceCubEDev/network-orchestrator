use crate::state::AppState;
use serde::Deserialize;
use tauri::State;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum FailureKind {
    Uncaught,
    UnhandledRejection,
    ReactUncaught,
    ReactRecovered,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ErrorClass {
    Error,
    TypeError,
    ReferenceError,
    RangeError,
    SyntaxError,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Asset {
    App,
    Index,
    Runtime,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FrontendFrame {
    asset: Asset,
    line: u32,
    column: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FrontendFailure {
    kind: FailureKind,
    error_class: ErrorClass,
    frames: Vec<FrontendFrame>,
}

#[tauri::command]
pub(crate) fn report_frontend_failure(
    state: State<'_, AppState>,
    failure: FrontendFailure,
) -> Result<(), String> {
    if failure.frames.len() > 8 {
        return Err("Too many diagnostic frames".into());
    }
    let mut message = format!(
        "gui frontend_failure pid={} kind={:?} class={:?}",
        std::process::id(),
        failure.kind,
        failure.error_class
    );
    for frame in failure.frames {
        use std::fmt::Write;
        let _ = write!(
            message,
            " frame={:?}:{}:{}",
            frame.asset, frame.line, frame.column
        );
    }
    #[cfg(target_os = "linux")]
    {
        let _ = &state;
        linux::record(
            net_manager_engine::linux_diagnostics::LogLevel::Error,
            &message,
        );
    }
    #[cfg(not(target_os = "linux"))]
    crate::commands::logs::record_log(&state, crate::commands::logs::LogLevel::Error, message);
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{initialize, install, record};

#[cfg(target_os = "linux")]
mod linux {
    use net_manager_engine::linux_diagnostics::{try_record_log, LogLevel};
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
    use std::os::unix::net::UnixDatagram;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;

    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    static PANIC_FILE: OnceLock<File> = OnceLock::new();
    static PANIC_RECORDED: AtomicBool = AtomicBool::new(false);

    // Callers pass controlled metadata, never request data or arbitrary error text.
    fn journal(level: LogLevel, message: &str) {
        let priority = match level {
            LogLevel::Info => 6,
            LogLevel::Warn => 4,
            LogLevel::Error => 3,
        };
        let sent = UnixDatagram::unbound().and_then(|socket| {
            socket.set_nonblocking(true)?;
            socket.send_to(
                format!(
                    "PRIORITY={priority}\nSYSLOG_IDENTIFIER=net-manager-app\nMESSAGE={message}\n"
                )
                .as_bytes(),
                "/run/systemd/journal/socket",
            )
        });
        if sent.is_err() {
            eprintln!("net-manager-app: {message}");
        }
    }

    pub(crate) fn record(level: LogLevel, message: &str) {
        journal(level, message);
        if ROOT
            .get()
            .is_some_and(|root| try_record_log(root, level, message).is_err())
        {
            journal(LogLevel::Warn, "gui diagnostic_store_write_failed");
        }
    }

    pub(crate) fn initialize(root: &Path) {
        let _ = ROOT.set(root.to_path_buf());
        record(
            LogLevel::Info,
            &format!(
                "gui setup_ready pid={} version={}",
                std::process::id(),
                env!("NETORCH_VERSION")
            ),
        );
        let opened = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join("app-logs/gui-panic.log"))
            .and_then(|file| {
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o077 != 0
                    || metadata.nlink() != 1
                {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                Ok(file)
            });
        match opened {
            Ok(file) => {
                let _ = PANIC_FILE.set(file);
            }
            Err(error) => record(
                LogLevel::Warn,
                &format!(
                    "gui panic_store_unavailable kind={:?} os_code={:?}",
                    error.kind(),
                    error.raw_os_error()
                ),
            ),
        }
    }

    pub(crate) fn install() {
        std::panic::set_hook(Box::new(|info| {
            if PANIC_RECORDED.swap(true, Ordering::SeqCst) {
                journal(
                    LogLevel::Error,
                    &format!("gui concurrent_panic pid={}", std::process::id()),
                );
                return;
            }
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|time| time.as_millis())
                .unwrap_or_default();
            let mut message = format!(
                "gui panic pid={} version={} ts_unix_ms={timestamp} thread={:?}",
                std::process::id(),
                env!("NETORCH_VERSION"),
                std::thread::current().id()
            );
            if let Some(location) = info.location() {
                let file = Path::new(location.file())
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                use std::fmt::Write;
                let _ = write!(
                    message,
                    " source={file}:{}:{}",
                    location.line(),
                    location.column()
                );
            }
            let trace = std::backtrace::Backtrace::force_capture().to_string();
            for frame in trace
                .lines()
                .filter(|line| {
                    line.trim()
                        .split_once(':')
                        .is_some_and(|(index, _)| index.parse::<usize>().is_ok())
                })
                .take(16)
            {
                message.push_str(" frame=");
                message.extend(frame.trim().chars().filter(|ch| !ch.is_control()).take(240));
            }
            // Never invoke the previous hook: panic payloads can contain configs.
            // A pre-opened file avoids re-entering the log store's lock on panic.
            if let Some(file) = PANIC_FILE.get() {
                let _ = file.set_len(0);
                let _ = file.write_all_at(message.as_bytes(), 0);
                let _ = file.sync_data();
            }
            journal(LogLevel::Error, &message);
            PANIC_RECORDED.store(false, Ordering::SeqCst);
        }));
        journal(
            LogLevel::Info,
            &format!(
                "gui launch pid={} version={}",
                std::process::id(),
                env!("NETORCH_VERSION")
            ),
        );
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn panic_diagnostic_survives_without_payload() {
            const CHILD: &str = "NETORCH_DIAGNOSTIC_TEST_CHILD";
            if let Some(root) = std::env::var_os(CHILD) {
                install();
                initialize(Path::new(&root));
                panic!("vless://private-credential@private-host password=private-password");
            }
            let root = crate::test_support::unique_dir("panic-diagnostic");
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "diagnostics::linux::tests::panic_diagnostic_survives_without_payload",
                    "--nocapture",
                ])
                .env(CHILD, &root)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let pid = child.id();
            let output = child.wait_with_output().unwrap();
            assert!(!output.status.success());
            let record = std::fs::read_to_string(root.join("app-logs/gui-panic.log")).unwrap();
            assert!(record.contains(&format!("pid={pid}")));
            assert!(record.contains("source=diagnostics.rs:"));
            assert!(record.contains("frame="));
            for bytes in [record.as_bytes(), output.stderr.as_slice()] {
                let text = String::from_utf8_lossy(bytes);
                assert!(!text.contains("private-credential"));
                assert!(!text.contains("private-password"));
                assert!(!text.contains("private-host"));
            }
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
