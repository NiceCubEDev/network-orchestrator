//! Metadata-only diagnostics. Verbose output must never block a network operation.
use net_manager_core::daemon_protocol::LoggingVerbosity;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static VERBOSITY: AtomicU8 = AtomicU8::new(0);
static JOURNAL: OnceLock<Option<UnixDatagram>> = OnceLock::new();
static SNAPSHOTS: OnceLock<Option<mpsc::SyncSender<(u32, &'static str)>>> = OnceLock::new();
static LAST_SNAPSHOT: AtomicU64 = AtomicU64::new(0);
const MAX_THREADS: usize = 64;

pub fn set_verbosity(value: LoggingVerbosity) {
    VERBOSITY.store(
        match value {
            LoggingVerbosity::Normal => 0,
            LoggingVerbosity::Debug => 1,
            LoggingVerbosity::Trace => 2,
        },
        Ordering::Relaxed,
    );
}

pub fn verbosity() -> LoggingVerbosity {
    match VERBOSITY.load(Ordering::Relaxed) {
        1 => LoggingVerbosity::Debug,
        2 => LoggingVerbosity::Trace,
        _ => LoggingVerbosity::Normal,
    }
}

pub fn enabled(value: LoggingVerbosity) -> bool {
    VERBOSITY.load(Ordering::Relaxed)
        >= match value {
            LoggingVerbosity::Normal => 0,
            LoggingVerbosity::Debug => 1,
            LoggingVerbosity::Trace => 2,
        }
}

pub fn debug(message: fmt::Arguments<'_>) {
    if enabled(LoggingVerbosity::Debug) {
        emit(7, format_args!("debug {message}"));
    }
}

pub fn trace(message: fmt::Arguments<'_>) {
    if enabled(LoggingVerbosity::Trace) {
        emit(7, format_args!("trace {message}"));
    }
}

fn emit(priority: u8, message: fmt::Arguments<'_>) -> bool {
    let socket = JOURNAL.get_or_init(|| {
        let opened = UnixDatagram::unbound().and_then(|socket| {
            socket.set_nonblocking(true)?;
            socket.connect("/run/systemd/journal/socket")?;
            Ok(socket)
        });
        if opened.is_err() {
            eprintln!("network-orchestrator-daemon: diagnostic journal unavailable");
        }
        opened.ok()
    });
    let Some(socket) = socket else {
        return false;
    };
    // All callers supply controlled metadata, never request bodies or raw errors.
    let text = format!("PRIORITY={priority}\nSYSLOG_IDENTIFIER=network-orchestrator-daemon\nMESSAGE=network-orchestrator-daemon: {message}");
    text.len() <= 4096 && socket.send(text.as_bytes()).is_ok()
}

/// Capture on a separate bounded worker: /proc reads must not hold up recovery.
/// Repeated timeouts coalesce; captures remain enabled at normal verbosity too.
pub fn snapshot_process(pid: u32, reason: &'static str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let previous = LAST_SNAPSHOT.load(Ordering::Relaxed);
    if now.saturating_sub(previous) < 5
        || LAST_SNAPSHOT
            .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    let sender = SNAPSHOTS.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<(u32, &'static str)>(1);
        std::thread::Builder::new()
            .name("hang-diagnostics".into())
            .spawn(move || {
                while let Ok((pid, reason)) = receiver.recv() {
                    let mut record = |line: String| {
                        if !emit(4, format_args!("{line}")) {
                            // Only the diagnostic worker can block on stderr, never a core/actor task.
                            eprintln!("network-orchestrator-daemon: {line}");
                        }
                    };
                    capture_process(Path::new("/proc"), pid, reason, &mut record);
                    if pid != std::process::id() {
                        capture_process(
                            Path::new("/proc"),
                            std::process::id(),
                            reason,
                            &mut record,
                        );
                    }
                }
            })
            .ok()
            .map(|_| sender)
    });
    if let Some(sender) = sender {
        let _ = sender.try_send((pid, reason));
    }
}

fn limited_text(path: &Path, limit: u64) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?.take(limit).read_to_string(&mut text)?;
    Ok(text)
}

fn symbol(text: &str) -> Option<&str> {
    let text = text.trim();
    (!text.is_empty()
        && text.len() <= 96
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.')))
    .then_some(text)
}

fn capture_process(root: &Path, pid: u32, reason: &str, record: &mut impl FnMut(String)) {
    record(format!("hang snapshot begin pid={pid} reason={reason}"));
    let tasks = match std::fs::read_dir(root.join(pid.to_string()).join("task")) {
        Ok(tasks) => tasks,
        Err(error) => {
            record(format!(
                "hang snapshot unavailable pid={pid} os_code={:?}",
                error.raw_os_error()
            ));
            return;
        }
    };
    let mut count = 0;
    for task in tasks
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.parse::<u32>().is_ok())
        })
        .take(MAX_THREADS + 1)
    {
        if count == MAX_THREADS {
            record(format!(
                "hang snapshot truncated pid={pid} limit={MAX_THREADS}"
            ));
            break;
        }
        count += 1;
        let tid = task
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .unwrap();
        let path = task.path();
        let status = limited_text(&path.join("status"), 4096);
        let state = status
            .as_ref()
            .ok()
            .and_then(|text| text.lines().find_map(|line| line.strip_prefix("State:")))
            .and_then(|text| text.trim().chars().next())
            .filter(|state| "RSDZTWtXxKWPIN".contains(*state));
        let wchan = limited_text(&path.join("wchan"), 128);
        let wait = wchan
            .as_ref()
            .ok()
            .and_then(|text| symbol(text))
            .unwrap_or("unknown");
        let syscall = limited_text(&path.join("syscall"), 256);
        // Never record syscall arguments, pointers, names, environments or descriptors.
        let syscall_number = syscall
            .as_ref()
            .ok()
            .and_then(|text| text.split_whitespace().next())
            .and_then(|number| number.parse::<i32>().ok())
            .filter(|number| (-1..=10000).contains(number));
        let stack = limited_text(&path.join("stack"), 4096);
        let frames: Vec<&str> = stack
            .as_ref()
            .map(|text| {
                text.lines()
                    .filter_map(|line| {
                        line.split_whitespace().find_map(|word| {
                            word.split_once('+').and_then(|(name, _)| symbol(name))
                        })
                    })
                    .take(4)
                    .collect()
            })
            .unwrap_or_default();
        record(format!("hang thread pid={pid} tid={tid} state={} wchan={wait} syscall={syscall_number:?} kernel_frames={} status_errno={:?} wchan_errno={:?} syscall_errno={:?} stack_errno={:?}", state.unwrap_or('?'), frames.join(","), status.as_ref().err().and_then(io::Error::raw_os_error), wchan.as_ref().err().and_then(io::Error::raw_os_error), syscall.as_ref().err().and_then(io::Error::raw_os_error), stack.as_ref().err().and_then(io::Error::raw_os_error)));
    }
    record(format!("hang snapshot end pid={pid} threads={count}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn hang_evidence_records_wait_and_frames_without_process_secrets_or_addresses() {
        let root = std::env::temp_dir().join(format!(
            "netorch-hang-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let task = root.join("42/task/43");
        std::fs::create_dir_all(&task).unwrap();
        std::fs::write(
            task.join("status"),
            "Name:\tNEVER_LOG_NAME\nState:\tD (disk sleep)\n",
        )
        .unwrap();
        std::fs::write(task.join("wchan"), "rtnl_lock").unwrap();
        std::fs::write(
            task.join("syscall"),
            "47 0xSECRET_ARGUMENT 0xSECRET_POINTER",
        )
        .unwrap();
        std::fs::write(
            task.join("stack"),
            "[<0xSECRET_ADDRESS>] rtnl_lock+0x19/0x20\n[<0>] tun_chr_close+0x2/0x30 [tun]\n",
        )
        .unwrap();
        let mut lines = Vec::new();
        capture_process(&root, 42, "xray_sigterm_timeout", &mut |line| {
            lines.push(line)
        });
        let output = lines.join("\n");
        assert!(output.contains(
            "state=D wchan=rtnl_lock syscall=Some(47) kernel_frames=rtnl_lock,tun_chr_close"
        ));
        assert!(!output.contains("SECRET"));
        assert!(!output.contains("NEVER_LOG_NAME"));
        std::fs::remove_file(task.join("stack")).unwrap();
        lines.clear();
        capture_process(&root, 42, "xray_sigkill_timeout", &mut |line| {
            lines.push(line)
        });
        assert!(lines
            .iter()
            .any(|line| line.contains("state=D") && line.contains("stack_errno=Some(2)")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_process_is_reported_without_exposing_paths() {
        let root = std::env::temp_dir().join(format!(
            "netorch-no-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut lines = Vec::new();
        capture_process(&root, 42, "netlink_reply_timeout", &mut |line| {
            lines.push(line)
        });
        assert!(lines
            .iter()
            .any(|line| line.contains("unavailable pid=42 os_code=Some(2)")));
        assert!(lines
            .iter()
            .all(|line| !line.contains(root.to_str().unwrap())));
    }
}
