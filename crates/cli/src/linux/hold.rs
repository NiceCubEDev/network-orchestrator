//! Foreground connection lifetime and signal handling.
use super::auth;
use super::ctx::Ctx;
use net_manager_core::models::{Profile, TunnelState};
use net_manager_engine::linux_engine::LinuxEngine;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How often foreground mode checks the connection.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(10);
/// Consecutive "not running" readings before foreground mode ends: three polls,
/// about the daemon's own 30 s grace, so a `switch` that reconnects in between
/// does not end it.
const MISSES_BEFORE_EXIT: u32 = 3;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Interrupt, termination and terminal hangup disconnect foreground mode.
fn install_signal_handlers() {
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
    }
}

/// Why a watch ended.
#[derive(Debug, PartialEq, Eq)]
pub enum WatchEnd {
    /// Asked to stop (signal).
    Signal,
    /// The tunnel is no longer running.
    TunnelGone,
}

/// Waits until `stop` is set or the tunnel has not been running for
/// `misses` readings in a row. Every reading is a short connection to the
/// daemon, which keeps this process registered as a client.
pub fn watch(
    engine: &LinuxEngine,
    profile: &Profile,
    stop: &AtomicBool,
    interval: Duration,
    misses: u32,
) -> WatchEnd {
    let mut missed = 0;
    let mut last = Instant::now() - interval;
    loop {
        if stop.load(Ordering::SeqCst) {
            return WatchEnd::Signal;
        }
        if last.elapsed() >= interval {
            last = Instant::now();
            match engine.status(profile) {
                Ok(status) if status.state == TunnelState::Running => missed = 0,
                Ok(_) => missed += 1,
                // The daemon being unreachable is not evidence the tunnel is gone.
                Err(_) => {}
            }
            if missed >= misses {
                return WatchEnd::TunnelGone;
            }
        }
        std::thread::sleep(Duration::from_millis(100).min(interval));
    }
}

/// `netorch up --foreground`: holds the connection in this terminal and
/// disconnects on Ctrl+C.
pub fn run_foreground(ctx: &Ctx, profile: &Profile) -> Result<String, String> {
    install_signal_handlers();
    eprintln!("Press Ctrl+C to disconnect.");
    let end = watch(
        &ctx.engine,
        profile,
        &STOP,
        WATCH_INTERVAL,
        MISSES_BEFORE_EXIT,
    );
    match end {
        WatchEnd::Signal => {
            auth::run(ctx.root_user, || ctx.engine.disconnect(profile))?;
            Ok(format!("Disconnected \"{}\"", profile.name))
        }
        WatchEnd::TunnelGone => Err(format!("\"{}\" is no longer connected", profile.name)),
    }
}
