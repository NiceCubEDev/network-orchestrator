//! CLI edits replace profiles.json atomically. Observe the file identity,
//! not an in-memory document, and reuse the frontend's existing refresh event.
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use tauri::{Emitter, Manager};

fn revision(path: &std::path::Path) -> std::io::Result<Option<(u64, u64, i64, i64)>> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some((
            metadata.dev(),
            metadata.ino(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) async fn watch(app: tauri::AppHandle, path: PathBuf) {
    let mut previous = revision(&path).ok().flatten();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if app
            .state::<crate::state::AppState>()
            .shutting_down
            .load(Ordering::Acquire)
        {
            return;
        }
        let Ok(current) = revision(&path) else {
            continue;
        };
        if current != previous {
            previous = current;
            let _ = app.emit("route-changed", ());
        }
    }
}
