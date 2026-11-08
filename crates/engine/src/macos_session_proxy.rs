//! A lifetime flock plus durable cross-root claim: a crashed owner must not
//! let another root snapshot its unrestored proxy as the user's baseline.
use crate::macos_transaction::{self, FileLock};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

fn user_base() -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStrExt;
    let uid = macos_transaction::user_uid()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = [0u8; 16 * 1024];
    if unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
        || pwd.pw_dir.is_null()
    {
        return Err("The user's trusted home directory could not be resolved".into());
    }
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(
        unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }.to_bytes(),
    ));
    macos_transaction::canonical_root(&home, false)?
        .ok_or("The user's home directory is missing")?;
    #[cfg(target_os = "macos")]
    let base = home.join("Library/Application Support/NetworkOrchestrator/SharedRuntime");
    #[cfg(not(target_os = "macos"))]
    let base = home.join(".local/state/network-orchestrator/macos-shared-proxy");
    macos_transaction::canonical_root(&base, true)?;
    Ok(base)
}

fn read_claim(base: &Path) -> Result<Option<PathBuf>, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(base.join("system-proxy-owner.json"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("The per-user proxy claim could not be read".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "The per-user proxy claim could not be inspected")?;
    if !metadata.is_file()
        || metadata.uid() != macos_transaction::user_uid()?
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 4096
    {
        return Err("The per-user proxy claim is unsafe".into());
    }
    crate::macos_state::reject_writable_acl(&file)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "The per-user proxy claim could not be read")?;
    if bytes.len() > 4096 {
        return Err("The per-user proxy claim is too large".into());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "The per-user proxy claim is invalid".into())
}

fn write_claim(base: &Path, root: &Path) -> Result<(), String> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "Cannot timestamp proxy claim")?
        .as_nanos();
    let temp = base.join(format!(
        ".system-proxy-owner-{}-{nonce}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)
            .map_err(|_| "The per-user proxy claim could not be prepared")?;
        crate::macos_state::reject_writable_acl(&file)?;
        let bytes =
            serde_json::to_vec(root).map_err(|_| "The proxy owner path could not be encoded")?;
        if bytes.len() > 4096 {
            return Err("The proxy owner path is too long".into());
        }
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "The per-user proxy claim could not be saved")?;
        fs::rename(&temp, base.join("system-proxy-owner.json"))
            .map_err(|_| "The per-user proxy claim could not be committed")?;
        File::open(base)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "The proxy claim directory could not be synced")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub(crate) fn acquire(root: &Path) -> Result<FileLock, String> {
    let base = user_base()?;
    acquire_at(root, &base)
}

pub(crate) fn acquire_at(root: &Path, base: &Path) -> Result<FileLock, String> {
    macos_transaction::canonical_root(base, true)?;
    let guard = macos_transaction::lock_file(&base.join("system-proxy.lock"), true)?
        .ok_or("Another data directory owns the per-user system proxy")?;
    if let Some(previous) = read_claim(base)? {
        if previous != root
            && (macos_transaction::canonical_root(&previous, false)?.is_none()
                || crate::runtime::persisted_proxy_owner(&previous)?.is_some())
        {
            return Err("Another data directory has an unfinished system proxy restore. Recover that connection first.".into());
        }
    }
    write_claim(base, root)?;
    Ok(guard)
}

pub(crate) fn release(root: &Path) -> Result<(), String> {
    let base = user_base()?;
    release_at(root, &base)
}

pub(crate) fn release_at(root: &Path, base: &Path) -> Result<(), String> {
    match read_claim(base)? {
        None => return Ok(()),
        Some(owner) if owner == root => {}
        Some(_) => return Err("The per-user proxy owner changed unexpectedly".into()),
    }
    fs::remove_file(base.join("system-proxy-owner.json"))
        .map_err(|_| "The per-user proxy claim could not be cleared")?;
    File::open(base)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "The proxy claim directory could not be synced".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crash_releases_flock_but_retains_unrestored_cross_root_claim() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let base = temp.path().join("coordination");
        macos_transaction::canonical_root(&first, true).unwrap();
        macos_transaction::canonical_root(&second, true).unwrap();
        let mut proxy = net_manager_core::system_proxy::SystemProxyManager::with_adapter(
            first.join("runtime/system-proxy.json"),
            Box::new(TestProxy),
        )
        .unwrap();
        let held = acquire_at(&first, &base).unwrap();
        proxy.apply("p", 1080, &[]).unwrap();
        assert!(acquire_at(&second, &base).is_err());
        drop(held);
        assert!(acquire_at(&second, &base).is_err());
        let recovered = acquire_at(&first, &base).unwrap();
        proxy.restore_any().unwrap();
        release_at(&first, &base).unwrap();
        drop(recovered);
        let next = acquire_at(&second, &base).unwrap();
        release_at(&second, &base).unwrap();
        drop(next);
    }
    struct TestProxy;
    impl net_manager_core::system_proxy::ProxyAdapter for TestProxy {
        fn snapshot(&mut self) -> std::io::Result<net_manager_core::system_proxy::ProxySnapshot> {
            Ok(Default::default())
        }
        fn apply(&mut self, _: &str, _: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn restore(
            &mut self,
            _: &net_manager_core::system_proxy::ProxySnapshot,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }
}
