//! Persist the next activation identity before starting, so a stale frontend
//! can never name a replacement activation after an owner restart.
use crate::macos_transaction;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(crate) fn load(root: &Path) -> Result<u64, String> {
    if macos_transaction::canonical_root(&root.join("runtime"), false)?.is_none() {
        return Ok(0);
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(root.join("runtime/activation-generation"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err("Activation generation could not be read".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "Activation generation could not be inspected")?;
    if !metadata.is_file()
        || metadata.uid() != macos_transaction::user_uid()?
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 20
    {
        return Err("Activation generation file is unsafe".into());
    }
    crate::macos_state::reject_writable_acl(&file)?;
    let mut bytes = [0u8; 21];
    let mut count = 0;
    loop {
        let read = file
            .read(&mut bytes[count..])
            .map_err(|_| "Activation generation could not be read")?;
        if read == 0 {
            break;
        }
        count += read;
        if count > 20 {
            return Err("Activation generation is too large".into());
        }
    }
    std::str::from_utf8(&bytes[..count])
        .map_err(|_| "Activation generation is invalid")?
        .parse()
        .map_err(|_| "Activation generation is invalid".into())
}

pub(crate) fn reserve(root: &Path, previous: u64) -> Result<u64, String> {
    if load(root)? != previous {
        return Err("Activation generation changed outside the owner".into());
    }
    let next = previous
        .checked_add(1)
        .ok_or("Activation generation exhausted")?;
    let runtime = macos_transaction::canonical_root(&root.join("runtime"), true)?
        .ok_or("Missing runtime directory")?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "Cannot timestamp activation generation")?
        .as_nanos();
    let temp = runtime.join(format!(
        ".activation-generation-{}-{next}-{nonce}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)
            .map_err(|_| "Activation generation could not be prepared")?;
        crate::macos_state::reject_writable_acl(&file)?;
        write!(file, "{next}")
            .and_then(|_| file.sync_all())
            .map_err(|_| "Activation generation could not be saved")?;
        fs::rename(&temp, runtime.join("activation-generation"))
            .map_err(|_| "Activation generation could not be committed")?;
        File::open(&runtime)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "Activation generation directory could not be synced")?;
        Ok(next)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activation_identity_is_persistent_and_never_reused() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(load(temp.path()).unwrap(), 0);
        assert!(!temp.path().join("runtime").exists());
        assert_eq!(reserve(temp.path(), 0).unwrap(), 1);
        assert_eq!(load(temp.path()).unwrap(), 1);
        assert!(reserve(temp.path(), 0).is_err());
        assert_eq!(reserve(temp.path(), 1).unwrap(), 2);
    }
}
