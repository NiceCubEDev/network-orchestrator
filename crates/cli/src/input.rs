//! Bounded typed input. Parse errors never echo a document containing secrets.
use serde::de::DeserializeOwned;
use std::io::{IsTerminal, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
const MAX: u64 = 1024 * 1024;

pub fn bytes(path: &Path, secret: bool) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    if path == Path::new("-") {
        let stdin = std::io::stdin();
        if secret && stdin.is_terminal() {
            return Err(
                "Pipe secret input or use a protected file; terminal stdin is not accepted".into(),
            );
        }
        stdin
            .take(MAX + 1)
            .read_to_end(&mut data)
            .map_err(|_| "Could not read stdin")?;
    } else {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "Could not open input file")?;
        let meta = file
            .metadata()
            .map_err(|_| "Could not inspect input file")?;
        if !meta.is_file() || meta.len() > MAX {
            return Err("Input must be a bounded regular file".into());
        }
        if secret
            && (meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().mode() & 0o077 != 0
                || meta.nlink() != 1)
        {
            return Err("Credential input must be private (chmod 600), single-linked and owned by this user".into());
        }
        file.take(MAX + 1)
            .read_to_end(&mut data)
            .map_err(|_| "Could not read input file")?;
    }
    if data.len() as u64 > MAX {
        return Err("Input is too large".into());
    }
    Ok(data)
}
pub fn json<T: DeserializeOwned>(path: &Path, secret: bool) -> Result<T, String> {
    serde_json::from_slice(&bytes(path, secret)?)
        .map_err(|_| "Invalid input document; check the typed command schema".into())
}
pub fn text(path: &Path, secret: bool) -> Result<String, String> {
    String::from_utf8(bytes(path, secret)?).map_err(|_| "Input must be UTF-8".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_files_refuse_public_permissions_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        std::fs::write(&p, "sensitive-invalid-json").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(bytes(&p, true).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = json::<serde_json::Value>(&p, true).unwrap_err();
        assert!(!err.contains("sensitive"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(bytes(&link, true).is_err());
    }
}
