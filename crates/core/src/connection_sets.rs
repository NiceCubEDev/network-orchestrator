//! Protected connection-set documents shared by the native and Linux clients.
use crate::{config_security::protect_path, models::Profile, profiles::ProfileStore};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

const MAX_BYTES: u64 = 1024 * 1024;
const MAX_SETS: usize = 256;

/// Per-profile input only. Credentials never enter saved sets or command results.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionSetCredentialInput {
    pub credentials: crate::daemon_protocol::OpenVpnCredentials,
    #[serde(default)]
    pub remember: bool,
}

pub type CredentialInputs = BTreeMap<String, ConnectionSetCredentialInput>;

pub fn read_credentials_file(path: &Path) -> Result<CredentialInputs, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Cannot open connection-set credentials file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect connection-set credentials file")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_BYTES
    {
        return Err(
            "Connection-set credentials file must be private, bounded and owned by this user"
                .into(),
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read connection-set credentials file")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("Connection-set credentials file is too large".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid connection-set credentials file".into())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionSet {
    pub id: String,
    pub name: String,
    pub profile_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
    version: u32,
    sets: Vec<ConnectionSet>,
    #[serde(default, skip_serializing_if = "is_false")]
    native_legacy_imported: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && id != "."
        && id != ".."
}

pub fn validate(set: &ConnectionSet) -> Result<(), String> {
    if !valid_id(&set.id) {
        return Err("Invalid connection-set ID".into());
    }
    // Preserve legacy labels; the protected document bounds their size.
    if set.name.len() as u64 > MAX_BYTES
        || set.name.trim().is_empty()
        || set.name.chars().any(char::is_control)
    {
        return Err("Invalid connection-set name".into());
    }
    if set.profile_ids.len() > 256 {
        return Err("Too many connection-set members".into());
    }
    let mut ids = HashSet::new();
    for id in &set.profile_ids {
        if !valid_id(id) || !ids.insert(id) {
            return Err("Invalid or duplicate connection-set member".into());
        }
    }
    Ok(())
}

fn validate_batch(sets: &[ConnectionSet]) -> Result<(), String> {
    if sets.len() > MAX_SETS {
        return Err("Too many connection sets".into());
    }
    let mut ids = HashSet::new();
    for set in sets {
        validate(set)?;
        if !ids.insert(&set.id) {
            return Err("Duplicate connection-set ID".into());
        }
    }
    Ok(())
}

/// Bounded regular-file input; never follows symlinks or waits on a FIFO.
pub fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Cannot open connection-set file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect connection-set file")?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err("Invalid or oversized connection-set file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read connection-set file")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("Connection-set file is too large".into());
    }
    Ok(bytes)
}

fn lock(root: &Path, name: &str) -> Result<File, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("Run connection sets as your own user, without sudo".into());
    }
    fs::create_dir_all(root).map_err(|_| "Cannot create connection-set directory")?;
    let metadata =
        fs::symlink_metadata(root).map_err(|_| "Cannot inspect connection-set directory")?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("Connection-set directory is not owned by this user".into());
    }
    protect_path(root).map_err(|_| "Cannot protect connection-set directory")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join(name))
        .map_err(|_| "Cannot open connection-set lock")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect connection-set lock")?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
    {
        return Err("Unsafe connection-set lock".into());
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| "Cannot protect connection-set lock")?;
    file.lock().map_err(|_| "Cannot lock connection sets")?;
    Ok(file)
}

/// Serialize connection-set lifecycle operations without exposing arbitrary lock paths.
pub fn lock_lifecycle(root: &Path) -> Result<File, String> {
    lock(root, "connection-sets.runtime.lock")
}

fn load(root: &Path) -> Result<Document, String> {
    let path = root.join("connection-sets.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Document {
                version: 1,
                sets: Vec::new(),
                native_legacy_imported: false,
            })
        }
        Err(_) => return Err("Cannot inspect connection sets".into()),
        Ok(metadata)
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.nlink() != 1 =>
        {
            return Err("Unsafe connection-set store".into())
        }
        Ok(_) => (),
    }
    let document: Document = serde_json::from_slice(&read_input(&path)?)
        .map_err(|_| "Invalid connection-set document")?;
    if document.version != 1 {
        return Err("Unsupported connection-set document version".into());
    }
    validate_batch(&document.sets)?;
    Ok(document)
}

fn save(root: &Path, document: &Document) -> Result<(), String> {
    validate_batch(&document.sets)?;
    let bytes = serde_json::to_vec_pretty(document).map_err(|_| "Cannot encode connection sets")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("Connection-set store is too large".into());
    }
    // A unique temp file leaves crash debris harmless; the separate lock survives rename.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "System clock unavailable")?
        .as_nanos();
    let temp = root.join(format!(
        "connection-sets.{}.{stamp}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| "Cannot create connection-set transaction")?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|_| "Cannot write connection sets")?;
        file.sync_all().map_err(|_| "Cannot sync connection sets")?;
        fs::rename(&temp, root.join("connection-sets.json"))
            .map_err(|_| "Cannot commit connection sets")?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "Cannot sync connection-set directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub fn list(root: &Path) -> Result<Vec<ConnectionSet>, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("Run connection sets as your own user, without sudo".into());
    }
    Ok(load(root)?.sets)
}

pub fn get(root: &Path, id: &str) -> Result<ConnectionSet, String> {
    list(root)?
        .into_iter()
        .find(|set| set.id == id)
        .ok_or_else(|| format!("Connection set '{id}' not found"))
}

pub fn missing_members(set: &ConnectionSet, profiles: &[Profile]) -> Vec<String> {
    set.profile_ids
        .iter()
        .filter(|id| !profiles.iter().any(|p| &p.id == *id))
        .cloned()
        .collect()
}

pub fn validate_members(set: &ConnectionSet, profiles: &[Profile]) -> Result<(), String> {
    let missing = missing_members(set, profiles);
    if !missing.is_empty() {
        return Err(format!(
            "Missing connection-set members: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

pub fn put(root: &Path, store: &ProfileStore, set: ConnectionSet) -> Result<ConnectionSet, String> {
    validate(&set)?;
    validate_members(
        &set,
        &store.load().map_err(|_| "Cannot load profiles")?.profiles,
    )?;
    let _guard = lock(root, "connection-sets.json.lock")?;
    let mut document = load(root)?;
    if let Some(old) = document.sets.iter_mut().find(|old| old.id == set.id) {
        *old = set.clone();
    } else {
        document.sets.push(set.clone());
    }
    save(root, &document)?;
    Ok(set)
}

pub fn delete(root: &Path, id: &str) -> Result<(), String> {
    let _guard = lock(root, "connection-sets.json.lock")?;
    let mut document = load(root)?;
    let before = document.sets.len();
    document.sets.retain(|set| set.id != id);
    if document.sets.len() == before {
        return Err(format!("Connection set '{id}' not found"));
    }
    save(root, &document)
}

/// Legacy snapshots are insert-only. Repeated/stale imports cannot replace shared edits.
pub fn import(root: &Path, incoming: Vec<ConnectionSet>) -> Result<Vec<ConnectionSet>, String> {
    validate_batch(&incoming)?;
    let _guard = lock(root, "connection-sets.json.lock")?;
    let mut document = load(root)?;
    let mut changed = false;
    for set in incoming {
        if !document.sets.iter().any(|old| old.id == set.id) {
            document.sets.push(set);
            changed = true;
        }
    }
    if changed {
        save(root, &document)?;
    }
    Ok(document.sets)
}

/// One-time native defaults migration. The marker and sets commit together;
/// stale defaults can never resurrect a set deleted after migration.
pub fn import_legacy_once(
    root: &Path,
    incoming: Vec<ConnectionSet>,
) -> Result<Vec<ConnectionSet>, String> {
    let _guard = lock(root, "connection-sets.json.lock")?;
    let mut document = load(root)?;
    if document.native_legacy_imported {
        return Ok(document.sets);
    }
    validate_batch(&incoming)?;
    for set in incoming {
        if !document.sets.iter().any(|old| old.id == set.id) {
            document.sets.push(set);
        }
    }
    document.native_legacy_imported = true;
    save(root, &document)?;
    Ok(document.sets)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_labels_survive_migration_without_weakening_document_bounds() {
        let root = tempfile::tempdir().unwrap();
        let legacy = ConnectionSet {
            id: "legacy".into(),
            name: "Рабочий набор ".repeat(40),
            profile_ids: vec!["missing-profile".into()],
        };
        import_legacy_once(root.path(), vec![legacy.clone()]).unwrap();
        assert_eq!(get(root.path(), "legacy").unwrap(), legacy);
        let oversized = ConnectionSet {
            id: "oversized".into(),
            name: "x".repeat(MAX_BYTES as usize),
            profile_ids: Vec::new(),
        };
        assert!(import(root.path(), vec![oversized]).is_err());
        assert_eq!(list(root.path()).unwrap(), vec![legacy]);
    }

    #[test]
    fn input_boundaries_and_duplicate_batch_are_rejected() {
        let set = ConnectionSet {
            id: "valid".into(),
            name: "Set".into(),
            profile_ids: vec!["member".into()],
        };
        assert!(validate(&set).is_ok());
        assert!(validate_batch(&[set.clone(), set.clone()]).is_err());
        for id in ["../escape", ".", "..", "member\n", ""] {
            assert!(!valid_id(id));
        }
        let mut invalid = set;
        invalid.profile_ids.push("member".into());
        assert!(validate(&invalid).is_err());
    }

    #[test]
    fn unsafe_input_and_future_documents_fail_without_replacement() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("input.json");
        fs::write(&target, b"[]").unwrap();
        let link = root.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_input(&link).is_err());
        assert!(read_input(root.path()).is_err());
        let oversized = root.path().join("oversized.json");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert!(read_input(&oversized).is_err());
        let path = root.path().join("connection-sets.json");
        let future = br#"{"version":999,"sets":[]}"#;
        fs::write(&path, future).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(list(root.path()).is_err());
        assert!(import(root.path(), Vec::new()).is_err());
        assert_eq!(fs::read(path).unwrap(), future);
    }
    #[test]
    fn credential_files_reject_public_symlink_fifo_and_oversized_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credentials.json");
        fs::write(&path, br#"{"profile":{"credentials":{"authUserPass":{"username":"fixture","password":"synthetic"}},"remember":false}}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_credentials_file(&path).unwrap().len(), 1);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_credentials_file(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_credentials_file(&link).is_err());
        let fifo = directory.path().join("credentials.fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(read_credentials_file(&fifo).is_err());
        let file = File::create(&path).unwrap();
        file.set_len(MAX_BYTES + 1).unwrap();
        assert!(read_credentials_file(&path).is_err());
    }
}
