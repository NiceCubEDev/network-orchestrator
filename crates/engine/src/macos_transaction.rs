//! Cross-frontend operation serialization, separate from service ownership.
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

pub(crate) fn user_uid() -> Result<u32, String> {
    let uid = unsafe { libc::getuid() };
    let effective = unsafe { libc::geteuid() };
    check_user_identity(uid, effective)
}

fn check_user_identity(uid: u32, effective: u32) -> Result<u32, String> {
    if uid == 0 || uid != effective {
        return Err("Run the user connection service as your own user, never sudo/root".into());
    }
    Ok(uid)
}

/// Resolve a user root, admitting only root-controlled OS ancestor aliases.
pub fn canonical_root(root: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    canonical_directory(root, create, true, user_uid()?)
}

pub(crate) fn trusted_directory(path: &Path) -> Result<(), String> {
    canonical_directory(path, false, false, user_uid()?)?
        .ok_or_else(|| "The executable directory is missing".to_string())
        .map(|_| ())
}

/// Admitted sudo executors may read their console user's settings, never create.
pub fn canonical_root_for_user(root: &Path, expected_uid: u32) -> Result<Option<PathBuf>, String> {
    canonical_directory(root, false, true, read_owner_uid(Some(expected_uid))?)
}

fn read_owner_uid(expected_uid: Option<u32>) -> Result<u32, String> {
    let Some(expected_uid) = expected_uid else {
        return user_uid();
    };
    let real = unsafe { libc::getuid() };
    let effective = unsafe { libc::geteuid() };
    if expected_uid == 0 || real != effective || (real != 0 && real != expected_uid) {
        return Err("The saved data must belong to the admitted console user".into());
    }
    Ok(expected_uid)
}

/// Resolve existing trusted ancestors without creating a missing data-root
/// suffix. Mutation entrypoints must still acquire with_root_lock afterward.
pub fn normalized_root_path(root: &Path, expected_uid: Option<u32>) -> Result<PathBuf, String> {
    canonical_directory_at(root, false, true, read_owner_uid(expected_uid)?, 0, true)?
        .ok_or_else(|| "The data directory could not be normalized".to_string())
}

fn canonical_directory(
    root: &Path,
    create: bool,
    user_owned: bool,
    uid: u32,
) -> Result<Option<PathBuf>, String> {
    canonical_directory_at(root, create, user_owned, uid, 0, false)
}

fn system_link_allowed(parent_uid: u32, parent_mode: u32, link_uid: u32, ancestor: bool) -> bool {
    ancestor && parent_uid == 0 && parent_mode & 0o022 == 0 && link_uid == 0
}

fn canonical_directory_at(
    root: &Path,
    create: bool,
    user_owned: bool,
    uid: u32,
    links: u8,
    preserve_missing: bool,
) -> Result<Option<PathBuf>, String> {
    if links > 16 {
        return Err("Too many system directory aliases".into());
    }
    if !root.is_absolute() || root.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("The data directory must be an absolute path without '..'".into());
    }
    let mut path = PathBuf::from("/");
    let mut directory = File::open("/").map_err(|_| "Cannot open the data directory")?;
    let mut components = root
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .peekable();
    let mut saw_component = false;
    while let Some(component) = components.next() {
        saw_component = true;
        let bytes = component.as_encoded_bytes();
        if bytes.len() > 255 || bytes.contains(&0) {
            return Err("Invalid data directory component".into());
        }
        let mut name = [0u8; 256];
        name[..bytes.len()].copy_from_slice(bytes);
        let mut fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            if !create {
                if preserve_missing {
                    path.push(component);
                    for tail in components {
                        let bytes = tail.as_encoded_bytes();
                        if bytes.len() > 255 || bytes.contains(&0) {
                            return Err("Invalid data directory component".into());
                        }
                        path.push(tail);
                    }
                    return Ok(Some(path));
                }
                return Ok(None);
            }
            if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr().cast(), 0o700) } != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err("The data directory could not be created".into());
            }
            fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr().cast(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if fd < 0 {
            let mut link: libc::stat = unsafe { std::mem::zeroed() };
            let is_link = unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    name.as_ptr().cast(),
                    &mut link,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
                && link.st_mode & libc::S_IFMT == libc::S_IFLNK;
            if is_link {
                let parent = directory
                    .metadata()
                    .map_err(|_| "Cannot inspect system alias parent")?;
                if !system_link_allowed(
                    parent.uid(),
                    parent.mode(),
                    link.st_uid,
                    components.peek().is_some() || !user_owned,
                ) {
                    return Err("The data directory contains an unsafe symbolic link".into());
                }
                crate::macos_state::reject_writable_acl(&directory)?;
                let mut target = [0u8; 4096];
                let length = unsafe {
                    libc::readlinkat(
                        directory.as_raw_fd(),
                        name.as_ptr().cast(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                if length <= 0 || length as usize >= target.len() {
                    return Err("The system directory alias could not be read".into());
                }
                use std::os::unix::ffi::OsStrExt;
                let target = Path::new(std::ffi::OsStr::from_bytes(&target[..length as usize]));
                let mut redirected = if target.is_absolute() {
                    target.to_path_buf()
                } else {
                    path.join(target)
                };
                for tail in components {
                    redirected.push(tail);
                }
                let mut normalized = PathBuf::from("/");
                for component in redirected.components() {
                    match component {
                        Component::Normal(part) => normalized.push(part),
                        Component::ParentDir => {
                            let _ = normalized.pop();
                        }
                        _ => {}
                    }
                }
                return canonical_directory_at(
                    &normalized,
                    create,
                    user_owned,
                    uid,
                    links + 1,
                    preserve_missing,
                );
            }
            return Err("The data directory contains an unsafe or inaccessible component".into());
        }
        let next = unsafe { File::from_raw_fd(fd) };
        let metadata = next
            .metadata()
            .map_err(|_| "Cannot inspect the data directory")?;
        let sticky_system = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0 && !sticky_system)
            || (user_owned
                && components.peek().is_none()
                && (metadata.uid() != uid || metadata.mode() & 0o022 != 0))
        {
            return Err("The data directory has unsafe ownership or permissions".into());
        }
        crate::macos_state::reject_writable_acl(&next)?;
        path.push(component);
        directory = next;
    }
    if user_owned && !saw_component {
        return Err("The filesystem root is not an application data directory".into());
    }
    Ok(Some(path))
}

// SCM_RIGHTS duplicates share this flock: release only by closing the final
// descriptor, never by issuing LOCK_UN from an individual scope.
pub(crate) struct FileLock(File);

pub(crate) fn lock_file(path: &Path, nonblocking: bool) -> Result<Option<FileLock>, String> {
    let uid = user_uid()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Cannot open the connection coordination lock")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect the connection lock")?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("The connection lock has unsafe ownership, links or permissions".into());
    }
    crate::macos_state::reject_writable_acl(&file)?;
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
        if nonblocking && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err("Cannot acquire the connection lock".into());
    }
    Ok(Some(FileLock(file)))
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn root_lock(root: &Path, nonblocking: bool) -> Result<Option<FileLock>, String> {
    let root = canonical_root(root, true)?.ok_or("The data directory is missing")?;
    lock_file(&root.join(".operation.lock"), nonblocking)
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn try_root_lock(root: &Path) -> Result<Option<FileLock>, String> {
    root_lock(root, true)
}

thread_local! {
    static OPERATION: RefCell<Option<(PathBuf, RawFd)>> = const { RefCell::new(None) };
}

struct OperationScope;
impl Drop for OperationScope {
    fn drop(&mut self) {
        OPERATION.with(|held| {
            held.borrow_mut().take();
        });
    }
}

pub(crate) fn operation_fd(root: &Path) -> Result<Option<RawFd>, String> {
    OPERATION.with(|held| {
        let held = held.borrow();
        let Some((owned, fd)) = held.as_ref() else {
            return Ok(None);
        };
        if canonical_root(root, false)?.as_ref() != Some(owned) {
            return Err("A runtime request cannot cross data-root transactions".into());
        }
        Ok(Some(*fd))
    })
}

#[cfg(any(target_os = "macos", test))]
/// Adopt the same flock description, not a second acquisition. Closing the
/// final descriptor (including IPC duplicates) releases the operation.
pub(crate) fn adopt_operation_lock(root: &Path, file: File) -> Result<FileLock, String> {
    let expected = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(root.join(".operation.lock"))
        .map_err(|_| "The operation lock is missing")?
        .metadata()
        .map_err(|_| "The operation lock could not be inspected")?;
    let metadata = file
        .metadata()
        .map_err(|_| "The transferred operation lock could not be inspected")?;
    if !metadata.is_file()
        || metadata.uid() != user_uid()?
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.dev() != expected.dev()
        || metadata.ino() != expected.ino()
    {
        return Err("The transferred operation lock is not this root's private lock".into());
    }
    crate::macos_state::reject_writable_acl(&file)?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
    {
        return Err("The transferred operation lock could not be protected".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("The transferred operation lock is not owned by this transaction".into());
    }
    Ok(FileLock(file))
}

/// Serialize store writes with runtime stop/change/restart transactions.
/// The action must not acquire this lock recursively.
pub fn with_root_lock<T>(
    root: &Path,
    action: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    if OPERATION.with(|held| held.borrow().is_some()) {
        return Err("A root operation cannot acquire its transaction lock recursively".into());
    }
    let root = canonical_root(root, true)?.ok_or("The data directory is missing")?;
    let guard =
        lock_file(&root.join(".operation.lock"), false)?.ok_or("The operation lock is busy")?;
    OPERATION.with(|held| *held.borrow_mut() = Some((root, guard.0.as_raw_fd())));
    let _scope = OperationScope;
    action()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::{Arc, Barrier};

    #[test]
    fn absent_read_is_side_effect_free_and_aliases_share_identity() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        assert!(canonical_root(&missing, false).unwrap().is_none());
        assert!(!missing.exists());
        assert_eq!(
            canonical_root(temp.path(), false).unwrap(),
            canonical_root(&temp.path().join("."), false).unwrap()
        );
    }

    #[test]
    fn rejects_symlink_and_hardlinked_lock_and_unsafe_root() {
        let temp = tempfile::tempdir().unwrap();
        let alias = temp.path().join("alias");
        symlink(temp.path(), &alias).unwrap();
        assert!(canonical_root(&alias, false).is_err());
        let lock = temp.path().join(".operation.lock");
        std::fs::write(&lock, "").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&lock, temp.path().join("other")).unwrap();
        assert!(with_root_lock(temp.path(), || Ok(())).is_err());
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(canonical_root(temp.path(), false).is_err());
    }

    #[test]
    fn operation_lock_serializes_threads_and_try_lock_never_blocks() {
        let temp = tempfile::tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let root = temp.path().to_path_buf();
        let other = root.clone();
        let ready = barrier.clone();
        let thread = std::thread::spawn(move || {
            with_root_lock(&other, || {
                ready.wait();
                std::thread::sleep(std::time::Duration::from_millis(80));
                Ok(())
            })
            .unwrap()
        });
        barrier.wait();
        assert!(try_root_lock(&root).unwrap().is_none());
        thread.join().unwrap();
        assert!(try_root_lock(&root).unwrap().is_some());
    }
    #[test]
    fn rejects_root_and_changed_effective_identity_before_any_filesystem_access() {
        assert!(check_user_identity(0, 0).is_err());
        assert!(check_user_identity(1000, 0).is_err());
        assert!(check_user_identity(1000, 1001).is_err());
        assert_eq!(check_user_identity(1000, 1000).unwrap(), 1000);
    }
    #[test]
    fn transferred_description_keeps_operation_locked_after_client_scope_exits() {
        let temp = tempfile::tempdir().unwrap();
        let receiver = with_root_lock(temp.path(), || {
            let fd = operation_fd(temp.path())?.ok_or("Missing operation descriptor")?;
            let duplicate = unsafe { libc::dup(fd) };
            assert!(duplicate >= 0);
            adopt_operation_lock(temp.path(), unsafe { File::from_raw_fd(duplicate) })
        })
        .unwrap();
        assert!(try_root_lock(temp.path()).unwrap().is_none());
        drop(receiver);
        assert!(try_root_lock(temp.path()).unwrap().is_some());
    }

    #[test]
    fn nested_transactions_fail_without_deadlock_and_unrelated_fd_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        assert!(with_root_lock(temp.path(), || with_root_lock(temp.path(), || Ok(()))).is_err());
        assert!(try_root_lock(temp.path()).unwrap().is_some());
        let other = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp.path().join("unrelated"))
            .unwrap();
        assert!(adopt_operation_lock(temp.path(), other).is_err());
    }

    #[test]
    fn owner_aware_read_never_creates_missing_data() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("absent");
        let uid = user_uid().unwrap();
        assert!(canonical_root_for_user(&missing, uid).unwrap().is_none());
        assert!(!missing.exists());
        assert!(canonical_root_for_user(&missing, 0).is_err());
        assert!(canonical_root_for_user(&missing, uid + 1).is_err());
    }
    #[test]
    fn only_trusted_system_ancestor_links_are_admitted() {
        assert!(system_link_allowed(0, 0o755, 0, true));
        assert!(!system_link_allowed(1000, 0o700, 0, true));
        assert!(!system_link_allowed(0, 0o777, 0, true));
        assert!(!system_link_allowed(0, 0o755, 1000, true));
        assert!(!system_link_allowed(0, 0o755, 0, false));
    }

    #[test]
    fn trusted_binary_directory_resolves_system_alias_but_user_leaf_stays_strict() {
        let actual = std::fs::canonicalize("/bin").unwrap();
        assert_eq!(
            canonical_directory(Path::new("/bin"), false, false, user_uid().unwrap()).unwrap(),
            Some(actual)
        );
        let temp = tempfile::tempdir().unwrap();
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(temp.path(), &alias).unwrap();
        assert!(canonical_root(&alias, false).is_err());
        assert!(canonical_root(&alias.join("nested"), true).is_err());
        assert!(!temp.path().join("nested").exists());
    }
    #[test]
    fn normalization_preserves_missing_suffix_without_creating_it() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("new/deeper/data");
        let parent = canonical_root(temp.path(), false).unwrap().unwrap();
        assert_eq!(
            normalized_root_path(&input, None).unwrap(),
            parent.join("new/deeper/data")
        );
        assert!(!temp.path().join("new").exists());
        assert!(normalized_root_path(&input, Some(0)).is_err());
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(temp.path(), &alias).unwrap();
        assert!(normalized_root_path(&alias.join("new"), None).is_err());
    }

    #[test]
    fn normalization_resolves_system_alias_before_missing_suffix() {
        let temp = tempfile::tempdir().unwrap();
        let suffix = temp.path().file_name().unwrap();
        let input = Path::new("/bin").join(suffix).join("data");
        let expected = std::fs::canonicalize("/bin")
            .unwrap()
            .join(suffix)
            .join("data");
        assert_eq!(normalized_root_path(&input, None).unwrap(), expected);
        assert!(!Path::new("/bin").join(suffix).exists());
    }
}
