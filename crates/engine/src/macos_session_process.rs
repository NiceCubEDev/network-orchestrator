//! Protected process identity records; never signal an unverified/recycled PID.
use crate::macos_transaction;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Identity {
    executable: PathBuf,
    started_seconds: u64,
    started_fraction: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessRecord {
    profile_id: String,
    pid: u32,
    identity: Identity,
    generation: u128,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    processes: Vec<ProcessRecord>,
}

#[cfg(target_os = "macos")]
fn identity(pid: u32) -> Result<Identity, String> {
    use std::os::raw::{c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    #[repr(C)]
    struct BsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        reserved: u32,
        comm: [u8; 16],
        name: [u8; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        tdev: u32,
        tpgid: u32,
        nice: i32,
        started_seconds: u64,
        started_microseconds: u64,
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            size: c_int,
        ) -> c_int;
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, size: u32) -> c_int;
    }
    let mut info: BsdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as c_int;
    if unsafe { proc_pidinfo(pid as c_int, 3, 0, (&mut info as *mut BsdInfo).cast(), size) } != size
    {
        return Err("Cannot verify the owned Xray process start identity".into());
    }
    let mut path = [0u8; 4096];
    if unsafe { proc_pidpath(pid as c_int, path.as_mut_ptr().cast(), path.len() as u32) } <= 0 {
        return Err("Cannot verify the owned Xray executable".into());
    }
    let length = path
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("Invalid process executable identity")?;
    Ok(Identity {
        executable: PathBuf::from(std::ffi::OsStr::from_bytes(&path[..length])),
        started_seconds: info.started_seconds,
        started_fraction: info.started_microseconds,
    })
}

#[cfg(target_os = "linux")]
fn identity(pid: u32) -> Result<Identity, String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| "Cannot verify owned process identity")?;
    let fields = stat.rsplit_once(") ").ok_or("Invalid process identity")?.1;
    let ticks: u64 = fields
        .split_whitespace()
        .nth(19)
        .ok_or("Missing process start identity")?
        .parse()
        .map_err(|_| "Invalid process start identity")?;
    Ok(Identity {
        executable: fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|_| "Cannot verify process executable")?,
        started_seconds: ticks,
        started_fraction: 0,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn identity(_pid: u32) -> Result<Identity, String> {
    Err("Process identity is unsupported".into())
}

fn path(root: &Path) -> PathBuf {
    root.join("runtime/local-processes.json")
}

fn load(root: &Path) -> Result<Journal, String> {
    if macos_transaction::canonical_root(&root.join("runtime"), false)?.is_none() {
        return Ok(Journal {
            version: 1,
            processes: Vec::new(),
        });
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path(root))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Journal {
                version: 1,
                processes: Vec::new(),
            })
        }
        Err(_) => return Err("Owned process journal could not be read".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "Owned process journal could not be inspected")?;
    if !metadata.is_file()
        || metadata.uid() != macos_transaction::user_uid()?
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 64 * 1024
    {
        return Err("Owned process journal is unsafe".into());
    }
    crate::macos_state::reject_writable_acl(&file)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Owned process journal could not be read")?;
    if bytes.len() > 64 * 1024 {
        return Err("Owned process journal is too large".into());
    }
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|_| "Owned process journal is invalid")?;
    if journal.version != 1 {
        return Err("Unsupported owned process journal version".into());
    }
    Ok(journal)
}

#[cfg(target_os = "macos")]
pub(crate) fn validate(root: &Path) -> Result<(), String> {
    load(root).map(|_| ())
}

fn save(root: &Path, journal: &Journal) -> Result<(), String> {
    macos_transaction::canonical_root(&root.join("runtime"), true)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "Cannot timestamp owned process journal")?
        .as_nanos();
    let temp = root
        .join("runtime")
        .join(format!(".local-processes-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)
            .map_err(|_| "Owned process journal could not be created")?;
        crate::macos_state::reject_writable_acl(&file)?;
        let bytes = serde_json::to_vec(journal)
            .map_err(|_| "Owned process journal could not be encoded")?;
        if bytes.len() > 64 * 1024 {
            return Err("Owned process journal is too large".into());
        }
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Owned process journal could not be saved")?;
        fs::rename(&temp, path(root))
            .map_err(|_| "Owned process journal could not be committed".to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub(crate) fn record(
    root: &Path,
    profile: &str,
    pid: u32,
    executable: &Path,
) -> Result<(), String> {
    let identity = identity(pid)?;
    if identity.executable != executable {
        return Err("Owned Xray executable identity changed".into());
    }
    let mut journal = load(root)?;
    journal
        .processes
        .retain(|record| record.profile_id != profile);
    journal.processes.push(ProcessRecord {
        profile_id: profile.into(),
        pid,
        identity,
        generation: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "Cannot timestamp activation")?
            .as_nanos(),
    });
    save(root, &journal)
}

#[cfg(target_os = "macos")]
pub(crate) fn forget(root: &Path, profile: &str) -> Result<(), String> {
    let mut journal = load(root)?;
    journal
        .processes
        .retain(|record| record.profile_id != profile);
    save(root, &journal)
}

fn exited(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(") ")
                    .map(|(_, fields)| fields.starts_with('Z') || fields.starts_with('X'))
            })
            .unwrap_or(false)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::raw::{c_int, c_void};
        #[link(name = "proc")]
        unsafe extern "C" {
            fn proc_pidinfo(
                pid: c_int,
                flavor: c_int,
                arg: u64,
                buffer: *mut c_void,
                size: c_int,
            ) -> c_int;
        }
        // proc_bsdinfo begins with pbi_flags, pbi_status; SZOMB is 5.
        let mut info = [0u8; 136];
        let size = unsafe {
            proc_pidinfo(
                pid as c_int,
                3,
                0,
                info.as_mut_ptr().cast(),
                info.len() as c_int,
            )
        };
        size == info.len() as c_int && u32::from_ne_bytes([info[4], info[5], info[6], info[7]]) == 5
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        false
    }
}

fn same_process(record: &ProcessRecord) -> Result<bool, String> {
    match identity(record.pid) {
        Ok(found) => Ok(found == record.identity),
        Err(error) => {
            if exited(record.pid)
                || (unsafe { libc::kill(record.pid as libc::pid_t, 0) } != 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
            {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

fn wait_for_exit(record: &ProcessRecord) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // An exiting process can lose its executable before the kernel reaps it.
        let same = same_process(record);
        if matches!(&same, Ok(false)) {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return same.map(|alive| !alive);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn recover(root: &Path, executable: &Path) -> Result<(), String> {
    let journal = load(root)?;
    for record in &journal.processes {
        if record.pid <= 1 || record.pid > i32::MAX as u32 {
            return Err("Owned process journal contains an invalid process identifier".into());
        }
        if record.identity.executable != executable {
            continue;
        }
        if !same_process(record)? {
            continue;
        }
        if unsafe { libc::kill(record.pid as libc::pid_t, libc::SIGTERM) } != 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err("The owned Xray process could not be stopped".into());
        }
        if !wait_for_exit(record)? && same_process(record)? {
            if unsafe { libc::kill(record.pid as libc::pid_t, libc::SIGKILL) } != 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err("The owned Xray process could not be stopped".into());
            }
            if !wait_for_exit(record)? {
                return Err(
                    "The owned Xray process has not exited; recovery record retained".into(),
                );
            }
        }
    }
    save(
        root,
        &Journal {
            version: 1,
            processes: Vec::new(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recycled_or_unapproved_process_is_never_signalled() {
        let temp = tempfile::tempdir().unwrap();
        let pid = std::process::id();
        let mut wrong_start = identity(pid).unwrap();
        wrong_start.started_fraction = wrong_start.started_fraction.wrapping_add(1);
        let executable = wrong_start.executable.clone();
        save(
            temp.path(),
            &Journal {
                version: 1,
                processes: vec![ProcessRecord {
                    profile_id: "p".into(),
                    pid,
                    identity: wrong_start,
                    generation: 1,
                }],
            },
        )
        .unwrap();
        recover(temp.path(), &executable).unwrap();
        assert!(identity(pid).is_ok());
        assert!(load(temp.path()).unwrap().processes.is_empty());
    }
    #[test]
    fn malformed_journal_is_retained_for_recovery() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("runtime")).unwrap();
        fs::write(path(temp.path()), "invalid").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path(temp.path()), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(recover(temp.path(), Path::new("/not-xray")).is_err());
        assert_eq!(fs::read_to_string(path(temp.path())).unwrap(), "invalid");
    }
    #[test]
    fn verified_owned_child_is_stopped_and_journal_cleared() {
        let temp = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = child.id();
        let executable = identity(pid).unwrap().executable;
        if let Err(error) = record(temp.path(), "p", pid, &executable) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{error}");
        }
        let reaper = std::thread::spawn(move || child.wait().unwrap());
        recover(temp.path(), &executable).unwrap();
        assert!(!reaper.join().unwrap().success());
        assert!(load(temp.path()).unwrap().processes.is_empty());
    }
}
