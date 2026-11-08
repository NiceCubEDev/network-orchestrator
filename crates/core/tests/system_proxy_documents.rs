#![cfg(unix)]

use net_manager_core::system_proxy::{
    load_ownership, ProxyAdapter, ProxySnapshot, SystemProxyManager,
};
use std::{fs, io, os::unix::fs::PermissionsExt};

struct Desktop;
impl ProxyAdapter for Desktop {
    fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
        Ok(ProxySnapshot::default())
    }
    fn apply(&mut self, _: &str, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn restore(&mut self, _: &ProxySnapshot) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_stale_temporary_symlink_cannot_overwrite_an_unrelated_file() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("system-proxy.json");
    let victim = directory.path().join("unrelated");
    fs::write(&victim, b"keep this file").unwrap();
    std::os::unix::fs::symlink(&victim, directory.path().join("system-proxy.json.tmp")).unwrap();
    let mut manager = SystemProxyManager::with_adapter(&state, Box::new(Desktop)).unwrap();
    manager.apply("profile", 1080, &[]).unwrap();
    assert_eq!(fs::read(&victim).unwrap(), b"keep this file");
    assert_eq!(
        load_ownership(&state).unwrap().unwrap().profile_id,
        "profile"
    );
}

#[test]
fn linked_state_is_rejected_without_changing_the_target_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let victim = directory.path().join("unrelated.json");
    fs::write(&victim, br#"{"version":1,"ownership":null}"#).unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
    let state = directory.path().join("system-proxy.json");
    std::os::unix::fs::symlink(&victim, &state).unwrap();
    assert!(SystemProxyManager::with_adapter(&state, Box::new(Desktop)).is_err());
    assert!(load_ownership(&state).is_err());
    assert_eq!(
        fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::read(&victim).unwrap(),
        br#"{"version":1,"ownership":null}"#
    );
}

#[test]
fn proxy_state_reads_reject_hardlinks_pipes_and_oversized_documents() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("source.json");
    fs::write(&target, br#"{"version":1,"ownership":null}"#).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let state = directory.path().join("system-proxy.json");
    fs::hard_link(&target, &state).unwrap();
    assert!(load_ownership(&state).is_err());
    fs::remove_file(&state).unwrap();
    let path = std::ffi::CString::new(state.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(load_ownership(&state).is_err());
    fs::remove_file(&state).unwrap();
    fs::File::create(&state)
        .unwrap()
        .set_len(2 * 1024 * 1024)
        .unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_ownership(&state).is_err());
}
