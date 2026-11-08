use super::{owner_locks, Client};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Inspect,
    Bootout,
    Bootstrap,
}

/// A loaded launchd job caches its arguments and environment. Replacing its
/// plist is insufficient: only an ownerless registration may be reloaded.
pub(super) fn register(
    client: &Client,
    root: &Path,
    write_plist: impl FnOnce() -> Result<(), String>,
    mut run: impl FnMut(Action) -> Result<bool, String>,
) -> Result<(), String> {
    if client.attach(false)?.is_some() {
        return Ok(());
    }
    // Also excludes a launchd/manual owner that is starting but not yet listening.
    // Keep both lifetime/cutover locks through bootout, never kill a live owner.
    let ownership = owner_locks(root)?;
    write_plist()?;
    if run(Action::Inspect)? && !run(Action::Bootout)? {
        return Err("Cannot unload the stale launchd user registration".into());
    }
    // The newly bootstrapped process must be able to acquire its lifetime locks.
    drop(ownership);
    if !run(Action::Bootstrap)? {
        return Err("launchd refused the connection user service".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_session::{Backend, Operation, Outcome, TestServer};
    use std::cell::RefCell;

    struct Idle;
    impl Backend for Idle {
        fn execute(&mut self, _: Operation) -> Result<Outcome, String> {
            Err("No operations are expected during launchd admission".into())
        }
        fn reap(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn shutdown(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn live_authenticated_owner_never_rewrites_or_unloads_registration() {
        let root = tempfile::tempdir().unwrap();
        let server = TestServer::start(root.path(), Idle);
        register(
            &server.client(),
            root.path(),
            || panic!("must not replace a live owner's plist"),
            |_| panic!("must not control a live owner's launchd job"),
        )
        .unwrap();
    }

    #[test]
    fn starting_owner_lifetime_lock_prevents_registration_changes() {
        let root = tempfile::tempdir().unwrap();
        let _owner = owner_locks(root.path()).unwrap();
        let client = Client::new(root.path().into(), root.path().join("helper.sock"));
        assert!(register(
            &client,
            root.path(),
            || panic!("must not rewrite while an owner starts"),
            |_| panic!("must not bootout while an owner starts"),
        )
        .is_err());
    }

    #[test]
    fn stale_cached_registration_is_removed_under_lifetime_lock_then_rebootstrapped() {
        for present in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let client = Client::new(root.path().into(), root.path().join("helper.sock"));
            let calls = RefCell::new(Vec::new());
            register(
                &client,
                root.path(),
                || {
                    assert!(owner_locks(root.path()).is_err());
                    Ok(())
                },
                |action| {
                    calls.borrow_mut().push(action);
                    if action == Action::Bootstrap {
                        assert!(owner_locks(root.path()).is_ok());
                    } else {
                        assert!(owner_locks(root.path()).is_err());
                    }
                    Ok(action != Action::Inspect || present)
                },
            )
            .unwrap();
            let expected = if present {
                vec![Action::Inspect, Action::Bootout, Action::Bootstrap]
            } else {
                vec![Action::Inspect, Action::Bootstrap]
            };
            assert_eq!(*calls.borrow(), expected);
        }
    }

    #[test]
    fn failed_bootout_never_bootstraps_over_stale_registration() {
        let root = tempfile::tempdir().unwrap();
        let client = Client::new(root.path().into(), root.path().join("helper.sock"));
        assert!(register(
            &client,
            root.path(),
            || Ok(()),
            |action| match action {
                Action::Inspect => Ok(true),
                Action::Bootout => Ok(false),
                Action::Bootstrap => panic!("failed bootout must stop registration replacement"),
            }
        )
        .is_err());
        assert!(owner_locks(root.path()).is_ok());
    }
    #[test]
    fn helper_handshake_mismatch_cannot_replace_loaded_registration() {
        let root = tempfile::tempdir().unwrap();
        let server = TestServer::start(root.path(), Idle);
        let mut client = server.client();
        client.helper = root.path().join("different-helper.sock");
        assert!(register(
            &client,
            root.path(),
            || panic!("must not rewrite after a helper handshake mismatch"),
            |_| panic!("must not unload an incompatible live owner"),
        )
        .is_err());
    }
}
