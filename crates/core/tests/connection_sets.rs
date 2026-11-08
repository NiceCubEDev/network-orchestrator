#![cfg(unix)]

use net_manager_core::{connection_sets as sets, profiles::ProfileStore};

fn saved(id: &str, name: &str, members: &[&str]) -> sets::ConnectionSet {
    sets::ConnectionSet {
        id: id.into(),
        name: name.into(),
        profile_ids: members.iter().map(|id| (*id).into()).collect(),
    }
}

#[test]
fn legacy_sets_import_once_preserves_edits_deletions_and_missing_members() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let legacy = vec![saved("old", "Legacy", &["missing-profile"])];
    let imported = sets::import_legacy_once(root, legacy.clone()).unwrap();
    assert_eq!(imported, legacy);
    assert_eq!(
        sets::missing_members(&imported[0], &[]),
        ["missing-profile"]
    );

    let store = ProfileStore::new(root.join("profiles.json"));
    let edited = saved("old", "Edited", &[]);
    sets::put(root, &store, edited.clone()).unwrap();
    assert_eq!(
        sets::import_legacy_once(root, legacy.clone()).unwrap(),
        [edited]
    );

    sets::delete(root, "old").unwrap();
    let current = saved("current", "Current", &[]);
    sets::put(root, &store, current.clone()).unwrap();
    assert_eq!(sets::import_legacy_once(root, legacy).unwrap(), [current]);
}

#[test]
fn rejected_legacy_batch_does_not_mark_migration_complete() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let first = saved("first", "First", &[]);
    let invalid = saved("../escape", "Invalid", &[]);
    assert!(sets::import_legacy_once(root, vec![first.clone(), invalid]).is_err());
    assert!(sets::list(root).unwrap().is_empty());
    assert_eq!(
        sets::import_legacy_once(root, vec![first.clone()]).unwrap(),
        [first]
    );
}

#[test]
fn explicit_import_remains_insert_only_after_native_migration() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let original = saved("same", "Original", &[]);
    sets::import_legacy_once(root, vec![original.clone()]).unwrap();
    let other = saved("other", "Other", &[]);
    let imported = sets::import(root, vec![saved("same", "Stale", &[]), other.clone()]).unwrap();
    assert_eq!(imported, [original, other]);
    assert_eq!(
        sets::import_legacy_once(root, vec![saved("late", "Late", &[])]).unwrap(),
        imported
    );
}

#[test]
fn listing_an_absent_store_does_not_create_the_data_directory() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("absent");
    assert!(sets::list(&root).unwrap().is_empty());
    assert!(!root.exists());
}
