#![cfg(unix)]

use base64::Engine;
use net_manager_core::{geo_assets, models::Profile};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn fixture() -> (tempfile::TempDir, Profile, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let profile = Profile {
        xray_geoip_url: Some("https://geo.invalid/geoip.dat".into()),
        ..Profile::default()
    };
    let cache =
        geo_assets::profile_asset_dir(directory.path(), profile.xray_geoip_url.as_deref(), None);
    fs::create_dir(&cache).unwrap();
    (directory, profile, cache)
}

#[test]
fn cached_transport_works_from_read_only_files_without_creating_an_overlay() {
    let (directory, profile, cache) = fixture();
    let asset = cache.join("geoip.dat");
    fs::write(&asset, b"synthetic geo data").unwrap();
    fs::set_permissions(&asset, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o500)).unwrap();
    let result = geo_assets::cached_protocol_geo_assets(directory.path(), &profile, unsafe {
        libc::geteuid()
    })
    .unwrap()
    .unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(result.geoip_dat_b64.unwrap())
            .unwrap(),
        b"synthetic geo data"
    );
    assert!(result.geosite_dat_b64.is_none());
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 1);
}

#[test]
fn missing_configured_cache_is_not_silently_replaced_by_stock_data() {
    let (directory, profile, _) = fixture();
    assert!(
        geo_assets::cached_protocol_geo_assets(directory.path(), &profile, unsafe {
            libc::geteuid()
        })
        .is_err()
    );
    let absent = directory.path().join("not-created");
    assert!(
        geo_assets::cached_protocol_geo_assets(&absent, &Profile::default(), unsafe {
            libc::geteuid()
        })
        .unwrap()
        .is_none()
    );
    assert!(!absent.exists());
}

#[test]
fn cached_transport_rejects_links_pipes_oversize_and_wrong_owner_identity() {
    let (directory, profile, cache) = fixture();
    let source = directory.path().join("source");
    fs::write(&source, b"synthetic").unwrap();
    let asset = cache.join("geoip.dat");
    let uid = unsafe { libc::geteuid() };
    std::os::unix::fs::symlink(&source, &asset).unwrap();
    assert!(geo_assets::cached_protocol_geo_assets(directory.path(), &profile, uid).is_err());
    fs::remove_file(&asset).unwrap();
    fs::hard_link(&source, &asset).unwrap();
    assert!(geo_assets::cached_protocol_geo_assets(directory.path(), &profile, uid).is_err());
    fs::remove_file(&asset).unwrap();
    let path = std::ffi::CString::new(asset.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(geo_assets::cached_protocol_geo_assets(directory.path(), &profile, uid).is_err());
    fs::remove_file(&asset).unwrap();
    fs::File::create(&asset)
        .unwrap()
        .set_len(geo_assets::MAX_GEO_ASSET_BYTES as u64 + 1)
        .unwrap();
    assert!(geo_assets::cached_protocol_geo_assets(directory.path(), &profile, uid).is_err());
    fs::write(&asset, b"synthetic").unwrap();
    assert!(geo_assets::cached_protocol_geo_assets(
        directory.path(),
        &profile,
        uid.wrapping_add(1)
    )
    .is_err());
    assert!(geo_assets::cached_protocol_geo_assets(directory.path(), &profile, 0).is_err());
}
