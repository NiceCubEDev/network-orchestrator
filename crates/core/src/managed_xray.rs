use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const MANAGED_XRAY_VERSION: &str = "v26.7.28";
pub const MANAGED_XRAY_URL: &str =
    "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-windows-64.zip";
pub const MANAGED_XRAY_SHA256: &str =
    "c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1";
pub const MAX_XRAY_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

const MAX_XRAY_ENTRY_BYTES: u64 = 48 * 1024 * 1024;
const MAX_XRAY_TOTAL_BYTES: u64 = 96 * 1024 * 1024;
const ALLOWLIST: [&str; 7] = [
    "xray.exe",
    "geoip.dat",
    "geosite.dat",
    "LICENSE",
    "README.md",
    "wintun.dll",
    "LICENSE-Wintun",
];
const REQUIRED: [&str; 3] = ["xray.exe", "geoip.dat", "geosite.dat"];
const REQUIRED_SHA256: [(&str, &str); 3] = [
    (
        "xray.exe",
        "1d9674327972a21afd4c906a7a72bb0856935aa9e0227c87f34f03d11a88bddf",
    ),
    (
        "geoip.dat",
        "cdf411fce977a1f48adb6a3b224e3e2bd7eccfcd4d6e2e30c6dc443f1a0e8e52",
    ),
    (
        "geosite.dat",
        "ea8d817c4782a84db4104ba416329bb14024f69568c666f5cca6c4303ef1942e",
    ),
];

const WINDOWS_TUN_SHA256: [(&str, &str); 2] = [
    (
        "wintun.dll",
        "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
    ),
    (
        "LICENSE-Wintun",
        "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2",
    ),
];

#[derive(Clone, Copy)]
struct ArchiveLayout {
    version: &'static str,
    executable_name: &'static str,
    allowlist: &'static [&'static str],
    required_names: &'static [&'static str],
}

const WINDOWS_LAYOUT: ArchiveLayout = ArchiveLayout {
    version: MANAGED_XRAY_VERSION,
    executable_name: "xray.exe",
    allowlist: &ALLOWLIST,
    required_names: &REQUIRED,
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_XRAY_VERSION: &str = "v26.10.31";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_XRAY_PACKAGE_ROOT: &str = "/usr/lib/network-orchestrator/xray";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_XRAY_URL: &str =
    "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip";
// Official XTLS release asset Xray-linux-64.zip.dgst, SHA2-256.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_XRAY_SHA256: &str =
    "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_ALLOWLIST: [&str; 5] = ["xray", "geoip.dat", "geosite.dat", "LICENSE", "README.md"];
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_REQUIRED: [&str; 3] = ["xray", "geoip.dat", "geosite.dat"];
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_LAYOUT: ArchiveLayout = ArchiveLayout {
    version: LINUX_XRAY_VERSION,
    executable_name: "xray",
    allowlist: &LINUX_ALLOWLIST,
    required_names: &LINUX_REQUIRED,
};
// SHA-256 of required files extracted from the archive above.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_REQUIRED_SHA256: [(&str, &str); 3] = [
    (
        "xray",
        "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
    ),
    (
        "geoip.dat",
        "ce90dc02a81528109c99d769e1f8fe3071ded6b02a574f31e62d8f4eee312563",
    ),
    (
        "geosite.dat",
        "9ee94acb06e2f795831fb1589c0dc7af9242b0fb8d9196afd981b915b1097ed3",
    ),
];

#[cfg(unix)]
pub const MACOS_XRAY_VERSION: &str = MANAGED_XRAY_VERSION;
#[cfg(unix)]
pub const MACOS_XRAY_URL: &str =
    "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-macos-arm64-v8a.zip";
// Official XTLS release asset Xray-macos-arm64-v8a.zip.dgst, SHA2-256.
#[cfg(unix)]
pub const MACOS_XRAY_SHA256: &str =
    "9b99a351febe31b7e0c7f22deeb1577a1da0b98aaa51aec7fd17832e68cf63d6";
#[cfg(unix)]
const MACOS_ALLOWLIST: [&str; 5] = ["xray", "geoip.dat", "geosite.dat", "LICENSE", "README.md"];
#[cfg(unix)]
const MACOS_REQUIRED: [&str; 3] = ["xray", "geoip.dat", "geosite.dat"];
#[cfg(unix)]
const MACOS_LAYOUT: ArchiveLayout = ArchiveLayout {
    version: MACOS_XRAY_VERSION,
    executable_name: "xray",
    allowlist: &MACOS_ALLOWLIST,
    required_names: &MACOS_REQUIRED,
};
// SHA-256 of required files extracted from the archive above; the .dat assets
// are byte-identical to the Windows package of the same release.
#[cfg(unix)]
pub const MACOS_REQUIRED_SHA256: [(&str, &str); 3] = [
    (
        "xray",
        "bd4154efa640c5b8e21f10b68afcc9177c4f1f543be3ec0485b10c499b2a4b27",
    ),
    (
        "geoip.dat",
        "cdf411fce977a1f48adb6a3b224e3e2bd7eccfcd4d6e2e30c6dc443f1a0e8e52",
    ),
    (
        "geosite.dat",
        "ea8d817c4782a84db4104ba416329bb14024f69568c666f5cca6c4303ef1942e",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedXrayInstallation {
    pub executable: PathBuf,
    pub version_dir: PathBuf,
    pub created: bool,
}

pub fn managed_version_dir(root: &Path) -> PathBuf {
    root.join(MANAGED_XRAY_VERSION)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn linux_managed_version_dir(root: &Path) -> PathBuf {
    root.join(LINUX_XRAY_VERSION)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn verify_managed_linux_executable(root: &Path, executable: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(invalid_data("managed xray installation contains a symlink"));
    }
    let root = root.canonicalize()?;
    let expected_dir = linux_managed_version_dir(&root);
    if executable.canonicalize()? != expected_dir.join("xray") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable is outside the managed xray installation",
        ));
    }
    for name in LINUX_REQUIRED {
        if fs::symlink_metadata(expected_dir.join(name))?
            .file_type()
            .is_symlink()
        {
            return Err(invalid_data("managed xray installation contains a symlink"));
        }
    }
    verify_required_hashes(&expected_dir, &LINUX_REQUIRED_SHA256)?;
    let executable_metadata = fs::symlink_metadata(expected_dir.join("xray"))?;
    let mode = executable_metadata.permissions().mode() & 0o777;
    if mode == 0o700 {
        return Ok(());
    }
    if !package_executable_mode_allowed(mode, executable_metadata.uid()) {
        return Err(invalid_data(
            "managed xray executable has unsafe permissions",
        ));
    }
    for name in LINUX_REQUIRED {
        verify_root_owned_readonly_path(&expected_dir.join(name))?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn package_executable_mode_allowed(mode: u32, uid: u32) -> bool {
    mode == 0o755 && uid == 0
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn verify_root_owned_readonly_path(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for component in path.ancestors() {
        let metadata = fs::symlink_metadata(component)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(invalid_data(
                "managed xray package path is not root-owned and read-only",
            ));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn install_verified_linux_archive(
    root: &Path,
    archive: &[u8],
) -> io::Result<ManagedXrayInstallation> {
    install_archive_for_platform(
        root,
        archive,
        LINUX_XRAY_SHA256,
        &LINUX_REQUIRED_SHA256,
        LINUX_LAYOUT,
    )
}

/// Drop a present-but-unverified Linux version tree (e.g. the empty
/// directory a removed distro package leaves behind) so a fresh install is
/// not blocked by `AlreadyExists`. Hash-verified trees and missing paths
/// are left alone; a stray symlink or file is unlinked, never followed.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn remove_incomplete_linux_version(root: &Path) -> io::Result<()> {
    remove_incomplete_version_dir(&linux_managed_version_dir(root), &LINUX_REQUIRED_SHA256)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn remove_incomplete_version_dir(
    version_dir: &Path,
    expected_required: &[(&str, &str)],
) -> io::Result<()> {
    match fs::symlink_metadata(version_dir) {
        Ok(metadata) if metadata.is_dir() => {
            if version_verified(version_dir, expected_required) {
                return Ok(());
            }
            fs::remove_dir_all(version_dir)
        }
        Ok(_) => fs::remove_file(version_dir),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Remove the managed Linux version tree entirely (`xray.remove`).
/// Returns whether anything was deleted.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn remove_linux_version(root: &Path) -> io::Result<bool> {
    let version_dir = linux_managed_version_dir(root);
    match fs::symlink_metadata(&version_dir) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&version_dir)?,
        Ok(_) => fs::remove_file(&version_dir)?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    }
    Ok(true)
}

/// Relax a fresh install to distro-package permissions: directories and the
/// executable become `0755`, data files `0644`. The installer runs as root
/// so files stay root-owned — `verify_managed_linux_executable` accepts the
/// package layout, and the binary is additionally usable by unprivileged
/// user-space (SOCKS/HTTP) mode.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn relax_linux_package_permissions(root: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let version_dir = linux_managed_version_dir(root);
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(&version_dir, fs::Permissions::from_mode(0o755))?;
    for entry in fs::read_dir(&version_dir)? {
        let path = entry?.path();
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            continue;
        }
        let mode = if path.file_name() == Some(std::ffi::OsStr::new("xray")) {
            0o755
        } else {
            0o644
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(unix)]
pub fn macos_managed_version_dir(root: &Path) -> PathBuf {
    root.join(MACOS_XRAY_VERSION)
}

/// Accept only the pinned macOS executable inside the per-user managed root:
/// no symlinks, owner-only executable, every required file hash-verified.
#[cfg(unix)]
pub fn verify_managed_macos_executable(root: &Path, executable: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(invalid_data("managed xray installation contains a symlink"));
    }
    let root = root.canonicalize()?;
    let expected_dir = macos_managed_version_dir(&root);
    if executable.canonicalize()? != expected_dir.join("xray") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable is outside the managed xray installation",
        ));
    }
    for name in MACOS_REQUIRED {
        if fs::symlink_metadata(expected_dir.join(name))?
            .file_type()
            .is_symlink()
        {
            return Err(invalid_data("managed xray installation contains a symlink"));
        }
    }
    let mode = fs::metadata(expected_dir.join("xray"))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(invalid_data(
            "managed xray executable has unsafe permissions",
        ));
    }
    verify_required_hashes(&expected_dir, &MACOS_REQUIRED_SHA256)
}

#[cfg(unix)]
pub fn install_verified_macos_archive(
    root: &Path,
    archive: &[u8],
) -> io::Result<ManagedXrayInstallation> {
    install_archive_for_platform(
        root,
        archive,
        MACOS_XRAY_SHA256,
        &MACOS_REQUIRED_SHA256,
        MACOS_LAYOUT,
    )
}

/// Download a pinned archive into memory with a hard size cap. Slow links are
/// fine; only a stalled connection (no bytes for 30 s) aborts. Integrity is
/// enforced afterwards by the hash-checking installer.
pub async fn download_archive(url: &str) -> io::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(20))
        .read_timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("Network-Orchestrator/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .build()
        .map_err(io::Error::other)?;
    let mut response = client
        .get(url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|_| io::Error::other("managed Xray download failed"))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_XRAY_ARCHIVE_BYTES as u64)
    {
        return Err(invalid_data("managed Xray archive is larger than allowed"));
    }
    let mut buffer = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| io::Error::other("managed Xray download failed"))?
    {
        if buffer.len() + chunk.len() > MAX_XRAY_ARCHIVE_BYTES {
            return Err(invalid_data("managed Xray archive is larger than allowed"));
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

pub fn is_managed_executable(root: &Path, executable: &Path) -> io::Result<bool> {
    let root = root.canonicalize()?;
    let executable = executable.canonicalize()?;
    Ok(executable == managed_version_dir(&root).join("xray.exe"))
}

pub fn is_managed_executable_location(root: &Path, executable: &Path) -> io::Result<bool> {
    let root = root.canonicalize()?;
    let version = managed_version_dir(&root).canonicalize()?;
    if executable.file_name() != Some(std::ffi::OsStr::new("xray.exe")) {
        return Ok(false);
    }
    let Some(parent) = executable.parent() else {
        return Ok(false);
    };
    Ok(parent.canonicalize()? == version)
}

pub fn verify_managed_executable(root: &Path, executable: &Path) -> io::Result<()> {
    let root = root.canonicalize()?;
    let executable = executable.canonicalize()?;
    let expected_dir = managed_version_dir(&root);
    if executable != expected_dir.join("xray.exe") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable is outside the managed xray installation",
        ));
    }
    verify_required_hashes(&expected_dir, &REQUIRED_SHA256)
}

/// Verify the bundled Wintun payload beside the selected executable before
/// Windows TUN startup. Legacy SOCKS-only installs remain valid independently.
pub fn verify_windows_tun_support(executable: &Path) -> io::Result<()> {
    let directory = executable
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty());
    if directory.is_some_and(|directory| {
        WINDOWS_TUN_SHA256
            .iter()
            .all(|(name, hash)| windows_tun_file_verified(directory, name, hash))
    }) {
        Ok(())
    } else {
        Err(invalid_data(
            "Windows TUN support is missing or failed integrity verification; install managed Xray again in Settings",
        ))
    }
}

pub fn install_verified_archive(
    root: &Path,
    archive: &[u8],
) -> io::Result<ManagedXrayInstallation> {
    install_archive_with_expected_hash(
        root,
        archive,
        MANAGED_XRAY_SHA256,
        &REQUIRED_SHA256,
        &WINDOWS_TUN_SHA256,
    )
}

fn install_archive_with_expected_hash(
    root: &Path,
    archive: &[u8],
    expected_hash: &str,
    expected_required: &[(&str, &str)],
    expected_tun: &[(&str, &str)],
) -> io::Result<ManagedXrayInstallation> {
    if !expected_tun.is_empty() && root.join(MANAGED_XRAY_VERSION).is_dir() {
        // Verify the legacy executable/assets and the whole pinned archive first.
        // Only missing, independently verified TUN files may be added afterwards.
        let installed = install_archive_for_platform(
            root,
            archive,
            expected_hash,
            expected_required,
            WINDOWS_LAYOUT,
        )?;
        complete_windows_tun_package(&installed.version_dir, archive, expected_tun)?;
        return Ok(installed);
    }
    let required: Vec<_> = expected_required
        .iter()
        .chain(expected_tun)
        .copied()
        .collect();
    install_archive_for_platform(root, archive, expected_hash, &required, WINDOWS_LAYOUT)
}

fn windows_tun_file_verified(directory: &Path, name: &str, expected_hash: &str) -> bool {
    fs::symlink_metadata(directory.join(name))
        .is_ok_and(|metadata| metadata.len() <= MAX_XRAY_ENTRY_BYTES)
        && version_verified(directory, &[(name, expected_hash)])
}

fn complete_windows_tun_package(
    directory: &Path,
    archive: &[u8],
    expected: &[(&str, &str)],
) -> io::Result<()> {
    if fs::symlink_metadata(directory)?.file_type().is_symlink() {
        return Err(invalid_data("managed Xray directory must not be a symlink"));
    }
    // Never overwrite an unrecognised file, including a symlink or directory.
    for (name, hash) in expected {
        match fs::symlink_metadata(directory.join(name)) {
            Ok(_) if !windows_tun_file_verified(directory, name, hash) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("managed Xray TUN file '{name}' failed verification; remove it explicitly before reinstalling"),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let names: Vec<_> = expected.iter().map(|(name, _)| *name).collect();
    let central = allowlisted_central_names(archive, &names)?;
    let mut reader = zip::ZipArchive::new(std::io::Cursor::new(archive)).map_err(invalid_data)?;
    let mut payloads = Vec::new();
    for (name, hash) in expected {
        if central
            .iter()
            .filter(|entry| entry.as_str() == *name)
            .count()
            != 1
        {
            return Err(invalid_data(
                "archive has missing or duplicate Windows TUN files",
            ));
        }
        let entry = reader.by_name(name).map_err(invalid_data)?;
        if !entry.is_file()
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            || entry.size() > MAX_XRAY_ENTRY_BYTES
        {
            return Err(invalid_data("archive contains an invalid Windows TUN file"));
        }
        let declared_size = entry.size();
        let mut bytes = Vec::new();
        entry
            .take(MAX_XRAY_ENTRY_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != declared_size || sha256_hex(&bytes) != *hash {
            return Err(invalid_data(
                "archive Windows TUN file failed integrity verification",
            ));
        }
        payloads.push((*name, *hash, bytes));
    }
    for (name, hash, bytes) in payloads {
        let target = directory.join(name);
        if !windows_tun_file_verified(directory, name, hash) {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let temporary = directory.join(format!(".{name}.tmp-{}-{nanos}", std::process::id()));
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            let result = (|| {
                file.write_all(&bytes)?;
                file.sync_all()?;
                drop(file);
                crate::config_security::protect_path(&temporary)?;
                // Hard-link publication is atomic and cannot replace a file that
                // appeared concurrently. Both names stay on the same volume.
                match fs::hard_link(&temporary, &target) {
                    Ok(()) => Ok(()),
                    Err(_) if windows_tun_file_verified(directory, name, hash) => Ok(()),
                    Err(error) => Err(error),
                }
            })();
            let _ = fs::remove_file(&temporary);
            result?;
        }
        crate::config_security::protect_path(&target)?;
    }
    Ok(())
}

fn install_archive_for_platform(
    root: &Path,
    archive: &[u8],
    expected_hash: &str,
    expected_required: &[(&str, &str)],
    layout: ArchiveLayout,
) -> io::Result<ManagedXrayInstallation> {
    let ArchiveLayout {
        version,
        executable_name,
        allowlist,
        required_names,
    } = layout;
    if archive.len() > MAX_XRAY_ARCHIVE_BYTES {
        return Err(invalid_input(format!(
            "archive exceeds the {} byte download limit",
            MAX_XRAY_ARCHIVE_BYTES
        )));
    }
    let actual = format!("{:x}", Sha256::digest(archive));
    if actual != expected_hash {
        return Err(invalid_data(
            "archive sha-256 does not match the pinned digest",
        ));
    }
    let final_dir = root.join(version);
    let executable = final_dir.join(executable_name);
    if final_dir.is_dir() {
        if version_verified(&final_dir, expected_required) {
            protect_version_tree(root, &final_dir, required_names, executable_name)?;
            return Ok(ManagedXrayInstallation {
                executable,
                version_dir: final_dir,
                created: false,
            });
        }
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "managed xray directory '{}' exists but is incomplete; remove it explicitly before reinstalling",
                version
            ),
        ));
    }

    let mut seen_names = std::collections::HashSet::new();
    for name in allowlisted_central_names(archive, allowlist)? {
        if !seen_names.insert(name.clone()) {
            return Err(invalid_data(format!(
                "archive contains a duplicate entry '{name}'"
            )));
        }
    }

    let mut archive_reader =
        zip::ZipArchive::new(std::io::Cursor::new(archive)).map_err(invalid_data)?;
    let mut selected: HashMap<String, usize> = HashMap::new();
    let mut total: u64 = 0;
    for index in 0..archive_reader.len() {
        let entry = archive_reader.by_index(index).map_err(invalid_data)?;
        if !entry.is_file() || !allowlist.contains(&entry.name()) {
            continue;
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(invalid_data("archive contains a symlink"));
        }
        if selected.insert(entry.name().to_string(), index).is_some() {
            return Err(invalid_data(format!(
                "archive contains a duplicate entry '{}'",
                entry.name()
            )));
        }
        if entry.size() > MAX_XRAY_ENTRY_BYTES {
            return Err(invalid_data(format!(
                "archive entry '{}' exceeds the {} byte limit",
                entry.name(),
                MAX_XRAY_ENTRY_BYTES
            )));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_XRAY_TOTAL_BYTES {
            return Err(invalid_data(format!(
                "archive entries exceed the {} byte total limit",
                MAX_XRAY_TOTAL_BYTES
            )));
        }
    }
    for required in required_names {
        if !selected.contains_key(*required) {
            return Err(invalid_data(format!(
                "archive is missing required entry '{required}'"
            )));
        }
    }

    fs::create_dir_all(root)?;
    crate::config_security::protect_path(root)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let staging = root.join(format!("{version}.tmp-{}-{nanos}", std::process::id()));
    let outcome = (|| {
        fs::create_dir(&staging)?;
        crate::config_security::protect_path(&staging)?;
        for (name, index) in &selected {
            let mut entry = archive_reader.by_index(*index).map_err(invalid_data)?;
            let declared_size = entry.size();
            let target = staging.join(name);
            let mut limited = (&mut entry).take(MAX_XRAY_ENTRY_BYTES + 1);
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)?;
            let written = io::copy(&mut limited, &mut output)?;
            drop(output);
            if written != declared_size {
                return Err(invalid_data(format!(
                    "archive entry '{name}' did not match its declared size"
                )));
            }
            crate::config_security::protect_path(&target)?;
        }
        verify_required_hashes(&staging, expected_required)?;
        protect_version_tree(root, &staging, required_names, executable_name)?;
        match fs::rename(&staging, &final_dir) {
            Ok(()) => Ok(ManagedXrayInstallation {
                executable,
                version_dir: final_dir,
                created: true,
            }),
            Err(err) => {
                if version_verified(&final_dir, expected_required) {
                    protect_version_tree(root, &final_dir, required_names, executable_name)?;
                    Ok(ManagedXrayInstallation {
                        executable,
                        version_dir: final_dir,
                        created: false,
                    })
                } else {
                    Err(err)
                }
            }
        }
    })();
    if outcome.is_err() || staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    outcome
}

fn allowlisted_central_names(archive: &[u8], allowlist: &[&str]) -> io::Result<Vec<String>> {
    let scan_from = archive.len().saturating_sub(22 + 65_535);
    let mut eocd = None;
    for pos in (scan_from..archive.len().saturating_sub(21)).rev() {
        if archive[pos..pos + 4] == [0x50, 0x4b, 0x05, 0x06] {
            let comment_len =
                u16::from_le_bytes(archive[pos + 20..pos + 22].try_into().unwrap()) as usize;
            if pos + 22 + comment_len == archive.len() {
                eocd = Some(pos);
                break;
            }
        }
    }
    let eocd = eocd.ok_or_else(|| invalid_data("archive end-of-central-directory not found"))?;
    let records = u16::from_le_bytes(archive[eocd + 10..eocd + 12].try_into().unwrap()) as usize;
    let mut pos = u32::from_le_bytes(archive[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let mut names = Vec::new();
    for _ in 0..records {
        if pos + 46 > archive.len() || archive[pos..pos + 4] != [0x50, 0x4b, 0x01, 0x02] {
            return Err(invalid_data("archive central directory is malformed"));
        }
        let name_len = u16::from_le_bytes(archive[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(archive[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len =
            u16::from_le_bytes(archive[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let name_end = pos + 46 + name_len;
        if name_end > archive.len() {
            return Err(invalid_data("archive central directory is truncated"));
        }
        let name = std::str::from_utf8(&archive[pos + 46..name_end])
            .map_err(|_| invalid_data("archive entry name is not UTF-8"))?;
        if allowlist.contains(&name) {
            names.push(name.to_string());
        }
        pos = name_end + extra_len + comment_len;
    }
    Ok(names)
}

fn version_verified(version_dir: &Path, expected_required: &[(&str, &str)]) -> bool {
    expected_required.iter().all(|(name, expected_hash)| {
        let path = version_dir.join(name);
        fs::symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            && fs::read(&path)
                .map(|data| sha256_hex(&data) == *expected_hash)
                .unwrap_or(false)
    })
}

fn verify_required_hashes(
    version_dir: &Path,
    expected_required: &[(&str, &str)],
) -> io::Result<()> {
    for (name, expected_hash) in expected_required {
        let path = version_dir.join(name);
        let data = fs::read(&path)?;
        if sha256_hex(&data) != *expected_hash {
            return Err(invalid_data(format!(
                "managed xray file '{name}' failed integrity verification"
            )));
        }
    }
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn protect_version_tree(
    root: &Path,
    version_dir: &Path,
    required_names: &[&str],
    executable_name: &str,
) -> io::Result<()> {
    crate::config_security::protect_path(root)?;
    crate::config_security::protect_path(version_dir)?;
    for name in required_names {
        crate::config_security::protect_path(&version_dir.join(name))?;
    }
    #[cfg(unix)]
    if executable_name == "xray" {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            version_dir.join(executable_name),
            fs::Permissions::from_mode(0o700),
        )?;
    }
    #[cfg(not(unix))]
    let _ = executable_name;
    Ok(())
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-mgxray-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn required_entries() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("xray.exe", b"MZ fake xray".to_vec()),
            ("geoip.dat", b"geoip".to_vec()),
            ("geosite.dat", b"geosite".to_vec()),
        ]
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn linux_required_entries() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("xray", b"ELF fake xray".to_vec()),
            ("geoip.dat", b"geoip".to_vec()),
            ("geosite.dat", b"geosite".to_vec()),
        ]
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn install_linux_synthetic(root: &Path, archive: &[u8]) -> io::Result<ManagedXrayInstallation> {
        let file_hashes: Vec<(String, String)> = linux_required_entries()
            .iter()
            .map(|(name, data)| (name.to_string(), sha256_hex(data)))
            .collect();
        let refs: Vec<(&str, &str)> = file_hashes
            .iter()
            .map(|(n, h)| (n.as_str(), h.as_str()))
            .collect();
        install_archive_for_platform(root, archive, &sha256_hex(archive), &refs, LINUX_LAYOUT)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_installs_executable_and_assets_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("linux-valid");
        let root = dir.join("xray");
        let owned = linux_required_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_linux_synthetic(&root, &archive).unwrap();
        assert!(installed.created);
        assert_eq!(installed.executable, installed.version_dir.join("xray"));
        assert_eq!(
            fs::metadata(&installed.executable)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(installed.version_dir.join("geoip.dat"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!install_linux_synthetic(&root, &archive).unwrap().created);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_rejects_wrong_archive_and_tampered_assets() {
        let dir = unique_dir("linux-integrity");
        let root = dir.join("xray");
        let owned = linux_required_entries();
        let archive = build_archive(&slices(&owned));
        assert_eq!(
            install_verified_linux_archive(&root, &archive)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!root.join(LINUX_XRAY_VERSION).exists());
        let installed = install_linux_synthetic(&root, &archive).unwrap();
        fs::write(installed.version_dir.join("geoip.dat"), b"tampered").unwrap();
        assert!(install_linux_synthetic(&root, &archive).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_rejects_missing_binary_without_publishing_version() {
        let dir = unique_dir("linux-missing");
        let root = dir.join("xray");
        let archive = build_archive(&[("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")]);
        assert_eq!(
            install_linux_synthetic(&root, &archive).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!linux_managed_version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_rejects_wrong_file_hash_before_atomic_publish() {
        let dir = unique_dir("linux-wrong-file-hash");
        let root = dir.join("xray");
        let archive = build_archive(&[
            ("xray", b"ELF fake xray"),
            ("geoip.dat", b"tampered"),
            ("geosite.dat", b"geosite"),
        ]);
        assert_eq!(
            install_linux_synthetic(&root, &archive).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!linux_managed_version_dir(&root).exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn remove_incomplete_drops_stale_tree_but_keeps_verified() {
        let dir = unique_dir("linux-incomplete");
        let root = dir.join("xray");
        let version_dir = linux_managed_version_dir(&root);

        fs::create_dir_all(&version_dir).unwrap();
        remove_incomplete_linux_version(&root).unwrap();
        assert!(!version_dir.exists());

        fs::create_dir_all(&version_dir).unwrap();
        fs::write(version_dir.join("xray"), b"stale").unwrap();
        remove_incomplete_linux_version(&root).unwrap();
        assert!(!version_dir.exists());

        // A symlinked version dir is unlinked, never traversed.
        let target = dir.join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("xray"), b"kept").unwrap();
        std::os::unix::fs::symlink(&target, &version_dir).unwrap();
        remove_incomplete_linux_version(&root).unwrap();
        assert!(!version_dir.exists() && target.join("xray").exists());

        let owned = linux_required_entries();
        let file_hashes: Vec<(String, String)> = owned
            .iter()
            .map(|(n, d)| (n.to_string(), sha256_hex(d)))
            .collect();
        let refs: Vec<(&str, &str)> = file_hashes
            .iter()
            .map(|(n, h)| (n.as_str(), h.as_str()))
            .collect();
        fs::create_dir_all(&version_dir).unwrap();
        for (name, data) in &owned {
            fs::write(version_dir.join(name), data).unwrap();
        }
        remove_incomplete_version_dir(&version_dir, &refs).unwrap();
        assert!(version_dir.join("xray").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn remove_linux_version_reports_whether_tree_existed() {
        let dir = unique_dir("linux-remove");
        let root = dir.join("xray");
        assert!(!remove_linux_version(&root).unwrap());
        fs::create_dir_all(linux_managed_version_dir(&root)).unwrap();
        assert!(remove_linux_version(&root).unwrap());
        assert!(!linux_managed_version_dir(&root).exists());
        assert!(!remove_linux_version(&root).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn relax_permissions_produces_distro_package_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("linux-relax");
        let root = dir.join("xray");
        let owned = linux_required_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_linux_synthetic(&root, &archive).unwrap();
        relax_linux_package_permissions(&root).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&installed.version_dir), 0o755);
        assert_eq!(mode(&installed.executable), 0o755);
        assert_eq!(mode(&installed.version_dir.join("geoip.dat")), 0o644);
        assert_eq!(mode(&installed.version_dir.join("geosite.dat")), 0o644);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn package_mode_policy_requires_root_owner_and_no_group_write() {
        assert!(package_executable_mode_allowed(0o755, 0));
        assert!(!package_executable_mode_allowed(0o775, 0));
        assert!(!package_executable_mode_allowed(0o757, 0));
        assert!(!package_executable_mode_allowed(0o755, 1000));
        assert!(!package_executable_mode_allowed(0o644, 0));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_rejects_symlinked_existing_asset() {
        let dir = unique_dir("linux-symlink");
        let root = dir.join("xray");
        let owned = linux_required_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_linux_synthetic(&root, &archive).unwrap();
        let external = dir.join("external-geoip.dat");
        fs::write(&external, b"geoip").unwrap();
        fs::remove_file(installed.version_dir.join("geoip.dat")).unwrap();
        std::os::unix::fs::symlink(&external, installed.version_dir.join("geoip.dat")).unwrap();
        assert_eq!(
            install_linux_synthetic(&root, &archive).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn official_linux_archive_verifies_when_supplied_outside_normal_tests() {
        use std::os::unix::fs::PermissionsExt;
        let Ok(path) = std::env::var("XRAY_LINUX_ARCHIVE") else {
            return;
        };
        let archive = fs::read(path).unwrap();
        assert_eq!(sha256_hex(&archive), LINUX_XRAY_SHA256);
        let dir = unique_dir("linux-official");
        let root = dir.join("xray");
        let installed = install_verified_linux_archive(&root, &archive).unwrap();
        verify_managed_linux_executable(&root, &installed.executable).unwrap();
        let version = std::process::Command::new(&installed.executable)
            .arg("version")
            .output()
            .unwrap();
        assert!(version.status.success());
        assert!(String::from_utf8_lossy(&version.stdout).contains("26.3.27"));
        fs::set_permissions(&installed.executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_managed_linux_executable(&root, &installed.executable).is_err());
        fs::set_permissions(&installed.executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(installed.version_dir.join("geosite.dat"), b"tampered").unwrap();
        assert_eq!(
            verify_managed_linux_executable(&root, &installed.executable)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    fn slices<'a>(entries: &'a [(&'a str, Vec<u8>)]) -> Vec<(&'a str, &'a [u8])> {
        entries.iter().map(|(n, d)| (*n, d.as_slice())).collect()
    }

    fn sha256_hex(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }

    fn install_synthetic(root: &Path, archive: &[u8]) -> io::Result<ManagedXrayInstallation> {
        let file_hashes: Vec<(String, String)> = required_entries()
            .iter()
            .map(|(name, data)| (name.to_string(), sha256_hex(data)))
            .collect();
        let refs: Vec<(&str, &str)> = file_hashes
            .iter()
            .map(|(n, h)| (n.as_str(), h.as_str()))
            .collect();
        install_archive_with_expected_hash(root, archive, &sha256_hex(archive), &refs, &[])
    }

    fn version_dir(root: &Path) -> PathBuf {
        managed_version_dir(root)
    }

    fn windows_tun_entries() -> Vec<(&'static str, Vec<u8>)> {
        let mut entries = required_entries();
        entries.push(("wintun.dll", b"MZ pinned Wintun".to_vec()));
        entries.push(("LICENSE-Wintun", b"pinned Wintun license".to_vec()));
        entries
    }

    fn install_tun_synthetic(root: &Path, archive: &[u8]) -> io::Result<ManagedXrayInstallation> {
        let hashes: Vec<_> = windows_tun_entries()
            .iter()
            .map(|(name, bytes)| (name.to_string(), sha256_hex(bytes)))
            .collect();
        let refs: Vec<_> = hashes
            .iter()
            .map(|(name, hash)| (name.as_str(), hash.as_str()))
            .collect();
        let (base, tun) = refs.split_at(REQUIRED.len());
        install_archive_with_expected_hash(root, archive, &sha256_hex(archive), base, tun)
    }

    #[test]
    fn windows_tun_install_includes_verified_driver_and_license() {
        let dir = unique_dir("windows-tun-package");
        let root = dir.join("xray");
        let owned = windows_tun_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_tun_synthetic(&root, &archive).unwrap();
        for (name, bytes) in owned {
            assert_eq!(fs::read(installed.version_dir.join(name)).unwrap(), bytes);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn windows_tun_install_completes_legacy_package_without_replacing_base() {
        let dir = unique_dir("windows-tun-upgrade");
        let root = dir.join("xray");
        let base = required_entries();
        let legacy = install_synthetic(&root, &build_archive(&slices(&base))).unwrap();
        let owned = windows_tun_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_tun_synthetic(&root, &archive).unwrap();
        assert!(!installed.created);
        assert_eq!(installed.executable, legacy.executable);
        for (name, bytes) in owned {
            assert_eq!(fs::read(installed.version_dir.join(name)).unwrap(), bytes);
        }
        assert!(!install_tun_synthetic(&root, &archive).unwrap().created);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn windows_tun_install_preserves_existing_tampered_driver() {
        let dir = unique_dir("windows-tun-preserve");
        let root = dir.join("xray");
        let base = required_entries();
        let installed = install_synthetic(&root, &build_archive(&slices(&base))).unwrap();
        fs::write(installed.version_dir.join("wintun.dll"), b"unknown driver").unwrap();
        let owned = windows_tun_entries();
        let error = install_tun_synthetic(&root, &build_archive(&slices(&owned))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(installed.version_dir.join("wintun.dll")).unwrap(),
            b"unknown driver"
        );
        assert!(!installed.version_dir.join("LICENSE-Wintun").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn windows_tun_wrong_archive_driver_is_rejected_before_publication() {
        let dir = unique_dir("windows-tun-wrong-hash");
        let root = dir.join("xray");
        let mut owned = windows_tun_entries();
        owned
            .iter_mut()
            .find(|(name, _)| *name == "wintun.dll")
            .unwrap()
            .1 = b"wrong driver".to_vec();
        let error = install_tun_synthetic(&root, &build_archive(&slices(&owned))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn windows_tun_upgrade_rejects_unverified_archive_without_adding_files() {
        let dir = unique_dir("windows-tun-upgrade-bad-hash");
        let root = dir.join("xray");
        let base = required_entries();
        let installed = install_synthetic(&root, &build_archive(&slices(&base))).unwrap();
        let mut owned = windows_tun_entries();
        owned
            .iter_mut()
            .find(|(name, _)| *name == "LICENSE-Wintun")
            .unwrap()
            .1 = b"wrong license".to_vec();
        let error = install_tun_synthetic(&root, &build_archive(&slices(&owned))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!installed.version_dir.join("wintun.dll").exists());
        assert!(!installed.version_dir.join("LICENSE-Wintun").exists());
        assert!(
            !install_synthetic(&root, &build_archive(&slices(&base)))
                .unwrap()
                .created
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn windows_tun_guard_is_actionable_and_does_not_expose_paths() {
        let dir = unique_dir("windows-tun-guard");
        let executable = dir.join("xray.exe");
        for driver in [None, Some(b"unverified driver".as_slice())] {
            if let Some(bytes) = driver {
                fs::write(dir.join("wintun.dll"), bytes).unwrap();
            }
            let error = verify_windows_tun_support(&executable).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let message = error.to_string();
            assert!(message.contains("install managed Xray again in Settings"));
            assert!(!message.contains(&dir.display().to_string()));
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn valid_archive_installs_allowlisted_files() {
        let dir = unique_dir("valid");
        let root = dir.join("backends").join("xray");
        let owned = required_entries();
        let mut entries: Vec<(&str, &[u8])> = slices(&owned);
        entries.push(("LICENSE", b"license text"));
        entries.push(("README.md", b"readme"));
        let archive = build_archive(&entries);

        let result = install_synthetic(&root, &archive).unwrap();

        assert!(result.created);
        assert_eq!(result.version_dir, version_dir(&root));
        assert_eq!(result.executable, version_dir(&root).join("xray.exe"));
        for (name, data) in &entries {
            assert_eq!(fs::read(version_dir(&root).join(name)).unwrap(), *data);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wrong_hash_leaves_no_version_directory() {
        let dir = unique_dir("wronghash");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);

        let err = install_verified_archive(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        assert!(!root.exists() || fs::read_dir(&root).unwrap().next().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_archive_is_rejected_before_open() {
        let dir = unique_dir("oversized");
        let root = dir.join("xray");
        let archive = vec![0u8; MAX_XRAY_ARCHIVE_BYTES + 1];

        let err = install_verified_archive(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unknown_and_traversal_entries_are_not_written() {
        let dir = unique_dir("traversal");
        let root = dir.join("xray");
        let owned = required_entries();
        let mut entries: Vec<(&str, &[u8])> = slices(&owned);
        entries.push(("sub/xray.exe", b"nested"));
        entries.push(("evil.dll", b"evil"));
        let archive = build_archive(&entries);

        let result = install_synthetic(&root, &archive).unwrap();

        assert!(result.created);
        let written: Vec<_> = fs::read_dir(&result.version_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(written.len(), 3);
        assert!(!result.version_dir.join("sub").exists());
        assert!(!result.version_dir.join("evil.dll").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_required_entry_fails_without_version() {
        let dir = unique_dir("missingreq");
        let root = dir.join("xray");
        let archive = build_archive(&[
            ("xray.exe", b"MZ".as_slice()),
            ("geoip.dat", b"geoip".as_slice()),
        ]);

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        let staging_left: Vec<_> = fs::read_dir(&root)
            .map(|rd| rd.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(staging_left.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn duplicate_allowlisted_entry_fails_without_version() {
        let dir = unique_dir("dup");
        let root = dir.join("xray");
        let owned = required_entries();
        let mut entries: Vec<(&str, &[u8])> = slices(&owned);
        entries.push(("xray2exe", b"MZ second"));
        let mut archive = build_archive(&entries);
        let mut cursor = 0;
        while let Some(pos) = archive[cursor..]
            .windows(b"xray2exe".len())
            .position(|w| w == b"xray2exe")
        {
            archive[cursor + pos..cursor + pos + 8].copy_from_slice(b"xray.exe");
            cursor += pos + 8;
        }

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_entry_metadata_fails_without_version() {
        let dir = unique_dir("bigentry");
        let root = dir.join("xray");
        let big = vec![0u8; usize::try_from(MAX_XRAY_ENTRY_BYTES + 1).unwrap()];
        let archive = build_archive(&[
            ("xray.exe", b"MZ".as_slice()),
            ("geoip.dat", b"geoip".as_slice()),
            ("geosite.dat", big.as_slice()),
        ]);

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn complete_existing_version_is_idempotent() {
        let dir = unique_dir("idempotent");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);

        let first = install_synthetic(&root, &archive).unwrap();
        assert!(first.created);
        let second = install_synthetic(&root, &archive).unwrap();

        assert!(!second.created);
        assert_eq!(second.executable, first.executable);
        assert_eq!(
            fs::read(version_dir(&root).join("xray.exe")).unwrap(),
            b"MZ fake xray"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn incomplete_existing_version_is_preserved() {
        let dir = unique_dir("incomplete");
        let root = dir.join("xray");
        let final_dir = version_dir(&root);
        fs::create_dir_all(&final_dir).unwrap();
        fs::write(final_dir.join("xray.exe"), b"original").unwrap();
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(final_dir.join("xray.exe")).unwrap(), b"original");
        assert!(!final_dir.join("geoip.dat").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tampered_existing_version_is_preserved_and_rejected() {
        let dir = unique_dir("tampered");
        let root = dir.join("xray");
        let final_dir = version_dir(&root);
        fs::create_dir_all(&final_dir).unwrap();
        for name in ["xray.exe", "geoip.dat", "geosite.dat"] {
            fs::write(final_dir.join(name), b"tampered").unwrap();
        }
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        for name in ["xray.exe", "geoip.dat", "geosite.dat"] {
            assert_eq!(fs::read(final_dir.join(name)).unwrap(), b"tampered");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_managed_executable_rejects_tampered_runtime_file() {
        let dir = unique_dir("verify-tampered");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);
        let installed = install_synthetic(&root, &archive).unwrap();

        fs::write(installed.version_dir.join("geosite.dat"), b"tampered").unwrap();

        let err = verify_managed_executable(&root, &installed.executable).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_managed_executable_rejects_noncanonical_sibling() {
        let dir = unique_dir("verify-sibling");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);
        install_synthetic(&root, &archive).unwrap();
        let sibling = dir.join("other").join("xray.exe");
        fs::create_dir_all(sibling.parent().unwrap()).unwrap();
        fs::write(&sibling, b"MZ").unwrap();

        let err = verify_managed_executable(&root, &sibling).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn managed_executable_requires_exact_canonical_path() {
        let dir = unique_dir("canonical");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);
        let installed = install_synthetic(&root, &archive).unwrap();

        assert!(is_managed_executable(&root, &installed.executable).unwrap());
        let sibling = dir.join("other").join("xray.exe");
        fs::create_dir_all(sibling.parent().unwrap()).unwrap();
        fs::write(&sibling, b"MZ").unwrap();
        assert!(!is_managed_executable(&root, &sibling).unwrap());
        let nested = version_dir(&root).join("sub").join("xray.exe");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(&nested, b"MZ").unwrap();
        assert!(!is_managed_executable(&root, &nested).unwrap());
        assert!(is_managed_executable(&root, &dir.join("missing.exe")).is_err());
        assert!(is_managed_executable(&dir.join("noroot"), &installed.executable).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn managed_location_allows_missing_executable_but_rejects_escape() {
        let dir = unique_dir("location");
        let root = dir.join("xray");
        let version = version_dir(&root);
        fs::create_dir_all(&version).unwrap();

        let missing_exe = version.join("xray.exe");
        assert!(is_managed_executable_location(&root, &missing_exe).unwrap());

        assert!(!is_managed_executable_location(&root, &version.join("xray2.exe")).unwrap());

        let sibling_dir = root.join("other");
        fs::create_dir_all(&sibling_dir).unwrap();
        assert!(!is_managed_executable_location(&root, &sibling_dir.join("xray.exe")).unwrap());

        let nested_dir = version.join("sub");
        fs::create_dir_all(&nested_dir).unwrap();
        assert!(!is_managed_executable_location(&root, &nested_dir.join("xray.exe")).unwrap());

        let escaped = version.join("..").join("other").join("xray.exe");
        assert!(!is_managed_executable_location(&root, &escaped).unwrap());

        assert!(is_managed_executable_location(&dir.join("noroot"), &missing_exe).is_err());
        let missing_parent = version.join("nosuchdir").join("xray.exe");
        assert!(is_managed_executable_location(&root, &missing_parent).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn macos_required_entries() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("xray", b"Mach-O fake xray".to_vec()),
            ("geoip.dat", b"geoip".to_vec()),
            ("geosite.dat", b"geosite".to_vec()),
        ]
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn install_macos_synthetic(root: &Path, archive: &[u8]) -> io::Result<ManagedXrayInstallation> {
        let file_hashes: Vec<(String, String)> = macos_required_entries()
            .iter()
            .map(|(name, data)| (name.to_string(), sha256_hex(data)))
            .collect();
        let refs: Vec<(&str, &str)> = file_hashes
            .iter()
            .map(|(n, h)| (n.as_str(), h.as_str()))
            .collect();
        install_archive_for_platform(root, archive, &sha256_hex(archive), &refs, MACOS_LAYOUT)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn macos_manifest_installs_private_executable_and_assets() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("macos-valid");
        let root = dir.join("xray");
        let owned = macos_required_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_macos_synthetic(&root, &archive).unwrap();
        assert!(installed.created);
        assert_eq!(installed.version_dir, macos_managed_version_dir(&root));
        assert_eq!(installed.executable, installed.version_dir.join("xray"));
        let mode = fs::metadata(&installed.executable)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(!install_macos_synthetic(&root, &archive).unwrap().created);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn macos_manifest_rejects_unpinned_archive_without_publishing() {
        let dir = unique_dir("macos-unpinned");
        let root = dir.join("xray");
        let owned = macos_required_entries();
        let archive = build_archive(&slices(&owned));
        assert_eq!(
            install_verified_macos_archive(&root, &archive)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!macos_managed_version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn macos_verification_rejects_foreign_path_and_synthetic_payload() {
        let dir = unique_dir("macos-verify");
        let root = dir.join("xray");
        let owned = macos_required_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_macos_synthetic(&root, &archive).unwrap();
        // Synthetic payload never matches the pinned official hashes.
        assert!(verify_managed_macos_executable(&root, &installed.executable).is_err());
        let foreign = dir.join("xray-foreign");
        fs::write(&foreign, b"Mach-O fake xray").unwrap();
        assert_eq!(
            verify_managed_macos_executable(&root, &foreign)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn official_macos_archive_verifies_when_supplied_outside_normal_tests() {
        let Ok(path) = std::env::var("XRAY_MACOS_ARCHIVE") else {
            return;
        };
        let archive = fs::read(path).unwrap();
        assert_eq!(sha256_hex(&archive), MACOS_XRAY_SHA256);
        let dir = unique_dir("macos-official");
        let root = dir.join("xray");
        let installed = install_verified_macos_archive(&root, &archive).unwrap();
        verify_managed_macos_executable(&root, &installed.executable).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
