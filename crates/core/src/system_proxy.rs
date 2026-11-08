use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const PROXY_STATE_DOCUMENT_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxySnapshot {
    pub proxy_enable: Option<u32>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
    /// macOS: per-service proxy state captured before apply. Empty elsewhere.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub macos_services: Vec<MacServiceProxy>,
    /// Linux/GNOME: `org.gnome.system.proxy` state captured before apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gnome: Option<GnomeProxy>,
    /// Linux/KDE: `kioslaverc` `[Proxy Settings]` captured before apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kde: Option<KdeProxy>,
}

/// KDE proxy settings (`kioslaverc`, group `Proxy Settings`). `None` means the
/// key was absent (or empty) and is deleted again on restore.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KdeProxy {
    pub proxy_type: Option<String>,
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub socks_proxy: Option<String>,
    pub no_proxy_for: Option<String>,
}

/// GNOME proxy settings (`gsettings org.gnome.system.proxy`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GnomeProxy {
    /// `none`, `manual` or `auto`.
    pub mode: String,
    pub http: GnomeProxyHost,
    pub https: GnomeProxyHost,
    pub socks: GnomeProxyHost,
    pub ignore_hosts: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GnomeProxyHost {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MacProxyEndpoint {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MacServiceProxy {
    pub service: String,
    pub web: MacProxyEndpoint,
    pub secure_web: MacProxyEndpoint,
    pub socks: MacProxyEndpoint,
    pub bypass: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyOwnership {
    pub profile_id: String,
    pub snapshot: ProxySnapshot,
    pub applied_server: String,
    pub applied_override: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStateDocument {
    pub version: u32,
    pub ownership: Option<ProxyOwnership>,
}

pub trait ProxyAdapter: Send {
    fn snapshot(&mut self) -> io::Result<ProxySnapshot>;
    fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()>;
    fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()>;
    /// Platform bypass entries that are always prepended to the profile's
    /// custom list — loopback and LAN destinations must never be proxied.
    /// Entries are expressed in the adapter's own syntax.
    fn default_bypass(&self) -> Vec<String> {
        Vec::new()
    }
}

pub struct SystemProxyManager {
    path: PathBuf,
    adapter: Box<dyn ProxyAdapter>,
    ownership: Option<ProxyOwnership>,
}

impl std::fmt::Debug for SystemProxyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemProxyManager")
            .field("path", &self.path)
            .field("ownership", &self.ownership)
            .finish_non_exhaustive()
    }
}

impl SystemProxyManager {
    #[cfg(windows)]
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        Self::with_adapter(path, Box::new(WindowsProxyAdapter))
    }

    #[cfg(target_os = "macos")]
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        Self::with_adapter(path, Box::new(macos::MacProxyAdapter::system()))
    }

    #[cfg(target_os = "linux")]
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let adapter = linux::system_adapter().unwrap_or_else(|| Box::new(UnsupportedProxyAdapter));
        Self::with_adapter(path, adapter)
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        Self::with_adapter(path, Box::new(UnsupportedProxyAdapter))
    }

    pub fn with_adapter(
        path: impl Into<PathBuf>,
        adapter: Box<dyn ProxyAdapter>,
    ) -> io::Result<Self> {
        let path = path.into();
        let document = load_document(&path)?;
        Ok(Self {
            path,
            adapter,
            ownership: document.ownership,
        })
    }

    pub fn ownership(&self) -> Option<&ProxyOwnership> {
        self.ownership.as_ref()
    }

    pub fn apply(&mut self, profile_id: &str, port: u16, bypass: &[String]) -> io::Result<()> {
        self.apply_server(profile_id, format!("socks=127.0.0.1:{port}"), bypass)
    }

    /// Like [`apply`](Self::apply), but also routes plain HTTP and HTTPS
    /// clients to the profile's HTTP CONNECT listener when it has one.
    pub fn apply_with_http(
        &mut self,
        profile_id: &str,
        socks_port: u16,
        http_port: Option<u16>,
        bypass: &[String],
    ) -> io::Result<()> {
        let server = match http_port {
            Some(http) => {
                format!("http=127.0.0.1:{http};https=127.0.0.1:{http};socks=127.0.0.1:{socks_port}")
            }
            None => format!("socks=127.0.0.1:{socks_port}"),
        };
        self.apply_server(profile_id, server, bypass)
    }

    fn apply_server(
        &mut self,
        profile_id: &str,
        server: String,
        bypass: &[String],
    ) -> io::Result<()> {
        if self.ownership.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "system proxy is already owned by a profile",
            ));
        }
        let snapshot = self.adapter.snapshot()?;
        let mut entries = self.adapter.default_bypass();
        for entry in bypass {
            if !entries.iter().any(|existing| existing == entry) {
                entries.push(entry.clone());
            }
        }
        let applied_override = entries.join(";");
        self.ownership = Some(ProxyOwnership {
            profile_id: profile_id.to_string(),
            snapshot: snapshot.clone(),
            applied_server: server.clone(),
            applied_override: applied_override.clone(),
        });
        if let Err(err) = self.persist() {
            self.ownership = None;
            return Err(err);
        }
        if let Err(err) = self.adapter.apply(&server, &applied_override) {
            let mut message = format!("failed to apply system proxy: {err}");
            match self.adapter.restore(&snapshot) {
                Err(restore_err) => {
                    message.push_str(&format!(
                        "; snapshot restore failed: {restore_err}; ownership record kept for recovery"
                    ));
                }
                Ok(()) => {
                    self.ownership = None;
                    if let Err(persist_err) = self.persist() {
                        message
                            .push_str(&format!("; ownership record cleanup failed: {persist_err}"));
                    }
                }
            }
            return Err(io::Error::new(err.kind(), message));
        }
        Ok(())
    }

    pub fn restore(&mut self, profile_id: &str) -> io::Result<()> {
        let Some(ownership) = self.ownership.clone() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no system proxy ownership is recorded",
            ));
        };
        if ownership.profile_id != profile_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "system proxy is owned by profile '{}', not '{profile_id}'",
                    ownership.profile_id
                ),
            ));
        }
        self.adapter.restore(&ownership.snapshot)?;
        self.ownership = None;
        self.persist()
    }

    pub fn restore_any(&mut self) -> io::Result<()> {
        let Some(ownership) = self.ownership.clone() else {
            return Ok(());
        };
        self.adapter.restore(&ownership.snapshot)?;
        self.ownership = None;
        self.persist()
    }

    fn persist(&self) -> io::Result<()> {
        save_document(
            &self.path,
            &ProxyStateDocument {
                version: PROXY_STATE_DOCUMENT_VERSION,
                ownership: self.ownership.clone(),
            },
        )
    }
}

/// Read current persisted ownership without changing desktop settings.
pub fn load_ownership(path: &Path) -> io::Result<Option<ProxyOwnership>> {
    load_document(path).map(|document| document.ownership)
}

fn load_document(path: &Path) -> io::Result<ProxyStateDocument> {
    use std::io::Read;

    const MAX_STATE_BYTES: u64 = 1024 * 1024;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ProxyStateDocument {
                version: PROXY_STATE_DOCUMENT_VERSION,
                ownership: None,
            });
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid proxy state file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Proxy state must be a private regular file owned by this user",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
    file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Proxy state file is too large",
        ));
    }
    let document: ProxyStateDocument = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid proxy state document"))?;
    if document.version != PROXY_STATE_DOCUMENT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported proxy state document version {}",
                document.version
            ),
        ));
    }
    Ok(document)
}

fn save_document(path: &Path, document: &ProxyStateDocument) -> io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Change the system proxy as your own user, without sudo",
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Unsafe proxy state directory",
                ));
            }
        }
    }
    let json = serde_json::to_vec_pretty(document)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Cannot encode proxy state"))?;
    if json.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Proxy state file is too large",
        ));
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let temp_path = path.with_extension(format!("{}.{}.tmp", std::process::id(), stamp));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp_path)?;
    let result = (|| {
        crate::config_security::protect_path(&temp_path)?;
        file.write_all(&json)?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        #[cfg(unix)]
        if let Some(parent) = parent {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

pub fn snapshot_matches(expected: &ProxySnapshot, actual: &ProxySnapshot) -> bool {
    expected == actual
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
/// Parse `http=127.0.0.1:P;https=…;socks=…`; only loopback targets are
/// accepted so a corrupted ownership record can never redirect traffic.
pub(crate) fn parse_server(
    server: &str,
) -> io::Result<std::collections::HashMap<&'static str, u16>> {
    let mut targets = std::collections::HashMap::new();
    for part in server.split(';').filter(|part| !part.is_empty()) {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy target");
        let (scheme, address) = part.split_once('=').ok_or_else(invalid)?;
        let port = address
            .strip_prefix("127.0.0.1:")
            .and_then(|port| port.parse::<u16>().ok())
            .filter(|port| *port != 0)
            .ok_or_else(invalid)?;
        let key = match scheme {
            "http" => "web",
            "https" => "secure",
            "socks" => "socks",
            _ => return Err(invalid()),
        };
        targets.insert(key, port);
    }
    if targets.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no proxy target",
        ));
    }
    Ok(targets)
}

#[cfg(not(any(windows, target_os = "macos")))]
struct UnsupportedProxyAdapter;

#[cfg(not(any(windows, target_os = "macos")))]
impl ProxyAdapter for UnsupportedProxyAdapter {
    fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
        Err(unsupported())
    }
    fn apply(&mut self, _server: &str, _bypass: &str) -> io::Result<()> {
        Err(unsupported())
    }
    fn restore(&mut self, _snapshot: &ProxySnapshot) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "system proxy is not supported on this platform",
    )
}

#[cfg(windows)]
struct WindowsProxyAdapter;

#[cfg(windows)]
mod windows_proxy {
    use super::{io, ProxySnapshot};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    const SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    const PROXY_ENABLE: &str = "ProxyEnable";
    const PROXY_SERVER: &str = "ProxyServer";
    const PROXY_OVERRIDE: &str = "ProxyOverride";

    struct RegKey(HKEY);

    impl Drop for RegKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn open_key(access: windows::Win32::System::Registry::REG_SAM_FLAGS) -> io::Result<RegKey> {
        let mut key = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(wide(SUBKEY).as_ptr()),
                0,
                access,
                &mut key,
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(RegKey(key))
    }

    fn get_dword(key: HKEY, name: &str) -> io::Result<Option<u32>> {
        let mut value = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(wide(name).as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some(&mut value as *mut u32 as *mut _),
                Some(&mut size),
            )
        };
        if status.is_err() {
            if status.0 as i32 == 2 {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(Some(value))
    }

    fn get_string(key: HKEY, name: &str) -> io::Result<Option<String>> {
        let name_wide = wide(name);
        let mut size = 0u32;
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(name_wide.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                None,
                Some(&mut size),
            )
        };
        if status.is_err() {
            if status.0 as i32 == 2 {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        let mut buffer = vec![0u16; (size as usize / 2).max(1)];
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(name_wide.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr() as *mut _),
                Some(&mut size),
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        let len = size as usize / 2;
        buffer.truncate(len.min(buffer.len()));
        while buffer.last() == Some(&0) {
            buffer.pop();
        }
        Ok(Some(String::from_utf16_lossy(&buffer)))
    }

    fn set_dword(key: HKEY, name: &str, value: u32) -> io::Result<()> {
        let status = unsafe {
            RegSetValueExW(
                key,
                PCWSTR(wide(name).as_ptr()),
                0,
                REG_DWORD,
                Some(std::slice::from_raw_parts(
                    &value as *const u32 as *const u8,
                    4,
                )),
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(())
    }

    fn set_string(key: HKEY, name: &str, value: &str) -> io::Result<()> {
        let data = wide(value);
        let status = unsafe {
            RegSetValueExW(
                key,
                PCWSTR(wide(name).as_ptr()),
                0,
                REG_SZ,
                Some(std::slice::from_raw_parts(
                    data.as_ptr() as *const u8,
                    data.len() * 2,
                )),
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(())
    }

    fn delete_value(key: HKEY, name: &str) -> io::Result<()> {
        let status = unsafe { RegDeleteValueW(key, PCWSTR(wide(name).as_ptr())) };
        if status.is_err() && status.0 as i32 != 2 {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(())
    }

    fn read_back(key: HKEY) -> io::Result<ProxySnapshot> {
        Ok(ProxySnapshot {
            proxy_enable: get_dword(key, PROXY_ENABLE)?,
            proxy_server: get_string(key, PROXY_SERVER)?,
            proxy_override: get_string(key, PROXY_OVERRIDE)?,
            ..Default::default()
        })
    }

    fn broadcast_settings_change() {
        let param = wide(SUBKEY);
        unsafe {
            let mut result: usize = 0;
            let _ = SendMessageTimeoutW(
                HWND(HWND_BROADCAST.0),
                WM_SETTINGCHANGE,
                WPARAM(0),
                LPARAM(param.as_ptr() as isize),
                SMTO_ABORTIFHUNG,
                2000,
                Some(&mut result as *mut usize as *mut _),
            );
        }
    }

    pub fn snapshot() -> io::Result<ProxySnapshot> {
        let key = open_key(KEY_READ)?;
        Ok(ProxySnapshot {
            proxy_enable: get_dword(key.0, PROXY_ENABLE)?,
            proxy_server: get_string(key.0, PROXY_SERVER)?,
            proxy_override: get_string(key.0, PROXY_OVERRIDE)?,
            ..Default::default()
        })
    }

    pub fn apply(server: &str, bypass: &str) -> io::Result<()> {
        let key = open_key(KEY_READ | KEY_WRITE)?;
        set_dword(key.0, PROXY_ENABLE, 1)?;
        set_string(key.0, PROXY_SERVER, server)?;
        set_string(key.0, PROXY_OVERRIDE, bypass)?;
        let expected = ProxySnapshot {
            proxy_enable: Some(1),
            proxy_server: Some(server.to_string()),
            proxy_override: Some(bypass.to_string()),
            ..Default::default()
        };
        let actual = read_back(key.0)?;
        drop(key);
        if !super::snapshot_matches(&expected, &actual) {
            return Err(io::Error::other(
                "applied system proxy values do not match the registry",
            ));
        }
        broadcast_settings_change();
        Ok(())
    }

    pub fn restore(snapshot: &ProxySnapshot) -> io::Result<()> {
        let key = open_key(KEY_READ | KEY_WRITE)?;
        match snapshot.proxy_enable {
            Some(value) => set_dword(key.0, PROXY_ENABLE, value)?,
            None => delete_value(key.0, PROXY_ENABLE)?,
        }
        match &snapshot.proxy_server {
            Some(value) => set_string(key.0, PROXY_SERVER, value)?,
            None => delete_value(key.0, PROXY_SERVER)?,
        }
        match &snapshot.proxy_override {
            Some(value) => set_string(key.0, PROXY_OVERRIDE, value)?,
            None => delete_value(key.0, PROXY_OVERRIDE)?,
        }
        let actual = read_back(key.0)?;
        drop(key);
        if !super::snapshot_matches(snapshot, &actual) {
            return Err(io::Error::other(
                "restored system proxy values do not match the registry",
            ));
        }
        broadcast_settings_change();
        Ok(())
    }

    /// Loopback/LAN bypass in Windows ProxyOverride syntax. `172.16.0.0/12`
    /// cannot be expressed as one wildcard, so it is spelled out per octet.
    pub fn default_bypass() -> Vec<String> {
        let mut entries: Vec<String> = ["<local>", "localhost", "127.*", "::1", "10.*"]
            .iter()
            .map(|entry| entry.to_string())
            .collect();
        for octet in 16u8..=31 {
            entries.push(format!("172.{octet}.*"));
        }
        entries.extend(
            [
                "192.168.*",
                "169.254.*",
                "fe80::*",
                "fc00::*",
                "*.local",
                "*.lan",
                "*.internal",
                "*.home",
            ]
            .iter()
            .map(|entry| entry.to_string()),
        );
        entries
    }
}

#[cfg(windows)]
impl ProxyAdapter for WindowsProxyAdapter {
    fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
        windows_proxy::snapshot()
    }
    fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
        windows_proxy::apply(server, bypass)
    }
    fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
        windows_proxy::restore(snapshot)
    }
    fn default_bypass(&self) -> Vec<String> {
        windows_proxy::default_bypass()
    }
}

/// macOS system proxy through `networksetup`, applied to every enabled
/// hardware network service (VPN services are owned by their providers and
/// left untouched). Runs as the logged-in admin user; no root helper.
#[cfg(target_os = "macos")]
pub mod macos {
    use super::{parse_server, MacProxyEndpoint, MacServiceProxy, ProxyAdapter, ProxySnapshot};
    use std::io;
    use std::process::Command;

    const NETWORKSETUP: &str = "/usr/sbin/networksetup";
    const KINDS: [(&str, &str); 3] = [
        ("web", "webproxy"),
        ("secure", "securewebproxy"),
        ("socks", "socksfirewallproxy"),
    ];

    pub trait NetworksetupRunner: Send {
        fn run(&mut self, args: &[String]) -> io::Result<String>;
    }

    pub struct SystemNetworksetup;

    impl NetworksetupRunner for SystemNetworksetup {
        fn run(&mut self, args: &[String]) -> io::Result<String> {
            let output = Command::new(NETWORKSETUP).args(args).output()?;
            if !output.status.success() {
                return Err(io::Error::other("networksetup failed"));
            }
            let text = String::from_utf8_lossy(&output.stdout).into_owned();
            // networksetup reports some failures on stdout with exit status 0.
            if text.starts_with("** Error") {
                return Err(io::Error::other("networksetup rejected the proxy change"));
            }
            Ok(text)
        }
    }

    pub struct MacProxyAdapter<R: NetworksetupRunner = SystemNetworksetup> {
        runner: R,
    }

    impl MacProxyAdapter<SystemNetworksetup> {
        pub fn system() -> Self {
            Self::with_runner(SystemNetworksetup)
        }
    }

    impl<R: NetworksetupRunner> MacProxyAdapter<R> {
        pub fn with_runner(runner: R) -> Self {
            Self { runner }
        }

        pub fn runner(&self) -> &R {
            &self.runner
        }

        fn call(&mut self, args: &[&str]) -> io::Result<String> {
            let owned: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            self.runner.run(&owned)
        }

        fn services(&mut self) -> io::Result<Vec<String>> {
            let services = hardware_services(&self.call(&["-listnetworkserviceorder"])?);
            if services.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no enabled network service found",
                ));
            }
            Ok(services)
        }

        fn read_endpoint(&mut self, kind: &str, service: &str) -> io::Result<MacProxyEndpoint> {
            Ok(parse_endpoint(
                &self.call(&[&format!("-get{kind}"), service])?,
            ))
        }

        fn write_endpoint(
            &mut self,
            kind: &str,
            service: &str,
            endpoint: &MacProxyEndpoint,
        ) -> io::Result<()> {
            if !endpoint.server.is_empty() {
                let port = endpoint.port.to_string();
                self.call(&[&format!("-set{kind}"), service, &endpoint.server, &port])?;
            }
            if !endpoint.enabled || endpoint.server.is_empty() {
                self.call(&[&format!("-set{kind}state"), service, "off"])?;
            }
            Ok(())
        }

        fn write_bypass(&mut self, service: &str, bypass: &[String]) -> io::Result<()> {
            let mut args = vec!["-setproxybypassdomains".to_string(), service.to_string()];
            if bypass.is_empty() {
                args.push("Empty".into());
            } else {
                args.extend(bypass.iter().cloned());
            }
            self.runner.run(&args).map(|_| ())
        }
    }

    impl<R: NetworksetupRunner> ProxyAdapter for MacProxyAdapter<R> {
        fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
            let mut services = Vec::new();
            for service in self.services()? {
                let bypass = parse_bypass(&self.call(&["-getproxybypassdomains", &service])?);
                services.push(MacServiceProxy {
                    web: self.read_endpoint(KINDS[0].1, &service)?,
                    secure_web: self.read_endpoint(KINDS[1].1, &service)?,
                    socks: self.read_endpoint(KINDS[2].1, &service)?,
                    bypass,
                    service,
                });
            }
            Ok(ProxySnapshot {
                macos_services: services,
                ..Default::default()
            })
        }

        fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
            let targets = parse_server(server)?;
            let bypass: Vec<String> = bypass
                .split(';')
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect();
            for service in self.services()? {
                for (key, kind) in KINDS {
                    if let Some(port) = targets.get(key) {
                        let endpoint = MacProxyEndpoint {
                            enabled: true,
                            server: "127.0.0.1".into(),
                            port: *port,
                        };
                        self.write_endpoint(kind, &service, &endpoint)?;
                    }
                }
                self.write_bypass(&service, &bypass)?;
            }
            Ok(())
        }

        fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
            for saved in &snapshot.macos_services {
                let service = saved.service.as_str();
                self.write_endpoint(KINDS[0].1, service, &saved.web)?;
                self.write_endpoint(KINDS[1].1, service, &saved.secure_web)?;
                self.write_endpoint(KINDS[2].1, service, &saved.socks)?;
                self.write_bypass(service, &saved.bypass)?;
            }
            Ok(())
        }

        fn default_bypass(&self) -> Vec<String> {
            [
                "localhost",
                "127.0.0.1",
                "::1",
                "*.local",
                "169.254/16",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "fe80::/10",
                "fc00::/7",
            ]
            .iter()
            .map(|entry| entry.to_string())
            .collect()
        }
    }

    /// Enabled services that sit on a hardware device, in service order.
    pub fn hardware_services(order: &str) -> Vec<String> {
        let mut services = Vec::new();
        let mut pending: Option<String> = None;
        for line in order.lines().map(str::trim) {
            if let Some(port) = line.strip_prefix("(Hardware Port:") {
                let device = port
                    .rsplit_once("Device:")
                    .map(|(_, device)| device.trim_end_matches(')').trim())
                    .unwrap_or("");
                if let Some(name) = pending.take().filter(|_| !device.is_empty()) {
                    services.push(name);
                }
            } else if let Some((index, name)) = line
                .strip_prefix('(')
                .and_then(|rest| rest.split_once(") "))
            {
                // "(*)" marks a disabled service.
                pending = (index != "*").then(|| name.to_string());
            }
        }
        services
    }

    fn parse_endpoint(text: &str) -> MacProxyEndpoint {
        let mut endpoint = MacProxyEndpoint::default();
        for line in text.lines() {
            match line.split_once(':') {
                Some(("Enabled", value)) => endpoint.enabled = value.trim() == "Yes",
                Some(("Server", value)) => endpoint.server = value.trim().to_string(),
                Some(("Port", value)) => endpoint.port = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        endpoint
    }

    fn parse_bypass(text: &str) -> Vec<String> {
        if text.starts_with("There aren't any") {
            return Vec::new();
        }
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// Linux system proxy for the logged-in user: GNOME-family desktops through
/// `gsettings` (`org.gnome.system.proxy`) and KDE Plasma through
/// `kwriteconfig` (`kioslaverc`). Bare window managers without either report
/// the proxy as unavailable.
#[cfg(target_os = "linux")]
pub mod linux {
    use super::{parse_server, GnomeProxy, GnomeProxyHost, KdeProxy, ProxyAdapter, ProxySnapshot};
    use std::io;
    use std::process::Command;

    const SCHEMA: &str = "org.gnome.system.proxy";

    pub trait GsettingsRunner: Send {
        fn run(&mut self, args: &[String]) -> io::Result<String>;
    }

    pub struct SystemGsettings;

    impl GsettingsRunner for SystemGsettings {
        fn run(&mut self, args: &[String]) -> io::Result<String> {
            let output = Command::new("gsettings").args(args).output()?;
            if !output.status.success() {
                return Err(io::Error::other("gsettings failed"));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }

    /// Whether the GNOME proxy schema can be read, i.e. `gsettings` exists and
    /// the schema is installed. A missing session bus fails here too.
    fn gnome_available() -> bool {
        SystemGsettings
            .run(&["get".into(), SCHEMA.into(), "mode".into()])
            .is_ok()
    }

    /// The adapter for the running desktop, or `None` when neither backend is
    /// usable. KDE sessions prefer `kioslaverc`; everything else prefers GNOME's
    /// schema, which GTK applications honor on any desktop.
    pub fn system_adapter() -> Option<Box<dyn ProxyAdapter>> {
        let kde_session = std::env::var("XDG_CURRENT_DESKTOP")
            .map(|desktop| desktop.to_ascii_lowercase().contains("kde"))
            .unwrap_or(false);
        if kde_session {
            if let Some(adapter) = KdeProxyAdapter::system() {
                return Some(Box::new(adapter));
            }
        }
        gnome_available().then(|| Box::new(GnomeProxyAdapter::system()) as Box<dyn ProxyAdapter>)
    }

    pub fn available() -> bool {
        system_adapter().is_some()
    }

    pub struct GnomeProxyAdapter<R: GsettingsRunner = SystemGsettings> {
        runner: R,
    }

    impl GnomeProxyAdapter<SystemGsettings> {
        pub fn system() -> Self {
            Self::with_runner(SystemGsettings)
        }
    }

    impl<R: GsettingsRunner> GnomeProxyAdapter<R> {
        pub fn with_runner(runner: R) -> Self {
            Self { runner }
        }

        pub fn runner(&self) -> &R {
            &self.runner
        }

        fn get(&mut self, schema: &str, key: &str) -> io::Result<String> {
            self.runner
                .run(&["get".into(), schema.into(), key.into()])
                .map(|text| text.trim().to_string())
        }

        fn set(&mut self, schema: &str, key: &str, value: &str) -> io::Result<()> {
            self.runner
                .run(&["set".into(), schema.into(), key.into(), value.into()])
                .map(|_| ())
        }

        fn read_host(&mut self, protocol: &str) -> io::Result<GnomeProxyHost> {
            let schema = format!("{SCHEMA}.{protocol}");
            Ok(GnomeProxyHost {
                host: parse_string(&self.get(&schema, "host")?),
                port: self.get(&schema, "port")?.parse().unwrap_or(0),
            })
        }

        fn write_host(&mut self, protocol: &str, host: &GnomeProxyHost) -> io::Result<()> {
            let schema = format!("{SCHEMA}.{protocol}");
            self.set(&schema, "host", &quote(&host.host))?;
            self.set(&schema, "port", &host.port.to_string())
        }
    }

    impl<R: GsettingsRunner> ProxyAdapter for GnomeProxyAdapter<R> {
        fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
            let gnome = GnomeProxy {
                mode: parse_string(&self.get(SCHEMA, "mode")?),
                http: self.read_host("http")?,
                https: self.read_host("https")?,
                socks: self.read_host("socks")?,
                ignore_hosts: parse_list(&self.get(SCHEMA, "ignore-hosts")?),
            };
            Ok(ProxySnapshot {
                gnome: Some(gnome),
                ..Default::default()
            })
        }

        fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
            let targets = parse_server(server)?;
            let bypass: Vec<String> = bypass
                .split(';')
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect();
            // A protocol without a target is cleared so a previous manual
            // setting cannot leak traffic past the profile.
            for (key, protocol) in [("web", "http"), ("secure", "https"), ("socks", "socks")] {
                let host = match targets.get(key) {
                    Some(port) => GnomeProxyHost {
                        host: "127.0.0.1".into(),
                        port: *port,
                    },
                    None => GnomeProxyHost::default(),
                };
                self.write_host(protocol, &host)?;
            }
            self.set(SCHEMA, "ignore-hosts", &format_list(&bypass))?;
            self.set(SCHEMA, "mode", "'manual'")
        }

        fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
            let Some(saved) = &snapshot.gnome else {
                return Ok(());
            };
            self.write_host("http", &saved.http)?;
            self.write_host("https", &saved.https)?;
            self.write_host("socks", &saved.socks)?;
            self.set(SCHEMA, "ignore-hosts", &format_list(&saved.ignore_hosts))?;
            self.set(SCHEMA, "mode", &quote(&saved.mode))
        }

        fn default_bypass(&self) -> Vec<String> {
            default_bypass_list()
        }
    }

    pub trait KdeRunner: Send {
        fn run(&mut self, program: &str, args: &[String]) -> io::Result<String>;
    }

    pub struct SystemKde;

    impl KdeRunner for SystemKde {
        fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
            let output = Command::new(program).args(args).output()?;
            if !output.status.success() {
                return Err(io::Error::other(format!("{program} failed")));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }

    const KDE_FILE: &str = "kioslaverc";
    const KDE_GROUP: &str = "Proxy Settings";

    pub struct KdeProxyAdapter<R: KdeRunner = SystemKde> {
        runner: R,
        /// Tool generation suffix: `6` or `5` (`kwriteconfig6`).
        version: &'static str,
    }

    impl KdeProxyAdapter<SystemKde> {
        /// Plasma 6 first, then Plasma 5; `None` when neither tool answers.
        pub fn system() -> Option<Self> {
            ["6", "5"].into_iter().find_map(|version| {
                let mut adapter = Self::with_runner(SystemKde, version);
                adapter.read("ProxyType").ok().map(|_| adapter)
            })
        }
    }

    impl<R: KdeRunner> KdeProxyAdapter<R> {
        pub fn with_runner(runner: R, version: &'static str) -> Self {
            Self { runner, version }
        }

        pub fn runner(&self) -> &R {
            &self.runner
        }

        fn read(&mut self, key: &str) -> io::Result<Option<String>> {
            let args = ["--file", KDE_FILE, "--group", KDE_GROUP, "--key", key].map(String::from);
            let text = self
                .runner
                .run(&format!("kreadconfig{}", self.version), &args)?;
            let value = text.trim();
            Ok((!value.is_empty()).then(|| value.to_string()))
        }

        fn write(&mut self, key: &str, value: Option<&str>) -> io::Result<()> {
            let mut args: Vec<String> = ["--file", KDE_FILE, "--group", KDE_GROUP, "--key", key]
                .map(String::from)
                .to_vec();
            match value {
                Some(value) => args.push(value.to_string()),
                None => args.push("--delete".to_string()),
            }
            self.runner
                .run(&format!("kwriteconfig{}", self.version), &args)
                .map(|_| ())
        }

        /// Running KDE applications re-read the proxy settings on this signal;
        /// without it they keep the old values until restarted. Best effort.
        fn notify(&mut self) {
            let args = [
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:",
            ]
            .map(String::from);
            let _ = self.runner.run("dbus-send", &args);
        }
    }

    impl<R: KdeRunner> ProxyAdapter for KdeProxyAdapter<R> {
        fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
            let kde = KdeProxy {
                proxy_type: self.read("ProxyType")?,
                http_proxy: self.read("httpProxy")?,
                https_proxy: self.read("httpsProxy")?,
                socks_proxy: self.read("socksProxy")?,
                no_proxy_for: self.read("NoProxyFor")?,
            };
            Ok(ProxySnapshot {
                kde: Some(kde),
                ..Default::default()
            })
        }

        fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
            let targets = parse_server(server)?;
            let bypass: Vec<&str> = bypass.split(';').filter(|e| !e.is_empty()).collect();
            // KDE stores `scheme://host port`; unset protocols are deleted so
            // an earlier manual setting cannot bypass the profile.
            let value = |key: &str, scheme: &str| {
                targets
                    .get(key)
                    .map(|port| format!("{scheme}://127.0.0.1 {port}"))
            };
            self.write("httpProxy", value("web", "http").as_deref())?;
            self.write("httpsProxy", value("secure", "http").as_deref())?;
            self.write("socksProxy", value("socks", "socks").as_deref())?;
            self.write("NoProxyFor", Some(&bypass.join(",")))?;
            self.write("ProxyType", Some("1"))?;
            self.notify();
            Ok(())
        }

        fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
            let Some(saved) = &snapshot.kde else {
                return Ok(());
            };
            self.write("httpProxy", saved.http_proxy.as_deref())?;
            self.write("httpsProxy", saved.https_proxy.as_deref())?;
            self.write("socksProxy", saved.socks_proxy.as_deref())?;
            self.write("NoProxyFor", saved.no_proxy_for.as_deref())?;
            self.write("ProxyType", saved.proxy_type.as_deref())?;
            self.notify();
            Ok(())
        }

        fn default_bypass(&self) -> Vec<String> {
            default_bypass_list()
        }
    }

    /// Loopback and LAN destinations that must never be proxied; GNOME and KDE
    /// both accept host names, wildcards and CIDR in one list.
    fn default_bypass_list() -> Vec<String> {
        [
            "localhost",
            "127.0.0.0/8",
            "::1",
            "*.local",
            "169.254.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fe80::/10",
            "fc00::/7",
        ]
        .iter()
        .map(|entry| entry.to_string())
        .collect()
    }

    fn quote(value: &str) -> String {
        format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
    }

    fn format_list(items: &[String]) -> String {
        let quoted: Vec<String> = items.iter().map(|item| quote(item)).collect();
        format!("[{}]", quoted.join(", "))
    }

    /// `'manual'` → `manual`.
    fn parse_string(text: &str) -> String {
        let inner = text.trim();
        let inner = inner.strip_prefix('\'').unwrap_or(inner);
        let inner = inner.strip_suffix('\'').unwrap_or(inner);
        inner.replace("\\'", "'").replace("\\\\", "\\")
    }

    /// `['a', 'b']` or `@as []` → `["a", "b"]`.
    fn parse_list(text: &str) -> Vec<String> {
        let text = text.trim();
        let Some(body) = text
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        else {
            return Vec::new();
        };
        body.split(',')
            .map(parse_string)
            .filter(|item| !item.is_empty())
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::HashMap;

        #[derive(Default)]
        struct FakeGsettings {
            values: HashMap<String, String>,
            writes: Vec<String>,
            fail_on: Option<String>,
        }

        impl GsettingsRunner for FakeGsettings {
            fn run(&mut self, args: &[String]) -> io::Result<String> {
                let key = format!("{} {}", args[1], args[2]);
                match args[0].as_str() {
                    "get" => Ok(format!(
                        "{}\n",
                        self.values.get(&key).cloned().unwrap_or_default()
                    )),
                    _ => {
                        if self.fail_on.as_deref() == Some(key.as_str()) {
                            return Err(io::Error::other("gsettings failed"));
                        }
                        self.writes.push(format!("{key}={}", args[3]));
                        self.values.insert(key, args[3].clone());
                        Ok(String::new())
                    }
                }
            }
        }

        fn seeded() -> FakeGsettings {
            let mut fake = FakeGsettings::default();
            for (key, value) in [
                ("org.gnome.system.proxy mode", "'none'"),
                (
                    "org.gnome.system.proxy ignore-hosts",
                    "['localhost', '10.0.0.0/8']",
                ),
                ("org.gnome.system.proxy.http host", "'corp'"),
                ("org.gnome.system.proxy.http port", "3128"),
                ("org.gnome.system.proxy.https host", "''"),
                ("org.gnome.system.proxy.https port", "0"),
                ("org.gnome.system.proxy.socks host", "''"),
                ("org.gnome.system.proxy.socks port", "0"),
            ] {
                fake.values.insert(key.into(), value.into());
            }
            fake
        }

        #[test]
        fn snapshot_reads_gsettings_values() {
            let mut adapter = GnomeProxyAdapter::with_runner(seeded());
            let gnome = adapter.snapshot().unwrap().gnome.unwrap();
            assert_eq!(gnome.mode, "none");
            assert_eq!(gnome.http.host, "corp");
            assert_eq!(gnome.http.port, 3128);
            assert_eq!(gnome.ignore_hosts, vec!["localhost", "10.0.0.0/8"]);
        }

        #[test]
        fn empty_list_parses_from_typed_literal() {
            assert!(parse_list("@as []").is_empty());
            assert_eq!(format_list(&[]), "[]");
        }

        #[test]
        fn apply_sets_loopback_targets_and_clears_missing_ones() {
            let mut adapter = GnomeProxyAdapter::with_runner(seeded());
            adapter
                .apply("socks=127.0.0.1:1080", "localhost;10.0.0.0/8")
                .unwrap();
            let values = &adapter.runner().values;
            assert_eq!(values["org.gnome.system.proxy mode"], "'manual'");
            assert_eq!(values["org.gnome.system.proxy.socks host"], "'127.0.0.1'");
            assert_eq!(values["org.gnome.system.proxy.socks port"], "1080");
            assert_eq!(values["org.gnome.system.proxy.http host"], "''");
            assert_eq!(
                values["org.gnome.system.proxy ignore-hosts"],
                "['localhost', '10.0.0.0/8']"
            );
        }

        #[test]
        fn mode_is_switched_last_when_applying_and_restoring() {
            let mut adapter = GnomeProxyAdapter::with_runner(seeded());
            let snapshot = adapter.snapshot().unwrap();
            adapter.apply("socks=127.0.0.1:1080", "").unwrap();
            assert_eq!(
                adapter.runner().writes.last().unwrap(),
                "org.gnome.system.proxy mode='manual'"
            );
            adapter.restore(&snapshot).unwrap();
            assert_eq!(
                adapter.runner().writes.last().unwrap(),
                "org.gnome.system.proxy mode='none'"
            );
        }

        #[test]
        fn restore_returns_previous_settings() {
            let mut adapter = GnomeProxyAdapter::with_runner(seeded());
            let snapshot = adapter.snapshot().unwrap();
            adapter
                .apply("http=127.0.0.1:8080;socks=127.0.0.1:1080", "x")
                .unwrap();
            adapter.restore(&snapshot).unwrap();
            assert_eq!(adapter.snapshot().unwrap(), snapshot);
        }

        #[test]
        fn rejects_non_loopback_targets() {
            let mut adapter = GnomeProxyAdapter::with_runner(seeded());
            let err = adapter.apply("socks=10.1.1.1:1080", "").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(adapter.runner().writes.is_empty());
        }

        #[test]
        fn apply_failure_surfaces_runner_error() {
            let mut fake = seeded();
            fake.fail_on = Some("org.gnome.system.proxy.socks port".into());
            let mut adapter = GnomeProxyAdapter::with_runner(fake);
            assert!(adapter.apply("socks=127.0.0.1:1080", "").is_err());
        }
    }
    #[cfg(test)]
    mod kde_tests {
        use super::*;
        use std::collections::HashMap;

        #[derive(Default)]
        struct FakeKde {
            values: HashMap<String, String>,
            calls: Vec<String>,
            notified: usize,
        }

        impl KdeRunner for FakeKde {
            fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                self.calls.push(format!("{program} {}", args.join(" ")));
                if program.starts_with("kreadconfig") {
                    let key = args.last().unwrap();
                    return Ok(format!(
                        "{}\n",
                        self.values.get(key).cloned().unwrap_or_default()
                    ));
                }
                if program.starts_with("kwriteconfig") {
                    let key = args[args.iter().position(|a| a == "--key").unwrap() + 1].clone();
                    if args.iter().any(|a| a == "--delete") {
                        self.values.remove(&key);
                    } else {
                        self.values.insert(key, args.last().unwrap().clone());
                    }
                    return Ok(String::new());
                }
                self.notified += 1;
                Ok(String::new())
            }
        }

        fn seeded() -> FakeKde {
            let mut fake = FakeKde::default();
            fake.values.insert("ProxyType".into(), "0".into());
            fake.values
                .insert("NoProxyFor".into(), "localhost,10.0.0.0/8".into());
            fake
        }

        #[test]
        fn snapshot_treats_empty_values_as_absent() {
            let mut adapter = KdeProxyAdapter::with_runner(seeded(), "6");
            let kde = adapter.snapshot().unwrap().kde.unwrap();
            assert_eq!(kde.proxy_type.as_deref(), Some("0"));
            assert_eq!(kde.no_proxy_for.as_deref(), Some("localhost,10.0.0.0/8"));
            assert_eq!(kde.http_proxy, None);
        }

        #[test]
        fn apply_writes_kio_style_targets_and_notifies() {
            let mut adapter = KdeProxyAdapter::with_runner(seeded(), "6");
            adapter
                .apply(
                    "http=127.0.0.1:8080;socks=127.0.0.1:1080",
                    "localhost;*.local",
                )
                .unwrap();
            let values = &adapter.runner().values;
            assert_eq!(values["ProxyType"], "1");
            assert_eq!(values["httpProxy"], "http://127.0.0.1 8080");
            assert_eq!(values["socksProxy"], "socks://127.0.0.1 1080");
            assert_eq!(values["NoProxyFor"], "localhost,*.local");
            assert!(!values.contains_key("httpsProxy"));
            assert_eq!(adapter.runner().notified, 1);
        }

        #[test]
        fn restore_deletes_keys_that_were_absent() {
            let mut adapter = KdeProxyAdapter::with_runner(seeded(), "6");
            let snapshot = adapter.snapshot().unwrap();
            adapter.apply("socks=127.0.0.1:1080", "x").unwrap();
            adapter.restore(&snapshot).unwrap();
            let values = &adapter.runner().values;
            assert_eq!(values["ProxyType"], "0");
            assert_eq!(values["NoProxyFor"], "localhost,10.0.0.0/8");
            assert!(!values.contains_key("socksProxy"));
            assert_eq!(adapter.snapshot().unwrap(), snapshot);
        }

        #[test]
        fn rejects_non_loopback_targets_without_writing() {
            let mut adapter = KdeProxyAdapter::with_runner(seeded(), "6");
            assert!(adapter.apply("socks=10.1.1.1:1080", "").is_err());
            assert!(adapter
                .runner()
                .calls
                .iter()
                .all(|c| !c.starts_with("kwriteconfig")));
        }

        #[test]
        fn proxy_type_is_switched_last() {
            let mut adapter = KdeProxyAdapter::with_runner(seeded(), "6");
            adapter.apply("socks=127.0.0.1:1080", "").unwrap();
            let writes: Vec<&String> = adapter
                .runner()
                .calls
                .iter()
                .filter(|c| c.starts_with("kwriteconfig"))
                .collect();
            assert!(writes.last().unwrap().contains("ProxyType"));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::system_proxy::{
        ProxyAdapter, ProxySnapshot, ProxyStateDocument, SystemProxyManager,
    };
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-proxy-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[derive(Default)]
    struct FakeAdapter {
        snapshot: ProxySnapshot,
        fail_apply: bool,
        fail_restore: bool,
        calls: Vec<String>,
        store_path: Option<PathBuf>,
        ownership_seen_during_apply: Option<bool>,
        defaults: Vec<String>,
    }

    impl ProxyAdapter for FakeAdapter {
        fn default_bypass(&self) -> Vec<String> {
            self.defaults.clone()
        }
        fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
            Ok(self.snapshot.clone())
        }
        fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
            self.calls.push(format!("apply:{server}|{bypass}"));
            if let Some(path) = &self.store_path {
                self.ownership_seen_during_apply = Some(
                    fs::read_to_string(path)
                        .ok()
                        .map(|raw| {
                            raw.contains("\"ownership\":{") || raw.contains("\"ownership\": {")
                        })
                        .unwrap_or(false),
                );
            }
            if self.fail_apply {
                return Err(io::Error::other("adapter apply failed"));
            }
            Ok(())
        }
        fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
            self.calls.push(format!(
                "restore:enable={:?}|server={:?}|override={:?}",
                snapshot.proxy_enable, snapshot.proxy_server, snapshot.proxy_override
            ));
            if self.fail_restore {
                return Err(io::Error::other("adapter restore failed"));
            }
            Ok(())
        }
    }

    fn manager(
        dir: &std::path::Path,
        adapter: FakeAdapter,
    ) -> (SystemProxyManager, Arc<Mutex<FakeAdapter>>) {
        let adapter = Arc::new(Mutex::new(adapter));
        let mgr = SystemProxyManager::with_adapter(
            dir.join("proxy-state.json"),
            Box::new(SharedAdapter(adapter.clone())),
        )
        .unwrap();
        (mgr, adapter)
    }

    struct SharedAdapter(Arc<Mutex<FakeAdapter>>);

    impl ProxyAdapter for SharedAdapter {
        fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
            self.0.lock().unwrap().snapshot()
        }
        fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
            self.0.lock().unwrap().apply(server, bypass)
        }
        fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
            self.0.lock().unwrap().restore(snapshot)
        }
        fn default_bypass(&self) -> Vec<String> {
            self.0.lock().unwrap().default_bypass()
        }
    }

    #[test]
    fn apply_prepends_adapter_default_bypass_and_dedupes_user_entries() {
        let dir = unique_dir("default-bypass");
        let adapter = FakeAdapter {
            defaults: vec!["<local>".into(), "localhost".into(), "10.*".into()],
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        mgr.apply("p1", 10808, &["10.*".into(), "*.corp.internal".into()])
            .unwrap();

        let calls = &adapter.lock().unwrap().calls;
        assert_eq!(
            calls,
            &["apply:socks=127.0.0.1:10808|<local>;localhost;10.*;*.corp.internal"]
        );
        assert_eq!(
            mgr.ownership().unwrap().applied_override,
            "<local>;localhost;10.*;*.corp.internal"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_store_loads_empty_and_malformed_fails() {
        let dir = unique_dir("load");
        let mgr = SystemProxyManager::with_adapter(
            dir.join("proxy-state.json"),
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap();
        assert!(mgr.ownership().is_none());

        let bad = dir.join("bad.json");
        fs::write(&bad, b"{ not json").unwrap();
        crate::config_security::protect_path(&bad).unwrap();
        let err = SystemProxyManager::with_adapter(
            &bad,
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let ver = dir.join("ver.json");
        fs::write(&ver, br#"{"version": 99, "ownership": null}"#).unwrap();
        crate::config_security::protect_path(&ver).unwrap();
        let err = SystemProxyManager::with_adapter(
            &ver,
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_persists_ownership_before_adapter_call() {
        let dir = unique_dir("apply");
        let store = dir.join("proxy-state.json");
        let adapter = FakeAdapter {
            snapshot: ProxySnapshot {
                proxy_enable: Some(0),
                proxy_server: None,
                proxy_override: Some("localhost".into()),
                ..Default::default()
            },
            store_path: Some(store.clone()),
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        mgr.apply("p1", 10808, &["<local>".into(), "10.*".into()])
            .unwrap();

        assert_eq!(
            adapter.lock().unwrap().ownership_seen_during_apply,
            Some(true)
        );
        let calls = &adapter.lock().unwrap().calls;
        assert_eq!(calls, &["apply:socks=127.0.0.1:10808|<local>;10.*"]);

        let owner = mgr.ownership().unwrap();
        assert_eq!(owner.profile_id, "p1");
        assert_eq!(owner.applied_server, "socks=127.0.0.1:10808");
        assert_eq!(owner.applied_override, "<local>;10.*");
        assert_eq!(owner.snapshot.proxy_enable, Some(0));
        assert_eq!(owner.snapshot.proxy_server, None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_rejects_second_owner() {
        let dir = unique_dir("conflict");
        let (mut mgr, _adapter) = manager(&dir, FakeAdapter::default());
        mgr.apply("p1", 10808, &[]).unwrap();
        let err = mgr.apply("p2", 10809, &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(mgr.ownership().unwrap().profile_id, "p1");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_failure_rolls_back_snapshot_and_clears_ownership() {
        let dir = unique_dir("rollback");
        let adapter = FakeAdapter {
            fail_apply: true,
            snapshot: ProxySnapshot {
                proxy_enable: Some(1),
                proxy_server: Some("old".into()),
                proxy_override: None,
                ..Default::default()
            },
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        let err = mgr.apply("p1", 10808, &[]).unwrap_err();
        assert!(err.to_string().contains("adapter apply failed"));

        let calls = adapter.lock().unwrap().calls.clone();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with("apply:"));
        assert_eq!(
            calls[1],
            "restore:enable=Some(1)|server=Some(\"old\")|override=None"
        );
        assert!(mgr.ownership().is_none());
        let doc: ProxyStateDocument =
            serde_json::from_str(&fs::read_to_string(dir.join("proxy-state.json")).unwrap())
                .unwrap();
        assert!(doc.ownership.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_failure_with_restore_failure_keeps_ownership() {
        let dir = unique_dir("rollback-fail");
        let adapter = FakeAdapter {
            fail_apply: true,
            fail_restore: true,
            snapshot: ProxySnapshot {
                proxy_enable: Some(1),
                proxy_server: Some("old".into()),
                proxy_override: None,
                ..Default::default()
            },
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        let err = mgr.apply("p1", 10808, &[]).unwrap_err();
        assert!(err.to_string().contains("adapter apply failed"));
        assert!(err.to_string().contains("adapter restore failed"));

        let calls = adapter.lock().unwrap().calls.clone();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with("apply:"));
        assert!(calls[1].starts_with("restore:"));

        let owner = mgr
            .ownership()
            .expect("ownership must survive failed rollback");
        assert_eq!(owner.profile_id, "p1");
        let doc: ProxyStateDocument =
            serde_json::from_str(&fs::read_to_string(dir.join("proxy-state.json")).unwrap())
                .unwrap();
        assert_eq!(doc.ownership.unwrap().profile_id, "p1");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restore_requires_owner_and_restores_snapshot() {
        let dir = unique_dir("restore");
        let adapter = FakeAdapter {
            snapshot: ProxySnapshot {
                proxy_enable: None,
                proxy_server: None,
                proxy_override: None,
                ..Default::default()
            },
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        mgr.apply("p1", 10808, &["<local>".into()]).unwrap();

        let err = mgr.restore("other").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(mgr.ownership().is_some());

        mgr.restore("p1").unwrap();
        let calls = &adapter.lock().unwrap().calls;
        assert_eq!(
            calls.last().unwrap(),
            "restore:enable=None|server=None|override=None"
        );
        assert!(mgr.ownership().is_none());

        let err = mgr.restore("p1").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restore_any_clears_stale_ownership() {
        let dir = unique_dir("any");
        let (mut mgr, adapter) = manager(&dir, FakeAdapter::default());
        mgr.apply("gone", 10808, &[]).unwrap();
        mgr.restore_any().unwrap();
        assert!(mgr.ownership().is_none());
        assert!(adapter
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c.starts_with("restore:")));

        let mut mgr2 = SystemProxyManager::with_adapter(
            dir.join("proxy-state.json"),
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap();
        mgr2.restore_any().unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn snapshot_matches_compares_exactly() {
        use crate::system_proxy::snapshot_matches;
        let base = ProxySnapshot {
            proxy_enable: Some(1),
            proxy_server: Some("socks=127.0.0.1:10808".into()),
            proxy_override: Some("<local>".into()),
            ..Default::default()
        };
        assert!(snapshot_matches(&base, &base.clone()));

        let mut different = base.clone();
        different.proxy_enable = Some(0);
        assert!(!snapshot_matches(&base, &different));

        let mut missing = base.clone();
        missing.proxy_server = None;
        assert!(!snapshot_matches(&base, &missing));

        let empty = ProxySnapshot::default();
        assert!(snapshot_matches(&empty, &ProxySnapshot::default()));
    }

    #[test]
    fn applied_state_file_is_acl_protected() {
        let dir = unique_dir("acl");
        let store = dir.join("proxy-state.json");
        let (mut mgr, _) = manager(&dir, FakeAdapter::default());
        mgr.apply("p1", 10808, &["<local>".into()]).unwrap();

        #[cfg(windows)]
        {
            let protection = crate::config_security::inspect_path_protection(&store).unwrap();
            assert!(protection.protected_dacl);
            assert!(protection.current_user);
            assert!(protection.system);
            assert!(protection.administrators);
        }
        #[cfg(not(windows))]
        {
            assert!(store.exists());
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ownership_survives_manager_reload() {
        let dir = unique_dir("reload");
        let store = dir.join("proxy-state.json");
        let (mut mgr, _) = manager(&dir, FakeAdapter::default());
        mgr.apply("p1", 10808, &["127.*".into()]).unwrap();
        drop(mgr);

        let mgr = SystemProxyManager::with_adapter(
            &store,
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap();
        let owner = mgr.ownership().unwrap();
        assert_eq!(owner.profile_id, "p1");
        assert_eq!(owner.applied_server, "socks=127.0.0.1:10808");
        fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::macos::*;
    use super::*;
    use std::collections::HashMap;

    /// Records every networksetup invocation and answers reads from a script.
    #[derive(Default)]
    struct FakeNetworksetup {
        answers: HashMap<String, String>,
        writes: Vec<Vec<String>>,
    }
    impl NetworksetupRunner for FakeNetworksetup {
        fn run(&mut self, args: &[String]) -> io::Result<String> {
            let key = args.join(" ");
            if args[0].starts_with("-set") {
                self.writes.push(args.to_vec());
                return Ok(String::new());
            }
            self.answers
                .get(&key)
                .cloned()
                .ok_or_else(|| io::Error::other(format!("unexpected read {key}")))
        }
    }

    const ORDER: &str = "An asterisk (*) denotes that a network service is disabled.\n\
(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n\
(2) incy\n(Hardware Port: com.wireguard.macos, Device: )\n\n\
(*) iPhone USB\n(Hardware Port: iPhone USB, Device: en9)\n\n\
(3) USB LAN\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n";

    fn proxy(enabled: bool, server: &str, port: u16) -> String {
        format!(
            "Enabled: {}\nServer: {server}\nPort: {port}\nAuthenticated Proxy Enabled: 0\n",
            if enabled { "Yes" } else { "No" }
        )
    }

    fn fake() -> FakeNetworksetup {
        let mut fake = FakeNetworksetup::default();
        fake.answers
            .insert("-listnetworkserviceorder".into(), ORDER.into());
        for service in ["Wi-Fi", "USB LAN"] {
            fake.answers
                .insert(format!("-getwebproxy {service}"), proxy(false, "", 0));
            fake.answers.insert(
                format!("-getsecurewebproxy {service}"),
                proxy(true, "corp.proxy", 3128),
            );
            fake.answers.insert(
                format!("-getsocksfirewallproxy {service}"),
                proxy(false, "", 0),
            );
            fake.answers.insert(
                format!("-getproxybypassdomains {service}"),
                "*.local\n169.254/16\n".into(),
            );
        }
        fake
    }

    #[test]
    fn hardware_services_skip_disabled_and_vpn_entries() {
        assert_eq!(hardware_services(ORDER), vec!["Wi-Fi", "USB LAN"]);
    }

    #[test]
    fn snapshot_captures_every_proxy_kind_and_bypass_list() {
        let mut adapter = MacProxyAdapter::with_runner(fake());
        let snapshot = adapter.snapshot().unwrap();
        assert_eq!(snapshot.macos_services.len(), 2);
        let wifi = &snapshot.macos_services[0];
        assert_eq!(wifi.service, "Wi-Fi");
        assert!(!wifi.web.enabled);
        assert_eq!(
            wifi.secure_web,
            MacProxyEndpoint {
                enabled: true,
                server: "corp.proxy".into(),
                port: 3128
            }
        );
        assert_eq!(wifi.bypass, vec!["*.local", "169.254/16"]);
    }

    #[test]
    fn apply_points_http_https_and_socks_at_loopback_on_each_service() {
        let mut adapter = MacProxyAdapter::with_runner(fake());
        adapter
            .apply(
                "http=127.0.0.1:20809;https=127.0.0.1:20809;socks=127.0.0.1:20808",
                "localhost;*.corp",
            )
            .unwrap();
        let writes = &adapter.runner().writes;
        for service in ["Wi-Fi", "USB LAN"] {
            for (verb, port) in [
                ("-setwebproxy", "20809"),
                ("-setsecurewebproxy", "20809"),
                ("-setsocksfirewallproxy", "20808"),
            ] {
                assert!(writes.contains(&vec![
                    verb.to_string(),
                    service.to_string(),
                    "127.0.0.1".into(),
                    port.into()
                ]));
            }
            assert!(writes.contains(&vec![
                "-setproxybypassdomains".to_string(),
                service.to_string(),
                "localhost".into(),
                "*.corp".into()
            ]));
        }
        assert!(!writes.iter().any(|w| w.contains(&"incy".to_string())));
    }

    #[test]
    fn apply_rejects_non_loopback_targets() {
        let mut adapter = MacProxyAdapter::with_runner(fake());
        assert!(adapter.apply("socks=192.0.2.1:1080", "").is_err());
        assert!(adapter.runner().writes.is_empty());
    }

    #[test]
    fn restore_reinstates_previous_values_and_disables_unused_kinds() {
        let mut adapter = MacProxyAdapter::with_runner(fake());
        let snapshot = adapter.snapshot().unwrap();
        adapter.restore(&snapshot).unwrap();
        let writes = &adapter.runner().writes;
        assert!(writes.contains(&vec![
            "-setsecurewebproxy".to_string(),
            "Wi-Fi".into(),
            "corp.proxy".into(),
            "3128".into()
        ]));
        assert!(writes.contains(&vec![
            "-setwebproxystate".to_string(),
            "Wi-Fi".into(),
            "off".into()
        ]));
        assert!(writes.contains(&vec![
            "-setsocksfirewallproxystate".to_string(),
            "USB LAN".into(),
            "off".into()
        ]));
        assert!(writes.contains(&vec![
            "-setproxybypassdomains".to_string(),
            "Wi-Fi".into(),
            "*.local".into(),
            "169.254/16".into()
        ]));
    }

    #[test]
    fn manager_round_trip_persists_and_restores_through_mac_adapter() {
        let dir = std::env::temp_dir().join(format!("netorch-macproxy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut manager = SystemProxyManager::with_adapter(
            dir.join("proxy.json"),
            Box::new(MacProxyAdapter::with_runner(fake())),
        )
        .unwrap();
        manager
            .apply_with_http("profile-a", 20808, Some(20809), &[])
            .unwrap();
        let owner = manager.ownership().unwrap();
        assert_eq!(
            owner.applied_server,
            "http=127.0.0.1:20809;https=127.0.0.1:20809;socks=127.0.0.1:20808"
        );
        assert_eq!(owner.snapshot.macos_services.len(), 2);
        manager.restore("profile-a").unwrap();
        assert!(manager.ownership().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
