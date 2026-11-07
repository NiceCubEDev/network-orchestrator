#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
        TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn to_io_error(err: windows::core::Error) -> io::Error {
        let hresult = err.code().0;
        if hresult < 0 && (hresult & 0x1FFF_0000) == (0x0007 << 16) {
            io::Error::from_raw_os_error(hresult & 0xFFFF)
        } else {
            io::Error::other(err.to_string())
        }
    }

    pub fn is_elevated() -> io::Result<bool> {
        unsafe {
            let mut raw = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw).map_err(to_io_error)?;
            let token = TokenHandle(raw);
            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = 0u32;
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some(&mut elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            )
            .map_err(to_io_error)?;
            Ok(elevation.TokenIsElevated != 0)
        }
    }

    /// Enable SeBackupPrivilege on the current process token. Required to read
    /// ACL-protected files (e.g. WireGuard `.conf.dpapi` configs owned by
    /// SYSTEM) even when the process is elevated. Returns `Ok(())` if the
    /// privilege was already enabled or was successfully enabled.
    pub fn enable_backup_privilege() -> io::Result<()> {
        unsafe {
            let mut raw = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw,
            )
            .map_err(to_io_error)?;
            let token = TokenHandle(raw);

            let backup_name: Vec<u16> = OsStr::new("SeBackupPrivilege")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut luid = LUID::default();
            LookupPrivilegeValueW(
                PCWSTR::null(),
                PCWSTR::from_raw(backup_name.as_ptr()),
                &mut luid,
            )
            .map_err(to_io_error)?;

            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(
                token.0,
                false,
                Some(&mut tp as *mut TOKEN_PRIVILEGES),
                0,
                None,
                None,
            )
            .map_err(to_io_error)?;
            Ok(())
        }
    }

    pub fn restart_elevated() -> io::Result<()> {
        let exe = std::env::current_exe()?;
        let file: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let verb: Vec<u16> = OsStr::new("runas")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let result = unsafe {
            ShellExecuteW(
                HWND::default(),
                PCWSTR::from_raw(verb.as_ptr()),
                PCWSTR::from_raw(file.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        if result.0 as usize <= 32 {
            return Err(io::Error::other(format!(
                "ShellExecuteW runas failed with code {}",
                result.0 as usize
            )));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use imp::{enable_backup_privilege, is_elevated, restart_elevated};

#[cfg(not(windows))]
pub fn is_elevated() -> std::io::Result<bool> {
    Ok(true)
}

#[cfg(not(windows))]
pub fn restart_elevated() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "elevation relaunch is only supported on Windows",
    ))
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn enable_backup_privilege() -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_elevated_returns_ok() {
        assert!(is_elevated().is_ok());
    }
}
