//! Recovery before Tauri's single-instance plugin can block on a stale UI.

use std::marker::PhantomData;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, BOOL, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND,
    ERROR_SUCCESS, HANDLE, HWND, LPARAM, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT, WPARAM,
};
use windows::Win32::Globalization::{CompareStringOrdinal, GetUserDefaultUILanguage, CSTR_EQUAL};
use windows::Win32::System::DataExchange::COPYDATASTRUCT;
use windows::Win32::System::Threading::{
    CreateMutexW, OpenMutexW, OpenProcess, QueryFullProcessImageNameW, ReleaseMutex,
    TerminateProcess, WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, SYNCHRONIZATION_SYNCHRONIZE,
};
use windows::Win32::UI::Controls::{
    TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION,
    TDF_SIZE_TO_CONTENT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, FindWindowW, GetForegroundWindow, GetWindow, GetWindowLongW,
    GetWindowThreadProcessId, IsIconic, IsWindowVisible, MessageBoxW, PostMessageW,
    SendMessageTimeoutW, SetForegroundWindow, ShowWindowAsync, GWL_EXSTYLE, GWL_STYLE, GW_OWNER,
    IDCANCEL, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, SMTO_ABORTIFHUNG, SMTO_BLOCK,
    SMTO_ERRORONEXIT, SW_RESTORE, SW_SHOW, WM_CLOSE, WM_COPYDATA, WM_NULL, WS_CAPTION,
    WS_EX_TOOLWINDOW,
};

const TITLE: &str = "Network Orchestrator is already running";
const OPEN_ID: i32 = 1001;
const RESTART_ID: i32 = 1002;
const FORCE_ID: i32 = 1003;
const STARTUP_WAIT: Duration = Duration::from_millis(1500);
const GRACEFUL_WAIT_MS: u32 = 5000;
const MESSAGE_TIMEOUT_MS: u32 = 750;
const RESTART_ARGUMENT: &str = "--netorch-request-restart";
// Wire format used by the pinned tauri-plugin-single-instance 2.4.5.
const SINGLE_INSTANCE_DATA: usize = 1542;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Choice {
    Open,
    Restart,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryError {
    Unavailable,
    Unverified,
    Permission,
    StillStarting,
    Busy,
    DidNotExit,
    Dialog,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenOutcome {
    Opened,
    Exited,
}

trait GracefulRestart {
    fn request_restart(&mut self) -> Result<(), RecoveryError>;
    fn close_main_window(&mut self) -> Result<(), RecoveryError>;
    fn wait_for_exit(&mut self) -> Result<bool, RecoveryError>;
}

fn request_graceful_restart(platform: &mut impl GracefulRestart) -> Result<bool, RecoveryError> {
    match platform.request_restart() {
        Ok(()) | Err(RecoveryError::Unavailable) => {}
        Err(error) => return Err(error),
    }
    let close_result = platform.close_main_window();
    // The explicit-exit request may already have destroyed the main window.
    // Process completion, rather than the IPC acknowledgement, proves success.
    if platform.wait_for_exit()? {
        Ok(true)
    } else {
        close_result.map(|()| false)
    }
}

fn restart_payload(cwd: &str, executable: &str) -> Vec<u8> {
    format!("{cwd}|{executable}|{RESTART_ARGUMENT}\0").into_bytes()
}

trait RecoveryPlatform {
    type Instance;

    fn detect(&mut self) -> Result<Option<Self::Instance>, RecoveryError>;
    fn choose(&mut self) -> Result<Choice, RecoveryError>;
    fn open(&mut self, instance: &Self::Instance) -> Result<OpenOutcome, RecoveryError>;
    fn close(&mut self, instance: &Self::Instance) -> Result<bool, RecoveryError>;
    fn confirm_force(&mut self) -> Result<bool, RecoveryError>;
    fn force_quit(&mut self, instance: &Self::Instance) -> Result<(), RecoveryError>;
    fn show_error(&mut self, error: RecoveryError);
}

fn recover(platform: &mut impl RecoveryPlatform) -> bool {
    let instance = match platform.detect() {
        Ok(None) => return true,
        Ok(Some(instance)) => instance,
        Err(error) => {
            platform.show_error(error);
            return false;
        }
    };
    loop {
        let result = match platform.choose() {
            Ok(Choice::Cancel) => return false,
            Ok(Choice::Open) => match platform.open(&instance) {
                Ok(OpenOutcome::Opened) => return false,
                Ok(OpenOutcome::Exited) => return true,
                Err(error) => {
                    platform.show_error(error);
                    continue;
                }
            },
            Ok(Choice::Restart) => match platform.close(&instance) {
                Ok(true) => return true,
                Ok(false) => match platform.confirm_force() {
                    Ok(false) => continue,
                    Ok(true) => platform.force_quit(&instance),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        match result {
            Ok(()) => return true,
            Err(error) => {
                platform.show_error(error);
                return false;
            }
        }
    }
}

/// Run before constructing Tauri: its pinned Windows single-instance plugin
/// sends an unbounded synchronous message, even when no main window exists.
pub fn prepare_launch(identifier: &str) -> Option<LaunchGuard> {
    let mut platform = NativePlatform { identifier };
    let guard = match acquire_startup_gate(identifier, 1500) {
        Ok(guard) => guard,
        Err(error) => {
            platform.show_error(error);
            return None;
        }
    };
    recover(&mut platform).then_some(guard)
}

/// Keep this guard until Builder::build has registered the plugin's helper.
/// A different mutex serializes preflight without retaining the plugin mutex.
#[must_use]
pub struct LaunchGuard {
    handle: OwnedHandle,
    // Windows mutex ownership must be released on the acquiring thread.
    _same_thread: PhantomData<Rc<()>>,
}

impl Drop for LaunchGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.handle.0);
        }
    }
}

fn acquire_startup_gate(identifier: &str, timeout: u32) -> Result<LaunchGuard, RecoveryError> {
    let name = wide(&format!("{identifier}-startup"));
    let handle = OwnedHandle(
        unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }.map_err(native_error)?,
    );
    match unsafe { WaitForSingleObject(handle.0, timeout) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(LaunchGuard {
            handle,
            _same_thread: PhantomData,
        }),
        WAIT_TIMEOUT => Err(RecoveryError::Busy),
        _ => Err(RecoveryError::Unverified),
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct ExistingInstance {
    process: OwnedHandle,
    pid: u32,
    helper: HWND,
}

struct NativePlatform<'a> {
    identifier: &'a str,
}

impl RecoveryError {
    fn text(self) -> &'static str {
        match self {
            Self::Unavailable => "The existing application has no available main window or is not responding. You can restart it instead.",
            Self::Unverified => "The existing application could not be verified. It will not be closed.",
            Self::Permission => "The existing application cannot be controlled. Run Network Orchestrator as administrator and try again.",
            Self::StillStarting => "The existing application is still starting. Try again shortly.",
            Self::Busy => "Another launch or recovery is already in progress. Close its dialog or try again shortly.",
            Self::DidNotExit => "The existing application did not exit. It has not been restarted.",
            Self::Dialog => "The recovery dialog could not be displayed.",
        }
    }
}

impl NativePlatform<'_> {
    fn helper(&self) -> Option<HWND> {
        let class = wide(&format!("{}-sic", self.identifier));
        let title = wide(&format!("{}-siw", self.identifier));
        unsafe { FindWindowW(PCWSTR(class.as_ptr()), PCWSTR(title.as_ptr())) }.ok()
    }

    fn mutex_exists(&self) -> Result<bool, RecoveryError> {
        let name = wide(&format!("{}-sim", self.identifier));
        match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, PCWSTR(name.as_ptr())) } {
            // Never retain this probe handle: it would keep the named mutex
            // alive after the old process exits and confuse the plugin.
            Ok(handle) => {
                drop(OwnedHandle(handle));
                Ok(true)
            }
            Err(error) if error.code() == ERROR_FILE_NOT_FOUND.to_hresult() => Ok(false),
            Err(error) => Err(native_error(error)),
        }
    }

    fn released(&self, instance: &ExistingInstance) -> Result<(), RecoveryError> {
        if !process_exited(instance, 0)? {
            return Err(RecoveryError::DidNotExit);
        }
        let deadline = Instant::now() + STARTUP_WAIT;
        loop {
            if self.helper().is_none() && !self.mutex_exists()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(RecoveryError::StillStarting);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl RecoveryPlatform for NativePlatform<'_> {
    type Instance = ExistingInstance;

    fn detect(&mut self) -> Result<Option<ExistingInstance>, RecoveryError> {
        let deadline = Instant::now() + STARTUP_WAIT;
        loop {
            if let Some(helper) = self.helper() {
                let pid = window_pid(helper);
                if pid == 0 || pid == std::process::id() {
                    return Err(RecoveryError::Unverified);
                }
                let process = OwnedHandle(
                    unsafe {
                        OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                            false,
                            pid,
                        )
                    }
                    .map_err(native_error)?,
                );
                // The held handle identifies this process throughout the
                // dialog, including when its window disappears or it exits.
                verify_executable(process.0)?;
                if window_pid(helper) != pid {
                    return Err(RecoveryError::Unverified);
                }
                return Ok(Some(ExistingInstance {
                    process,
                    pid,
                    helper,
                }));
            }
            if !self.mutex_exists()? {
                return Ok(None);
            }
            if Instant::now() >= deadline {
                return Err(RecoveryError::StillStarting);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn choose(&mut self) -> Result<Choice, RecoveryError> {
        let button = task_dialog(
            TITLE,
            "An existing instance was found. Open its window or restart the application.",
            &[
                (OPEN_ID, "Open existing window"),
                (RESTART_ID, "Restart application"),
                (IDCANCEL.0, "Cancel"),
            ],
        )?;
        Ok(match button {
            OPEN_ID => Choice::Open,
            RESTART_ID => Choice::Restart,
            _ => Choice::Cancel,
        })
    }

    fn open(&mut self, instance: &ExistingInstance) -> Result<OpenOutcome, RecoveryError> {
        if process_exited(instance, 0)? {
            self.released(instance)?;
            return Ok(OpenOutcome::Exited);
        }
        let window = main_window(instance)?.ok_or(RecoveryError::Unavailable)?;
        probe_window(window, instance.pid)?;
        unsafe {
            // Asynchronous restoration cannot block on the old UI thread.
            let show = if IsIconic(window).as_bool() {
                SW_RESTORE
            } else {
                SW_SHOW
            };
            let _ = ShowWindowAsync(window, show);
            let _ = SetForegroundWindow(window);
        }
        let deadline = Instant::now() + Duration::from_millis(1000);
        loop {
            if window_pid(window) != instance.pid {
                return Err(RecoveryError::Unavailable);
            }
            let foreground = unsafe { GetForegroundWindow() };
            if unsafe { IsWindowVisible(window).as_bool() && !IsIconic(window).as_bool() }
                && window_pid(foreground) == instance.pid
            {
                return Ok(OpenOutcome::Opened);
            }
            if Instant::now() >= deadline {
                return Err(RecoveryError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    fn close(&mut self, instance: &ExistingInstance) -> Result<bool, RecoveryError> {
        if process_exited(instance, 0)? {
            self.released(instance)?;
            return Ok(true);
        }
        verify_executable(instance.process.0)?;
        if request_graceful_restart(&mut NativeRestart { instance })? {
            self.released(instance)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn confirm_force(&mut self) -> Result<bool, RecoveryError> {
        Ok(task_dialog(
            "Force quit the existing application?",
            "Force quitting skips normal cleanup. Active VPN connections or routes may remain, and unsaved changes may be lost.",
            &[(FORCE_ID, "Force quit and restart"), (IDCANCEL.0, "Cancel")],
        )? == FORCE_ID)
    }

    fn force_quit(&mut self, instance: &ExistingInstance) -> Result<(), RecoveryError> {
        if process_exited(instance, 0)? {
            return self.released(instance);
        }
        // Request destructive access only after the separate confirmation.
        // The original process handle stays held, preventing PID reuse.
        let terminate = OwnedHandle(
            unsafe {
                OpenProcess(
                    PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    false,
                    instance.pid,
                )
            }
            .map_err(native_error)?,
        );
        verify_executable(terminate.0)?;
        unsafe { TerminateProcess(terminate.0, 1) }.map_err(native_error)?;
        if !process_exited(instance, GRACEFUL_WAIT_MS)? {
            return Err(RecoveryError::DidNotExit);
        }
        self.released(instance)
    }

    fn show_error(&mut self, error: RecoveryError) {
        if task_dialog(TITLE, error.text(), &[(1, "Close")]).is_err() {
            // Keep failures visible even if Common Controls initialization
            // prevented TaskDialog from being created before Tauri starts.
            let title = wide(&localized(TITLE));
            let body = wide(&localized(error.text()));
            unsafe {
                MessageBoxW(
                    HWND::default(),
                    PCWSTR(body.as_ptr()),
                    PCWSTR(title.as_ptr()),
                    MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
                );
            }
        }
    }
}

struct NativeRestart<'a> {
    instance: &'a ExistingInstance,
}

impl GracefulRestart for NativeRestart<'_> {
    fn request_restart(&mut self) -> Result<(), RecoveryError> {
        if process_exited(self.instance, 0)? {
            return Ok(());
        }
        if window_pid(self.instance.helper) != self.instance.pid {
            return Err(RecoveryError::Unverified);
        }
        let cwd = std::env::current_dir().unwrap_or_default();
        let executable = std::env::current_exe().map_err(|_| RecoveryError::Unverified)?;
        let mut payload = restart_payload(&cwd.to_string_lossy(), &executable.to_string_lossy());
        let data = COPYDATASTRUCT {
            dwData: SINGLE_INSTANCE_DATA,
            cbData: payload.len() as u32,
            lpData: payload.as_mut_ptr().cast(),
        };
        unsafe {
            SetLastError(ERROR_SUCCESS);
            if SendMessageTimeoutW(
                self.instance.helper,
                WM_COPYDATA,
                WPARAM(0),
                LPARAM(&data as *const _ as isize),
                SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
                MESSAGE_TIMEOUT_MS,
                None,
            )
            .0 == 0
            {
                return Err(if GetLastError() == ERROR_ACCESS_DENIED {
                    RecoveryError::Permission
                } else {
                    RecoveryError::Unavailable
                });
            }
        }
        Ok(())
    }

    fn close_main_window(&mut self) -> Result<(), RecoveryError> {
        if process_exited(self.instance, 0)? {
            return Ok(());
        }
        if let Some(window) = main_window(self.instance)? {
            if window_pid(window) != self.instance.pid {
                return Err(RecoveryError::Unverified);
            }
            // Older versions ignore the restart argument. Close only their
            // real main window; never destroy the single-instance helper.
            unsafe { PostMessageW(window, WM_CLOSE, WPARAM(0), LPARAM(0)) }
                .map_err(native_error)?;
        }
        Ok(())
    }

    fn wait_for_exit(&mut self) -> Result<bool, RecoveryError> {
        process_exited(self.instance, GRACEFUL_WAIT_MS)
    }
}

fn process_exited(instance: &ExistingInstance, timeout: u32) -> Result<bool, RecoveryError> {
    match unsafe { WaitForSingleObject(instance.process.0, timeout) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(RecoveryError::Unverified),
    }
}

fn verify_executable(process: HANDLE) -> Result<(), RecoveryError> {
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(native_error)?;
    let process_path = std::ffi::OsString::from_wide(&buffer[..length as usize]);
    let current = std::env::current_exe().map_err(|_| RecoveryError::Unverified)?;
    let current = current
        .canonicalize()
        .map_err(|_| RecoveryError::Unverified)?;
    let actual = Path::new(&process_path)
        .canonicalize()
        .map_err(|_| RecoveryError::Unverified)?;
    if same_path(&actual, &current) {
        Ok(())
    } else {
        Err(RecoveryError::Unverified)
    }
}

fn same_path(first: &Path, second: &Path) -> bool {
    let first: Vec<u16> = first.as_os_str().encode_wide().collect();
    let second: Vec<u16> = second.as_os_str().encode_wide().collect();
    unsafe { CompareStringOrdinal(&first, &second, true) == CSTR_EQUAL }
}

fn window_pid(window: HWND) -> u32 {
    let mut pid = 0;
    unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
    pid
}

fn real_main_window(
    same_process: bool,
    helper: bool,
    owner: bool,
    tool: bool,
    caption: bool,
) -> bool {
    same_process && !helper && !owner && !tool && caption
}

fn main_window(instance: &ExistingInstance) -> Result<Option<HWND>, RecoveryError> {
    struct Search<'a> {
        instance: &'a ExistingInstance,
        result: Option<HWND>,
    }
    unsafe extern "system" fn visit(window: HWND, state: LPARAM) -> BOOL {
        let search = &mut *(state.0 as *mut Search<'_>);
        let owner = GetWindow(window, GW_OWNER).is_ok();
        let tool = GetWindowLongW(window, GWL_EXSTYLE) as u32 & WS_EX_TOOLWINDOW.0 != 0;
        let caption = GetWindowLongW(window, GWL_STYLE) as u32 & WS_CAPTION.0 == WS_CAPTION.0;
        if real_main_window(
            window_pid(window) == search.instance.pid,
            window == search.instance.helper,
            owner,
            tool,
            caption,
        ) && (search.result.is_none() || IsWindowVisible(window).as_bool())
        {
            search.result = Some(window);
        }
        BOOL(1)
    }
    let mut search = Search {
        instance,
        result: None,
    };
    unsafe { EnumWindows(Some(visit), LPARAM(&mut search as *mut _ as isize)) }
        .map_err(native_error)?;
    Ok(search.result)
}

fn probe_window(window: HWND, pid: u32) -> Result<(), RecoveryError> {
    if window_pid(window) != pid {
        return Err(RecoveryError::Unverified);
    }
    unsafe {
        SetLastError(ERROR_SUCCESS);
        if SendMessageTimeoutW(
            window,
            WM_NULL,
            WPARAM(0),
            LPARAM(0),
            SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
            MESSAGE_TIMEOUT_MS,
            None,
        )
        .0 == 0
        {
            if GetLastError() == ERROR_ACCESS_DENIED {
                return Err(RecoveryError::Permission);
            }
            return Err(RecoveryError::Unavailable);
        }
    }
    Ok(())
}

fn native_error(error: windows::core::Error) -> RecoveryError {
    if error.code() == ERROR_ACCESS_DENIED.to_hresult() {
        RecoveryError::Permission
    } else {
        RecoveryError::Unverified
    }
}

fn task_dialog(title: &str, body: &str, buttons: &[(i32, &str)]) -> Result<i32, RecoveryError> {
    let title = wide(&localized(title));
    let body = wide(&localized(body));
    let labels: Vec<Vec<u16>> = buttons
        .iter()
        .map(|(_, key)| wide(&localized(key)))
        .collect();
    let buttons: Vec<TASKDIALOG_BUTTON> = buttons
        .iter()
        .zip(&labels)
        .map(|((id, _), label)| TASKDIALOG_BUTTON {
            nButtonID: *id,
            pszButtonText: PCWSTR(label.as_ptr()),
        })
        .collect();
    let config = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        pszMainInstruction: PCWSTR(title.as_ptr()),
        pszContent: PCWSTR(body.as_ptr()),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: if buttons.iter().any(|button| button.nButtonID == IDCANCEL.0) {
            IDCANCEL.0
        } else {
            1
        },
        ..Default::default()
    };
    let mut selected = 0;
    unsafe { TaskDialogIndirect(&config, Some(&mut selected), None, None) }
        .map_err(|_| RecoveryError::Dialog)?;
    Ok(selected)
}

pub(crate) fn localized(key: &str) -> String {
    static CATALOG: OnceLock<serde_json::Value> = OnceLock::new();
    let catalog = CATALOG.get_or_init(|| {
        let russian = unsafe { GetUserDefaultUILanguage() } & 0x03ff == 0x19;
        let json = if russian {
            include_str!("../../locales/ru.json")
        } else {
            include_str!("../../locales/en.json")
        };
        serde_json::from_str(json).unwrap_or_default()
    });
    catalog
        .get("messages")
        .and_then(|messages| messages.get(key))
        .and_then(|value| value.as_str())
        .unwrap_or(key)
        .to_owned()
}

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeRestart {
        request: Result<(), RecoveryError>,
        close: Result<(), RecoveryError>,
        exited: bool,
        actions: Vec<&'static str>,
    }

    impl GracefulRestart for FakeRestart {
        fn request_restart(&mut self) -> Result<(), RecoveryError> {
            self.actions.push("restart IPC");
            self.request
        }

        fn close_main_window(&mut self) -> Result<(), RecoveryError> {
            self.actions.push("close main");
            self.close
        }

        fn wait_for_exit(&mut self) -> Result<bool, RecoveryError> {
            self.actions.push("wait");
            Ok(self.exited)
        }
    }

    #[test]
    fn tray_restart_requests_explicit_exit_before_legacy_window_close() {
        let mut platform = FakeRestart {
            request: Ok(()),
            close: Ok(()),
            exited: true,
            actions: Vec::new(),
        };
        assert!(request_graceful_restart(&mut platform).unwrap());
        assert_eq!(platform.actions, ["restart IPC", "close main", "wait"]);
    }

    #[test]
    fn timed_out_restart_ipc_still_uses_legacy_graceful_fallback() {
        let mut platform = FakeRestart {
            request: Err(RecoveryError::Unavailable),
            close: Ok(()),
            exited: true,
            actions: Vec::new(),
        };
        assert!(request_graceful_restart(&mut platform).unwrap());
        assert_eq!(platform.actions, ["restart IPC", "close main", "wait"]);
    }

    #[test]
    fn restart_ipc_does_not_continue_with_an_unsafe_target() {
        for error in [RecoveryError::Unverified, RecoveryError::Permission] {
            let mut platform = FakeRestart {
                request: Err(error),
                close: Ok(()),
                exited: false,
                actions: Vec::new(),
            };
            assert_eq!(request_graceful_restart(&mut platform), Err(error));
            assert_eq!(platform.actions, ["restart IPC"]);
        }
    }

    #[test]
    fn graceful_restart_does_not_treat_a_delivered_request_as_process_exit() {
        let mut platform = FakeRestart {
            request: Ok(()),
            close: Ok(()),
            exited: false,
            actions: Vec::new(),
        };
        assert!(!request_graceful_restart(&mut platform).unwrap());
        assert_eq!(platform.actions, ["restart IPC", "close main", "wait"]);
    }

    #[test]
    fn restart_ipc_payload_preserves_the_pinned_plugin_protocol_and_exact_argument() {
        let payload = restart_payload(r"C:\Synthetic cwd", r"C:\Synthetic app\Orchestrator.exe");
        let text = std::ffi::CStr::from_bytes_with_nul(&payload)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            text.split('|').collect::<Vec<_>>(),
            [
                r"C:\Synthetic cwd",
                r"C:\Synthetic app\Orchestrator.exe",
                "--netorch-request-restart"
            ]
        );
    }

    fn gate_name() -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        format!(
            "netorch-test-gate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn independent_startup_gate_serializes_first_launches_and_releases_on_drop() {
        let name = gate_name();
        let guard = acquire_startup_gate(&name, 0)
            .unwrap_or_else(|_| panic!("first launch must own the gate"));
        let other_name = name.clone();
        assert!(std::thread::spawn(move || matches!(
            acquire_startup_gate(&other_name, 20),
            Err(RecoveryError::Busy)
        ))
        .join()
        .unwrap());
        drop(guard);
        assert!(
            std::thread::spawn(move || acquire_startup_gate(&name, 0).is_ok())
                .join()
                .unwrap()
        );
    }

    #[test]
    fn startup_gate_recovers_an_abandoned_owner() {
        let name = gate_name();
        let other_name = name.clone();
        let raw = std::thread::spawn(move || {
            let name = wide(&format!("{other_name}-startup"));
            let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }.unwrap();
            assert_eq!(unsafe { WaitForSingleObject(handle, 0) }, WAIT_OBJECT_0);
            // Keep the object alive while the owning synthetic thread exits.
            handle.0 as isize
        })
        .join()
        .unwrap();
        let _original = OwnedHandle(HANDLE(raw as *mut _));
        assert!(acquire_startup_gate(&name, 0).is_ok());
    }

    struct FakePlatform {
        existing: Result<Option<()>, RecoveryError>,
        choices: VecDeque<Choice>,
        opened: Result<OpenOutcome, RecoveryError>,
        closed: Result<bool, RecoveryError>,
        force_confirmed: bool,
        force_result: Result<(), RecoveryError>,
        actions: Vec<&'static str>,
        errors: Vec<RecoveryError>,
    }

    impl Default for FakePlatform {
        fn default() -> Self {
            Self {
                existing: Ok(Some(())),
                choices: VecDeque::from([Choice::Cancel]),
                opened: Ok(OpenOutcome::Opened),
                closed: Ok(false),
                force_confirmed: false,
                force_result: Ok(()),
                actions: Vec::new(),
                errors: Vec::new(),
            }
        }
    }

    impl RecoveryPlatform for FakePlatform {
        type Instance = ();

        fn detect(&mut self) -> Result<Option<()>, RecoveryError> {
            self.actions.push("detect");
            self.existing
        }

        fn choose(&mut self) -> Result<Choice, RecoveryError> {
            self.actions.push("choose");
            Ok(self
                .choices
                .pop_front()
                .expect("a recovery choice was expected"))
        }

        fn open(&mut self, _: &()) -> Result<OpenOutcome, RecoveryError> {
            self.actions.push("open");
            self.opened
        }

        fn close(&mut self, _: &()) -> Result<bool, RecoveryError> {
            self.actions.push("close");
            self.closed
        }

        fn confirm_force(&mut self) -> Result<bool, RecoveryError> {
            self.actions.push("confirm force");
            Ok(self.force_confirmed)
        }

        fn force_quit(&mut self, _: &()) -> Result<(), RecoveryError> {
            self.actions.push("force quit");
            self.force_result
        }

        fn show_error(&mut self, error: RecoveryError) {
            self.errors.push(error);
        }
    }

    #[test]
    fn absent_instance_launches_without_a_dialog() {
        let mut platform = FakePlatform {
            existing: Ok(None),
            ..Default::default()
        };
        assert!(recover(&mut platform));
        assert_eq!(platform.actions, ["detect"]);
    }

    #[test]
    fn opening_an_existing_window_does_not_launch_another_instance() {
        let mut platform = FakePlatform {
            choices: VecDeque::from([Choice::Open]),
            ..Default::default()
        };
        assert!(!recover(&mut platform));
        assert_eq!(platform.actions, ["detect", "choose", "open"]);
    }

    #[test]
    fn missing_or_hung_main_window_returns_to_recovery_choices() {
        let mut platform = FakePlatform {
            choices: VecDeque::from([Choice::Open, Choice::Restart]),
            opened: Err(RecoveryError::Unavailable),
            closed: Ok(true),
            ..Default::default()
        };
        assert!(recover(&mut platform));
        assert_eq!(platform.errors, [RecoveryError::Unavailable]);
        assert_eq!(
            platform.actions,
            ["detect", "choose", "open", "choose", "close"]
        );
    }

    #[test]
    fn restart_requires_explicit_force_confirmation_after_graceful_close() {
        let mut platform = FakePlatform {
            choices: VecDeque::from([Choice::Restart, Choice::Cancel]),
            ..Default::default()
        };
        assert!(!recover(&mut platform));
        assert_eq!(
            platform.actions,
            ["detect", "choose", "close", "confirm force", "choose"]
        );
    }

    #[test]
    fn confirmed_force_quit_must_finish_before_a_fresh_launch() {
        let mut platform = FakePlatform {
            choices: VecDeque::from([Choice::Restart]),
            force_confirmed: true,
            ..Default::default()
        };
        assert!(recover(&mut platform));
        assert_eq!(
            platform.actions,
            ["detect", "choose", "close", "confirm force", "force quit"]
        );
    }

    #[test]
    fn force_quit_failure_does_not_start_the_plugin() {
        let mut platform = FakePlatform {
            choices: VecDeque::from([Choice::Restart]),
            force_confirmed: true,
            force_result: Err(RecoveryError::DidNotExit),
            ..Default::default()
        };
        assert!(!recover(&mut platform));
        assert_eq!(platform.errors, [RecoveryError::DidNotExit]);
    }

    #[test]
    fn unverifiable_or_inaccessible_instances_are_never_closed() {
        for error in [RecoveryError::Unverified, RecoveryError::Permission] {
            let mut platform = FakePlatform {
                existing: Err(error),
                ..Default::default()
            };
            assert!(!recover(&mut platform));
            assert_eq!(platform.actions, ["detect"]);
            assert_eq!(platform.errors, [error]);
        }
    }

    #[test]
    fn an_instance_that_exited_before_open_can_be_replaced() {
        let mut platform = FakePlatform {
            choices: VecDeque::from([Choice::Open]),
            opened: Ok(OpenOutcome::Exited),
            ..Default::default()
        };
        assert!(recover(&mut platform));
    }

    #[test]
    fn the_visible_plugin_helper_and_owned_or_tool_windows_are_not_main_windows() {
        assert!(!real_main_window(true, true, false, false, true));
        assert!(!real_main_window(true, false, true, false, true));
        assert!(!real_main_window(true, false, false, true, true));
        assert!(!real_main_window(false, false, false, false, true));
        assert!(!real_main_window(true, false, false, false, false));
        assert!(real_main_window(true, false, false, false, true));
    }

    #[test]
    fn executable_identity_uses_the_entire_case_insensitive_windows_path() {
        assert!(same_path(
            Path::new(r"C:\Apps\Оркестратор.exe"),
            Path::new(r"c:\apps\ОРКЕСТРАТОР.EXE")
        ));
        assert!(!same_path(
            Path::new(r"C:\Apps\Orchestrator.exe"),
            Path::new(r"C:\Other\Orchestrator.exe")
        ));
        assert!(!same_path(
            Path::new(r"C:\Apps\Orchestrator.exe"),
            Path::new(r"C:\Apps\Orchestrator-copy.exe")
        ));
    }
}
