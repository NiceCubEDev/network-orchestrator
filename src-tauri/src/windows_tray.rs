use crate::windows_instance::localized;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

pub(crate) const TRAY_ID: &str = "network-orchestrator-windows";

fn opens_window(button: MouseButton, state: Option<MouseButtonState>) -> bool {
    matches!(button, MouseButton::Left) && matches!(state, None | Some(MouseButtonState::Up))
}

fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub(crate) fn install(app: &mut tauri::App) -> tauri::Result<bool> {
    let Some(icon) = app.default_window_icon() else {
        return Ok(false);
    };
    let open = MenuItem::with_id(
        app,
        "windows-tray-open",
        localized("Open window"),
        true,
        None::<&str>,
    )?;
    let hide = MenuItem::with_id(
        app,
        "windows-tray-hide",
        localized("Hide window"),
        true,
        None::<&str>,
    )?;
    let exit = MenuItem::with_id(
        app,
        "windows-tray-exit",
        localized("Exit application"),
        true,
        None::<&str>,
    )?;
    let menu = Menu::with_items(app, &[&open, &hide, &exit])?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon.clone())
        .tooltip("Network Orchestrator")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "windows-tray-open" => show_window(app),
            "windows-tray-hide" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            "windows-tray-exit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            let open = match event {
                TrayIconEvent::Click {
                    button,
                    button_state,
                    ..
                } => opens_window(button, Some(button_state)),
                TrayIconEvent::DoubleClick { button, .. } => opens_window(button, None),
                _ => false,
            };
            if open {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_tray_opens_on_left_release_or_double_click_only() {
        assert!(opens_window(MouseButton::Left, Some(MouseButtonState::Up)));
        assert!(opens_window(MouseButton::Left, None));
        assert!(!opens_window(
            MouseButton::Left,
            Some(MouseButtonState::Down)
        ));
        assert!(!opens_window(
            MouseButton::Right,
            Some(MouseButtonState::Up)
        ));
        assert!(!opens_window(MouseButton::Right, None));
    }
}
