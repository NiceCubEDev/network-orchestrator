//! One data-directory contract for the Linux CLI and GUI. Development GUI
//! identities remain isolated unless the user explicitly selects a directory.
use std::path::PathBuf;

pub const APPLICATION_ID: &str = "com.netmanager.app";
pub const DATA_DIR_ENV: &str = "NETORCH_DATA_DIR";

pub fn data_root(
    application_id: &str,
    explicit: Option<PathBuf>,
    xdg: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(root) = explicit {
        return if root.is_absolute() {
            Ok(root)
        } else {
            Err("The data directory must be an absolute path".into())
        };
    }
    if let Some(root) = xdg.filter(|root| root.is_absolute()) {
        return Ok(root.join(application_id));
    }
    home.filter(|home| home.is_absolute())
        .map(|home| home.join(".local/share").join(application_id))
        .ok_or_else(|| "The home directory could not be found".into())
}

pub fn from_environment(application_id: &str) -> Result<PathBuf, String> {
    data_root(
        application_id,
        std::env::var_os(DATA_DIR_ENV).map(PathBuf::from),
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_directory_wins_and_relative_override_is_rejected() {
        assert_eq!(
            data_root(
                APPLICATION_ID,
                Some("/isolated".into()),
                Some("/xdg".into()),
                Some("/home/u".into()),
            )
            .unwrap(),
            PathBuf::from("/isolated")
        );
        assert!(data_root(APPLICATION_ID, Some("relative".into()), None, None).is_err());
    }

    #[test]
    fn xdg_precedence_and_development_identity_remain_isolated() {
        let production = data_root(
            APPLICATION_ID,
            None,
            Some("/xdg".into()),
            Some("/home/u".into()),
        )
        .unwrap();
        let development = data_root(
            "com.netmanager.app.dev",
            None,
            Some("/xdg".into()),
            Some("/home/u".into()),
        )
        .unwrap();
        assert_eq!(production, PathBuf::from("/xdg/com.netmanager.app"));
        assert_eq!(development, PathBuf::from("/xdg/com.netmanager.app.dev"));
    }

    #[test]
    fn relative_xdg_is_ignored_but_an_absolute_home_is_required() {
        assert_eq!(
            data_root(
                APPLICATION_ID,
                None,
                Some("relative".into()),
                Some("/home/u".into())
            )
            .unwrap(),
            PathBuf::from("/home/u/.local/share/com.netmanager.app")
        );
        assert!(data_root(APPLICATION_ID, None, None, Some("relative".into())).is_err());
        assert!(data_root(APPLICATION_ID, None, None, None).is_err());
    }
}
