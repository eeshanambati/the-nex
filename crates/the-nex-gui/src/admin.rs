//! "Always open as administrator" (Windows). The choice is one empty file in the user's own
//! app-data folder. When it is there and the app was opened without administrator rights, the
//! app starts itself again through the Windows approval prompt and closes; if the prompt is
//! declined it simply carries on without them. Nothing is gained without that approval, so a
//! program that sets the choice can only cause a prompt.

use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use the_nex_core::config;

const MARKER: &str = "open-as-administrator";

#[derive(Serialize)]
pub struct AdminChoice {
    /// The option exists on this system (Windows only).
    available: bool,
    on: bool,
    /// This window already runs with administrator rights.
    elevated: bool,
}

fn marker() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|dir| PathBuf::from(dir).join("TheNex").join(MARKER))
}

fn is_on(marker: &Path) -> bool {
    marker.is_file()
}

fn set(marker: &Path, on: bool) -> Result<(), String> {
    let done = if on {
        marker
            .parent()
            .map_or(Ok(()), fs::create_dir_all)
            .and_then(|()| fs::write(marker, b""))
    } else {
        match fs::remove_file(marker) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    };
    done.map_err(|e| format!("The setting could not be saved: {e}"))
}

/// Whether to start again with administrator rights: asked for, possible here, and not yet so.
fn should_relaunch(available: bool, on: bool, elevated: bool) -> bool {
    available && on && !elevated
}

/// Called first thing: true when an elevated copy was started and this one should close.
pub fn relaunch_if_wanted() -> bool {
    let on = marker().is_some_and(|m| is_on(&m));
    if !should_relaunch(cfg!(windows), on, config::running_privileged()) {
        return false;
    }
    #[cfg(windows)]
    if let Ok(exe) = std::env::current_exe() {
        return the_nex_core::platform::start_elevated(&exe);
    }
    false
}

fn choice() -> AdminChoice {
    AdminChoice {
        available: cfg!(windows) && marker().is_some(),
        on: marker().is_some_and(|m| is_on(&m)),
        elevated: config::running_privileged(),
    }
}

#[tauri::command]
pub fn get_open_as_admin() -> AdminChoice {
    choice()
}

#[tauri::command]
pub fn set_open_as_admin(on: bool) -> Result<AdminChoice, String> {
    let marker = marker()
        .filter(|_| cfg!(windows))
        .ok_or("This option is only available on Windows.")?;
    set(&marker, on)?;
    Ok(choice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_choice_is_kept_and_taken_back() {
        let dir = std::env::temp_dir().join(format!("thenex-admin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let marker = dir.join("TheNex").join(MARKER);
        assert!(!is_on(&marker));
        set(&marker, true).unwrap();
        assert!(is_on(&marker));
        set(&marker, true).unwrap();
        set(&marker, false).unwrap();
        assert!(!is_on(&marker));
        set(&marker, false).unwrap(); // already off: not an error
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn it_starts_again_only_when_asked_possible_and_not_yet_elevated() {
        assert!(should_relaunch(true, true, false));
        // Already elevated: never again, so a declined or repeated start cannot loop.
        assert!(!should_relaunch(true, true, true));
        assert!(!should_relaunch(true, false, false));
        assert!(!should_relaunch(false, true, false));
    }
}
