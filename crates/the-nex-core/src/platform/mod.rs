//! OS abstraction used by every core module. Each target provides the same function set:
//! discover_watched_dirs, discover_canary_dirs, discover_quick_scan_dirs, set_hidden_file,
//! program_file, vouched_file,
//! lock_quarantined_file, unlock_restored_file, send_desktop_notification, is_trusted_binary,
//! path_key, path_is_within, install_service, uninstall_service, service_installed,
//! run_service, run_tray, tray_is_running, run_elevated, install_ctrlc_handler, detach_console.

use std::path::PathBuf;
use std::sync::mpsc::{self, SyncSender};
use std::sync::OnceLock;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use self::windows::*;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use self::macos::*;

#[cfg(not(any(windows, target_os = "macos")))]
compile_error!("The Nex implements the platform layer for Windows and macOS only");

pub const DAEMON_EXE_STEM: &str = "the-nex";
pub const GUI_EXE_STEM: &str = "the-nex-gui";

/// Kernel/session-critical processes and The Nex itself; never terminated on either OS.
const PROTECTED_PROCESS_NAMES: &[&str] = &[
    "system",
    "system idle process",
    "idle",
    "registry",
    "memory compression",
    "secure system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "launchd",
    "kernel_task",
    "windowserver",
    "finder",
    "loginwindow",
    "dock",
    "systemuiserver",
    "the-nex",
    "the-nex.exe",
    "the-nex-gui",
    "the-nex-gui.exe",
];

/// Which file a path leads to, however it is spelled: a hard link, a rename and a moved folder
/// all keep it. None where the system gives no such number (Windows) or the file is gone.
pub(crate) fn file_identity(path: &std::path::Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Windows answers `\\?\C:\x`; people and the event log know it as `C:\x`. A name that only the
/// long form reaches (a trailing dot or space), or a path too long for older tools, keeps it.
pub(crate) fn plain_path(path: std::path::PathBuf) -> std::path::PathBuf {
    match path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(plain)
            if plain.as_bytes().get(1) == Some(&b':')
                && plain.len() < 248
                && !odd_spelling(plain, true) =>
        {
            PathBuf::from(plain)
        }
        _ => path,
    }
}

/// True when a path contains `..`; containment checks reject such paths instead of resolving them.
pub(crate) fn has_parent_dir(path: &std::path::Path) -> bool {
    path.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// True when a full path is not spelled the one plain way: an empty, "." or ".." part, or on
/// Windows a trailing dot or space (which the system drops), a stream name, or a short name
/// ("PROGRA~1"). A check that compares path text must not trust such a path: the file it leads to
/// may be somewhere else.
pub(crate) fn odd_spelling(path: &str, windows: bool) -> bool {
    path.split(|c| c == '/' || (windows && c == '\\'))
        .skip(1)
        .any(|part| {
            matches!(part, "" | "." | "..")
                || (windows
                    && (part.ends_with(['.', ' ']) || part.contains(':') || has_short_name(part)))
        })
}

/// "~" and a digit, as in the short names Windows makes.
fn has_short_name(part: &str) -> bool {
    part.as_bytes()
        .windows(2)
        .any(|pair| pair[0] == b'~' && pair[1].is_ascii_digit())
}

pub fn is_protected_process(pid: u32, name: &str) -> bool {
    if matches!(pid, 0 | 1 | 4) || pid == std::process::id() {
        return true;
    }
    let lower = name.to_lowercase();
    PROTECTED_PROCESS_NAMES.contains(&lower.as_str())
}

/// Queues a desktop notification and returns at once. Delivery can block for seconds
/// (macOS notification centre, osascript fallback, WinRT activation), so detectors and the
/// tray's message loop hand it to one background thread instead of waiting. When the queue
/// is full the notification is dropped; the event log always has the record.
pub fn send_desktop_notification_async(title: &str, body: &str) {
    static QUEUE: OnceLock<Option<SyncSender<(String, String)>>> = OnceLock::new();
    let queue = QUEUE.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<(String, String)>(32);
        std::thread::Builder::new()
            .name("thenex-notify".into())
            .spawn(move || {
                for (title, body) in rx {
                    send_desktop_notification(&title, &body);
                }
            })
            .ok()
            .map(|_| tx)
    });
    match queue {
        Some(tx) => {
            let _ = tx.try_send((title.to_string(), body.to_string()));
        }
        None => send_desktop_notification(title, body),
    }
}

/// Moves what a data folder that was not ours (made by a standard user before the first
/// install) may hold out of the way: the settings, always-allowed and never-scan lists, the schedule's state
/// and seen findings, the event logs and the quarantine folder with its metadata. Each goes
/// to `<name>.planted-<n>` beside it, never deleted, so nothing of the user's is lost for good.
/// The caller has already cut inheritance and set the grants, so nobody can put it back.
#[cfg(any(windows, test))]
pub(crate) fn set_aside_planted(cfg: &crate::config::AppConfig) -> Vec<String> {
    let mut notes = Vec::new();
    for path in [
        &cfg.allowed_file,
        &cfg.skipped_file,
        &cfg.settings_file,
        &cfg.base_dir.join(crate::schedule::STATE_FILE),
        &cfg.base_dir.join(crate::schedule::SEEN_FILE),
        &cfg.log_dir,
        &cfg.quarantine_dir,
    ] {
        if std::fs::symlink_metadata(path).is_err() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let aside = (0u32..)
            .map(|n| path.with_file_name(format!("{name}.planted-{n}")))
            .find(|candidate| std::fs::symlink_metadata(candidate).is_err());
        notes.push(match aside.map(|a| std::fs::rename(path, &a).map(|()| a)) {
            Some(Ok(a)) => format!(
                "moved {} to {}: it was in a data folder that existed before the first install",
                path.display(),
                a.display()
            ),
            Some(Err(e)) => format!("could not move {} aside: {e}", path.display()),
            None => format!("could not move {} aside", path.display()),
        });
    }
    notes
}

/// Path of a sibling binary installed next to the running executable (the-nex / the-nex-gui).
pub fn sibling_executable(stem: &str) -> PathBuf {
    let file_name = format!("{stem}{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(&file_name)))
        .unwrap_or_else(|| PathBuf::from(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_processes_cover_both_platforms() {
        for pid in [0, 1, 4, std::process::id()] {
            assert!(is_protected_process(pid, "anything"), "pid {pid}");
        }
        for name in [
            "the-nex",
            "the-nex.exe",
            "the-nex-gui",
            "Explorer.EXE",
            "svchost.exe",
            "launchd",
            "WindowServer",
        ] {
            assert!(is_protected_process(4242, name), "{name}");
        }
        assert!(!is_protected_process(99999, "malware_sim.exe"));
    }

    #[test]
    fn only_one_plain_spelling_of_a_path_is_accepted() {
        for path in [
            r"c:\windows\system32\a.exe",
            "c:/program files/a b/c.d/e.exe",
        ] {
            assert!(!odd_spelling(path, true), "{path}");
        }
        for path in [
            r"c:\windows\system32\..\..\users\a.exe",
            r"c:\windows\\system32\a.exe",
            r"c:\windows\.\a.exe",
            r"c:\windows\system32\spool.\drivers\a.exe",
            r"c:\windows\system32\spool \a.exe",
            r"c:\windows\system32\spool::$index_allocation\a.exe",
            r"\\host\share\a.exe",
            r"c:\windows\system32\spool\driver~1\color\a.exe",
            r"c:\program files\vendor\tempfo~2.x\a.exe",
        ] {
            assert!(odd_spelling(path, true), "{path}");
        }
        assert!(!odd_spelling(r"c:\windows\a~b\~c.exe", true));
        assert!(!odd_spelling("/usr/bin/a..b/c.", false));
        assert!(!odd_spelling("/usr/bin/a~1", false));
        for path in ["/usr//bin/a", "/usr/./a", "/usr/../a", "//usr/a"] {
            assert!(odd_spelling(path, false), "{path}");
        }
    }

    #[test]
    fn a_folder_that_was_not_ours_is_moved_aside_never_deleted() {
        use crate::config::AppConfig;
        let dir = std::env::temp_dir().join(format!("thenex-planted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let kept = dir.join("thenex_model.onnx");
        std::fs::write(&kept, b"model").unwrap();
        let planted = [
            &cfg.allowed_file,
            &cfg.skipped_file,
            &cfg.settings_file,
            &dir.join("scheduled_scan.json"),
            &dir.join("scheduled_seen.json"),
            &cfg.events_log,
            &crate::quarantine::rotated_events_path(&cfg.events_log),
            &cfg.quarantine_dir.join("id.meta.json"),
        ];
        for file in planted {
            std::fs::write(file, file.display().to_string()).unwrap();
        }
        // A leftover of an earlier move is not overwritten.
        std::fs::write(dir.join("allowed.json.planted-0"), b"older").unwrap();
        let notes = set_aside_planted(&cfg);
        assert_eq!(notes.len(), 7, "{notes:?}");
        assert!(kept.exists());
        for file in [
            &cfg.allowed_file,
            &cfg.skipped_file,
            &cfg.settings_file,
            &cfg.events_log,
        ] {
            assert!(!file.exists(), "{}", file.display());
        }
        assert_eq!(
            std::fs::read(dir.join("allowed.json.planted-0")).unwrap(),
            b"older"
        );
        assert_eq!(
            std::fs::read(dir.join("allowed.json.planted-1")).unwrap(),
            planted[0].display().to_string().as_bytes()
        );
        assert!(dir
            .join("Quarantine.planted-0")
            .join("id.meta.json")
            .exists());
        assert!(dir.join("logs.planted-0").join("events.jsonl.1").exists());
        // Nothing left to move the second time.
        assert!(set_aside_planted(&cfg).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_dir_detection() {
        assert!(has_parent_dir(std::path::Path::new("a/../b")));
        assert!(!has_parent_dir(std::path::Path::new("a/b..c/d")));
    }

    #[test]
    fn sibling_executables_live_next_to_the_current_binary() {
        let gui = sibling_executable(GUI_EXE_STEM);
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(gui.parent().unwrap(), exe_dir);
        assert!(gui
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("the-nex-gui"));
    }
}
