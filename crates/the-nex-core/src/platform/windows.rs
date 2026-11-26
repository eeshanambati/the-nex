use crate::canary;
use crate::config::{self, AppConfig};
use crate::logger;
use crate::quarantine;
use std::env;
use std::ffi::{c_void, OsStr, OsString};
use std::fs;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Security::{
    IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, SetFileAttributesW};
use windows_sys::Win32::System::Console::{
    FreeConsole, GetConsoleProcessList, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenMutexW, WaitForSingleObject, INFINITE, SYNCHRONIZATION_SYNCHRONIZE,
};
use windows_sys::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

pub const SELF_EXE_NAME: &str = "the-nex.exe";
const SERVICE_DISPLAY_NAME: &str = "The Nex Endpoint Protection";
const SERVICE_DESCRIPTION: &str =
    "Real-time ransomware canary, zip bomb, malicious binary and living-off-the-land script protection.";
const RUN_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "TheNexNotifier";
const USER_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const TRAY_RUN_VALUE: &str = "TheNexTray";
const NOTIFIER_ARG: &str = "--notifier";
const TRAY_ARG: &str = "--tray";
/// Per-session name; the notifier stays quiet while a tray instance owns it.
pub const TRAY_MUTEX_NAME: &str = r"Local\TheNexTray";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const CTRL_CLOSE_EVENT: u32 = 2;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
const ERROR_SERVICE_EXISTS: i32 = 1073;
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(20);

const SID_SYSTEM: &str = "*S-1-5-18";
const SID_ADMINISTRATORS: &str = "*S-1-5-32-544";
const SID_USERS: &str = "*S-1-5-32-545";
const SID_EVERYONE: &str = "*S-1-1-0";

const SKIPPED_PROFILES: &[&str] = &[
    "public",
    "default",
    "default user",
    "all users",
    "defaultapppool",
    "wdagutilityaccount",
];

/// Folders under otherwise admin-only trees that standard users can write to.
const USER_WRITABLE_FRAGMENTS: &[&str] = &[
    r"\temp\",
    r"\tmp\",
    r"\tasks\",
    r"\tracing\",
    r"\spool\",
    r"\com\dmp\",
    r"\fxstmp\",
    r"\registration\crmlog\",
    r"\catroot2\",
];

fn to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn system_root() -> PathBuf {
    env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

fn system32_tool(name: &str) -> PathBuf {
    system_root().join("System32").join(name)
}

fn users_root() -> PathBuf {
    let drive = env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    PathBuf::from(format!(r"{drive}\Users"))
}

/// Case-insensitive, separator-normalized comparison key for Windows paths.
pub fn path_key(path: &Path) -> String {
    let mut key = path.to_string_lossy().replace('/', "\\").to_lowercase();
    if let Some(rest) = key.strip_prefix(r"\\?\unc\") {
        key = format!(r"\\{rest}");
    } else if let Some(rest) = key.strip_prefix(r"\\?\") {
        key = rest.to_string();
    }
    while key.len() > 3 && key.ends_with('\\') {
        key.pop();
    }
    key
}

/// Not told cheaply here: every process is read each time.
pub fn process_versions() -> Option<std::collections::HashMap<u32, (u64, i32)>> {
    None
}

pub fn path_is_within(path: &Path, root: &Path) -> bool {
    if super::has_parent_dir(path) {
        return false;
    }
    let path = path_key(path);
    let root = path_key(root);
    if path == root {
        return true;
    }
    let prefix = if root.ends_with('\\') {
        root
    } else {
        format!("{root}\\")
    };
    path.starts_with(&prefix)
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    paths
        .into_iter()
        .filter(|p| seen.insert(path_key(p)))
        .collect()
}

/// Real interactive profiles under %SystemDrive%\Users (junctions and built-ins skipped).
fn user_profiles() -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(users_root()) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            let Ok(kind) = entry.file_type() else {
                return false;
            };
            let name = entry.file_name().to_string_lossy().to_lowercase();
            kind.is_dir()
                && !kind.is_symlink()
                && !name.starts_with('.')
                && !SKIPPED_PROFILES.contains(&name.as_str())
        })
        .map(|entry| entry.path())
        .collect()
}

/// `names` inside the profile plus inside any OneDrive* folder (known-folder redirection).
fn profile_folders(profile: &Path, names: &[&str]) -> Vec<PathBuf> {
    let mut roots = vec![profile.to_path_buf()];
    if let Ok(entries) = fs::read_dir(profile) {
        roots.extend(
            entries
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .to_lowercase()
                        .starts_with("onedrive")
                        && e.path().is_dir()
                })
                .map(|e| e.path()),
        );
    }
    roots
        .iter()
        .flat_map(|root| names.iter().map(move |name| root.join(name)))
        .filter(|p| p.is_dir())
        .collect()
}

pub fn discover_watched_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for profile in user_profiles() {
        dirs.extend(profile_folders(&profile, &["Downloads", "Desktop"]));
        let user_temp = profile.join("AppData").join("Local").join("Temp");
        if user_temp.is_dir() {
            dirs.push(user_temp);
        }
    }
    for temp in [system_root().join("Temp"), env::temp_dir()] {
        if temp.is_dir() {
            dirs.push(temp);
        }
    }
    dedup_paths(dirs)
}

pub fn discover_canary_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for profile in user_profiles() {
        dirs.extend(profile_folders(&profile, &["Desktop", "Documents"]));
    }
    dedup_paths(dirs)
}

/// Downloads and Desktop of every real user (temp folders are left to the live watcher).
pub fn discover_quick_scan_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for profile in user_profiles() {
        dirs.extend(profile_folders(&profile, &["Downloads", "Desktop"]));
    }
    dedup_paths(dirs)
}

pub fn set_hidden_file(path: &Path) {
    let wide = to_wide(path.as_os_str());
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives both calls.
    unsafe {
        let attributes = GetFileAttributesW(wide.as_ptr());
        if attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_HIDDEN == 0 {
            SetFileAttributesW(wide.as_ptr(), attributes | FILE_ATTRIBUTE_HIDDEN);
        }
    }
}

fn run_tool<I, S>(program: &Path, args: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let mut message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if message.is_empty() {
        message = String::from_utf8_lossy(&output.stdout).trim().to_string();
    }
    Err(format!(
        "{} failed ({}): {message}",
        program.display(),
        output.status
    ))
}

fn icacls(path: &Path, args: &[&str]) -> bool {
    let mut full: Vec<&OsStr> = vec![path.as_os_str()];
    full.extend(args.iter().map(OsStr::new));
    run_tool(&system32_tool("icacls.exe"), full).is_ok()
}

/// icacls follows reparse points; SYSTEM must never re-ACL a link target chosen by a user.
fn is_link_or_missing(path: &Path) -> bool {
    fs::symlink_metadata(path).map_or(true, |m| m.file_type().is_symlink())
}

/// Lets any local user create a file in `dir`, but no folder and nothing below it. SYSTEM has
/// full control of `dir` and so can delete what is left there whatever its own ACL says.
pub fn let_users_add_files(dir: &Path) -> bool {
    let add_file = format!("{SID_USERS}:(WD)");
    !is_link_or_missing(dir) && icacls(dir, &["/grant", add_file.as_str()])
}

/// Read-only, owned by Administrators, readable only by SYSTEM/Administrators, execute denied to everyone.
pub fn lock_quarantined_file(path: &Path) {
    if is_link_or_missing(path) {
        logger::warn(format!(
            "refusing to lock link or missing file {}",
            path.display()
        ));
        return;
    }
    let _ = quarantine::set_readonly(path, true);
    icacls(path, &["/setowner", SID_ADMINISTRATORS]);
    let system = format!("{SID_SYSTEM}:(F)");
    let admins = format!("{SID_ADMINISTRATORS}:(F)");
    if !icacls(
        path,
        &[
            "/inheritance:r",
            "/grant:r",
            system.as_str(),
            admins.as_str(),
        ],
    ) {
        logger::warn(format!("could not restrict ACL on {}", path.display()));
    }
    let deny_execute = format!("{SID_EVERYONE}:(X)");
    icacls(path, &["/deny", deny_execute.as_str()]);
}

pub fn unlock_restored_file(path: &Path) {
    if is_link_or_missing(path) {
        logger::warn(format!(
            "refusing to unlock link or missing file {}",
            path.display()
        ));
        return;
    }
    icacls(path, &["/reset"]);
    let _ = quarantine::set_readonly(path, false);
}

/// WinRT toast via notify-rust (tauri-winrt-notification), under the PowerShell app id.
/// The older winrt-notification 0.5 crate is deliberately not used: its windows 0.24 import
/// library maps WaitOnAddress/WakeByAddress* to vertdll.dll, which hijacked std's thread
/// parking and crashed every binary with STATUS_ACCESS_VIOLATION.
pub fn send_desktop_notification(title: &str, body: &str) {
    let shown = notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .sound_name("SMS")
        .show();
    if let Err(e) = shown {
        logger::warn(format!("desktop notification failed: {e}"));
    }
}

fn trusted_roots() -> &'static [String] {
    static ROOTS: OnceLock<Vec<String>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let root = system_root();
        let mut dirs = vec![
            root.join("System32"),
            root.join("SysWOW64"),
            root.join("WinSxS"),
            root.join("SystemApps"),
            root.join("ImmersiveControlPanel"),
            root.join("Microsoft.NET"),
        ];
        for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(dir) = env::var_os(var) {
                dirs.push(PathBuf::from(dir));
            }
        }
        let mut keys: Vec<String> = dirs.iter().map(|d| path_key(d)).collect();
        keys.sort();
        keys.dedup();
        keys
    })
}

fn is_in_trusted_root(path: &Path) -> bool {
    let key = path_key(path);
    if super::odd_spelling(&key, true) {
        return false;
    }
    if USER_WRITABLE_FRAGMENTS.iter().any(|f| key.contains(f)) {
        return false;
    }
    trusted_roots()
        .iter()
        .any(|root| key.starts_with(&format!("{root}\\")))
}

fn has_valid_authenticode(path: &Path) -> bool {
    let wide = to_wide(path.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: ptr::null_mut(),
        pSIPClientData: ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: ptr::null_mut(),
        pwszURLReference: ptr::null_mut(),
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: ptr::null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // INVALID_HANDLE_VALUE as the window: never show UI.
    let no_ui = usize::MAX as *mut c_void;
    // SAFETY: all pointers reference live, correctly laid out structures for the call;
    // the CLOSE call releases the state allocated by VERIFY.
    unsafe {
        let status = WinVerifyTrust(no_ui, &mut action, (&mut data as *mut WINTRUST_DATA).cast());
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(no_ui, &mut action, (&mut data as *mut WINTRUST_DATA).cast());
        status == 0
    }
}

/// Admin-only system/program folders, or a valid embedded Authenticode signature.
pub fn is_trusted_binary(path: &Path) -> bool {
    is_in_trusted_root(path) || has_valid_authenticode(path)
}

pub fn program_file(process: &sysinfo::Process) -> Option<PathBuf> {
    process.exe().map(Path::to_path_buf)
}

pub fn vouched_file(process: &sysinfo::Process) -> Option<PathBuf> {
    program_file(process)
}

/// (volume, file index, size, modified, changed) of the file at `path`, read without following a
/// link. Another file under the name has another index, and rewriting this one moves its change
/// time, which unlike the modified time is not set by ordinary tools.
pub fn file_stamp(path: &Path) -> Option<crate::bin_ai::FileStamp> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let wide = to_wide(path.as_os_str());
    // SAFETY: `wide` is NUL-terminated; both out structures are plain data of the size given,
    // and the handle is closed exactly once.
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        let mut basic: FILE_BASIC_INFO = std::mem::zeroed();
        let read = GetFileInformationByHandle(handle, &mut info) != 0
            && GetFileInformationByHandleEx(
                handle,
                FileBasicInfo,
                (&mut basic as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            ) != 0;
        CloseHandle(handle);
        let join = |high: u32, low: u32| (u64::from(high) << 32) | u64::from(low);
        read.then(|| {
            (
                u64::from(info.dwVolumeSerialNumber),
                join(info.nFileIndexHigh, info.nFileIndexLow),
                join(info.nFileSizeHigh, info.nFileSizeLow),
                i128::from(basic.LastWriteTime),
                i128::from(basic.ChangeTime),
            )
        })
    }
}

/// shortcut: always false, so a Microsoft-signed file outside the Windows folders is not
/// spared by a known-malware match (the Windows folders themselves are alert-only by path,
/// see ai_policy). Upgrade by checking the signer's chain for the Microsoft root once a
/// Windows machine is available to test it on.
pub fn is_os_vendor_signed(_path: &Path) -> bool {
    false
}

/// Whether `vendor` itself signed it: cannot be told here (see `is_os_vendor_signed`).
pub fn is_signed_by(_path: &Path, _vendor: &str) -> Option<bool> {
    None
}

/// One value of a registry key, as raw bytes; None when it is too large to be a command line.
pub struct RegistryValue {
    pub name: String,
    pub kind: u32,
    pub data: Option<Vec<u8>>,
}

impl RegistryValue {
    pub fn is_text(&self) -> bool {
        use windows_sys::Win32::System::Registry::{REG_EXPAND_SZ, REG_SZ};
        self.kind == REG_SZ || self.kind == REG_EXPAND_SZ
    }

    /// `%NAME%` in it is replaced by Windows.
    pub fn expand(&self) -> bool {
        self.kind == windows_sys::Win32::System::Registry::REG_EXPAND_SZ
    }
}

/// A key's values; `incomplete` when there were more, or the rest could not be read.
#[derive(Default)]
pub struct RegistryValues {
    pub values: Vec<RegistryValue>,
    pub incomplete: bool,
}

/// The text of a registry value, up to its first NUL as Windows reads it.
pub fn registry_text(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// The values under `HKLM` or `HKCU` `subkey`, read-only and bounded. A key that does not exist
/// has none. Used by the startup listing.
pub fn read_registry_values(local_machine: bool, subkey: &str) -> Result<RegistryValues, String> {
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
        ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_READ,
    };
    const MAX_VALUES: u32 = 2000;
    /// The longest name the registry allows, with its NUL.
    const MAX_NAME: usize = 16384;
    /// A command line can have 32,767 characters.
    const MAX_DATA: usize = 128 * 1024;
    let root = if local_machine {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    };
    let wide = to_wide(OsStr::new(subkey));
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and `key` is a valid out pointer.
    match unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ, &mut key) } {
        ERROR_SUCCESS => {}
        ERROR_FILE_NOT_FOUND => return Ok(RegistryValues::default()),
        ERROR_ACCESS_DENIED => return Err("You do not have permission to read this key.".into()),
        _ => return Err("This key could not be read.".into()),
    }
    let mut found = RegistryValues::default();
    let mut name = vec![0u16; MAX_NAME];
    let mut data = vec![0u8; MAX_DATA];
    for index in 0..=MAX_VALUES {
        let mut name_len = name.len() as u32;
        let mut data_len = data.len() as u32;
        let mut kind = 0u32;
        // SAFETY: the buffers and their lengths match; `key` is open until RegCloseKey below.
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if index == MAX_VALUES || !matches!(status, ERROR_SUCCESS | ERROR_MORE_DATA) {
            found.incomplete = true;
            break;
        }
        // With ERROR_MORE_DATA the name's length is not given back; it ends at its NUL.
        let end = name.iter().position(|u| *u == 0).unwrap_or(name.len());
        let end = if status == ERROR_SUCCESS {
            name_len as usize
        } else {
            end
        };
        found.values.push(RegistryValue {
            name: String::from_utf16_lossy(&name[..end]),
            kind,
            data: (status == ERROR_SUCCESS).then(|| data[..data_len as usize].to_vec()),
        });
    }
    // SAFETY: closes the key opened above, once.
    unsafe { RegCloseKey(key) };
    Ok(found)
}

/// Windows command-line quoting for one argument (CommandLineToArgvW rules).
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(c);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

/// Runs `program args` through the UAC prompt and waits for it; returns its exit code.
pub fn run_elevated(program: &Path, args: &[&str]) -> Result<i32, String> {
    let verb = to_wide(OsStr::new("runas"));
    let file = to_wide(program.as_os_str());
    let parameters = to_wide(OsStr::new(
        &args
            .iter()
            .map(|a| quote_arg(a))
            .collect::<Vec<_>>()
            .join(" "),
    ));
    // SAFETY: SHELLEXECUTEINFOW is plain data; every pointer stays alive until the call returns
    // and the returned process handle is closed exactly once.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 {
            let code = GetLastError();
            return Err(if code == ERROR_CANCELLED {
                "the administrator prompt was cancelled".to_string()
            } else {
                format!(
                    "could not start {} elevated (Win32 error {code})",
                    program.display()
                )
            });
        }
        if info.hProcess.is_null() {
            return Err("elevated process handle unavailable".to_string());
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut exit_code = 0u32;
        GetExitCodeProcess(info.hProcess, &mut exit_code);
        CloseHandle(info.hProcess);
        Ok(exit_code as i32)
    }
}

/// Starts `program` with administrator rights through the approval prompt, without waiting for
/// it. False when it was not started (the prompt was declined, or it failed).
pub fn start_elevated(program: &Path) -> bool {
    let verb = to_wide(OsStr::new("runas"));
    let file = to_wide(program.as_os_str());
    // SAFETY: SHELLEXECUTEINFOW is plain data and every pointer in it outlives the call; no
    // process handle is asked for, so none is left to close.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.nShow = windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        ShellExecuteExW(&mut info) != 0
    }
}

pub fn tray_is_running() -> bool {
    let name = to_wide(OsStr::new(TRAY_MUTEX_NAME));
    // SAFETY: valid NUL-terminated name; the handle is closed immediately.
    unsafe {
        let handle = OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr());
        if handle.is_null() {
            false
        } else {
            CloseHandle(handle);
            true
        }
    }
}

pub fn run_tray(cfg: AppConfig) -> Result<(), String> {
    tray::run(cfg)
}

fn win32_code(err: &windows_service::Error) -> Option<i32> {
    match err {
        windows_service::Error::Winapi(io) => io.raw_os_error(),
        _ => None,
    }
}

fn service_error(context: &str, err: windows_service::Error) -> String {
    match win32_code(&err) {
        Some(5) => format!("{context}: access denied (run from an elevated Administrator prompt)"),
        Some(code) => format!("{context}: {err} (Win32 error {code})"),
        None => format!("{context}: {err}"),
    }
}

pub fn service_installed() -> bool {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|manager| manager.open_service(config::SERVICE_NAME, ServiceAccess::QUERY_STATUS))
        .is_ok()
}

fn service_info(executable: PathBuf) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(config::SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: Vec::new(),
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    }
}

fn restart_action(delay_secs: u64) -> ServiceAction {
    ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(delay_secs),
    }
}

// UNVERIFIED / RESIDUAL RISK (Windows, not testable in the current environment):
// - Binaries are installed under ProgramData\TheNex. A local user who pre-created that folder
//   before install can have planted DLLs there (DLL planting) that the SYSTEM service loads;
//   the ownership/ACL reset below does not remove already-planted content.
// - `icacls /T` may traverse junctions inside a pre-created tree, so the reset can touch targets
//   outside it.
// Planned fix: install binaries under Program Files (admin-only writable) and keep only data in
// ProgramData; if the data folder exists and is not owned by Administrators/SYSTEM, rename it
// aside (never reset in place) and recreate it. The installer (installer.nsi) is deliberately
// unchanged until that can be tested on Windows.
//
// Planted files: a folder that already existed and was NOT owned by Administrators or SYSTEM
// before we touched it was made by a standard user, so what it holds (allowed.json, settings.json,
// the schedule's state, the logs, the quarantine folder) is not ours. After inheritance is cut and
// the grants are set (so nobody can put it back) it is moved aside to ".planted-<n>", never
// deleted; the engine then starts from defaults (everything on, nothing allowed). A folder an
// earlier install hardened is owned by Administrators, so uninstalling and installing again keeps
// the person's own settings and list. Unverified on Windows (type-checked only).
/// `fresh`: the installer, which takes the ownership first, found that it was not.
fn harden_data_dirs(cfg: &AppConfig, fresh: bool) -> Vec<String> {
    let pre_existing = cfg.base_dir.exists();
    // Looked at before the ownership below is taken.
    let ours = pre_existing && !fresh && owned_by_admins(&cfg.base_dir);
    let mut notes = restrict_data_dirs(cfg);
    if pre_existing && !ours {
        notes.extend(super::set_aside_planted(cfg));
        // The moved folders are made again, and their grants set again.
        notes.extend(restrict_data_dirs(cfg));
    }
    notes
}

/// True when the owner of `path` is Administrators or SYSTEM. False when it cannot be told.
fn owned_by_admins(path: &Path) -> bool {
    let wide = to_wide(path.as_os_str());
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; on success `owner` points into `descriptor`, which is
    // read before it is freed.
    unsafe {
        let status = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        );
        if status != 0 {
            return false;
        }
        let admins = IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            || IsWellKnownSid(owner, WinLocalSystemSid) != 0;
        LocalFree(descriptor);
        admins
    }
}

/// Takes ownership, resets the ACLs, cuts inheritance and sets the grants.
fn restrict_data_dirs(cfg: &AppConfig) -> Vec<String> {
    let mut notes = Vec::new();
    if let Err(e) = cfg.ensure_dirs() {
        notes.push(e);
    }
    // A user may have pre-created the folder: take ownership and drop its ACL before granting.
    for dir in [&cfg.base_dir, &cfg.quarantine_dir] {
        icacls(dir, &["/setowner", SID_ADMINISTRATORS, "/T", "/C"]);
        icacls(dir, &["/reset", "/T", "/C"]);
    }
    let system = format!("{SID_SYSTEM}:(OI)(CI)F");
    let admins = format!("{SID_ADMINISTRATORS}:(OI)(CI)F");
    let users = format!("{SID_USERS}:(OI)(CI)RX");
    let base_grants = [
        "/inheritance:r",
        "/grant:r",
        system.as_str(),
        admins.as_str(),
        users.as_str(),
    ];
    if !icacls(&cfg.base_dir, &base_grants) {
        notes.push(format!(
            "could not restrict ACL on {}",
            cfg.base_dir.display()
        ));
    }
    if !icacls(
        &cfg.quarantine_dir,
        &[
            "/inheritance:r",
            "/grant:r",
            system.as_str(),
            admins.as_str(),
        ],
    ) {
        notes.push(format!(
            "could not restrict ACL on {}",
            cfg.quarantine_dir.display()
        ));
    }
    notes
}

fn register_autostart(key: &str, value: &str, exe: &Path, arg: &str) -> Result<(), String> {
    let command = format!("\"{}\" {arg}", exe.display());
    run_tool(
        &system32_tool("reg.exe"),
        [
            "add",
            key,
            "/v",
            value,
            "/t",
            "REG_SZ",
            "/d",
            command.as_str(),
            "/f",
        ],
    )
}

fn unregister_autostart(key: &str, value: &str) -> bool {
    run_tool(
        &system32_tool("reg.exe"),
        ["delete", key, "/v", value, "/f"],
    )
    .is_ok()
}

/// Terminates other the-nex.exe instances started with `arg` (notifier or tray).
fn stop_session_processes(arg: &str) -> usize {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    let me = std::process::id();
    sys.processes()
        .values()
        .filter(|p| {
            p.pid().as_u32() != me
                && OsStr::new(p.name())
                    .to_string_lossy()
                    .eq_ignore_ascii_case(SELF_EXE_NAME)
                && p.cmd()
                    .iter()
                    .any(|a| OsStr::new(a).to_string_lossy().eq_ignore_ascii_case(arg))
        })
        .filter(|p| p.kill())
        .count()
}

/// Where the service's program must be: the data folder, which only administrators can change.
/// None when `source` is already there (the installer runs it from there).
fn engine_destination(source: &Path, base: &Path) -> Option<PathBuf> {
    let folder = source.parent()?;
    (path_key(folder) != path_key(base)).then(|| base.join(SELF_EXE_NAME))
}

/// The files that run beside the engine, copied from `from` into `to` when they are there.
const ENGINE_COMPANIONS: &[&str] = &[
    "the-nex-gui.exe",
    config::MODEL_FILE_NAME,
    crate::known_bad::FILE_NAME,
    "icon.ico",
];

/// Copies this program (and what runs beside it) into the protected data folder and returns
/// the copy, which is what the service then runs as SYSTEM. Run from anywhere else, such as a
/// build folder, any program of the user's could replace the file and run as SYSTEM.
fn place_engine(source: &Path, base: &Path, notes: &mut Vec<String>) -> Result<PathBuf, String> {
    let Some(target) = engine_destination(source, base) else {
        return Ok(source.to_path_buf());
    };
    // The tray and notifier run this program from there and would keep the file open.
    stop_session_processes(NOTIFIER_ARG);
    stop_session_processes(TRAY_ARG);
    let copy = |from: &Path, to: &Path| {
        if fs::symlink_metadata(to).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!(
                "{} is a link; refusing to write through it",
                to.display()
            ));
        }
        fs::copy(from, to)
            .map(|_| ())
            .map_err(|e| format!("cannot copy {} to {}: {e}", from.display(), to.display()))
    };
    copy(source, &target)?;
    let from = source.parent().unwrap_or(base);
    for name in ENGINE_COMPANIONS {
        if from.join(name).is_file() {
            if let Err(e) = copy(&from.join(name), &base.join(name)) {
                notes.push(e);
            }
        }
    }
    notes.push(format!("copied the engine to {}", target.display()));
    Ok(target)
}

/// Asks a running service to stop and waits for it, up to `SERVICE_STOP_TIMEOUT`.
fn stop_and_wait(service: &windows_service::service::Service) {
    if service
        .query_status()
        .is_ok_and(|s| s.current_state == ServiceState::Stopped)
    {
        return;
    }
    let _ = service.stop();
    let started = Instant::now();
    while started.elapsed() < SERVICE_STOP_TIMEOUT {
        match service.query_status() {
            Ok(s) if s.current_state == ServiceState::Stopped => break,
            Ok(_) => thread::sleep(Duration::from_millis(250)),
            Err(_) => break,
        }
    }
}

pub fn install_service(fresh_data: bool) -> Result<String, String> {
    let source = env::current_exe().map_err(|e| format!("cannot resolve executable path: {e}"))?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| service_error("cannot open the Service Control Manager", e))?;
    let mut notes = Vec::new();
    // A running service holds its program open; it is started again below.
    if let Ok(running) = manager.open_service(
        config::SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    ) {
        stop_and_wait(&running);
    }
    // The folder is made safe first, so nothing can be planted between the copy and the start.
    let base = config::default_base_dir();
    notes.extend(harden_data_dirs(
        &AppConfig::for_base_dir(&base),
        fresh_data,
    ));
    let exe = place_engine(&source, &base, &mut notes)?;

    let info = service_info(exe.clone());
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = match manager.create_service(&info, access) {
        Ok(service) => {
            notes.push(format!("service '{}' registered", config::SERVICE_NAME));
            service
        }
        Err(e) if win32_code(&e) == Some(ERROR_SERVICE_EXISTS) => {
            let service = manager
                .open_service(config::SERVICE_NAME, access)
                .map_err(|e| service_error("cannot open existing service", e))?;
            service
                .change_config(&info)
                .map_err(|e| service_error("cannot update existing service", e))?;
            notes.push(format!("service '{}' updated", config::SERVICE_NAME));
            service
        }
        Err(e) => return Err(service_error("cannot create service", e)),
    };

    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|e| service_error("cannot set service description", e))?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                restart_action(5),
                restart_action(5),
                restart_action(30),
            ]),
        })
        .map_err(|e| service_error("cannot set restart-on-failure policy", e))?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| service_error("cannot enable failure actions", e))?;

    // Registered is not running: without this the service waits for the next restart.
    match service.start::<&OsStr>(&[]) {
        Ok(()) => notes.push(format!("service '{}' started", config::SERVICE_NAME)),
        Err(e) if win32_code(&e) == Some(ERROR_SERVICE_ALREADY_RUNNING) => {}
        Err(e) => {
            return Err(service_error(
                "service installed but could not be started",
                e,
            ))
        }
    }
    register_autostart(RUN_KEY, RUN_VALUE, &exe, NOTIFIER_ARG)
        .map_err(|e| format!("service installed but notifier autostart failed: {e}"))?;
    notes.push(format!(
        "notifier autostart registered ({RUN_KEY}\\{RUN_VALUE})"
    ));
    register_autostart(USER_RUN_KEY, TRAY_RUN_VALUE, &exe, TRAY_ARG)
        .map_err(|e| format!("service installed but tray autostart failed: {e}"))?;
    notes.push(format!(
        "tray autostart registered ({USER_RUN_KEY}\\{TRAY_RUN_VALUE})"
    ));
    notes.push(format!("executable: {}", exe.display()));
    Ok(notes.join("\n"))
}

pub fn uninstall_service() -> Result<String, String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| service_error("cannot open the Service Control Manager", e))?;
    let mut notes = Vec::new();
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    match manager.open_service(config::SERVICE_NAME, access) {
        Ok(service) => {
            stop_and_wait(&service);
            service
                .delete()
                .map_err(|e| service_error("cannot delete service", e))?;
            notes.push(format!("service '{}' removed", config::SERVICE_NAME));
        }
        Err(e) if win32_code(&e) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
            notes.push(format!(
                "service '{}' was not installed",
                config::SERVICE_NAME
            ));
        }
        Err(e) => return Err(service_error("cannot open service", e)),
    }

    if unregister_autostart(RUN_KEY, RUN_VALUE) {
        notes.push("notifier autostart removed".to_string());
    }
    if unregister_autostart(USER_RUN_KEY, TRAY_RUN_VALUE) {
        notes.push("tray autostart removed".to_string());
    }
    let stopped = stop_session_processes(NOTIFIER_ARG) + stop_session_processes(TRAY_ARG);
    if stopped > 0 {
        notes.push(format!("stopped {stopped} notifier/tray process(es)"));
    }
    let removed = canary::remove_canaries(
        &AppConfig::for_base_dir(&config::default_base_dir()),
        &discover_canary_dirs(),
    );
    notes.push(format!("removed {removed} canary file(s)"));
    Ok(notes.join("\n"))
}

static SERVICE_CONTEXT: OnceLock<(Arc<AtomicBool>, AppConfig)> = OnceLock::new();

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = service_body() {
        logger::error(format!("service terminated with error: {e}"));
    }
}

fn service_body() -> windows_service::Result<()> {
    let Some((shutdown, cfg)) = SERVICE_CONTEXT.get().cloned() else {
        return Ok(());
    };
    let stop_flag = Arc::clone(&shutdown);
    let handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                stop_flag.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status = service_control_handler::register(config::SERVICE_NAME, handler)?;
    status.set_service_status(service_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ))?;
    crate::engine::run(cfg, shutdown);
    status.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
    ))?;
    Ok(())
}

/// Hands control to the SCM dispatcher; returns when the service stops.
pub fn run_service(shutdown: Arc<AtomicBool>, cfg: AppConfig) -> Result<(), String> {
    if SERVICE_CONTEXT.set((shutdown, cfg)).is_err() {
        return Err("service context already initialized".to_string());
    }
    service_dispatcher::start(config::SERVICE_NAME, ffi_service_main).map_err(|e| {
        if win32_code(&e) == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            "not launched by the Service Control Manager; use --console to run interactively or --install to register the service".to_string()
        } else {
            format!("service dispatcher failed: {e}")
        }
    })
}

static CONSOLE_SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> i32 {
    if let Some(flag) = CONSOLE_SHUTDOWN.get() {
        flag.store(true, Ordering::SeqCst);
    }
    if ctrl_type == CTRL_CLOSE_EVENT {
        // Window close terminates the process when the handler returns; give workers a moment.
        thread::sleep(Duration::from_secs(2));
    }
    1
}

pub fn install_ctrlc_handler(shutdown: Arc<AtomicBool>) {
    let _ = CONSOLE_SHUTDOWN.set(shutdown);
    // SAFETY: registers a 'static handler function with the matching signature.
    unsafe {
        SetConsoleCtrlHandler(Some(console_ctrl_handler), 1);
    }
}

/// Closes the console window when this process owns it (Run-key launch of a console binary).
pub fn detach_console() {
    let mut pids = [0u32; 4];
    // SAFETY: the buffer length passed matches the array.
    unsafe {
        if GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) == 1 {
            FreeConsole();
        }
    }
}

/// Notification-area icon: hidden window + Shell_NotifyIconW, polling events.jsonl once a second.
mod tray {
    use super::{to_wide, TRAY_MUTEX_NAME};
    use crate::config::{AppConfig, EVENTS_FILE_NAME};
    use crate::notifier::EventTail;
    use crate::platform::{self, GUI_EXE_STEM};
    use crate::quarantine::{self, ThreatEvent};
    use crate::status;
    use std::cell::RefCell;
    use std::ffi::OsStr;
    use std::mem::size_of;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HWND, LPARAM, LRESULT, POINT, WPARAM,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::HiDpi::{
        SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
        NIM_MODIFY, NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
        DispatchMessageW, GetCursorPos, GetMessageW, GetSystemMetrics, KillTimer, LoadIconW,
        LoadImageW, PostMessageW, PostQuitMessage, RegisterClassExW, RegisterWindowMessageW,
        SetForegroundWindow, SetTimer, TrackPopupMenu, TranslateMessage, HICON, IDI_APPLICATION,
        IMAGE_ICON, LR_DEFAULTCOLOR, LR_LOADFROMFILE, MF_SEPARATOR, MF_STRING, MSG, SM_CXSMICON,
        SM_CYSMICON, SW_HIDE, SW_SHOWNORMAL, TPM_BOTTOMALIGN, TPM_RIGHTBUTTON, WM_APP, WM_COMMAND,
        WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WM_TIMER, WNDCLASSEXW,
        WS_OVERLAPPED,
    };

    const WM_TRAY: u32 = WM_APP + 1;
    const TRAY_ID: u32 = 1;
    const TIMER_ID: usize = 1;
    const POLL_MS: u32 = 1000;
    const CMD_OPEN: usize = 1001;
    const CMD_SCAN: usize = 1002;
    const CMD_EXIT: usize = 1003;
    /// Resource ID of the icon embedded into the-nex.exe by the daemon's build script.
    const ICON_RESOURCE_ID: usize = 1;
    const MAX_TOASTS_PER_POLL: usize = 3;

    static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

    struct TrayState {
        cfg: AppConfig,
        tail: EventTail,
        icon: HICON,
        alerts: u64,
        last_alert: Option<String>,
    }

    thread_local! {
        static STATE: RefCell<Option<TrayState>> = const { RefCell::new(None) };
    }

    fn wide(text: &str) -> Vec<u16> {
        to_wide(OsStr::new(text))
    }

    fn copy_into(dst: &mut [u16], text: &str) {
        let units: Vec<u16> = text.encode_utf16().take(dst.len() - 1).collect();
        dst[..units.len()].copy_from_slice(&units);
        dst[units.len()] = 0;
    }

    fn icon_file_candidates(cfg: &AppConfig) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_path_buf))
        {
            candidates.push(dir.join("icon.ico"));
            candidates.push(dir.join("thenex.ico"));
        }
        candidates.push(cfg.base_dir.join("icon.ico"));
        candidates
    }

    /// Embedded resource first (crisp, multi-size), then icon.ico beside the exe or in the data dir.
    unsafe fn load_icon(cfg: &AppConfig) -> HICON {
        let cx = GetSystemMetrics(SM_CXSMICON);
        let cy = GetSystemMetrics(SM_CYSMICON);
        let module = GetModuleHandleW(ptr::null());
        let embedded = LoadImageW(
            module,
            ICON_RESOURCE_ID as *const u16,
            IMAGE_ICON,
            cx,
            cy,
            LR_DEFAULTCOLOR,
        );
        if !embedded.is_null() {
            return embedded;
        }
        for path in icon_file_candidates(cfg) {
            if !path.is_file() {
                continue;
            }
            let wide_path = to_wide(path.as_os_str());
            let loaded = LoadImageW(
                ptr::null_mut(),
                wide_path.as_ptr(),
                IMAGE_ICON,
                cx,
                cy,
                LR_LOADFROMFILE,
            );
            if !loaded.is_null() {
                return loaded;
            }
        }
        LoadIconW(ptr::null_mut(), IDI_APPLICATION)
    }

    fn tooltip(cfg: &AppConfig, alerts: u64, last_alert: Option<&str>) -> String {
        let state = match status::read_status(&cfg.status_file) {
            Some(s) if s.is_fresh() && s.dry_run => "Protected (dry run)",
            Some(s) if s.is_fresh() => "Protected",
            _ => "Service offline",
        };
        let mut text = format!("The Nex · {state}");
        if alerts > 0 {
            text.push_str(&format!(
                " · {alerts} alert{}",
                if alerts == 1 { "" } else { "s" }
            ));
        }
        if let Some(last) = last_alert {
            text.push('\n');
            text.push_str(last);
        }
        quarantine::truncate_chars(&text, 127)
    }

    unsafe fn notify_data(hwnd: HWND, icon: HICON, tip: &str) -> NOTIFYICONDATAW {
        let mut data: NOTIFYICONDATAW = std::mem::zeroed();
        data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = hwnd;
        data.uID = TRAY_ID;
        data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        data.uCallbackMessage = WM_TRAY;
        data.hIcon = icon;
        copy_into(&mut data.szTip, tip);
        data
    }

    fn snapshot() -> Option<(HICON, String)> {
        STATE.with(|cell| {
            let guard = cell.try_borrow().ok()?;
            let state = guard.as_ref()?;
            Some((
                state.icon,
                tooltip(&state.cfg, state.alerts, state.last_alert.as_deref()),
            ))
        })
    }

    unsafe fn add_icon(hwnd: HWND) {
        if let Some((icon, tip)) = snapshot() {
            let data = notify_data(hwnd, icon, &tip);
            Shell_NotifyIconW(NIM_ADD, &data);
        }
    }

    unsafe fn remove_icon(hwnd: HWND) {
        let mut data: NOTIFYICONDATAW = std::mem::zeroed();
        data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = hwnd;
        data.uID = TRAY_ID;
        Shell_NotifyIconW(NIM_DELETE, &data);
    }

    /// Pulls new events; state is released before toasts so a re-entrant message never sees a held borrow.
    unsafe fn poll(hwnd: HWND) {
        let alerts: Vec<ThreatEvent> = STATE
            .with(|cell| {
                let mut guard = cell.try_borrow_mut().ok()?;
                let state = guard.as_mut()?;
                let fresh: Vec<ThreatEvent> = state
                    .tail
                    .poll()
                    .into_iter()
                    .filter(ThreatEvent::is_alert)
                    .collect();
                state.alerts += fresh.len() as u64;
                if let Some(last) = fresh.last() {
                    state.last_alert = Some(format!(
                        "{} {}: {}",
                        last.timestamp.with_timezone(&chrono::Local).format("%H:%M"),
                        last.threat_type,
                        last.action_taken
                    ));
                }
                Some(fresh)
            })
            .unwrap_or_default();
        if let Some((icon, tip)) = snapshot() {
            let data = notify_data(hwnd, icon, &tip);
            Shell_NotifyIconW(NIM_MODIFY, &data);
        }
        for event in alerts.iter().take(MAX_TOASTS_PER_POLL) {
            platform::send_desktop_notification_async(
                &quarantine::notification_title(event),
                &quarantine::notification_body(event),
            );
        }
    }

    unsafe fn shell_open(hwnd: HWND, verb: &str, file: &Path, parameters: &str, show: i32) -> bool {
        let verb = wide(verb);
        let file = to_wide(file.as_os_str());
        let parameters = wide(parameters);
        let result = ShellExecuteW(
            hwnd,
            verb.as_ptr(),
            file.as_ptr(),
            parameters.as_ptr(),
            ptr::null(),
            show,
        );
        result as usize > 32
    }

    unsafe fn open_gui(hwnd: HWND) {
        let gui = platform::sibling_executable(GUI_EXE_STEM);
        if !gui.is_file() {
            platform::send_desktop_notification_async(
                "The Nex",
                &format!("The desktop app was not found at {}", gui.display()),
            );
            return;
        }
        if !shell_open(hwnd, "open", &gui, "", SW_SHOWNORMAL) {
            platform::send_desktop_notification_async("The Nex", "Could not open the desktop app.");
        }
    }

    unsafe fn start_quick_scan(hwnd: HWND) {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        if shell_open(hwnd, "runas", &exe, "--quick-scan", SW_HIDE) {
            platform::send_desktop_notification_async(
                "The Nex",
                "Quick scan started. Findings appear in the activity log.",
            );
        } else {
            platform::send_desktop_notification_async(
                "The Nex",
                "Quick scan needs administrator approval and was not started.",
            );
        }
    }

    unsafe fn show_menu(hwnd: HWND) {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let open = wide("Open The Nex");
        let scan = wide("Quick Scan");
        let exit = wide("Exit Tray");
        AppendMenuW(menu, MF_STRING, CMD_OPEN, open.as_ptr());
        AppendMenuW(menu, MF_STRING, CMD_SCAN, scan.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_EXIT, exit.as_ptr());
        let mut point = POINT { x: 0, y: 0 };
        GetCursorPos(&mut point);
        // Foreground + WM_NULL make the menu close when the user clicks elsewhere.
        SetForegroundWindow(hwnd);
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
            point.x,
            point.y,
            0,
            hwnd,
            ptr::null(),
        );
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_TRAY => {
                match lparam as u32 {
                    WM_LBUTTONUP => open_gui(hwnd),
                    WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                    _ => {}
                }
                0
            }
            WM_COMMAND => {
                match wparam & 0xFFFF {
                    CMD_OPEN => open_gui(hwnd),
                    CMD_SCAN => start_quick_scan(hwnd),
                    CMD_EXIT => {
                        DestroyWindow(hwnd);
                    }
                    _ => {}
                }
                0
            }
            WM_TIMER => {
                poll(hwnd);
                0
            }
            WM_DESTROY => {
                KillTimer(hwnd, TIMER_ID);
                remove_icon(hwnd);
                PostQuitMessage(0);
                0
            }
            _ => {
                let taskbar_created = TASKBAR_CREATED.load(Ordering::Relaxed);
                if taskbar_created != 0 && msg == taskbar_created {
                    // Explorer restarted: the notification area forgot every icon.
                    add_icon(hwnd);
                    return 0;
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
        }
    }

    pub fn run(cfg: AppConfig) -> Result<(), String> {
        let mutex_name = to_wide(OsStr::new(TRAY_MUTEX_NAME));
        // SAFETY: plain Win32 calls with valid NUL-terminated strings; every handle is released.
        unsafe {
            let mutex = CreateMutexW(ptr::null(), 0, mutex_name.as_ptr());
            if mutex.is_null() {
                return Err("cannot create the tray mutex".to_string());
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                CloseHandle(mutex);
                return Ok(());
            }
            let result = message_loop(cfg);
            CloseHandle(mutex);
            result
        }
    }

    unsafe fn message_loop(cfg: AppConfig) -> Result<(), String> {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let instance = GetModuleHandleW(ptr::null());
        let class_name = wide("TheNexTrayWindow");
        let mut class: WNDCLASSEXW = std::mem::zeroed();
        class.cbSize = size_of::<WNDCLASSEXW>() as u32;
        class.lpfnWndProc = Some(window_proc);
        class.hInstance = instance;
        class.lpszClassName = class_name.as_ptr();
        if RegisterClassExW(&class) == 0 {
            return Err(format!(
                "RegisterClassExW failed (Win32 error {})",
                GetLastError()
            ));
        }
        let title = wide("The Nex");
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            ptr::null(),
        );
        if hwnd.is_null() {
            return Err(format!(
                "CreateWindowExW failed (Win32 error {})",
                GetLastError()
            ));
        }
        let taskbar_message = wide("TaskbarCreated");
        TASKBAR_CREATED.store(
            RegisterWindowMessageW(taskbar_message.as_ptr()),
            Ordering::Relaxed,
        );

        let events = if cfg.events_log.file_name().is_some() {
            cfg.events_log.clone()
        } else {
            cfg.log_dir.join(EVENTS_FILE_NAME)
        };
        let icon = load_icon(&cfg);
        STATE.with(|cell| {
            *cell.borrow_mut() = Some(TrayState {
                tail: EventTail::new(events),
                cfg,
                icon,
                alerts: 0,
                last_alert: None,
            })
        });
        add_icon(hwnd);
        SetTimer(hwnd, TIMER_ID, POLL_MS, None);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        STATE.with(|cell| cell.borrow_mut().take());
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn tooltips_fit_the_shell_limit() {
            let cfg = AppConfig::for_base_dir(&std::env::temp_dir().join("thenex-tray-test"));
            let long = "x".repeat(400);
            let text = tooltip(&cfg, 12, Some(&long));
            assert!(text.chars().count() <= 127);
            assert!(text.starts_with("The Nex · Service offline · 12 alerts"));
            let mut buffer = [0u16; 128];
            copy_into(&mut buffer, &text);
            assert_eq!(
                buffer.iter().position(|&c| c == 0),
                Some(text.encode_utf16().count())
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_keys_normalize() {
        assert_eq!(path_key(Path::new(r"C:\Users\A\")), r"c:\users\a");
        assert_eq!(path_key(Path::new(r"\\?\C:\Users\A")), r"c:\users\a");
        assert_eq!(path_key(Path::new("C:/Users/A")), r"c:\users\a");
        assert!(path_is_within(
            Path::new(r"C:\Users\A\Desktop\x"),
            Path::new(r"c:\users\a")
        ));
        assert!(!path_is_within(
            Path::new(r"C:\Users\Ab\x"),
            Path::new(r"C:\Users\A")
        ));
    }

    #[test]
    fn system_binaries_are_trusted_and_temp_is_not() {
        assert!(is_trusted_binary(&system32_tool("notepad.exe")));
        assert!(!is_in_trusted_root(
            &system_root().join("Temp").join("x.exe")
        ));
        assert!(!is_in_trusted_root(
            &system_root().join(r"System32\..\..\Users\a\evil.exe")
        ));
        assert!(!is_in_trusted_root(
            &system32_tool("spool")
                .join("drivers")
                .join("color")
                .join("x.exe")
        ));
    }

    #[test]
    fn unsigned_temp_file_is_not_trusted() {
        let path = env::temp_dir().join(format!("thenex-untrusted-{}.exe", std::process::id()));
        fs::write(&path, b"MZ not really a binary").unwrap();
        assert!(!is_trusted_binary(&path));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn hidden_attribute_is_applied() {
        let path = env::temp_dir().join(format!("thenex-hidden-{}.txt", std::process::id()));
        fs::write(&path, b"x").unwrap();
        set_hidden_file(&path);
        let wide = to_wide(path.as_os_str());
        // SAFETY: valid NUL-terminated path.
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        assert_ne!(attributes, INVALID_FILE_ATTRIBUTES);
        assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN, 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn arguments_are_quoted_for_elevation() {
        assert_eq!(quote_arg("--restore"), "--restore");
        assert_eq!(
            quote_arg("C:\\Program Files\\x"),
            "\"C:\\Program Files\\x\""
        );
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(
            quote_arg("C:\\dir with space\\"),
            "\"C:\\dir with space\\\\\""
        );
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn the_service_runs_a_copy_in_the_protected_folder() {
        let base = Path::new(r"C:\ProgramData\TheNex");
        let built = Path::new(r"C:\Users\kim\the-nex\target\release\the-nex.exe");
        assert_eq!(
            engine_destination(built, base),
            Some(base.join("the-nex.exe"))
        );
        // The installer runs it from there already; the case of the letters does not matter.
        let installed = Path::new(r"c:\programdata\thenex\the-nex.exe");
        assert_eq!(engine_destination(installed, base), None);
    }

    #[test]
    fn tray_mutex_is_absent_without_a_tray() {
        if !tray_is_running() {
            assert!(!tray_is_running());
        }
        assert!(TRAY_MUTEX_NAME.starts_with("Local\\"));
    }
}
