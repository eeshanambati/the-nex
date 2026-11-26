use crate::config::AppConfig;
use crate::known_bad::Digest32;
use crate::logger::{self, lock_or_recover};
use crate::platform;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

const MAX_EVENTS_BYTES: u64 = 50 * 1024 * 1024;
const MOVE_ATTEMPTS: u32 = 8;
const MOVE_RETRY_DELAY: Duration = Duration::from_millis(250);
const META_SUFFIX: &str = ".meta.json";
const QUARANTINE_SUFFIX: &str = ".quarantined";
const MAX_ID_LEN: usize = 64;

static EVENT_LOG_LOCK: Mutex<()> = Mutex::new(());
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);
static THREAT_EVENTS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub threat_type: String,
    pub severity: Severity,
    pub target: String,
    pub action_taken: String,
    pub details: String,
    /// Recorded without a desktop notification (one finding among many in a full scan; the
    /// scan's own summary event is the alert).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quiet: bool,
    /// SHA-256 of the file judged, recorded for detections that "Always allow" can cover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl ThreatEvent {
    pub fn new(
        threat_type: &str,
        severity: Severity,
        target: impl Into<String>,
        action_taken: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            id: new_id(),
            timestamp: Utc::now(),
            threat_type: threat_type.to_string(),
            severity,
            target: target.into(),
            action_taken: action_taken.into(),
            details: details.into(),
            quiet: false,
            sha256: None,
        }
    }

    pub fn with_sha256(self, digest: Option<Digest32>) -> Self {
        Self {
            sha256: digest.map(|d| to_hex(&d)),
            ..self
        }
    }

    /// Worth a person's attention: every detection, and nothing that is only a record (a restore,
    /// a scan that found nothing).
    pub fn is_alert(&self) -> bool {
        !self.quiet && self.severity > Severity::Low
    }

    /// Quarantine ID recorded in `action_taken` ("QUARANTINED id=<ID>"), if any.
    pub fn quarantine_id(&self) -> Option<&str> {
        let rest = self.action_taken.split("id=").nth(1)?;
        let id = rest.split(|c: char| c.is_whitespace() || c == ';').next()?;
        is_valid_id(id).then_some(id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineMeta {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantined_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub threat_type: String,
    pub details: String,
    pub quarantined_at: DateTime<Utc>,
    /// Original owner (Unix only) so a root restore hands the file back to the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_gid: Option<u32>,
    /// Original permission bits (Unix), restored instead of a blanket 0644.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_mode: Option<u32>,
    /// (device, inode) of the original parent folder (Unix); restore refuses a different folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_dev: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_ino: Option<u64>,
}

pub fn new_id() -> String {
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed) % 10_000;
    format!(
        "{}-{:x}-{n:04}",
        Utc::now().format("%Y%m%d%H%M%S%3f"),
        std::process::id()
    )
}

pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(max_chars.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

pub fn notification_title(event: &ThreatEvent) -> String {
    format!(
        "The Nex: {} ({})",
        event.threat_type,
        event.severity.as_str()
    )
}

pub fn notification_body(event: &ThreatEvent) -> String {
    format!(
        "{}\n{}",
        truncate_chars(&event.target, 120),
        truncate_chars(&event.action_taken, 120)
    )
}

/// Threat events (severity above LOW) recorded by this process.
pub fn threat_events_recorded() -> u64 {
    THREAT_EVENTS.load(Ordering::Relaxed)
}

/// Appends one JSON line; a single write on an O_APPEND handle keeps lines whole.
pub fn append_event(cfg: &AppConfig, event: &ThreatEvent) -> io::Result<()> {
    let _guard = lock_or_recover(&EVENT_LOG_LOCK);
    if let Some(parent) = cfg.events_log.parent() {
        fs::create_dir_all(parent)?;
    }
    rotate_events_if_needed(&cfg.events_log);
    let mut line = serde_json::to_string(event).map_err(io::Error::other)?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.events_log)?;
    file.write_all(line.as_bytes())?;
    file.flush()
}

pub fn record_event(cfg: &AppConfig, event: ThreatEvent) {
    let event = ThreatEvent {
        quiet: event.quiet || cfg.quiet_events,
        ..event
    };
    if cfg.repeats.as_ref().is_some_and(|r| r.is_repeat(&event)) {
        logger::info(format!(
            "{} already reported by an earlier scheduled scan: {}",
            event.threat_type, event.target
        ));
        return;
    }
    let summary = format!(
        "{} [{}] target={} action={} details={}",
        event.threat_type,
        event.severity.as_str(),
        event.target,
        event.action_taken,
        event.details
    );
    if event.severity == Severity::Low {
        logger::info(summary);
    } else {
        THREAT_EVENTS.fetch_add(1, Ordering::Relaxed);
        logger::warn(summary);
    }
    if let Err(e) = append_event(cfg, &event) {
        logger::error(format!(
            "cannot append event to {}: {e}",
            cfg.events_log.display()
        ));
    }
    if cfg.interactive && !event.quiet {
        platform::send_desktop_notification_async(
            &notification_title(&event),
            &notification_body(&event),
        );
    }
}

const RESTORE_EVENT: &str = "QUARANTINE_RESTORE";
/// Why a restored file is only reported (see `was_restored`).
pub const RESTORED_BY_USER: &str = "you restored this file from quarantine";

/// Logs that a person put a file back, which also keeps it there (see `was_restored`).
pub fn record_restore(cfg: &AppConfig, meta: &QuarantineMeta, how: &str) {
    let mut event = ThreatEvent::new(
        RESTORE_EVENT,
        Severity::Low,
        meta.original_path.display().to_string(),
        "RESTORED",
        format!("id={} sha256={}{how}", meta.id, meta.sha256),
    );
    event.sha256 = Some(meta.sha256.clone());
    record_event(cfg, event);
}

/// The file at `path` is, byte for byte, one a person put back there. An estimate must not take
/// it away again the moment it lands; a match in the known-malware list still may. The answer
/// comes from the engine's own log, which other programs cannot write.
/// shortcut: forgotten once the log has rotated twice (2 x 50 MB); give it its own list then.
pub fn was_restored(cfg: &AppConfig, path: &Path, digest: Option<Digest32>) -> bool {
    let real = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let keys = [platform::path_key(path), platform::path_key(&real)];
    let mut hashes: Vec<String> = Vec::new();
    for log in [rotated_events_path(&cfg.events_log), cfg.events_log.clone()] {
        let Ok(bytes) = fs::read(&log) else {
            continue;
        };
        // Only the few lines that can be a restore are parsed.
        let restores = bytes
            .split(|b| *b == b'\n')
            .filter(|line| {
                line.windows(RESTORE_EVENT.len())
                    .any(|w| w == RESTORE_EVENT.as_bytes())
            })
            .filter_map(|line| serde_json::from_slice::<ThreatEvent>(line).ok());
        hashes.extend(
            restores
                .filter(|e| e.threat_type == RESTORE_EVENT)
                .filter(|e| keys.contains(&platform::path_key(Path::new(&e.target))))
                .filter_map(|e| e.sha256),
        );
    }
    if hashes.is_empty() {
        return false;
    }
    let found = digest.map_or_else(|| sha256_file(path).ok(), |d| Some(to_hex(&d)));
    found.is_some_and(|found| hashes.contains(&found))
}

/// Where the full log is moved to (`events.jsonl` becomes `events.jsonl.1`).
pub fn rotated_events_path(path: &Path) -> PathBuf {
    path.with_extension("jsonl.1")
}

fn rotate_events_if_needed(path: &Path) {
    if fs::metadata(path)
        .map(|m| m.len() >= MAX_EVENTS_BYTES)
        .unwrap_or(false)
    {
        let rotated = rotated_events_path(path);
        let _ = fs::remove_file(&rotated);
        let _ = fs::rename(path, &rotated);
    }
}

/// Newest-first events from the log, reading at most the trailing `max_bytes`.
pub fn read_recent_events(path: &Path, max_bytes: u64) -> io::Result<Vec<ThreatEvent>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    let mut buffer = Vec::with_capacity((len - start) as usize);
    io::Seek::seek(&mut file, io::SeekFrom::Start(start))?;
    file.read_to_end(&mut buffer)?;
    let text = String::from_utf8_lossy(&buffer);
    let mut lines = text.lines();
    if start > 0 {
        lines.next();
    }
    let mut events: Vec<ThreatEvent> = lines
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    events.reverse();
    Ok(events)
}

/// Opens a regular file for reading without following a final symlink. O_NONBLOCK keeps a FIFO
/// planted in its place from hanging the daemon, and anything but a regular file is refused.
#[cfg(unix)]
pub fn open_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
pub fn open_nofollow(path: &Path) -> io::Result<File> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symlink refused",
        ));
    }
    File::open(path)
}

/// Rewrites the permission bits of a regular file; refuses symlinks and never follows one.
/// Unix: fchmod on an O_NOFOLLOW handle.
#[cfg(unix)]
pub fn chmod_nofollow(path: &Path, change: impl FnOnce(u32) -> u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match open_nofollow(path) {
        Ok(file) => {
            let meta = file.metadata()?;
            if !meta.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a regular file",
                ));
            }
            file.set_permissions(fs::Permissions::from_mode(change(
                meta.permissions().mode(),
            )))
        }
        // A mode-000 file cannot be opened by its (non-root) owner. root never lands here, and
        // a non-root caller gains nothing from a followed link, so check the link and use the path.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            let meta = fs::symlink_metadata(path)?;
            if !meta.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a regular file",
                ));
            }
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(change(meta.permissions().mode())),
            )
        }
        Err(e) => Err(e),
    }
}

/// Toggles the read-only state of a regular file. Refuses symlinks (a root caller must never
/// chmod whatever a user-planted link points at).
pub fn set_readonly(path: &Path, readonly: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is a symlink", path.display()),
            ));
        }
        // Owner-write only on clear: std's set_readonly(false) would make the file world-writable.
        chmod_nofollow(path, |mode| {
            if readonly {
                mode & !0o222
            } else {
                mode | 0o200
            }
        })
    }
    #[cfg(not(unix))]
    {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        let mut permissions = meta.permissions();
        if permissions.readonly() != readonly {
            permissions.set_readonly(readonly);
            fs::set_permissions(path, permissions)?;
        }
        Ok(())
    }
}

/// Rename first; fall back to copy + delete for cross-volume moves. Retries cover
/// transient sharing violations (scanners, a just-terminated process image).
/// Path-based: used by the Windows paths only. On Unix the fd-relative `fdops` moves replace it.
// UNVERIFIED (Windows, known limitation): a junction swapped into a parent folder between the
// checks and this move can still redirect it, and fs::copy may follow a reparse point at the
// destination. Closing that needs handle-based (NtSetInformationFile) renames; not done yet.
#[cfg_attr(unix, allow(dead_code))]
pub fn move_file(src: &Path, dst: &Path) -> io::Result<()> {
    let mut last_error = io::Error::other("move not attempted");
    for attempt in 0..MOVE_ATTEMPTS {
        let rename_error = match fs::rename(src, dst) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        let fallback_error = match fs::copy(src, dst) {
            Ok(_) => {
                let _ = set_readonly(src, false);
                match fs::remove_file(src) {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let _ = set_readonly(dst, false);
                        let _ = fs::remove_file(dst);
                        e
                    }
                }
            }
            Err(e) => {
                if dst.exists() {
                    let _ = fs::remove_file(dst);
                }
                e
            }
        };
        last_error = io::Error::new(
            fallback_error.kind(),
            format!("rename failed ({rename_error}); copy fallback failed ({fallback_error})"),
        );
        if attempt + 1 < MOVE_ATTEMPTS {
            thread::sleep(MOVE_RETRY_DELAY);
        }
    }
    Err(last_error)
}

fn sanitize_file_name(path: &Path) -> String {
    let raw = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect();
    if cleaned.is_empty() {
        "unnamed".to_string()
    } else {
        cleaned
    }
}

pub fn meta_path(cfg: &AppConfig, id: &str) -> PathBuf {
    cfg.quarantine_dir.join(format!("{id}{META_SUFFIX}"))
}

fn write_meta(cfg: &AppConfig, meta: &QuarantineMeta) -> io::Result<()> {
    let target = meta_path(cfg, &meta.id);
    let staging = target.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    fs::write(&staging, body)?;
    fs::rename(&staging, &target)
}

/// True when `canonical` is `lexical` with no link resolved other than macOS's root-owned
/// system aliases (/tmp, /var, /etc -> /private/...). HFS/APFS are case-insensitive by default.
#[cfg(unix)]
fn same_dir(canonical: &Path, lexical: &Path) -> bool {
    let mut lex = lexical.to_path_buf();
    #[cfg(target_os = "macos")]
    if let Some(Component::Normal(first)) = lexical.components().nth(1) {
        if matches!(first.to_str(), Some("tmp" | "var" | "etc")) {
            lex = Path::new("/private").join(lexical.strip_prefix("/").unwrap_or(lexical));
        }
    }
    let norm = |p: &Path| {
        let s = p.to_string_lossy().into_owned();
        if cfg!(target_os = "macos") {
            s.to_lowercase()
        } else {
            s
        }
    };
    norm(&lex) == norm(canonical)
}

pub fn quarantine_file(
    path: &Path,
    cfg: &AppConfig,
    threat_type: &str,
    details: &str,
) -> io::Result<QuarantineMeta> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    fs::create_dir_all(&cfg.quarantine_dir)?;
    // Canonical parent: restore later refuses a destination whose parent resolves elsewhere.
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let original_path = match (
        absolute.parent().map(fs::canonicalize),
        absolute.file_name(),
    ) {
        (Some(Ok(parent)), Some(name)) => {
            // A parent that resolves elsewhere than the path we were given means a link was
            // swapped in after the scan: root would move a file the detector never looked at.
            #[cfg(unix)]
            if !same_dir(&parent, absolute.parent().unwrap_or(Path::new("/"))) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} resolves through a link; refusing to quarantine",
                        absolute.display()
                    ),
                ));
            }
            platform::plain_path(parent.join(name))
        }
        _ => absolute,
    };
    // Whatever the detector was given: a file in a never-scan place is never moved.
    cfg.skipped.refresh();
    if cfg.is_skipped(&original_path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is on the never-scan list", original_path.display()),
        ));
    }
    let id = new_id();
    let quarantined_path = cfg.quarantine_dir.join(format!(
        "{id}_{}{QUARANTINE_SUFFIX}",
        sanitize_file_name(path)
    ));

    #[cfg(unix)]
    let moved = fdops::quarantine_move(&original_path, &quarantined_path)?;
    #[cfg(not(unix))]
    let moved = {
        let sha256 = sha256_file(path)?;
        move_file(&original_path, &quarantined_path)?;
        Moved {
            sha256,
            size: metadata.len(),
            ..Moved::default()
        }
    };
    platform::lock_quarantined_file(&quarantined_path);

    let mut meta = QuarantineMeta {
        id,
        original_path,
        quarantined_path,
        sha256: moved.sha256,
        size: moved.size,
        threat_type: threat_type.to_string(),
        details: details.to_string(),
        quarantined_at: Utc::now(),
        owner_uid: moved.uid,
        owner_gid: moved.gid,
        original_mode: moved.mode,
        parent_dev: moved.parent_dev,
        parent_ino: moved.parent_ino,
    };
    if let Err(e) = write_meta(cfg, &meta) {
        platform::unlock_restored_file(&meta.quarantined_path);
        #[cfg(unix)]
        let rolled_back = fdops::restore_move(&meta);
        #[cfg(not(unix))]
        let rolled_back = move_file(&meta.quarantined_path, &meta.original_path);
        if let Err(re) = rolled_back {
            logger::error(format!(
                "quarantine record failed and rollback of {} -> {} failed: {re}",
                meta.quarantined_path.display(),
                meta.original_path.display()
            ));
        }
        return Err(e);
    }
    // Only now, because it can take long and a file without a record could not be restored. A
    // writer that still held the file open may have changed it after the move: record what is
    // there now, or restore would refuse on a hash mismatch forever.
    if let Ok(now) = sha256_file(&meta.quarantined_path) {
        if now != meta.sha256 {
            meta.sha256 = now;
            if let Err(e) = write_meta(cfg, &meta) {
                logger::error(format!("quarantine record {} not updated: {e}", meta.id));
            }
        }
    }
    Ok(meta)
}

/// What the move captured from the very file it moved (Unix: from one fstat on the open fd).
#[derive(Default)]
struct Moved {
    sha256: String,
    size: u64,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
    parent_dev: Option<u64>,
    parent_ino: Option<u64>,
}

/// Reads and validates a quarantine record; the stored path must stay inside the quarantine folder.
pub fn load_meta(id: &str, cfg: &AppConfig) -> io::Result<QuarantineMeta> {
    if !is_valid_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid quarantine ID: {id}"),
        ));
    }
    let meta_file = meta_path(cfg, id);
    let raw = fs::read(&meta_file)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", meta_file.display())))?;
    let meta: QuarantineMeta =
        serde_json::from_slice(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let clean = |p: &Path| !p.components().any(|c| matches!(c, Component::ParentDir));
    if meta.id != id
        || meta.quarantined_path.parent() != Some(cfg.quarantine_dir.as_path())
        || !clean(&meta.quarantined_path)
        || !clean(&meta.original_path)
        || !meta.original_path.is_absolute()
        || !platform::path_is_within(&meta.quarantined_path, &cfg.quarantine_dir)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quarantine metadata does not match its ID or location",
        ));
    }
    Ok(meta)
}

/// Every quarantine record, newest first.
pub fn list_quarantined(cfg: &AppConfig) -> io::Result<Vec<QuarantineMeta>> {
    let mut records = Vec::new();
    for entry in fs::read_dir(&cfg.quarantine_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(META_SUFFIX) else {
            continue;
        };
        if let Ok(meta) = load_meta(id, cfg) {
            records.push(meta);
        }
    }
    records.sort_by_key(|r| std::cmp::Reverse(r.quarantined_at));
    Ok(records)
}

pub fn restore_file(id: &str, cfg: &AppConfig) -> io::Result<QuarantineMeta> {
    let meta = load_meta(id, cfg)?;
    // symlink_metadata: a dangling link at the destination still counts as "exists".
    if fs::symlink_metadata(&meta.original_path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; move it away before restoring",
                meta.original_path.display()
            ),
        ));
    }
    platform::unlock_restored_file(&meta.quarantined_path);
    let relock = || platform::lock_quarantined_file(&meta.quarantined_path);
    if let Err(e) = restore_place(&meta) {
        relock();
        return Err(e);
    }
    fs::remove_file(meta_path(cfg, id))?;
    Ok(meta)
}

/// Unix: every step is fd-relative (see `fdops`), so a swapped parent folder cannot redirect the
/// root daemon, and the destination is created exclusively with no placeholder.
#[cfg(unix)]
fn restore_place(meta: &QuarantineMeta) -> io::Result<()> {
    fdops::restore_move(meta)
}

/// Runs as SYSTEM: the destination folder must still be the real folder recorded at quarantine
/// time, not a link a user swapped in since.
// UNVERIFIED (Windows, known limitation): this check and the move below are separate path
// operations, so a junction swapped in between them can still redirect the restore. A
// handle-based restore (open the parent without reparse, rename relative to that handle) is the
// planned fix; it could not be built or tested here.
#[cfg(not(unix))]
fn restore_place(meta: &QuarantineMeta) -> io::Result<()> {
    let parent = meta.original_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stored path has no parent folder",
        )
    })?;
    let real = fs::canonicalize(parent)?;
    if platform::path_key(&real) != platform::path_key(parent)
        || fs::symlink_metadata(parent)?.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} no longer resolves to itself; refusing to restore",
                parent.display()
            ),
        ));
    }
    let actual = sha256_file(&meta.quarantined_path)?;
    if actual != meta.sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SHA-256 mismatch for {}: expected {}, found {actual}",
                meta.quarantined_path.display(),
                meta.sha256
            ),
        ));
    }
    // create_new reserves the name (never overwrites); the later rename replaces only our placeholder.
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&meta.original_path)?;
    if let Err(e) = move_file(&meta.quarantined_path, &meta.original_path) {
        let _ = fs::remove_file(&meta.original_path);
        return Err(e);
    }
    // A same-volume rename keeps the quarantine ACL; re-inherit from the destination folder.
    platform::unlock_restored_file(&meta.original_path);
    Ok(())
}

/// Permanently removes a quarantined file and its record.
pub fn delete_quarantined_file(id: &str, cfg: &AppConfig) -> io::Result<QuarantineMeta> {
    let meta = load_meta(id, cfg)?;
    if meta.quarantined_path.exists() {
        platform::unlock_restored_file(&meta.quarantined_path);
        fs::remove_file(&meta.quarantined_path)?;
    }
    fs::remove_file(meta_path(cfg, id))?;
    Ok(meta)
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    hash_reader(&mut open_nofollow(path)?)
}

fn hash_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(to_hex(&hasher.finalize()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// fd-relative file moves for the root daemon. The parent folder is opened once by walking from
/// "/" one O_NOFOLLOW component at a time; everything after that goes through that directory fd,
/// so swapping a path component for a symlink afterwards cannot redirect a move, chmod or chown.
/// Remaining window: a same-owner swap of the *entry* inside the already-pinned folder, which can
/// at worst move a different file out of that same folder (checked by device/inode just before).
#[cfg(unix)]
mod fdops {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::io::Seek;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const DIR_FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    const FILE_FLAGS: i32 = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;

    fn bad(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
        io::Error::new(kind, msg.into())
    }

    fn openat(dir: RawFd, name: &OsStr, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        let name = CString::new(name.as_bytes())
            .map_err(|_| bad(io::ErrorKind::InvalidInput, "NUL in path"))?;
        // SAFETY: `name` is NUL-terminated and outlives the call; `dir` is a live descriptor or AT_FDCWD.
        let fd = unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                flags | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Opens an absolute directory, refusing a symlink at any component.
    fn open_dir_chain(path: &Path) -> io::Result<OwnedFd> {
        let mut dir = openat(libc::AT_FDCWD, OsStr::new("/"), DIR_FLAGS, 0)?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => dir = openat(dir.as_raw_fd(), name, DIR_FLAGS, 0)?,
                _ => return Err(bad(io::ErrorKind::InvalidInput, "path is not canonical")),
            }
        }
        Ok(dir)
    }

    fn unlinkat(dir: RawFd, name: &OsStr) -> io::Result<()> {
        let name = CString::new(name.as_bytes())
            .map_err(|_| bad(io::ErrorKind::InvalidInput, "NUL in path"))?;
        // SAFETY: `name` is NUL-terminated and outlives the call; `dir` is a live descriptor.
        if unsafe { libc::unlinkat(dir, name.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Renames without ever replacing an existing destination.
    fn rename_excl(src_dir: RawFd, src: &OsStr, dst_dir: RawFd, dst: &OsStr) -> io::Result<()> {
        let (src, dst) = (CString::new(src.as_bytes()), CString::new(dst.as_bytes()));
        let (Ok(src), Ok(dst)) = (src, dst) else {
            return Err(bad(io::ErrorKind::InvalidInput, "NUL in path"));
        };
        // SAFETY: both names are NUL-terminated and outlive the call; the directory fds are live.
        #[cfg(target_os = "macos")]
        let rc = unsafe {
            libc::renameatx_np(
                src_dir,
                src.as_ptr(),
                dst_dir,
                dst.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        // SAFETY: as above.
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::renameat2(
                src_dir,
                src.as_ptr(),
                dst_dir,
                dst.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        // Other unix: linkat fails with EEXIST instead of replacing; then drop the old name.
        // SAFETY: as above.
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let rc = unsafe {
            let rc = libc::linkat(src_dir, src.as_ptr(), dst_dir, dst.as_ptr(), 0);
            if rc == 0 {
                libc::unlinkat(src_dir, src.as_ptr(), 0)
            } else {
                rc
            }
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn fchown(file: &File, uid: u32, gid: u32) -> io::Result<()> {
        // SAFETY: `file` owns a live descriptor for the duration of the call.
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn id_of(meta: &fs::Metadata) -> (u64, u64) {
        (meta.dev(), meta.ino())
    }

    fn dir_id(dir: &OwnedFd) -> io::Result<(u64, u64)> {
        Ok(id_of(&File::from(dir.try_clone()?).metadata()?))
    }

    /// (dev, ino) of the entry currently named `name` in `dir`, never following a link.
    fn entry_id(dir: &OwnedFd, name: &OsStr) -> io::Result<(u64, u64)> {
        let entry = File::from(openat(dir.as_raw_fd(), name, FILE_FLAGS, 0)?);
        Ok(id_of(&entry.metadata()?))
    }

    fn split(path: &Path) -> io::Result<(&Path, &OsStr)> {
        match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => Ok((parent, name)),
            _ => Err(bad(io::ErrorKind::InvalidData, "path has no parent folder")),
        }
    }

    /// Copies while hashing, so the digest is of exactly the bytes written.
    fn copy_hashing(src: &mut File, dst: &mut File) -> io::Result<String> {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let n = src.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            dst.write_all(&buffer[..n])?;
        }
        dst.sync_all()?;
        Ok(to_hex(&hasher.finalize()))
    }

    /// Moves the file at `original` into quarantine. Owner, mode, size and hash all come from one
    /// descriptor opened O_NOFOLLOW|O_NONBLOCK; hard-linked and non-regular files are refused.
    pub fn quarantine_move(original: &Path, dst: &Path) -> io::Result<Moved> {
        let (parent, name) = split(original)?;
        let parent_fd = open_dir_chain(parent)?;
        let (parent_dev, parent_ino) = dir_id(&parent_fd)?;
        let mut src = File::from(openat(parent_fd.as_raw_fd(), name, FILE_FLAGS, 0)?);
        let meta = src.metadata()?;
        if !meta.is_file() {
            return Err(bad(io::ErrorKind::InvalidInput, "not a regular file"));
        }
        if meta.nlink() > 1 {
            return Err(bad(
                io::ErrorKind::InvalidInput,
                "hard-linked file refused (another name would keep it reachable)",
            ));
        }
        let mut sha256 = hash_reader(&mut src)?;
        let id = id_of(&meta);
        if entry_id(&parent_fd, name)? != id {
            return Err(bad(
                io::ErrorKind::InvalidData,
                "file changed while quarantining",
            ));
        }
        match rename_excl(parent_fd.as_raw_fd(), name, libc::AT_FDCWD, dst.as_os_str()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                // Cross-volume: O_EXCL|O_NOFOLLOW creation never follows a planted link.
                src.rewind()?;
                let mut out = File::from(openat(
                    libc::AT_FDCWD,
                    dst.as_os_str(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    0o600,
                )?);
                match copy_hashing(&mut src, &mut out) {
                    Ok(hash) => sha256 = hash,
                    Err(e) => {
                        let _ = fs::remove_file(dst);
                        return Err(e);
                    }
                }
                if entry_id(&parent_fd, name).ok() != Some(id) {
                    let _ = fs::remove_file(dst);
                    return Err(bad(
                        io::ErrorKind::InvalidData,
                        "file changed while quarantining",
                    ));
                }
                if let Err(e) = unlinkat(parent_fd.as_raw_fd(), name) {
                    let _ = fs::remove_file(dst);
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
        Ok(Moved {
            sha256,
            size: meta.len(),
            uid: Some(meta.uid()),
            gid: Some(meta.gid()),
            mode: Some(meta.mode() & 0o7777),
            parent_dev: Some(parent_dev),
            parent_ino: Some(parent_ino),
        })
    }

    /// Places `src` (already hash-checked) at `name` in `parent_fd`: exclusive create, copy,
    /// fsync, and the caller then unlinks the source.
    fn place_by_copy(
        src: &mut File,
        parent_fd: &OwnedFd,
        name: &OsStr,
        want_sha: &str,
    ) -> io::Result<File> {
        src.rewind()?;
        let mut out = File::from(openat(
            parent_fd.as_raw_fd(),
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )?);
        let copied = copy_hashing(src, &mut out).and_then(|hash| {
            if hash == want_sha {
                Ok(())
            } else {
                Err(bad(
                    io::ErrorKind::InvalidData,
                    "SHA-256 mismatch while copying",
                ))
            }
        });
        if let Err(e) = copied {
            let _ = unlinkat(parent_fd.as_raw_fd(), name);
            return Err(e);
        }
        Ok(out)
    }

    /// Moves the quarantined file back to its original name, fd-relative to the original parent.
    pub fn restore_move(meta: &QuarantineMeta) -> io::Result<()> {
        let (parent, name) = split(&meta.original_path)?;
        // Any symlink component (a swapped parent) fails here instead of redirecting root.
        let parent_fd = open_dir_chain(parent)?;
        if let (Some(dev), Some(ino)) = (meta.parent_dev, meta.parent_ino) {
            if dir_id(&parent_fd)? != (dev, ino) {
                return Err(bad(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} is no longer the recorded folder; refusing to restore",
                        parent.display()
                    ),
                ));
            }
        }
        let mut src = open_nofollow(&meta.quarantined_path)?;
        let src_id = id_of(&src.metadata()?);
        let actual = hash_reader(&mut src)?;
        if actual != meta.sha256 {
            return Err(bad(
                io::ErrorKind::InvalidData,
                format!(
                    "SHA-256 mismatch for {}: expected {}, found {actual}",
                    meta.quarantined_path.display(),
                    meta.sha256
                ),
            ));
        }
        let dest = match rename_excl(
            libc::AT_FDCWD,
            meta.quarantined_path.as_os_str(),
            parent_fd.as_raw_fd(),
            name,
        ) {
            Ok(()) => {
                let dest = File::from(openat(parent_fd.as_raw_fd(), name, FILE_FLAGS, 0)?);
                if id_of(&dest.metadata()?) != src_id {
                    return Err(bad(
                        io::ErrorKind::InvalidData,
                        "destination changed during restore",
                    ));
                }
                dest
            }
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                let dest = place_by_copy(&mut src, &parent_fd, name, &meta.sha256)?;
                if let Err(e) = fs::remove_file(&meta.quarantined_path) {
                    let _ = unlinkat(parent_fd.as_raw_fd(), name);
                    return Err(e);
                }
                dest
            }
            Err(e) => return Err(e),
        };
        let mut mode = meta.original_mode.unwrap_or(0o644);
        if let (Some(uid), Some(gid)) = (meta.owner_uid, meta.owner_gid) {
            if let Err(e) = fchown(&dest, uid, gid) {
                logger::warn(format!(
                    "could not restore owner of {}: {e}",
                    meta.original_path.display()
                ));
                // Still owned by root: never hand back a setuid/setgid/sticky root file.
                mode &= 0o777;
            }
        }
        // After chown, which clears setuid/setgid bits.
        dest.set_permissions(fs::Permissions::from_mode(mode))
    }

    #[cfg(test)]
    pub fn place_by_copy_for_test(
        src: &mut File,
        parent: &Path,
        name: &OsStr,
        want_sha: &str,
    ) -> io::Result<File> {
        place_by_copy(src, &open_dir_chain(parent)?, name, want_sha)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("thenex-q-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn every_detection_is_an_alert_and_a_record_is_not() {
        let event = |kind: &str, severity| ThreatEvent::new(kind, severity, "t", "a", "d");
        for kind in [
            "MALWARE_AI",
            "MALWARE_AI_PROCESS",
            "RANSOMWARE_SUSPECT",
            "INTEGRITY",
        ] {
            assert!(event(kind, Severity::Medium).is_alert(), "{kind}");
        }
        assert!(!event("QUARANTINE_RESTORE", Severity::Low).is_alert());
        let quiet = ThreatEvent {
            quiet: true,
            ..event("ZIP_BOMB", Severity::High)
        };
        assert!(!quiet.is_alert());
    }

    #[cfg(windows)]
    #[test]
    fn the_recorded_place_is_written_the_way_people_read_it() {
        let root = temp_root("plain");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let victim = root.join("victim.exe");
        fs::write(&victim, b"MZ payload").unwrap();
        let meta = quarantine_file(&victim, &cfg, "T", "d").unwrap();
        assert!(
            !meta.original_path.to_string_lossy().contains(r"\\?\"),
            "{meta:?}"
        );
        restore_file(&meta.id, &cfg).unwrap();
        assert!(victim.exists());

        // Only the long form of the path reaches this name, so it is kept.
        let odd = PathBuf::from(format!(r"\\?\{}\odd. ", root.display()));
        assert_eq!(platform::plain_path(odd.clone()), odd);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn id_validation_and_extraction() {
        assert!(is_valid_id(&new_id()));
        assert!(!is_valid_id("../evil"));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("a b"));
        let event = ThreatEvent::new("ZIP_BOMB", Severity::High, "x", "QUARANTINED id=abc-12", "");
        assert_eq!(event.quarantine_id(), Some("abc-12"));
        let event = ThreatEvent::new(
            "X",
            Severity::High,
            "x",
            "TERMINATED 1; QUARANTINED id=z_9",
            "",
        );
        assert_eq!(event.quarantine_id(), Some("z_9"));
        let event = ThreatEvent::new("X", Severity::High, "x", "DRY_RUN", "");
        assert_eq!(event.quarantine_id(), None);
    }

    #[test]
    fn quarantine_list_restore_and_delete() {
        let root = temp_root("roundtrip");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let victim = root.join("victim.exe");
        fs::write(&victim, b"MZ payload").unwrap();
        let expected = sha256_file(&victim).unwrap();

        let meta = quarantine_file(&victim, &cfg, "TEST", "unit test").unwrap();
        assert!(!victim.exists());
        assert!(meta.quarantined_path.exists());
        assert!(meta_path(&cfg, &meta.id).exists());
        assert_eq!(meta.sha256, expected);
        assert_eq!(list_quarantined(&cfg).unwrap(), vec![meta.clone()]);

        restore_file(&meta.id, &cfg).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"MZ payload");
        assert!(list_quarantined(&cfg).unwrap().is_empty());

        let again = quarantine_file(&victim, &cfg, "TEST", "unit test").unwrap();
        delete_quarantined_file(&again.id, &cfg).unwrap();
        assert!(!again.quarantined_path.exists());
        assert!(!victim.exists());
        assert!(list_quarantined(&cfg).unwrap().is_empty());
        assert!(delete_quarantined_file(&again.id, &cfg).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recent_events_are_newest_first() {
        let root = temp_root("events");
        let cfg = AppConfig::for_base_dir(&root);
        for kind in ["A", "B", "C"] {
            append_event(&cfg, &ThreatEvent::new(kind, Severity::High, "t", "a", "d")).unwrap();
        }
        let events = read_recent_events(&cfg.events_log, 1 << 20).unwrap();
        let kinds: Vec<&str> = events.iter().map(|e| e.threat_type.as_str()).collect();
        assert_eq!(kinds, ["C", "B", "A"]);
        let tail = read_recent_events(&cfg.events_log, 400).unwrap();
        assert!(tail.len() < 3 && tail[0].threat_type == "C");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_rejects_path_traversal_ids() {
        let cfg = AppConfig::for_base_dir(&std::env::temp_dir().join("thenex-none"));
        let err = restore_file("..\\..\\x", &cfg).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn cross_volume_copy_never_follows_a_planted_link() {
        let root = temp_root("copy");
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(&root).unwrap(); // /var is a symlink; the walk refuses those
        let src_path = root.join("src.bin");
        fs::write(&src_path, b"payload").unwrap();
        let sha = sha256_hex(b"payload");
        let mut src = File::open(&src_path).unwrap();

        let ok = fdops::place_by_copy_for_test(&mut src, &root, std::ffi::OsStr::new("dst"), &sha)
            .unwrap();
        drop(ok);
        assert_eq!(fs::read(root.join("dst")).unwrap(), b"payload");

        // a link planted at the destination name is refused, its target untouched
        let victim = root.join("victim");
        fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, root.join("evil")).unwrap();
        let name = std::ffi::OsStr::new("evil");
        assert!(fdops::place_by_copy_for_test(&mut src, &root, name, &sha).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");

        // a hash mismatch leaves nothing behind
        let wrong = std::ffi::OsStr::new("wrong");
        assert!(fdops::place_by_copy_for_test(&mut src, &root, wrong, "00").is_err());
        assert!(!root.join("wrong").exists());
        let _ = fs::remove_dir_all(&root);
    }
}
