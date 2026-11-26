//! "Always allow" for one exact file. The list (`allowed.json`) holds SHA-256 hashes the AI and
//! zip-bomb engines must not flag again. It sits beside settings.json and has the same
//! protection: only someone who can write the data folder can change it, so malware running as
//! the normal user cannot allow itself. A privileged service goes further and ignores a file
//! that is not owned by root or that others can write.
//!
//! Matching is by SHA-256 only, never by path or name, so a changed file is checked again. A
//! hash on the known-malware list is never allowed, whatever this list says, and scripts
//! (LotL) and canaries have no file hash and so cannot be listed at all.

use crate::check_file;
use crate::config::{self, AppConfig};
use crate::known_bad::{self, Digest32, Stamp};
use crate::logger::{self, lock_or_recover};
#[cfg(windows)]
use crate::platform;
use crate::quarantine::{self, QuarantineMeta, Severity, ThreatEvent};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, UNIX_EPOCH};

pub const FILE_NAME: &str = "allowed.json";
pub const MAX_ENTRIES: usize = 1000;
const MAX_NAME_CHARS: usize = 120;
/// 1,000 entries are well under 1 MB; a bigger file is not ours.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// An event log is read at most this far, a line at most this long.
const MAX_LOG_BYTES: u64 = 128 * 1024 * 1024;
const MAX_LOG_LINE: u64 = 1024 * 1024;
const PROMPT_NAME_CHARS: usize = 60;
/// How long one change waits for another to finish.
pub(crate) const LOCK_WAIT: Duration = Duration::from_secs(3);
/// Detections an entry can cover: whole files judged by an estimating engine. `MANUAL` is for
/// an entry added by hand from the command line.
pub const ALLOWABLE_TYPES: &[&str] = &["MALWARE_AI", "MALWARE_AI_PROCESS", "ZIP_BOMB", "MANUAL"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllowedFile {
    pub sha256: String,
    pub name: String,
    pub threat_type: String,
    pub added_at: DateTime<Utc>,
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// 64 hex digits, returned lower-case.
pub fn parse_sha256(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err("a SHA-256 is 64 hexadecimal characters".to_string())
    }
}

/// A shown name only: control characters and a leading `-` (which a command line would read as
/// an option) are replaced, and the length is bounded.
pub fn clean_name(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .filter(|c| !check_file::is_invisible_format(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_NAME_CHARS)
        .collect();
    match cleaned.trim() {
        "" => "unnamed".to_string(),
        name => match name.strip_prefix('-') {
            Some(rest) => format!("_{rest}"),
            None => name.to_string(),
        },
    }
}

/// The CLI is strict: a name with a control character or an over-long one is an error.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("the name must be 1 to {MAX_NAME_CHARS} characters"));
    }
    if name.chars().any(char::is_control) {
        return Err("the name must not contain control characters".to_string());
    }
    Ok(())
}

/// A file name for an administrator prompt or a confirm step: control, bidirectional and
/// zero-width characters (which can reorder or hide text) are removed and the length is bounded.
pub fn prompt_name(name: &str) -> String {
    let hidden = |c: char| c.is_control() || check_file::is_invisible_format(c);
    let cleaned: String = name.chars().filter(|c| !hidden(*c)).collect();
    let cleaned = cleaned.trim();
    match cleaned.char_indices().nth(PROMPT_NAME_CHARS) {
        _ if cleaned.is_empty() => "unnamed".to_string(),
        Some((cut, _)) => format!("{}...", &cleaned[..cut]),
        None => cleaned.to_string(),
    }
}

const PREFIX_CHARS: usize = 16;

/// The start of a SHA-256: what a prompt shows. `--expect` takes all of it.
pub fn shown_prefix(sha256: &str) -> &str {
    sha256.get(..PREFIX_CHARS).unwrap_or(sha256)
}

/// Refuses a recorded SHA-256 other than exactly the one the person was asked about.
pub fn check_expected(sha256: &str, expect: Option<&str>) -> Result<(), String> {
    match expect {
        Some(expect) if !sha256.eq_ignore_ascii_case(expect) => Err(format!(
            "the recorded SHA-256 is {sha256}, not {expect}, so nothing was allowed"
        )),
        _ => Ok(()),
    }
}

/// What a prompt says about one file: the start of its SHA-256, then its name. The name comes
/// last because someone else chose it: it cannot be made to look like text that follows.
pub fn describe(name: &str, sha256: &str) -> String {
    format!(
        "SHA-256 {}, file name: {}",
        shown_prefix(sha256),
        prompt_name(name)
    )
}

pub fn check_type(threat_type: &str) -> Result<(), String> {
    if ALLOWABLE_TYPES.contains(&threat_type) {
        Ok(())
    } else {
        Err(format!(
            "{threat_type} detections cannot be always allowed (only {})",
            ALLOWABLE_TYPES.join(", ")
        ))
    }
}

impl AllowedFile {
    pub fn new(sha256: &str, name: &str, threat_type: &str) -> Result<Self, String> {
        check_type(threat_type)?;
        Ok(Self {
            sha256: parse_sha256(sha256)?,
            name: clean_name(name),
            threat_type: threat_type.to_string(),
            added_at: Utc::now(),
        })
    }

    /// From the SHA-256 the engine recorded when it flagged the file, never from a re-read path.
    pub fn from_event(event: &ThreatEvent) -> Result<Self, String> {
        let sha256 = event
            .sha256
            .as_deref()
            .ok_or("this event has no recorded file hash")?;
        let name = Path::new(&event.target).file_name().map_or_else(
            || event.target.clone(),
            |n| n.to_string_lossy().into_owned(),
        );
        Self::new(sha256, &name, &event.threat_type)
    }

    pub fn from_quarantined(meta: &QuarantineMeta) -> Result<Self, String> {
        let name = meta
            .original_path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        Self::new(&meta.sha256, &name, &meta.threat_type)
    }
}

/// Why a list file must not be trusted, from its owner and permission bits. A privileged
/// service wants root as the owner; nobody may let others write it.
#[cfg(unix)]
fn untrusted_reason(uid: u32, mode: u32, privileged: bool) -> Option<&'static str> {
    if mode & 0o022 != 0 {
        Some("other users can write it")
    } else if privileged && uid != 0 {
        Some("it is not owned by root")
    } else {
        None
    }
}

/// Why the list could not be used. Only `Damaged` may be replaced by a writer.
#[derive(Debug)]
pub enum LoadError {
    /// Could not be read right now (I/O error, too many open files): worth trying again.
    Io(io::Error),
    /// Not ours: wrong owner or mode, or too large. Never read, never overwritten.
    Refused(String),
    /// Read, but not a valid list.
    Damaged(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Refused(why) | Self::Damaged(why) => f.write_str(why),
        }
    }
}

impl From<LoadError> for String {
    fn from(e: LoadError) -> String {
        e.to_string()
    }
}

/// The bytes of a list only an administrator may change; None when there is no such file.
/// shortcut: Windows relies on the ACL of ProgramData\TheNex; upgrade by checking the file's
/// owner SID there as well.
pub(crate) fn read_protected(path: &Path, privileged: bool) -> Result<Option<Vec<u8>>, LoadError> {
    let io_error =
        |e: io::Error| LoadError::Io(io::Error::new(e.kind(), format!("{}: {e}", path.display())));
    let file = match quarantine::open_nofollow(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
            return Err(LoadError::Refused(format!(
                "{} is ignored: {e}",
                path.display()
            )))
        }
        Err(e) => return Err(io_error(e)),
    };
    let meta = file.metadata().map_err(io_error)?;
    #[cfg(unix)]
    {
        // Checked on the open handle, so a swap after the open changes nothing.
        use std::os::unix::fs::MetadataExt;
        if let Some(why) = untrusted_reason(meta.uid(), meta.mode(), privileged) {
            return Err(LoadError::Refused(format!(
                "{} is ignored: {why}",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = privileged;
    if meta.len() > MAX_FILE_BYTES {
        return Err(LoadError::Refused(
            "the list is too large to be ours".to_string(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    Ok(Some(bytes))
}

/// Loads the list. A missing file is an empty list; a damaged or untrusted one is an error and
/// is never partly used.
pub fn load(path: &Path, privileged: bool) -> Result<Vec<AllowedFile>, LoadError> {
    let Some(bytes) = read_protected(path, privileged)? else {
        return Ok(Vec::new());
    };
    let entries: Vec<AllowedFile> =
        serde_json::from_slice(&bytes).map_err(|e| LoadError::Damaged(format!("damaged: {e}")))?;
    let mut seen = HashSet::new();
    let well_formed = entries.len() <= MAX_ENTRIES
        && entries
            .iter()
            .all(|e| parse_sha256(&e.sha256).is_ok_and(|h| h == e.sha256 && seen.insert(h)));
    if well_formed {
        Ok(entries)
    } else {
        Err(LoadError::Damaged(
            "damaged: an entry is malformed or the list is over its limit".to_string(),
        ))
    }
}

/// Changes whenever a list file's content, owner or permissions change.
pub(crate) type ListStamp = (u128, u64, u128);

pub(crate) fn list_stamp(path: &Path) -> ListStamp {
    fs::metadata(path).map_or((0, 0, 0), |m| {
        let modified = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok());
        // ctime also moves on chmod/chown, which must make the trust check run again.
        #[cfg(unix)]
        let changed = {
            use std::os::unix::fs::MetadataExt;
            (m.ctime() as u128) << 32 | m.ctime_nsec() as u128
        };
        #[cfg(not(unix))]
        let changed = 0;
        (modified.map_or(0, |d| d.as_nanos()), m.len(), changed)
    })
}

#[derive(Debug, Default)]
struct Loaded {
    stamp: Option<ListStamp>,
    hashes: HashSet<String>,
    error: Option<String>,
}

/// The list as a running process sees it: re-read when the file changes, so a service honours
/// a new entry within a second without a restart.
#[derive(Debug)]
pub struct LiveAllowed {
    path: PathBuf,
    state: Mutex<Loaded>,
}

impl LiveAllowed {
    pub fn new(path: PathBuf) -> Self {
        let live = Self {
            path,
            state: Mutex::default(),
        };
        live.refresh();
        live
    }

    /// One stat; reads the file only when it changed.
    pub fn refresh(&self) {
        self.refresh_with(|path| load(path, config::running_privileged()));
    }

    fn refresh_with(&self, load: impl FnOnce(&Path) -> Result<Vec<AllowedFile>, LoadError>) {
        let stamp = list_stamp(&self.path);
        let mut state = lock_or_recover(&self.state);
        if state.stamp == Some(stamp) {
            return;
        }
        let result = load(&self.path);
        // A failed read is retried next time; a verdict about the content is kept until it changes.
        state.stamp = (!matches!(result, Err(LoadError::Io(_)))).then_some(stamp);
        match result {
            Ok(entries) => {
                state.hashes = entries.into_iter().map(|e| e.sha256).collect();
                state.error = None;
            }
            Err(e) => {
                state.hashes.clear();
                state.error = Some(e.to_string());
            }
        }
    }

    pub fn contains(&self, sha256: &str) -> bool {
        lock_or_recover(&self.state).hashes.contains(sha256)
    }

    /// Why the file is being ignored, if it is.
    pub fn error(&self) -> Option<String> {
        lock_or_recover(&self.state).error.clone()
    }

    pub fn len(&self) -> usize {
        lock_or_recover(&self.state).hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The stamp of the file as it is now (never following a link), for `check`.
pub fn stamp_of(path: &Path) -> Option<Stamp> {
    let meta = fs::symlink_metadata(path).ok()?;
    // Windows: which file it is (volume and index) and when it last changed in any way, read
    // from the file itself; size and modified time alone are kept by a same-size swap.
    #[cfg(windows)]
    if meta.is_file() {
        return platform::file_stamp(path).map(Stamp::Strong);
    }
    known_bad::stamp(&meta)
}

/// Hashes `path` (the file about to be flagged) and says whether that exact content is always
/// allowed. `judged` is the stamp taken before the engine read the file to score it: the hash
/// counts only if the file still has that stamp after it was hashed, so an event never records
/// (and the list never matches) bytes that were not the ones judged. `None` when the file
/// cannot be hashed (too large, not a regular file) or changed in between, which can never be
/// allowed.
// shortcut: Windows has only size and modified time as a stamp (see `known_bad::Stamp::Weak`),
// which a swap can keep; there it narrows the window rather than closing it. Closing it means
// hashing the very bytes the engine scored (volume serial + file index + change time would do).
pub fn check(cfg: &AppConfig, path: &Path, judged: Option<Stamp>) -> (Option<Digest32>, bool) {
    check_with(cfg, path, judged, known_bad::hash_file)
}

/// Like `check`, for a caller that scored a buffer it still holds: `scored` is the SHA-256 of
/// exactly those bytes, so nothing about the file on disk (a held mapping can change it
/// without a new stamp) can make another file match.
pub fn check_scored(cfg: &AppConfig, path: &Path, scored: Digest32) -> (Option<Digest32>, bool) {
    let allowed = cfg.is_allowed(&scored);
    if allowed {
        log_allowed(path);
    }
    (Some(scored), allowed)
}

fn log_allowed(path: &Path) {
    logger::info(format!(
        "{} matches an always-allowed SHA-256; not flagged",
        path.display()
    ));
}

/// Only the change time moved (an extended attribute or a Finder tag was set): same file,
/// same inode, size and modified time.
fn only_ctime_moved(before: Stamp, after: Stamp) -> bool {
    match (before, after) {
        (Stamp::Strong(a), Stamp::Strong(b)) => {
            a.4 != b.4 && (a.0, a.1, a.2, a.3) == (b.0, b.1, b.2, b.3)
        }
        _ => false,
    }
}

fn check_with(
    cfg: &AppConfig,
    path: &Path,
    judged: Option<Stamp>,
    mut hash: impl FnMut(&Path, u64) -> Option<Digest32>,
) -> (Option<Digest32>, bool) {
    let digest = judged.and_then(|before| {
        let digest = hash(path, known_bad::MAX_HASH_BYTES)?;
        let after = stamp_of(path)?;
        if after == before {
            return Some(digest);
        }
        // shortcut: a change-time-only difference (xattr, Finder tag) gets one more hash that
        // must agree and see a steady stamp; a swap that also forged the modified time looks the
        // same here. Upgrade by hashing the scored buffer (as `check_scored` does) everywhere.
        if only_ctime_moved(before, after) {
            let again = hash(path, known_bad::MAX_HASH_BYTES)?;
            return (again == digest && stamp_of(path) == Some(after)).then_some(digest);
        }
        None
    });
    let allowed = digest.is_some_and(|d| cfg.is_allowed(&d));
    if allowed {
        log_allowed(path);
    }
    (digest, allowed)
}

/// One change to the list at a time: the system's own lock on a file beside it, released when
/// the returned file is dropped, also by a crash. Only its owner can open the file, so another
/// user cannot hold the lock to block changes.
pub(crate) fn lock(list: &Path, wait: Duration) -> io::Result<fs::File> {
    if let Some(parent) = list.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(list.with_extension("json.lock"))?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(fs::TryLockError::WouldBlock) if started.elapsed() < wait => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "another change to this list is in progress; try again",
                ));
            }
            Err(fs::TryLockError::Error(e)) => return Err(e),
        }
    }
}

/// The list to change. A list that could not be read or was refused is an error, so a change
/// never rewrites it and loses entries; only a damaged one is replaced, and a copy is kept.
pub(crate) fn load_for_update<T>(
    list: &Path,
    load: fn(&Path, bool) -> Result<Vec<T>, LoadError>,
) -> io::Result<Vec<T>> {
    match load(list, config::running_privileged()) {
        Ok(entries) => Ok(entries),
        Err(LoadError::Io(e)) => Err(e),
        Err(LoadError::Refused(why)) => Err(io::Error::new(io::ErrorKind::InvalidData, why)),
        Err(LoadError::Damaged(why)) => {
            // An earlier copy is evidence too: a new one never replaces it.
            let mut kept = list.with_extension("json.damaged");
            if kept.symlink_metadata().is_ok() {
                kept = list.with_extension(format!(
                    "json.damaged-{}",
                    Utc::now().timestamp_nanos_opt().unwrap_or_default()
                ));
            }
            fs::rename(list, &kept)?;
            logger::warn(format!(
                "{} replaced ({why}); the old file is kept as {}",
                list.display(),
                kept.display()
            ));
            Ok(Vec::new())
        }
    }
}

/// Adds one entry (a no-op returning false when already listed). The caller loads the
/// known-malware list into `cfg` first. Fails with `PermissionDenied` for anyone who cannot
/// write the data folder, which is the whole point.
pub fn add(cfg: &AppConfig, entry: AllowedFile) -> io::Result<bool> {
    let hash = parse_sha256(&entry.sha256).map_err(invalid)?;
    check_type(&entry.threat_type).map_err(invalid)?;
    if cfg.known_bad.contains(&digest_of(&hash)) {
        return Err(invalid(
            "it is on the known-malware list and can never be allowed",
        ));
    }
    let _lock = lock(&cfg.allowed_file, LOCK_WAIT)?;
    let mut entries = load_for_update(&cfg.allowed_file, load)?;
    if entries.iter().any(|e| e.sha256 == hash) {
        return Ok(false);
    }
    if entries.len() >= MAX_ENTRIES {
        return Err(invalid(format!("the list is full ({MAX_ENTRIES} files)")));
    }
    let name = entry.name.clone();
    entries.push(AllowedFile {
        sha256: hash.clone(),
        ..entry
    });
    save(cfg, &entries)?;
    audit(cfg, "ADDED", &name, &hash);
    Ok(true)
}

/// The 32 bytes of a hash already checked by `parse_sha256`.
fn digest_of(hex: &str) -> Digest32 {
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("0"), 16).unwrap_or(0);
    }
    digest
}

/// Removes one entry; false when it was not listed (a damaged list lists nothing).
pub fn remove(cfg: &AppConfig, sha256: &str) -> io::Result<bool> {
    let hash = parse_sha256(sha256).map_err(invalid)?;
    let _lock = lock(&cfg.allowed_file, LOCK_WAIT)?;
    let mut entries = match load(&cfg.allowed_file, config::running_privileged()) {
        Err(LoadError::Damaged(_)) => return Ok(false),
        _ => load_for_update(&cfg.allowed_file, load)?,
    };
    let before = entries.len();
    entries.retain(|e| e.sha256 != hash);
    if entries.len() == before {
        return Ok(false);
    }
    save(cfg, &entries)?;
    audit(cfg, "REMOVED", &hash, &hash);
    Ok(true)
}

fn save(cfg: &AppConfig, entries: &[AllowedFile]) -> io::Result<()> {
    let body = serde_json::to_vec_pretty(entries).map_err(io::Error::other)?;
    config::write_atomic(&cfg.allowed_file, &body)?;
    cfg.allowed.refresh();
    Ok(())
}

fn audit(cfg: &AppConfig, action: &str, target: &str, sha256: &str) {
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            "ALLOWLIST",
            Severity::Low,
            target,
            action,
            format!("sha256={sha256}"),
        ),
    );
}

/// Searches one log for `id`, reading at most `MAX_LOG_BYTES` and never
/// holding more than one line (`MAX_LOG_LINE`) in memory.
fn find_in_log(log: impl Read, id: &str) -> io::Result<Option<ThreatEvent>> {
    let mut reader = io::BufReader::new(log.take(MAX_LOG_BYTES));
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAX_LOG_LINE)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(None);
        }
        if line.last() != Some(&b'\n') && read as u64 == MAX_LOG_LINE {
            // Too long to be an event: skip to the end of the line.
            let mut rest = Vec::new();
            while (&mut reader)
                .take(MAX_LOG_LINE)
                .read_until(b'\n', &mut rest)?
                > 0
                && rest.last() != Some(&b'\n')
            {
                rest.clear();
            }
            continue;
        }
        if line.windows(id.len()).any(|w| w == id.as_bytes()) {
            if let Ok(event) = serde_json::from_slice::<ThreatEvent>(&line) {
                if event.id == id {
                    return Ok(Some(event));
                }
            }
        }
    }
}

/// The logged event with this ID, from this process's own data folder (the current log, then
/// the rotated one). "Always allow" uses the hash the engine recorded in that event, never one
/// supplied by whoever asks. A privileged engine reads the root-owned log here, so the
/// desktop app (user-level) cannot choose what is allowed.
pub fn event_by_id(cfg: &AppConfig, id: &str) -> io::Result<ThreatEvent> {
    if !quarantine::is_valid_id(id) {
        return Err(invalid(format!("invalid event ID: {id}")));
    }
    for path in [
        cfg.events_log.clone(),
        quarantine::rotated_events_path(&cfg.events_log),
    ] {
        let log = match quarantine::open_nofollow(&path) {
            Ok(log) => log,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
        };
        if let Some(event) = find_in_log(log, id)? {
            return Ok(event);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "that event is no longer in the log",
    ))
}

/// The engines hash only files up to `MAX_HASH_BYTES`, so an entry for a bigger one could
/// never match.
pub fn check_size(size: u64) -> Result<(), String> {
    if size > known_bad::MAX_HASH_BYTES {
        return Err(format!(
            "this file is larger than {} MB, which is too large to always allow (it would still be flagged); nothing was restored",
            known_bad::MAX_HASH_BYTES / (1024 * 1024)
        ));
    }
    Ok(())
}

/// What to tell someone who allowed an event whose file is still in quarantine: allowing does
/// not restore it.
pub fn still_quarantined_note(id: &str) -> String {
    format!(
        "The file is still in quarantine (ID {id}). Restore it from the Quarantine page, or run: the-nex --restore {id}"
    )
}

/// Lists the hash from a quarantine record (the bytes that were moved) and restores the file.
/// If the restore fails the hash does not stay allowed.
pub fn allow_and_restore(
    id: &str,
    cfg: &AppConfig,
    expect: Option<&str>,
) -> io::Result<QuarantineMeta> {
    let meta = quarantine::load_meta(id, cfg)?;
    check_expected(&meta.sha256, expect).map_err(invalid)?;
    check_size(meta.size).map_err(invalid)?;
    let added = add(cfg, AllowedFile::from_quarantined(&meta).map_err(invalid)?)?;
    match quarantine::restore_file(id, cfg) {
        Ok(meta) => Ok(meta),
        Err(e) => {
            if added {
                let _ = remove(cfg, &meta.sha256);
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known_bad;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-allow-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(hash: &str) -> AllowedFile {
        AllowedFile::new(hash, "tool.exe", "MALWARE_AI").unwrap()
    }

    fn hash_n(n: usize) -> String {
        format!("{n:064x}")
    }

    #[test]
    fn input_is_checked_strictly() {
        assert_eq!(
            parse_sha256(&format!(" {} ", HASH.to_uppercase())).unwrap(),
            HASH
        );
        for bad in [
            "",
            "abc",
            &HASH[1..],
            &format!("{HASH}0"),
            &HASH.replace('0', "g"),
        ] {
            assert!(parse_sha256(bad).is_err(), "{bad}");
        }
        assert!(check_name("ok.exe").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name("a\nb").is_err());
        assert!(check_name(&"x".repeat(121)).is_err());
        assert_eq!(clean_name("--evil\x07name"), "_-evil name");
        for allowed in ALLOWABLE_TYPES {
            assert!(check_type(allowed).is_ok());
        }
        for never in [
            "KNOWN_MALWARE",
            "LOTL_SCRIPT",
            "RANSOMWARE_CANARY",
            "RANSOMWARE_SUSPECT",
            "",
        ] {
            assert!(check_type(never).is_err(), "{never}");
        }
    }

    #[test]
    fn a_missing_list_is_empty_and_a_damaged_one_is_refused() {
        let dir = temp("load");
        let file = dir.join(FILE_NAME);
        assert!(load(&file, false).unwrap().is_empty());
        let good = serde_json::to_vec(&[entry(HASH)]).unwrap();
        fs::write(&file, &good).unwrap();
        assert_eq!(load(&file, false).unwrap()[0].sha256, HASH);
        let upper = String::from_utf8(good.clone())
            .unwrap()
            .replace(HASH, &HASH.to_uppercase());
        for damaged in [
            b"not json".to_vec(),
            b"{\"sha256\":1}".to_vec(),
            upper.into_bytes(),
            serde_json::to_vec(&[entry(HASH), entry(HASH)]).unwrap(),
            serde_json::to_vec(&[AllowedFile {
                sha256: "short".to_string(),
                ..entry(HASH)
            }])
            .unwrap(),
        ] {
            fs::write(&file, &damaged).unwrap();
            assert!(load(&file, false).is_err());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_list_is_capped() {
        let dir = temp("cap");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let full: Vec<AllowedFile> = (0..MAX_ENTRIES).map(|n| entry(&hash_n(n))).collect();
        fs::write(&cfg.allowed_file, serde_json::to_vec(&full).unwrap()).unwrap();
        assert_eq!(load(&cfg.allowed_file, false).unwrap().len(), MAX_ENTRIES);
        assert!(add(&cfg, entry(&hash_n(MAX_ENTRIES))).is_err());
        let over: Vec<AllowedFile> = (0..=MAX_ENTRIES).map(|n| entry(&hash_n(n))).collect();
        fs::write(&cfg.allowed_file, serde_json::to_vec(&over).unwrap()).unwrap();
        assert!(load(&cfg.allowed_file, false).is_err());
        cfg.allowed.refresh();
        assert!(cfg.allowed.is_empty() && cfg.allowed.error().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ownership_and_permissions_decide_trust() {
        assert_eq!(untrusted_reason(0, 0o644, true), None);
        assert_eq!(untrusted_reason(501, 0o644, false), None);
        assert!(
            untrusted_reason(501, 0o644, true).is_some(),
            "a service wants root"
        );
        assert!(untrusted_reason(0, 0o664, true).is_some());
        assert!(untrusted_reason(0, 0o602, false).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_list_others_can_write_is_ignored_by_the_live_view() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("mode");
        let mut cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        add(&cfg, entry(HASH)).unwrap();
        assert!(cfg.allowed.contains(HASH));
        let file = &cfg.allowed_file;
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::set_permissions(file, fs::Permissions::from_mode(0o666)).unwrap();
        cfg.allowed.refresh();
        assert!(!cfg.allowed.contains(HASH));
        assert!(cfg
            .allowed
            .error()
            .unwrap()
            .contains("other users can write"));
        cfg.allowed = std::sync::Arc::new(LiveAllowed::new(cfg.allowed_file.clone()));
        assert!(cfg.allowed.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn someone_who_cannot_write_the_data_folder_cannot_add_an_entry() {
        use std::os::unix::fs::PermissionsExt;
        if config::running_privileged() {
            return; // root writes anywhere
        }
        let dir = temp("denied");
        let cfg = AppConfig::for_base_dir(&dir);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let denied = add(&cfg, entry(HASH)).unwrap_err();
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        assert!(!cfg.allowed_file.exists() && !cfg.allowed.contains(HASH));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_malware_is_never_allowed_and_changes_are_picked_up() {
        let dir = temp("known");
        let mut cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let digest = digest_of(HASH);
        let list = dir.join("list.bin");
        known_bad::write_list(&list, &[digest], 1_795_000_000).unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        let refused = add(&cfg, entry(HASH)).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
        // Even a list written by hand cannot make a listed hash count as allowed.
        fs::write(
            &cfg.allowed_file,
            serde_json::to_vec(&[entry(HASH)]).unwrap(),
        )
        .unwrap();
        assert!(!cfg.is_allowed(&digest));
        assert!(
            cfg.allowed.contains(HASH),
            "it is on the list, but never honoured"
        );

        let other = digest_of(&hash_n(7));
        assert!(!cfg.is_allowed(&other));
        assert!(add(&cfg, entry(&hash_n(7))).unwrap());
        assert!(!add(&cfg, entry(&hash_n(7))).unwrap(), "already listed");
        assert!(cfg.is_allowed(&other));
        assert!(remove(&cfg, &hash_n(7)).unwrap() && !cfg.is_allowed(&other));
        assert!(!remove(&cfg, &hash_n(7)).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn events_and_records_give_the_recorded_hash_and_only_for_allowable_types() {
        let mut event = ThreatEvent::new("MALWARE_AI", Severity::High, "/x/dir/app.bin", "Q", "d");
        assert!(AllowedFile::from_event(&event).is_err(), "no hash recorded");
        event.sha256 = Some(HASH.to_string());
        let found = AllowedFile::from_event(&event).unwrap();
        assert_eq!(
            (found.sha256.as_str(), found.name.as_str()),
            (HASH, "app.bin")
        );
        for never in ["KNOWN_MALWARE", "LOTL_SCRIPT", "RANSOMWARE_CANARY"] {
            event.threat_type = never.to_string();
            assert!(AllowedFile::from_event(&event).is_err(), "{never}");
        }
        // Old logs have no hash and still parse; a missing hash is not written back.
        let old = r#"{"id":"a","timestamp":"2026-01-01T00:00:00Z","threat_type":"ZIP_BOMB","severity":"HIGH","target":"t","action_taken":"x","details":"d"}"#;
        let parsed: ThreatEvent = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.sha256, None);
        assert!(!serde_json::to_string(&parsed).unwrap().contains("sha256"));
    }

    #[test]
    fn restore_and_allow_lists_the_hash_only_if_the_restore_works() {
        let dir = temp("restore");
        let mut cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        cfg.load_known_bad().unwrap();
        let place = |name: &str, kind: &str| {
            let path = dir.join(name);
            fs::write(&path, name.as_bytes()).unwrap();
            let meta = quarantine::quarantine_file(&path, &cfg, kind, "test").unwrap();
            (path, meta)
        };

        let (path, meta) = place("fine.bin", "ZIP_BOMB");
        let restored = allow_and_restore(&meta.id, &cfg, None).unwrap();
        assert!(path.exists() && restored.sha256 == meta.sha256);
        assert_eq!(load(&cfg.allowed_file, false).unwrap()[0].name, "fine.bin");

        // The destination is taken, so the restore fails and the hash must not stay allowed.
        let (path, meta) = place("blocked.bin", "MALWARE_AI");
        fs::write(&path, b"someone else's file").unwrap();
        assert!(allow_and_restore(&meta.id, &cfg, None).is_err());
        assert!(!cfg.is_allowed(&digest_of(&meta.sha256)));
        assert!(
            quarantine::load_meta(&meta.id, &cfg).is_ok(),
            "still quarantined"
        );

        // Known malware and anything that is not a file verdict cannot be allowed at all.
        let (path, meta) = place("bad.bin", "KNOWN_MALWARE");
        assert!(allow_and_restore(&meta.id, &cfg, None).is_err());
        assert!(!path.exists() && quarantine::load_meta(&meta.id, &cfg).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prompt_names_lose_hidden_characters_and_are_short() {
        assert_eq!(prompt_name("a\u{202E}b\u{200B}c\nd\u{7}\u{2066}e"), "abcde");
        assert_eq!(prompt_name("\u{202E}\u{200B}  "), "unnamed");
        assert_eq!(
            prompt_name("a\u{2028}b\u{2029}c\u{AD}d\u{206A}e\u{FFF9}f\u{E0041}g"),
            "abcdefg"
        );
        assert_eq!(clean_name("x\u{202E}fdp.exe\u{2028}"), "xfdp.exe");
        assert_eq!(prompt_name(&"é".repeat(100)).chars().count(), 63);
        assert_eq!(
            describe("x\u{202E}.exe", HASH),
            "SHA-256 0123456789abcdef, file name: x.exe"
        );
    }

    /// What failed on Windows CI: another file of the same size, with the same modified time
    /// (a coarse clock gives it that, or the swapper sets it), took the judged file's place.
    #[test]
    fn a_same_size_file_with_a_forged_time_is_still_another_file() {
        let dir = temp("forged");
        let file = dir.join("tool.bin");
        fs::write(&file, b"judged bytes").unwrap();
        let modified = fs::metadata(&file).unwrap().modified().unwrap();
        let judged = stamp_of(&file);
        fs::remove_file(&file).unwrap();
        fs::write(&file, b"other bytes!").unwrap();
        let forged = fs::File::options().write(true).open(&file).unwrap();
        forged.set_modified(modified).unwrap();
        drop(forged);
        assert_ne!(stamp_of(&file), judged);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_swapped_after_it_was_judged_has_no_digest_and_is_never_allowed() {
        let dir = temp("swap");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let file = dir.join("tool.bin");
        fs::write(&file, b"judged bytes").unwrap();
        add(&cfg, entry(&quarantine::sha256_hex(b"other bytes"))).unwrap();
        let judged = stamp_of(&file);

        // Unchanged: the digest is the judged file's, and it is not on the list.
        let (digest, allowed) = check(&cfg, &file, judged);
        assert_eq!(
            digest,
            Some(digest_of(&quarantine::sha256_hex(b"judged bytes")))
        );
        assert!(!allowed);
        // No stamp from before the judging: nothing can be vouched for.
        assert_eq!(check(&cfg, &file, None), (None, false));
        // Swapped for an allowed file between the judging and the hashing: no digest at all.
        let swap = |path: &Path, max: u64| {
            fs::remove_file(path).unwrap();
            fs::write(path, b"other bytes").unwrap();
            known_bad::hash_file(path, max)
        };
        assert_eq!(check_with(&cfg, &file, judged, swap), (None, false));
        // Swapped after the hash was taken: also caught by the second stamp.
        let late = |path: &Path, max: u64| {
            let digest = known_bad::hash_file(path, max);
            fs::remove_file(path).unwrap();
            // Another length: on Windows a swap within one clock tick shows in nothing else.
            fs::write(path, b"yet another one").unwrap();
            digest
        };
        let judged = stamp_of(&file);
        assert_eq!(check_with(&cfg, &file, judged, late), (None, false));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_scored_bytes_decide_not_whatever_is_on_disk_now() {
        let dir = temp("scored");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let file = dir.join("tool.bin");
        // On disk now: bytes that are always allowed. What was scored: different bytes.
        fs::write(&file, b"allowed bytes").unwrap();
        add(&cfg, entry(&quarantine::sha256_hex(b"allowed bytes"))).unwrap();
        let scored = digest_of(&quarantine::sha256_hex(b"scored bytes"));
        assert_eq!(check_scored(&cfg, &file, scored), (Some(scored), false));
        let allowed = digest_of(&quarantine::sha256_hex(b"allowed bytes"));
        assert_eq!(check_scored(&cfg, &file, allowed), (Some(allowed), true));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_change_time_bump_alone_does_not_make_an_allowed_file_flagged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("ctime");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let file = dir.join("tool.bin");
        fs::write(&file, b"same bytes").unwrap();
        add(&cfg, entry(&quarantine::sha256_hex(b"same bytes"))).unwrap();
        let judged = stamp_of(&file);
        std::thread::sleep(Duration::from_millis(20));
        // Like an extended attribute or a Finder tag: ctime moves, the content does not.
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(stamp_of(&file), judged);
        let (digest, allowed) = check(&cfg, &file, judged);
        assert!(digest.is_some() && allowed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_privileged_reader_refuses_a_list_owned_by_a_user() {
        if config::running_privileged() {
            return; // the file would be root's own
        }
        let dir = temp("owner");
        let file = dir.join(FILE_NAME);
        fs::write(&file, serde_json::to_vec(&[entry(HASH)]).unwrap()).unwrap();
        assert!(load(&file, false).is_ok());
        match load(&file, true) {
            Err(LoadError::Refused(why)) => assert!(why.contains("not owned by root"), "{why}"),
            other => panic!("{other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_list_that_was_refused_or_cannot_be_read_is_never_rewritten() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("norewrite");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        add(&cfg, entry(HASH)).unwrap();
        let original = fs::read(&cfg.allowed_file).unwrap();

        fs::set_permissions(&cfg.allowed_file, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            add(&cfg, entry(&hash_n(1))).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(remove(&cfg, HASH).is_err());
        assert_eq!(fs::read(&cfg.allowed_file).unwrap(), original);

        if !config::running_privileged() {
            fs::set_permissions(&cfg.allowed_file, fs::Permissions::from_mode(0o000)).unwrap();
            assert_eq!(
                add(&cfg, entry(&hash_n(1))).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(remove(&cfg, HASH).is_err());
        }
        fs::set_permissions(&cfg.allowed_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(fs::read(&cfg.allowed_file).unwrap(), original);
        assert!(!cfg.allowed_file.with_extension("json.damaged").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_damaged_list_is_replaced_and_a_copy_is_kept() {
        let dir = temp("damaged");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let kept = cfg.allowed_file.with_extension("json.damaged");
        fs::write(&cfg.allowed_file, b"not json").unwrap();
        assert!(!remove(&cfg, HASH).unwrap(), "nothing to remove from it");
        assert_eq!(fs::read(&cfg.allowed_file).unwrap(), b"not json");
        assert!(add(&cfg, entry(HASH)).unwrap());
        assert_eq!(fs::read(&kept).unwrap(), b"not json");
        assert_eq!(load(&cfg.allowed_file, false).unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_earlier_damaged_copy_is_never_overwritten() {
        let dir = temp("damaged2");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        fs::write(&cfg.allowed_file, b"first damage").unwrap();
        assert!(add(&cfg, entry(HASH)).unwrap());
        fs::write(&cfg.allowed_file, b"second damage").unwrap();
        assert!(add(&cfg, entry(&hash_n(1))).unwrap());
        let kept = cfg.allowed_file.with_extension("json.damaged");
        assert_eq!(fs::read(&kept).unwrap(), b"first damage");
        let copies: Vec<Vec<u8>> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".damaged-"))
            .map(|e| fs::read(e.path()).unwrap())
            .collect();
        assert_eq!(copies, [b"second damage".to_vec()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_read_is_retried_but_a_verdict_on_the_content_is_kept() {
        let dir = temp("retry");
        let file = dir.join(FILE_NAME);
        let live = LiveAllowed::new(file.clone());
        fs::write(&file, serde_json::to_vec(&[entry(HASH)]).unwrap()).unwrap();
        live.refresh_with(|_| Err(LoadError::Io(io::Error::other("too many open files"))));
        assert!(live.error().is_some() && !live.contains(HASH));
        // Same file, same stamp: it is read again because the last read failed.
        live.refresh_with(|path| load(path, false));
        assert!(live.contains(HASH) && live.error().is_none());
        // A damaged file is a verdict: it is not parsed again until it changes.
        fs::write(&file, b"not json").unwrap();
        live.refresh_with(|path| load(path, false));
        assert!(live.error().is_some());
        live.refresh_with(|_| panic!("read again"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn changes_to_the_list_are_serialised() {
        let dir = temp("lock");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        std::thread::scope(|scope| {
            for n in 0..12 {
                let cfg = &cfg;
                scope.spawn(move || add(cfg, entry(&hash_n(n))).unwrap());
            }
        });
        assert_eq!(load(&cfg.allowed_file, false).unwrap().len(), 12);

        // A lock someone holds makes the change wait and then give up; a leftover file is no lock.
        let held = lock(&cfg.allowed_file, Duration::from_millis(80)).unwrap();
        let started = Instant::now();
        let timeout = lock(&cfg.allowed_file, Duration::from_millis(80))
            .err()
            .unwrap();
        assert_eq!(timeout.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(held);
        assert!(cfg.allowed_file.with_extension("json.lock").exists());
        drop(lock(&cfg.allowed_file, Duration::from_millis(80)).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_event_is_found_by_its_id_in_the_current_and_the_rotated_log() {
        let dir = temp("events");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let mut zip = ThreatEvent::new("ZIP_BOMB", Severity::High, "/x/pack.zip", "Q", "d");
        zip.sha256 = Some(HASH.to_string());
        let mut old = ThreatEvent::new("MALWARE_AI", Severity::High, "/x/old.bin", "Q", "d");
        old.sha256 = Some(hash_n(9));
        let lotl = ThreatEvent::new("LOTL_SCRIPT", Severity::High, "osascript (pid 4)", "K", "d");
        let mut known = ThreatEvent::new("KNOWN_MALWARE", Severity::High, "/x/bad", "Q", "d");
        known.sha256 = Some(hash_n(8));
        for e in [&zip, &lotl, &known] {
            quarantine::append_event(&cfg, e).unwrap();
        }
        let line = serde_json::to_string(&old).unwrap() + "\n";
        fs::write(quarantine::rotated_events_path(&cfg.events_log), line).unwrap();

        assert_eq!(event_by_id(&cfg, &zip.id).unwrap(), zip);
        assert_eq!(event_by_id(&cfg, &old.id).unwrap(), old);
        assert_eq!(
            event_by_id(&cfg, "20200101000000000-1-0000")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            event_by_id(&cfg, "../x").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        // Same type rules as ever: scripts have no file, and known malware is never allowed.
        for forged in [&lotl, &known] {
            let found = event_by_id(&cfg, &forged.id).unwrap();
            assert!(
                AllowedFile::from_event(&found).is_err(),
                "{}",
                found.threat_type
            );
        }
        assert!(add(&cfg, AllowedFile::from_event(&zip).unwrap()).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_log_search_is_bounded_and_skips_lines_that_are_too_long() {
        let mut event = ThreatEvent::new("ZIP_BOMB", Severity::High, "/x/a.zip", "Q", "d");
        event.sha256 = Some(HASH.to_string());
        let mut log = vec![b'x'; MAX_LOG_LINE as usize * 2 + 5];
        log.push(b'\n');
        log.extend_from_slice(b"not json with the id inside\n");
        log.extend_from_slice(serde_json::to_string(&event).unwrap().as_bytes());
        assert_eq!(find_in_log(&log[..], &event.id).unwrap(), Some(event));
        assert_eq!(find_in_log(&log[..], "nope").unwrap(), None);
    }

    #[test]
    fn a_file_too_large_to_ever_match_is_refused_before_anything_is_restored() {
        let dir = temp("toolarge");
        let mut cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        cfg.load_known_bad().unwrap();
        let path = dir.join("huge.bin");
        fs::write(&path, b"stands in for a huge file").unwrap();
        let meta = quarantine::quarantine_file(&path, &cfg, "MALWARE_AI", "t").unwrap();
        let record = quarantine::meta_path(&cfg, &meta.id);
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
        json["size"] = (known_bad::MAX_HASH_BYTES + 1).into();
        fs::write(&record, serde_json::to_vec(&json).unwrap()).unwrap();

        let refused = allow_and_restore(&meta.id, &cfg, None).unwrap_err();
        assert!(refused.to_string().contains("too large"), "{refused}");
        assert!(!path.exists() && !cfg.allowed_file.exists());
        assert!(
            quarantine::load_meta(&meta.id, &cfg).is_ok(),
            "still quarantined"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
