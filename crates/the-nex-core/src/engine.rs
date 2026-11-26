use crate::bin_ai::{self, BinaryAiScanner};
use crate::canary::{self, CanaryMsg};
use crate::config::{AppConfig, Engine};
use crate::known_bad;
use crate::logger;
use crate::platform;
use crate::process_guard;
use crate::quarantine::{self, Severity, ThreatEvent};
use crate::scan_jobs::{self, ScanJobs};
use crate::schedule::{self, Scheduler};
use crate::skiplist;
use crate::status::{self, ResourceUsage, Telemetry};
use crate::zip_bomb;
use chrono::Utc;
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const MAIN_TICK: Duration = Duration::from_millis(250);
const SETTINGS_RELOAD_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_INTERVAL: Duration = Duration::from_secs(2);
const SCAN_REQUEST_INTERVAL: Duration = Duration::from_secs(1);
const REDISCOVER_INTERVAL: Duration = Duration::from_secs(60);
const SCAN_SETTLE: Duration = Duration::from_millis(300);
const SCAN_RECV_TIMEOUT: Duration = Duration::from_millis(150);
const MAX_PENDING_SCANS: usize = 50_000;
const QUICK_SCAN_MAX_DEPTH: usize = 8;
const QUICK_SCAN_MAX_FILES: u64 = 50_000;
const BINARY_EXTENSIONS: &[&str] = &["exe", "dll", "scr", "sys", "cpl", "ocx", "com", "efi"];
/// Written next to events.jsonl by `--quick-scan` so callers that cannot read stdout (UAC) get the report.
pub const QUICK_SCAN_REPORT_FILE: &str = "last_quick_scan.json";
pub const FULL_SCAN_REPORT_FILE: &str = "last_full_scan.json";
pub const SCHEDULED_SCAN_REPORT_FILE: &str = "last_scheduled_scan.json";
pub const SCAN_PROGRESS_FILE: &str = "scan_progress.json";
/// Marks the summary event (and its notification) of a scan the service started by itself.
pub const SCHEDULED_SCAN_EVENT: &str = "SCHEDULED_SCAN";

/// True for a Mach-O program or library, from the start of the file: thin (32/64-bit, either
/// byte order) and fat/universal headers.
///
/// Object files (file type MH_OBJECT, usually `.o`) are left out. They are compiler output
/// waiting to be linked: they cannot run, are never signed, and their single segment is always
/// readable, writable and executable, which the model reads as an injector. A build folder
/// holds thousands of them; scoring them flagged 12,408 on one developer's Mac, and in a
/// watched folder would quarantine a build as it was being made.
#[cfg(target_os = "macos")]
fn is_macho_program(head: &[u8]) -> bool {
    const MH_OBJECT: u32 = 1;
    // The file type is the fourth 32-bit field of a thin header. A header cut short (a file
    // still being written) counts as a program, as it did before.
    let file_type = |decode: fn([u8; 4]) -> u32| {
        head.get(12..16)
            .and_then(|field| field.try_into().ok())
            .map(decode)
    };
    match head.get(..4) {
        Some([0xCF | 0xCE, 0xFA, 0xED, 0xFE]) => file_type(u32::from_le_bytes) != Some(MH_OBJECT),
        Some([0xFE, 0xED, 0xFA, 0xCF | 0xCE]) => file_type(u32::from_be_bytes) != Some(MH_OBJECT),
        Some([0xCA, 0xFE, 0xBA, 0xBE | 0xBF]) => true,
        _ => false,
    }
}

#[cfg(not(target_os = "macos"))]
fn is_macho_program(_head: &[u8]) -> bool {
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Archive,
    Binary,
    Other,
}

/// Cheap triage by magic bytes (and extension for files still being written).
pub fn classify_file(path: &Path) -> FileKind {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let mut head = [0u8; 16];
    // No-follow, non-blocking: a FIFO or symlink swapped in after the lstat must not hang the scan.
    let read = quarantine::open_nofollow(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    let head = &head[..read];
    if head.starts_with(b"MZ") || is_macho_program(head) {
        return FileKind::Binary;
    }
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") || ext == "zip" {
        return FileKind::Archive;
    }
    if BINARY_EXTENSIONS.contains(&ext.as_str()) {
        return FileKind::Binary;
    }
    FileKind::Other
}

/// The Nex's own data, quarantine and log folders are never scanned, nor what the owner listed.
fn should_ignore(cfg: &AppConfig, path: &Path) -> bool {
    is_own_or_skipped(cfg, path)
        || is_engine_output(cfg, path)
        || zip_bomb::is_ignored_extension(path)
}

fn is_own_or_skipped(cfg: &AppConfig, path: &Path) -> bool {
    platform::path_is_within(path, &cfg.base_dir)
        || platform::path_is_within(path, &cfg.quarantine_dir)
        || cfg.is_skipped(path)
}

/// The files the engine itself writes next to the event log (including rotated and
/// staging copies). Only these are skipped, not the whole folder: `--log-file` may
/// point into a watched directory, which must stay protected.
fn is_engine_output(cfg: &AppConfig, path: &Path) -> bool {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let same_dir = platform::path_is_within(parent, &cfg.log_dir)
        && platform::path_is_within(&cfg.log_dir, parent);
    if !same_dir {
        return false;
    }
    let name = name.to_string_lossy().to_lowercase();
    let events = cfg
        .events_log
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let own_files = [
        events.as_str(),
        crate::config::STATUS_FILE_NAME,
        QUICK_SCAN_REPORT_FILE,
        FULL_SCAN_REPORT_FILE,
        SCHEDULED_SCAN_REPORT_FILE,
        SCAN_PROGRESS_FILE,
        logger::LOG_FILE_NAME,
    ];
    let is_own = own_files
        .iter()
        .any(|own| !own.is_empty() && name.starts_with(&own.to_lowercase()));
    is_own
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuickScanFinding {
    pub path: PathBuf,
    pub threat_type: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QuickScanReport {
    pub roots: Vec<PathBuf>,
    pub files_examined: u64,
    pub files_scanned: u64,
    pub findings: Vec<QuickScanFinding>,
    pub dry_run: bool,
    pub truncated: bool,
    pub duration_ms: u64,
    /// Scan folders that exist but could not be opened (e.g. macOS privacy blocks Downloads
    /// without Full Disk Access). A scan with any of these is not a clean result.
    #[serde(default)]
    pub unreadable: Vec<PathBuf>,
    /// A full scan (the whole disk, report only) rather than a quick one.
    #[serde(default)]
    pub full: bool,
    /// Stopped early because the user cancelled.
    #[serde(default)]
    pub cancelled: bool,
    /// iCloud / File Provider placeholders left alone: reading one would download it.
    #[serde(default)]
    pub cloud_skipped: u64,
    /// Places on the never-scan list that were met and left alone (a folder counts once).
    #[serde(default)]
    pub never_scan: u64,
    /// RFC 3339; makes every report distinct so a waiting client can see a new one arrive.
    #[serde(default)]
    pub finished_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    Quick,
    Full,
    /// Started by the service on the user's schedule: a quick scan's folders, report only.
    Scheduled,
}

impl ScanKind {
    pub fn report_file(self) -> &'static str {
        match self {
            ScanKind::Quick => QUICK_SCAN_REPORT_FILE,
            ScanKind::Full => FULL_SCAN_REPORT_FILE,
            ScanKind::Scheduled => SCHEDULED_SCAN_REPORT_FILE,
        }
    }
}

/// Bounds of one walk. Quick and full scans differ only in these and in their folders.
pub struct ScanLimits {
    pub max_depth: usize,
    pub max_files: u64,
    /// Folders this close to a scan root that cannot be opened are listed in the report
    /// (0 = only the roots; 2 reaches /Users/<name>/Desktop from /Users, 3 from the top of a drive)...
    pub report_unreadable_depth: usize,
    /// ...but below the roots only inside these trees: people's own folders, which Full Disk
    /// Access unlocks. System folders macOS never opens (SIP) would otherwise show up in every
    /// report and no scan would ever read as clean.
    pub report_unreadable_under: &'static [&'static str],
    /// Look every file up in the known-malware list (false: only the types the list holds,
    /// because hashing every file on a whole disk would take hours).
    pub hash_every_file: bool,
}

pub const QUICK_LIMITS: ScanLimits = ScanLimits {
    max_depth: QUICK_SCAN_MAX_DEPTH,
    max_files: QUICK_SCAN_MAX_FILES,
    report_unreadable_depth: 0,
    report_unreadable_under: &[],
    hash_every_file: true,
};
pub const FULL_LIMITS: ScanLimits = ScanLimits {
    max_depth: 64,
    max_files: 20_000_000,
    report_unreadable_depth: if cfg!(windows) { 3 } else { 2 },
    report_unreadable_under: &["/Users", "/home"],
    hash_every_file: false,
};
const MAX_UNREADABLE_LISTED: usize = 50;

/// iCloud / File Provider placeholders ("dataless" files and folders): opening one makes macOS
/// download it, so a scan would pull down the user's whole cloud drive.
#[cfg(target_os = "macos")]
fn is_cloud_placeholder(metadata: &fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt;
    const SF_DATALESS: u32 = 0x4000_0000;
    metadata.st_flags() & SF_DATALESS != 0
}

/// OneDrive and other Cloud Files placeholders. Only the attribute that the cloud filter itself
/// keeps counts: a program can set FILE_ATTRIBUTE_OFFLINE on its own file, and RECALL_ON_OPEN has
/// the value of FILE_ATTRIBUTE_EA, so either would be a way to hide from every scan.
#[cfg(windows)]
fn needs_download(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    attributes & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS != 0
}

#[cfg(windows)]
fn is_cloud_placeholder(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    needs_download(metadata.file_attributes())
}

#[cfg(not(any(target_os = "macos", windows)))]
fn is_cloud_placeholder(_metadata: &fs::Metadata) -> bool {
    false
}

/// A placeholder every walk leaves alone. On Windows only files: a program can make its own
/// placeholder folders, and one would otherwise hide everything in it.
fn not_here_yet(metadata: &fs::Metadata) -> bool {
    is_cloud_placeholder(metadata) && (metadata.is_file() || cfg!(target_os = "macos"))
}

fn is_dataless(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| not_here_yet(&m))
}

/// Inspects one complete file with the enabled engines; detections are acted on and logged.
/// `hash` = also look it up in the known-malware list, first: a match there is certain, so the
/// file is dealt with before the engines that only estimate get to it.
fn inspect_file(
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
    path: &Path,
    kind: FileKind,
    hash: bool,
    telemetry: &Telemetry,
) -> Option<QuickScanFinding> {
    let estimated = match kind {
        FileKind::Archive => cfg.engine_enabled(Engine::ZipBomb),
        FileKind::Binary => cfg.engine_enabled(Engine::BinAi),
        FileKind::Other => false,
    };
    if !hash && !estimated {
        return None;
    }
    telemetry.add_files_scanned(1);
    if hash {
        if let Some(detail) = known_bad::check_file(cfg, path) {
            return Some(QuickScanFinding {
                path: path.to_path_buf(),
                threat_type: known_bad::THREAT_TYPE.to_string(),
                detail,
            });
        }
    }
    match kind {
        FileKind::Archive if estimated => {
            zip_bomb::scan_and_respond(path, cfg).map(|threat| QuickScanFinding {
                path: path.to_path_buf(),
                threat_type: "ZIP_BOMB".to_string(),
                detail: threat.summary(),
            })
        }
        FileKind::Binary if estimated => bin_ai::scan_and_respond(path, cfg, scanner)
            .and_then(|outcome| outcome.detection)
            .map(|detail| QuickScanFinding {
                path: path.to_path_buf(),
                threat_type: "MALWARE_AI".to_string(),
                detail,
            }),
        _ => None,
    }
}

/// True only for a regular file; symlinks are never followed into scanning or quarantine
/// (a link could point at a file the daemon's privileges can touch but the writer cannot).
pub fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Live path: waits for the writer to finish, then inspects.
pub fn scan_path(cfg: &AppConfig, scanner: &BinaryAiScanner, path: &Path, telemetry: &Telemetry) {
    if should_ignore(cfg, path) || !is_regular_file(path) {
        return;
    }
    // Windows reports the change when the content arrives, which queues the file again.
    if cfg!(windows) && fs::symlink_metadata(path).is_ok_and(|m| is_cloud_placeholder(&m)) {
        return;
    }
    let kind = classify_file(path);
    let hash = cfg.known_bad_active();
    // Programs and archives are parsed, so they must be complete. Every other file is only
    // hashed: a half-written one simply does not match, and the write that completes it
    // queues the file again (scan_worker), so there is no need to hold the queue for it.
    if kind == FileKind::Other {
        if !hash {
            return;
        }
    } else if !zip_bomb::wait_for_file_ready(path) {
        return;
    }
    inspect_file(cfg, scanner, path, kind, hash, telemetry);
}

/// What has arrived inside a folder that was moved here whole: for that, the system reports the
/// folder and none of its files. Entered folder by folder, behind everything newer.
#[derive(Default)]
struct Arrived {
    queue: VecDeque<PathBuf>,
    queued: HashSet<PathBuf>,
}

impl Arrived {
    fn push(&mut self, path: PathBuf) {
        if self.queue.len() >= MAX_PENDING_SCANS {
            if self.queued.insert(PathBuf::new()) {
                logger::warn("too many files arrived at once; the rest is left to the next scan");
            }
        } else if self.queued.insert(path.clone()) {
            self.queue.push_back(path);
        }
    }

    fn pop(&mut self) -> Option<PathBuf> {
        let path = self.queue.pop_front()?;
        self.queued.remove(&path);
        if self.queue.is_empty() {
            self.queued.clear();
        }
        Some(path)
    }

    /// Queues what a folder holds. A link is never followed.
    fn enter(&mut self, cfg: &AppConfig, dir: &Path) {
        if is_own_or_skipped(cfg, dir) || is_dataless(dir) {
            return;
        }
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            let is_link = entry.file_type().map_or(true, |t| t.is_symlink());
            if !is_link && !entry.metadata().is_ok_and(|m| not_here_yet(&m)) {
                self.push(entry.path());
            }
        }
    }
}

/// Loads the known-malware list into `cfg`. A list that is damaged, altered or not the one
/// this build was made with is refused whole: protection carries on without it and the
/// refusal is logged where the owner will see it.
pub fn load_known_bad(cfg: &mut AppConfig) {
    match cfg.load_known_bad() {
        Ok(()) if cfg.known_bad.is_empty() => {
            logger::info("known-malware list: none installed (the engine is idle)")
        }
        Ok(()) => logger::info(format!(
            "known-malware list loaded: {}",
            cfg.known_bad.summary()
        )),
        Err(e) => {
            logger::error(format!("known-malware list refused: {e}"));
            quarantine::record_event(
                cfg,
                ThreatEvent::new(
                    "INTEGRITY",
                    Severity::High,
                    known_bad::FILE_NAME,
                    "LIST_REFUSED: known-malware checks are off until it is replaced",
                    format!("the known-malware list was refused: {e}"),
                ),
            );
        }
    }
}

/// Whatever the drive: the Users folder of C: counts as "/Users" here.
fn in_reported_tree(limits: &ScanLimits, dir: &Path) -> bool {
    let mut parts = dir.components();
    if let Some(Component::Prefix(_)) = dir.components().next() {
        parts.next();
    }
    let dir = parts.as_path();
    limits
        .report_unreadable_under
        .iter()
        .any(|tree| dir.starts_with(tree))
}

/// One-shot recursive scan of existing files under `roots` (bounded in depth and file count).
pub fn quick_scan(
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
    roots: &[PathBuf],
    telemetry: &Telemetry,
) -> QuickScanReport {
    scan_tree(
        cfg,
        scanner,
        roots,
        telemetry,
        &QUICK_LIMITS,
        &mut |_, _| true,
    )
}

/// The walk behind every on-demand scan. `on_dir(report so far, folder being read)` is called
/// for each folder and each file in it, so it must be cheap; returning false cancels the scan.
pub fn scan_tree(
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
    roots: &[PathBuf],
    telemetry: &Telemetry,
    limits: &ScanLimits,
    on_dir: &mut dyn FnMut(&QuickScanReport, &Path) -> bool,
) -> QuickScanReport {
    let started = Instant::now();
    let mut report = QuickScanReport {
        roots: roots.to_vec(),
        dry_run: cfg.is_dry_run(),
        ..QuickScanReport::default()
    };
    let scanned_before = telemetry.files_scanned.load(Ordering::Relaxed);
    let hash_active = cfg.known_bad_active();
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    'walk: while let Some((dir, depth)) = stack.pop() {
        report.files_scanned = telemetry.files_scanned.load(Ordering::Relaxed) - scanned_before;
        if !on_dir(&report, &dir) {
            report.cancelled = true;
            break 'walk;
        }
        // A long scan follows changes to the never-scan list as it goes.
        cfg.skipped.refresh();
        if cfg.is_skipped(&dir) {
            report.never_scan += 1;
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                let listed = depth == 0
                    || (depth <= limits.report_unreadable_depth && in_reported_tree(limits, &dir));
                if listed
                    && e.kind() != std::io::ErrorKind::NotFound
                    && report.unreadable.len() < MAX_UNREADABLE_LISTED
                {
                    report.unreadable.push(dir);
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            if cfg.is_skipped(&path) {
                report.never_scan += 1;
                continue;
            }
            if should_ignore(cfg, &path) {
                continue;
            }
            if entry.metadata().is_ok_and(|m| not_here_yet(&m)) {
                report.cloud_skipped += 1;
                continue;
            }
            if kind.is_dir() {
                if depth < limits.max_depth {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            report.files_examined += 1;
            if report.files_examined > limits.max_files {
                report.truncated = true;
                break 'walk;
            }
            // Per file, not per folder: one folder of large programs can take minutes, and
            // progress must keep moving (and a cancel must land) all through it.
            report.files_scanned = telemetry.files_scanned.load(Ordering::Relaxed) - scanned_before;
            if !on_dir(&report, &dir) {
                report.cancelled = true;
                break 'walk;
            }
            let file_kind = classify_file(&path);
            let hash = hash_active
                && (limits.hash_every_file
                    || known_bad::is_listed_type(&path, file_kind != FileKind::Other));
            if file_kind == FileKind::Other && !hash {
                continue;
            }
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                inspect_file(cfg, scanner, &path, file_kind, hash, telemetry)
            }));
            if let Ok(Some(finding)) = outcome {
                report.findings.push(finding);
            }
        }
    }
    report.files_scanned = telemetry.files_scanned.load(Ordering::Relaxed) - scanned_before;
    report.duration_ms = started.elapsed().as_millis() as u64;
    report
}

/// Quick scan as run by `--quick-scan` and the desktop app.
pub fn run_quick_scan(cfg: &AppConfig, scanner: &BinaryAiScanner) -> QuickScanReport {
    run_scan(
        cfg,
        scanner,
        &Telemetry::default(),
        ScanKind::Quick,
        &mut |_, _| true,
    )
}

/// A whole on-demand scan: walk, log a summary event and leave the report next to events.jsonl.
pub fn run_scan(
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
    telemetry: &Telemetry,
    kind: ScanKind,
    on_dir: &mut dyn FnMut(&QuickScanReport, &Path) -> bool,
) -> QuickScanReport {
    // A full or scheduled scan only reports. The model wrongly flags about 1 clean program in 200, so moving
    // files across the whole disk on its word would break installed software. Its findings are
    // logged without a notification each; the summary event below is the one alert.
    let mut report_only = AppConfig {
        dry_run: true,
        quiet_events: true,
        ..cfg.clone()
    };
    let seen_file = cfg.base_dir.join(schedule::SEEN_FILE);
    let seen = Arc::new(schedule::SeenFindings::load(&seen_file));
    if kind == ScanKind::Scheduled {
        report_only.repeats = Some(Arc::clone(&seen));
    }
    let (scan_cfg, roots, limits, event) = match kind {
        ScanKind::Quick => (cfg, quick_scan_roots(cfg), &QUICK_LIMITS, "QUICK_SCAN"),
        ScanKind::Full => (
            &report_only,
            full_scan_roots(cfg),
            &FULL_LIMITS,
            "FULL_SCAN",
        ),
        ScanKind::Scheduled => (
            &report_only,
            quick_scan_roots(cfg),
            &QUICK_LIMITS,
            SCHEDULED_SCAN_EVENT,
        ),
    };
    let mut report = scan_tree(scan_cfg, scanner, &roots, telemetry, limits, on_dir);
    report.full = kind == ScanKind::Full;
    report.finished_at = Utc::now().to_rfc3339();
    let scheduled = kind == ScanKind::Scheduled;
    if scheduled {
        seen.save(&seen_file, !report.cancelled);
    }
    let mut summary = ThreatEvent::new(
            event,
            if report.findings.is_empty() {
                Severity::Low
            } else {
                Severity::High
            },
            // A scheduled scan's alert names no folder or file: it is shown on the lock screen.
            if scheduled {
                "Scheduled scan".to_string()
            } else {
                roots
                    .iter()
                    .map(|r| r.display().to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            },
            format!("{} threat(s) found", report.findings.len()),
            format!(
                "{}examined={} scanned={} truncated={} cancelled={} unreadable_folders={} cloud_skipped={} never_scan={} duration_ms={}",
                if kind == ScanKind::Scheduled {
                    "scheduled, report only; "
                } else {
                    ""
                },
                report.files_examined,
                report.files_scanned,
                report.truncated,
                report.cancelled,
                report.unreadable.len(),
                report.cloud_skipped,
                report.never_scan,
                report.duration_ms
            ),
    );
    // A clean scheduled scan is recorded without a notification; with findings it is the one.
    summary.quiet = scheduled && report.findings.is_empty();
    quarantine::record_event(cfg, summary);
    // A stopped scheduled scan leaves the last complete report in place: it looked at part of
    // the files, and "nothing found" about that would be false.
    let write_report = !(scheduled && report.cancelled);
    if let Some(json) = serde_json::to_vec_pretty(&report)
        .ok()
        .filter(|_| write_report)
    {
        // Staged and renamed so a client polling for the report never reads half of it.
        let path = cfg.log_dir.join(kind.report_file());
        let staging = path.with_extension("json.tmp");
        if fs::write(&staging, json).is_ok() {
            let _ = fs::rename(&staging, &path);
        }
    }
    report
}

pub fn read_scan_report(cfg: &AppConfig, kind: ScanKind) -> Option<QuickScanReport> {
    serde_json::from_slice(&fs::read(cfg.log_dir.join(kind.report_file())).ok()?).ok()
}

pub fn read_last_quick_scan(cfg: &AppConfig) -> Option<QuickScanReport> {
    read_scan_report(cfg, ScanKind::Quick)
}

/// Everywhere software can be installed or dropped. Apple's sealed system volume is left out
/// (it is read-only and signed), as are external and network drives.
pub fn full_scan_roots(cfg: &AppConfig) -> Vec<PathBuf> {
    if let Some(dir) = &cfg.watch_dir {
        return vec![dir.clone()];
    }
    #[cfg(target_os = "macos")]
    let roots: Vec<PathBuf> = [
        "/Applications",
        "/Users",
        "/Library",
        "/opt",
        "/usr/local",
        "/private/tmp",
        "/private/var/tmp",
        "/private/var/folders",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    #[cfg(windows)]
    let roots = vec![PathBuf::from(format!(
        "{}\\",
        std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string())
    ))];
    #[cfg(not(any(target_os = "macos", windows)))]
    let roots: Vec<PathBuf> = ["/home", "/opt", "/usr/local", "/tmp", "/var/tmp"]
        .iter()
        .map(PathBuf::from)
        .collect();
    roots.into_iter().filter(|p| p.is_dir()).collect()
}

pub fn quick_scan_roots(cfg: &AppConfig) -> Vec<PathBuf> {
    match &cfg.watch_dir {
        Some(dir) => vec![dir.clone()],
        None => platform::discover_quick_scan_dirs(),
    }
}

/// Never a folder on the never-scan list: no decoy is put there.
pub fn canary_dirs(cfg: &AppConfig) -> Vec<PathBuf> {
    let mut dirs = all_canary_dirs(cfg);
    dirs.retain(|dir| !cfg.is_skipped(dir));
    dirs
}

fn all_canary_dirs(cfg: &AppConfig) -> Vec<PathBuf> {
    match &cfg.watch_dir {
        Some(dir) => vec![dir.clone()],
        None => platform::discover_canary_dirs(),
    }
}

/// (directory, recursive). Canary-only folders are watched top-level only.
fn watch_plan(cfg: &AppConfig) -> Vec<(PathBuf, bool)> {
    if let Some(dir) = &cfg.watch_dir {
        return vec![(dir.clone(), true)];
    }
    let mut plan: Vec<(PathBuf, bool)> = platform::discover_watched_dirs()
        .into_iter()
        .filter(|dir| !cfg.is_skipped(dir))
        .map(|dir| (dir, true))
        .collect();
    for dir in canary_dirs(cfg) {
        let covered = plan.iter().any(|(watched, recursive)| {
            platform::path_key(watched) == platform::path_key(&dir)
                || (*recursive && platform::path_is_within(&dir, watched))
        });
        if !covered {
            plan.push((dir, false));
        }
    }
    plan
}

fn dispatch_event(event: Event, scan_tx: &Sender<PathBuf>, canary_tx: &Sender<CanaryMsg>) {
    if matches!(event.kind, EventKind::Access(_)) {
        return;
    }
    let scan_relevant = matches!(
        event.kind,
        EventKind::Any
            | EventKind::Create(_)
            | EventKind::Modify(
                ModifyKind::Any | ModifyKind::Data(_) | ModifyKind::Name(_) | ModifyKind::Other
            )
    );
    // What a folder that merely changed holds is reported file by file; one that was moved or cloned
    // here whole is not, and "created" may be either.
    let arrived = matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(_))
    );
    for path in event.paths {
        if canary::is_canary_path(&path) {
            let _ = canary_tx.send(CanaryMsg::FsEvent(path));
        } else if scan_relevant && (arrived || !is_real_dir(&path)) {
            let _ = scan_tx.send(path);
        }
    }
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

fn build_watcher(
    scan_tx: Sender<PathBuf>,
    canary_tx: Sender<CanaryMsg>,
) -> Option<RecommendedWatcher> {
    let handler = move |result: notify::Result<Event>| match result {
        Ok(event) => dispatch_event(event, &scan_tx, &canary_tx),
        Err(e) => logger::warn(format!("file watcher error: {e}")),
    };
    match notify::recommended_watcher(handler) {
        Ok(watcher) => Some(watcher),
        Err(e) => {
            logger::error(format!("cannot create file watcher: {e}"));
            None
        }
    }
}

fn refresh_watches(
    cfg: &AppConfig,
    watcher: &mut RecommendedWatcher,
    watched: &mut HashMap<String, PathBuf>,
    plan: &[(PathBuf, bool)],
) {
    watched.retain(|_, dir| {
        // Gone, or put on the never-scan list.
        if dir.is_dir() && !cfg.is_skipped(dir) {
            true
        } else {
            let _ = watcher.unwatch(dir);
            false
        }
    });
    for (dir, recursive) in plan {
        let key = platform::path_key(dir);
        if watched.contains_key(&key) || !dir.is_dir() {
            continue;
        }
        let mode = if *recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        match watcher.watch(dir, mode) {
            Ok(()) => {
                logger::info(format!(
                    "watching {} ({})",
                    dir.display(),
                    if *recursive { "recursive" } else { "top level" }
                ));
                watched.insert(key, dir.clone());
            }
            Err(e) => logger::warn(format!("cannot watch {}: {e}", dir.display())),
        }
    }
}

fn scan_worker(
    cfg: Arc<AppConfig>,
    scanner: Arc<BinaryAiScanner>,
    telemetry: Arc<Telemetry>,
    rx: Receiver<PathBuf>,
    shutdown: Arc<AtomicBool>,
) {
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    let mut arrived = Arrived::default();
    let look_at = |path: &Path, arrived: &mut Arrived| {
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            if is_real_dir(path) {
                arrived.enter(&cfg, path);
            } else {
                scan_path(&cfg, &scanner, path, &telemetry);
            }
        }));
        if outcome.is_err() {
            logger::error(format!(
                "file scanner recovered from a panic on {}",
                path.display()
            ));
        }
    };
    while !shutdown.load(Ordering::SeqCst) {
        let wait = if arrived.queue.is_empty() {
            SCAN_RECV_TIMEOUT
        } else {
            Duration::ZERO
        };
        match rx.recv_timeout(wait) {
            Ok(path) => {
                pending.insert(path, Instant::now());
                while let Ok(more) = rx.try_recv() {
                    pending.insert(more, Instant::now());
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if pending.len() > MAX_PENDING_SCANS {
            logger::warn(format!(
                "file event backlog exceeded {MAX_PENDING_SCANS}; dropping queued scans"
            ));
            pending.clear();
        }
        let ready: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, seen)| seen.elapsed() >= SCAN_SETTLE)
            .map(|(path, _)| path.clone())
            .collect();
        for path in &ready {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            pending.remove(path);
            look_at(path, &mut arrived);
        }
        // One at a time, so that a big folder never holds up a file that has just come.
        if ready.is_empty() {
            if let Some(path) = arrived.pop() {
                // It has its own report, which is newer.
                if !pending.contains_key(&path) {
                    look_at(&path, &mut arrived);
                }
            }
        }
    }
}

fn spawn_worker<F>(workers: &mut Vec<JoinHandle<()>>, name: &str, body: F)
where
    F: FnOnce() + Send + 'static,
{
    match thread::Builder::new().name(name.to_string()).spawn(body) {
        Ok(handle) => workers.push(handle),
        Err(e) => logger::error(format!("cannot start {name}: {e}")),
    }
}

/// Logs a change in whether the always-allowed list is being used: refused (damaged, or not
/// owned by root) or accepted again.
fn report_allowed(cfg: &AppConfig, refusal: &Option<String>) {
    let Some(why) = refusal else {
        logger::info(format!(
            "always-allowed files: {} listed",
            cfg.allowed.len()
        ));
        return;
    };
    logger::error(format!("always-allowed list refused: {why}"));
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            "INTEGRITY",
            Severity::High,
            crate::allowlist::FILE_NAME,
            "LIST_REFUSED: no file is always allowed until it is replaced",
            format!("the always-allowed list was refused: {why}"),
        ),
    );
}

/// Logs a change in whether the never-scan list is being used.
fn report_skipped(cfg: &AppConfig, refusal: &Option<String>) {
    let Some(why) = refusal else {
        logger::info(format!(
            "never-scan places: {} listed",
            cfg.skipped.places().len()
        ));
        return;
    };
    logger::error(format!("never-scan list refused: {why}"));
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            skiplist::EVENT,
            Severity::Medium,
            skiplist::FILE_NAME,
            "LIST_REFUSED: the never-scan list cannot be used",
            format!("the never-scan list was refused: {why}"),
        ),
    );
}

/// Runs every detector until `shutdown` is set. Used by both the service and `--console`.
pub fn run(mut cfg: AppConfig, shutdown: Arc<AtomicBool>) {
    logger::init(&cfg.log_dir, cfg.interactive);
    panic::set_hook(Box::new(|info| logger::error(format!("panic: {info}"))));
    if let Err(e) = cfg.ensure_dirs() {
        logger::error(format!("startup: {e}"));
    }
    load_known_bad(&mut cfg);
    logger::info(format!(
        "The Nex starting (base={}, events={}, quarantine={}, dry_run={}, model={})",
        cfg.base_dir.display(),
        cfg.events_log.display(),
        cfg.quarantine_dir.display(),
        cfg.is_dry_run(),
        cfg.model_path.display()
    ));

    let started_at = Utc::now();
    let cfg = Arc::new(cfg);
    let telemetry = Arc::new(Telemetry::default());
    let scanner =
        Arc::new(BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes));
    telemetry
        .model_loaded
        .store(scanner.has_model(), Ordering::Relaxed);
    let (scan_tx, scan_rx) = mpsc::channel::<PathBuf>();
    let (canary_tx, canary_rx) = mpsc::channel::<CanaryMsg>();
    let mut workers = Vec::new();

    {
        let cfg = Arc::clone(&cfg);
        let telemetry = Arc::clone(&telemetry);
        let shutdown = Arc::clone(&shutdown);
        let dirs = all_canary_dirs(&cfg);
        spawn_worker(&mut workers, "nex-canary", move || {
            canary::run(cfg, dirs, canary_rx, telemetry, shutdown)
        });
    }
    {
        let cfg = Arc::clone(&cfg);
        let scanner = Arc::clone(&scanner);
        let telemetry = Arc::clone(&telemetry);
        let shutdown = Arc::clone(&shutdown);
        spawn_worker(&mut workers, "nex-file-scan", move || {
            scan_worker(cfg, scanner, telemetry, scan_rx, shutdown)
        });
    }
    {
        let cfg = Arc::clone(&cfg);
        let scanner = Arc::clone(&scanner);
        let telemetry = Arc::clone(&telemetry);
        let shutdown = Arc::clone(&shutdown);
        spawn_worker(&mut workers, "nex-process-guard", move || {
            process_guard::run(cfg, scanner, telemetry, shutdown)
        });
    }

    let mut watcher = build_watcher(scan_tx.clone(), canary_tx.clone());
    let mut watched: HashMap<String, PathBuf> = HashMap::new();
    if let Some(w) = watcher.as_mut() {
        refresh_watches(&cfg, w, &mut watched, &watch_plan(&cfg));
    }
    // On-demand scans requested by the desktop app (see scan_jobs).
    let jobs = Arc::new(ScanJobs::default());
    let mut scheduler = Scheduler::load(&cfg);
    if let Err(e) = scan_jobs::prepare(&cfg) {
        logger::warn(format!("on-demand scans are unavailable: {e}"));
    }
    let mut last_requests = Instant::now();
    let mut last_discovery = Some(Instant::now());
    let mut last_settings = Instant::now();
    let mut allowed_refusal: Option<String> = None;
    let mut skipped_refusal: Option<String> = None;
    let mut skipped_places = cfg.skipped.places();
    let mut last_status: Option<Instant> = None;
    let mut status_error_logged = false;
    let mut own_process = System::new();
    let own_pid = Pid::from_u32(std::process::id());
    let cpu_count = thread::available_parallelism()
        .map(|n| n.get() as f32)
        .unwrap_or(1.0);

    while !shutdown.load(Ordering::SeqCst) {
        if last_requests.elapsed() >= SCAN_REQUEST_INTERVAL {
            last_requests = Instant::now();
            jobs.poll(&cfg, &scanner, &telemetry);
            scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        }
        if last_settings.elapsed() >= SETTINGS_RELOAD_INTERVAL {
            last_settings = Instant::now();
            if let Some(toggles) = cfg.toggles.reload_if_changed(&cfg.settings_file) {
                logger::info(format!("settings reloaded: {toggles:?}"));
            }
            cfg.allowed.refresh();
            let refusal = cfg.allowed.error();
            if refusal != allowed_refusal {
                report_allowed(&cfg, &refusal);
                allowed_refusal = refusal;
            }
            cfg.skipped.refresh();
            let refusal = cfg.skipped.error();
            if refusal != skipped_refusal {
                report_skipped(&cfg, &refusal);
                skipped_refusal = refusal;
            }
            // A change takes effect on the watched folders and decoys now, not in a minute.
            if cfg.skipped.places() != skipped_places {
                skipped_places = cfg.skipped.places();
                last_discovery = None;
            }
        }
        if last_status.is_none_or(|t| t.elapsed() >= STATUS_INTERVAL) {
            last_status = Some(Instant::now());
            telemetry.set_watched_dirs(watched.values().cloned().collect());
            own_process.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[own_pid]),
                true,
                ProcessRefreshKind::nothing().with_memory().with_cpu(),
            );
            let usage = own_process
                .process(own_pid)
                .map(|p| ResourceUsage {
                    memory_bytes: p.memory(),
                    cpu_percent: p.cpu_usage() / cpu_count,
                })
                .unwrap_or_default();
            let snapshot = status::build_status(&cfg, &telemetry, started_at, usage);
            match status::write_status(&cfg.status_file, &snapshot) {
                Ok(()) => status_error_logged = false,
                Err(e) if !status_error_logged => {
                    status_error_logged = true;
                    logger::warn(format!("cannot write {}: {e}", cfg.status_file.display()));
                }
                Err(_) => {}
            }
        }
        if last_discovery.is_none_or(|t| t.elapsed() >= REDISCOVER_INTERVAL) {
            last_discovery = Some(Instant::now());
            if watcher.is_none() {
                watcher = build_watcher(scan_tx.clone(), canary_tx.clone());
                watched.clear();
            }
            if let Some(w) = watcher.as_mut() {
                refresh_watches(&cfg, w, &mut watched, &watch_plan(&cfg));
            }
            let _ = canary_tx.send(CanaryMsg::SetDirs(canary_dirs(&cfg)));
        }
        thread::sleep(MAIN_TICK);
    }

    logger::info("The Nex stopping");
    // A scan in progress stops at the next file and is waited for, so shutdown (or an update)
    // never cuts one off mid-write; a scheduled one is simply retried later.
    jobs.cancel();
    jobs.join();
    drop(watcher);
    drop(scan_tx);
    drop(canary_tx);
    for worker in workers {
        let _ = worker.join();
    }
    let _ = fs::remove_file(&cfg.status_file);
    logger::info("The Nex stopped");
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_regular_files() {
        let dir = std::env::temp_dir().join(format!("thenex-sym-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let real = dir.join("real");
        fs::write(&real, b"x").unwrap();
        let link = dir.join("link");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(super::is_regular_file(&real));
        assert!(!super::is_regular_file(&link));
        let _ = fs::remove_dir_all(&dir);
    }

    use super::*;

    #[cfg(unix)]
    #[test]
    fn classify_file_does_not_hang_on_a_fifo_or_follow_a_link() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("thenex-fifo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("pipe.dat");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(classify_file(&fifo), FileKind::Other); // returns instead of blocking

        let real = dir.join("real.dat");
        fs::write(&real, b"MZ\x90\x00").unwrap();
        let link = dir.join("link.dat");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(classify_file(&real), FileKind::Binary);
        assert_eq!(classify_file(&link), FileKind::Other);
        let _ = fs::remove_dir_all(&dir);
    }

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-engine-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn classifies_by_magic_and_extension() {
        let dir = temp_root("classify");
        let cases = [
            ("a.bin", b"MZ\x90\x00rest".to_vec(), FileKind::Binary),
            ("b.dat", b"PK\x03\x04rest".to_vec(), FileKind::Archive),
            ("c.zip", b"garbage".to_vec(), FileKind::Archive),
            ("d.exe", Vec::new(), FileKind::Binary),
            ("e.txt", b"hello".to_vec(), FileKind::Other),
        ];
        for (name, bytes, expected) in cases {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            assert_eq!(classify_file(&path), expected, "{name}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn object_files_are_not_programs() {
        let dir = temp_root("macho");
        // magic, cpu type, cpu subtype, file type (2 = executable, 6 = library, 1 = object)
        let header = |magic: [u8; 4], file_type: [u8; 4]| {
            let mut bytes = magic.to_vec();
            bytes.extend_from_slice(&[0u8; 8]);
            bytes.extend_from_slice(&file_type);
            bytes.extend_from_slice(&[0u8; 16]);
            bytes
        };
        let (le64, le32) = ([0xCF, 0xFA, 0xED, 0xFE], [0xCE, 0xFA, 0xED, 0xFE]);
        let be64 = [0xFE, 0xED, 0xFA, 0xCF];
        let cases = [
            ("tool", header(le64, [2, 0, 0, 0]), FileKind::Binary),
            ("lib.dylib", header(le64, [6, 0, 0, 0]), FileKind::Binary),
            ("unit.o", header(le64, [1, 0, 0, 0]), FileKind::Other),
            ("unit32.o", header(le32, [1, 0, 0, 0]), FileKind::Other),
            ("unit_be.o", header(be64, [0, 0, 0, 1]), FileKind::Other),
            // A big-endian executable is not misread as a little-endian object, or back.
            ("tool_be", header(be64, [0, 0, 0, 2]), FileKind::Binary),
            // Named like an object but linked: the header decides, not the name.
            ("renamed.o", header(le64, [2, 0, 0, 0]), FileKind::Binary),
            // Universal files are sorted out slice by slice in bin_ai::mach_profile.
            (
                "fat",
                vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2],
                FileKind::Binary,
            ),
            ("half_written", le64.to_vec(), FileKind::Binary),
        ];
        for (name, bytes, expected) in cases {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            assert_eq!(classify_file(&path), expected, "{name}");
        }
        // The real thing: this test program is a Mach-O executable.
        assert_eq!(
            classify_file(&std::env::current_exe().unwrap()),
            FileKind::Binary
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_directories_are_never_scanned() {
        let base = std::env::temp_dir().join("thenex-engine-ignore");
        let quarantine = base.join("q-elsewhere");
        let events = base.join("l").join("e.jsonl");
        let cfg = AppConfig::for_base_dir(&base)
            .with_overrides(Some(quarantine.as_path()), Some(events.as_path()));
        assert!(should_ignore(&cfg, &base.join("Quarantine").join("x.exe")));
        assert!(should_ignore(&cfg, &base.join("q-elsewhere").join("x.exe")));
        assert!(should_ignore(
            &cfg,
            Path::new(r"C:\Users\x\Downloads\a.exe.crdownload")
        ));
        assert!(!should_ignore(
            &cfg,
            Path::new(r"C:\Users\x\Downloads\a.exe")
        ));
    }

    /// `--log-file` inside a watched folder must not blind the scanner to that folder.
    #[test]
    fn log_file_beside_watched_files_only_skips_engine_output() {
        let root = std::env::temp_dir().join("thenex-engine-logbeside");
        let watch = root.join("watch");
        let cfg = AppConfig::for_base_dir(&root.join("base")).with_overrides(
            Some(root.join("quarantine").as_path()),
            Some(root.join("events.jsonl").as_path()),
        );
        for own in [
            "events.jsonl",
            "events.jsonl.1",
            "status.json",
            "status.json.tmp",
            "last_quick_scan.json",
            "thenex.log",
            "thenex.log.1",
        ] {
            assert!(should_ignore(&cfg, &root.join(own)), "{own}");
        }
        assert!(!should_ignore(&cfg, &root.join("invoice.zip")));
        assert!(!should_ignore(&cfg, &watch.join("ratio_bomb.zip")));
        assert!(!should_ignore(&cfg, &watch.join("events.jsonl")));
    }

    #[test]
    fn quick_scan_walks_and_respects_toggles() {
        let root = temp_root("quick");
        let watch = root.join("watch");
        fs::create_dir_all(watch.join("nested")).unwrap();
        fs::write(watch.join("notes.txt"), b"plain text").unwrap();
        fs::write(watch.join("nested").join("broken.zip"), b"not really a zip").unwrap();
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.dry_run = true;
        cfg.watch_dir = Some(watch.clone());
        let scanner = BinaryAiScanner::heuristic_only();
        let telemetry = Telemetry::default();

        let report = quick_scan(&cfg, &scanner, &quick_scan_roots(&cfg), &telemetry);
        assert_eq!(report.roots, vec![watch.clone()]);
        assert_eq!(report.files_examined, 2);
        assert_eq!(report.files_scanned, 1);
        assert!(report.findings.is_empty());
        assert!(report.dry_run);

        let mut toggles = cfg.toggles.snapshot();
        toggles.set(Engine::ZipBomb, false);
        cfg.toggles.apply(toggles);
        let report = quick_scan(&cfg, &scanner, &[watch], &telemetry);
        assert_eq!(report.files_scanned, 0);
        assert!(report.unreadable.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    /// A config whose known-malware list holds exactly the files in `listed`.
    fn cfg_with_list(root: &Path, listed: &[PathBuf]) -> AppConfig {
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let digests: Vec<_> = listed
            .iter()
            .map(|p| known_bad::hash_file(p, u64::MAX).unwrap())
            .collect();
        let list = root.join("list.bin");
        known_bad::write_list(&list, &digests, 1_795_000_000).unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        cfg
    }

    /// Events of one type, oldest first.
    fn events_of(cfg: &AppConfig, kind: &str) -> Vec<ThreatEvent> {
        quarantine::read_recent_events(&cfg.events_log, 1 << 20)
            .unwrap_or_default()
            .into_iter()
            .rev()
            .filter(|e| e.threat_type == kind)
            .collect()
    }

    fn set_engine(cfg: &AppConfig, engine: Engine, on: bool) {
        let mut toggles = cfg.toggles.snapshot();
        toggles.set(engine, on);
        cfg.toggles.apply(toggles);
    }

    #[test]
    fn a_listed_file_is_quarantined_and_dry_run_and_the_switch_are_respected() {
        let root = temp_root("known");
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let names = ["payroll.docm", "payroll_dry.docm", "payroll_off.docm"];
        let listed: Vec<PathBuf> = names.iter().map(|n| watch.join(n)).collect();
        for (i, path) in listed.iter().enumerate() {
            fs::write(path, format!("harmless decoy {i}")).unwrap();
        }
        let clean = watch.join("meeting_notes.docm");
        fs::write(&clean, b"ordinary file").unwrap();
        let cfg = cfg_with_list(&root, &listed);
        let scanner = BinaryAiScanner::heuristic_only();
        let telemetry = Telemetry::default();

        scan_path(&cfg, &scanner, &clean, &telemetry);
        assert!(clean.exists());
        assert!(events_of(&cfg, known_bad::THREAT_TYPE).is_empty());

        scan_path(&cfg, &scanner, &listed[0], &telemetry);
        assert!(!listed[0].exists(), "moved to quarantine");
        let events = events_of(&cfg, known_bad::THREAT_TYPE);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Critical);
        assert!(events[0].action_taken.starts_with("QUARANTINED id="));
        assert!(events[0]
            .details
            .starts_with("matched known-malware list (list of 2026-11-18, 3 entries) sha256="));
        let id = events[0].quarantine_id().unwrap();
        let meta = quarantine::load_meta(id, &cfg).unwrap();
        assert_eq!(meta.original_path.file_name(), listed[0].file_name());
        assert_eq!(meta.threat_type, known_bad::THREAT_TYPE);

        set_engine(&cfg, Engine::DryRun, true);
        scan_path(&cfg, &scanner, &listed[1], &telemetry);
        assert!(listed[1].exists(), "dry run never moves a file");
        let events = events_of(&cfg, known_bad::THREAT_TYPE);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].action_taken, "DRY_RUN: would quarantine");
        set_engine(&cfg, Engine::DryRun, false);

        set_engine(&cfg, Engine::KnownBad, false);
        scan_path(&cfg, &scanner, &listed[2], &telemetry);
        assert!(listed[2].exists(), "the engine is switched off");
        assert_eq!(events_of(&cfg, known_bad::THREAT_TYPE).len(), 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn quick_scans_hash_every_file_and_full_scans_only_the_types_the_list_holds() {
        let root = temp_root("known-scan");
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let listed = vec![watch.join("listed.txt"), watch.join("listed.docm")];
        fs::write(&listed[0], b"decoy with a type the list does not hold").unwrap();
        fs::write(&listed[1], b"decoy document").unwrap();
        fs::write(watch.join("clean.txt"), b"ordinary").unwrap();
        let mut cfg = cfg_with_list(&root, &listed);
        cfg.dry_run = true;
        let scanner = BinaryAiScanner::heuristic_only();
        let roots = [watch];
        let scan = |limits: &ScanLimits| {
            scan_tree(
                &cfg,
                &scanner,
                &roots,
                &Telemetry::default(),
                limits,
                &mut |_, _| true,
            )
        };

        let quick = scan(&QUICK_LIMITS);
        assert_eq!((quick.files_examined, quick.files_scanned), (3, 3));
        assert_eq!(quick.findings.len(), 2);
        assert!(quick
            .findings
            .iter()
            .all(|f| f.threat_type == "KNOWN_MALWARE"
                && f.detail.starts_with("matched known-malware list")));

        let full = scan(&FULL_LIMITS);
        assert_eq!((full.files_examined, full.files_scanned), (3, 1));
        assert_eq!(full.findings.len(), 1);
        assert_eq!(full.findings[0].path, listed[1]);
        assert!(listed.iter().all(|p| p.exists()), "dry run");

        set_engine(&cfg, Engine::KnownBad, false);
        let off = scan(&QUICK_LIMITS);
        assert_eq!((off.files_scanned, off.findings.len()), (0, 0));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn only_content_windows_would_download_is_left_alone() {
        const RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
        // What an online-only OneDrive file reports.
        assert!(needs_download(
            RECALL_ON_DATA_ACCESS | 0x1000 | 0x400 | 0x200 | 0x20
        ));
        // Any program can set these on its own file, so they must not hide it from a scan:
        // offline, hidden + system, pinned, unpinned, and "has extended attributes" (the same
        // value as RECALL_ON_OPEN).
        for settable in [0x1000, 0x2 | 0x4, 0x8_0000, 0x10_0000, 0x4_0000] {
            assert!(!needs_download(settable), "{settable:#x}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_file_marked_offline_by_a_program_is_still_scanned() {
        let root = temp_root("offline");
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let bomb = watch.join("offline.zip");
        fs::write(&bomb, decoy_bomb()).unwrap();
        let marked = std::process::Command::new("attrib")
            .arg("+O")
            .arg(&bomb)
            .status();
        assert!(marked.unwrap().success());
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        let telemetry = Telemetry::default();
        let report = quick_scan(
            &cfg,
            &BinaryAiScanner::heuristic_only(),
            &[watch],
            &telemetry,
        );
        assert_eq!((report.cloud_skipped, report.findings.len()), (0, 1));
        assert!(!bomb.exists(), "moved to quarantine");
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn a_locked_folder_of_a_person_is_reported_by_a_full_scan() {
        let people = [r"C:\Users", r"C:\Users\kim\Desktop", r"D:\Users\kim"];
        for dir in people {
            assert!(in_reported_tree(&FULL_LIMITS, Path::new(dir)), "{dir}");
        }
        for other in [r"C:\Windows\CSC", r"C:\ProgramData\Users"] {
            assert!(!in_reported_tree(&FULL_LIMITS, Path::new(other)), "{other}");
        }
    }

    #[test]
    fn every_report_the_engine_writes_is_its_own_output() {
        let root = temp_root("own-output");
        let cfg = AppConfig {
            log_dir: root.clone(),
            events_log: root.join("events.jsonl"),
            ..AppConfig::for_base_dir(&root.join("base"))
        };
        for kind in [ScanKind::Quick, ScanKind::Full, ScanKind::Scheduled] {
            let report = root.join(kind.report_file());
            assert!(is_engine_output(&cfg, &report), "{kind:?}");
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// From a real Windows log: a file restored from quarantine went straight back into it, three
    /// times, because live protection saw it arrive.
    #[test]
    fn a_restored_file_stays_where_it_was_put() {
        let root = temp_root("restored");
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let scanner = BinaryAiScanner::with_fixed_score(0.99);
        let telemetry = Telemetry::default();
        let (bomb, program) = (watch.join("decoy.zip"), watch.join("decoy.exe"));
        fs::write(&bomb, decoy_bomb()).unwrap();
        fs::write(&program, decoy_program()).unwrap();
        for (kind, path) in [("ZIP_BOMB", &bomb), ("MALWARE_AI", &program)] {
            scan_path(&cfg, &scanner, path, &telemetry);
            let id = events_of(&cfg, kind)[0]
                .quarantine_id()
                .unwrap()
                .to_string();
            let meta = quarantine::restore_file(&id, &cfg).unwrap();
            quarantine::record_restore(&cfg, &meta, "");
            scan_path(&cfg, &scanner, path, &telemetry);
            let seen = events_of(&cfg, kind);
            assert!(path.exists(), "{kind}: {seen:?}");
            assert!(
                seen[1].action_taken.starts_with("ALERT_ONLY: you restored"),
                "{seen:?}"
            );
            assert!(seen[1].quiet, "its owner has already decided");

            // Another file under that name, and the same file elsewhere, are judged afresh.
            let copy = path.with_file_name(format!(
                "copy-{kind}.{}",
                path.extension().unwrap().to_string_lossy()
            ));
            fs::copy(path, &copy).unwrap();
            scan_path(&cfg, &scanner, &copy, &telemetry);
            assert!(!copy.exists(), "{kind}");
            let mut bytes = fs::read(path).unwrap();
            bytes.push(0);
            fs::write(path, bytes).unwrap();
            scan_path(&cfg, &scanner, path, &telemetry);
            assert!(!path.exists(), "{kind}");
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// A match in the known-malware list is certain: restoring it changes nothing.
    #[test]
    fn a_restored_listed_file_is_quarantined_again() {
        let root = temp_root("restored-known");
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let listed = watch.join("payroll.docm");
        fs::write(&listed, b"harmless decoy").unwrap();
        let cfg = cfg_with_list(&root, std::slice::from_ref(&listed));
        let scanner = BinaryAiScanner::heuristic_only();
        scan_path(&cfg, &scanner, &listed, &Telemetry::default());
        let id = events_of(&cfg, known_bad::THREAT_TYPE)[0]
            .quarantine_id()
            .unwrap()
            .to_string();
        let meta = quarantine::restore_file(&id, &cfg).unwrap();
        quarantine::record_restore(&cfg, &meta, "");
        scan_path(&cfg, &scanner, &listed, &Telemetry::default());
        assert!(!listed.exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// A zip with one entry of 20 MiB of zeros: a harmless decoy that trips the ratio rule.
    fn decoy_bomb() -> Vec<u8> {
        use std::io::Write;
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("zeros.bin", options).unwrap();
        writer.write_all(&vec![0u8; 20 * 1024 * 1024]).unwrap();
        writer.finish().unwrap();
        cursor.into_inner()
    }

    /// A thin Mach-O executable header: parsed as a program, which the fixed-score scanner
    /// then rates as malicious.
    fn decoy_program() -> Vec<u8> {
        [0xFEED_FACF, 0x0100_000C, 0, 2, 0, 0, 0, 0]
            .iter()
            .flat_map(|field: &u32| field.to_le_bytes())
            .collect()
    }

    fn always_allow(cfg: &AppConfig, path: &Path, kind: &str) {
        let sha = quarantine::sha256_file(path).unwrap();
        let entry = crate::allowlist::AllowedFile::new(&sha, "decoy", kind).unwrap();
        assert!(crate::allowlist::add(cfg, entry).unwrap());
    }

    #[test]
    fn an_always_allowed_file_is_left_alone_until_one_byte_changes() {
        let root = temp_root("allowed");
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        set_engine(&cfg, Engine::DryRun, true);
        let scanner = BinaryAiScanner::with_fixed_score(0.99);
        let telemetry = Telemetry::default();
        let (bomb, program) = (watch.join("decoy.zip"), watch.join("decoy.exe"));
        fs::write(&bomb, decoy_bomb()).unwrap();
        fs::write(&program, decoy_program()).unwrap();
        let events = |kind: &str| events_of(&cfg, kind);

        // Flagged (dry run), and the event carries the hash of the file that was judged.
        scan_path(&cfg, &scanner, &bomb, &telemetry);
        scan_path(&cfg, &scanner, &program, &telemetry);
        for (kind, path) in [("ZIP_BOMB", &bomb), ("MALWARE_AI", &program)] {
            let seen = events(kind);
            assert_eq!(seen.len(), 1, "{kind}");
            assert_eq!(seen[0].action_taken, "DRY_RUN: would quarantine");
            assert_eq!(
                seen[0].sha256.as_deref(),
                Some(quarantine::sha256_file(path).unwrap().as_str())
            );
            always_allow(&cfg, path, kind);
        }

        // Allowed: no event even in dry run, and nothing moves for real.
        scan_path(&cfg, &scanner, &bomb, &telemetry);
        scan_path(&cfg, &scanner, &program, &telemetry);
        assert_eq!(
            (events("ZIP_BOMB").len(), events("MALWARE_AI").len()),
            (1, 1)
        );
        set_engine(&cfg, Engine::DryRun, false);
        let quick = quick_scan(&cfg, &scanner, std::slice::from_ref(&watch), &telemetry);
        assert!(quick.findings.is_empty(), "{:?}", quick.findings);
        assert!(bomb.exists() && program.exists());
        assert_eq!(
            (events("ZIP_BOMB").len(), events("MALWARE_AI").len()),
            (1, 1)
        );

        // One byte different is a different file: flagged and quarantined again.
        for path in [&bomb, &program] {
            let mut bytes = fs::read(path).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            let changed = path.with_file_name(format!(
                "changed-{}",
                path.file_name().unwrap().to_string_lossy()
            ));
            fs::write(&changed, bytes).unwrap();
            scan_path(&cfg, &scanner, &changed, &telemetry);
            assert!(!changed.exists(), "{} was quarantined", changed.display());
            assert!(path.exists(), "the allowed original is untouched");
        }
        assert_eq!(
            (events("ZIP_BOMB").len(), events("MALWARE_AI").len()),
            (2, 2)
        );
        assert!(events("ZIP_BOMB")[1]
            .action_taken
            .starts_with("QUARANTINED id="));

        // Removed from the list, the original is flagged again.
        for path in [&bomb, &program] {
            let sha = quarantine::sha256_file(path).unwrap();
            assert!(crate::allowlist::remove(&cfg, &sha).unwrap());
        }
        scan_path(&cfg, &scanner, &bomb, &telemetry);
        assert!(!bomb.exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// Found by an audit: for a folder that is moved in, the system reports only the folder.
    #[test]
    fn a_folder_that_is_moved_in_is_scanned_and_one_that_changed_is_not_walked() {
        let root = temp_root("moved-in");
        let cfg = Arc::new(AppConfig::for_base_dir(&root.join("base")));
        cfg.ensure_dirs().unwrap();
        // Deeper than a Quick Scan goes, and named like a download in progress.
        let folder = root.join("app.download");
        let deep = folder.join("1/2/3/4/5/6/7/8/9/10");
        fs::create_dir_all(&deep).unwrap();
        let program = deep.join("decoy.exe");
        fs::write(&program, decoy_program()).unwrap();
        let sent = |kind: EventKind| -> Vec<PathBuf> {
            let (tx, rx) = mpsc::channel();
            let (canary, _keep) = mpsc::channel();
            dispatch_event(Event::new(kind).add_path(folder.clone()), &tx, &canary);
            drop(tx);
            rx.iter().collect()
        };
        use notify::event::{DataChange, RenameMode};
        let name = ModifyKind::Name(RenameMode::Any);
        assert_eq!(sent(EventKind::Modify(name)), [folder.clone()]);
        let created = EventKind::Create(notify::event::CreateKind::Folder);
        assert_eq!(sent(created), [folder.clone()]);
        assert!(sent(EventKind::Modify(ModifyKind::Data(DataChange::Any))).is_empty());

        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = {
            let (cfg, shutdown) = (Arc::clone(&cfg), Arc::clone(&shutdown));
            let scanner = Arc::new(BinaryAiScanner::with_fixed_score(0.99));
            thread::spawn(move || scan_worker(cfg, scanner, Arc::default(), rx, shutdown))
        };
        tx.send(folder.clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while program.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        shutdown.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        assert!(!program.exists(), "quarantined");
        assert_eq!(events_of(&cfg, "MALWARE_AI").len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_never_scan_place_is_left_alone_by_every_scan_until_it_is_taken_off() {
        let root = crate::skiplist::tests::listable("engine");
        let watch = root.join("watch");
        let (private, beside) = (watch.join("Private"), watch.join("Private2"));
        for dir in [&private.join("deep"), &beside] {
            fs::create_dir_all(dir).unwrap();
        }
        let hidden = [
            private.join("decoy.exe"),
            private.join("deep").join("decoy.zip"),
            private.join("listed.docm"),
            watch.join("one.exe"),
        ];
        let seen = [beside.join("decoy.exe"), watch.join("two.zip")];
        for path in hidden.iter().chain(&seen) {
            match path.extension().and_then(|e| e.to_str()) {
                Some("zip") => fs::write(path, decoy_bomb()).unwrap(),
                Some("docm") => fs::write(path, b"a listed decoy").unwrap(),
                _ => fs::write(path, decoy_program()).unwrap(),
            }
        }
        let mut cfg = cfg_with_list(&root, std::slice::from_ref(&hidden[2]));
        for (place, folder) in [(&private, true), (&hidden[3], false)] {
            assert!(crate::skiplist::add(&cfg, place, folder).unwrap());
        }
        let scanner = BinaryAiScanner::with_fixed_score(0.99);
        let telemetry = Telemetry::default();

        // Live: not even counted as looked at. Detection for real (no dry run), every engine on.
        for path in &hidden {
            scan_path(&cfg, &scanner, path, &telemetry);
        }
        assert_eq!(telemetry.files_scanned.load(Ordering::Relaxed), 0);
        // And a detector that was already at work cannot move one.
        let refused = quarantine::quarantine_file(&hidden[0], &cfg, "MALWARE_AI", "test");
        assert!(refused.unwrap_err().to_string().contains("never-scan"));

        // Every kind of scan. Quick is the one that acts; the others only report.
        cfg.watch_dir = Some(watch.clone());
        for kind in [ScanKind::Scheduled, ScanKind::Full, ScanKind::Quick] {
            let report = run_scan(&cfg, &scanner, &telemetry, kind, &mut |_, _| true);
            let mut found: Vec<&Path> = report.findings.iter().map(|f| f.path.as_path()).collect();
            found.sort();
            assert_eq!(
                found,
                seen.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
                "{kind:?}"
            );
            assert_eq!(
                (report.never_scan, report.files_examined),
                (2, 2),
                "{kind:?}"
            );
        }
        assert!(hidden.iter().all(|p| p.exists()));
        assert!(seen.iter().all(|p| !p.exists()), "quarantined");
        let named = quarantine::read_recent_events(&cfg.events_log, 1 << 20).unwrap();
        for event in named
            .iter()
            .filter(|e| e.threat_type != crate::skiplist::EVENT)
        {
            assert!(
                hidden
                    .iter()
                    .all(|p| event.target != p.display().to_string()),
                "{event:?}"
            );
        }

        // A scan of the listed folder itself says it was left out, not that it is clean.
        let report = quick_scan(&cfg, &scanner, std::slice::from_ref(&private), &telemetry);
        assert_eq!((report.never_scan, report.files_examined), (1, 0));

        // Not a place for decoys.
        cfg.watch_dir = Some(private.clone());
        assert!(canary_dirs(&cfg).is_empty());

        // Taken off the list, the same files are dealt with; dry run and switches still count.
        for place in [&private, &hidden[3]] {
            assert!(crate::skiplist::remove(&cfg, place).unwrap());
        }
        set_engine(&cfg, Engine::DryRun, true);
        let report = quick_scan(&cfg, &scanner, std::slice::from_ref(&watch), &telemetry);
        assert_eq!((report.findings.len(), report.never_scan), (4, 0));
        assert!(hidden.iter().all(|p| p.exists()), "dry run");
        set_engine(&cfg, Engine::DryRun, false);
        scan_path(&cfg, &scanner, &hidden[0], &telemetry);
        assert!(!hidden[0].exists(), "quarantined");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_on_the_known_malware_list_is_quarantined_even_when_it_is_also_allowed() {
        let root = temp_root("known-and-allowed");
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let program = watch.join("both.exe");
        fs::write(&program, decoy_program()).unwrap();
        let cfg = cfg_with_list(&root, std::slice::from_ref(&program));
        // `allowlist::add` refuses a listed hash, so the list is written by hand: even then
        // the hash is in effect as "allowed" in the file but never honoured.
        let sha = quarantine::sha256_file(&program).unwrap();
        let entry = crate::allowlist::AllowedFile::new(&sha, "both", "MALWARE_AI").unwrap();
        assert!(crate::allowlist::add(&cfg, entry.clone()).is_err());
        fs::write(&cfg.allowed_file, serde_json::to_vec(&[entry]).unwrap()).unwrap();
        cfg.allowed.refresh();
        assert!(cfg.allowed.contains(&sha));

        let scanner = BinaryAiScanner::with_fixed_score(0.99);
        scan_path(&cfg, &scanner, &program, &Telemetry::default());
        assert!(!program.exists(), "quarantined");
        let events = events_of(&cfg, known_bad::THREAT_TYPE);
        assert_eq!(events.len(), 1);
        assert!(events[0].action_taken.starts_with("QUARANTINED id="));
        assert!(events_of(&cfg, "MALWARE_AI").is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_refused_list_is_logged_and_leaves_the_engine_idle() {
        let root = temp_root("known-refused");
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let list = root.join("list.bin");
        known_bad::write_list(&list, &[[9u8; 32]], 5).unwrap();
        let mut bytes = fs::read(&list).unwrap();
        *bytes.last_mut().unwrap() ^= 0x01;
        fs::write(&list, bytes).unwrap();
        cfg.hash_list = Some(list);

        load_known_bad(&mut cfg);
        assert!(!cfg.known_bad_active());
        let events = events_of(&cfg, "INTEGRITY");
        assert_eq!(events.len(), 1);
        assert!(events[0].details.contains("checksum mismatch"));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn quick_scan_reports_folders_it_cannot_open() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root("blocked");
        let (open, locked, missing) = (root.join("open"), root.join("locked"), root.join("gone"));
        fs::create_dir_all(&open).unwrap();
        fs::create_dir_all(&locked).unwrap();
        fs::write(open.join("notes.txt"), b"plain text").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        let scanner = BinaryAiScanner::heuristic_only();
        let roots = [open, locked.clone(), missing];
        let report = quick_scan(&cfg, &scanner, &roots, &Telemetry::default());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(report.files_examined, 1);
        // root can open anything; a folder that does not exist is simply skipped
        if fs::read_dir("/var/root").is_err() {
            assert_eq!(report.unreadable, vec![locked]);
        }
        let _ = fs::remove_dir_all(&root);
    }
}
