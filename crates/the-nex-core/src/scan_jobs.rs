//! On-demand scans run by the background service. It already runs with the rights (and, on
//! macOS, the Full Disk Access) a scan needs, so the desktop app asks it to scan instead of
//! starting a second privileged process behind a password prompt.
//!
//! A request is an empty file with a fixed name in `<data dir>/requests`, which any local user
//! may create. Only the name is ever looked at, never the content. Any local user can therefore
//! start a scan, or cancel one a user started. None of them can cancel the scheduled scan; a
//! scan a user asks for stops it once per due period (it is retried later), and after that waits
//! behind it, where a cancel request removes it. A full scan only reports; a quick scan acts on what it finds in
//! Downloads and Desktop exactly as live protection already does for new files there.
//! shortcut: no per-user authorisation of requests, add it before a scan can do more than that.

use crate::bin_ai::BinaryAiScanner;
use crate::config::AppConfig;
use crate::engine::{self, QuickScanReport, ScanKind, SCAN_PROGRESS_FILE};
use crate::logger;
use crate::schedule;
use crate::status::{Telemetry, FUTURE_SKEW_SECS};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const REQUEST_DIR_NAME: &str = "requests";
const CANCEL_REQUEST: &str = "cancel-scan";
const PROGRESS_EVERY: Duration = Duration::from_millis(500);
/// Progress older than this was left by a service that stopped mid-scan. Generous: checking one
/// very large program can take a while, and a scan wrongly called dead would show an old result.
const PROGRESS_STALE_SECS: i64 = 120;
pub const BUSY: &str = "A scan is already running";
const POLL_STEP: Duration = Duration::from_millis(200);

fn request_name(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Quick => "quick-scan",
        ScanKind::Full => "full-scan",
        // Never read by `poll`: only the schedule starts one, so nobody can ask for it.
        ScanKind::Scheduled => "scheduled-scan",
    }
}

pub fn request_dir(cfg: &AppConfig) -> PathBuf {
    cfg.base_dir.join(REQUEST_DIR_NAME)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    /// A scheduled scan says `Quick` here and `scheduled: true` below: the previous release
    /// cannot read any other name and would drop the whole file.
    pub kind: ScanKind,
    pub running: bool,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub files_examined: u64,
    pub files_scanned: u64,
    pub findings: u64,
    /// Folder being read.
    pub current: String,
    /// Started by the schedule (a user's scan may stop it); missing in older files.
    #[serde(default)]
    pub scheduled: bool,
}

impl ScanProgress {
    /// Running, and written recently enough that the service is still alive.
    pub fn is_live(&self) -> bool {
        // From the future: the clock was set back, so it says nothing.
        self.running
            && (-FUTURE_SKEW_SECS..=PROGRESS_STALE_SECS)
                .contains(&(Utc::now() - self.updated_at).num_seconds())
    }
}

fn write_progress(cfg: &AppConfig, progress: &ScanProgress) {
    let path = cfg.log_dir.join(SCAN_PROGRESS_FILE);
    let staging = path.with_extension("json.tmp");
    if let Ok(json) = serde_json::to_vec(progress) {
        if fs::write(&staging, json).is_ok() {
            let _ = fs::rename(&staging, &path);
        }
    }
}

pub fn read_progress(cfg: &AppConfig) -> Option<ScanProgress> {
    serde_json::from_slice(&fs::read(cfg.log_dir.join(SCAN_PROGRESS_FILE)).ok()?).ok()
}

// ---- service side ------------------------------------------------------------------------

/// Creates the request folder: anyone may add a file, nobody but the service may remove one
/// (on Windows users can also list it). Also clears progress left behind by a previous run.
pub fn prepare(cfg: &AppConfig) -> io::Result<()> {
    let _ = fs::remove_file(cfg.log_dir.join(SCAN_PROGRESS_FILE));
    let dir = request_dir(cfg);
    fs::create_dir_all(&dir)?;
    // Anything left in there (stale requests, or junk a user parked) goes at every start.
    for entry in fs::read_dir(&dir)?.flatten() {
        remove_entry(&entry.path());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1733))?;
    }
    // The installed service only: run by hand, the folder is already the user's own.
    #[cfg(windows)]
    if crate::config::running_privileged() && !crate::platform::let_users_add_files(&dir) {
        // Without the folder the app knows not to ask (see `available`).
        fs::remove_dir(&dir)?;
        return Err(io::Error::other(
            "could not open the request folder to users",
        ));
    }
    Ok(())
}

/// True if the request was there and has been removed. The entry is whatever a local user put
/// under that name, so it is only unlinked (never opened or followed); one that cannot be
/// removed is ignored, or it would start a scan on every poll.
fn take_request(dir: &Path, name: &str) -> bool {
    let path = dir.join(name);
    fs::symlink_metadata(&path).is_ok() && remove_entry(&path)
}

/// Removes whatever a user left at `path` without opening or following it. An immutable flag
/// (`chflags uchg`, which the owner may set) would pin the name and block that request for
/// everyone, so it is cleared and the removal retried.
fn remove_entry(path: &Path) -> bool {
    let remove = || match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path).is_ok(),
        Ok(_) => fs::remove_file(path).is_ok(),
        Err(_) => true,
    };
    if remove() {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
            // SAFETY: `c` is a valid NUL-terminated path; lchflags does not follow a symlink.
            unsafe { libc::lchflags(c.as_ptr(), 0) };
        }
    }
    remove()
}

#[derive(Default)]
pub struct ScanJobs {
    running: AtomicBool,
    cancel: AtomicBool,
    /// The running scan is the scheduled one.
    scheduled: AtomicBool,
    /// User scans that arrived during the scheduled one (a quick and a full one can both wait),
    /// started one after the other once that one has stopped.
    waiting: Mutex<Vec<ScanKind>>,
    /// The scheduled scan was already stopped for a user's scan since one last ran to the end:
    /// the retry is not stopped again, or a local user could keep it from ever finishing.
    preempted: AtomicBool,
    /// How the last scheduled scan ended (true = ran to the end), until the schedule reads it.
    outcome: Mutex<Option<bool>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl ScanJobs {
    /// Called about once a second by the service: starts a requested scan (one at a time) and
    /// passes on a cancel request. The scheduled scan ignores cancel requests (they remove a
    /// scan waiting behind it instead). A requested scan stops it once and runs in its place;
    /// after that it waits for the scheduled scan to end.
    pub fn poll(
        self: &Arc<Self>,
        cfg: &Arc<AppConfig>,
        scanner: &Arc<BinaryAiScanner>,
        telemetry: &Arc<Telemetry>,
    ) {
        let dir = request_dir(cfg);
        if take_request(&dir, CANCEL_REQUEST) {
            if !self.scheduled.load(Ordering::SeqCst) {
                self.cancel.store(true, Ordering::SeqCst);
            } else {
                // Cancels the user's scans queued behind the scheduled one, not the schedule.
                locked(&self.waiting).clear();
            }
        }
        for kind in [ScanKind::Full, ScanKind::Quick] {
            if take_request(&dir, request_name(kind)) {
                if !self.is_running() {
                    self.start(kind, cfg, scanner, telemetry);
                } else if self.scheduled.load(Ordering::SeqCst) {
                    let mut waiting = locked(&self.waiting);
                    if !waiting.contains(&kind) {
                        waiting.push(kind);
                    }
                    drop(waiting);
                    if !self.preempted.swap(true, Ordering::SeqCst) {
                        self.cancel.store(true, Ordering::SeqCst);
                    }
                }
                // else: a request that arrives during a user's scan is dropped, not queued.
            }
        }
        if !self.is_running() {
            let next = {
                let mut waiting = locked(&self.waiting);
                (!waiting.is_empty()).then(|| waiting.remove(0))
            };
            if let Some(kind) = next {
                self.start(kind, cfg, scanner, telemetry);
            }
        }
    }

    /// Starts a scan on its own thread unless one is running; true when it was started.
    pub fn start(
        self: &Arc<Self>,
        kind: ScanKind,
        cfg: &Arc<AppConfig>,
        scanner: &Arc<BinaryAiScanner>,
        telemetry: &Arc<Telemetry>,
    ) -> bool {
        if self.running.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.cancel.store(false, Ordering::SeqCst);
        self.scheduled
            .store(kind == ScanKind::Scheduled, Ordering::SeqCst);
        let (jobs, cfg, scanner, telemetry) = (
            Arc::clone(self),
            Arc::clone(cfg),
            Arc::clone(scanner),
            Arc::clone(telemetry),
        );
        let spawned = thread::Builder::new()
            .name("nex-scan-job".to_string())
            .spawn(move || {
                // Cleared on drop, so a panic in the scan cannot leave the service refusing
                // every later request.
                struct Idle(Arc<ScanJobs>);
                impl Drop for Idle {
                    fn drop(&mut self) {
                        self.0.scheduled.store(false, Ordering::SeqCst);
                        self.0.running.store(false, Ordering::SeqCst);
                    }
                }
                let idle = Idle(jobs);
                if kind == ScanKind::Scheduled {
                    schedule::lower_priority();
                }
                idle.0.run(kind, &cfg, &scanner, &telemetry);
            });
        match spawned {
            Ok(handle) => {
                *locked(&self.thread) = Some(handle);
                true
            }
            Err(e) => {
                logger::warn(format!("cannot start the scan: {e}"));
                self.scheduled.store(false, Ordering::SeqCst);
                self.running.store(false, Ordering::SeqCst);
                false
            }
        }
    }

    /// Waits for the scan thread (after `cancel`), so a service shutdown ends a scan cleanly.
    pub fn join(&self) {
        let handle = locked(&self.thread).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }

    #[cfg(test)]
    pub(crate) fn set_scheduled_outcome(&self, finished: bool) {
        *locked(&self.outcome) = Some(finished);
    }

    /// Whether the last scheduled scan ran to the end; None if none ended since the last call.
    pub fn take_scheduled_outcome(&self) -> Option<bool> {
        locked(&self.outcome).take()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stops a running scan at the next folder (service shutdown).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    fn run(
        &self,
        kind: ScanKind,
        cfg: &AppConfig,
        scanner: &BinaryAiScanner,
        telemetry: &Telemetry,
    ) {
        logger::info(format!("{kind:?} scan requested"));
        let started_at = Utc::now();
        let snapshot = |report: &QuickScanReport, dir: &Path, running: bool| ScanProgress {
            kind: if kind == ScanKind::Scheduled {
                ScanKind::Quick
            } else {
                kind
            },
            running,
            started_at,
            updated_at: Utc::now(),
            files_examined: report.files_examined,
            files_scanned: report.files_scanned,
            findings: report.findings.len() as u64,
            current: dir.display().to_string(),
            scheduled: kind == ScanKind::Scheduled,
        };
        let mut last_write: Option<Instant> = None;
        let report = engine::run_scan(cfg, scanner, telemetry, kind, &mut |report, dir| {
            if last_write.is_none_or(|t| t.elapsed() >= PROGRESS_EVERY) {
                last_write = Some(Instant::now());
                write_progress(cfg, &snapshot(report, dir, true));
            }
            !self.cancel.load(Ordering::SeqCst)
        });
        write_progress(cfg, &snapshot(&report, Path::new(""), false));
        if kind == ScanKind::Scheduled {
            if !report.cancelled {
                self.preempted.store(false, Ordering::SeqCst);
            }
            *locked(&self.outcome) = Some(!report.cancelled);
        }
    }
}

// ---- client side (desktop app) -----------------------------------------------------------

/// True when the service that owns `cfg`'s data folder accepts scan requests.
pub fn available(cfg: &AppConfig) -> bool {
    request_dir(cfg).is_dir()
}

fn drop_request(cfg: &AppConfig, name: &str) -> Result<(), String> {
    let path = request_dir(cfg).join(name);
    match fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
    {
        Ok(_) => Ok(()),
        // Another user's identical request is already waiting there.
        Err(_) if fs::symlink_metadata(&path).is_ok() => Ok(()),
        Err(e) => Err(format!("could not reach the background service: {e}")),
    }
}

pub fn request(cfg: &AppConfig, kind: ScanKind) -> Result<(), String> {
    // A scheduled scan is not "busy": the service stops it for this request.
    if read_progress(cfg).is_some_and(|p| p.is_live() && !p.scheduled) {
        return Err(BUSY.to_string());
    }
    drop_request(cfg, request_name(kind))
}

pub fn request_cancel(cfg: &AppConfig) -> Result<(), String> {
    drop_request(cfg, CANCEL_REQUEST)
}

/// Asks the service for a scan and waits for its report: `timeout` without a sign of life, not in
/// all. A full Downloads folder takes many minutes.
pub fn request_and_wait(
    cfg: &AppConfig,
    kind: ScanKind,
    timeout: Duration,
) -> Result<QuickScanReport, String> {
    let before = engine::read_scan_report(cfg, kind);
    request(cfg, kind)?;
    let deadline = Instant::now() + timeout;
    // A scan that is running has answered, however long it takes.
    while Instant::now() < deadline
        || read_progress(cfg).is_some_and(|p| p.is_live() && p.kind == kind && !p.scheduled)
    {
        thread::sleep(POLL_STEP);
        match engine::read_scan_report(cfg, kind) {
            Some(report) if Some(&report) != before.as_ref() => return Ok(report),
            _ => {}
        }
    }
    Err("the background service did not answer; check that it is running".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(tag: &str) -> (PathBuf, AppConfig) {
        let root = std::env::temp_dir().join(format!("thenex-jobs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        fs::write(watch.join("notes.txt"), b"plain text").unwrap();
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.watch_dir = Some(watch);
        cfg.ensure_dirs().unwrap();
        prepare(&cfg).unwrap();
        (root, cfg)
    }

    fn service(
        cfg: &AppConfig,
    ) -> (
        Arc<ScanJobs>,
        Arc<AppConfig>,
        Arc<BinaryAiScanner>,
        Arc<Telemetry>,
    ) {
        (
            Arc::new(ScanJobs::default()),
            Arc::new(cfg.clone()),
            Arc::new(BinaryAiScanner::heuristic_only()),
            Arc::new(Telemetry::default()),
        )
    }

    fn wait_idle(jobs: &ScanJobs) {
        for _ in 0..200 {
            if !jobs.running.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("scan job did not finish");
    }

    #[test]
    fn a_long_scan_is_waited_for_while_it_moves() {
        let (root, cfg) = sandbox("long");
        let (client, step) = (cfg.clone(), Duration::from_millis(300));
        let waiting = thread::spawn(move || {
            request_and_wait(&client, ScanKind::Quick, Duration::from_secs(1))
        });
        let asked = request_dir(&cfg).join(request_name(ScanKind::Quick));
        while !asked.exists() {
            thread::sleep(Duration::from_millis(5));
        }
        for _ in 0..8 {
            write_progress(
                &cfg,
                &ScanProgress {
                    kind: ScanKind::Quick,
                    running: true,
                    started_at: Utc::now(),
                    updated_at: Utc::now(),
                    files_examined: 1,
                    files_scanned: 1,
                    findings: 0,
                    current: String::new(),
                    scheduled: false,
                },
            );
            thread::sleep(step);
        }
        let report = QuickScanReport {
            finished_at: Utc::now().to_rfc3339(),
            ..QuickScanReport::default()
        };
        let path = cfg.log_dir.join(ScanKind::Quick.report_file());
        fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(
            waiting.join().unwrap().is_ok(),
            "over twice the wait for an answer"
        );

        fs::remove_file(cfg.log_dir.join(SCAN_PROGRESS_FILE)).unwrap();
        assert!(request_and_wait(&cfg, ScanKind::Quick, step).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_requested_full_scan_runs_reports_and_never_moves_files() {
        let (root, cfg) = sandbox("full");
        let (jobs, shared, scanner, telemetry) = service(&cfg);
        assert!(available(&cfg));
        jobs.poll(&shared, &scanner, &telemetry); // nothing requested: nothing happens
        assert!(read_progress(&cfg).is_none());

        request(&cfg, ScanKind::Full).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);

        let report = engine::read_scan_report(&cfg, ScanKind::Full).unwrap();
        assert!(report.full && report.dry_run && !report.cancelled);
        assert_eq!(report.files_examined, 1);
        assert!(!report.finished_at.is_empty());
        let progress = read_progress(&cfg).unwrap();
        assert!(!progress.running && !progress.is_live());
        assert_eq!(progress.files_examined, 1);
        // The request was consumed: polling again does not rescan.
        let first = report.finished_at.clone();
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);
        assert_eq!(
            engine::read_scan_report(&cfg, ScanKind::Full)
                .unwrap()
                .finished_at,
            first
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cancel_stops_a_scan_and_requests_are_only_names() {
        let (root, cfg) = sandbox("cancel");
        let (jobs, shared, scanner, telemetry) = service(&cfg);
        // A cancel waiting with the request: the cancel is consumed first, the new scan runs whole.
        request_cancel(&cfg).unwrap();
        request(&cfg, ScanKind::Quick).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);
        assert!(
            !engine::read_scan_report(&cfg, ScanKind::Quick)
                .unwrap()
                .cancelled
        );

        // A cancelled flag set while running stops the walk at the next folder.
        jobs.cancel();
        let report = engine::run_scan(&cfg, &scanner, &telemetry, ScanKind::Full, &mut |_, _| {
            !jobs.cancel.load(Ordering::SeqCst)
        });
        assert!(report.cancelled && report.files_examined == 0);

        // Hostile entries: a directory tree and a dangling symlink under the request name are
        // removed without being followed, and each counts as one request at most.
        let dir = request_dir(&cfg);
        fs::create_dir_all(dir.join("full-scan").join("deep")).unwrap();
        assert!(take_request(&dir, "full-scan"));
        assert!(!take_request(&dir, "full-scan"));
        #[cfg(unix)]
        {
            let outside = root.join("outside.txt");
            fs::write(&outside, b"keep").unwrap();
            std::os::unix::fs::symlink(&outside, dir.join("quick-scan")).unwrap();
            assert!(take_request(&dir, "quick-scan"));
            assert_eq!(fs::read(&outside).unwrap(), b"keep");
        }
        // An immutable request (the owner can set that flag) is still removed, and start-up
        // clears whatever was left in the folder.
        #[cfg(target_os = "macos")]
        {
            let pinned = dir.join("full-scan");
            fs::write(&pinned, b"").unwrap();
            let flagged = std::process::Command::new("/usr/bin/chflags")
                .arg("uchg")
                .arg(&pinned)
                .status();
            if flagged.is_ok_and(|s| s.success()) {
                assert!(fs::remove_file(&pinned).is_err());
                assert!(take_request(&dir, "full-scan"));
            }
        }
        fs::write(dir.join("junk-a-user-left"), b"x").unwrap();
        prepare(&cfg).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_second_request_during_a_live_scan_is_refused() {
        let (root, cfg) = sandbox("busy");
        write_progress(
            &cfg,
            &ScanProgress {
                kind: ScanKind::Full,
                running: true,
                started_at: Utc::now(),
                updated_at: Utc::now(),
                files_examined: 5,
                files_scanned: 1,
                findings: 0,
                current: "/Applications".to_string(),
                scheduled: false,
            },
        );
        assert_eq!(request(&cfg, ScanKind::Quick), Err(BUSY.to_string()));
        // The same progress, but stale: the service died, so a new request is accepted.
        let mut stale = read_progress(&cfg).unwrap();
        stale.updated_at = Utc::now() - chrono::Duration::seconds(PROGRESS_STALE_SECS + 5);
        write_progress(&cfg, &stale);
        assert!(request(&cfg, ScanKind::Quick).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_request_file_cannot_cancel_a_scheduled_scan_but_a_requested_scan_replaces_it() {
        let (root, cfg) = sandbox("preempt");
        let (jobs, shared, scanner, telemetry) = service(&cfg);
        // As if the scheduled scan were running.
        jobs.running.store(true, Ordering::SeqCst);
        jobs.scheduled.store(true, Ordering::SeqCst);
        request_cancel(&cfg).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        assert!(
            !jobs.cancel.load(Ordering::SeqCst),
            "a cancel request is ignored"
        );
        assert!(
            fs::read_dir(request_dir(&cfg)).unwrap().next().is_none(),
            "and consumed"
        );
        // Not busy for the user: the request is accepted and stops the scheduled scan.
        write_progress(
            &cfg,
            &ScanProgress {
                kind: ScanKind::Quick,
                running: true,
                started_at: Utc::now(),
                updated_at: Utc::now(),
                files_examined: 1,
                files_scanned: 0,
                findings: 0,
                current: String::new(),
                scheduled: true,
            },
        );
        request(&cfg, ScanKind::Full).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        assert!(jobs.cancel.load(Ordering::SeqCst));
        assert_eq!(*locked(&jobs.waiting), [ScanKind::Full]);
        // Once the scheduled scan has stopped, the user's scan runs.
        jobs.running.store(false, Ordering::SeqCst);
        jobs.scheduled.store(false, Ordering::SeqCst);
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);
        let report = engine::read_scan_report(&cfg, ScanKind::Full).unwrap();
        assert!(report.full && !report.cancelled);
        // Between users' scans a cancel still works.
        jobs.running.store(true, Ordering::SeqCst);
        request_cancel(&cfg).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        assert!(jobs.cancel.load(Ordering::SeqCst));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_scheduled_scan_is_stopped_for_a_user_once_then_user_scans_wait_behind_it() {
        let (root, cfg) = sandbox("once");
        let (jobs, shared, scanner, telemetry) = service(&cfg);
        let scheduled_runs = |jobs: &ScanJobs| {
            jobs.running.store(true, Ordering::SeqCst);
            jobs.scheduled.store(true, Ordering::SeqCst);
            jobs.cancel.store(false, Ordering::SeqCst);
        };
        // First time in this due period: the user's scan stops it and takes its place.
        scheduled_runs(&jobs);
        request(&cfg, ScanKind::Full).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        assert!(jobs.cancel.load(Ordering::SeqCst));
        // The retry cannot be stopped again, however often a user asks: the scans wait.
        scheduled_runs(&jobs);
        for _ in 0..3 {
            request(&cfg, ScanKind::Full).unwrap();
            request(&cfg, ScanKind::Quick).unwrap();
            jobs.poll(&shared, &scanner, &telemetry);
            assert!(!jobs.cancel.load(Ordering::SeqCst), "the retry runs on");
        }
        // Both kinds wait, not only the last one asked for.
        assert_eq!(*locked(&jobs.waiting), [ScanKind::Full, ScanKind::Quick]);
        // A cancel request is not swallowed: it removes what waits, and the schedule goes on.
        request_cancel(&cfg).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        assert!(locked(&jobs.waiting).is_empty() && !jobs.cancel.load(Ordering::SeqCst));
        jobs.running.store(false, Ordering::SeqCst);
        jobs.scheduled.store(false, Ordering::SeqCst);
        jobs.poll(&shared, &scanner, &telemetry);
        assert!(!jobs.is_running(), "nothing was left waiting");

        // Without a cancel, the waiting scans run one after the other once the schedule is done.
        scheduled_runs(&jobs);
        request(&cfg, ScanKind::Full).unwrap();
        request(&cfg, ScanKind::Quick).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        jobs.running.store(false, Ordering::SeqCst);
        jobs.scheduled.store(false, Ordering::SeqCst);
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);
        assert!(engine::read_scan_report(&cfg, ScanKind::Full).is_some());
        assert!(engine::read_scan_report(&cfg, ScanKind::Quick).is_none());
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);
        assert!(engine::read_scan_report(&cfg, ScanKind::Quick).is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stopped_scheduled_run_is_not_a_finished_one_and_leaves_the_last_report() {
        let (root, cfg) = sandbox("stopped");
        let (jobs, _shared, scanner, telemetry) = service(&cfg);
        jobs.run(ScanKind::Scheduled, &cfg, &scanner, &telemetry);
        let complete = engine::read_scan_report(&cfg, ScanKind::Scheduled).unwrap();
        assert!(!complete.cancelled && complete.files_examined == 1);
        assert_eq!(jobs.take_scheduled_outcome(), Some(true));
        // Stopped: not counted as finished, still "stopped once", and the report stays.
        jobs.preempted.store(true, Ordering::SeqCst);
        jobs.cancel();
        jobs.run(ScanKind::Scheduled, &cfg, &scanner, &telemetry);
        assert_eq!(jobs.take_scheduled_outcome(), Some(false));
        assert!(jobs.preempted.load(Ordering::SeqCst));
        assert_eq!(
            engine::read_scan_report(&cfg, ScanKind::Scheduled).unwrap(),
            complete
        );
        assert!(!read_progress(&cfg).unwrap().running);
        // Finished: counted, and the next due period may be stopped once again.
        jobs.cancel.store(false, Ordering::SeqCst);
        jobs.run(ScanKind::Scheduled, &cfg, &scanner, &telemetry);
        assert_eq!(jobs.take_scheduled_outcome(), Some(true));
        assert!(!jobs.preempted.load(Ordering::SeqCst));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn one_scan_runs_at_a_time_and_join_waits_for_the_scan_thread() {
        let (root, cfg) = sandbox("join");
        let (jobs, shared, scanner, telemetry) = service(&cfg);
        // The scheduled scan ends by taking the outcome lock: holding it keeps the thread alive.
        let held = locked(&jobs.outcome);
        assert!(jobs.start(ScanKind::Scheduled, &shared, &scanner, &telemetry));
        assert!(
            !jobs.start(ScanKind::Full, &shared, &scanner, &telemetry),
            "a second scan is refused while one runs"
        );
        assert!(jobs.is_running());
        jobs.cancel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = {
            let jobs = Arc::clone(&jobs);
            thread::spawn(move || {
                jobs.join();
                let _ = done_tx.send(jobs.is_running());
            })
        };
        assert!(
            done_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "join returned while the scan thread was still running"
        );
        drop(held);
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(20)), Ok(false));
        waiter.join().unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_previous_release_still_reads_the_progress_of_a_scheduled_scan() {
        // The struct as shipped in v0.4.1 (`git show v0.4.1:crates/the-nex-core/src/scan_jobs.rs`).
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum OldKind {
            Quick,
            Full,
        }
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct OldProgress {
            kind: OldKind,
            running: bool,
            started_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
            files_examined: u64,
            files_scanned: u64,
            findings: u64,
            current: String,
        }
        let (root, cfg) = sandbox("oldprogress");
        let (jobs, _shared, scanner, telemetry) = service(&cfg);
        let report = engine::run_scan(
            &cfg,
            &scanner,
            &telemetry,
            ScanKind::Scheduled,
            &mut |r, d| {
                write_progress(
                    &cfg,
                    &ScanProgress {
                        kind: ScanKind::Quick,
                        running: true,
                        started_at: Utc::now(),
                        updated_at: Utc::now(),
                        files_examined: r.files_examined,
                        files_scanned: 0,
                        findings: 0,
                        current: d.display().to_string(),
                        scheduled: true,
                    },
                );
                true
            },
        );
        assert_eq!(report.files_examined, 1);
        // The real writer, through `run` itself.
        jobs.run(ScanKind::Scheduled, &cfg, &scanner, &telemetry);
        let json = fs::read(cfg.log_dir.join(SCAN_PROGRESS_FILE)).unwrap();
        let old: OldProgress = serde_json::from_slice(&json).unwrap();
        assert!(matches!(old.kind, OldKind::Quick) && !old.running);
        assert!(read_progress(&cfg).unwrap().scheduled);
        assert!(!matches!(old.kind, OldKind::Full));
        // And a file from the previous release still reads here.
        let mut value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        value.as_object_mut().unwrap().remove("scheduled");
        assert!(
            !serde_json::from_value::<ScanProgress>(value)
                .unwrap()
                .scheduled
        );
        assert_eq!(*locked(&jobs.outcome), Some(true));
        let _ = fs::remove_dir_all(&root);
    }
}
