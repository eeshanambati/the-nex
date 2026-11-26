use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use the_nex_core::allowlist::{self, AllowedFile};
use the_nex_core::bin_ai::BinaryAiScanner;
use the_nex_core::config::{self, AppConfig, CliArgs, Mode, RuntimeToggles};
use the_nex_core::engine;
use the_nex_core::quarantine::{self, QuarantineMeta, Severity, ThreatEvent};
use the_nex_core::skiplist;
use the_nex_core::{canary, logger, notifier, platform};

fn main() -> ExitCode {
    let args = match config::parse_args(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", config::USAGE);
            return ExitCode::from(2);
        }
    };
    let shutdown = Arc::new(AtomicBool::new(false));

    match &args.mode {
        Mode::Help => {
            println!("{}", config::USAGE);
            ExitCode::SUCCESS
        }
        Mode::Install => report(platform::install_service(args.fresh_data)),
        Mode::Uninstall => report(platform::uninstall_service()),
        Mode::Restore(id) => restore(id, &args),
        Mode::Delete(id) => delete(id, &args),
        Mode::Allow(sha256) => allow(sha256, &args),
        Mode::AllowEvent(id) => allow_event(id, &args),
        Mode::Disallow(sha256) => disallow(sha256, &args),
        Mode::AllowQuarantined(id) => allow_quarantined(id, &args),
        Mode::ListAllowed => list_allowed(&args),
        Mode::NeverScan(path, folder) => changed(
            skiplist::add(&cli_config(&args), path, *folder),
            ["Added", "Already listed"],
        ),
        Mode::ScanAgain(path) => changed(
            skiplist::remove(&cli_config(&args), path),
            ["Removed", "Not listed"],
        ),
        Mode::ListNeverScan => list_never_scan(&args),
        Mode::Set(engine, enabled) => update_settings(&args, |t| t.set(*engine, *enabled)),
        Mode::SetSchedule(schedule) => update_settings(&args, |t| t.scan_schedule = *schedule),
        Mode::QuickScan => scan(&args, engine::ScanKind::Quick),
        Mode::FullScan => scan(&args, engine::ScanKind::Full),
        Mode::RearmCanaries => rearm_canaries(&args),
        Mode::ScanFile(target) => scan_file(target, &args),
        Mode::CheckFile(target) => check_file(target, &args),
        Mode::ListStartup => list_startup(&args),
        Mode::Notifier => {
            platform::detach_console();
            logger::init_without_file(false);
            let cfg = AppConfig::from_cli_in_session(&args);
            notifier::run_notifier(&cfg, shutdown);
            ExitCode::SUCCESS
        }
        Mode::Tray => {
            platform::detach_console();
            logger::init_without_file(false);
            report(
                platform::run_tray(AppConfig::from_cli_in_session(&args)).map(|()| String::new()),
            )
        }
        Mode::Console => {
            platform::install_ctrlc_handler(Arc::clone(&shutdown));
            let cfg = AppConfig::from_cli(&args);
            engine::run(cfg, shutdown);
            ExitCode::SUCCESS
        }
        Mode::Service => {
            let cfg = AppConfig::from_cli(&args);
            logger::init(&cfg.log_dir, false);
            match platform::run_service(shutdown, cfg) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    logger::error(&e);
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn report(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(message) => {
            if !message.is_empty() {
                println!("{message}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cli_config(args: &CliArgs) -> AppConfig {
    let cfg = AppConfig::from_cli(args);
    logger::init(&cfg.log_dir, true);
    cfg
}

fn restore(id: &str, args: &CliArgs) -> ExitCode {
    let cfg = cli_config(args);
    restored(id, quarantine::restore_file(id, &cfg), &cfg)
}

fn restored(id: &str, result: std::io::Result<QuarantineMeta>, cfg: &AppConfig) -> ExitCode {
    match result {
        Ok(meta) => {
            quarantine::record_restore(cfg, &meta, "");
            println!("Restored {} to {}", meta.id, meta.original_path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: restoring {id} failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A config that knows the known-malware list, so a listed hash can never be allowed. If the
/// list is on this build but cannot be verified, nothing is changed.
fn allow_config(args: &CliArgs) -> Result<AppConfig, String> {
    let mut cfg = cli_config(args);
    cfg.load_known_bad()?;
    Ok(cfg)
}

fn allow(sha256: &str, args: &CliArgs) -> ExitCode {
    let result = AllowedFile::new(
        sha256,
        args.allow_name.as_deref().unwrap_or("unnamed"),
        args.allow_type.as_deref().unwrap_or("MANUAL"),
    )
    .and_then(|entry| {
        let cfg = allow_config(args)?;
        allowlist::add(&cfg, entry).map_err(|e| e.to_string())
    });
    match result {
        Ok(added) => {
            println!("{}", if added { "Added" } else { "Already listed" });
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot allow {sha256}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The hash comes from this engine's own event log, never from the caller: when the desktop
/// app asks for this through the administrator prompt, a user-level program cannot choose it.
fn allow_event(id: &str, args: &CliArgs) -> ExitCode {
    let result = allow_config(args).and_then(|cfg| {
        let event = allowlist::event_by_id(&cfg, id).map_err(|e| e.to_string())?;
        let entry = AllowedFile::from_event(&event)?;
        allowlist::check_expected(&entry.sha256, args.expect.as_deref())?;
        let added = allowlist::add(&cfg, entry).map_err(|e| e.to_string())?;
        let note = event
            .quarantine_id()
            .filter(|q| quarantine::load_meta(q, &cfg).is_ok())
            .map(allowlist::still_quarantined_note);
        Ok((added, note))
    });
    match result {
        Ok((added, note)) => {
            println!("{}", if added { "Added" } else { "Already listed" });
            if let Some(note) = note {
                println!("{note}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot allow event {id}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn disallow(sha256: &str, args: &CliArgs) -> ExitCode {
    match allowlist::remove(&cli_config(args), sha256) {
        Ok(removed) => {
            println!("{}", if removed { "Removed" } else { "Not listed" });
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot remove {sha256}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn allow_quarantined(id: &str, args: &CliArgs) -> ExitCode {
    match allow_config(args) {
        Ok(cfg) => restored(
            id,
            allowlist::allow_and_restore(id, &cfg, args.expect.as_deref()),
            &cfg,
        ),
        Err(e) => {
            eprintln!("error: cannot allow {id}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn list_allowed(args: &CliArgs) -> ExitCode {
    let cfg = AppConfig::from_cli(args);
    match allowlist::load(&cfg.allowed_file, config::running_privileged()) {
        Ok(entries) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Prints the first word when the never-scan list changed, the second when it did not have to.
fn changed(result: std::io::Result<bool>, [done, already]: [&str; 2]) -> ExitCode {
    report(
        result
            .map(|changed| if changed { done } else { already }.to_string())
            .map_err(|e| e.to_string()),
    )
}

fn list_never_scan(args: &CliArgs) -> ExitCode {
    let cfg = AppConfig::from_cli(args);
    report(
        skiplist::load(&cfg.skipped_file, config::running_privileged())
            .map(|places| serde_json::to_string_pretty(&places).unwrap_or_default())
            .map_err(String::from),
    )
}

fn delete(id: &str, args: &CliArgs) -> ExitCode {
    let cfg = cli_config(args);
    match quarantine::delete_quarantined_file(id, &cfg) {
        Ok(meta) => {
            quarantine::record_event(
                &cfg,
                ThreatEvent::new(
                    "QUARANTINE_DELETE",
                    Severity::Low,
                    meta.original_path.display().to_string(),
                    "DELETED",
                    format!("id={} sha256={}", meta.id, meta.sha256),
                ),
            );
            println!("Deleted {} ({})", meta.id, meta.original_path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: deleting {id} failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn update_settings(args: &CliArgs, change: impl FnOnce(&mut RuntimeToggles)) -> ExitCode {
    let cfg = AppConfig::from_cli(args);
    let mut toggles = match RuntimeToggles::load(&cfg.settings_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {}: {e}", cfg.settings_file.display());
            return ExitCode::FAILURE;
        }
    };
    change(&mut toggles);
    match toggles.save(&cfg.settings_file) {
        Ok(()) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&toggles).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot write {}: {e}", cfg.settings_file.display());
            ExitCode::FAILURE
        }
    }
}

fn scan(args: &CliArgs, kind: engine::ScanKind) -> ExitCode {
    let mut cfg = cli_config(args);
    if let Err(e) = cfg.ensure_dirs() {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    engine::load_known_bad(&mut cfg);
    let scanner = BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes);
    let telemetry = the_nex_core::status::Telemetry::default();
    let result = engine::run_scan(&cfg, &scanner, &telemetry, kind, &mut |_, _| true);
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
    ExitCode::SUCCESS
}

/// `--scan-file`: a file, every file directly inside a folder, or `@list` (one path per line).
fn scan_targets(target: &Path) -> Result<Vec<PathBuf>, String> {
    let text = target.to_string_lossy();
    if let Some(list) = text.strip_prefix('@') {
        let content = fs::read_to_string(list).map_err(|e| format!("{list}: {e}"))?;
        return Ok(content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(PathBuf::from)
            .collect());
    }
    if target.is_dir() {
        let entries = fs::read_dir(target).map_err(|e| format!("{}: {e}", target.display()))?;
        let mut files: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        return Ok(files);
    }
    if target.is_file() {
        Ok(vec![target.to_path_buf()])
    } else {
        Err(format!("{} does not exist", target.display()))
    }
}

/// Read-only: scores each binary with the AI engine and prints one JSON object per line with
/// the verdict, the reasons behind it and the raw features. Nothing is quarantined or logged.
fn scan_file(target: &Path, args: &CliArgs) -> ExitCode {
    logger::init_without_file(true);
    let cfg = AppConfig::from_cli(args);
    let paths = match scan_targets(target) {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let scanner = BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes);
    let mut flagged = 0usize;
    for path in &paths {
        let line = match scanner.assess(path) {
            Some(assessment) => {
                let malicious = assessment.score >= cfg.ai_threshold;
                flagged += usize::from(malicious);
                let verdict = if malicious { "malicious" } else { "clean" };
                serde_json::json!({
                    "path": path.display().to_string(),
                    "verdict": verdict,
                    "score": assessment.score,
                    "threshold": cfg.ai_threshold,
                    "engine": assessment.engine,
                    "heuristic": assessment.heuristic,
                    "trusted": platform::is_trusted_binary(path),
                    "reasons": assessment.reasons,
                    "features": assessment.features,
                    "profile": assessment.profile,
                })
            }
            None => serde_json::json!({
                "path": path.display().to_string(),
                "verdict": "not_scored",
                "error": "not a readable PE or Mach-O executable within the size limit",
            }),
        };
        println!("{line}");
    }
    eprintln!(
        "{} file(s) checked, {flagged} at or above the {:.2} threshold (engine: {})",
        paths.len(),
        cfg.ai_threshold,
        scanner.engine_name()
    );
    ExitCode::SUCCESS
}

/// Read-only: one JSON line for one file (see the_nex_core::check_file). Never logs an event.
fn check_file(target: &Path, args: &CliArgs) -> ExitCode {
    logger::init_without_file(false);
    let mut cfg = AppConfig::from_cli(args);
    if let Err(e) = cfg.load_known_bad() {
        // The check still runs; it just has no list to compare against.
        eprintln!("known-malware list not used: {e}");
    }
    let scanner = BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes);
    let result = the_nex_core::check_file::check(&cfg, &scanner, target);
    println!("{}", serde_json::to_string(&result).unwrap_or_default());
    ExitCode::SUCCESS
}

/// Read-only: one JSON document of everything that starts by itself, each item judged. Never
/// logs an event (see the_nex_core::startup).
fn list_startup(args: &CliArgs) -> ExitCode {
    logger::init_without_file(false);
    let mut cfg = AppConfig::from_cli(args);
    if let Err(e) = cfg.load_known_bad() {
        eprintln!("known-malware list not used: {e}");
    }
    let scanner = BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes);
    let report = the_nex_core::startup::list(
        &Arc::new(cfg),
        &Arc::new(scanner),
        args.startup_dir.as_deref(),
        the_nex_core::startup::Limits::default(),
    );
    println!("{}", serde_json::to_string(&report).unwrap_or_default());
    ExitCode::SUCCESS
}

fn rearm_canaries(args: &CliArgs) -> ExitCode {
    let cfg = cli_config(args);
    let states = canary::rearm_canaries(&engine::canary_dirs(&cfg));
    println!(
        "{}",
        serde_json::to_string_pretty(&states).unwrap_or_default()
    );
    if states.iter().all(|s| s.is_intact()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
