use crate::allowlist;
use crate::config::{AppConfig, ZipLimits};
use crate::quarantine::{self, Severity, ThreatEvent};
use std::fs::{self, File};
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
use zip::{CompressionMethod, ZipArchive};

const IGNORED_EXTENSIONS: &[&str] = &[
    "crdownload",
    "part",
    "partial",
    "download",
    "opdownload",
    "tmp",
    "quarantined",
];
const READY_POLL: Duration = Duration::from_millis(150);
const READY_MAX_RETRIES: u32 = 5;
const READY_STABLE_CHECKS: u32 = 2;

const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const CDFH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const MAX_EOCD_SEARCH: u64 = 22 + u16::MAX as u64;
const MAX_CD_BYTES: u64 = 64 * 1024 * 1024;
/// Real datasets reach ~1.3M entries (ImageNet); the 64 MiB central-directory cap bounds the rest.
const MAX_ENTRIES: u64 = 10_000_000;
/// Local-header walk cap: no directory bounds it, so allow what a maximal directory could hold
/// (46 B is the smallest central-directory entry).
const LFH_MAX_ENTRIES: u64 = MAX_CD_BYTES / 46;
/// How far before the EOCD to look for a displaced central directory.
const SCAN_WINDOW: u64 = 1024 * 1024;
/// Real decompression done to verify declared sizes, per top-level archive.
const SAMPLE_BUDGET: u64 = 64 * 1024 * 1024;
/// Nested archives read into memory, cumulative per top-level archive.
const NESTED_BUDGET: u64 = 256 * 1024 * 1024;
/// Past this the optional decompression work stops and the scan fails open.
const TIME_BUDGET: Duration = Duration::from_secs(10);
/// For the zip library to find a directory our own parser could not.
const OPEN_BUDGET: Duration = Duration::from_secs(2);
const NESTED_EXTENSIONS: &[&str] = &["zip", "jar", "war", "apk", "xpi"];
/// A Java program bundles its libraries as jars, which bundle theirs: that many levels more than
/// the limit, as long as the deepest ones are jars. Size and ratio are checked all the way down.
const JAR_EXTRA_DEPTH: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipThreatKind {
    CompressionRatio,
    UncompressedSize,
    OverlappingEntries,
    NestingDepth,
    NestedSizeMismatch,
    /// More entries than any real archive carries (Zip64 counts included).
    EntryCount,
    /// Local header and central directory disagree about method or sizes.
    HeaderMismatch,
    /// Carries an end-of-central-directory record but no parser can make sense of it.
    Malformed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ZipThreat {
    pub kind: ZipThreatKind,
    pub depth: u32,
    pub entries: usize,
    pub total_compressed: u64,
    pub total_uncompressed: u64,
    pub detail: String,
}

impl ZipThreat {
    pub fn summary(&self) -> String {
        format!(
            "{:?} at depth {}: {} (entries={}, compressed={} B, uncompressed={} B)",
            self.kind,
            self.depth,
            self.detail,
            self.entries,
            self.total_compressed,
            self.total_uncompressed
        )
    }
}

pub fn is_ignored_extension(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|ext| IGNORED_EXTENSIONS.contains(&ext.as_str()))
}

/// Opens a regular file without blocking on FIFOs or following symlinks.
fn open_regular(path: &Path) -> std::io::Result<File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(file)
}

/// Neither written nor changed for this long (a change time cannot be set back on Unix).
fn quiet_for(meta: &fs::Metadata, time: Duration) -> bool {
    let modified = meta.modified().ok();
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        let since_epoch = Duration::new(
            u64::try_from(meta.ctime()).unwrap_or(0),
            u32::try_from(meta.ctime_nsec()).unwrap_or(0),
        );
        Some(std::time::UNIX_EPOCH + since_epoch)
    };
    #[cfg(not(unix))]
    let changed = modified;
    [modified, changed]
        .iter()
        .all(|t| t.is_some_and(|t| t.elapsed().is_ok_and(|age| age >= time)))
}

/// True once the size is unchanged across two consecutive 150 ms checks and the file opens; at
/// once for a file nobody has touched for that long.
pub fn wait_for_file_ready(path: &Path) -> bool {
    if is_ignored_extension(path) {
        return false;
    }
    let mut previous = match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => {
            // Nothing wrote it lately: no need to hold up the files behind it. A later write
            // queues it again.
            // Not on Windows: there a file's times may lag until its writer closes it.
            if cfg!(unix)
                && quiet_for(&m, READY_POLL * READY_STABLE_CHECKS)
                && open_regular(path).is_ok()
            {
                return true;
            }
            m.len()
        }
        _ => return false,
    };
    let mut stable = 0;
    for _ in 0..(READY_STABLE_CHECKS + READY_MAX_RETRIES) {
        thread::sleep(READY_POLL);
        let current = match fs::symlink_metadata(path) {
            Ok(m) if m.is_file() => m.len(),
            _ => return false,
        };
        if current == previous {
            stable += 1;
            if stable >= READY_STABLE_CHECKS && open_regular(path).is_ok() {
                return true;
            }
        } else {
            stable = 0;
            previous = current;
        }
    }
    false
}

/// Reads the central directory, local headers and (bounded, in-memory) nested archives; never
/// extracts to disk. Work is bounded by byte and time budgets, and failures fail open.
pub fn inspect_zip_file(path: &Path, cfg: &AppConfig) -> Option<ZipThreat> {
    inspect_zip_file_checked(path, cfg).0
}

/// Like [`inspect_zip_file`], and also says whether a time, sample or nesting budget ran out
/// before everything was verified (then "no threat" only means none was found in what was read).
pub fn inspect_zip_file_checked(path: &Path, cfg: &AppConfig) -> (Option<ZipThreat>, bool) {
    let Ok(file) = open_regular(path) else {
        return (None, true);
    };
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return (None, true);
    };
    // Small buffer: every header probe seeks, and a seek throws the buffer away.
    inspect_root(BufReader::with_capacity(4096, file), len, &cfg.zip_limits)
}

pub fn inspect_zip_bytes(bytes: &[u8], limits: &ZipLimits) -> Option<ZipThreat> {
    inspect_root(Cursor::new(bytes), bytes.len() as u64, limits).0
}

fn inspect_root<R: Read + Seek>(
    reader: R,
    len: u64,
    limits: &ZipLimits,
) -> (Option<ZipThreat>, bool) {
    let mut scan = Scan {
        cumulative: 0,
        root_len: len.max(1),
        sample_left: SAMPLE_BUDGET,
        nested_left: NESTED_BUDGET,
        deadline: Instant::now() + TIME_BUDGET,
        incomplete: false,
    };
    let threat = inspect_level(reader, 1, false, limits, &mut scan);
    let late = Instant::now() > scan.deadline;
    (threat, scan.incomplete || late)
}

/// Per-top-level-archive work budgets shared by every nesting level.
struct Scan {
    /// Declared uncompressed bytes summed over all levels.
    cumulative: u64,
    root_len: u64,
    sample_left: u64,
    nested_left: u64,
    deadline: Instant,
    /// A budget cut some verification short.
    incomplete: bool,
}

/// One central-directory entry plus what its local header says.
struct Rec {
    cd_index: usize,
    method: u16,
    compressed: u64,
    uncompressed: u64,
    /// Local header start .. end of compressed data, absolute in the file.
    extent: Option<(u64, u64)>,
    nested: bool,
    jar: bool,
    mismatch: Option<String>,
    /// The entry needs a password: its content cannot be read.
    encrypted: bool,
}

enum Raw {
    TooMany(u64),
    Recs(Vec<Rec>),
    /// `eocd`: an end-of-central-directory record was found even though the walk failed.
    Unparsable {
        eocd: bool,
    },
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        buf.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        buf.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(buf: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        buf.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn read_at<R: Read + Seek>(reader: &mut R, at: u64, len: usize) -> Option<Vec<u8>> {
    reader.seek(SeekFrom::Start(at)).ok()?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn is_nested_name(name: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(name).to_ascii_lowercase();
    NESTED_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
}

fn is_jar_name(name: &[u8]) -> bool {
    name.to_ascii_lowercase().ends_with(b".jar")
}

struct Pending {
    rec: Rec,
    local: u64,
    raw_sizes: (u32, u32),
}

/// Applies a Zip64 extra field (id 1) to whichever of the three fields hold the 0xFFFFFFFF marker.
fn apply_zip64(extra: &[u8], mut fields: [(u32, &mut u64); 3]) {
    let mut e = 0usize;
    while let (Some(id), Some(size)) = (u16_at(extra, e), u16_at(extra, e + 2)) {
        let body = e + 4;
        if id == 1 {
            let mut at = body;
            for (wanted, slot) in fields.iter_mut() {
                if *wanted == 0xFFFF_FFFF {
                    if let Some(v) = u64_at(extra, at) {
                        **slot = v;
                    }
                    at += 8;
                }
            }
        }
        e = body.saturating_add(size as usize);
    }
}

/// One central-directory record at `pos`, plus the offset of the next one.
fn parse_cdfh(cd: &[u8], pos: usize, index: usize) -> Option<(Pending, usize)> {
    if cd.get(pos..pos.checked_add(4)?) != Some(&CDFH_SIG[..]) {
        return None;
    }
    let encrypted = u16_at(cd, pos + 8)? & 1 != 0;
    let method = u16_at(cd, pos + 10)?;
    let comp32 = u32_at(cd, pos + 20)?;
    let unc32 = u32_at(cd, pos + 24)?;
    let name_len = u16_at(cd, pos + 28)? as usize;
    let extra_len = u16_at(cd, pos + 30)? as usize;
    let comment_len = u16_at(cd, pos + 32)? as usize;
    let off32 = u32_at(cd, pos + 42)?;
    let name_at = pos + 46;
    let extra_at = name_at.checked_add(name_len)?;
    let next = extra_at.checked_add(extra_len)?.checked_add(comment_len)?;
    let name = cd.get(name_at..extra_at)?;
    let extra = cd.get(extra_at..extra_at.checked_add(extra_len)?)?;
    let (mut compressed, mut uncompressed, mut local) = (comp32 as u64, unc32 as u64, off32 as u64);
    apply_zip64(
        extra,
        [
            (unc32, &mut uncompressed),
            (comp32, &mut compressed),
            (off32, &mut local),
        ],
    );
    let rec = Rec {
        cd_index: index,
        method,
        compressed,
        uncompressed,
        extent: None,
        nested: !name.ends_with(b"/") && is_nested_name(name),
        jar: is_jar_name(name),
        mismatch: None,
        encrypted,
    };
    Some((
        Pending {
            rec,
            local,
            raw_sizes: (comp32, unc32),
        },
        next,
    ))
}

/// Reads the central directory assuming archive offsets are shifted by `base`; succeeds only
/// when it yields every declared entry.
fn read_cd<R: Read + Seek>(
    reader: &mut R,
    base: u64,
    cd_offset: u64,
    cd_size: u64,
    entries: u64,
) -> Option<Vec<Pending>> {
    let cd = read_at(reader, base.checked_add(cd_offset)?, cd_size as usize)?;
    let mut pending: Vec<Pending> = Vec::with_capacity((entries as usize).min(4096));
    let mut pos = 0usize;
    while (pending.len() as u64) < entries {
        let (p, next) = parse_cdfh(&cd, pos, pending.len())?;
        pending.push(p);
        pos = next;
    }
    Some(pending)
}

/// Last EOCD in the tail: (tail bytes, index in tail, absolute offset).
fn locate_eocd<R: Read + Seek>(reader: &mut R, len: u64) -> Option<(Vec<u8>, usize, u64)> {
    let tail_len = len.min(MAX_EOCD_SEARCH);
    let tail_start = len - tail_len;
    let tail = read_at(reader, tail_start, tail_len as usize)?;
    let eocd = (0..=tail.len().checked_sub(22)?).rev().find(|&i| {
        tail.get(i..i + 4) == Some(&EOCD_SIG[..])
            && u16_at(&tail, i + 20).is_some_and(|c| i + 22 + c as usize <= tail.len())
    })?;
    Some((tail, eocd, tail_start + eocd as u64))
}

/// Own central-directory walk (Zip64 aware, stub/junk aware). `Unparsable` lets the caller fall
/// back; `eocd` says whether an end-of-central-directory record was seen at all.
fn raw_parse<R: Read + Seek>(reader: &mut R, len: u64, deadline: Instant) -> Raw {
    let Some((tail, eocd, eocd_abs)) = locate_eocd(reader, len) else {
        return Raw::Unparsable { eocd: false };
    };
    raw_parse_inner(reader, &tail, eocd, eocd_abs, deadline)
        .unwrap_or(Raw::Unparsable { eocd: true })
}

fn raw_parse_inner<R: Read + Seek>(
    reader: &mut R,
    tail: &[u8],
    eocd: usize,
    eocd_abs: u64,
    deadline: Instant,
) -> Option<Raw> {
    // Split archive (spanned or the last segment of .z01/.zip): the directory is not all here,
    // so this is not a malformed archive. Let the caller fall back without an EOCD verdict.
    if u16_at(tail, eocd + 4)? != 0 || u16_at(tail, eocd + 6)? != 0 {
        return Some(Raw::Unparsable { eocd: false });
    }
    let mut entries = u16_at(tail, eocd + 10)? as u64;
    let mut cd_size = u32_at(tail, eocd + 12)? as u64;
    let mut cd_offset = u32_at(tail, eocd + 16)? as u64;
    let mut cd_end = eocd_abs;

    let zip64_marker = entries == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF;
    if zip64_marker {
        if let Some(locator) = eocd_abs
            .checked_sub(20)
            .and_then(|at| read_at(reader, at, 20))
        {
            if u32_at(&locator, 0)? == 0x0706_4b50 {
                let stated = u64_at(&locator, 8)?;
                let guess = eocd_abs.checked_sub(20 + 56);
                let record = [Some(stated), guess].into_iter().flatten().find_map(|at| {
                    let rec = read_at(reader, at, 56)?;
                    (u32_at(&rec, 0)? == 0x0606_4b50).then_some((at, rec))
                });
                let (at, rec) = record?;
                entries = u64_at(&rec, 32)?;
                cd_size = u64_at(&rec, 40)?;
                cd_offset = u64_at(&rec, 48)?;
                cd_end = at;
            }
        }
    }
    if entries > MAX_ENTRIES {
        return Some(Raw::TooMany(entries));
    }
    if cd_size > MAX_CD_BYTES {
        return None;
    }
    // Bytes in front of the archive (self-extractor stub) shift every stored offset; bytes
    // between the directory and the EOCD (junk) break the arithmetic, so also try no shift and
    // then every central-directory signature found just before the EOCD.
    let mut found = cd_end
        .checked_sub(cd_size)
        .and_then(|v| v.checked_sub(cd_offset))
        .and_then(|base| Some((base, read_cd(reader, base, cd_offset, cd_size, entries)?)))
        .or_else(|| Some((0, read_cd(reader, 0, cd_offset, cd_size, entries)?)));
    if found.is_none() {
        let from = cd_end.saturating_sub(cd_size + SCAN_WINDOW).max(cd_offset);
        let window = read_at(reader, from, (cd_end.checked_sub(from)?) as usize)?;
        let starts = window
            .windows(4)
            .enumerate()
            .filter(|(_, w)| *w == CDFH_SIG)
            .map(|(i, _)| from + i as u64)
            .take(8);
        for start in starts {
            let base = start - cd_offset;
            if let Some(p) = read_cd(
                reader,
                base,
                cd_offset,
                cd_size.min(cd_end - start),
                entries,
            ) {
                found = Some((base, p));
                break;
            }
        }
    }
    let (base, mut pending) = found?;

    // Visit local headers in file order so the reads stay sequential. Past the deadline the
    // remaining entries keep no extent; the verdict from what was read still stands.
    let mut order: Vec<usize> = (0..pending.len()).collect();
    order.sort_unstable_by_key(|&i| pending[i].local);
    for i in order {
        if Instant::now() > deadline {
            break;
        }
        let p = &mut pending[i];
        let Some(start) = base.checked_add(p.local) else {
            continue;
        };
        let mut h = [0u8; 30];
        if !read_exact_at(reader, start, &mut h) || h[..4] != LFH_SIG {
            continue;
        }
        let (Some(flags), Some(method), Some(lc), Some(lu), Some(n), Some(x)) = (
            u16_at(&h, 6),
            u16_at(&h, 8),
            u32_at(&h, 18),
            u32_at(&h, 22),
            u16_at(&h, 26),
            u16_at(&h, 28),
        ) else {
            continue;
        };
        let data = start.saturating_add(30 + n as u64 + x as u64);
        p.rec.extent = Some((start, data.saturating_add(p.rec.compressed)));
        if method != p.rec.method {
            p.rec.mismatch = Some(format!(
                "local header method {method} differs from central directory method {}",
                p.rec.method
            ));
        } else if flags & 8 == 0
            && (lc, lu) != (0, 0)
            && lc != 0xFFFF_FFFF
            && lu != 0xFFFF_FFFF
            && p.raw_sizes.0 != 0xFFFF_FFFF
            && p.raw_sizes.1 != 0xFFFF_FFFF
            && (lc, lu) != p.raw_sizes
        {
            p.rec.mismatch = Some(format!(
                "local header sizes {lc}/{lu} differ from central directory {}/{}",
                p.raw_sizes.0, p.raw_sizes.1
            ));
        }
    }
    Some(Raw::Recs(pending.into_iter().map(|p| p.rec).collect()))
}

fn read_exact_at<R: Read + Seek>(reader: &mut R, at: u64, buf: &mut [u8]) -> bool {
    reader.seek(SeekFrom::Start(at)).is_ok() && reader.read_exact(buf).is_ok()
}

/// Walks local headers from offset 0 the way a streaming extractor would, ignoring the central
/// directory entirely. Stops at the first non-header, truncated entry or streamed (descriptor)
/// entry whose size is unknown.
/// The flag is true when `cap` entries were collected and more headers may follow.
fn lfh_walk<R: Read + Seek>(
    reader: &mut R,
    len: u64,
    deadline: Instant,
    cap: u64,
) -> (Vec<Rec>, bool) {
    let mut recs = Vec::new();
    let mut pos = 0u64;
    while Instant::now() <= deadline {
        let mut h = [0u8; 30];
        if !read_exact_at(reader, pos, &mut h) || h[..4] != LFH_SIG {
            break;
        }
        let (Some(flags), Some(method), Some(c32), Some(u32v), Some(n), Some(x)) = (
            u16_at(&h, 6),
            u16_at(&h, 8),
            u32_at(&h, 18),
            u32_at(&h, 22),
            u16_at(&h, 26),
            u16_at(&h, 28),
        ) else {
            break;
        };
        if flags & 8 != 0 && c32 == 0 {
            break;
        }
        let (mut compressed, mut uncompressed) = (c32 as u64, u32v as u64);
        let data = pos + 30 + n as u64 + x as u64;
        if c32 == 0xFFFF_FFFF || u32v == 0xFFFF_FFFF {
            let Some(extra) = read_at(reader, pos + 30 + n as u64, x as usize) else {
                break;
            };
            apply_zip64(
                &extra,
                [
                    (u32v, &mut uncompressed),
                    (c32, &mut compressed),
                    (0, &mut 0),
                ],
            );
        }
        let end = data.saturating_add(compressed);
        if end > len {
            break;
        }
        if recs.len() as u64 >= cap {
            return (recs, true);
        }
        recs.push(Rec {
            cd_index: recs.len(),
            method,
            compressed,
            uncompressed,
            extent: Some((pos, end)),
            nested: false,
            jar: false,
            mismatch: None,
            encrypted: flags & 1 != 0,
        });
        pos = end;
    }
    (recs, false)
}

/// Fallback record list straight from the zip crate for archives the raw walk cannot parse.
fn crate_recs<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Vec<Rec> {
    let mut recs = Vec::with_capacity(archive.len().min(4096));
    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index_raw(index) else {
            continue;
        };
        let start = entry.data_start();
        recs.push(Rec {
            cd_index: index,
            method: if entry.compression() == CompressionMethod::Stored {
                0
            } else {
                8
            },
            compressed: entry.compressed_size(),
            uncompressed: entry.size(),
            extent: Some((
                entry.header_start(),
                start.saturating_add(entry.compressed_size()),
            )),
            nested: !entry.is_dir() && is_nested_name(entry.name_raw()),
            jar: is_jar_name(entry.name_raw()),
            mismatch: None,
            encrypted: entry.encrypted(),
        });
    }
    recs
}

/// Counts bytes an entry really yields, up to `cap`, without keeping them.
fn read_up_to(mut reader: impl Read, cap: u64) -> u64 {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    while total < cap {
        let want = (cap - total).min(buf.len() as u64) as usize;
        match reader.read(&mut buf[..want]) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n as u64,
        }
    }
    total
}

/// Fails once the time is up. The zip library looks for a directory without any limit of its own:
/// a small file of repeated end records keeps it busy for minutes.
struct Timed<R> {
    inner: R,
    deadline: Instant,
}

impl<R> Timed<R> {
    fn check(&self) -> io::Result<()> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "out of time"));
        }
        Ok(())
    }
}

impl<R: Read> Read for Timed<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        self.inner.read(buf)
    }
}

impl<R: Seek> Seek for Timed<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.check()?;
        self.inner.seek(to)
    }
}

fn inspect_level<R: Read + Seek>(
    mut reader: R,
    depth: u32,
    jar: bool,
    limits: &ZipLimits,
    scan: &mut Scan,
) -> Option<ZipThreat> {
    let len = reader.seek(SeekFrom::End(0)).ok()?;
    let raw = raw_parse(&mut reader, len, scan.deadline);
    let mut archive = None;
    let recs = match raw {
        Raw::TooMany(entries) => {
            return Some(ZipThreat {
                kind: ZipThreatKind::EntryCount,
                depth,
                entries: usize::try_from(entries).unwrap_or(usize::MAX),
                total_compressed: 0,
                total_uncompressed: 0,
                detail: format!("{entries} declared entries exceeds the limit of {MAX_ENTRIES}"),
            });
        }
        Raw::Recs(recs) => recs,
        Raw::Unparsable { eocd } => {
            let deadline = scan.deadline.min(Instant::now() + OPEN_BUDGET);
            let opens = ZipArchive::new(Timed {
                inner: &mut reader,
                deadline,
            })
            .is_ok();
            // Not found in time is not the same as not there.
            let timed_out = !opens && Instant::now() > deadline;
            scan.incomplete |= timed_out;
            if opens {
                // Reopened because the failure branch below needs `reader` back.
                let mut a = ZipArchive::new(Timed {
                    inner: &mut reader,
                    deadline: scan.deadline,
                })
                .map_err(|_| scan.incomplete = true)
                .ok()?;
                let recs = crate_recs(&mut a);
                archive = Some(a);
                recs
            } else {
                // Streaming extractors ignore the directory, so judge what the headers say.
                let (recs, truncated) = lfh_walk(&mut reader, len, scan.deadline, LFH_MAX_ENTRIES);
                if truncated {
                    return Some(ZipThreat {
                        kind: ZipThreatKind::EntryCount,
                        depth,
                        entries: recs.len(),
                        total_compressed: 0,
                        total_uncompressed: 0,
                        detail: format!(
                            "more than {LFH_MAX_ENTRIES} local headers without a usable directory"
                        ),
                    });
                }
                if recs.is_empty() {
                    return (eocd && !timed_out).then(|| ZipThreat {
                        kind: ZipThreatKind::Malformed,
                        depth,
                        entries: 0,
                        total_compressed: 0,
                        total_uncompressed: 0,
                        detail: "carries a central directory record but cannot be parsed"
                            .to_string(),
                    });
                }
                recs
            }
        }
    };
    let entries = recs.len();
    let max_depth = limits.max_depth + if jar { JAR_EXTRA_DEPTH } else { 0 };
    if depth > max_depth {
        return Some(ZipThreat {
            kind: ZipThreatKind::NestingDepth,
            depth,
            entries,
            total_compressed: 0,
            total_uncompressed: 0,
            detail: format!("archive nested {depth} levels deep exceeds the limit of {max_depth}"),
        });
    }

    let total_compressed = recs
        .iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.compressed));
    let total_uncompressed = recs
        .iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.uncompressed));
    scan.cumulative = scan.cumulative.saturating_add(total_uncompressed);
    let threat = |kind: ZipThreatKind, detail: String| {
        Some(ZipThreat {
            kind,
            depth,
            entries,
            total_compressed,
            total_uncompressed,
            detail,
        })
    };

    if total_uncompressed > limits.max_uncompressed_bytes
        || scan.cumulative > limits.max_uncompressed_bytes
    {
        return threat(
            ZipThreatKind::UncompressedSize,
            format!(
                "declared uncompressed size {} B (cumulative {} B) exceeds {} B",
                total_uncompressed, scan.cumulative, limits.max_uncompressed_bytes
            ),
        );
    }

    let ratio = total_uncompressed as f64 / total_compressed.max(1) as f64;
    if ratio > limits.max_ratio && total_uncompressed >= limits.min_ratio_check_bytes {
        return threat(
            ZipThreatKind::CompressionRatio,
            format!(
                "compression ratio {ratio:.1}:1 exceeds {:.0}:1",
                limits.max_ratio
            ),
        );
    }
    // A bomb entry hidden among large incompressible ones dilutes the whole-archive ratio.
    if let Some(r) = recs.iter().find(|r| {
        r.uncompressed >= limits.min_ratio_check_bytes
            && r.uncompressed as f64 / r.compressed.max(1) as f64 > limits.max_ratio
    }) {
        return threat(
            ZipThreatKind::CompressionRatio,
            format!(
                "entry #{} ratio {:.1}:1 exceeds {:.0}:1",
                r.cd_index,
                r.uncompressed as f64 / r.compressed.max(1) as f64,
                limits.max_ratio
            ),
        );
    }

    // Whole-entry extents (local header through data) catch shared and quoted headers too.
    let mut extents: Vec<(u64, u64)> = recs.iter().filter_map(|r| r.extent).collect();
    extents.sort_unstable();
    let mut max_end = 0u64;
    let mut max_span = (0u64, 0u64);
    for &(start, end) in &extents {
        if start < max_end {
            return threat(
                ZipThreatKind::OverlappingEntries,
                format!(
                    "entry at offset {start} overlaps entry spanning {}..{}",
                    max_span.0, max_span.1
                ),
            );
        }
        if end > max_end {
            max_end = end;
            max_span = (start, end);
        }
    }

    if let Some(r) = recs
        .iter()
        .find(|r| r.method == 0 && r.uncompressed > r.compressed)
    {
        return threat(
            ZipThreatKind::NestedSizeMismatch,
            format!(
                "stored entry #{} declares {} B but only holds {} B",
                r.cd_index, r.uncompressed, r.compressed
            ),
        );
    }
    if let Some(r) = recs.iter().find(|r| r.mismatch.is_some()) {
        return threat(
            ZipThreatKind::HeaderMismatch,
            format!(
                "entry #{}: {}",
                r.cd_index,
                r.mismatch.clone().unwrap_or_default()
            ),
        );
    }

    // Everything below decompresses, so it is bounded by byte and time budgets.
    // Passwords and compression methods this check cannot read hide what is inside.
    scan.incomplete |= recs
        .iter()
        .any(|r| r.encrypted || !matches!(r.method, 0 | 8));
    if !recs.iter().any(|r| r.nested || r.method == 8) {
        return None;
    }
    let mut archive = match archive {
        Some(a) => a,
        None => match ZipArchive::new(Timed {
            inner: &mut reader,
            deadline: scan.deadline,
        }) {
            Ok(a) => a,
            Err(_) => {
                scan.incomplete = true;
                return None;
            }
        },
    };

    // Actual decompressed bytes versus the declared size, smallest declarations first.
    let mut sample: Vec<&Rec> = recs
        .iter()
        .filter(|r| r.method == 8 && r.compressed > 0 && !r.nested)
        .collect();
    sample.sort_unstable_by_key(|r| r.uncompressed);
    for r in sample {
        if scan.sample_left == 0 || Instant::now() > scan.deadline {
            scan.incomplete = true;
            break;
        }
        let Ok(entry) = archive.by_index(r.cd_index) else {
            scan.incomplete = true;
            continue;
        };
        let declared = entry.size();
        let cap = declared.saturating_add(1).min(scan.sample_left);
        scan.incomplete |= cap <= declared;
        let got = read_up_to(entry, cap);
        scan.sample_left -= got;
        if got > declared {
            return threat(
                ZipThreatKind::NestedSizeMismatch,
                format!(
                    "entry #{} inflates beyond its declared size of {declared} B",
                    r.cd_index
                ),
            );
        }
    }

    // A declared size is only a claim: always read up to the cap and trust what comes out.
    for r in recs.iter().filter(|r| r.nested) {
        if scan.nested_left == 0 || Instant::now() > scan.deadline {
            scan.incomplete = true;
            continue;
        }
        let cap = limits.max_nested_mem_read.min(scan.nested_left);
        let mut data = Vec::new();
        let declared = {
            let Ok(entry) = archive.by_index(r.cd_index) else {
                scan.incomplete = true;
                continue;
            };
            let declared = entry.size();
            if entry
                .take(cap.saturating_add(1))
                .read_to_end(&mut data)
                .is_err()
            {
                scan.incomplete = true;
                continue;
            }
            declared
        };
        let actual = data.len() as u64;
        scan.nested_left = scan.nested_left.saturating_sub(actual);
        if actual > declared {
            return threat(
                ZipThreatKind::NestedSizeMismatch,
                format!(
                    "nested archive #{} inflates beyond its declared size of {declared} B (read limit {} B)",
                    r.cd_index, limits.max_nested_mem_read
                ),
            );
        }
        if actual > cap {
            // Too large to unpack in memory; only a clearly bomb-like ratio is worth a verdict.
            if actual as f64 / r.compressed.max(1) as f64 > limits.max_ratio {
                return threat(
                    ZipThreatKind::NestedSizeMismatch,
                    format!(
                        "nested archive #{} exceeds the {cap} B read limit with ratio above {:.0}:1 and cannot be verified",
                        r.cd_index, limits.max_ratio
                    ),
                );
            }
            scan.incomplete = true;
            continue;
        }
        if actual < declared {
            return threat(
                ZipThreatKind::NestedSizeMismatch,
                format!(
                    "nested archive #{} declares {declared} B but yields only {actual} B",
                    r.cd_index
                ),
            );
        }
        if let Some(inner) =
            inspect_level(Cursor::new(data.as_slice()), depth + 1, r.jar, limits, scan)
        {
            return Some(inner);
        }
        // Ratios multiply through nesting: everything unpacked versus the file on disk.
        let effective = scan.cumulative as f64 / scan.root_len as f64;
        if effective > limits.max_ratio && scan.cumulative >= limits.min_ratio_check_bytes {
            return threat(
                ZipThreatKind::CompressionRatio,
                format!(
                    "effective nested ratio {effective:.1}:1 exceeds {:.0}:1",
                    limits.max_ratio
                ),
            );
        }
    }
    None
}

pub fn scan_and_respond(path: &Path, cfg: &AppConfig) -> Option<ZipThreat> {
    scan_and_respond_with(path, cfg, inspect_zip_file)
}

// shortcut: the archive is streamed from disk, so no buffer of the judged bytes is held to hash;
// the stamp taken BEFORE inspecting catches an ordinary swap, not a write through a mapping
// someone else holds open. Upgrade by hashing while reading the archive.
fn scan_and_respond_with(
    path: &Path,
    cfg: &AppConfig,
    inspect: impl FnOnce(&Path, &AppConfig) -> Option<ZipThreat>,
) -> Option<ZipThreat> {
    let judged = allowlist::stamp_of(path);
    let threat = inspect(path, cfg)?;
    let (digest, allowed) = allowlist::check(cfg, path, judged);
    if allowed {
        return None;
    }
    let details = threat.summary();
    let restored = quarantine::was_restored(cfg, path, digest);
    let action = if restored {
        format!("ALERT_ONLY: {}", quarantine::RESTORED_BY_USER)
    } else if cfg.is_dry_run() {
        "DRY_RUN: would quarantine".to_string()
    } else {
        match quarantine::quarantine_file(path, cfg, "ZIP_BOMB", &details) {
            Ok(meta) => format!("QUARANTINED id={}", meta.id),
            Err(e) => format!("QUARANTINE_FAILED: {e}"),
        }
    };
    let mut event = ThreatEvent::new(
        "ZIP_BOMB",
        Severity::High,
        path.display().to_string(),
        action,
        details,
    )
    .with_sha256(digest);
    event.quiet = restored;
    quarantine::record_event(cfg, event);
    Some(threat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn build_zip(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            for (name, data) in files {
                let options =
                    SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
                writer.start_file(*name, options).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    /// Two central-directory records pointing at the same local file (non-recursive bomb shape).
    fn overlapping_zip() -> Vec<u8> {
        let data = vec![b'A'; 4096];
        let crc = crc32(&data);
        let size = data.len() as u32;
        let local_name = b"payload.bin";
        let mut out = Vec::new();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x21u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(local_name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(local_name);
        out.extend_from_slice(&data);
        let cd_offset = out.len() as u32;
        for name in [&b"payload.bin"[..], &b"payload-alias.bin"[..]] {
            out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0x21u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(name);
        }
        let cd_size = out.len() as u32 - cd_offset;
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn nested(levels: usize) -> Vec<u8> {
        let mut current = build_zip(&[("leaf.txt", b"hello".to_vec())]);
        for level in 1..levels {
            let name = format!("level{level}.zip");
            current = build_zip(&[(name.as_str(), current)]);
        }
        current
    }

    fn incomplete_for(bytes: &[u8]) -> (Option<ZipThreatKind>, bool) {
        let (threat, incomplete) = inspect_root(
            Cursor::new(bytes),
            bytes.len() as u64,
            &ZipLimits::default(),
        );
        (threat.map(|t| t.kind), incomplete)
    }

    /// Sets the general-purpose flags and compression method in every header of `bytes`.
    fn patch_headers(bytes: &mut [u8], flags: u16, method: u16) {
        for (sig, flag_at, method_at) in [(LFH_SIG, 6, 8), (CDFH_SIG, 8, 10)] {
            let mut from = 0;
            while let Some(i) = bytes[from..].windows(4).position(|w| w == sig) {
                let at = from + i;
                bytes[at + flag_at..at + flag_at + 2].copy_from_slice(&flags.to_le_bytes());
                bytes[at + method_at..at + method_at + 2].copy_from_slice(&method.to_le_bytes());
                from = at + 4;
            }
        }
    }

    #[test]
    fn archives_that_cannot_be_looked_into_are_not_reported_as_complete() {
        let plain = build_zip(&[("a.txt", b"hello hello hello".to_vec())]);
        assert_eq!(incomplete_for(&plain), (None, false));
        let mut password = plain.clone();
        patch_headers(&mut password, 1, 8);
        assert_eq!(incomplete_for(&password), (None, true), "password, deflate");
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            writer.start_file("a.txt", stored).unwrap();
            writer.write_all(b"hello").unwrap();
            writer.finish().unwrap();
        }
        let mut stored_password = cursor.into_inner();
        assert_eq!(incomplete_for(&stored_password), (None, false));
        patch_headers(&mut stored_password, 1, 0);
        assert_eq!(
            incomplete_for(&stored_password),
            (None, true),
            "password, stored"
        );
        let mut lzma = plain;
        patch_headers(&mut lzma, 0, 14);
        assert_eq!(incomplete_for(&lzma), (None, true), "lzma");
        // A nested archive that cannot be opened.
        let mut nested = build_zip(&[("inner.zip", build_zip(&[("a", b"x".to_vec())]))]);
        patch_headers(&mut nested, 1, 8);
        assert_eq!(incomplete_for(&nested), (None, true), "password, nested");
    }

    #[test]
    fn a_nested_archive_too_large_to_unpack_is_incomplete() {
        let outer = build_zip(&[("big.zip", vec![0u8; 64 * 1024])]);
        let limits = ZipLimits {
            max_ratio: 1e12,
            max_nested_mem_read: 1024,
            ..ZipLimits::default()
        };
        let (threat, incomplete) =
            inspect_root(Cursor::new(&outer[..]), outer.len() as u64, &limits);
        assert_eq!((threat.map(|t| t.kind), incomplete), (None, true));
    }

    #[test]
    fn a_file_swapped_while_it_was_inspected_is_not_allowed() {
        use crate::allowlist::{self, AllowedFile};
        let dir = std::env::temp_dir().join(format!("thenex-zip-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        cfg.dry_run = true;
        let file = dir.join("a.zip");
        std::fs::write(&file, b"judged bytes").unwrap();
        let allowed = quarantine::sha256_hex(b"swapped bytes");
        allowlist::add(
            &cfg,
            AllowedFile::new(&allowed, "a.zip", "ZIP_BOMB").unwrap(),
        )
        .unwrap();
        let swap_then_flag = |path: &Path, _: &AppConfig| {
            std::fs::remove_file(path).unwrap();
            std::fs::write(path, b"swapped bytes").unwrap();
            Some(ZipThreat {
                kind: ZipThreatKind::Malformed,
                depth: 1,
                entries: 0,
                total_compressed: 0,
                total_uncompressed: 0,
                detail: String::new(),
            })
        };
        // The stamp was taken before the inspection, so the swapped-in bytes are not vouched for.
        assert!(scan_and_respond_with(&file, &cfg, swap_then_flag).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn benign_zip_is_allowed() {
        let bytes = build_zip(&[
            ("readme.txt", b"The Nex benign archive".to_vec()),
            (
                "data.bin",
                (0..4096u32).map(|i| (i * 7 % 256) as u8).collect(),
            ),
        ]);
        assert_eq!(inspect_zip_bytes(&bytes, &ZipLimits::default()), None);
    }

    /// Found by an audit: the zip library searched this one for minutes.
    #[test]
    fn a_file_of_repeated_end_records_is_given_up_on_in_time() {
        // One entry, no directory behind it: not a zip, again and again.
        let mut end = b"PK\x05\x06".to_vec();
        end.extend([0, 0, 0, 0, 1, 0, 1, 0, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let bytes = end.repeat(4 * 1024 * 1024 / end.len());
        let started = Instant::now();
        let (threat, incomplete) = inspect_root(
            Cursor::new(&bytes[..]),
            bytes.len() as u64,
            &ZipLimits::default(),
        );
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "{:?}",
            started.elapsed()
        );
        assert!(
            threat.is_none() && incomplete,
            "{threat:?} {incomplete} {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_file_nobody_touches_is_ready_at_once_and_a_fresh_one_is_waited_for() {
        let path = std::env::temp_dir().join(format!("thenex-ready-{}.zip", std::process::id()));
        fs::write(&path, b"PK").unwrap();
        let started = Instant::now();
        assert!(wait_for_file_ready(&path));
        assert!(started.elapsed() >= READY_POLL * READY_STABLE_CHECKS);
        let started = Instant::now();
        assert!(wait_for_file_ready(&path));
        assert!(!cfg!(unix) || started.elapsed() < READY_POLL);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn small_compressible_zip_is_below_ratio_floor() {
        let bytes = build_zip(&[("zeros.bin", vec![0u8; 256 * 1024])]);
        assert_eq!(inspect_zip_bytes(&bytes, &ZipLimits::default()), None);
    }

    #[test]
    fn ratio_bomb_is_flagged() {
        let limits = ZipLimits {
            min_ratio_check_bytes: 1024 * 1024,
            ..ZipLimits::default()
        };
        let bytes = build_zip(&[("zeros.bin", vec![0u8; 2 * 1024 * 1024])]);
        let threat = inspect_zip_bytes(&bytes, &limits).expect("ratio bomb must be flagged");
        assert_eq!(threat.kind, ZipThreatKind::CompressionRatio);
    }

    #[test]
    fn declared_size_limit_is_enforced() {
        let limits = ZipLimits {
            max_uncompressed_bytes: 1024,
            ..ZipLimits::default()
        };
        let bytes = build_zip(&[("big.bin", vec![7u8; 4096])]);
        let threat = inspect_zip_bytes(&bytes, &limits).expect("size limit must trigger");
        assert_eq!(threat.kind, ZipThreatKind::UncompressedSize);
    }

    #[test]
    fn overlapping_entries_are_flagged() {
        let threat = inspect_zip_bytes(&overlapping_zip(), &ZipLimits::default())
            .expect("overlap must be flagged");
        assert_eq!(threat.kind, ZipThreatKind::OverlappingEntries);
    }

    #[test]
    fn nesting_beyond_limit_is_flagged() {
        assert_eq!(inspect_zip_bytes(&nested(3), &ZipLimits::default()), None);
        let threat = inspect_zip_bytes(&nested(4), &ZipLimits::default())
            .expect("4-level nesting must be flagged");
        assert_eq!(threat.kind, ZipThreatKind::NestingDepth);
        assert_eq!(threat.depth, 4);
    }

    /// A Minecraft modpack (.mrpack) holds mods (.jar) that bundle libraries (.jar) that bundle
    /// theirs; one was quarantined on a real PC.
    #[test]
    fn jars_inside_jars_are_how_programs_are_packed() {
        let wrap = |name: &str, inner: Vec<u8>| build_zip(&[(name, inner)]);
        let jar = wrap("Main.class", b"code".to_vec());
        let pack = wrap(
            "mods/a.jar",
            wrap("jars/b.jar", wrap("jars/c.jar", jar.clone())),
        );
        assert_eq!(inspect_zip_bytes(&pack, &ZipLimits::default()), None);

        // Calling the layers .jar buys two levels, not any number, and no zip below the limit.
        let deep = (0..5).fold(jar.clone(), |inner, _| wrap("x.jar", inner));
        let zip_below = wrap("a.jar", wrap("b.jar", wrap("c.zip", jar)));
        for archive in [deep, zip_below] {
            let threat = inspect_zip_bytes(&archive, &ZipLimits::default()).unwrap();
            assert_eq!(threat.kind, ZipThreatKind::NestingDepth);
        }
        // And a bomb down there is still found.
        let bomb = build_zip(&[("zeros.bin", vec![0u8; 20 * 1024 * 1024])]);
        let hidden = wrap("a.jar", wrap("b.jar", wrap("c.jar", bomb)));
        let threat = inspect_zip_bytes(&hidden, &ZipLimits::default()).unwrap();
        assert_eq!(threat.kind, ZipThreatKind::CompressionRatio);
    }

    #[test]
    fn expired_deadline_keeps_the_structural_verdict() {
        let bomb = build_zip(&[("zeros.bin", vec![0u8; 2 * 1024 * 1024])]);
        let limits = ZipLimits {
            min_ratio_check_bytes: 1024 * 1024,
            ..ZipLimits::default()
        };
        let mut scan = Scan {
            cumulative: 0,
            root_len: bomb.len() as u64,
            sample_left: SAMPLE_BUDGET,
            nested_left: NESTED_BUDGET,
            deadline: Instant::now() - Duration::from_secs(1),
            incomplete: false,
        };
        let threat = inspect_level(Cursor::new(bomb.as_slice()), 1, false, &limits, &mut scan)
            .expect("ratio verdict survives an expired deadline");
        assert_eq!(threat.kind, ZipThreatKind::CompressionRatio);
    }

    #[test]
    fn last_segment_of_a_split_archive_is_not_malformed() {
        let whole = build_zip(&[("a.txt", b"alpha".to_vec()), ("b.txt", b"beta".to_vec())]);
        let cd = whole.windows(4).position(|w| w == CDFH_SIG).unwrap();
        // Only the directory and EOCD survive in the last segment; it names disk 1.
        let mut tail = whole[cd..].to_vec();
        let eocd = tail.windows(4).rposition(|w| w == EOCD_SIG).unwrap();
        tail[eocd + 4] = 1;
        tail[eocd + 6] = 1;
        assert_eq!(inspect_zip_bytes(&tail, &ZipLimits::default()), None);
    }

    #[test]
    fn local_header_walk_is_capped() {
        let bytes = build_zip(&[
            ("a", b"1".to_vec()),
            ("b", b"2".to_vec()),
            ("c", b"3".to_vec()),
        ]);
        let len = bytes.len() as u64;
        let far = Instant::now() + Duration::from_secs(5);
        let (recs, truncated) = lfh_walk(&mut Cursor::new(bytes.as_slice()), len, far, 2);
        assert!(truncated && recs.len() == 2);
        let (recs, truncated) = lfh_walk(&mut Cursor::new(bytes.as_slice()), len, far, 3);
        assert!(!truncated && recs.len() == 3);
    }

    #[test]
    fn non_zip_bytes_are_ignored() {
        assert_eq!(inspect_zip_bytes(b"not a zip", &ZipLimits::default()), None);
    }

    #[test]
    fn partial_downloads_are_ignored() {
        assert!(is_ignored_extension(Path::new("setup.exe.crdownload")));
        assert!(is_ignored_extension(Path::new("a.PART")));
        assert!(!is_ignored_extension(Path::new("a.zip")));
    }
}
