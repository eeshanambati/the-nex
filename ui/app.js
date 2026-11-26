"use strict";

const tauri = window.__TAURI__;
const invoke = tauri && tauri.core && typeof tauri.core.invoke === "function" ? tauri.core.invoke : null;

const REFRESH_MS = 2000;
const CONFIRM_MS = 4000;
const OVERVIEW_EVENTS = 5;
const ACTIVITY_LIMIT = 1000;
const PAGE_TITLES = { overview: "Home", activity: "Activity", startup: "Startup", aegismesh: "AegisMesh", settings: "Settings" };
// The five tabs; two of them hold several pages, shown as a second row of buttons.
const SUBPAGES = {
  activity: [["activity", "History"], ["quarantine", "Quarantine"]],
  settings: [["settings", "General"], ["engines", "Protection"], ["exceptions", "Exceptions"], ["canaries", "Decoy files"], ["devices", "Computers"], ["look", "Look"]],
};
const tabOf = (page) => Object.keys(SUBPAGES).find((tab) => SUBPAGES[tab].some(([id]) => id === page)) || page;
const PAGE_SUBS = {
  activity: "What The Nex saw and did, newest first.",
  quarantine: "Files that were moved to a safe place. Put them back or delete them here.",
  startup: "What starts by itself on this computer.",
  settings: "Setup, scheduled scans and reports.",
  engines: "Everything runs on this computer. Nothing is uploaded.",
  exceptions: "Files and folders The Nex leaves alone.",
  canaries: "Hidden decoys that reveal ransomware the moment they change.",
  devices: "Every computer signed in to your account.",
  look: "Theme and wallpaper.",
  aegismesh: "Silent SOS simulation: wearables, tap rhythms, emergency signs and the relay mesh.",
};

function greeting() {
  const now = new Date();
  const hour = now.getHours();
  const part = hour < 5 ? "Good night" : hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
  return `${part} · ${now.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" })}`;
}
const TOGGLE_FIELDS = {
  known_bad: "known_bad_enabled",
  zip_bomb: "zip_bomb_enabled",
  bin_ai: "bin_ai_enabled",
  process_guard: "process_guard_enabled",
  canary: "canary_enabled",
  dry_run: "dry_run",
};
const RED_TYPES = new Set(["ZIP_BOMB", "RANSOMWARE_CANARY", "RANSOMWARE_SUSPECT", "MALWARE_AI", "MALWARE_AI_PROCESS", "KNOWN_MALWARE"]);
const AMBER_TYPES = new Set(["LOTL_SCRIPT"]);
// What people see; the names in the event log stay as they are.
const TYPE_LABELS = {
  KNOWN_MALWARE: "Known malware",
  ZIP_BOMB: "Trick zip file",
  MALWARE_AI: "Risky program",
  MALWARE_AI_PROCESS: "Risky running program",
  LOTL_SCRIPT: "Dangerous command",
  RANSOMWARE_CANARY: "Ransomware alarm",
  RANSOMWARE_SUSPECT: "Possible ransomware",
  QUICK_SCAN: "Quick scan",
  FULL_SCAN: "Full scan",
  SCHEDULED_SCAN: "Scheduled scan",
  QUARANTINE_RESTORE: "Put back",
  QUARANTINE_DELETE: "Deleted",
  ALLOWLIST: "Always allowed",
  NEVER_SCAN: "Never scan",
};
function typeLabel(type) {
  return TYPE_LABELS[type] || String(type || "").toLowerCase().replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}
const GREEN_TYPES = new Set(["QUARANTINE_RESTORE"]);
// Detections that "Always allow" can cover: whole files judged by an estimating engine.
const ALLOWABLE_TYPES = new Set(["MALWARE_AI", "MALWARE_AI_PROCESS", "ZIP_BOMB"]);
const ALLOW_NOTE = "Always allow: this exact file (matched by its SHA-256) will never be flagged again until its contents change. It needs your administrator approval.";
// A file name for a confirm step: control, bidi and zero-width characters removed, clipped.
// Same list as the engine's check_file::is_invisible_format.
const HIDDEN_CHARS = /[\p{Cc}\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFF9-\uFFFB\u{E0000}-\u{E007F}]/gu;
function cleanName(name) {
  return String(name || "").replace(HIDDEN_CHARS, "").trim() || "unnamed";
}
function shownName(name) {
  const clean = cleanName(name);
  return clean.length > 60 ? `${clean.slice(0, 60)}...` : clean;
}
/** Why "Always allow" cannot be used right now (an older background service), else "". */
function allowProblem() {
  return (state.dashboard && state.dashboard.allow_problem) || "";
}
/** Larger files are never matched by their hash, so they cannot be always allowed. */
function allowableSize(size) {
  const max = state.dashboard && state.dashboard.thresholds && state.dashboard.thresholds.max_hash_bytes;
  return Number.isFinite(max) && Number(size) <= max;
}
/** The note under an "Always allow" button. While the button is armed it says which file this is,
 * so the person confirms the very file that will be allowed (Windows' UAC shows no text). */
function allowNote(action, id, name, sha256, extra = "") {
  const problem = allowProblem();
  if (problem) return problem;
  const which = confirming(action, id) ? `About to allow: ${shownName(name)}, SHA-256 ${String(sha256).slice(0, 16)}. ` : "";
  return `${which}${ALLOW_NOTE}${extra}`;
}

const state = {
  page: "overview",
  query: "",
  severity: "ALL",
  dashboard: null,
  quarantine: [],
  refreshing: false,
  pendingToggles: new Set(),
  confirm: null,
  openEvent: null,
  openQuarantine: null,
  activityType: null, // Activity filters set by clicking the overview (a threat type, a day)
  activityDay: null,
  scanning: false,
};

const SEARCH_PAGES = new Set(["activity", "quarantine"]);
const TYPE_NOTES = {
  ZIP_BOMB: "An archive built to expand far beyond its size and exhaust the disk or memory. It was caught before anything was extracted.",
  LOTL_SCRIPT: "A built-in tool (PowerShell, cmd, mshta, osascript…) was started the way malware uses it, for example with a hidden window, an encoded command or a download.",
  KNOWN_MALWARE: "A file or program whose fingerprint (SHA-256) is on the known-malware list. This is a certain match, not a guess.",
  MALWARE_AI: "The on-device AI model scored this new program as malicious. The detail line lists what it noticed.",
  MALWARE_AI_PROCESS: "The on-device AI model scored the image of a running program as malicious.",
  RANSOMWARE_CANARY: "A decoy file that nothing should touch was changed: the typical first sign of ransomware encrypting files.",
  RANSOMWARE_SUSPECT: "A program changed many files in a way that looks like ransomware.",
  QUARANTINE_RESTORE: "You restored this file from quarantine to where it was found.",
  QUARANTINE_DELETE: "You deleted this file from quarantine for good.",
  SCHEDULED_SCAN: "A scan The Nex started by itself on your schedule. It only reports what it finds and never moves or deletes anything.",
};

const $ = (id) => document.getElementById(id);

function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = options.text;
  if (options.title) node.title = options.title;
  for (const [key, value] of Object.entries(options.attrs || {})) node.setAttribute(key, value);
  for (const child of children) node.append(child);
  return node;
}

function call(command, args) {
  if (!invoke) return Promise.reject(new Error("The Nex desktop runtime is not available in this window."));
  return invoke(command, args || {});
}

function errorText(error) {
  if (typeof error === "string") return error;
  return (error && error.message) || String(error);
}

let noticeTimer = null;
function notice(message, isError) {
  const box = $("notice");
  box.textContent = message;
  box.classList.toggle("error", Boolean(isError));
  box.setAttribute("role", isError ? "alert" : "status");
  box.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { box.hidden = true; }, isError ? 9000 : 5000);
}

function formatTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString([], { hour12: false });
}

function formatDateTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { hour12: false });
}

/** Counts a tile's number up (or down) to its new value instead of jumping. */
function setCount(node, value) {
  const target = Number(value) || 0;
  const from = Number(node.dataset.value);
  node.dataset.value = String(target);
  if (!Number.isFinite(from) || from === target || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    node.textContent = count(target);
    return;
  }
  const start = performance.now();
  const step = (now) => {
    if (node.dataset.value !== String(target)) return; // a newer value took over
    const k = Math.min(1, (now - start) / 700);
    const eased = 1 - Math.pow(1 - k, 3);
    node.textContent = count(Math.round(from + (target - from) * eased));
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function sameDay(a, b) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** "20:06:24" today, "Yesterday 19:07" or "Nov 21, 19:07" before that. */
function formatWhen(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  const now = new Date();
  if (sameDay(date, now)) return date.toLocaleTimeString([], { hour12: false });
  const time = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (sameDay(date, yesterday)) return `Yesterday ${time}`;
  return `${date.toLocaleDateString([], { month: "short", day: "numeric" })}, ${time}`;
}

/** "40 s ago", "5 min ago", "3 h ago", "2 days ago". */
function relativeTime(iso) {
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return "";
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  const days = Math.round(s / 86400);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

function folderOf(path) {
  const text = String(path || "");
  const cut = Math.max(text.lastIndexOf("\\"), text.lastIndexOf("/"));
  return cut > 0 ? text.slice(0, cut) : "";
}

function severityKey(value) {
  return String(value || "").toUpperCase();
}

function copyButton(text, label = "Copy") {
  const button = el("button", { className: "btn btn-small", text: label, attrs: { type: "button" } });
  button.addEventListener("click", async (event) => {
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    setTimeout(() => { button.textContent = label; }, 1400);
  });
  return button;
}

/** Copies an item's details (file name only, account name removed) and opens the website's
 *  report form in the browser. The app itself sends nothing. */
function reportButton(item, ...more) {
  const button = el("button", {
    className: "btn btn-small", text: "Report as safe",
    title: "Copies these details, without the file's folder or your account name, and opens the report form in your browser",
    attrs: { type: "button" },
  });
  button.addEventListener("click", async (event) => {
    event.stopPropagation();
    const d = state.dashboard;
    const text = NexReport.reportText(item, { version: d && d.daemon.version, platform: d && d.platform });
    try {
      await navigator.clipboard.writeText(text);
      notice("Details copied. Paste them into the report form that is opening in your browser.", false);
    } catch {
      notice("The details could not be copied; the report form is still opening.", true);
    }
    call("open_report_page", { kind: "false_alarm" }).catch((error) => notice(errorText(error), true));
  });
  return el("div", { className: "button-group detail-actions" }, [button, ...more]);
}

function detailGrid(entries, note) {
  const grid = el("dl", { className: "detail-grid" });
  for (const [term, value, copy] of entries) {
    const dd = el("dd", {}, [el("span", { text: value })]);
    if (copy) dd.append(copyButton(copy));
    grid.append(el("dt", { text: term }), dd);
  }
  if (note) grid.append(el("p", { className: "detail-note", text: note }));
  return grid;
}

/** A clickable row plus its hidden detail row; `open` shows the details. */
function expandable(cells, detail, open, onToggle, columns) {
  const row = el("tr", { className: `expand-row${open ? " open" : ""}`, attrs: { tabindex: "0", "aria-expanded": String(open) } }, cells);
  row.addEventListener("click", (event) => {
    if (event.target.closest("button")) return;
    onToggle();
  });
  row.addEventListener("keydown", (event) => {
    if ((event.key === "Enter" || event.key === " ") && event.target === row) {
      event.preventDefault();
      onToggle();
    }
  });
  if (!open) return [row];
  const cell = el("td", { attrs: { colspan: String(columns) } }, [detail]);
  return [row, el("tr", { className: "detail-row" }, [cell])];
}

const chevron = () => el("span", { className: "chev", attrs: { "aria-hidden": "true" } });

function formatShortDate(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
}

function formatUptime(seconds) {
  if (seconds == null) return "";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function count(value) {
  return Number(value || 0).toLocaleString();
}

function shortPath(path) {
  const text = String(path || "");
  const separator = text.includes("\\") ? "\\" : "/";
  const parts = text.split(/[\\/]/).filter(Boolean);
  return parts.length <= 2 ? text : parts.slice(-2).join(separator);
}

function fileName(path) {
  const parts = String(path || "").split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : String(path || "");
}

function typeClass(type) {
  if (RED_TYPES.has(type)) return "pill red";
  if (AMBER_TYPES.has(type)) return "pill amber";
  if (GREEN_TYPES.has(type)) return "pill green";
  return "pill";
}

function actionLabel(action) {
  const text = String(action || "");
  if (text.startsWith("DRY_RUN")) return "Only watched";
  if (text.includes("QUARANTINE_FAILED") || text === "TERMINATE_FAILED") return "Failed";
  if (text.startsWith("TERMINATED") && text.includes("QUARANTINED")) return "Stopped and held";
  if (text.startsWith("QUARANTINED")) return "Held";
  if (text.startsWith("TERMINATED")) return "Stopped";
  if (text === "ALERT_RAISED" || text.startsWith("ALERT_ONLY")) return "Told you";
  if (text === "RESTORED") return "Put back";
  if (text === "DELETED") return "Deleted";
  const found = /^(\d+) threat/.exec(text); // a finished scan
  if (found) return found[1] === "0" ? "Nothing found" : `${found[1]} found`;
  const word = text.split(/[\s=]/)[0].replace(/_/g, " ");
  return word ? word.charAt(0).toUpperCase() + word.slice(1).toLowerCase() : "—";
}

function severityName(severity) {
  const key = severityKey(severity);
  return key.charAt(0) + key.slice(1).toLowerCase();
}

function eventRow(event) {
  const row = el("tr", { title: "Open in Activity", attrs: { tabindex: "0" } }, [
    el("td", {}, [el("span", { className: typeClass(event.threat_type), text: typeLabel(event.threat_type) })]),
    el("td", { text: fileName(event.target), title: event.target }),
    el("td", { text: actionLabel(event.action_taken), title: event.action_taken }),
    el("td", { className: "right muted", text: relativeTime(event.timestamp), title: formatDateTime(event.timestamp) }),
  ]);
  const open = () => openActivity({ open: event.id });
  row.addEventListener("click", open);
  row.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
  return row;
}

const DAY_MS = 86400000;

/** Opens Activity, optionally filtered to one threat type or one day, or with one event open. */
function openActivity({ type = null, day = null, open = null } = {}) {
  state.activityType = type;
  state.activityDay = day;
  state.openEvent = open;
  state.severity = "ALL";
  for (const pill of document.querySelectorAll(".pill-filter")) pill.classList.toggle("active", pill.dataset.severity === "ALL");
  showPage("activity");
}

function renderActivityFilters() {
  const chips = [];
  if (state.activityType) chips.push(["What", typeLabel(state.activityType), () => { state.activityType = null; }]);
  if (state.activityDay !== null) {
    const label = new Date(state.activityDay).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "short" });
    chips.push(["Day", label, () => { state.activityDay = null; }]);
  }
  const holder = $("activity-filters");
  holder.hidden = chips.length === 0;
  replaceIfChanged(holder, JSON.stringify(chips.map((c) => c.slice(0, 2))), () => chips.map(([name, value, clear]) => {
    const close = el("button", { text: "×", title: `Show every ${name.toLowerCase()}`, attrs: { type: "button", "aria-label": `Clear the ${name.toLowerCase()} filter` } });
    close.addEventListener("click", () => { clear(); refresh(true); });
    return el("span", { className: "filter-chip" }, [el("small", { text: name }), el("span", { text: value }), close]);
  }));
}

function activityRows(event) {
  const open = state.openEvent === event.id;
  const cells = [
    el("td", {}, [
      el("span", { className: "cell-main", text: formatWhen(event.timestamp) }),
      el("span", { className: "cell-sub", text: relativeTime(event.timestamp) }),
    ]),
    el("td", {}, [el("span", { className: typeClass(event.threat_type), text: typeLabel(event.threat_type) })]),
    el("td", { title: event.target }, [
      el("span", { className: "cell-main", text: fileName(event.target) }),
      el("span", { className: "cell-sub", text: folderOf(event.target) || "—" }),
    ]),
    el("td", { className: "sans", text: actionLabel(event.action_taken), title: event.action_taken }),
    el("td", {}, [chevron()]),
  ];
  const detail = detailGrid([
    ["When", `${formatDateTime(event.timestamp)} (${relativeTime(event.timestamp)})`],
    ["Where", event.target, event.target],
    ["How serious", severityName(event.severity)],
    ["Type", event.threat_type],
    ["Detail", event.details],
    ["Action taken", event.action_taken],
    ["Event ID", event.id, event.id],
  ], TYPE_NOTES[event.threat_type]);
  const allowable = event.sha256 && ALLOWABLE_TYPES.has(event.threat_type);
  detail.append(reportButton(event, ...(allowable ? [quarantineButton("allow_event", "Always allow", event.id)] : [])));
  if (allowable) detail.append(el("p", { className: "detail-note", text: allowNote("allow_event", event.id, fileName(event.target), event.sha256) }));
  return expandable(cells, detail, open, () => {
    state.openEvent = open ? null : event.id;
    loadEvents().catch(() => {});
  }, 5);
}

function setSwitch(button, checked) {
  button.setAttribute("aria-checked", checked ? "true" : "false");
}

function renderToggles(toggles, enabled) {
  for (const button of document.querySelectorAll(".switch[data-engine]")) {
    const engine = button.dataset.engine;
    if (state.pendingToggles.has(engine)) continue;
    setSwitch(button, Boolean(toggles && toggles[TOGGLE_FIELDS[engine]]));
    button.disabled = !enabled;
  }
}

function focusEngine(engine) {
  const row = document.querySelector(`[data-engine-row="${engine}"]`);
  if (!row) return;
  requestAnimationFrame(() => {
    row.scrollIntoView({ block: "center", behavior: "smooth" });
    row.classList.remove("flash");
    void row.offsetWidth; // restart the highlight
    row.classList.add("flash");
  });
}

function buildEngineRows() {
  const rows = $("engine-rows");
  const engines = [
    ["known_bad", "Known malware", "Compares files and programs with a list of known malware."],
    ["zip_bomb", "Trick zip files", "Spots zip files built to fill up the computer, before they are opened."],
    ["bin_ai", "New programs", "Gives programs from unknown makers a risk score."],
    ["process_guard", "Dangerous commands", "Stops commands that attacks often use to download or hide things."],
    ["canary", "Ransomware decoys", "Hidden decoy files that raise the alarm the moment something tampers with them."],
  ];
  for (const [engine, title, description] of engines) {
    const thresholds = el("div", { className: "thresholds", attrs: { "data-thresholds": engine } });
    rows.append(el("div", { className: "row", attrs: { "data-engine-row": engine } }, [
      el("div", {}, [el("h3", { text: title }), el("p", { className: "muted", text: description }), el("details", { className: "more" }, [el("summary", { text: "Technical details" }), thresholds])]),
      el("button", { className: "switch", attrs: { role: "switch", "aria-checked": "false", "data-engine": engine, "aria-label": title } }),
    ]));
  }
}

function fillThresholds(engine, values) {
  const holder = document.querySelector(`[data-thresholds="${engine}"]`);
  if (!holder) return;
  holder.replaceChildren(...values.map((value) => el("span", { className: "pill", text: value })));
}

function facts(list, entries, badges) {
  list.replaceChildren(...entries.flatMap(([term, value]) => [
    el("dt", { text: term }),
    badges ? el("dd", {}, [el("code", { className: "path-badge", text: value })]) : el("dd", { text: value }),
  ]));
}

function renderDashboard(d) {
  const online = d.daemon.online;
  const footerDot = $("service-dot");
  footerDot.className = online ? "dot ok" : "dot";
  $("service-text").textContent = online
    ? `Running · ${(d.daemon.memory_mb || 0).toFixed(1)} MB`
    : "Not running";

  const topDot = $("top-status-dot");
  const topText = $("top-status-text");
  if (!online) {
    topDot.className = "dot bad";
    topText.textContent = "Not protected";
  } else if (d.dry_run) {
    topDot.className = "dot warn";
    topText.textContent = "Only watching";
  } else {
    topDot.className = "dot ok";
    topText.textContent = "Protected";
  }

  const protection = $("protection-dot");
  if (!online) {
    protection.className = "dot bad";
    $("protection-text").textContent = "You're not protected";
  } else if (d.dry_run) {
    protection.className = "dot warn";
    $("protection-text").textContent = "Only watching";
  } else {
    protection.className = "dot ok";
    $("protection-text").textContent = "You're protected";
  }
  setCount($("stat-scanned"), d.scanned);
  setCount($("stat-threats"), d.threats_detected);
  // In dry run nothing is stopped: say what actually happened.
  $("stat-threats-sub").textContent = d.dry_run ? "threats seen, not stopped" : "threats so far";
  setCount($("stat-quarantined"), d.quarantined);
  renderProtection(d);
  if (window.NexSetup) window.NexSetup.render(d);

  const badge = $("quarantine-badge");
  badge.textContent = String(d.quarantined);
  badge.hidden = d.quarantined === 0;

  const t = d.thresholds;
  const kb = d.known_bad || {};
  renderToggles(d.toggles, true);

  fillThresholds("known_bad", kb.loaded ? [`${count(kb.entries)} hashes`, `list of ${String(kb.created).slice(0, 10)}`] : ["no list installed"]);
  fillThresholds("zip_bomb", [
    `ratio > ${t.max_ratio}:1 above ${t.min_ratio_check_mb} MB`,
    `size ≤ ${t.max_uncompressed_gb} GB`,
    `depth ≤ ${t.max_depth}`,
    `nested read ≤ ${t.nested_read_mb} MB`,
  ]);
  fillThresholds("bin_ai", [`malicious ≥ ${t.ai_threshold}`, d.model_loaded ? "onnx" : "heuristic"]);
  fillThresholds("process_guard", [`${count(d.processes_watched)} watched`, `${count(d.processes_inspected)} inspected`]);
  fillThresholds("canary", [`${d.canaries_intact}/${d.canaries.length} intact`, "2s self-write cooldown"]);

  facts($("model-facts"), [
    ["Model file", d.model_path],
    ["Present", d.model_present ? "yes" : "no"],
    ["Service engine", online ? (d.model_loaded ? "ONNX (tract)" : "heuristic fallback") : "service offline"],
    ["Decision threshold", String(t.ai_threshold)],
  ]);

  renderCanaries(d.canaries);

  const servicePill = $("service-state");
  if (d.service_installed && online) {
    servicePill.className = "pill status green";
    servicePill.textContent = "Installed · running";
  } else if (d.service_installed) {
    servicePill.className = "pill status amber";
    servicePill.textContent = "Installed · stopped";
  } else {
    servicePill.className = "pill status";
    servicePill.textContent = "Not installed";
  }
  $("service-detail").textContent = online
    ? `PID ${d.daemon.pid} · v${d.daemon.version} · up ${formatUptime(d.daemon.uptime_seconds)} · ${(d.daemon.memory_mb || 0).toFixed(1)} MB · ${(d.daemon.cpu_percent || 0).toFixed(1)}% CPU`
    : "Nothing is being checked.";
  if (!$("install-service").dataset.busy) $("install-service").textContent = d.service_installed ? "Reinstall" : "Install";
  if (!$("uninstall-service").dataset.busy) $("uninstall-service").disabled = !d.service_installed;

  replaceIfChanged($("watched-dirs"), JSON.stringify(d.watched_dirs), () => (d.watched_dirs.length
    ? d.watched_dirs.map((dir) => el("li", {}, [el("code", { className: "path-badge", text: dir })]))
    : [el("li", { className: "muted", text: "No watched folders found." })]));
  facts($("data-facts"), [
    ["Data folder", d.data_dir],
    ["Event log", d.events_log],
    ["Settings", d.settings_file],
    ["Platform", d.platform],
  ], true);
}

/** What protection needs, each on or off. */
function protectionItems(d) {
  const t = d.toggles || {};
  const on = ["known_bad_enabled", "zip_bomb_enabled", "bin_ai_enabled", "process_guard_enabled", "canary_enabled"].filter((k) => t[k]).length;
  const decoys = (d.canaries || []).length;
  return [
    { ok: d.daemon.online, text: "The background service is off", goto: "settings" },
    { ok: on === 5, text: `${on} of 5 protections are on`, goto: "engines" },
    ...(t.known_bad_enabled ? [{ ok: Boolean(d.known_bad && d.known_bad.loaded), text: "No list of known malware installed", goto: "engines" }] : []),
    { ok: Boolean(d.model_loaded), text: "The risk score model is not loaded", goto: "engines", focus: "bin_ai" },
    { ok: decoys > 0 && d.canaries_intact === decoys, text: `${d.canaries_intact} of ${decoys} decoy files in place`, goto: "canaries" },
    { ok: !d.dry_run, text: "Only watching: nothing is stopped", goto: "engines" },
  ];
}

function renderProtection(d) {
  const missing = protectionItems(d).filter((item) => !item.ok);
  $("hero").dataset.tone = !missing.length ? "ok" : d.daemon.online ? "warn" : "bad";
  $("protection-detail").textContent = missing.length
    ? "This needs a look:"
    : "New files and programs are checked as they appear.";
  replaceIfChanged($("score-items"), JSON.stringify(missing), () => missing.map((item) => el("li", { className: "no" }, [
    el("button", { text: item.text, attrs: { type: "button", "data-goto": item.goto, ...(item.focus ? { "data-focus": item.focus } : {}) } }),
  ])));
}

const CHART_REFRESH_MS = 30000;

async function loadChart(force) {
  // Each load reads the whole event log; forced refreshes (after any action) come in bursts.
  if (state.chartAt && Date.now() - state.chartAt < (force ? 2000 : CHART_REFRESH_MS)) return;
  state.chartAt = Date.now();
  const seq = refreshSeq;
  const days = [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  for (let i = 6; i >= 0; i--) {
    const day = new Date(today);
    day.setDate(day.getDate() - i);
    days.push({ start: day.getTime(), label: day.toLocaleDateString(undefined, { weekday: "short" }) });
  }
  const chart = await call("get_threat_chart", { dayStarts: days.map((d) => d.start) }).catch(() => ({ days: days.map(() => ({ critical: 0, high: 0, other: 0 })), by_type: {} }));
  if (seq !== refreshSeq) return;
  days.forEach((d, i) => Object.assign(d, chart.days[i]));
  const byType = new Map(Object.entries(chart.by_type));
  renderChartFacts(days, byType);
  const max = Math.max(1, ...days.map((d) => d.critical + d.high + d.other));
  replaceIfChanged($("threat-chart"), JSON.stringify(days), () => days.map((d, index) => {
    const total = d.critical + d.high + d.other;
    const stack = el("div", { className: "bar-stack" });
    for (const kind of ["critical", "high", "other"]) {
      if (!d[kind]) continue;
      const seg = el("div", { className: `seg ${kind}` });
      seg.style.height = `${Math.max(2, (d[kind] / max) * 100)}%`; // a quiet day stays visible beside a huge one
      stack.append(seg);
    }
    const col = el("button", {
      className: `bar-col${index === days.length - 1 ? " today" : ""}`,
      title: `${d.label}: ${count(total)} threat${total === 1 ? "" : "s"}. Click to see them.`,
      attrs: { type: "button" },
    }, [
      el("b", { className: total ? "mono" : "mono zero", text: count(total) }),
      stack,
      el("span", { text: d.label }),
    ]);
    col.addEventListener("click", () => openActivity({ day: d.start }));
    return col;
  }));
}

const TYPE_COLOURS = {
  KNOWN_MALWARE: "var(--ink)",
  ZIP_BOMB: "var(--red)",
  RANSOMWARE_CANARY: "var(--red)",
  RANSOMWARE_SUSPECT: "var(--red)",
  MALWARE_AI: "var(--ink)",
  MALWARE_AI_PROCESS: "var(--ink)",
  LOTL_SCRIPT: "var(--amber)",
};

function renderChartFacts(days, byType) {
  const totals = days.map((d) => d.critical + d.high + d.other);
  const week = totals.reduce((a, b) => a + b, 0);
  const critical = days.reduce((a, d) => a + d.critical, 0);
  const busiest = totals.indexOf(Math.max(...totals));
  const facts = [
    [count(week), "threats this week"],
    [count(totals[totals.length - 1]), "today"],
    [count(critical), "critical"],
    [week ? days[busiest].label : "—", week ? `busiest day (${count(totals[busiest])})` : "busiest day"],
  ];
  replaceIfChanged($("chart-facts"), JSON.stringify(facts), () => facts.map(([value, label]) => el("div", {}, [
    el("b", { text: value }),
    el("span", { text: label }),
  ])));
  const rows = [...byType.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  const top = rows.length ? rows[0][1] : 1;
  replaceIfChanged($("by-type"), JSON.stringify(rows), () => (rows.length ? rows.map(([type, n]) => {
    const bar = el("i");
    bar.style.setProperty("--w", `${Math.max(6, (n / top) * 100)}%`);
    if (TYPE_COLOURS[type]) bar.style.setProperty("--bar", TYPE_COLOURS[type]);
    const button = el("button", { title: `${TYPE_NOTES[type] || typeLabel(type)} Click to see these events.`, attrs: { type: "button" } }, [
      el("span", { text: typeLabel(type) }), el("b", { text: count(n) }), bar,
    ]);
    button.addEventListener("click", () => openActivity({ type }));
    return el("li", {}, [button]);
  }) : [el("li", { className: "none", text: "No threats in the last 7 days." })]));
}

function renderOffline(reason) {
  $("top-status-dot").className = "dot bad";
  $("top-status-text").textContent = "Not protected";
  $("service-dot").className = "dot";
  $("service-text").textContent = "Not running";
  $("protection-dot").className = "dot bad";
  $("protection-text").textContent = "You're not protected";
  $("hero").dataset.tone = "bad";
  $("protection-detail").textContent = reason;
  replaceIfChanged($("score-items"), "offline", () => []);
  $("service-state").className = "pill status red";
  $("service-state").textContent = "Unavailable";
  renderToggles(null, false);
  if (window.NexSetup) window.NexSetup.render(null);
  for (const id of ["quick-scan", "full-scan", "verify-canaries", "install-service", "uninstall-service"]) $(id).disabled = true;
}

function matchesQuery(...fields) {
  if (!state.query) return true;
  const query = state.query.toLowerCase();
  return fields.some((field) => String(field || "").toLowerCase().includes(query));
}

// Rebuilding rows on every 2 s poll would swallow clicks that straddle a rebuild, so only
// replace a table body when what it shows has changed.
function replaceIfChanged(node, signature, build) {
  if (node.dataset.signature === signature) return;
  node.dataset.signature = signature;
  node.replaceChildren(...build());
}

function renderCanaries(canaries) {
  const shown = canaries.filter((c) => matchesQuery(c.path, c.state));
  replaceIfChanged($("canary-rows"), JSON.stringify(shown.map((c) => [c.path, c.state])), () => shown.map((c) => el("tr", {}, [
    el("td", { text: c.path, title: c.path }),
    el("td", {}, [el("span", { className: c.state === "Intact" ? "pill green" : "pill red", text: c.state })]),
  ])));
  $("canary-empty").hidden = shown.length > 0;
}

function confirming(action, id) {
  return state.confirm && state.confirm.action === action && state.confirm.id === id && Date.now() < state.confirm.until;
}

function quarantineButton(action, label, id) {
  const armed = confirming(action, id);
  const problem = action.startsWith("allow") ? allowProblem() : "";
  const button = el("button", {
    className: action === "delete" ? "btn btn-small btn-danger" : "btn btn-small",
    text: armed ? `Confirm ${label.toLowerCase()}` : label,
    title: problem || (action.startsWith("allow") ? ALLOW_NOTE : ""),
    attrs: { type: "button" },
  });
  button.disabled = Boolean(problem);
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    quarantineAction(action, id, event);
  });
  return button;
}

const FILE_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9.5 12.5l5 5M14.5 12.5l-5 5"/></svg>';

function quarantineRows(q) {
  const open = state.openQuarantine === q.id;
  const icon = el("span", { className: "file-icon" });
  icon.innerHTML = FILE_ICON;
  const cells = [
    el("td", { title: q.original_path }, [
      el("div", { className: "file-cell" }, [icon, el("span", {}, [
        el("span", { className: "cell-main", text: fileName(q.original_path) }),
        el("span", { className: "cell-sub", text: folderOf(q.original_path) || "—" }),
      ])]),
    ]),
    el("td", { title: q.details }, [
      el("span", { className: typeClass(q.threat_type), text: typeLabel(q.threat_type) }),
    ]),
    el("td", { text: formatBytes(q.size) }),
    el("td", { title: formatDateTime(q.quarantined_at) }, [
      el("span", { className: "cell-main", text: formatShortDate(q.quarantined_at) }),
      el("span", { className: "cell-sub", text: relativeTime(q.quarantined_at) }),
    ]),
    el("td", { className: "right" }, [
      el("div", { className: "button-group end" }, [
        quarantineButton("restore", "Restore", q.id),
        quarantineButton("delete", "Delete", q.id),
        chevron(),
      ]),
    ]),
  ];
  const detail = detailGrid([
    ["Found at", q.original_path, q.original_path],
    ["Why", q.details],
    ["Size", `${formatBytes(q.size)} (${count(q.size)} bytes)`],
    ["Fingerprint (SHA-256)", q.sha256, q.sha256],
    ["Quarantined", `${formatDateTime(q.quarantined_at)} (${relativeTime(q.quarantined_at)})`],
    ["Stored as", q.quarantined_path],
    ["Quarantine ID", q.id],
  ], `${TYPE_NOTES[q.threat_type] ? `${TYPE_NOTES[q.threat_type]} ` : ""}The file is locked away and cannot run. Restore puts it back where it was found; Delete removes it for good.`);
  const allowable = q.sha256 && ALLOWABLE_TYPES.has(q.threat_type) && allowableSize(q.size);
  detail.append(reportButton({ ...q, target: q.original_path, timestamp: q.quarantined_at },
    ...(allowable ? [quarantineButton("allow_quarantined", "Restore and always allow", q.id)] : [])));
  if (allowable) detail.append(el("p", { className: "detail-note", text: allowNote("allow_quarantined", q.id, fileName(q.original_path), q.sha256, " The file is restored first.") }));
  return expandable(cells, detail, open, () => {
    state.openQuarantine = open ? null : q.id;
    renderQuarantine();
  }, 5);
}

function renderQuarantineFacts(all) {
  const total = all.reduce((sum, q) => sum + (Number(q.size) || 0), 0);
  const newest = all.reduce((best, q) => (!best || q.quarantined_at > best.quarantined_at ? q : best), null);
  const types = new Map();
  for (const q of all) types.set(q.threat_type, (types.get(q.threat_type) || 0) + 1);
  const top = [...types.entries()].sort((a, b) => b[1] - a[1])[0];
  const facts = [
    [count(all.length), `file${all.length === 1 ? "" : "s"} held`],
    [formatBytes(total), "total size"],
    [newest ? relativeTime(newest.quarantined_at) : "—", "last file stopped"],
    [top ? typeLabel(top[0]) : "—", top ? `most common (${top[1]})` : "most common threat"],
  ];
  replaceIfChanged($("quarantine-facts"), JSON.stringify(facts), () => facts.map(([value, label]) => el("div", {}, [
    el("b", { className: "mono", text: value }),
    el("span", { text: label }),
  ])));
}

function renderQuarantine() {
  const records = state.quarantine.filter((q) => matchesQuery(q.id, q.original_path, q.sha256, q.threat_type, q.details));
  const signature = JSON.stringify([state.openQuarantine, records.map((q) => [q.id, confirming("restore", q.id), confirming("delete", q.id), confirming("allow_quarantined", q.id)]), allowProblem()]);
  replaceIfChanged($("quarantine-rows"), signature, () => records.flatMap(quarantineRows));
  renderQuarantineFacts(state.quarantine);
  $("quarantine-empty").hidden = records.length > 0;
  $("quarantine-count").textContent = `${state.quarantine.length} file${state.quarantine.length === 1 ? "" : "s"} · click a row for details`;
}

const ACTION_COMMANDS = { restore: "restore_quarantine", delete: "delete_quarantine", allow_quarantined: "allow_quarantined", allow_event: "allow_event" };

async function quarantineAction(action, id, event) {
  const redraw = () => { renderQuarantine(); loadEvents().catch(() => {}); };
  if (!confirming(action, id)) {
    state.confirm = { action, id, at: Date.now(), until: Date.now() + CONFIRM_MS };
    redraw();
    setTimeout(redraw, CONFIRM_MS + 50);
    return;
  }
  if (event.detail > 1 || Date.now() - state.confirm.at < 400) return; // a double-click must not confirm
  state.confirm = null;
  try {
    const message = await call(ACTION_COMMANDS[action], { id });
    notice(message, false);
  } catch (error) {
    notice(errorText(error), true);
  }
  await refresh(true);
}

async function loadEvents() {
  const seq = refreshSeq;
  const eventsSignature = (events) => events.map((e) => `${e.id}|${e.timestamp}`).join(",");
  if (state.page === "overview") {
    const overview = await call("get_events", { limit: OVERVIEW_EVENTS, query: null, severity: "ALL" });
    if (seq !== refreshSeq) return;
    // With the minute, so "2 min ago" stays true.
    replaceIfChanged($("overview-events"), `${eventsSignature(overview)}|${Math.floor(Date.now() / 60000)}`, () => overview.map((e) => eventRow(e)));
    $("overview-empty").hidden = overview.length > 0;
  }
  if (state.page === "activity") {
    const fetched = await call("get_events", { limit: ACTIVITY_LIMIT, query: state.query || null, severity: "ALL" });
    if (seq !== refreshSeq) return;
    const capped = fetched.length >= ACTIVITY_LIMIT; // there are more: every count below is a minimum
    const all = fetched.filter((e) => {
      if (state.activityType && e.threat_type !== state.activityType) return false;
      if (state.activityDay !== null) {
        const t = Date.parse(e.timestamp);
        if (t < state.activityDay || t >= state.activityDay + DAY_MS) return false;
      }
      return true;
    });
    renderActivityFilters();
    const counts = { ALL: all.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const e of all) counts[severityKey(e.severity)] = (counts[severityKey(e.severity)] || 0) + 1;
    for (const [key, value] of Object.entries(counts)) {
      const holder = $(`count-${key}`);
      if (holder) holder.textContent = count(value) + (capped && value ? "+" : "");
    }
    const shown = state.severity === "ALL" ? all : all.filter((e) => severityKey(e.severity) === state.severity);
    const range = all.length
      ? `Newest ${relativeTime(all[0].timestamp)} · oldest ${formatWhen(all[all.length - 1].timestamp)} · click a row for details`
      : "";
    $("activity-range").textContent = capped
      ? `Only the newest ${count(ACTIVITY_LIMIT)} events are listed; the Overview chart counts all of them. ${range}`
      : range;
    replaceIfChanged($("activity-events"), `${eventsSignature(shown)}|${state.openEvent}|${confirming("allow_event", state.openEvent)}|${allowProblem()}`, () => shown.flatMap(activityRows));
    $("activity-empty").hidden = shown.length > 0;
  }
}

let refreshSeq = 0; // each refresh bumps it; older responses see the change and don't render
/** The "Always allowed files" panel in Settings. */
async function loadAllowed() {
  let list = [];
  let problem = "";
  try {
    list = await call("list_allowed");
  } catch (error) {
    problem = errorText(error);
  }
  $("allowed-empty").textContent = problem || "No file is always allowed.";
  $("allowed-empty").hidden = list.length > 0;
  const armed = (entry) => confirming("remove_allowed", entry.sha256);
  replaceIfChanged($("allowed-list"), JSON.stringify([list, list.map(armed)]), () => list.map((entry) => {
    // Two steps, and the second says which file: Windows' administrator prompt shows no text.
    const remove = el("button", {
      className: "btn btn-small",
      text: armed(entry) ? `Confirm: check ${shownName(entry.name)} (SHA-256 ${entry.sha256.slice(0, 16)}) again` : "Remove",
      attrs: { type: "button", "aria-label": `Check ${shownName(entry.name)} again` },
    });
    remove.addEventListener("click", async (event) => {
      if (!armed(entry)) {
        state.confirm = { action: "remove_allowed", id: entry.sha256, at: Date.now(), until: Date.now() + CONFIRM_MS };
        loadAllowed();
        setTimeout(loadAllowed, CONFIRM_MS + 50);
        return;
      }
      if (event.detail > 1 || Date.now() - state.confirm.at < 400) return; // a double-click must not confirm
      state.confirm = null;
      remove.disabled = true;
      try {
        notice(await call("remove_allowed", { sha256: entry.sha256 }), false);
      } catch (error) {
        notice(errorText(error), true);
      }
      await loadAllowed();
    });
    return el("li", { className: "allowed-item" }, [
      el("span", {}, [
        el("span", { className: "cell-main", text: cleanName(entry.name), title: cleanName(entry.name) }),
        el("code", { className: "cell-sub", text: entry.sha256, title: `${entry.threat_type}, added ${formatDateTime(entry.added_at)}` }),
      ]),
      remove,
    ]);
  }));
}

/** The "Never scan" panel in Settings. */
async function loadNeverScan() {
  let list = [];
  let problem = "";
  try {
    list = await call("list_never_scan");
  } catch (error) {
    problem = errorText(error);
  }
  $("skip-empty").textContent = problem || "Nothing is left out of scans.";
  $("skip-empty").hidden = list.length > 0;
  const armed = (place) => confirming("remove_never_scan", place.path);
  replaceIfChanged($("skip-list"), JSON.stringify([list, list.map(armed)]), () => list.map((place) => {
    const remove = el("button", {
      className: "btn btn-small",
      text: armed(place) ? "Confirm: scan it again" : "Remove",
      attrs: { type: "button", "aria-label": `Scan ${place.path} again` },
    });
    remove.addEventListener("click", async (event) => {
      if (!armed(place)) {
        state.confirm = { action: "remove_never_scan", id: place.path, at: Date.now(), until: Date.now() + CONFIRM_MS };
        loadNeverScan();
        setTimeout(loadNeverScan, CONFIRM_MS + 50);
        return;
      }
      if (event.detail > 1 || Date.now() - state.confirm.at < 400) return; // a double-click must not confirm
      state.confirm = null;
      remove.disabled = true;
      try {
        notice(await call("remove_never_scan", { path: place.path }), false);
      } catch (error) {
        notice(errorText(error), true);
      }
      await loadNeverScan();
    });
    return el("li", { className: "allowed-item" }, [
      el("span", {}, [
        el("code", { text: place.path }),
        el("span", { className: "cell-sub", text: `${place.folder ? "Folder" : "File"}, added ${formatDateTime(place.added_at)}` }),
      ]),
      remove,
    ]);
  }));
}

// Two steps: the first finds the place and shows its real path, the second lists that very place.
let skipChosen = null;

function showSkipChoice(place, note) {
  skipChosen = place && { path: place.path, folder: place.folder, at: Date.now() };
  $("skip-add").textContent = place ? "Confirm" : "Add";
  $("skip-note").textContent = place
    ? `About to never scan this ${place.folder ? "folder and everything in it, now and later" : "file"}: ${place.path}. Press Confirm, then approve it as an administrator.`
    : note || "";
}

async function addNeverScan(event) {
  event.preventDefault();
  const path = $("skip-path").value;
  if (!path.trim()) return showSkipChoice(null, "Drop a folder or file, or paste its full path first.");
  if (skipChosen && Date.now() - skipChosen.at < 400) return; // a double-click must not confirm
  const chosen = skipChosen;
  $("skip-add").disabled = true;
  try {
    if (!chosen) {
      const place = await call("find_never_scan", { path });
      if ($("skip-path").value === path) showSkipChoice(place); // else it was edited meanwhile
      return;
    }
    notice(await call("add_never_scan", { path: chosen.path, folder: chosen.folder }), false);
    $("skip-path").value = "";
    showSkipChoice(null);
    await loadNeverScan();
  } catch (error) {
    showSkipChoice(null, errorText(error));
  } finally {
    $("skip-add").disabled = false;
  }
}

/** On the Exceptions page a drop fills the "Never scan" box; anywhere else it is a file check. */
function takeDrop(paths) {
  if (state.page !== "exceptions") return false;
  if (paths.length > 1) {
    notice("Drop one folder or file at a time.", true);
    return true;
  }
  $("skip-path").value = paths[0];
  showSkipChoice(null);
  $("skip-path").scrollIntoView({ block: "center" });
  $("skip-form").requestSubmit();
  return true;
}

/* ---- Scheduled scan and summary report (Settings) ------------------------------------------ */

function renderSchedule(info) {
  state.schedule = info;
  for (const button of document.querySelectorAll("[data-schedule]")) {
    button.setAttribute("aria-pressed", String(button.dataset.schedule === info.schedule));
  }
  const online = Boolean(state.dashboard && state.dashboard.daemon.online);
  $("schedule-next").textContent = NexSummary.nextRunText(info, online, new Date(), formatDateTime);
  $("schedule-last").textContent = NexSummary.lastScanText(info, formatDateTime);
}

async function loadSchedule() {
  try {
    renderSchedule(await call("get_scan_schedule"));
    const progress = await call("scan_progress").catch(() => null);
    if (progress && progress.scheduled && progress.running) {
      $("schedule-next").textContent = `A scheduled scan is running now: ${count(progress.files_examined)} files looked at so far.`;
    }
  } catch (error) {
    $("schedule-next").textContent = errorText(error);
  }
}

async function chooseSchedule(button) {
  const buttons = document.querySelectorAll("[data-schedule]");
  for (const other of buttons) other.disabled = true;
  try {
    renderSchedule(await call("set_scan_schedule", { schedule: button.dataset.schedule }));
  } catch (error) {
    notice(errorText(error), true);
    await loadSchedule();
  }
  for (const other of buttons) other.disabled = false;
}

async function saveReport() {
  const result = $("report-result");
  const button = $("save-report");
  button.disabled = true;
  button.textContent = "Saving…";
  try {
    const pressed = document.querySelector("[data-report-days][aria-pressed='true']");
    const path = await call("save_summary_report", {
      days: Number(pressed ? pressed.dataset.reportDays : 7),
      includeFolders: $("report-folders").checked,
    });
    result.replaceChildren(el("span", { text: `Saved: ${path}` }), copyButton(path, "Copy path"));
    result.hidden = false;
  } catch (error) {
    notice(errorText(error), true);
  }
  button.disabled = false;
  button.textContent = "Save report";
}

function wireScheduleAndReport() {
  for (const button of document.querySelectorAll("[data-schedule]")) button.addEventListener("click", () => chooseSchedule(button));
  for (const button of document.querySelectorAll("[data-report-days]")) {
    button.addEventListener("click", () => {
      for (const other of document.querySelectorAll("[data-report-days]")) other.setAttribute("aria-pressed", String(other === button));
    });
  }
  $("save-report").addEventListener("click", saveReport);
}

async function refresh(force) {
  if (state.refreshing && !force) return;
  state.refreshing = true;
  const seq = ++refreshSeq;
  try {
    const dashboard = await call("get_dashboard_state");
    if (seq !== refreshSeq) return;
    state.dashboard = dashboard;
    renderDashboard(state.dashboard);
    for (const id of ["quick-scan", "full-scan", "verify-canaries", "install-service"]) {
      if (!$(id).dataset.busy) $(id).disabled = false;
    }
    await loadEvents();
    if (state.page === "activity" && $("week").open) await loadChart(force);
    const quarantine = await call("list_quarantine").catch((error) => {
      if (state.page === "quarantine") notice(errorText(error), true);
      return state.quarantine;
    });
    if (seq !== refreshSeq) return;
    state.quarantine = quarantine;
    renderQuarantine();
    if (state.page === "exceptions") {
      await loadAllowed();
      await loadNeverScan();
    }
    if (state.page === "settings") await loadSchedule();
  } catch (error) {
    renderOffline(invoke ? `Unavailable — ${errorText(error)}` : "Open The Nex from its desktop app to manage protection.");
  } finally {
    state.refreshing = false;
  }
}

async function busy(buttonId, label, work) {
  const button = $(buttonId);
  const original = button.innerHTML; // static markup (label and icon), restored as it was
  button.dataset.busy = "1";
  button.disabled = true;
  button.textContent = label;
  try {
    await work();
  } catch (error) {
    notice(errorText(error), true);
  } finally {
    delete button.dataset.busy;
    button.disabled = false;
    button.innerHTML = original;
    await refresh(true);
  }
}

/* ---- Quick scan: a running sheet with a radar, then the result ------------------------------ */

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const MIN_SCAN_SHOW_MS = 1600; // a very fast scan still shows the animation long enough to read
const scanUi = { ticker: 0, hideTimer: 0 };

function hideScanSheet() {
  clearTimeout(scanUi.hideTimer);
  $("scan-sheet").hidden = true;
}

function setScanSheet(stateName, title, detail) {
  const sheet = $("scan-sheet");
  sheet.dataset.state = stateName;
  $("scan-title").textContent = title;
  $("scan-detail").textContent = detail;
}

async function runQuickScan() {
  if (state.scanning) return;
  state.scanning = true;
  clearTimeout(scanUi.hideTimer);
  const button = $("quick-scan");
  button.classList.add("scanning");
  button.querySelector(".scan-label").textContent = "Scanning…";
  beginScan();
  const sheet = $("scan-sheet");
  const roots = (state.dashboard && state.dashboard.watched_dirs) || [];
  setScanSheet("running", "Quick scan running", roots.length ? `Checking ${roots[0]}…` : "Checking your watched folders…");
  sheet.hidden = false;
  const started = performance.now();
  let rootIndex = 0;
  let lastSwitch = started;
  scanUi.ticker = setInterval(() => {
    const now = performance.now();
    $("scan-time").textContent = `${((now - started) / 1000).toFixed(1)} s`;
    if (roots.length > 1 && now - lastSwitch > 650) {
      lastSwitch = now;
      rootIndex = (rootIndex + 1) % roots.length;
      $("scan-detail").textContent = `Checking ${roots[rootIndex]}… (${rootIndex + 1} of ${roots.length} folders)`;
    }
  }, 100);

  let report = null;
  let failure = null;
  try {
    report = await call("run_quick_scan");
  } catch (error) {
    failure = error;
  }
  const shown = performance.now() - started;
  if (shown < MIN_SCAN_SHOW_MS) await sleep(MIN_SCAN_SHOW_MS - shown);
  clearInterval(scanUi.ticker);

  button.classList.remove("scanning");
  button.querySelector(".scan-label").textContent = "Quick Scan";
  endScan();
  if (failure) setScanSheet("error", "The scan could not run", errorText(failure));
  else showScanReport(report);
  await refresh(true);
}

// Both scan buttons are locked for the length of either scan.
function beginScan() {
  for (const id of ["quick-scan", "full-scan"]) {
    $(id).dataset.busy = "1"; // the 2 s refresh leaves a busy button alone
    $(id).disabled = true;
  }
  $("hero").classList.add("scanning");
  $("scan-findings").replaceChildren();
  for (const id of ["scan-view", "scan-close", "scan-cancel"]) $(id).hidden = true;
}

function endScan() {
  for (const id of ["quick-scan", "full-scan"]) {
    delete $(id).dataset.busy;
    $(id).disabled = false;
  }
  $("hero").classList.remove("scanning");
  $("scan-cancel").hidden = true;
  $("scan-close").hidden = false;
  state.scanning = false;
}

function scanDuration(ms) {
  const seconds = (ms || 0) / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

function showScanReport(report) {
  const full = Boolean(report.full);
  const name = full ? "Full scan" : "Scan";
  const threats = report.findings.length;
  const took = scanDuration(report.duration_ms);
  $("scan-time").textContent = took;
  const folders = report.roots.length;
  const notes = [
    `${count(report.files_scanned)} of ${count(report.files_examined)} files inspected in ${took} across ${folders} folder${folders === 1 ? "" : "s"}`,
    full ? "report only: nothing was moved" : report.dry_run ? "dry run: nothing was moved" : "",
    report.cloud_skipped ? `${count(report.cloud_skipped)} cloud-only items skipped (not downloaded)` : "",
    report.never_scan ? `${count(report.never_scan)} never-scan place${report.never_scan === 1 ? "" : "s"} not checked` : "",
    report.truncated ? "stopped at the file limit" : "",
  ].filter(Boolean).join(" · ");
  // Folders macOS would not let the scanner open: never report those as clean.
  const blocked = (report.unreadable || []).map(fileName);
  const listed = blocked.slice(0, 3).join(", ") + (blocked.length > 3 ? ` and ${blocked.length - 3} more` : "");
  const blockedNote = blocked.length
    ? `macOS blocked ${listed}. In System Settings > Privacy & Security > Full Disk Access, switch on The Nex's service (the-nex), then scan again.`
    : "";
  if (threats) {
    const title = full
      ? `Full scan flagged ${threats} file${threats === 1 ? "" : "s"} to review`
      : `Scan found ${threats} threat${threats === 1 ? "" : "s"}`;
    setScanSheet("bad", report.cancelled ? `${title} before it was cancelled` : title, [notes, blockedNote].filter(Boolean).join(" · "));
    $("scan-findings").replaceChildren(...report.findings.slice(0, 5).map((f) => el("li", {}, [
      el("span", { className: typeClass(f.threat_type), text: typeLabel(f.threat_type) }),
      el("span", { text: `${fileName(f.path)} · ${f.detail}`, title: f.path }),
    ])));
    $("scan-view").hidden = false;
  } else if (report.cancelled) {
    setScanSheet("error", `${name} cancelled`, `${notes} · nothing flagged so far`);
  } else if (blocked.length) {
    setScanSheet("error", `${name} could not read ${blocked.length} folder${blocked.length === 1 ? "" : "s"}`, [blockedNote, full ? notes : ""].filter(Boolean).join(" "));
  } else if (!report.files_examined && report.never_scan) {
    setScanSheet("error", `${name} checked nothing: everything is on your never-scan list`, notes);
  } else {
    setScanSheet("ok", `${name} complete: no threats found`, notes);
    scanUi.hideTimer = setTimeout(hideScanSheet, 9000);
  }
}

// The background service runs the full scan; this follows its progress file once a second.
// `since` is when it was asked for (0 when re-attaching to a scan already under way).
const FULL_SCAN_START_GRACE_MS = 20000;

async function followFullScan(since) {
  state.scanning = true;
  clearTimeout(scanUi.hideTimer);
  beginScan();
  setScanSheet("running", "Full scan running", "Asking the background service…");
  $("scan-sheet").hidden = false;
  $("scan-cancel").hidden = false;
  $("scan-cancel").disabled = false;
  const watchStart = Date.now();
  // The report only counts if it finished after this scan began: the one from an earlier run is
  // still on disk. `began` is when it was asked for, then the start time the service reports.
  let began = since ? since - 2000 : 0;
  let seen = false;
  let outcome = null;
  let failure = null;
  while (!outcome && !failure) {
    await sleep(1000);
    const progress = await call("scan_progress").catch(() => null);
    const ours = progress && progress.kind === "full";
    if (ours && progress.running) {
      seen = true;
      began = new Date(progress.started_at).getTime();
      $("scan-time").textContent = scanDuration(Date.now() - began);
      $("scan-detail").textContent = `${count(progress.files_examined)} files checked · ${count(progress.findings)} flagged · ${shortPath(progress.current)}`;
      continue;
    }
    const report = await call("last_full_scan").catch(() => null);
    const finished = report && report.finished_at ? new Date(report.finished_at).getTime() : 0;
    if (report && began && finished >= began) outcome = report;
    else if (seen) failure = "The background service stopped before the scan finished. Check that it is running (Settings), then try again.";
    else if (Date.now() - watchStart > FULL_SCAN_START_GRACE_MS) failure = "The background service did not start the scan. Check that it is running (Settings), then try again.";
  }
  endScan();
  if (failure) setScanSheet("error", "The full scan could not run", failure);
  else showScanReport(outcome);
  await refresh(true);
}

async function runFullScan() {
  if (state.scanning) return;
  state.scanning = true;
  try {
    await call("start_full_scan");
  } catch (error) {
    state.scanning = false;
    $("scan-findings").replaceChildren();
    $("scan-view").hidden = true;
    setScanSheet("error", "The full scan could not run", errorText(error));
    $("scan-close").hidden = false;
    $("scan-sheet").hidden = false;
    return;
  }
  await followFullScan(Date.now());
}

// A full scan outlives the window: pick it up again when the dashboard opens.
async function resumeFullScan() {
  const progress = await call("scan_progress").catch(() => null);
  if (progress && progress.kind === "full" && progress.running && !state.scanning) followFullScan(0);
}

function showPage(page) {
  state.page = page;
  const tab = tabOf(page);
  for (const item of document.querySelectorAll(".nav-item")) {
    const active = item.dataset.page === tab;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page"); else item.removeAttribute("aria-current");
  }
  const subpages = SUBPAGES[tab] || [];
  const subnav = $("subnav");
  subnav.hidden = !subpages.length;
  subnav.setAttribute("aria-label", PAGE_TITLES[tab]);
  subnav.replaceChildren(...subpages.map(([id, text]) => el("button", {
    className: "seg-btn", text,
    attrs: { type: "button", "data-goto": id, "aria-pressed": String(id === page) },
  })));
  for (const section of document.querySelectorAll(".page")) section.classList.toggle("active", section.id === `page-${page}`);
  $("page-title").textContent = PAGE_TITLES[tab];
  $("page-sub").textContent = page === "overview" ? greeting() : PAGE_SUBS[page] || "";
  $("search-box").hidden = !SEARCH_PAGES.has(page);
  $("top-status").hidden = page === "overview"; // Home says it large
  showAegis(page === "aegismesh");
  $("drop-overlay").dataset.use = page === "exceptions" ? "skip" : "check";
  call("drop_is_never_scan", { on: page === "exceptions" }).catch(() => {});
  if (page === "devices") document.dispatchEvent(new Event("nex-devices"));
  refresh(true);
}

// The AegisMesh console (three.js, MediaPipe) holds a lot of memory, so it loads when visited
// and unloads after two minutes away; a short detour keeps unsaved rhythm samples and results.
const AEGIS_CONSOLE = "aegismesh/index.html";
const AEGIS_UNLOAD_MS = 120000;
let aegisUnloadTimer = null;

function showAegis(active) {
  const frame = $("aegismesh-frame");
  if (!frame) return;
  const loaded = frame.getAttribute("src") === AEGIS_CONSOLE;
  clearTimeout(aegisUnloadTimer);
  // While its camera is on, the hidden page stays rendered (invisible, inert): a display:none
  // frame gets no video frames, which would freeze an SOS watch.
  const watching = !active && loaded && cameraInUse(frame);
  $("page-aegismesh").classList.toggle("watching", watching);
  frame.inert = watching;
  if (active && !loaded) {
    // Ask macOS for the camera (its popup) while the console loads.
    frame.setAttribute("src", AEGIS_CONSOLE);
    checkCamera();
  } else if (!active && loaded) {
    aegisUnloadTimer = setTimeout(() => {
      if (cameraInUse(frame)) return showAegis(false); // watch still on: look again later
      $("page-aegismesh").classList.remove("watching");
      frame.inert = false;
      frame.setAttribute("src", "about:blank");
    }, AEGIS_UNLOAD_MS);
  }
}

function cameraInUse(frame) {
  try {
    return [...frame.contentDocument.querySelectorAll("video")].some((v) => v.srcObject && v.srcObject.active);
  } catch {
    return false;
  }
}

async function checkCamera() {
  if (!invoke) return;
  try {
    const access = await call("camera_access");
    if (access !== "granted") $("camera-dialog").showModal();
  } catch {
    /* no answer to the popup: the console shows its own camera message */
  }
}

function wireCameraDialog() {
  const dialog = $("camera-dialog");
  $("camera-later").addEventListener("click", () => dialog.close());
  $("camera-settings").addEventListener("click", () => {
    dialog.close();
    call("open_camera_settings").catch((error) => notice(errorText(error), true));
  });
}

/** The Setup checklist's buttons do what the matching controls elsewhere already do. */
function runSetupAction(id) {
  if (id === "install") $("install-service").click();
  else if (id === "decoys") $("verify-canaries").click();
  else if (id === "open_disk_settings") call("open_full_disk_settings").catch((error) => notice(errorText(error), true));
  else if (id === "dry_run_off") call("toggle_engine", { engine: "dry_run", enabled: false }).then(() => refresh(true)).catch((error) => notice(errorText(error), true));
}

async function toggleEngine(button) {
  const engine = button.dataset.engine;
  if (state.pendingToggles.has(engine)) return;
  const enabled = button.getAttribute("aria-checked") !== "true";
  state.pendingToggles.add(engine);
  for (const twin of document.querySelectorAll(`.switch[data-engine="${engine}"]`)) { setSwitch(twin, enabled); twin.disabled = true; }
  try {
    const toggles = await call("toggle_engine", { engine, enabled });
    state.pendingToggles.delete(engine);
    renderToggles(toggles, true);
  } catch (error) {
    state.pendingToggles.delete(engine);
    for (const twin of document.querySelectorAll(`.switch[data-engine="${engine}"]`)) { setSwitch(twin, !enabled); twin.disabled = false; }
    notice(errorText(error), true);
  }
  await refresh(true);
}

function wire() {
  buildEngineRows();
  wireCameraDialog();
  for (const item of document.querySelectorAll(".nav-item")) item.addEventListener("click", () => showPage(item.dataset.page));
  // Anything with data-goto opens that page (tiles, engine cards, score items, links); a switch
  // inside a card still only toggles. data-focus also highlights one engine on the Engines page.
  const go = (target) => {
    if (target.dataset.goto === "activity") openActivity();
    else showPage(target.dataset.goto);
    if (target.dataset.focus) focusEngine(target.dataset.focus);
  };
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-goto]");
    if (target && !event.target.closest(".switch")) go(target);
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest(".switch[data-engine]");
    if (button && !button.disabled) toggleEngine(button);
  });
  for (const pill of document.querySelectorAll(".pill-filter")) {
    pill.addEventListener("click", () => {
      state.severity = pill.dataset.severity;
      for (const other of document.querySelectorAll(".pill-filter")) other.classList.toggle("active", other === pill);
      refresh(true);
    });
  }

  const search = $("search");
  let searchTimer = null;
  search.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = search.value.trim();
      refresh(true);
    }, 150);
  });
  search.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      search.value = "";
      state.query = "";
      search.blur();
      refresh(true);
    }
  });
  const mac = /Mac/i.test(navigator.platform || navigator.userAgent);
  $("search-hint").textContent = mac ? "⌘ K" : "Ctrl K";
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      search.focus();
      search.select();
    }
  });

  $("quick-scan").addEventListener("click", runQuickScan);
  $("full-scan").addEventListener("click", runFullScan);
  $("scan-cancel").addEventListener("click", () => {
    $("scan-cancel").disabled = true;
    $("scan-title").textContent = "Cancelling…";
    call("cancel_scan").catch((error) => notice(errorText(error), true));
  });
  $("scan-close").addEventListener("click", hideScanSheet);
  $("scan-view").addEventListener("click", () => { hideScanSheet(); openActivity(); });
  $("verify-canaries").addEventListener("click", () => busy("verify-canaries", "Verifying…", async () => {
    const canaries = await call("verify_canaries");
    const intact = canaries.filter((c) => c.state === "Intact").length;
    notice(`${intact} of ${canaries.length} decoy files in place.`, intact !== canaries.length);
  }));
  $("week").addEventListener("toggle", () => refresh(true));
  wireScheduleAndReport();
  $("report-problem").addEventListener("click", () => {
    call("open_report_page", { kind: "bug" }).catch((error) => notice(errorText(error), true));
  });
  $("skip-form").addEventListener("submit", addNeverScan);
  $("skip-path").addEventListener("input", () => showSkipChoice(null));
  $("install-service").addEventListener("click", () => busy("install-service", "Installing…", async () => {
    notice(await call("install_service"), false);
  }));
  $("uninstall-service").addEventListener("click", () => busy("uninstall-service", "Removing…", async () => {
    notice(await call("uninstall_service"), false);
  }));
  wireOpenAsAdmin();
}

/* Windows only: the row stays hidden elsewhere. */
async function wireOpenAsAdmin() {
  const button = $("open-as-admin");
  const show = (choice) => {
    $("admin-row").hidden = !choice.available;
    setSwitch(button, choice.on);
    $("admin-state").textContent = choice.elevated
      ? "This window is running as administrator."
      : choice.on ? "Takes effect the next time The Nex opens." : "";
  };
  try { show(await call("get_open_as_admin")); } catch { return; }
  button.addEventListener("click", async () => {
    try { show(await call("set_open_as_admin", { on: button.getAttribute("aria-checked") !== "true" })); }
    catch (error) { notice(errorText(error), true); }
  });
}

/* ---- Appearance: wallpaper layer + glass theme ------------------------------------------- */

const APPEARANCE_KEY = "thenex.appearance";
const DEFAULT_APPEARANCE = Object.freeze({ wallpaper_source: "preset:matte", bg_dim: 0, card_blur: 12, card_alpha: 0.95 });
// Before 0.3.1 the default was Matte Dark; a look still exactly on that old default was never
// customised, so it moves to the new default.
// The same goes for the 0.3.x Aurora default, replaced by the solid paper look.
const OLD_DEFAULTS = [
  { wallpaper_source: "preset:matte", bg_dim: 0.65, card_blur: 14, card_alpha: 0.72 },
  { wallpaper_source: "preset:aurora", bg_dim: 0.2, card_blur: 18, card_alpha: 0.62 },
];
const MAX_WALLPAPER_BYTES = 25 * 1024 * 1024;
const WALLPAPER_FILE_NAME = /\.(png|jpe?g|webp|gif)$/i;
const WALLPAPER_MIME = /^image\/(png|jpeg|webp|gif)$/;
const VALID_SOURCE = /^(preset:(aurora|matte|crimson|cyberhex)|url:https:\/\/\S+|file:wallpaper-[A-Za-z0-9-]+\.(png|jpe?g|webp|gif))$/i;
const SAVE_DELAY_MS = 350;
const IMAGE_TIMEOUT_MS = 20000;

const CRIMSON_CSS = [
  "radial-gradient(120% 80% at 76% 14%, rgba(239, 68, 68, 0.55) 0%, rgba(127, 29, 29, 0.32) 32%, transparent 62%)",
  "radial-gradient(90% 70% at 14% 92%, rgba(153, 27, 27, 0.55) 0%, transparent 62%)",
  "radial-gradient(55% 45% at 52% 56%, rgba(76, 5, 25, 0.85) 0%, transparent 72%)",
  "linear-gradient(160deg, #1d0508 0%, #0b0608 55%, #050506 100%)",
].join(", ");

// Pointy-top honeycomb: one 60 x 103.92 tile holds a hexagon plus the stub to the row below.
function hexVertex(i, j, corner) {
  const offsets = { t: [30, 0], ur: [60, 17.32], lr: [60, 51.96], b: [30, 69.28], ll: [0, 51.96], ul: [0, 17.32], s: [30, 103.92] };
  const [dx, dy] = offsets[corner];
  return `${(60 * i + dx).toFixed(2)},${(103.92 * j + dy).toFixed(2)}`;
}

function cyberHexCss() {
  const amber = "#F5A524";
  const cyan = "#38BDF8";
  const traces = [
    [amber, [[3, 1, "ul"], [3, 1, "t"], [3, 1, "ur"], [3, 1, "lr"], [3, 1, "b"], [3, 1, "s"]]],
    [cyan, [[9, 3, "ll"], [9, 3, "ul"], [9, 3, "t"], [9, 3, "ur"]]],
    [amber, [[17, 6, "t"], [17, 6, "ur"], [17, 6, "lr"], [17, 6, "b"], [17, 6, "ll"]]],
    [cyan, [[24, 2, "b"], [24, 2, "s"], [24, 3, "ur"], [24, 3, "lr"]]],
    [amber, [[28, 7, "ul"], [28, 7, "t"], [28, 7, "ur"]]],
    [cyan, [[12, 8, "lr"], [12, 8, "b"], [12, 8, "ll"], [12, 8, "ul"]]],
    [amber, [[30, 0, "ll"], [30, 0, "b"], [30, 0, "s"]]],
    [cyan, [[6, 7, "t"], [6, 7, "ur"], [6, 7, "lr"]]],
  ];
  const lines = traces.map(([color, points]) => {
    const pts = points.map(([i, j, corner]) => hexVertex(i, j, corner)).join(" ");
    return `<polyline points='${pts}' stroke='${color}' stroke-width='6' stroke-opacity='.45' filter='url(#g)'/>` +
      `<polyline points='${pts}' stroke='${color}' stroke-width='1.6'/>`;
  }).join("");
  const svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1920 1080' preserveAspectRatio='xMidYMid slice'>" +
    "<defs>" +
    "<radialGradient id='a' cx='22%' cy='18%' r='62%'><stop offset='0' stop-color='#0E3A4A' stop-opacity='.9'/><stop offset='1' stop-color='#05080D' stop-opacity='0'/></radialGradient>" +
    "<radialGradient id='b' cx='86%' cy='88%' r='55%'><stop offset='0' stop-color='#3D2A08' stop-opacity='.85'/><stop offset='1' stop-color='#05080D' stop-opacity='0'/></radialGradient>" +
    "<pattern id='h' width='60' height='103.92' patternUnits='userSpaceOnUse'><path d='M30 0L60 17.32V51.96L30 69.28L0 51.96V17.32ZM30 69.28V103.92' fill='none' stroke='#7DD3FC' stroke-opacity='.16' stroke-width='1.2'/></pattern>" +
    "<filter id='g' x='-10%' y='-10%' width='120%' height='120%'><feGaussianBlur stdDeviation='4'/></filter>" +
    "</defs>" +
    "<rect width='1920' height='1080' fill='#05080D'/><rect width='1920' height='1080' fill='url(#a)'/>" +
    "<rect width='1920' height='1080' fill='url(#b)'/><rect width='1920' height='1080' fill='url(#h)'/>" +
    `<g fill='none' stroke-linecap='round' stroke-linejoin='round'>${lines}</g></svg>`;
  return `url("data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}")`;
}

// Deep navy (or, in light mode, pale sky) with blue, violet and teal glows and two soft
// light streaks.
function auroraCss(light) {
  const base = light ? ["#F7F9FF", "#EEF2FC", "#E6ECFA"] : ["#0C1333", "#070A1B", "#04060E"];
  const glow = light ? [".45", ".38", ".30", ".16"] : [".55", ".5", ".26", ".16"];
  const svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1600 900' preserveAspectRatio='xMidYMid slice'>" +
    "<defs>" +
    `<linearGradient id='bg' x1='0' y1='0' x2='.4' y2='1'><stop offset='0' stop-color='${base[0]}'/><stop offset='.55' stop-color='${base[1]}'/><stop offset='1' stop-color='${base[2]}'/></linearGradient>` +
    `<radialGradient id='g1' cx='8%' cy='0%' r='55%'><stop offset='0' stop-color='${light ? "#9DB8FF" : "#4F7BFF"}' stop-opacity='${glow[0]}'/><stop offset='1' stop-color='#4F7BFF' stop-opacity='0'/></radialGradient>` +
    `<radialGradient id='g2' cx='96%' cy='8%' r='48%'><stop offset='0' stop-color='${light ? "#CBB4FF" : "#9B6BFF"}' stop-opacity='${glow[1]}'/><stop offset='1' stop-color='#9B6BFF' stop-opacity='0'/></radialGradient>` +
    `<radialGradient id='g3' cx='82%' cy='100%' r='50%'><stop offset='0' stop-color='${light ? "#8EEBD9" : "#2EE6C5"}' stop-opacity='${glow[2]}'/><stop offset='1' stop-color='#2EE6C5' stop-opacity='0'/></radialGradient>` +
    `<radialGradient id='g4' cx='12%' cy='96%' r='40%'><stop offset='0' stop-color='${light ? "#FFB3D1" : "#FF5FA2"}' stop-opacity='${glow[3]}'/><stop offset='1' stop-color='#FF5FA2' stop-opacity='0'/></radialGradient>` +
    "<linearGradient id='s1' x1='0' x2='1'><stop offset='0' stop-color='#5B8CFF' stop-opacity='0'/><stop offset='.45' stop-color='#7A6BFF' stop-opacity='.85'/><stop offset='.75' stop-color='#C46BFF' stop-opacity='.6'/><stop offset='1' stop-color='#C46BFF' stop-opacity='0'/></linearGradient>" +
    "<linearGradient id='s2' x1='0' x2='1'><stop offset='0' stop-color='#2EE6C5' stop-opacity='0'/><stop offset='.5' stop-color='#4FC3FF' stop-opacity='.7'/><stop offset='1' stop-color='#5B8CFF' stop-opacity='0'/></linearGradient>" +
    "<filter id='w' x='-20%' y='-50%' width='140%' height='200%'><feGaussianBlur stdDeviation='26'/></filter>" +
    "<filter id='n' x='-10%' y='-50%' width='120%' height='200%'><feGaussianBlur stdDeviation='2.2'/></filter>" +
    "</defs>" +
    "<rect width='1600' height='900' fill='url(#bg)'/>" +
    "<rect width='1600' height='900' fill='url(#g1)'/><rect width='1600' height='900' fill='url(#g2)'/>" +
    "<rect width='1600' height='900' fill='url(#g3)'/><rect width='1600' height='900' fill='url(#g4)'/>" +
    "<g fill='none' stroke-linecap='round'>" +
    "<path d='M-120 760C260 560 620 860 980 600S1500 260 1760 300' stroke='url(#s1)' stroke-width='90' opacity='.35' filter='url(#w)'/>" +
    "<path d='M-120 760C260 560 620 860 980 600S1500 260 1760 300' stroke='url(#s1)' stroke-width='3' opacity='.8' filter='url(#n)'/>" +
    "<path d='M-120 800C300 620 640 900 1000 650S1520 330 1760 360' stroke='url(#s1)' stroke-width='1.5' opacity='.55' filter='url(#n)'/>" +
    "<path d='M-80 880C360 720 760 820 1120 700S1500 560 1720 520' stroke='url(#s2)' stroke-width='70' opacity='.22' filter='url(#w)'/>" +
    "<path d='M-80 880C360 720 760 820 1120 700S1500 560 1720 520' stroke='url(#s2)' stroke-width='2' opacity='.6' filter='url(#n)'/>" +
    "</g></svg>";
  return `url("data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}")`;
}

const PRESETS = [
  { id: "aurora", label: "Aurora", css: () => auroraCss(isLight()) },
  {
    id: "matte",
    label: "Matte",
    css: "none",
    swatch: () => (isLight() ? "linear-gradient(135deg, #FFFFFF 0%, #EFEFED 100%)" : "linear-gradient(135deg, #1A1C1A 0%, #0B0C0B 100%)"),
  },
  { id: "crimson", label: "Crimson Abyss", css: CRIMSON_CSS },
  { id: "cyberhex", label: "Cyber Hex", css: cyberHexCss() },
];

const look = { current: { ...DEFAULT_APPEARANCE }, css: "none", previewUrl: null, saveTimer: null };

function clampNumber(value, low, high, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(high, Math.max(low, number)) : fallback;
}

function isOldDefault(a) {
  return Boolean(a) && OLD_DEFAULTS.some((old) => Object.keys(old).every((key) => a[key] === old[key]));
}

function normalizeAppearance(value) {
  const a = value && typeof value === "object" ? (isOldDefault(value) ? DEFAULT_APPEARANCE : value) : {};
  const source = typeof a.wallpaper_source === "string" && VALID_SOURCE.test(a.wallpaper_source) && !(invoke && /^url:/i.test(a.wallpaper_source)) // the CSP blocks remote images in the app
    ? a.wallpaper_source
    : DEFAULT_APPEARANCE.wallpaper_source;
  return {
    wallpaper_source: source,
    bg_dim: clampNumber(a.bg_dim, 0, 0.9, DEFAULT_APPEARANCE.bg_dim),
    card_blur: clampNumber(a.card_blur, 0, 24, DEFAULT_APPEARANCE.card_blur),
    card_alpha: clampNumber(a.card_alpha, 0.85, 1, DEFAULT_APPEARANCE.card_alpha),
  };
}

// Quoted CSS url(); quotes, backslashes and line breaks are escaped so a URL cannot break out.
function cssUrl(url) {
  return `url("${String(url).replace(/["\\\n\r\f]/g, (c) => `\\${c.charCodeAt(0).toString(16)} `)}")`;
}

function fileWallpaperUrl(name) {
  const convert = tauri && tauri.core && tauri.core.convertFileSrc;
  return typeof convert === "function" ? convert(name, "wallpaper") : null;
}

function imageSource(source) {
  if (source.startsWith("url:")) return source.slice(4);
  if (source.startsWith("file:")) return fileWallpaperUrl(source.slice(5));
  return null;
}

const resolve = (value) => (typeof value === "function" ? value() : value);

function wallpaperCss(source) {
  if (source.startsWith("preset:")) {
    const preset = PRESETS.find((p) => p.id === source.slice(7));
    return preset ? resolve(preset.css) : "none";
  }
  const src = imageSource(source);
  return src ? cssUrl(src) : "none";
}

function wallpaperLabel(source) {
  if (look.previewUrl) return "Preview · not saved";
  if (source.startsWith("preset:")) {
    const preset = PRESETS.find((p) => p.id === source.slice(7));
    return preset ? preset.label : "Preset";
  }
  if (source.startsWith("file:")) return "Custom image";
  try {
    return new URL(source.slice(4)).hostname;
  } catch {
    return "Web image";
  }
}

function readMirror() {
  try {
    return JSON.parse(localStorage.getItem(APPEARANCE_KEY) || "null");
  } catch {
    return null;
  }
}

function writeMirror(appearance, css) {
  try {
    localStorage.setItem(APPEARANCE_KEY, JSON.stringify({ ...appearance, css }));
  } catch {
    /* storage full or disabled: settings.json still has it */
  }
}

function setSlider(id, value, text) {
  const input = $(id);
  if (document.activeElement !== input) input.value = String(value);
  $(`${id}-value`).textContent = text;
}

function updateAppearanceControls() {
  const a = look.current;
  setSlider("bg-dim", Math.round(a.bg_dim * 100), `${Math.round(a.bg_dim * 100)}%`);
  setSlider("card-blur", Math.round(a.card_blur), `${Math.round(a.card_blur)}px`);
  setSlider("card-alpha", Math.round(a.card_alpha * 100), `${Math.round(a.card_alpha * 100)}%`);
  for (const chip of document.querySelectorAll(".preset")) {
    const active = !look.previewUrl && a.wallpaper_source === `preset:${chip.dataset.preset}`;
    chip.setAttribute("aria-pressed", active ? "true" : "false");
  }
  $("wallpaper-label").textContent = wallpaperLabel(a.wallpaper_source);
}

function applyAppearance(appearance, css) {
  const style = document.documentElement.style;
  style.setProperty("--bg-dim", String(appearance.bg_dim));
  style.setProperty("--card-blur", `${appearance.card_blur}px`);
  style.setProperty("--card-alpha", String(appearance.card_alpha));
  style.setProperty("--wallpaper", css);
  look.current = appearance;
  look.css = css;
  if (!look.previewUrl) writeMirror(appearance, css);
  updateAppearanceControls();
}

function appearanceStatus(text, kind) {
  const status = $("appearance-status");
  status.textContent = text;
  status.className = `small ${kind || "muted"}`;
}

function sentence(text) {
  const value = String(text || "");
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : value;
}

async function persistAppearance() {
  if (!invoke) return;
  try {
    const saved = normalizeAppearance(await call("save_appearance", { appearance: look.current }));
    if (saved.wallpaper_source !== look.current.wallpaper_source) applyAppearance(saved, wallpaperCss(saved.wallpaper_source));
  } catch (error) {
    appearanceStatus(`Could not save the appearance: ${errorText(error)}`, "error");
  }
}

function schedulePersist() {
  clearTimeout(look.saveTimer);
  look.saveTimer = setTimeout(persistAppearance, SAVE_DELAY_MS);
}

function clearPreview() {
  if (look.previewUrl) URL.revokeObjectURL(look.previewUrl);
  look.previewUrl = null;
}

function commitAppearance(appearance) {
  clearPreview();
  const next = normalizeAppearance(appearance);
  applyAppearance(next, wallpaperCss(next.wallpaper_source));
  schedulePersist();
}

function loadImage(src) {
  return new Promise((resolve, reject) => {
    if (!src) {
      reject(new Error("this wallpaper needs The Nex desktop app"));
      return;
    }
    const image = new Image();
    const timer = setTimeout(() => reject(new Error("the image took too long to load")), IMAGE_TIMEOUT_MS);
    image.onload = () => { clearTimeout(timer); resolve(); };
    image.onerror = () => { clearTimeout(timer); reject(new Error("the image could not be displayed (the site may block embedding)")); };
    image.src = src;
  });
}

const APPEARANCE_CONTROLS = ["apply-wallpaper-url", "choose-wallpaper-file", "reset-appearance", "wallpaper-url"];

async function withAppearanceBusy(label, work) {
  const controls = [...APPEARANCE_CONTROLS.map($), ...document.querySelectorAll(".preset")];
  for (const control of controls) control.disabled = true;
  appearanceStatus(label, "muted");
  try {
    await work();
  } catch (error) {
    appearanceStatus(sentence(errorText(error)), "error");
  } finally {
    for (const control of controls) control.disabled = false;
  }
}

function applyWallpaperUrl() {
  const input = $("wallpaper-url");
  const raw = input.value.trim();
  if (!raw) {
    appearanceStatus("Paste an image or wallpaper page address first.", "error");
    input.focus();
    return Promise.resolve();
  }
  return withAppearanceBusy("Fetching wallpaper…", async () => {
    let imageUrl = raw;
    if (invoke) imageUrl = await call("resolve_wallpaper_url", { url: raw });
    else if (!/^https:\/\/\S+$/i.test(raw)) throw new Error("enter a full https:// address");
    let source = `url:${imageUrl}`;
    let note = "";
    if (invoke) {
      source = `file:${await call("download_wallpaper", { url: imageUrl })}`; // a failed download is shown, never hot-linked
      note = " · saved for offline use";
    }
    await loadImage(imageSource(source));
    commitAppearance({ ...look.current, wallpaper_source: source });
    input.value = "";
    appearanceStatus(`Wallpaper applied${note}.`, "ok");
  });
}

function applyWallpaperFile(file) {
  if (!file) return Promise.resolve();
  return withAppearanceBusy("Saving image…", async () => {
    if (!WALLPAPER_FILE_NAME.test(file.name) && !WALLPAPER_MIME.test(file.type)) throw new Error("choose a PNG, JPG, WEBP or GIF image");
    if (file.size > MAX_WALLPAPER_BYTES) throw new Error("images up to 25 MB are supported");
    if (!invoke) {
      const url = URL.createObjectURL(file);
      await loadImage(url);
      clearPreview();
      look.previewUrl = url;
      applyAppearance(look.current, cssUrl(url));
      appearanceStatus("Previewing only: open The Nex desktop app to keep a local wallpaper.", "ok");
      return;
    }
    // Raw bytes (not JSON) so a 25 MB image is not inflated into a number array.
    const name = await invoke("save_wallpaper_file", new Uint8Array(await file.arrayBuffer()));
    const source = `file:${name}`;
    await loadImage(imageSource(source));
    commitAppearance({ ...look.current, wallpaper_source: source });
    appearanceStatus("Wallpaper applied · stored in the app's data folder.", "ok");
  });
}

function buildPresetChips() {
  $("wallpaper-presets").replaceChildren(...PRESETS.map((preset) => {
    const swatch = el("span", { className: "swatch" });
    swatch.style.backgroundImage = resolve(preset.swatch) || resolve(preset.css);
    const chip = el("button", { className: "preset", attrs: { type: "button", "data-preset": preset.id, "aria-pressed": "false" } }, [
      swatch,
      el("span", { text: preset.label }),
    ]);
    chip.addEventListener("click", () => {
      commitAppearance({ ...look.current, wallpaper_source: `preset:${preset.id}` });
      appearanceStatus(`${preset.label} applied.`, "ok");
    });
    return chip;
  }));
}

function wireAppearance() {
  buildPresetChips();
  const sliders = [
    ["bg-dim", "bg_dim", (value) => value / 100],
    ["card-blur", "card_blur", (value) => value],
    ["card-alpha", "card_alpha", (value) => value / 100],
  ];
  for (const [id, key, scale] of sliders) {
    $(id).addEventListener("input", (event) => {
      const next = normalizeAppearance({ ...look.current, [key]: scale(Number(event.target.value)) });
      applyAppearance(next, look.css);
      if (!look.previewUrl) schedulePersist();
    });
  }
  $("apply-wallpaper-url").addEventListener("click", applyWallpaperUrl);
  $("wallpaper-url").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      applyWallpaperUrl();
    }
  });
  $("choose-wallpaper-file").addEventListener("click", () => $("wallpaper-file").click());
  $("wallpaper-file").addEventListener("change", (event) => {
    const [file] = event.target.files || [];
    event.target.value = "";
    applyWallpaperFile(file);
  });
  $("reset-appearance").addEventListener("click", () => {
    $("wallpaper-url").value = "";
    commitAppearance({ ...DEFAULT_APPEARANCE });
    appearanceStatus("Default look restored.", "ok");
  });
}

/* ---- Theme: dark, light or match the system ---------------------------------------------- */

const THEME_KEY = "thenex.theme";
const lightQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;

function themePref() {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return value === "dark" || value === "system" ? value : "light";
  } catch {
    return "light";
  }
}

function isLight() {
  const pref = themePref();
  return pref === "light" || (pref === "system" && Boolean(lightQuery && lightQuery.matches));
}

function applyTheme() {
  document.documentElement.dataset.theme = isLight() ? "light" : "dark";
  // The macOS glass behind the page follows the window theme, not the page; keep them matched.
  const win = tauri && tauri.window && tauri.window.getCurrentWindow ? tauri.window.getCurrentWindow() : null;
  if (win) win.setTheme(themePref() === "system" ? null : isLight() ? "light" : "dark").catch(() => {});
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.setAttribute("aria-pressed", String(button.dataset.themeChoice === themePref()));
  }
  // The app draws its preset wallpapers in a light and a dark version.
  if (!look.previewUrl) applyAppearance(look.current, wallpaperCss(look.current.wallpaper_source));
  buildPresetChips();
  updateAppearanceControls();
}

function setTheme(pref) {
  try {
    localStorage.setItem(THEME_KEY, pref);
  } catch {
    /* storage disabled: the choice lasts until the window closes */
  }
  applyTheme();
}

function wireTheme() {
  $("theme-toggle").addEventListener("click", () => setTheme(isLight() ? "dark" : "light"));
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.addEventListener("click", () => setTheme(button.dataset.themeChoice));
  }
  if (lightQuery && lightQuery.addEventListener) lightQuery.addEventListener("change", () => { if (themePref() === "system") applyTheme(); });
}

async function initAppearance() {
  wireAppearance();
  const start = normalizeAppearance(readMirror() || DEFAULT_APPEARANCE);
  applyAppearance(start, wallpaperCss(start.wallpaper_source));
  if (!invoke) return;
  try {
    const stored = normalizeAppearance(await call("get_appearance"));
    if (JSON.stringify(stored) !== JSON.stringify(start)) applyAppearance(stored, wallpaperCss(stored.wallpaper_source));
  } catch {
    /* keep the mirrored look; settings.json is unreadable right now */
  }
}

let refreshTimer = null;
function openMenuPage(page) {
  if (page === "fullscan") runFullScan();
  else if (page === "activity") openActivity();
  else if (["quarantine", "settings"].includes(page)) showPage(page);
}

function startDashboard() {
  wire();
  if (window.NexSync) window.NexSync.start(call);
  call("drop_is_never_scan", { on: false }).catch(() => {}); // a reload starts on the first page
  // Offline assistant (ui/bot.js): read-only, starts only after sign-in like everything else here.
  if (window.NexBot) window.NexBot.start({ call, showPage, openActivity });
  if (window.NexFileCheck) window.NexFileCheck.start(copyButton, takeDrop); // drop a file on the window to check it
  if (window.NexStartup) window.NexStartup.start({ call, el, expandable, detailGrid, chevron, errorText });
  if (window.NexSetup) window.NexSetup.start({ copyButton, run: runSetupAction });
  $("page-sub").textContent = greeting();
  wireTheme();
  initAppearance().then(applyTheme);
  refresh(true);
  resumeFullScan();
  refreshTimer = setInterval(() => document.hidden || refresh(false), REFRESH_MS);
  document.addEventListener("visibilitychange", () => document.hidden || refresh(false));
  const events = window.__TAURI__ && window.__TAURI__.event;
  if (events) {
    // Menu-bar shortcuts (macOS); only known pages are honoured.
    events.listen("menubar://navigate", (e) => openMenuPage(e.payload));
    // A window the menu bar just rebuilt names its page in the address instead.
    openMenuPage(location.hash.slice(1));
    // One-shot: a reload (sign-out, lost session) must not land on that page again.
    if (location.hash) history.replaceState(null, "", location.pathname + location.search);
    events.listen("menubar://refresh", () => refresh(true));
  }
}

// Fail closed: the dashboard only starts once NexAuth confirms a valid session.
if (window.NexAuth && window.NexAuth.gate) window.NexAuth.gate(startDashboard);
