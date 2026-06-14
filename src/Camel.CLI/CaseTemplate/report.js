"use strict";
/*
 * Camel Audit Trail Viewer - static, dependency-free.
 *
 * Reads a per-case CLEF audit log (one JSON object per line, as written by Runtime.AuditEvent) and lets an
 * investigator (1) browse every recorded FINDING and trace it to the exact execution-log entries that prove it,
 * and (2) browse/filter the whole audit trail by event type, execution id, and free text.
 *
 * The trace relationship: a `finding` event carries its own `ExecutionId` (the Execute call that recorded it) and
 * `EvidenceExecutionIds` (the cited proof). Every `execution` (script + completed/failed status) and `command`
 * (individual tool invocation) event tagged with one of those ids belongs to the finding's chain of custody.
 */

const CASE_ID = document.body.dataset.caseId || "";
const CONF_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, SPECULATIVE: 3 };

// Parsed state.
let EVENTS = [];                 // all events, in file order, each annotated with a parsed Date `_t`
let BY_EXEC = new Map();         // executionId -> array of events
let SELECTED_FINDING = -1;       // index into EVENTS of the selected finding

// ---------- helpers ----------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids) if (kid !== null && kid !== undefined) n.append(kid.nodeType ? kid : document.createTextNode(kid));
  return n;
};
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtTime = (d) => d && !isNaN(d) ? d.toISOString().replace("T", " ").replace("Z", "Z").slice(0, 23) : "";
const splitIds = (s) => String(s ?? "").split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

// ---------- parsing ----------
function parseClef(text) {
  const events = [];
  let bad = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    try {
      const o = JSON.parse(line);
      o._t = o["@t"] ? new Date(o["@t"]) : null;
      events.push(o);
    } catch { bad++; }
  }
  return { events, bad };
}

function index() {
  BY_EXEC = new Map();
  for (const e of EVENTS) {
    const id = e.ExecutionId;
    if (!id) continue;
    if (!BY_EXEC.has(id)) BY_EXEC.set(id, []);
    BY_EXEC.get(id).push(e);
  }
}

// One-line human summary for the audit table / row.
function summarize(e) {
  switch (e.EventType) {
    case "command":
      return `${e.Toolkit ? e.Toolkit + "." : ""}${e.Operation || ""}  ${e.Command || ""} ${e.Arguments || ""}`.trim();
    case "execution":
      return e.Phase === "started"
        ? `EXECUTION started`
        : `EXECUTION ${e.Phase} (success=${e.Success}, ${e.DurationMs}ms)`;
    case "finding":
      return `[${e.Confidence}] ${e.Observation || ""}`;
    case "evidence":
      return e.Paths ? `Registered ${e.Count} item(s): ${e.Paths}` : (e.Message || "evidence");
    case "case":
      return `Case set to ${e.CaseId}${e.Previous ? ` (was ${e.Previous})` : ""}`;
    default:
      return e.Message || e.Observation || JSON.stringify(stripMeta(e));
  }
}

function stripMeta(e) {
  const o = {};
  for (const [k, v] of Object.entries(e)) if (!k.startsWith("@") && k !== "_t") o[k] = v;
  return o;
}

// ---------- findings view ----------
function findingEvents() {
  return EVENTS.map((e, i) => ({ e, i }))
    .filter((x) => x.e.EventType === "finding")
    .sort((a, b) => {
      const ca = CONF_ORDER[a.e.Confidence] ?? 9, cb = CONF_ORDER[b.e.Confidence] ?? 9;
      return ca - cb || (a.e._t - b.e._t);
    });
}

function renderFindingsList() {
  const list = $("#findingsList");
  list.innerHTML = "";
  const findings = findingEvents();
  $("#findCount").textContent = `(${findings.length})`;
  if (!findings.length) {
    list.append(el("p", { class: "empty" }, "No findings recorded in this audit log."));
    return;
  }
  for (const { e, i } of findings) {
    const conf = e.Confidence || "default";
    const card = el("div", { class: "fcard" + (i === SELECTED_FINDING ? " sel" : ""), "data-i": i, onclick: () => selectFinding(i) },
      el("div", { class: "frow" },
        el("span", { class: "badge b-" + (CONF_ORDER[conf] !== undefined ? conf : "default") }, conf),
        el("span", {}, fmtTime(e._t))),
      el("p", { class: "obs" }, truncate(e.Observation, 200)));
    list.append(card);
  }
}

const truncate = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

function selectFinding(i) {
  SELECTED_FINDING = i;
  $$("#findingsList .fcard").forEach((c) => c.classList.toggle("sel", +c.dataset.i === i));
  renderFindingDetail(EVENTS[i]);
}

function renderFindingDetail(f) {
  const d = $("#findingDetail");
  d.innerHTML = "";
  const conf = f.Confidence || "default";
  d.append(
    el("div", {},
      el("span", { class: "badge b-" + (CONF_ORDER[conf] !== undefined ? conf : "default") }, conf),
      el("span", { class: "pill", style: "margin-left:10px" }, fmtTime(f._t))),
    kv("Observation (what was seen)", f.Observation),
    kv("Interpretation (what it means)", f.Interpretation),
  );

  // Evidence execution ids cited as proof, plus the execution that recorded the finding.
  const evidenceIds = splitIds(f.EvidenceExecutionIds);
  const recordedIn = f.ExecutionId;
  const idsRow = el("div", { class: "kv" }, el("div", { class: "k" }, "Cited evidence executions"));
  const v = el("div", { class: "v" });
  if (evidenceIds.length) {
    evidenceIds.forEach((id, idx) => {
      if (idx) v.append(document.createTextNode("  "));
      v.append(el("span", { class: "execid", onclick: () => jumpToExec(id) }, id));
    });
  } else v.append(el("span", { class: "pill" }, "(none cited)"));
  idsRow.append(v);
  d.append(idsRow);

  // The trace: expand each cited evidence execution (and the recording execution) into its log entries.
  d.append(el("div", { class: "k", style: "margin-top:18px" }, "Chain of custody — audit-log entries"));
  const trace = el("div", { class: "trace" });
  const seen = new Set();
  const order = [...evidenceIds, recordedIn].filter((id) => id && !seen.has(id) && seen.add(id));
  if (!order.length) trace.append(el("p", { class: "empty" }, "No execution ids associated with this finding."));
  for (const id of order) trace.append(renderExecBlock(id, id === recordedIn && !evidenceIds.includes(id)));
  d.append(trace);
}

function kv(k, val) {
  return el("div", { class: "kv" }, el("div", { class: "k" }, k), el("div", { class: "v" }, val || "—"));
}

// Render one execution id as a block: its script, every command it ran, and its terminal status.
function renderExecBlock(execId, recordingOnly) {
  const evs = (BY_EXEC.get(execId) || []).slice().sort((a, b) => (a._t || 0) - (b._t || 0));
  const started = evs.find((e) => e.EventType === "execution" && e.Phase === "started");
  const terminal = evs.find((e) => e.EventType === "execution" && e.Phase !== "started");
  const cmds = evs.filter((e) => e.EventType === "command");

  const statusTxt = terminal
    ? `${terminal.Phase}${terminal.DurationMs != null ? " · " + terminal.DurationMs + "ms" : ""}`
    : (evs.length ? "(no terminal status)" : "(execution not found in this log)");
  const statusClass = terminal && terminal.Success === false ? "exit-bad" : "exit-ok";

  const block = el("div", { class: "exec-block" });
  block.append(el("div", { class: "exec-head" },
    el("span", { class: "execid", onclick: () => jumpToExec(execId) }, execId),
    el("span", { class: "status " + statusClass }, statusTxt),
    el("span", { class: "spacer", style: "flex:1" }),
    el("span", { class: "pill" }, recordingOnly ? "recorded the finding" : `${cmds.length} command(s)`)));

  if (started && started.Script) block.append(el("div", { class: "script" }, started.Script));

  if (cmds.length) {
    const tbl = el("table", { class: "cmds" });
    tbl.append(el("thead", {}, el("tr", {},
      el("th", { style: "width:150px" }, "Tool / op"), el("th", {}, "Command"),
      el("th", { style: "width:60px" }, "Exit"), el("th", { style: "width:70px" }, "Time"))));
    const tb = el("tbody");
    for (const c of cmds) {
      const exitOk = c.ExitCode === 0 && c.Completed !== false;
      tb.append(el("tr", {},
        el("td", {}, `${c.Toolkit ? c.Toolkit + "." : ""}${c.Operation || ""}`),
        el("td", { class: "cmd" }, `${c.Command || ""} ${c.Arguments || ""}`.trim()),
        el("td", { class: exitOk ? "exit-ok" : "exit-bad" }, c.ExitCode != null ? String(c.ExitCode) : (c.Completed === false ? "x" : "?")),
        el("td", {}, c.DurationMs != null ? c.DurationMs + "ms" : "")));
    }
    tbl.append(tb);
    block.append(tbl);
  } else if (!started) {
    block.append(el("div", { class: "empty" }, "No script or commands recorded under this execution id."));
  }
  return block;
}

// ---------- audit log view ----------
const activeTypes = new Set();    // empty = show all

function eventTypeCounts() {
  const m = new Map();
  for (const e of EVENTS) m.set(e.EventType, (m.get(e.EventType) || 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

function renderTypeChips() {
  const wrap = $("#typeChips");
  wrap.innerHTML = "";
  for (const [type, n] of eventTypeCounts()) {
    const chip = el("span", { class: "chip" + (activeTypes.has(type) ? " on" : ""), onclick: () => {
      activeTypes.has(type) ? activeTypes.delete(type) : activeTypes.add(type);
      renderTypeChips(); renderLog();
    } },
      el("span", { class: "etag et-" + type }, type),
      el("span", { class: "n" }, String(n)));
    wrap.append(chip);
  }
}

function renderLog() {
  const body = $("#logBody");
  body.innerHTML = "";
  const execQ = $("#execFilter").value.trim().toLowerCase();
  const textQ = $("#textFilter").value.trim().toLowerCase();

  const rows = EVENTS.filter((e) => {
    if (activeTypes.size && !activeTypes.has(e.EventType)) return false;
    if (execQ && !String(e.ExecutionId || "").toLowerCase().includes(execQ)) return false;
    if (textQ) {
      const hay = (summarize(e) + " " + (e.Interpretation || "") + " " + e.EventType).toLowerCase();
      if (!hay.includes(textQ)) return false;
    }
    return true;
  });

  $("#auditCount").textContent = `(${EVENTS.length})`;
  if (!rows.length) {
    body.append(el("tr", {}, el("td", { colspan: "4", class: "empty" }, "No events match the current filters.")));
    return;
  }
  for (const e of rows) {
    const tr = el("tr", { onclick: (ev) => toggleRow(ev.currentTarget, e) },
      el("td", { class: "ts" }, fmtTime(e._t)),
      el("td", {}, el("span", { class: "etag et-" + e.EventType }, e.EventType)),
      el("td", {}, e.ExecutionId
        ? el("span", { class: "execid", onclick: (ev) => { ev.stopPropagation(); $("#execFilter").value = e.ExecutionId; renderLog(); } }, e.ExecutionId)
        : ""),
      el("td", { class: "summary" }, truncate(summarize(e), 220)));
    body.append(tr);
  }
}

function toggleRow(tr, e) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("rowdetail")) { next.remove(); tr.classList.remove("exp"); return; }
  tr.classList.add("exp");
  const detail = el("tr", { class: "rowdetail" },
    el("td", { colspan: "4" }, el("pre", {}, JSON.stringify(stripMeta(e), null, 2))));
  tr.after(detail);
}

function jumpToExec(execId) {
  showView("auditView");
  activeTypes.clear();
  $("#textFilter").value = "";
  $("#execFilter").value = execId;
  renderTypeChips();
  renderLog();
}

// ---------- view switching ----------
function showView(id) {
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === id));
  $$("nav.tabs button").forEach((b) => b.classList.toggle("active", b.dataset.view === id));
}

// ---------- accuracy tab (rendered from the base64-embedded reports/accuracy.md) ----------
// Decode the inline base64 blob set by report.html. UTF-8 safe; empty when no accuracy.md was embedded.
function accuracyMarkdown() {
  const b64 = window.__ACCURACY_MD_B64__;
  if (!b64) return "";
  try { return decodeURIComponent(escape(atob(b64))); } catch { try { return atob(b64); } catch { return ""; } }
}

// Minimal, dependency-free Markdown -> HTML for the accuracy report: headings, ordered/unordered lists (with
// blank-line-separated and multi-line items), **bold**, *em*, `code`, [links], and paragraphs. Deliberately small.
function renderMarkdown(md) {
  const escHtml = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  const inline = (s) => escHtml(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');

  const lines = md.replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let listType = null, li = null, para = null;
  const flushLi = () => { if (li !== null) { out.push(`<li>${inline(li.join(" "))}</li>`); li = null; } };
  const closeList = () => { flushLi(); if (listType) { out.push(`</${listType}>`); listType = null; } };
  const flushPara = () => { if (para) { out.push(`<p>${inline(para.join(" "))}</p>`); para = null; } };
  const nextIsItem = (from) => {
    for (let j = from; j < lines.length; j++) {
      if (!lines[j].trim()) continue;
      return /^\s*([-*]|\d+\.)\s+/.test(lines[j]);
    }
    return false;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    const ul = line.match(/^\s*[-*]\s+(.*)$/);
    const ol = line.match(/^\s*\d+\.\s+(.*)$/);
    if (h) { flushPara(); closeList(); out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`); continue; }
    if (ul || ol) {
      flushPara();
      const want = ul ? "ul" : "ol";
      if (listType !== want) { closeList(); listType = want; out.push(`<${want}>`); } else flushLi();
      li = [ul ? ul[1] : ol[1]];
      continue;
    }
    if (!line.trim()) { flushPara(); if (listType && !nextIsItem(i + 1)) closeList(); continue; }
    if (li !== null) li.push(line.trim()); else (para ||= []).push(line.trim());
  }
  flushPara(); closeList();
  return out.join("\n");
}

function renderAccuracy() {
  const md = accuracyMarkdown();
  const el = $("#accuracyDoc");
  el.innerHTML = md.trim()
    ? renderMarkdown(md)
    : '<p class="empty">No accuracy report embedded. It is generated from this case\'s reports/accuracy.md.</p>';
}

// ---------- loading ----------
function load(text, sourceName) {
  const { events, bad } = parseClef(text);
  EVENTS = events;
  index();
  SELECTED_FINDING = -1;
  activeTypes.clear();

  const meta = $("#meta");
  const span = EVENTS.length && EVENTS[0]._t && EVENTS[EVENTS.length - 1]._t
    ? `${fmtTime(EVENTS[0]._t)} → ${fmtTime(EVENTS[EVENTS.length - 1]._t)}` : "";
  meta.innerHTML = "";
  // Note: ParentNode.append() stringifies a null argument to the text "null", so filter before appending.
  [
    el("span", {}, el("b", {}, String(EVENTS.length)), " events"),
    el("span", {}, "source: ", el("b", {}, sourceName)),
    span ? el("span", {}, span) : null,
    bad ? el("span", { style: "color:var(--bad)" }, `${bad} unparsable line(s)`) : null,
  ].filter(Boolean).forEach((n) => meta.append(n));

  renderTypeChips();
  renderLog();
  renderFindingsList();

  // Auto-select the first (highest-confidence) finding so the trace is visible immediately.
  const f = findingEvents()[0];
  if (f) selectFinding(f.i); else $("#findingDetail").innerHTML = '<p class="empty">No findings to trace.</p>';

  showView(EVENTS.length ? "findingsView" : "loadView");
}

// An optional sibling audit-data.js (generated once a case has run) may assign window.__AUDIT_CLEF__ with the raw
// .clef text. When present the viewer opens with the data already loaded, so it works by double-click over file://
// with no server and no file picker. Absent in a fresh template, the viewer falls through to fetch / picker.
function loadEmbedded() {
  if (typeof window.__AUDIT_CLEF__ === "string") {
    load(window.__AUDIT_CLEF__, window.__AUDIT_SOURCE__ || `../logs/audit-${CASE_ID}.clef (embedded)`);
    return true;
  }
  return false;
}

async function autoLoad() {
  if (!CASE_ID) return false;
  // report.html lives in the case's reports/ dir, so the log is one level up.
  const path = `../logs/audit-${CASE_ID}.clef`;
  try {
    const res = await fetch(path, { cache: "no-store" });
    if (!res.ok) return false;
    load(await res.text(), path);
    return true;
  } catch { return false; }  // file:// or not served - fall back to manual load
}

// Light/dark theme toggle. The saved choice is applied pre-paint by the inline <head> script; here we just
// reflect the current state on the button and persist changes. Default (no saved choice) is light.
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try { localStorage.setItem("camel-report-theme", theme); } catch { /* private mode / file:// */ }
  const btn = $("#themeBtn");
  if (btn) btn.textContent = theme === "light" ? "☀ Light" : "☾ Dark";
}

function wireUi() {
  const startTheme = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
  applyTheme(startTheme);
  $("#themeBtn").addEventListener("click", () =>
    applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light"));

  $$("nav.tabs button").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
  $("#fileInput").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const r = new FileReader();
    r.onload = () => load(r.result, file.name);
    r.readAsText(file);
  });
  $("#reloadBtn").addEventListener("click", () => autoLoad().then((ok) => { if (!ok) showView("loadView"); }));
  $("#execFilter").addEventListener("input", renderLog);
  $("#textFilter").addEventListener("input", renderLog);
  $("#clearFilters").addEventListener("click", () => {
    activeTypes.clear(); $("#execFilter").value = ""; $("#textFilter").value = "";
    renderTypeChips(); renderLog();
  });

  // Drag-and-drop anywhere.
  const dz = $("#dropZone");
  ["dragenter", "dragover"].forEach((ev) => document.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("hot"); }));
  ["dragleave", "drop"].forEach((ev) => document.addEventListener(ev, (e) => { e.preventDefault(); if (ev !== "dragover") dz.classList.remove("hot"); }));
  document.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const r = new FileReader();
    r.onload = () => load(r.result, file.name);
    r.readAsText(file);
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  wireUi();
  renderAccuracy();                      // independent of the audit log; render once on load
  if (loadEmbedded()) return;            // embedded data (works offline, file://)
  if (!await autoLoad()) showView("loadView");  // else fetch over HTTP, else file picker
});
