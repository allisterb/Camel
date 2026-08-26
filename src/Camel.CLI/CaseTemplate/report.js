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
const fmtNum = (n) => Number(n || 0).toLocaleString("en-US");
const shortModel = (m) => String(m).replace(/^claude-/, "").replace(/-\d{8}$/, "");

// Estimated USD cost. Standard Claude API list prices per 1M tokens (input, output), as of 2026-05-26.
// Prompt-cache pricing is derived: a 5-minute cache WRITE bills 1.25x input, a cache READ bills 0.1x input.
// Update these when list prices change. Unknown models are priced by family, else left out of the estimate.
const PRICING = {
  "claude-fable-5":    { in: 10, out: 50 },
  "claude-opus-4-8":   { in: 5,  out: 25 },
  "claude-opus-4-7":   { in: 5,  out: 25 },
  "claude-opus-4-6":   { in: 5,  out: 25 },
  "claude-opus-4-5":   { in: 5,  out: 25 },
  "claude-sonnet-4-6": { in: 3,  out: 15 },
  "claude-sonnet-4-5": { in: 3,  out: 15 },
  "claude-haiku-4-5":  { in: 1,  out: 5 },
};
function priceFor(model) {
  const id = String(model);
  const p = PRICING[id] || PRICING[id.replace(/-\d{8}$/, "")];
  if (p) return p;
  const m = id.toLowerCase();
  if (m.includes("opus")) return { in: 5, out: 25 };
  if (m.includes("sonnet")) return { in: 3, out: 15 };
  if (m.includes("haiku")) return { in: 1, out: 5 };
  if (m.includes("fable")) return { in: 10, out: 50 };
  return null;   // unknown model — excluded from the estimate
}
// USD cost of one model's usage row, or null when the model can't be priced.
function modelCost(model, m) {
  const p = priceFor(model);
  if (!p) return null;
  const inR = p.in / 1e6, outR = p.out / 1e6;
  return (m.input_tokens || 0) * inR
       + (m.output_tokens || 0) * outR
       + (m.cache_creation_input_tokens || 0) * inR * 1.25   // 5-min cache write
       + (m.cache_read_input_tokens || 0) * inR * 0.1;       // cache read
}
const fmtUsd = (n) => n < 0.01 ? "<$0.01" : "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
function fmtDur(ms) {
  const s = Math.round(ms / 1000);
  if (s < 90) return s + "s";
  const m = Math.round(s / 60);
  if (m < 90) return m + " min";
  return Math.floor(m / 60) + "h " + (m % 60) + "m";
}

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
// The attribution an event carries (set via LogContext): the workflow operation and/or the toolkit operation
// that issued the command. Surfaced as the audit log's "Source" column. shortOp drops the C# "Async" suffix.
const shortOp = (s) => String(s || "").replace(/Async$/, "");
function sourceParts(e) {
  const wf = e.Workflow ? e.Workflow + (e.WorkflowOperation ? "." + shortOp(e.WorkflowOperation) : "") : "";
  const tk = e.Toolkit ? e.Toolkit + (e.Operation ? "." + e.Operation : "") : "";
  return { wf, tk };
}
const sourceText = (e) => { const { wf, tk } = sourceParts(e); return [wf, tk].filter(Boolean).join(" › "); };
function sourceCell(e) {
  const { wf, tk } = sourceParts(e);
  if (!wf && !tk) return "";
  const span = el("span", { class: "src-chain", title: sourceText(e) });
  if (wf) span.append(el("span", { class: "wf" }, wf));
  if (wf && tk) span.append(el("span", { class: "sep" }, " › "));
  if (tk) span.append(el("span", { class: "tk" }, tk));
  return span;
}

function summarize(e) {
  switch (e.EventType) {
    case "command":
      // Tool/workflow attribution now lives in its own "Source" column; keep the summary to the command line.
      return `${e.Command || ""} ${e.Arguments || ""}`.trim();
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
  // A pen-test case records scored issues via auditVulnerability (the Vulnerabilities tab); its narrative Findings
  // tab is often empty. Hide the tab when it is empty on a pen-test case (engagement present) so a blank tab does
  // not sit next to the populated Vulnerabilities tab. A DFIR case always keeps Findings — its primary surface.
  const findTab = $("#tabFindings");
  if (findTab) findTab.classList.toggle("hidden", findings.length === 0 && !!window.__ENGAGEMENT__);
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
        el("td", { title: c.Workflow ? sourceText(c) : null }, `${c.Toolkit ? c.Toolkit + "." : ""}${c.Operation || ""}`),
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
      const hay = (summarize(e) + " " + sourceText(e) + " " + (e.Interpretation || "") + " " + e.EventType).toLowerCase();
      if (!hay.includes(textQ)) return false;
    }
    return true;
  });

  $("#auditCount").textContent = `(${EVENTS.length})`;
  if (!rows.length) {
    body.append(el("tr", {}, el("td", { colspan: "5", class: "empty" }, "No events match the current filters.")));
    return;
  }
  for (const e of rows) {
    const tr = el("tr", { onclick: (ev) => toggleRow(ev.currentTarget, e) },
      el("td", { class: "ts" }, fmtTime(e._t)),
      el("td", {}, el("span", { class: "etag et-" + e.EventType }, e.EventType)),
      el("td", {}, e.ExecutionId
        ? el("span", { class: "execid", onclick: (ev) => { ev.stopPropagation(); $("#execFilter").value = e.ExecutionId; renderLog(); } }, e.ExecutionId)
        : ""),
      el("td", { class: "src" }, sourceCell(e)),
      el("td", { class: "summary" }, truncate(summarize(e), 220)));
    body.append(tr);
  }
}

function toggleRow(tr, e) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("rowdetail")) { next.remove(); tr.classList.remove("exp"); return; }
  tr.classList.add("exp");
  const detail = el("tr", { class: "rowdetail" },
    el("td", { colspan: "5" }, el("pre", {}, JSON.stringify(stripMeta(e), null, 2))));
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
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    // Linkify "exec <id>" references (8-hex execution ids) so they jump to that execution in the Audit Log, like
    // the Findings tab. Gated on the "exec" cue so SHA/hash fragments (also hex) are never mistaken for exec ids.
    .replace(/\b(exec(?:ution)?\s+)([0-9a-f]{8})\b/gi, '$1<span class="execid" data-exec="$2">$2</span>');

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

// ---------- IOCs tab (rendered from the base64-embedded reports/iocs.csv) ----------
function iocsCsv() {
  const b64 = window.__IOCS_CSV_B64__;
  if (!b64) return "";
  try { return decodeURIComponent(escape(atob(b64))); } catch { try { return atob(b64); } catch { return ""; } }
}

// RFC4180-ish line splitter: handles quoted fields and "" escapes. The case CSVs are unquoted, but this keeps the
// parser correct if a field is ever quoted.
function parseCsvLine(line) {
  const out = []; let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ",") { out.push(cur); cur = ""; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

function renderIocs() {
  // For a pen-test engagement these indicators are the client's compromise evidence / purple-team handoff, not
  // DFIR indicators-of-compromise — relabel the tab + empty state. Same iocs.csv source, gated on the engagement.
  const penTest = !!window.__ENGAGEMENT__;
  const tab = $("#tabIocs");
  if (tab && tab.firstChild && tab.firstChild.nodeType === 3)
    tab.firstChild.textContent = penTest ? "Compromise Evidence " : "IOCs ";

  const csv = iocsCsv();
  const head = $("#iocsHead"), body = $("#iocsBody");
  head.innerHTML = ""; body.innerHTML = "";
  const rows = csv.replace(/\r\n/g, "\n").split("\n").filter((l) => l.trim()).map(parseCsvLine);
  if (rows.length < 2) {
    $("#iocCount").textContent = "";
    body.append(el("tr", {}, el("td", { class: "empty" }, penTest
      ? "No compromise-evidence rows embedded. Generated from this engagement's reports/iocs.csv (hosts, services, credentials, and indicators for purple-team handoff)."
      : "No IOC data embedded. It is generated from this case's reports/iocs.csv.")));
    return;
  }
  const header = rows[0];
  const ctxIdx = header.indexOf("context");
  const valIdx = header.indexOf("value");
  const execIdx = header.indexOf("audit_execution");
  const data = rows.slice(1);
  $("#iocCount").textContent = `(${data.length})`;

  // Header
  const widths = { indicator_type: "110px", first_seen_utc: "170px", audit_execution: "90px", value: "200px" };
  head.append(el("tr", {}, ...header.map((h) => el("th", widths[h] ? { style: `width:${widths[h]}` } : {}, h))));

  for (let row of data) {
    // Defensive: an unquoted comma in the free-text context column would over-split the row; fold the overflow
    // back into context so the boundary columns (type/value/time/exec) stay aligned.
    if (row.length > header.length && ctxIdx >= 0) {
      const extra = row.length - header.length;
      row = [...row.slice(0, ctxIdx), row.slice(ctxIdx, ctxIdx + 1 + extra).join(","), ...row.slice(ctxIdx + 1 + extra)];
    }
    const tr = el("tr", {});
    header.forEach((_h, i) => {
      const v = row[i] ?? "";
      if (i === execIdx) {
        const td = el("td", {});
        // audit_execution may carry one or more 8-hex ids; linkify each to jump to the Audit Log.
        v.split(/[\s,;]+/).filter(Boolean).forEach((tok, k) => {
          if (k) td.append(document.createTextNode(" "));
          td.append(/^[0-9a-f]{8}$/i.test(tok)
            ? el("span", { class: "execid", onclick: () => jumpToExec(tok) }, tok)
            : document.createTextNode(tok));
        });
        tr.append(td);
      } else if (i === ctxIdx) tr.append(el("td", { class: "ctx" }, v));
      else if (i === valIdx) tr.append(el("td", { class: "val" }, v));
      else if (i === 0) tr.append(el("td", {}, el("span", { class: "etag" }, v)));
      else tr.append(el("td", {}, v));
    });
    body.append(tr);
  }
}

// ---------- Vulnerabilities tab (pen-test cases; from `vulnerability` CLEF events) ----------
// The red counterpart of the Findings tab: a severity "report card" over the ranked master-detail. A `vulnerability`
// event carries Title / Severity / Cvss / AffectedAsset / Description / Remediation / References / EvidenceExecutionIds
// (see AuditVulnerability). Absent for a DFIR case, so the tab stays hidden.
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
const SEV_CLASSES = ["critical", "high", "medium", "low", "info"];
let SELECTED_VULN = -1;   // index into EVENTS of the selected vulnerability

const sevOf = (e) => String(e.Severity || "unknown").toLowerCase();
const cvssOf = (e) => { const n = parseFloat(e.Cvss); return isNaN(n) ? -1 : n; };

// Rank most-critical-first: severity band, then CVSS desc, then time.
function vulnerabilityEvents() {
  return EVENTS.map((e, i) => ({ e, i }))
    .filter((x) => x.e.EventType === "vulnerability")
    .sort((a, b) => {
      const sa = SEV_ORDER[sevOf(a.e)] ?? 5, sb = SEV_ORDER[sevOf(b.e)] ?? 5;
      return sa - sb || (cvssOf(b.e) - cvssOf(a.e)) || (a.e._t - b.e._t);
    });
}

// Severity "report card": one stat tile per band + a stacked severity bar. Basta/OSSTMM "vulnerability summary".
function renderReportCard(vulns) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const { e } of vulns) { const s = sevOf(e); if (s in counts) counts[s]++; else counts.info++; }
  const total = vulns.length;
  const card = el("div", { class: "reportcard", id: "reportCard" });
  card.append(el("div", { class: "rc-title" }, `Vulnerability summary — ${total} finding${total === 1 ? "" : "s"}`));
  const tiles = el("div", { class: "rc-tiles" });
  for (const s of SEV_CLASSES) {
    tiles.append(el("div", { class: "rc-tile " + s + (counts[s] ? "" : " zero") },
      el("div", { class: "n" }, String(counts[s])),
      el("div", { class: "l" }, s)));
  }
  card.append(tiles);
  if (total) {
    const bar = el("div", { class: "rc-bar", title: SEV_CLASSES.map((s) => `${counts[s]} ${s}`).join(" / ") });
    for (const s of SEV_CLASSES) {
      if (!counts[s]) continue;
      const seg = el("span", { class: "s-" + s }); seg.style.width = (counts[s] / total * 100) + "%";
      bar.append(seg);
    }
    card.append(bar);
  }
  return card;
}

function renderVulns() {
  const tab = $("#tabVulns"), list = $("#vulnsList");
  const vulns = vulnerabilityEvents();
  if (!vulns.length) { tab.classList.add("hidden"); return false; }
  tab.classList.remove("hidden");
  $("#vulnCount").textContent = `(${vulns.length})`;

  list.innerHTML = "";
  list.append(renderReportCard(vulns));
  for (const { e, i } of vulns) {
    const s = sevOf(e);
    const card = el("div", { class: "fcard vcard" + (i === SELECTED_VULN ? " sel" : ""), "data-i": i, onclick: () => selectVuln(i) },
      el("div", { class: "frow" },
        el("span", { class: "sev sev-" + (s in SEV_ORDER ? s : "unknown") }, s),
        cvssOf(e) >= 0 ? el("span", { class: "cvss" }, "CVSS " + e.Cvss) : null,
        el("span", { style: "margin-left:auto" }, e.AffectedAsset || "")),
      el("p", { class: "obs" }, truncate(e.Title, 200)));
    list.append(card);
  }
  return true;
}

function selectVuln(i) {
  SELECTED_VULN = i;
  $$("#vulnsList .vcard").forEach((c) => c.classList.toggle("sel", +c.dataset.i === i));
  renderVulnDetail(EVENTS[i]);
}

function renderVulnDetail(v) {
  const d = $("#vulnDetail");
  d.innerHTML = "";
  const s = sevOf(v);
  d.append(
    el("h2", { class: "detail-h" }, v.Title || "(untitled)"),
    el("div", {},
      el("span", { class: "sev sev-" + (s in SEV_ORDER ? s : "unknown") }, s),
      cvssOf(v) >= 0 ? el("span", { class: "cvss", style: "margin-left:10px" }, "CVSS " + v.Cvss) : null,
      el("span", { class: "pill", style: "margin-left:10px" }, fmtTime(v._t))),
    kv("Affected asset", v.AffectedAsset),
    kv("Description", v.Description),
    kv("Remediation", v.Remediation),
    kv("References", v.References),
  );

  // Evidence trace: reuse the Findings tab's exec-block renderer over the cited execution ids.
  const evidenceIds = splitIds(v.EvidenceExecutionIds);
  const recordedIn = v.ExecutionId;
  d.append(el("div", { class: "k", style: "margin-top:18px" }, "Evidence — audit-log entries"));
  const trace = el("div", { class: "trace" });
  const seen = new Set();
  const order = [...evidenceIds, recordedIn].filter((id) => id && !seen.has(id) && seen.add(id));
  if (!order.length) trace.append(el("p", { class: "empty" }, "No execution ids associated with this vulnerability."));
  for (const id of order) trace.append(renderExecBlock(id, id === recordedIn && !evidenceIds.includes(id)));
  d.append(trace);
}

// ---------- Authorization & Scope tab (pen-test cases; from engagement-data.js + the CLEF attestation) ----------
// window.__ENGAGEMENT__ is the serialized EngagementInfo (or absent for a DFIR case, when the tab stays hidden).
const BASELINE_ACTS = ["Recon", "Scan", "Enumerate", "VulnScan"];
const ALL_ACTS = [...BASELINE_ACTS, "Exploit", "CredentialAttack", "PostExploit", "Exfiltration", "SocialEngineering", "DenialOfService"];
const DANGER_ACTS = new Set(["SocialEngineering", "DenialOfService"]);

const authSec = (title, ...nodes) => el("div", { class: "authsec" }, el("h3", {}, title), ...nodes.filter(Boolean));
function authGrid(pairs) {
  const g = el("div", { class: "authgrid" });
  for (const [k, v, mono] of pairs) {
    if (v === null || v === undefined || v === "") continue;
    g.append(el("div", { class: "gk" }, k), el("div", { class: "gv" + (mono ? " mono" : "") }, v));
  }
  return g;
}
const fmtTestingHours = (h) => !h ? "any time (validity window enforced)"
  : `${(h.StartLocal || h.EndLocal) ? `${h.StartLocal || "?"}-${h.EndLocal || "?"}` : "any time"} ` +
    `${h.TimeZone || "UTC"} ${Array.isArray(h.Days) && h.Days.length ? h.Days.join("/") : "any day"}`;

function renderAuthorization() {
  const e = window.__ENGAGEMENT__;
  const tab = $("#tabAuth"), doc = $("#authDoc");
  if (!e || typeof e !== "object") { tab.classList.add("hidden"); return false; }
  tab.classList.remove("hidden");
  doc.innerHTML = "";

  doc.append(el("h2", { class: "title" }, "Engagement " + (e.EngagementId || "(unnamed)")));
  doc.append(el("div", { class: "sub" },
    (e.Client || "?") + " — authorized by " + (e.AuthorizedBy || "?") + (e.TestType ? " · " + e.TestType : "")));
  doc.append(el("div", { id: "attBanner" }));   // filled by renderAttestation() once the audit log loads

  doc.append(authSec("Engagement", authGrid([
    ["Client", e.Client], ["Authorized by", e.AuthorizedBy], ["RoE reference", e.RulesOfEngagementRef, true],
    ["Posture", e.Posture], ["Test type", e.TestType], ["Announced", e.Announced === false ? "No (covert)" : "Yes"],
    ["Valid from (UTC)", (e.ValidFromUtc || "").replace("T", " ").slice(0, 19), true],
    ["Valid until (UTC)", (e.ValidUntilUtc || "").replace("T", " ").slice(0, 19), true],
    ["Testing hours", fmtTestingHours(e.TestingHours)],
    ["External disclosure", e.AllowExternalTargetDisclosure ? "Permitted" : "Not permitted"],
  ])));

  // Scope table (in-scope + excluded carve-outs)
  const scope = Array.isArray(e.Scope) ? e.Scope : [];
  const inScope = scope.filter((s) => !s.Excluded), exScope = scope.filter((s) => s.Excluded);
  const scopeTbl = el("table", { class: "log" });
  scopeTbl.append(el("thead", {}, el("tr", {},
    el("th", { style: "width:120px" }, "Kind"), el("th", {}, "Target"), el("th", { style: "width:130px" }, "Disposition"))));
  const stb = el("tbody");
  for (const s of inScope) stb.append(el("tr", {}, el("td", {}, s.Kind), el("td", { class: "mono" }, s.Value), el("td", { class: "scope-in" }, "in scope")));
  for (const s of exScope) stb.append(el("tr", {}, el("td", {}, s.Kind), el("td", { class: "mono" }, s.Value), el("td", { class: "scope-ex" }, "EXCLUDED")));
  if (!scope.length) stb.append(el("tr", {}, el("td", { colspan: "3", class: "empty" }, "No scope entries — nothing is in scope (fail-closed).")));
  scopeTbl.append(stb);
  doc.append(authSec(`Scope — ${inScope.length} in-scope / ${exScope.length} excluded`, scopeTbl));

  // Authorized activity classes (baseline greyed, opted-in green, never-baseline explicit = red)
  const allowed = new Set([...BASELINE_ACTS, ...(Array.isArray(e.AllowedActivities) ? e.AllowedActivities : [])]);
  const acts = el("div", { class: "acts" });
  for (const a of ALL_ACTS) {
    const on = allowed.has(a), base = BASELINE_ACTS.includes(a), danger = DANGER_ACTS.has(a);
    acts.append(el("span", { class: "act" + (on ? " on" : " off") + (danger ? " danger" : "") },
      a, base ? el("span", { class: "base" }, " (baseline)") : null));
  }
  doc.append(authSec("Authorized activity classes", acts, el("div", { class: "sub", style: "margin-top:8px" },
    "Baseline (recon/scan/enumerate/vuln-scan) is always permitted within scope; intrusive classes are opt-in. " +
    "Denial-of-service and social-engineering are never baseline — red = explicitly authorized.")));

  doc.append(authSec("Intensity caps", authGrid([
    ["Max packet rate", e.MaxPacketRate != null ? e.MaxPacketRate + " pkt/s" : "server default (fail-safe, never uncapped)"],
    ["Max concurrent targets", e.MaxConcurrentTargets != null ? String(e.MaxConcurrentTargets) : "server default"],
    ["Test source addresses", Array.isArray(e.SourceAddresses) && e.SourceAddresses.length ? e.SourceAddresses.join(", ") : null, true],
    ["Authorized tools", Array.isArray(e.AuthorizedTools) && e.AuthorizedTools.length ? e.AuthorizedTools.join(", ") : null],
  ])));

  // Authorization documents (the signed proof — OSSTMM RoE): preserved copy + SHA-256
  const docs = Array.isArray(e.Documents) ? e.Documents : [];
  if (docs.length) {
    const dtbl = el("table", { class: "log" });
    dtbl.append(el("thead", {}, el("tr", {},
      el("th", { style: "width:150px" }, "Kind"), el("th", {}, "Preserved copy"), el("th", {}, "SHA-256"))));
    const dtb = el("tbody");
    for (const d of docs) dtb.append(el("tr", {},
      el("td", {}, d.Kind),
      el("td", {}, d.StoredPath ? el("a", { href: d.StoredPath.replace(/^reports\//, ""), target: "_blank" }, d.StoredPath) : (d.FilePath || "")),
      el("td", { class: "doc-hash" }, d.HashValue || "(unhashed)")));
    dtbl.append(dtb);
    doc.append(authSec("Authorization documents (signed proof)", dtbl));
  } else {
    doc.append(authSec("Authorization documents",
      el("p", { class: "empty" }, "No documents recorded — self-attested (a lab / self-owned engagement).")));
  }

  if (e.InternalAuthorizationWaiver)
    doc.append(authSec("Authorization waiver (residual risk)",
      el("div", { class: "att warn" }, el("div", { class: "att-line" },
        "Internal targets authorized by operator WAIVER (no signed document): " + e.InternalAuthorizationWaiver))));

  const contacts = Array.isArray(e.Contacts) ? e.Contacts : [];
  if (contacts.length) {
    const ctbl = el("table", { class: "log" });
    ctbl.append(el("thead", {}, el("tr", {}, el("th", {}, "Name"), el("th", {}, "Role"), el("th", {}, "Email"), el("th", {}, "Phone"))));
    const ctb = el("tbody");
    for (const c of contacts) ctb.append(el("tr", {}, el("td", {}, c.Name), el("td", {}, c.Role), el("td", {}, c.Email || ""), el("td", {}, c.Phone || "")));
    ctbl.append(ctb);
    doc.append(authSec("Points of contact", ctbl));
  }
  return true;
}

// Compliance attestation: turn the fail-closed gate's CLEF events into positive proof the engagement stayed
// authorized and in scope (every scope-violation is a refusal — evidence the gate held). Called from load().
function renderAttestation() {
  const banner = $("#attBanner");
  if (!banner) return;
  const n = (t) => EVENTS.filter((e) => e.EventType === t).length;
  const violations = n("scope-violation"), waivers = n("authorization-waiver");
  const disclosures = n("external-disclosure") + n("kb-disclosure"), engEvents = n("engagement");
  banner.innerHTML = "";
  const b = el("div", { class: "att" + (waivers > 0 ? " warn" : "") });
  b.append(el("div", { class: "att-h" }, "Scope-compliance attestation"));
  const line = el("div", { class: "att-line" });
  line.append("Every offensive action was confined to the authorized engagement. ");
  line.append(el("b", { class: violations ? "warnc" : "ok" }, String(violations)), " gate refusal(s) — out-of-scope targets, or client assets the RoE would not let us disclose — of which ",
              el("b", { class: "ok" }, "0"), " succeeded. ");
  if (waivers) line.append(el("b", { class: "warnc" }, String(waivers)), " authorization-waiver(s) recorded (residual risk). ");
  line.append(el("b", {}, String(disclosures)), " external-disclosure event(s). ");
  if (engEvents) line.append("Engagement registered and enforced across the session.");
  b.append(line);
  banner.append(b);
}

// ---------- Conversation tab (read-only chat reconstruction from chatlog-data.js) ----------
// window.__CHATLOG__ is an array of sessions: { file, turns:[{ role, ts, meta, side, blocks }] }, where a block is
// one of { k:"text"|"thinking", text } / { k:"tool_use", name, id, input, trunc } / { k:"tool_result", id, err,
// text, trunc }. The generator already trimmed/capped it; this just renders. Tool results are paired to their
// tool_use card by id so each call shows its own output.
// window.__TOKEN_USAGE__ = { assistantTurns, totals:{ input_tokens, output_tokens, cache_creation_input_tokens,
// cache_read_input_tokens, total_tokens }, breakdown:{ cached_tokens, new_tokens, new_input_tokens, output_tokens,
// cache_read_fraction_of_input }, byModel:{ <model>:{ turns, input_tokens, output_tokens,
// cache_creation_input_tokens, cache_read_input_tokens } } }. Cached = prompt-cache reads (reused, billed ~0.1x);
// new = fresh input + the one-time cache write + output. Returns the panel node, or null when there's no usage data.
function renderTokenPanel() {
  const t = window.__TOKEN_USAGE__;
  if (!t || !t.totals) return null;
  const b = t.breakdown || {};
  const cached = b.cached_tokens || 0;
  const fresh = b.new_tokens || 0;
  const denom = cached + fresh;
  const pct = (x) => denom ? Math.round((x / denom) * 1000) / 10 : 0;
  const total = t.totals.total_tokens || denom;

  // Estimated cost across all models (sum of per-model costs); flag if any model couldn't be priced.
  const models = t.byModel ? Object.entries(t.byModel) : [];
  let estCost = 0, anyUnpriced = false, anyPriced = false;
  for (const [name, m] of models) {
    const c = modelCost(name, m);
    if (c === null) anyUnpriced = true; else { estCost += c; anyPriced = true; }
  }

  const panel = el("div", { class: "token-panel" });
  const head = el("div", { class: "tp-head" },
    el("span", { class: "tp-title" }, "Token usage"),
    el("span", { class: "tp-total" }, el("b", {}, fmtNum(total)), " total tokens"),
    el("span", { class: "tp-sub" }, `over ${fmtNum(t.assistantTurns || 0)} assistant turns`));
  if (anyPriced)
    head.append(el("span", {
      class: "tp-cost",
      title: "Estimated at standard Claude API list prices (cache writes 1.25x input, reads 0.1x input)" +
             (anyUnpriced ? ". Some models could not be priced and are excluded." : "."),
    }, "~" + fmtUsd(estCost) + (anyUnpriced ? "+ est." : " est.")));
  panel.append(head);

  const bar = el("div", { class: "tp-bar", title: `New ${fmtNum(fresh)} / Cached ${fmtNum(cached)}` });
  const segNew = el("span", { class: "seg-new" }); segNew.style.width = pct(fresh) + "%";
  const segCached = el("span", { class: "seg-cached" }); segCached.style.width = pct(cached) + "%";
  bar.append(segNew, segCached);
  panel.append(bar);

  const cacheHitPct = Math.round((b.cache_read_fraction_of_input || 0) * 100);
  panel.append(el("div", { class: "tp-legend" },
    tokenKey("sw-new", "New", fresh, pct(fresh), `incl. ${fmtNum(b.output_tokens || 0)} output`),
    tokenKey("sw-cached", "Cached", cached, pct(cached), `${cacheHitPct}% of input reused from cache`)));

  // Runtime breakdown: total wall-clock split into model reasoning (+agent/transport) vs tool execution.
  if (t.durationMs) {
    const totalMs = t.durationMs;
    const toolMs = Math.min(t.toolCallMs || 0, totalMs);   // clamp: parallel tool calls can sum past wall-clock
    const reasonMs = Math.max(0, totalMs - toolMs);
    const denom = (reasonMs + toolMs) || 1;
    const rt = el("div", { class: "tp-runtime" });
    rt.append(el("div", { class: "tp-rt-head" },
      el("span", { class: "tp-rt-label" }, "Runtime"),
      el("span", { class: "tp-rt-total" }, "~" + fmtDur(totalMs)),
      el("span", { class: "tp-sub" }, "total run time")));
    const bar = el("div", { class: "tp-bar", title: `Model reasoning ${fmtDur(reasonMs)} / tool execution ${fmtDur(toolMs)}` });
    const segR = el("span", { class: "seg-reason" }); segR.style.width = (reasonMs / denom * 100) + "%";
    const segT = el("span", { class: "seg-tool" }); segT.style.width = (toolMs / denom * 100) + "%";
    bar.append(segR, segT);
    rt.append(bar);
    rt.append(el("div", { class: "tp-legend" },
      rtKey("sw-reason", "Model reasoning", reasonMs, totalMs),
      (t.toolCallMs != null ? rtKey("sw-tool", "Tool calls", toolMs, totalMs) : null)));
    panel.append(rt);
  }

  if (models.length) {
    const tb = el("tbody", {});
    for (const [name, m] of models) {
      const c = modelCost(name, m);
      tb.append(el("tr", {},
        el("td", {}, shortModel(name)),
        el("td", {}, fmtNum(m.turns)),
        el("td", {}, fmtNum((m.input_tokens || 0) + (m.cache_creation_input_tokens || 0))),
        el("td", {}, fmtNum(m.cache_read_input_tokens || 0)),
        el("td", {}, fmtNum(m.output_tokens || 0)),
        el("td", {}, c === null ? "-" : fmtUsd(c))));
    }
    panel.append(el("div", { class: "tp-models" }, el("table", {},
      el("thead", {}, el("tr", {},
        el("th", {}, "Model"), el("th", {}, "Turns"), el("th", {}, "New in"),
        el("th", {}, "Cached in"), el("th", {}, "Output"), el("th", {}, "Est. cost"))),
      tb)));
  }
  return panel;
}

function tokenKey(swClass, label, num, pct, note) {
  return el("span", { class: "key" },
    el("span", { class: "sw " + swClass }),
    `${label} `, el("span", { class: "num" }, fmtNum(num)),
    el("span", { class: "pct" }, ` (${pct}%)${note ? " - " + note : ""}`));
}

// Legend key for the runtime bar: a duration + its percent of the total run time.
function rtKey(swClass, label, ms, totalMs) {
  const pct = totalMs ? Math.round((ms / totalMs) * 1000) / 10 : 0;
  return el("span", { class: "key" },
    el("span", { class: "sw " + swClass }),
    `${label} `, el("span", { class: "num" }, fmtDur(ms)),
    el("span", { class: "pct" }, ` (${pct}%)`));
}

function renderChat() {
  const root = $("#chatLog");
  root.innerHTML = "";
  const tokenPanel = renderTokenPanel();
  if (tokenPanel) root.append(tokenPanel);
  const sessions = Array.isArray(window.__CHATLOG__) ? window.__CHATLOG__ : [];
  const total = sessions.reduce((n, s) => n + (s.turns ? s.turns.length : 0), 0);
  $("#chatCount").textContent = total ? `(${total})` : "";
  if (!total) {
    root.append(el("p", { class: "empty" },
      "No conversation embedded. It is generated from this case's logs/chatlog-*.jsonl."));
    return;
  }
  const toolSlots = new Map();   // tool_use id -> result placeholder element
  sessions.forEach((s, si) => {
    const first = (s.turns || []).find((t) => t.ts);
    if (sessions.length > 1)
      root.append(el("div", { class: "session-sep" },
        `session ${si + 1} of ${sessions.length}${first ? " - " + fmtTime(new Date(first.ts)) : ""}`));
    for (const turn of (s.turns || [])) renderTurn(turn, root, toolSlots);
  });
}

const tsSpan = (turn) => turn.ts ? el("span", { class: "ts" }, fmtTime(new Date(turn.ts))) : null;

function renderTurn(turn, root, toolSlots) {
  const blocks = turn.blocks || [];
  if (turn.role === "assistant") {
    const t = el("div", { class: "turn assistant" }, el("div", { class: "who" }, "Assistant", tsSpan(turn)));
    for (const b of blocks) {
      if (b.k === "thinking") t.append(el("details", { class: "think" },
        el("summary", {}, "thinking"), el("div", { class: "body" }, b.text)));
      else if (b.k === "text") t.append(el("div", { class: "bubble" }, b.text));
      else if (b.k === "tool_use") t.append(toolBlock(b, toolSlots));
    }
    root.append(t);
    return;
  }
  // user turn: tool_result blocks fill their matching call; text is a real prompt or an injected system note.
  for (const b of blocks) if (b.k === "tool_result") fillToolResult(b, root, toolSlots);
  const texts = blocks.filter((b) => b.k === "text" || b.k === "thinking");
  if (texts.length) {
    const sys = !!turn.meta;
    const t = el("div", { class: "turn " + (sys ? "system" : "user") },
      el("div", { class: "who" }, sys ? "System" : "User", tsSpan(turn)));
    for (const b of texts) t.append(el("div", { class: "bubble" }, b.text));
    root.append(t);
  }
}

function toolBlock(b, toolSlots) {
  const body = el("div", { class: "body" }, el("div", {}, b.input || "(no input)"));
  if (b.trunc) body.append(el("div", { class: "trunc" }, `[+${b.trunc} more chars truncated]`));
  const slot = el("div", {});                       // result fills in here when its tool_result turn arrives
  body.append(slot);
  if (b.id) toolSlots.set(b.id, slot);
  return el("details", { class: "tool" },
    el("summary", {}, el("span", { class: "tname" }, b.name || "tool"), " call"), body);
}

function fillToolResult(r, root, toolSlots) {
  const node = el("div", { style: "margin-top:6px;border-top:1px solid var(--border);padding-top:6px" },
    el("div", { class: r.err ? "result-err" : "result-ok" }, r.err ? "result (error)" : "result"),
    el("div", {}, r.text || "(empty)"),
    r.trunc ? el("div", { class: "trunc" }, `[+${r.trunc} more chars truncated]`) : null);
  const slot = r.id ? toolSlots.get(r.id) : null;
  if (slot) slot.append(node);
  else root.append(el("div", { class: "turn assistant" },           // orphan result (no call in view)
    el("details", { class: "tool" }, el("summary", {}, "tool result"), el("div", { class: "body" }, node))));
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

  // Vulnerabilities tab (pen-test): report card + ranked list; hidden when no `vulnerability` events. Auto-select
  // the first (most-critical) so its detail is visible immediately.
  SELECTED_VULN = -1;
  if (renderVulns()) { const v = vulnerabilityEvents()[0]; if (v) selectVuln(v.i); }

  // Auto-select the first (highest-confidence) finding so the trace is visible immediately.
  const f = findingEvents()[0];
  if (f) selectFinding(f.i); else $("#findingDetail").innerHTML = '<p class="empty">No findings to trace.</p>';

  renderAttestation();   // compliance banner on the Authorization tab (no-op when there is no engagement)

  // A pen-test case lands on Authorization & Scope (the authorization record is where a red report opens); a DFIR
  // case (no engagement) lands on Findings.
  showView(!EVENTS.length ? "loadView" : (window.__ENGAGEMENT__ ? "authView" : "findingsView"));
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

  // Delegated: clicking an "exec <id>" link rendered in the accuracy report jumps to that execution in the Audit
  // Log (same jumpToExec used by the Findings trace). Bound once; works for content rendered later.
  $("#accuracyDoc").addEventListener("click", (e) => {
    const t = e.target.closest(".execid");
    if (t && t.dataset.exec) jumpToExec(t.dataset.exec);
  });

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
  renderIocs();
  renderChat();
  renderAuthorization();                 // pen-test Authorization & Scope tab (hidden when there's no engagement)
  if (loadEmbedded()) return;            // embedded data (works offline, file://)
  if (!await autoLoad()) showView("loadView");  // else fetch over HTTP, else file picker
});
