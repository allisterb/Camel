# CLAUDE.md

Per-case project instructions for a Camel DFIR investigation. All forensics in this case run through
the **Camel** code-mode MCP server registered in `.mcp.json` (this directory). Fill in the case
details below as you confirm them through Camel, and cite each finding's `[audit] invocation=<id>`
handle so any conclusion can be traced to the tool executions that produced it.

---

## Start here — Camel session bootstrap

1. Read the SDK references `camel://sdk/core` then `camel://sdk/schema` (the method index and the JSON
   schema of every value those methods return). Call only methods documented there.
2. `SetCaseId("__CASE_ID__")` — the audit case id for this engagement. Every tool execution afterward
   is recorded to `audit-__CASE_ID__.clef`.
3. Drive the investigation with `ExecuteJavaScript`. Prefer **workflows** over raw toolkit calls; use
   the `anomaly` engine to triage large timelines; check `IsSuccess` / `null` on every result.

Evidence is mounted and read **read-only** — never modify files under the evidence paths. Write your
own notes, CSVs, and the final report only to `./analysis/`, `./exports/`, or `./reports/`. Report all
timestamps in UTC.

---

## Operating rules

- **Run fully autonomously, start to finish.** Never ask questions or pause for confirmation. If
  blocked, pick the most reasonable path and note it in your output.
- **No hallucinations.** Never guess, assume, or fabricate artifacts, file contents, or system states.
  Ground every conclusion in Camel SDK output and cite its `[audit] invocation=<id>` handle.
- **Code-mode only.** Drive every forensic operation through the Camel MCP server (`ExecuteJavaScript`).
  The shell (`Bash`) is denied by policy — do not attempt shell commands. Use only the documented SDK.

---

## Case Overview

| Field | Value |
|-------|-------|
| **Case ID** | `__CASE_ID__` |
| **Client / Org** | _fill in_ |
| **Incident summary** | _fill in_ |
| **Your role** | _fill in_ |

---

## Evidence

| Path (on the SIFT workstation) | System | Notes |
|--------------------------------|--------|-------|
| _e.g. `/cases/host.E01`_ | _host_ | _disk image / memory image; role_ |

---

## Camel recipes (starting points)

Consult `camel://sdk/core` for the full method list and exact signatures.

```js
// Disk → triage super-timeline → anomaly pivots in surrounding context.
const tl = await TimelineAnalysisWorkflow.CreateTriageTimelineAsync("/mnt/c", "/cases/host.plaso");
if (!tl.IsSuccess) { error(tl.Message); }
else {
  const piv = await TimelineAnalysisWorkflow.AutoPivotExpansionAsync("/cases/host.plaso", 200, 10, 5, true);
  log(piv.Message);
  for (const p of piv.Result.Pivots)
    log(`${p.Pivot.Time} ${p.Pivot.EventType} [${p.Pivot.Bits.toFixed(0)} bits] — ${p.SurroundingCount} events`);
}
```

```js
// Memory → full malware hunt with dumping + YARA.
const r = await MemoryAnalysisWorkflow.FindMalwareAsync("/cases/mem.raw", "/cases/dumps");
if (r.IsSuccess)
  for (const s of r.Result.HighConfidenceSuspects)
    log(`${s.Process} (PID ${s.Pid}) [${s.Categories.join(", ")}] ${s.Signals.join("; ")}`);
```

---

## Known IOCs

> Populate only with artifacts confirmed through Camel; cite each finding's audit invocation id.

| Indicator | Type | Detail | Audit invocation |
|-----------|------|--------|------------------|

---

## Incident Timeline (UTC)

| Timestamp (UTC) | Event | Audit invocation |
|-----------------|-------|------------------|
