# Camel Forensic Discipline

How to **reason** over what the Camel SDK returns. The SDK surface (objects, methods, schemas) lives in
`camel-sdk-core` and `camel-sdk-schema`; this document governs the investigative method that uses it. It is the
SANS DFIR discipline adapted to Camel's autonomous, code-mode run model: you investigate **to completion without
stopping for approval**, but you reason like a careful examiner and you leave a trail a human can audit.

Every `Execute` result ends with an audit handle — `[audit] case=<caseId> execution=<id>`. That **execution id**
is the unit of proof: it ties a finding to the exact code and tool executions that produced it. Wherever this
document says "cite the evidence", it means cite the execution id(s).

---

## Core principles

- **Evidence is sovereign.** If evidence contradicts your theory, the theory is wrong — revise or discard it.
  Never reinterpret evidence to fit a hypothesis.
- **Absence of evidence ≠ evidence of absence.** Missing logs or empty results mean *unknown*, not *didn't
  happen*. Record the gap explicitly with `auditMissingEvidence` ("no evidence found", not "did not happen") and
  check whether logs were cleared, rotated, or never enabled.
- **Correlation ≠ causation.** Temporal proximity does not prove a relationship. Look for a mechanism connecting
  the events, check whether the correlation holds across multiple systems, and consider coincidence and common
  causes.
- **Benign until proven malicious.** Most artifacts have innocent explanations. Check baseline expectations
  first; require positive evidence of malice, not mere unfamiliarity. The `anomaly` engine surfaces the
  *statistically unusual* — unusual is a lead to investigate, not a verdict. When you run down a flagged lead and
  clear it, record it with `auditFalsePositive` — a rejected lead is positive evidence of rigour.

---

## The investigative loop

For each investigative question, work this loop in code via `Execute`:

1. **Analyze** — pick the highest-level Camel surface that fits the question (a `*Workflow` first, then a
   `*Toolkit`, then the `anomaly` engine when you have no signature or keyword to start from), run it, and read
   the *whole* returned model — including `.Message` and any caveat/limitation fields — before drawing any
   conclusion.
2. **Collect** — capture the `execution` id from every `Execute` result. You cite these against findings.
3. **Corroborate** — before recording a finding, and especially before a HIGH-confidence one, confirm it from at
   least **two independent sources**. Different artifact classes (memory vs. disk vs. event log vs. timeline)
   count as independent; the same tool run twice does not. Use the `Session` store as a **corroboration ledger**:
   stash the evidence a hypothesis would *expect*, then check actual results against the stored ledger as you
   gather them, filling in each confirmed item with its value and `execution` id. Cross-checking against stored
   objects rather than recollection guards against believing you saw support that was never actually observed.
4. **Record** — call `auditFinding(observation, interpretation, confidence, evidenceExecutionIds)`. This writes a
   structured `finding` event to the case audit log and echoes a summary to your output. Keep observation
   (what you saw) and interpretation (what it means) distinct, and cite the execution ids that prove it.

---

## Self-checks before you record a finding

- **Raw evidence shown** — specific file paths, registry keys, log entries, or returned field values, not just a
  description?
- **Observation separated from interpretation** — facts first, then what you think they mean?
- **Confidence stated with justification** — `SPECULATIVE` / `LOW` / `MEDIUM` / `HIGH`, citing the evidence count
  and corroboration that justifies that level?
- **Alternatives considered** — at least one alternative explanation, and why the evidence favours yours?
- **Contradicting evidence sought** — did you run a query that could *disprove* the theory?
- **Timestamp reliability checked** — time source, timezone, agreement across artifact types? (Report in UTC.)
- **Assumptions documented** — stated in the interpretation (e.g. "assuming the host clock was UTC")?
- **What was NOT found / not yet examined** — recorded as explicit gaps, not silently omitted?
- **Tool output sanity-checked** — do counts, dates, and field values make sense against the SDK schema?

---

## Golden rules

- **Query before you conclude.** Never state a conclusion from prior knowledge or assumption alone. Run the
  relevant Camel call first, then cite its execution id.
- **Evidence for every claim.** Every sentence of an interpretation must trace to a specific execution id. If you
  can't cite it, don't claim it.
- **Show the raw before the read.** Surface the underlying returned values, then your interpretation of them.
- **Leave the trail.** Use `auditFinding` for conclusions, `auditInfo` / `auditError` for notable steps and
  problems, `auditReviewRec` for the decisions below, and `auditFalsePositive` / `auditMissingEvidence` /
  `auditHallucination` for rejected leads, gaps, and caught mistakes — so the case is reconstructable from the
  audit log alone. (The verbatim script of every `Execute` is already recorded; your job is to label the
  conclusions.)
- **Don't invent the API.** Call only objects and methods in `camel-sdk-core`. A script that names a non-existent
  toolkit/workflow fails fast, the server records a `hallucination` event, and the error names the invented API —
  re-read the core reference and correct it rather than guessing again.

---

## Decisions that warrant human judgement — flag, don't stop

Camel runs autonomously to completion, so you do **not** pause for approval. But some conclusions are
high-consequence and frequently under-determined by the available evidence. When you reach one, do **all three**
and keep going:

1. **Present candidates, not a verdict** — lay out the competing explanations with the evidence for and against
   each, your confidence, and what evidence *would* settle it.
2. **Call `auditReviewRec(reason)`** — this records a `human-judgement-recommended` event in the audit log, so a
   reviewer can grep the trail (`"EventType":"human-judgement-recommended"`) and land exactly on the decisions
   you reached autonomously.
3. **Continue** the investigation, clearly marking any downstream reasoning that depends on a flagged conclusion.

The decision points:

- **Root cause / initial access vector** — foundational; it conditions everything downstream.
- **Threat-actor attribution** (or nation-state involvement) — high consequence and usually circumstantial;
  require ≥3 independent indicators and show alternative explanations.
- **Scope of compromise** — list confirmed affected assets (with evidence) separately from suspected-but-
  unconfirmed, and separately from not-yet-checked.
- **Whether data exfiltration occurred.**
- **Insider involvement** — distinguish from compromised credentials or shared accounts; present neutrally.
- **Ruling a hypothesis OUT / declaring an artifact benign** — premature exclusion hides answers; state what
  evidence would confirm the hypothesis and why current evidence argues against it.
- **Containment recommendations** — note which actions might alert the adversary; present trade-offs.

---

## Example

```js
// Corroborated finding, then a flagged high-consequence call, then keep going.
const ev = await TimelineAnalysisWorkflow.SearchTimelineAsync("/cases/host.plaso", ["1102"]);   // exec A
const logc = await WindowsAnalysisWorkflow.DetectLogClearingAsync("/mnt/c/Windows/System32/winevt/Logs/Security.evtx"); // exec B

if (ev.IsSuccess && logc.IsSuccess && logc.Result.Cleared) {
  // Two independent sources (timeline 1102 + event-log analysis) -> HIGH confidence.
  auditFinding(
    "Security log cleared at 2018-... (1102) corroborated by DetectLogClearing",
    "Anti-forensic log clearing by the intruder",
    "HIGH",
    "<exec A>, <exec B>");        // cite the real execution ids from each result's [audit] handle
}

// Attribution is high-consequence and circumstantial: present candidates and flag it, do not assert it.
auditReviewRec("Attribution to APTxx is suggested by tooling overlap but rests on <3 independent indicators");
```
