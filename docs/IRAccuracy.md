# Camel IR Accuracy

*How Camel keeps an AI agent's forensic conclusions accurate — grounded in real evidence, honest about
confidence, and free of invention — through measures built into the architecture, not just asked for in a
prompt.*

For a reviewer or DFIR practitioner evaluating the trustworthiness of Camel's findings. No programming
knowledge assumed.

---

## What "accuracy" means here, and what threatens it

An incident-response report is only useful if its claims are *true* and *calibrated*. The characteristic
ways an LLM-driven investigation goes wrong are:

1. **Hallucination** — inventing an artifact, a tool, a field, or a fact that the evidence never showed.
2. **False positives** — calling a benign artifact malicious (an unfamiliar-but-normal service, a routine
   scheduled task).
3. **False negatives / mistaking gaps for facts** — treating a missing log as proof that "nothing
   happened" rather than "we don't know."
4. **Over-claiming** — stating a high-consequence, under-determined conclusion (attribution, root cause,
   scope, exfiltration) as settled fact.
5. **Misreading tool output** — drawing a conclusion from a large, noisy dump the model skimmed.

Camel addresses each with two complementary layers: **architectural measures** that make a class of error
structurally hard or self-revealing, and **prompt/discipline measures** that codify how a careful examiner
reasons. The two reinforce each other — defense in depth — and crucially, **every measure leaves a trace in
the audit trail**, so a reviewer can *verify* that the rigour happened rather than take it on faith.

---

## Architectural measures (structural, not advisory)

These do not depend on the model choosing to behave. They follow the same philosophy as Camel's
[guardrails](Constraints.md): make the failure impossible, or make it impossible to hide.

### A typed SDK that fails fast on invention

The agent does not free-type tool invocations. It calls a documented, typed API (the toolkits and
workflows in the `camel-sdk-core` resource). Calling a method or object that does not exist is a concrete
runtime error, not a plausible-looking wrong answer — so a fabricated capability **stops the script**
instead of silently producing fiction. The error names the invented API and is returned to the agent, which
turns the failure into a self-correction (re-read the reference, call the real method).

This is the core of how Camel attacks hallucination (threat 1): the surface the model can act through is
exactly the surface that actually exists.

### Invented APIs are recorded, not just rejected

When a script error names a non-existent `*Toolkit`/`*Workflow`, the server classifies it as a probable
**API hallucination** and emits a `hallucination` event to the audit trail automatically (see
[AuditTrail.md](AuditTrail.md)). The classifier is deliberately **conservative** — it fires only on the two
unambiguous, API-named error shapes ("is not defined" / "is not a function" on a Camel object). Ordinary
undeclared-variable typos and Jint language-feature gaps are *not* labelled hallucinations, because
"hallucination" is a strong claim in a forensic record and over-labelling would erode its meaning. Invented
*property* reads (which yield `undefined` rather than throwing) are left to the agent's own judgement (see
`auditHallucination` below).

### Findings are grounded in structured returns

Toolkit methods return **typed models with named fields**, not free text. The agent reads
`process.Pid`, `event.Timestamp`, `report.HighConfidenceSuspects` — values whose meaning and shape are
fixed and documented in `camel-sdk-schema`. This narrows the room to misread output (threat 5): the agent
consumes parsed fields, not a wall of console text it has to interpret. Workflows go further, returning a
`WorkflowResult<T>` the agent must check (`IsSuccess`, then read `Result`) before using the payload — a
fabricated "success" can't slip through an unchecked failure.

### Code-mode keeps irrelevant output out of context

Because the agent filters and reduces data *inside* the sandbox and returns only the distilled result, the
megabytes of raw tool output never enter the model's context window. Less noise in context is less material
to confuse, conflate, or misattribute (threat 5). This is the same context-efficiency property that makes
code-mode fast; here it doubles as an accuracy measure.

### The anomaly engine surfaces leads, not verdicts

Camel's label-free `(event_id, Δt)` anomaly detectors triage a large timeline down to a ranked, *explained*
shortlist of the statistically unusual. The output is framed — in the API and the discipline — as **leads to
investigate, not conclusions**. Statistically unusual is not the same as malicious; the agent must still
corroborate before recording a finding. This guards against the anomaly score itself becoming a false
positive (threat 2).

### Read-only evidence and a single audited path

Every forensic tool runs through one command-execution layer, against evidence mounted **read-only**, with
no shell escape ([Constraints.md](Constraints.md)). The agent reasons over the *real, unmodified* evidence,
and every command that produced a value is recorded. Accuracy is meaningless if the underlying data could
have been altered or if a finding could rest on an unrecorded command — neither is possible here.

---

## Prompt / discipline measures (the examiner's method)

The architecture bounds what the agent *can* do; the discipline shapes how it *should reason*. This is the
`camel-sdk-discipline` resource — the SANS DFIR method adapted to Camel — which every case is instructed to
read before drawing conclusions. (Defense in depth: these also restate the architectural rules.)

### Core principles

Four principles directly target the accuracy threats:

- **Evidence is sovereign** — if evidence contradicts the theory, the theory is wrong. (Against
  rationalising over-claims.)
- **Absence of evidence ≠ evidence of absence** — a missing log is *unknown*, not *didn't happen*. (Against
  threat 3.)
- **Correlation ≠ causation** — temporal proximity is not a mechanism. (Against false links.)
- **Benign until proven malicious** — require positive evidence of malice, not mere unfamiliarity. (Against
  threat 2.)

### Corroboration before confidence

A finding — especially a HIGH-confidence one — must be confirmed from **at least two independent artifact
classes** (memory vs. disk vs. event log vs. timeline). A single tool echoed twice does not count. This is
the structural antidote to both false positives and over-claiming.

### Findings separate fact from inference, with cited proof

Conclusions are recorded with `auditFinding(observation, interpretation, confidence, evidenceExecutionIds)`.
The signature **forces** the discipline:

- `observation` (what was seen) is kept distinct from `interpretation` (what it means) — so a reviewer can
  check the inference against the fact.
- `confidence` is an explicit `SPECULATIVE`/`LOW`/`MEDIUM`/`HIGH` — calibration is stated, not implied.
- `evidenceExecutionIds` cites the executions that prove it — every claim is traceable to its commands
  ([AuditTrail.md](AuditTrail.md)).

### Accuracy events: rejected leads, gaps, and caught mistakes

Three recording functions surface the *negative space* of an investigation — the part that is normally
invisible and where accuracy quietly succeeds or fails:

- **`auditFalsePositive(message)`** — a lead checked and cleared as benign. Recording it is positive evidence
  the agent ran the lead down rather than ignoring or over-flagging it (threat 2).
- **`auditMissingEvidence(message)`** — an evidentiary gap (absent, cleared, rotated, or disabled logs; an
  unavailable artifact). Records "no evidence found", not "did not happen" (threat 3).
- **`auditHallucination(message)`** — the agent catching *itself* inventing an artifact, method, or field
  (complementing the server's automatic detection above) (threat 1).

These are framed to the agent as **evidence of rigour, not admissions of failure** — so the incentive is to
surface them, not hide them.

### Flag high-consequence calls instead of asserting them

For the under-determined, high-consequence conclusions (root cause, attribution, scope, exfiltration,
insider), the agent does **not** assert a verdict. It presents the candidate explanations with the evidence
for and against each and its confidence, calls `auditReviewRec(reason)` to mark a
`human-judgement-recommended` event, and continues autonomously. A reviewer greps those events to land on
exactly the decisions that warrant a human (threat 4). The run stays autonomous; the over-claim is averted.

---

## Accuracy you can audit

The point of recording all of this is that a reviewer can **check the rigour, not just trust it**. From the
case's audit file alone:

- Every `finding` carries its confidence and the execution ids that prove it — pull them and verify the
  claim against the commands ([AuditTrail.md](AuditTrail.md), three-claim trace).
- `grep` the `false-positive` events to see which leads were run down and dismissed.
- `grep` the `missing-evidence` events to see what was unknown and why — and confirm no conclusion overreaches
  a gap.
- `grep` the `human-judgement-recommended` events to see every high-consequence call flagged for a human.
- `grep` the `hallucination` events to see any invented API the agent hit (and corrected).

Accuracy in Camel is therefore not a claim about the model — it is a property of the system and a record you
can inspect.

---

## Further reading

- [Architecture.md](Architecture.md) — how code-mode and the typed SDK work.
- [AuditTrail.md](AuditTrail.md) — the per-case record every measure above writes to.
- [Constraints.md](Constraints.md) — the architectural guardrails (read-only evidence, no shell, sandbox).
- `camel-sdk-discipline` — the forensic discipline resource the agent reads each case (source:
  `docs/Camel.discipline.md`).
