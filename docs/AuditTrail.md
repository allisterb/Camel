# Camel Audit Trail

*How every finding traces back to the exact command that produced it — and how an analyst can
reconstruct the whole investigation from the logs alone.*

This document is for the reviewer or DFIR practitioner evaluating Camel's chain of custody. No
programming knowledge is assumed.

---

## Why this exists

Camel lets an AI agent (Claude) conduct a forensic investigation by writing small programs that drive
court-vetted SIFT tools (Volatility, Sleuth Kit, Plaso, the Eric Zimmerman tools, YARA, …). For that
to be trustworthy, two things must hold:

1. **Traceability** — any claim in the agent's report can be tied to the specific tool execution that
   produced it.
2. **Reconstructability** — another analyst could rebuild the investigation from the logs alone,
   without the agent, the chat, or the original operator.

The audit trail delivers both. It is the evidentiary backbone of the case: a complete, structured,
per-case record of every tool that ran, with what arguments, on which host, with what result.

---

## Where the logs live

Every case is a self-contained directory. All logs are bundled in one place — the case's **`logs/`**
folder — distinguished by filename:

```
<case>/
├── CLAUDE.md          ← the analyst's case brief (instructions to the agent)
├── logs/
│   ├── audit-<caseId>.clef        ← the audit trail: tool executions + the agent's findings   (THIS document)
│   ├── chatlog-<session>-<UTC>.jsonl  ← the full agent conversation transcript
│   └── token-usage.json           ← client-side token consumption (efficiency/cost)
├── exports/           ← raw data the agent extracted
└── reports/           ← the agent's written deliverables: report.md + iocs.csv
```

There is **one audit file per case**, named for the case id the analyst chose (e.g.
`audit-srl-2018-rd01.clef`). Nothing is scattered across machine-wide logs; the case travels as a unit.

> **Format.** The audit file is [CLEF](https://clef-json.org/) (Compact Log Event Format): plain text,
> **one JSON object per line**. It opens in any text editor, and tools like `jq` or even `grep` can
> query it. No database, no proprietary viewer.

---

## What gets recorded

The agent works in "code-mode": it calls one tool, **`Execute`**, with a short program. Each `Execute`
call is one **execution**, and an execution drives one or more **commands** (the actual SIFT tools).
The audit file records both, as two kinds of event.

### 1. Execution events — the agent's steps

A boundary marker for each `Execute` call: when it `started`, `completed`, `failed`, or was
`cancelled`. The `started` event captures **the exact program the agent ran** — so the log records not
just which commands fired, but the reasoning step that drove them.

### 2. Command events — the tool executions

One per SIFT tool invocation, carrying the full attribution chain plus the result:

| Field | Meaning |
|-------|---------|
| `CaseId` | The case this belongs to (also the file name). |
| `ExecutionId` | Which agent step (`Execute` call) drove this command — the link the agent cites. |
| `Workflow` / `WorkflowOperation` | The high-level DFIR procedure, if one was used (e.g. `WindowsAnalysisWorkflow` › `FindWmiPersistenceAsync`). |
| `Toolkit` / `Operation` | The specific tool wrapper (e.g. `WindowsAnalysis` / `AmcacheParser`). |
| `Command` / `Arguments` | The **literal command line** that executed on the workstation. |
| `Host` | Which machine it ran on (the SIFT workstation, local or over SSH). |
| `Sudo`, `ExitCode`, `DurationMs`, `Completed` | Whether it ran elevated, its exit status, how long it took, and whether it finished. |

A real command event (from the bundled demo, formatted for readability):

```json
{ "@t": "2026-06-12T23:46:27.34Z",
  "EventType": "command",
  "Command": "strings",
  "Arguments": "-t d -n 6 '/mnt/rd01-c/Windows/System32/wbem/Repository/OBJECTS.DATA'",
  "Host": "192.168.8.117", "ExitCode": 0, "DurationMs": 1279,
  "Workflow": "WindowsAnalysisWorkflow", "WorkflowOperation": "FindWmiPersistenceAsync",
  "ExecutionId": "7f3a9c21", "CaseId": "srl-2018-rd01" }
```

Read plainly: *under case `srl-2018-rd01`, agent step `7f3a9c21`, the WMI-persistence workflow read the
WMI repository on host `192.168.8.117`; the command exited 0 in 1.28 s.*

### 3. Analysis events — the agent's findings and judgements

Execution and command events are emitted *structurally*: the agent cannot run a tool without them (see
[Why the trail is trustworthy](#why-the-trail-is-trustworthy-by-design-not-by-request)). On top of that
mechanical record, the agent annotates the trail with its **reasoning** — the conclusions it reached, the
leads it rejected, the gaps it hit — so a reviewer can reconstruct the case at the level of *findings*, not
just commands.

| Event type | Written when | Why it matters |
|------------|--------------|----------------|
| `finding` | A corroborated conclusion is recorded. Carries `Observation` (what was seen), `Interpretation` (what it means), `Confidence` (`SPECULATIVE`/`LOW`/`MEDIUM`/`HIGH`), and `EvidenceExecutionIds` (the execution ids that prove it). | The primary unit of result — fact kept separate from inference, each finding linked to the commands that support it. |
| `human-judgement-recommended` | The agent reaches a high-consequence, under-determined conclusion (root cause, attribution, scope, exfiltration, insider). | Marks where a human should review. The agent presents candidates and keeps going; a reviewer greps these to land on every such decision. |
| `false-positive` | A lead was checked and cleared as benign. | Shows leads were run down and rejected — positive evidence of rigour, and a counterweight to over-flagging. |
| `missing-evidence` | An evidentiary gap — logs absent, cleared, rotated, or disabled; an artifact unavailable. | Records "no evidence found", *not* "did not happen" — the distinction that keeps conclusions honest. |
| `hallucination` | The agent caught itself inventing an artifact/method/field — **or** the server detected a script referencing a non-existent toolkit/workflow (auto-emitted). | Makes invented-API failures visible and self-correcting rather than silent. See [IRAccuracy.md](IRAccuracy.md). |
| `information` / `error` | The agent notes a notable step or problem worth keeping. | General-purpose annotation. |

A real `finding` event (formatted for readability):

```json
{ "@t": "2026-06-13T14:44:40.42Z",
  "EventType": "finding", "Confidence": "HIGH",
  "Observation": "ntds.dit MFT $SI Created 2018-09-05 12:16:54Z; DC inbound 4624/4768/4769 for 'spsql' from 172.16.6.11; rd-01 4648 spsql->172.16.4.4",
  "Interpretation": "AD database dump on the DC, performed as 'spsql' driven from rd-01 — triple-corroborated",
  "EvidenceExecutionIds": "c4b23ed6, 0ca8473e, 1bce2f3e",
  "ExecutionId": "0003b5fa", "CaseId": "SRL-2018-TEST5" }
```

Note the two id fields. `ExecutionId` is the agent step that *recorded* the finding; `EvidenceExecutionIds`
are the steps that **prove** it — each a real execution whose command events a reviewer can pull and check.
A finding is the agent's claim; the cited executions are the structural evidence behind it.

---

## The link from a finding to its evidence

Every `Execute` result ends with a one-line **audit handle**:

```
[audit] case=srl-2018-rd01 execution=7f3a9c21
```

The agent is instructed to **cite that `execution` id next to each finding** in its report. That id is
the bridge: report → execution id → the audit events (the agent step and every command it ran).

---

## Tracing a finding (the three-claim test)

To verify a finding, take its cited `execution` id and pull every event under it.


Worked example — the agent reports:

> "rd-01 has fileless persistence: a WMI `CommandLineEventConsumer` runs an encoded PowerShell command
> that decodes to a download cradle to the **squirreldirectory.com** C2.
> `[audit] case=srl-2018-rd01 execution=7f3a9c21`"

Tracing `7f3a9c21` lands on the `strings` command above, reading the WMI repository `OBJECTS.DATA` on
rd-01 — the source of that finding. **Claim supported.**

No special tooling required — because each record is a single line, plain `grep` works on any box:

```bash
grep '"ExecutionId":"7f3a9c21"' audit-srl-2018-rd01.clef
```

---

## Reconstructing the whole case from the file alone

The entire investigation is in the one file, grouped by execution. For example, list every headline
tool execution end to end:

```bash
jq -r 'select(.EventType=="command" and .Toolkit)
       | "\(.["@t"])  \(.Workflow // "-") › \(.Operation)  $ \(.Command) \(.Arguments)"' \
   audit-srl-2018-rd01.clef
```

Because the `started` execution events also carry the exact program the agent ran, the file records
**which** commands ran, **what code** drove them, and **how long** each took — enough to replay the
investigation independently.


---

## The other two logs

Bundled in the same `logs/` folder for a complete record of the session:

- **`chatlog-<session>-<UTC>.jsonl`** — the full Claude Code conversation transcript: every message,
  tool call, and timestamp. Self-correction and reasoning live here.
- **`token-usage.json`** — client-side token consumption, with a breakdown that separates **cached**
  reuse (read from the prompt cache, billed at a reduced rate) from genuinely **new** tokens (fresh
  input, cache writes, and output), plus a per-model breakdown and turn count. This makes the
  efficiency/cost figure honest — a cache-heavy session whose raw total looks large may be mostly
  reuse.

Both are written automatically when the session ends.

---

## Why the trail is trustworthy (by design, not by request)

The integrity of the audit trail does not depend on the agent choosing to log things. It is structural:

- **Single audited path.** Every SIFT tool runs through one command-execution layer that emits the
  command event. The agent cannot run a forensic tool *without* it being recorded — logging is not an
  instruction the model could skip or forget.
- **No shell escape.** The agent's shell (`Bash`) is denied by policy. The only way it can touch
  evidence is through Camel's audited API, so the audit file is complete by construction. (This is an
  architectural guardrail, enforced by the runtime — not a prompt asking the model to behave.)
- **Read-only evidence.** Camel mounts and reads disk and memory images read-only; the agent never
  writes to the evidence, only to its own `exports/` and `reports/`.
- **Per-case isolation.** Each case has its own session and its own audit file, keyed by the case id.
- **Out-of-band capture.** The chat transcript and token summary are written by a session-end hook run
  by the harness, outside the agent — it cannot omit or edit them.
- **Honest attribution.** When a command runs through a high-level workflow, the trail records the
  workflow and operation; when the agent calls a tool directly, there is simply no workflow field — the
  log reflects what actually happened rather than dressing it up.

---

## Field reference (quick)

| Event | Key fields |
|-------|-----------|
| `execution` | `Phase` (`started`/`completed`/`failed`/`cancelled`), `Script` (on `started`), `Success`, `DurationMs`, `ExecutionId`, `CaseId` |
| `command` | `Command`, `Arguments`, `Host`, `Sudo`, `ExitCode`, `DurationMs`, `Completed`, `Workflow`, `WorkflowOperation`, `Toolkit`, `Operation`, `ExecutionId`, `CaseId` |
| `finding` | `Observation`, `Interpretation`, `Confidence`, `EvidenceExecutionIds`, `ExecutionId`, `CaseId` |
| `human-judgement-recommended`, `false-positive`, `missing-evidence`, `hallucination`, `information`, `error` | `Message`, `ExecutionId`, `CaseId` |

Common to all: `@t` (UTC timestamp), `@mt` (the human-readable message template), `EventType`.

---

## Further reading

- [Architecture.md](Architecture.md) — how code-mode works and what the SDK provides.
- [Constraints.md](Constraints.md) — the architectural guardrails that bound the agent.
- [IRAccuracy.md](IRAccuracy.md) — the prompt and architectural measures that keep findings accurate.
