# Camel Architecture — Code-Mode DFIR

*How Camel lets an AI agent run a forensic investigation by writing code against a typed SDK instead
of driving raw command-line tools one call at a time.*

For a reviewer or DFIR practitioner. No programming knowledge assumed.

---

## The problem it solves

The usual way to give an AI agent forensic capability is to let it call tools one at a time: run a
Volatility plugin, read the (often huge) output back into the model's context, decide the next call,
repeat. That approach has three chronic problems:

- **Context flooding** — raw tool output (a 200 MB event log, a full process list) is pulled into the
  model's limited context window, crowding out reasoning and driving up cost and latency.
- **Slowness** — every step is a full round-trip through the model.
- **Hallucination surface** — the model improvises tool flags and stitches results together in prose,
  with nothing to catch a mistaken assumption.

## The approach: code-mode

Camel uses **code-mode** (a programmatic tool-calling technique described by
[Anthropic](https://www.anthropic.com/engineering/code-execution-with-mcp) and
[Cloudflare](https://blog.cloudflare.com/code-mode-mcp/)). Instead of one tool call per step, the agent
writes a **small program** that orchestrates the forensic tools, and Camel runs it on the SIFT
workstation. The program filters, correlates, and distills *on the workstation*; only the conclusion
comes back to the model.

```
Traditional agent                         Camel code-mode
─────────────────                         ───────────────
model → call tool 1 → 200MB back → model  model → writes one program →
model → call tool 2 → 50MB back → model     Camel runs it on SIFT, filters/correlates →
model → call tool 3 → ...                    returns the distilled result
(raw output floods the context)           (only the answer hits the context)
```

The agent's job becomes **generating correct programs against a documented API** — a task LLMs are
strong at — rather than reasoning over raw forensic dumps in natural language.

---

## What the agent talks to

Camel is an **MCP server** (Model Context Protocol — the standard way Claude Code connects to external
capabilities). It exposes a deliberately tiny surface:

| MCP surface | Purpose |
|-------------|---------|
| **`SetCaseId`** (tool) | Names the investigation so its audit trail is filed under a human-readable case id. Called once. |
| **`Execute`** (tool) | Runs a JavaScript program against the Camel DFIR SDK and returns the distilled result. |
| **`camel://sdk/core`** (resource) | The SDK reference: every object and method, with parameter and return types. |
| **`camel://sdk/schema`** (resource) | The exact shape (fields) of every value the methods return. |

The agent reads the two reference resources first, then drives the whole case through `Execute`.

---

## What the SDK offers (three layers)

The program the agent writes calls into a typed SDK with three layers, from lowest to highest level:

1. **Toolkits** — typed wrappers over individual SIFT tools, grouped by domain: memory
   (Volatility 3), disk (Sleuth Kit / EWF), Windows artifacts (the Eric Zimmerman tools, event logs,
   registry), timeline (Plaso), YARA, and Unix utilities. Each method runs one tool and returns a
   parsed, structured result instead of raw text.

2. **Workflows** — codified multi-step DFIR procedures built on the toolkits: e.g. "find the malware on
   this memory image" (a six-step hunt), "build a triage timeline and surface the anomalies", "detect
   credential dumping", "hunt lateral movement". These encode established analyst knowledge (FOR508-style
   procedures) so the agent reaches for a vetted recipe rather than reinventing one. The agent is
   instructed to **prefer workflows**, dropping to toolkits only for gaps.

3. **Anomaly-detection engine** — classical, label-free machine-learning triage over large timelines
   (rare events, rare transitions, timing bursts/beacons). When there's no known signature or keyword
   to start from, this ranks a 100,000-event timeline down to a short, *explained* shortlist of what's
   statistically unusual — answering "where do I even begin to look?". Forensic triage of this kind is
   far better suited to a dedicated algorithm than to the model reading the timeline line by line.

Distilling inside the program (and using the anomaly engine to pre-rank) is what keeps irrelevant data
out of the model's context.

---

## Where it runs

Camel runs on .NET and works two ways without code changes:

- **On the SIFT workstation** — local execution.
- **From a separate machine** (e.g. Windows) **driving a remote SIFT workstation over SSH** — the same
  SDK calls execute on the remote box.

The agent's program always refers to paths *on the workstation*; Camel handles the local-or-remote I/O.

---

## A session, end to end

1. Claude Code launches the Camel MCP server for the case.
2. The agent reads `camel://sdk/core` and `camel://sdk/schema`.
3. It calls `SetCaseId("srl-2018-rd01")`.
4. It calls `Execute` with a program — for example: mount the disk image read-only, build a triage
   timeline, run the anomaly engine, and report the high-signal pivots. Camel runs it on SIFT and
   returns the distilled result plus an audit handle (`[audit] case=… execution=…`).
5. The agent reasons over the distilled result, writes more `Execute` programs to drill in, and
   assembles a report — citing the audit handle next to each finding.

Every tool the program runs is recorded in the case's audit trail (see
[AuditTrail.md](AuditTrail.md)), and the whole thing is bounded by architectural guardrails (see
[Constraints.md](Constraints.md)).

---

## Why this design helps on each axis

- **Autonomy & self-correction** — a mistaken method name or wrong assumption surfaces as a concrete
  runtime error from the JavaScript engine, which is returned to the agent so it can correct and retry
  — genuine, observable self-correction rather than guesswork.
- **Accuracy / fewer hallucinations** — the agent codes against a typed, fully documented SDK;
  inventing a method or field fails fast instead of producing confident prose. Findings are grounded in
  structured return values, each cited to its audited command.
- **Breadth & depth** — workflows provide depth (multi-step, cross-source procedures), and the anomaly
  engine adds a triage capability the agent couldn't cheaply do by hand.
- **Efficiency** — distilling on the workstation keeps raw output out of context, cutting tokens and
  latency (see the per-case `token-usage.json`).

---

## Further reading

- [AuditTrail.md](AuditTrail.md) — the chain-of-custody record and how to trace any finding.
- [Constraints.md](Constraints.md) — the architectural guardrails that bound the agent.
- `camel://sdk/core` and `camel://sdk/schema` — the agent-facing SDK reference (also in
  [Camel.core.md](Camel.core.md) / [Camel.schema.md](Camel.schema.md)).
