# Camel

**Code-mode DFIR.** Camel is an MCP server that lets an AI agent run a digital-forensics and
incident-response investigation by *writing code against a typed SDK* — driving court-vetted SIFT
Workstation tools (Volatility, Sleuth Kit, Plaso, the Eric Zimmerman tools, YARA, …), codified DFIR
workflows, and a classical anomaly-detection engine — instead of calling raw command-line tools one at
a time and reasoning over their output in prose.

Camel is an entry in the [SANS **Find Evil!** AI Hackathon](https://findevil.devpost.com/).

---

## Why code-mode

Letting an agent call forensic tools one at a time floods its context with raw output (a 200 MB event
log, a full process list), is slow, and invites hallucination. Camel instead has the agent write a
small program that filters, correlates, and distills **on the workstation**, returning only the
conclusion. The agent's task becomes generating correct programs against a documented API — which it
does well — rather than improvising tool flags and stitching dumps together in natural language.

Every tool execution is recorded to a per-case audit trail so any finding traces to the exact command
that produced it, and the agent operates inside architectural guardrails (no shell, sandboxed engine,
read-only evidence, no network) rather than prompt-based requests.

---

## Documentation

| Doc | What it covers |
|-----|----------------|
| [docs/Architecture.md](docs/Architecture.md) | How code-mode works, the three SDK layers (toolkits / workflows / anomaly engine), and a session end to end. **Start here.** |
| [docs/Constraints.md](docs/Constraints.md) | The architectural guardrails that bound the agent, and why they beat prompt-based rules. |
| [docs/AuditTrail.md](docs/AuditTrail.md) | The per-case chain-of-custody record, and how to trace any finding back to its tool execution. |
| [docs/Camel.core.md](docs/Camel.core.md) | The agent-facing SDK reference: every object and method (also served live as `camel://sdk/core`). |
| [docs/Camel.schema.md](docs/Camel.schema.md) | The exact shape of every value the SDK returns (also `camel://sdk/schema`). |

### Worked example

[demo/audit-sample/](demo/audit-sample/) — a real audit trail from running Camel against the SANS
FOR508 **SRL-2018 rd-01** host, with a [three-claim trace](demo/audit-sample/THREE_CLAIM_TRACE.md)
showing three findings tracked back to the commands that produced them.

---

## Running an investigation

Case setup is handled entirely by the Camel CLI — no global configuration is touched. The
[`create-case`](docs/Architecture.md) command scaffolds a self-contained case directory (instructions,
MCP registration, code-mode permissions, and the chain-of-custody hooks), then you launch Claude Code
in it:

```bash
# Local SIFT workstation:
dotnet /opt/camel/Camel.CLI.dll create-case /cases CLIENT-IR-2025-001

# …or drive a remote SIFT workstation over SSH (flags baked into the case):
dotnet /opt/camel/Camel.CLI.dll create-case /cases CLIENT-IR-2025-001 \
  --ssh --host <sifthost> --user <siftuser> --pass <siftpass>

cd /cases/CLIENT-IR-2025-001 && claude
```

The benchmark wrapper that wires Claude Code to Camel for the hackathon (and lets it run side-by-side
with upstream Protocol SIFT for comparison) is [**protocol-sift-camel**](https://github.com/allisterb/protocol-sift-camel).

---

## How Camel maps to the judging criteria

| Criterion | Where it's addressed |
|-----------|----------------------|
| **Autonomous Execution Quality** | Code-mode self-correction: a wrong call is a concrete runtime error returned to the agent — see [Architecture.md](docs/Architecture.md), [IRAccuracy.md](docs/IRAccuracy.md). Self-correction is visible in the bundled chat transcript. |
| **IR Accuracy** | Typed SDK fails fast on invented methods/fields; findings grounded in structured returns, each cited to an audited command; an enforced forensic discipline (corroboration, fact/inference separation, calibrated confidence) with rejected-lead / gap / hallucination events in the trail — [IRAccuracy.md](docs/IRAccuracy.md), [Architecture.md](docs/Architecture.md), [AuditTrail.md](docs/AuditTrail.md). |
| **Breadth & Depth** | Codified multi-step DFIR **workflows** + cross-source correlation + a label-free **anomaly-detection** engine for timeline triage — [Architecture.md](docs/Architecture.md). |
| **Constraint Implementation** | Architectural guardrails (no shell, sandboxed engine, read-only evidence, no network), not prompt rules — [Constraints.md](docs/Constraints.md). |
| **Audit Trail Quality** | Per-case CLEF audit log; every finding traceable to its command; case reconstructable from logs alone — [AuditTrail.md](docs/AuditTrail.md), [demo/](demo/audit-sample/). |
| **Usability & Documentation** | This doc set; one-command case setup with zero global footprint; self-contained cases. |

---

## Project layout

| Path | What it is |
|------|------------|
| `src/Camel.CLI` | Command-line entry point: the MCP server and the `create-case` case scaffolder. |
| `src/Camel.Server` | The constrained JavaScript execution engine and MCP server. |
| `src/Camel.Toolkits` | Typed wrappers over individual SIFT tools. |
| `src/Camel.Workflows` | Codified multi-step DFIR procedures over the toolkits. |
| `src/Camel.Inference` | The anomaly-detection engine (timeline triage). |
| `src/Camel.Environments` | Local / SSH execution against the SIFT workstation, with command auditing. |
| `src/Camel.Runtime` | Shared base types, logging, and the per-case audit log. |
| `docs/` | The documentation above. |
| `demo/audit-sample/` | A real audit trail + three-claim trace walkthrough. |
