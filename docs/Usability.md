# Camel Usability & Documentation

*What it takes to stand Camel up and run a case — and why the footprint is small, self-contained, and the
same on every platform.*

For a reviewer or DFIR practitioner. No programming knowledge assumed.

---

## One dependency: .NET 9

Camel is a .NET 9 / C# application. Its only prerequisite is the **.NET 9 runtime** — there is no Python
environment to provision, no Node toolchain, no system packages to apt-install for the harness itself. The
forensic tools it drives live on the SIFT workstation (Camel calls them); the Camel side is a single,
self-describing executable invoked through `dotnet`.

Because .NET 9 is cross-platform, the **same build runs on Windows, Linux, and macOS**. An analyst can run
Camel on whatever machine they already work on.

---

## Local or remote — the analyst's machine, not the evidence box

Camel abstracts I/O behind an **audit environment**, so the identical code path works two ways:

- **Local mode** — Camel runs on the SIFT workstation itself and executes tools directly.
- **Remote mode** — Camel runs on the **analyst's own machine** and drives a SIFT workstation **over SSH**.
  Connection details (`--host`, `--user`, `--pass`, `--port`) are supplied at case-creation time.

This matters for usability: the analyst does not have to log into, or install anything on, the evidence
machine to work a case. They point Camel at SIFT from their own laptop and go. (Contrast a skills-plus-CLI
design, which must be installed and run *on* the box where the tools live.)

---

## No installer, no global footprint

There is **no install script** — nothing to `curl … | bash`, nothing that mutates your shell profile or
writes into `~/.claude`. You build the CLI once (`dotnet build`/`dotnet publish`) and use it.

Setting up an investigation is **one command**:

```
camel create-case <parent-dir> <case-id> [--host <sift> --user <u> --pass <p>]
```

That scaffolds a **self-contained case directory** and nothing else:

```
<case-id>/
├── CLAUDE.md          ← the analyst's brief to the agent (case id substituted in)
├── .mcp.json          ← registers the `camel` MCP server, with the SSH/local flags baked in
├── .claude/
│   └── settings.json  ← per-case policy: Bash denied, only Camel's tools + scoped writes allowed;
│                         a SessionEnd hook that preserves the chat transcript + token usage
├── logs/              ← audit trail, chat transcript, token usage (written as the case runs)
├── exports/           ← raw data the agent extracts
└── reports/           ← the agent's deliverables (report.md + iocs.csv)
```

Everything the case needs is **inside the case folder**:

- **Zero global footprint.** The Claude Code policy and hooks are emitted into the case's own `.claude/`,
  not your user-global config. Two cases on the same machine can't interfere; deleting the case directory
  removes every trace. Nothing in `~/.claude` is read, written, or backed up.
- **The case travels as a unit.** Brief, server registration, policy, logs, exports, and reports are all in
  one directory — hand it to another analyst (or a judge) and it is complete and reproducible on its own.
- **The hook needs only .NET.** The SessionEnd transcript/token-usage hook runs the same Camel CLI
  (`dotnet "<dll>" preserve-chatlog`) — no extra Python or Node interpreter to keep the case self-contained.

To run the investigation: launch Claude Code in the case directory. It reads `.mcp.json`, starts Camel over
stdio, applies the per-case `.claude/` policy, and the analyst's brief in `CLAUDE.md` drives the work.

---

## How this compares to protocol-sift

Camel and [protocol-sift](https://github.com/teamdfir/protocol-sift) target the same goal — Claude-driven
DFIR on SIFT — with different deployment models. The contrast, on usability terms:

| | protocol-sift | Camel |
|---|---|---|
| **Install** | `curl … \| bash` install script | None — a `dotnet` build; no script |
| **Global config** | Writes `CLAUDE.md` + `settings.json` into `~/.claude` (backs up existing) | Nothing in `~/.claude`; per-case `.claude/` only |
| **Where it runs** | On the SIFT box, where its skills/CLIs live | Analyst's own machine (local **or** SSH-remote to SIFT) |
| **Runtime deps** | Claude Code + the SIFT CLIs/skills on-host | .NET 9 (cross-platform) |
| **Case setup** | Case templates within the global install | One `create-case` command → self-contained case dir |
| **Footprint to remove** | Global `~/.claude` files (restore from backup) | Delete the case directory |

This is a design trade-off, not a verdict on protocol-sift — but for an analyst who wants to keep their
machine clean, work cases from their own workstation, and hand a complete case to someone else, Camel's
self-contained model is the lower-friction path.

---

## The documentation set

Camel ships documentation aimed at two audiences:

**For the reviewer / analyst** (this `docs/` set, no code assumed):

- [Architecture.md](Architecture.md) — how code-mode works and what the SDK provides.
- [Constraints.md](Constraints.md) — the architectural guardrails (no shell, sandbox, read-only evidence).
- [AuditTrail.md](AuditTrail.md) — how every finding traces to the command that produced it.
- [IRAccuracy.md](IRAccuracy.md) — the measures that keep findings accurate.
- This document — setup and footprint.

**For the agent** (served as MCP resources, read at the start of each case):

- `camel-sdk-core` — the execution model and the full method index.
- `camel-sdk-schema` — the JSON schema of every value the methods return.
- `camel-sdk-discipline` — the forensic investigative discipline the agent reasons by.

A new analyst needs only this set and a SIFT workstation to reach: read the brief, create a case, launch
Claude.

---

## Further reading

- [Architecture.md](Architecture.md) — the code-mode design.
- [Constraints.md](Constraints.md) — the guardrails that make the model safe to run autonomously.
- [AuditTrail.md](AuditTrail.md) · [IRAccuracy.md](IRAccuracy.md) — chain of custody and accuracy.
