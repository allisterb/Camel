# Code-Mode in Camel

*Why Camel makes the agent write programs instead of calling tools, and how the execution engine is
built.*

This is the implementation-level companion to [Architecture.md](Architecture.md), which introduces
code-mode for a non-programmer. Here the audience is a reviewer or developer: it covers the
reasoning, the engine, the bindings, the failure modes that shaped the design, and the sharp edges
that remain. Security guardrails are treated separately in [Constraints.md](Constraints.md) and
only cross-referenced here.

---

## 1. What code-mode is

**Code-mode** is a programmatic tool-calling technique
([Anthropic](https://www.anthropic.com/engineering/code-execution-with-mcp),
[Cloudflare](https://blog.cloudflare.com/code-mode-mcp/)): rather than exposing N tools for the
model to call one at a time, the server exposes a **typed SDK and a single execution primitive**.
The model writes a program against the SDK; the server runs it next to the data; only the program's
distilled output returns to the model.

```
Tool-calling MCP                              Camel code-mode
────────────────                              ───────────────
model → call tool 1 → 200 MB back → model     model → writes one program →
model → call tool 2 →  50 MB back → model       Camel runs it on the workstation,
model → call tool 3 → …                         filters / correlates / ranks →
(raw output floods the context,                 returns the distilled result
 one round trip per step)                     (one round trip, only the answer)
```

Camel applies this to DFIR: the agent's task becomes **generating correct programs against a
documented, statically-typed API** — something LLMs are trained on at enormous scale — rather than
reasoning in prose over raw forensic dumps and improvising tool flags.

Camel's framing of the goal is to *lower* AI-driven forensic analysis: from natural-language
skills over plain-text tool output, down to code generation over specialized operations, workflows,
and machine-learning routines that codify existing analyst knowledge and consume and produce
**structured** data.

---

## 2. Why: five problems with tool-calling for forensics

### 2.1 The tool-definition tax

Every tool definition occupies context before any work begins. A faithful tool-per-operation
wrapper of the SIFT toolset would be hundreds of tools; even a modest catalog costs thousands of
tokens permanently.

Camel's equivalent surface — the full SDK reference — is **68 KB of method documentation and 95 KB
of return-type schemas**. Loading that up front for every session would be far worse than a tool
catalog.

Code-mode does not solve this by itself; it *relocates* the problem into documentation, which can
then be **paged**. Camel serves the reference as a map plus addressable subject areas
(§3.7), so a session reads an inventory and only the areas its task touches. The whole reference
stays available at `camel://sdk/core/all` for when it is genuinely wanted.

### 2.2 Intermediate results must pass through the model

This is the dominant cost in forensic work, and the fragment this document replaces recorded a real
instance of it. A script asked for a process list from a memory image and printed all of it:

```js
const ps = await MemoryAnalysisToolkit.WindowsPsListAsync(mem);
for (const r of rows) log(`${r[3]}\t${r[1]}\t${r[2]}\t${r[0]}`);   // print everything
```

```
Error: result (389,752 characters) exceeds maximum allowed tokens.
Output has been saved to …\tool-results\mcp-camel-Execute-1781377870456.txt
```

In a tool-calling design that 389,752-character payload **is** the tool result: there is nowhere to
put the filtering. In code-mode the filter is three lines earlier in the same program:

```js
const susp = /rclone|winscp|psexec|mimikatz|nc\.exe|certutil|bits|robocopy/i;
for (const r of rows) if (susp.test(r[3])) log(`${r[0]} pid=${r[1]} ppid=${r[2]} ${r[3]}`);
```

The distinction matters most where forensic data is largest: a 245 MB domain-controller
`Security.evtx`, a multi-GB memory capture, a 2.2-million-event super timeline. None of these can
enter a context window, and *sampling* them is exactly how the single `1102` "audit log cleared"
record gets dropped.

### 2.3 No transformation, aggregation, or joins between calls

Tool-calling gives the model no way to project fields, aggregate, or join across sources without
first materializing both sides in context. Correlating a process list against a timeline against a
registry hive means pulling all three in.

In a program these are ordinary expressions — `.filter()`, `.map()`, a `Map` keyed on PID, a
`Set` intersection — executed on the workstation, at no token cost.

### 2.4 Round-trip latency and error accumulation

Every tool call is a full model round trip. A 30-step investigation is 30 inference passes, each of
which can misread the previous output. A program expresses the same 30 steps once, and its
intermediate values are never re-interpreted by a language model — they are just variables.

As the context fills with raw tool output, the probability of misusing an API, misjudging a
consequence, or losing the thread rises. Code-mode keeps context small precisely where the risk of
error grows fastest.

### 2.5 The training-distribution argument

This is the reason the whole approach works. LLMs have seen vastly more correct JavaScript than
correct orchestration of forensic command-line tools. Code-mode converts the task into the one the
model is strongest at, and — critically — into one where **mistakes are mechanically detectable**:
a wrong method name is a runtime error, not confident prose (§4.1).

---

## 3. The implementation

Code-mode lives in `src/Camel.Server`. The engine is shared by both investigation domains; only the
bound globals differ.

| File | Role |
|---|---|
| `CamelMCPTools.cs` | the shared engine: the `Execute` tool, engine options, shared globals, audit integration, error classification, `table()` |
| `DFIRMCPTools.cs` | blue-team surface: evidence tools + the DFIR globals |
| `PenTestMCPTools.cs` | red-team surface: engagement tools + the offensive globals |
| `Sessions.cs` | per-session environment, `Session` storage, idle sweeping |
| `SdkDocs.cs` / `CamelResources.cs` | the SDK reference: area slicing and the index |

### 3.1 A deliberately small MCP surface

There is exactly **one execution tool**. Everything else is session or evidence setup, not
capability:

| Tool | Purpose |
|---|---|
| `Execute` | run a JavaScript program against the SDK; returns its distilled output plus an audit handle |
| `SetCaseId` | name the investigation so its audit trail is filed under a human-readable case id |
| `SetEvidence` | register the original evidence, arming the write-once spoliation guard (DFIR) |
| `VerifyEvidence` | re-hash the registered evidence and compare against supplied hashes (DFIR) |
| `EnsurePasswordlessSudo` | one-off provisioning for privileged tools over non-interactive SSH |

The forensic *capability* — every toolkit, workflow, and the anomaly engine — is reachable only
through `Execute`. That is what keeps the tool catalog from growing with the SDK.

### 3.2 The engine

[Jint](https://github.com/sebastienros/jint), an ECMAScript interpreter for .NET, configured in the
`CamelMCPTools` constructor:

```csharp
jsoptions = new Options();
jsoptions.Host.StringCompilationAllowed = false;              // no eval / new Function
jsoptions.ExperimentalFeatures = ExperimentalFeature.TaskInterop;  // await a CLR Task directly
jsoptions.Constraints.PromiseTimeout = TimeSpan.FromHours(24);
```

Three decisions worth explaining:

- **`StringCompilationAllowed = false`** disables `eval` and dynamically constructed code. The
  program cannot build new code at runtime to escape the bound surface.
- **`TaskInterop`** is what makes the SDK usable: an `async` C# method returning `Task<T>` is
  awaitable directly from JavaScript, so `await TimelineAnalysisWorkflow.CreateTriageTimelineAsync(…)`
  works with no wrapper layer.
- **`PromiseTimeout = 24h`** replaces Jint's 10-second default. That default is sensible for
  scripting a web page and catastrophic here — a super-timeline build or a multi-GB memory triage
  takes minutes to hours, and the default surfaced as a baffling
  `Promise rejected with Timeout of 00:00:10`.

Every submitted script is wrapped in an async IIFE before execution:

```csharp
jsinterp.ExecuteAsync($"(async () => {{\n{script}\n}})();", source: null, cancellationToken);
```

Top-level `await` is not available in a plain Jint script, and a module cannot drive a CLR-task
top-level await synchronously. The wrapper gives the agent top-level `await` anyway. The surrounding
newlines matter: without them a trailing `//` comment in the agent's script swallows the closing
brace.

### 3.3 Shared globals

Bound on every call, in both domains:

| Global | Purpose |
|---|---|
| `log(s)` / `error(s)` | accumulate response output |
| `exit(msg)` | stop immediately and return `msg` as ordinary output — *not* a tool error |
| `table(rows)` / `table(headers, rows)` | render an ASCII grid |
| `Session` | the per-session key-value store (§3.5) |
| `auditInfo` / `auditError` | write a line to the response **and** the case audit file |
| `auditFinding(observation, interpretation, confidence, evidenceIds)` | stage a structured forensic finding |
| `auditVulnerability(title, severity, cvss, asset, …)` | the red-team counterpart, carrying report-card fields |
| `auditReviewRec(reason)` | flag a high-consequence conclusion for human review |
| `auditFalsePositive` / `auditMissingEvidence` / `auditHallucination` | IR-accuracy events (see [IRAccuracy.md](IRAccuracy.md)) |

`exit()` is implemented by throwing `ExitException` to unwind the engine — the only reliable way to
halt — with a flag set synchronously *before* the throw, because Jint may wrap a CLR exception as a
promise rejection and lose the type. The catch block distinguishes it from a genuine fault and does
not mark the result as an error.

`table()` carries a scar worth recording. It was originally a typed CLR delegate
(`Action<string[], object[][]>`). Jint converts arguments *before* invoking a typed delegate, and
those conversion failures are **host** errors a script cannot catch: `table([{a:1},{a:2}])` died on
`No valid constructors found for type System.String`, and `table(model.Items)` on
`Object must implement IConvertible` — the latter killing the entire `Execute` call past a
`try/catch`. Since the natural call ("print this array of records") was exactly the failing one, it
is now a raw-argument `ClrFunction` that shapes the arguments itself and **returns a diagnostic
string on malformed input rather than throwing**. An output helper must not be able to kill an
analysis.

### 3.4 Domain globals, and why some are lazy

`BindDomainGlobals` is the only part of the engine that differs between the DFIR and pen-test
servers. In `DFIRMCPTools` the globals are declared as a table with an eagerness flag:

```csharp
("AnomalyDetectionToolkit", true,  _ => new Camel.Inference.AnomalyDetectionToolkit()),
("TimelineAnalysisWorkflow", true, s => s.WorkflowsApi.TimelineAnalysis),
…
("MemoryAnalysisToolkit",   false, s => s.ToolkitsApi.MemoryAnalysis),
("YaraToolkit",             false, s => s.ToolkitsApi.Yara),
```

```csharp
foreach (var (name, eager, resolve) in domainGlobals)
    if (eager || script.Contains(name, StringComparison.Ordinal))
        jsinterp.SetValue(name, resolve(session));
```

Workflows and the anomaly engine bind eagerly because construction is cheap — a workflow holds the
toolkit API and resolves toolkits on use, and the anomaly engine is pure computation with no
`AuditEnvironment` at all. **Toolkits bind lazily, only when the submitted script names them**,
because constructing one can trigger one-time provisioning (`Toolkit.InstallMissingTools` performs
synchronous downloads for the Eric Zimmerman tools, the YARA rules pack, hayabusa, …). Binding all
of them eagerly made the *first* `Execute` call of a fresh session hang while installing tools the
script never used — which presented as an unrelated "mount times out" symptom and took real effort
to diagnose.

A guardrail test asserts that the bound globals and the SDK documentation areas are exactly the same
set: a global with no documentation, or an area documenting nothing, fails the build.

### 3.5 Session storage

Each `Execute` call gets a fresh script scope, so `const`/`let` vanish between calls. `Session` — a
`Dictionary<string, object?>` bound identically on every call — is the one thing that persists:

```js
// First call: build it once.
const tl = await TimelineAnalysisWorkflow.CreateTriageTimelineAsync("/mnt/c", "/cases/host.plaso");
if (tl.IsSuccess) Session["timeline"] = tl.Result;

// A later call: the *same* object, no rebuild.
const t = Session["timeline"];
```

Three distinct benefits, only one of which is speed:

- **Speed** — the costliest steps run once instead of per call.
- **Reproducibility** — every later step reads the identical object. An agent that re-derives "the
  timeline" in two places can get subtly different results (re-filtered subsets, non-deterministic
  ordering); caching removes that drift.
- **Accuracy** — a finding that correlates two facts is sound only if both rest on the same
  evidence. See [IRAccuracy.md](IRAccuracy.md).

`delete Session["k"]` drops the reference so .NET reclaims the memory, keeping the cache from
growing without bound.

Idle handling is two-tier (`IdleSessionSweeper`): after the first threshold a session's **SSH
environment is disconnected but its `Storage` and `CaseId` survive**, and the next call reconnects
transparently; only after a longer threshold is the session evicted entirely. An investigation that
pauses does not lose its cached timeline.

### 3.6 Long calls: heartbeat and cancellation

A forensic program can legitimately run for many minutes. With no traffic on the response stream the
MCP client's per-call idle timeout fires and aborts the request — observed as *"transport dropped
mid-call; response was lost."*

`RunWithHeartbeatAsync` races the work against a 20-second timer and emits a progress notification
each time the timer wins, resetting the client's timer for the duration. Cancellation is wired in
both directions: if the client does abort, a registration on the cancellation token calls
`session.Environment.CancelExecutions()`, because Jint only observes its token at a JS/await
boundary — without it, a blocked SSH command reading a multi-GB tool output would keep running for
minutes after the client had gone. `CancelExecutions` swaps in a fresh token source so the session
remains usable.

`EnterCall`/`LeaveCall` mark the session busy so the idle sweeper cannot dispose the SSH environment
underneath a running analysis.

### 3.7 The SDK reference as paged resources

The reference documents are authored as one markdown file per kind and **sliced at runtime** into
addressable areas, so maintainers edit one place and the slices cannot drift:

| Resource | Contents |
|---|---|
| `camel://sdk/index` | the map — execution model, audit protocol, and the complete inventory of every global, method, and returned type, grouped by area |
| `camel://sdk/core/{Area}` | method detail for one area (`TimelineAnalysisToolkit`, `WindowsAnalysisWorkflow`, …) |
| `camel://sdk/schema/{Area}` | the fields of what that area's methods return |
| `camel://sdk/core/all`, `camel://sdk/schema/all` | the whole documents (~68 KB / ~95 KB) |
| `camel://sdk/discipline` | investigative discipline: how to reason over results, ground findings, flag high-consequence calls |

An area is named after the **JS global** it documents, because that is what the agent has in hand
when it needs the reference. Slices are located by heading *text* at any level, since the heading
level that names a toolkit is not consistent across the documents, and duplicate headings are
concatenated.

The effect on the tax in §2.1: a session reads the map (tens of KB) plus the two or three areas its
task touches, instead of ~163 KB of full reference. Reading the schema is not optional — without
it the agent cannot correctly read the fields of what a method returned — so making it cheap to
read *selectively* is what makes the discipline stick.

### 3.8 Audit integration

Every `Execute` call opens an audit scope carrying the session's `CaseId` and a fresh 8-character
`ExecutionId`, and both bracket the whole run so the properties flow across async boundaries into
the individual command-execution events. The exact script is recorded at start; completion,
failure, cancellation, and deliberate `exit()` are recorded distinctly, with durations.

The result returns the handle as a second content block:

```
[audit] case=srl-2018-rd01 execution=a3f19c04
```

The agent cites it next to each finding, so a reviewer can grep `audit-<caseId>.clef` and see
exactly which tool executions produced it. Details in [AuditTrail.md](AuditTrail.md).

---

## 4. What the design buys

### 4.1 Self-correction that actually works

A hallucinated method is not confident prose — it is a runtime error, immediately, and the script
**cannot continue past it**. That error text is returned to the agent, which corrects and retries.

Camel goes further and *classifies* the error. `ClassifyHallucination` recognizes two shapes:

- **An invented method.** Jint reports `Property 'Name' of object is not a function` without naming
  the receiver. Camel SDK methods are PascalCase by convention while JavaScript built-ins and a
  script's own helpers are camelCase, so a PascalCase missing member is almost certainly an invented
  SDK call — on a global *or* on a value one returned.
- **An invented global**, reported as `<Name> is not defined`, scoped to `*Toolkit`/`*Workflow` names
  so an ordinary undeclared-variable typo is not misfiled.

A match is recorded as a `hallucination` event in the audit trail and appended to the error the agent
receives, pointing it back at `camel://sdk/index`. Hallucination becomes an **observable, logged,
self-correcting** event rather than an invisible one — which is also why the trail can be used as
evidence of investigative rigour.

### 4.2 Determinism

A workflow is a fixed sequence of tool invocations. Calling it twice runs the same commands in the
same order — unlike a model re-deriving a procedure from prose, which may vary between runs. The
audit trail records the exact script, so any execution can be replayed and inspected.

### 4.3 Parallelism

Independent steps run concurrently. In JavaScript that is `Promise.all` over awaited SDK calls; in
the workflows themselves it is `Task.WhenAll`. Because the toolkit surface is `async` end to end,
independent tool invocations overlap instead of serializing — with concurrency capped so a
workstation is not driven out of memory.

### 4.4 Dedicated routines for data-intensive tasks

Some analyses should not be done by a language model at all. Ranking a 145,756-event timeline by
statistical surprise is arithmetic — exact, instant, and free in code; slow, expensive, and
unreliable token by token. The anomaly engine is bound as a global for exactly this reason; see
[MachineLearning.md](MachineLearning.md) and
[MachineLearningExpanded.md](MachineLearningExpanded.md).

### 4.5 Safety

Code-mode also makes guardrails enforceable *structurally*: there is no shell, no ambient
filesystem or network access, and only the explicitly bound objects are reachable. Scope and
activity gating on the offensive side, and the evidence-spoliation guard on the forensic side, sit
below the SDK where a script cannot route around them. That is [Constraints.md](Constraints.md)'s
subject and is not repeated here.

---

## 5. The sharp edges

Code-mode is not free. These are the recurring costs, all discovered the hard way.

**The .NET/JavaScript marshalling boundary leaks.** Agent-facing model properties must expose
materialized arrays (`T[]`), not lazy `IEnumerable<T>` — Jint hands a bare CLR enumerable to the
script with no `.map`, `.filter`, or `.length`, and the agent gets a `TypeError` on the most natural
thing to write. Similarly, a `ToolResult<int>`/`ToolResult<bool>`'s `Result` is *not* nullable
(unconstrained `T?` erases for value types), so it silently reads `0`/`false` on failure — scripts
must gate on `.IsSuccess`, never on `.Result == null`.

**The response is still capped.** Distilling inside the program is a discipline the agent has to
observe, not a guarantee; §2.2's 389,752-character failure is what forgetting looks like. The SDK
documentation and discipline resource both push toward summarizing rather than dumping.

**Jint is not V8.** No npm, no Node built-ins, a subset of modern JavaScript. That is a deliberate
security property (§3.2) and a real ergonomic cost, and it means engine-specific behaviour —
argument conversion, promise wrapping, CLR interop — has to be understood rather than assumed.

**Documentation is load-bearing.** Because the agent codes against a document, an API change that
misses the docs is worse than a build break: the agent writes code against an API that no longer
exists. Hence the guardrail test tying bound globals to documented areas, and the standing rule that
an SDK change updates the reference documents *and* the case template together.

**Errors are the primary feedback channel**, so their quality is part of the API. Every one of the
error-handling behaviours above — the exit flag, the raw-argument `table()`, the hallucination
classifier, returning partial output before a failure — exists because a bad error message costs an
entire round trip.

---

## 6. Where it runs

Camel is a cross-platform .NET application. It runs either **directly on the Linux-based SIFT
workstation**, or on a Windows or Linux machine that **connects to a workstation over SSH**, with no
code changes: `AuditEnvironment` abstracts command execution and file I/O so the same SDK call works
locally or remotely (see [AuditEnvironments.md](AuditEnvironments.md)).

The agent's program always refers to paths *on the workstation*. Each MCP session gets its own
environment and therefore its own SSH connection, resolved by session id.

The same engine serves both investigation domains — `dfir-server` binds the SIFT toolkits, workflows
and the anomaly engine; `pentest-server` binds the offensive toolkits and workflows behind the
engagement scope gate. Everything in §3.2 through §3.8 is shared.

---

## 7. Further reading

- [Architecture.md](Architecture.md) — the non-technical introduction to the same design.
- [Constraints.md](Constraints.md) — the architectural guardrails and why they are not prompt-based.
- [AuditTrail.md](AuditTrail.md) — the chain-of-custody record and how to trace a finding.
- [IRAccuracy.md](IRAccuracy.md) — the accuracy events and what they measure.
- [Workflows.md](Workflows.md) / [PenTestWorkflows.md](PenTestWorkflows.md) — the codified procedures.
- [MachineLearningExpanded.md](MachineLearningExpanded.md) — the anomaly engine in depth.
- `camel://sdk/index` — the agent-facing SDK map (authored as [Camel.core.md](Camel.core.md) and
  [Camel.schema.md](Camel.schema.md)).
