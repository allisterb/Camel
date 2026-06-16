# Audit Environments

An **audit environment** is the layer that sits *below* the toolkits in Camel's SDK and performs
all the actual I/O against the machine where SIFT Workstation runs. When the code-mode agent's
JavaScript calls a toolkit method, that method never touches the operating system directly — it
asks its audit environment to run a command or read a file. The audit environment is what makes
the same toolkit code work unchanged whether SIFT is local or reached over the network, and it is
the single chokepoint where command execution, evidence protection, concurrency, cancellation,
and the forensic audit trail are enforced.

## Where it sits

```
Agent JavaScript  (runs in the Jint engine)
      │  calls
Workflows         (Camel.Workflows — orchestrate multiple toolkit calls)
      │  call
Toolkits          (Camel.Toolkits — one strongly-typed method per SIFT tool)
      │  delegate all I/O to
AuditEnvironment  (Camel.Environments)  ◄── this layer
      │  runs commands / reads files on
SIFT Workstation  (local process, or remote over SSH)
```

Every toolkit takes a single `AuditEnvironment` as a constructor parameter and uses only its
abstracted I/O methods (`ExecuteCommandAsync`, `GetFileAsLocal`, `FileExists`, …). A toolkit
contains no knowledge of *where* the work runs.

## One abstraction, two implementations

`AuditEnvironment` is an abstract base class with two concrete implementations:

- **`LocalEnvironment`** — Camel is installed on the SIFT Workstation itself and runs tools as
  local child processes. On Unix, commands are run through `/bin/bash -c` so that pipes,
  redirects, `$()`, and escaped parentheses behave exactly as they would in a shell.
- **`SshAuditEnvironment`** — Camel runs on a separate machine and drives a remote SIFT
  Workstation over SSH (via SSH.NET). Commands execute through an SSH channel; large tool outputs
  are pulled back with SCP (`GetFileAsLocal`) so they can be stream-parsed from disk rather than
  captured through stdout. The connection is reconnect-on-demand: an idle sweep can release the
  expensive SSH transport (`DisconnectIdle`) while keeping the session's in-memory state, and the
  next command transparently reconnects.

Because both expose the same API, **a toolkit written once runs identically against a local or a
remote SIFT** — the only difference is which environment was created from configuration. The
environment is selected by the `SIFT:Environment` setting (`Local` or `Ssh`) via
`AuditEnvironment.CreateFromConfig`.

## What the environment is responsible for

Pushing these concerns down to the environment — the layer "closest" to where the evidence and
tools physically live — means every toolkit inherits them for free, rather than each tool having
to remember them.

### Command execution and OS abstraction
`ExecuteCommand` / `ExecuteCommandAsync` are the funnel every tool call passes through. They
handle privilege elevation (`sudo` on Unix), capture stdout/stderr and exit codes into a uniform
`CommandResult`, and normalize platform differences (path separators, line terminators, OS/version
detection). Higher-level helpers (find files, read env vars, list processes, resolve symlinks)
are built on the same primitive.

### Forensic audit trail
Every command — synchronous or async — is recorded in the per-case audit trail at exactly one
place: `AuditCommand`, called inside the execute methods. Each entry is enriched *ambiently* from
the logging context with the case ID, execution ID, and the originating toolkit, operation, and
workflow, producing the complete `Workflow → Operation → command` provenance chain that a finding
can be traced back to. The SSH environment attributes commands to the remote host name; the local
one to the local machine name (`AuditHostName`). Because auditing lives at this single chokepoint,
**no tool can run a command that escapes the audit log.**

### Evidence-spoliation protection
The original case evidence (disk images, memory captures, mounted artifacts) is registered against
the environment — **write-once per session**, so the guard cannot be silently repointed
mid-investigation. Before any write, overwrite, or delete, a toolkit calls
`FailIfEvidenceSpoliationRisk`, which throws if the target is an evidence file *or its containing
directory*. Path comparison normalizes separators and honours the filesystem's case-sensitivity so
an equivalent spelling cannot slip past. The environment can also verify evidence integrity on
demand (`VerifyCaseEvidenceAsync`), re-hashing each registered file and comparing it to the hash
supplied at registration — with EWF/`.E01` images content-verified via `ewfverify` rather than
hashing the container file. Enforcing this at the environment turns spoliation protection into an
architectural guarantee instead of a per-tool convention.

### Concurrency limiting
The async execute path runs under an optional per-environment concurrency cap
(`MaxConcurrentExecutions`, from config; `0` = unlimited). This bounds fan-out so that a code-mode
`Promise.all` issuing many parallel toolkit calls cannot exhaust the SSH connection's channels or
swamp the workstation.

### Cancellation
Every async command observes a shared cancellation token (`ExecuteCt`). Tripping it via
`CancelExecutions` aborts all in-flight and pending commands at once — for example when the MCP
client disconnects mid-call — and installs a fresh token so the session can continue afterward.

## Why this design matters

- **Write-once-run-anywhere toolkits.** The local/remote split lives entirely in the environment,
  so toolkit and workflow code stays free of transport details.
- **Auditability by construction.** A single execution chokepoint guarantees a complete,
  case-attributed chain of custody for every tool invocation.
- **Safety by construction.** Spoliation protection and concurrency/cancellation limits are
  enforced beneath the toolkits, so they apply uniformly and cannot be forgotten by an individual
  tool — or by generated agent code.
