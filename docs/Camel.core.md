# Camel JavaScript SDK — Core Reference

This is the **core** reference for the Camel JavaScript (JS) SDK — the typed API exposed to code that the agent
generates and executes inside the Camel MCP server's constrained JavaScript engine (via the `Execute`
MCP tool). It covers the **execution model** (the rules every generated script must follow) and the **method
signature index** for every top-level object: each method's name, purpose, parameter types, and return type.

The **JSON schema for every parameter and return model type** named below lives in the companion resource
**`camel-sdk-schema`** (`Camel.schema.md`). Read this core doc first to know what to call and what each call
returns; consult the schema doc when you need the exact fields of a returned object.

Camel is a *code-mode* MCP server: rather than invoking SIFT forensic tools one MCP call at a time, the model
writes a JavaScript program that orchestrates **toolkits** (typed wrappers over individual SIFT tools),
**workflows** (codified DFIR procedures built on the toolkits), and an **anomaly-detection** engine — returning
only the distilled result and keeping irrelevant tool output out of the model's context window.

> Only the objects and methods listed here exist. Do not call anything not documented in this reference.

## Execution model (read this first)

Scripts run on the [Jint](https://github.com/sebastianros/jint) engine, which supports most of **ECMAScript 2025**
(arrow functions, `let`/`const`, destructuring, template literals, `for…of`, spread, optional chaining `?.`,
nullish coalescing `??`, `Array`/`Map`/`Set`/`JSON`, etc.). Tailor generated code to that language version.

- **Your script body is wrapped in an `async` IIFE**, so top-level `await` is allowed. Do not add your own
  outer `async` wrapper — just write statements.
- **Almost every toolkit and workflow method is asynchronous** (returns a .NET `Task`, bridged to an awaitable
  JS promise). You **must `await`** them. The exception is `AnomalyDetectionToolkit`, whose methods are synchronous.
- **Methods are invoked by their C# (PascalCase) names**, e.g. `await MemoryAnalysisToolkit.WindowsPsListAsync(image)`.
- **Returned objects expose properties in PascalCase**, e.g. `result.IsSuccess`, `event.Timestamp`.
- **Parameters are positional** (JS has no named args). Omit *trailing* optional params; pass earlier defaults
  explicitly (use `null` for nullable types) to reach a later one.
- **Toolkit data methods return a `ToolResult<T>` (check `.IsSuccess`, read `.Result` or `.Message`); a handful of
  pure-action methods (mount / dump / extract) return `bool`; workflow methods return `WorkflowResult<T>`.** A
  failed `ToolResult` distinguishes "the tool isn't installed on this platform" from "the command ran but failed";
  an empty `.Result` collection means "ran clean, found nothing" — not a failure. Always check `.IsSuccess`
  before reading the payload. (See the `ToolResult` schema in `camel-sdk-schema`.)
- Output via the globals `log` / `error` / `table`. The `audit*` family additionally persists to the per-case
  audit log: `auditInfo`/`auditError` (notes), `auditFinding`/`auditReviewRec` (a structured finding / a review
  flag), and `auditFalsePositive`/`auditMissingEvidence`/`auditHallucination` (IR-accuracy events). There is no
  interactive prompting. `eval`/`new Function` are disabled.
- **How to reason** over what these methods return — the investigative discipline, grounding rules, and the
  decisions to flag for human judgement — is the companion resource **`camel-sdk-discipline`** (`Camel.discipline.md`).
- **`Session`** is a string-keyed store that **persists between `Execute` calls** in the same session: cache an
  expensive result once and reuse it later (see *Session storage* below) instead of recomputing it.

Path arguments are paths **on the SIFT workstation** (local or over SSH). Each MCP session has its own isolated
environment; toolkits are constructed lazily on first access and cached for the session.

## Audit trail (case attribution — do this)

Camel records every tool execution to a **per-case audit log** so any finding can be traced to the exact command
that produced it. Two things are expected of you:

1. **Call the `SetCaseId` MCP tool once at the start of an investigation** with a short, human-readable case id
   (e.g. `srl-2018-rd01`). This is a separate MCP tool, not a JS SDK call. Every tool execution afterward is
   written to `audit-<caseId>.clef` and tagged with the case, the toolkit/tool, the command, host, exit code, and
   duration.
2. **Call the `SetEvidence` MCP tool once, right after `SetCaseId`,** to register the original evidence files
   (disk images, memory captures, mounts, hives, logs) as `[{ filePath, hashType?, hashValue? }]` — `hashType` is
   one of `None`/`MD5`/`SHA1`/`SHA256`, and both hash fields are optional (omit them when the case gives no hash).
   This is a separate MCP tool, not a JS SDK call. The server then **architecturally refuses** any later tool
   execution that would write over, extract into, or modify a registered evidence path (or its directory),
   throwing an evidence-spoliation error — chain-of-custody enforced by the server, not by prompt discipline.
   `SetEvidence` first preflights that every path exists on the workstation: if any is missing it registers
   nothing and returns a "not found" error listing them (stage the files and retry); on success it returns each
   file with its size. Evidence is write-once per session; a second `SetEvidence` call is refused and audited
   (start a new session to change it). Read the evidence as input freely — only writes onto evidence paths are
   blocked. Optionally call
   the **`VerifyEvidence` MCP tool** after `SetEvidence` to re-hash each file on disk and confirm it matches the
   supplied hash (no-hash files get a SHA-1 baseline and always pass; `.E01`/EWF images are content-verified with
   ewfverify, so you can supply an E01's acquisition MD5/SHA1); a mismatch is a chain-of-custody alarm. It can be
   slow on large images, so it is on-demand, not automatic.
3. **Every `Execute` result ends with an audit handle line** — `[audit] case=<caseId> execution=<id>`.
   **Cite that `execution` id (and the toolkit/method) next to the findings it supports in your report**, so a
   reviewer can trace each finding to its tool executions in the case's audit file. Treat it as the evidence
   citation for everything that script established.

## Global Functions

`log(message: string)` — write an informational line to the script's output buffer (the text returned to the
agent when the script finishes).

`error(message: string)` — write an error line to the output buffer (same mechanism as `log`; use it to mark a problem).

`exit(message: string)` — **stop the script immediately** and return `message` to the agent (appended after any
output produced before it). This is a deliberate early exit, *not* a tool failure — the result is a normal success
result whose text carries your message. Use it to bail out of a multi-step script on an unrecoverable condition
without nesting the rest in `else` branches — e.g.
`if (!mountResult.IsSuccess) exit('mount failed: ' + mountResult.Message);`. The message is also recorded in the
per-case audit log. Code after the call does not run.

`auditInfo(message: string)` — like `log`, but **also** records the line in the per-case audit log (`audit-<caseId>.clef`)
as an `information` event. Use it for notable steps and conclusions you want preserved in the trail, not just returned to you.

`auditError(message: string)` — like `error`, but **also** records the line in the per-case audit log as an `error` event.

`auditFinding(observation: string, interpretation: string, confidence: string, evidenceExecutionIds: string)` — records a
structured forensic finding to the audit log as a `finding` event: `observation` (what you saw, as fact),
`interpretation` (what it means), `confidence` (`SPECULATIVE`/`LOW`/`MEDIUM`/`HIGH`), and `evidenceExecutionIds` (the
`[audit] execution=` ids that prove it). This is the primary way to record a conclusion — see the
`camel-sdk-discipline` resource for the method that governs when and how.

`auditReviewRec(reason: string)` — records a `human-judgement-recommended` event for a high-consequence conclusion
(root cause, attribution, scope, exfiltration, insider) so a reviewer can find it in the trail. Present the
candidates and call this — the run continues autonomously; it does not stop.

`auditFalsePositive(message: string)` — records a `false-positive` event: a lead you checked and rejected as benign
(the *benign-until-proven-malicious* principle). Surfacing rejected leads is positive evidence of rigour.

`auditMissingEvidence(message: string)` — records a `missing-evidence` event: an evidentiary gap (absent, cleared,
rotated, or disabled logs; an unavailable artifact). State "no evidence found", not "did not happen".

`auditHallucination(message: string)` — records a `hallucination` event when you catch yourself having invented an
artifact, method, or field. (The server also emits this automatically when a script references a non-existent
toolkit/workflow — the resulting error names the invented API and is returned to you so you can self-correct.)

`table(headers: string[], dataRows: object[][])` — write a tabular block to the output buffer (`headers` are the
column headers; `dataRows` is one inner array of cell values per row).

> Output is accumulated and returned as the tool result. If the script throws, output produced before the
> failure is still returned, followed by the error message. The `audit*` functions persist beyond the response:
> they land in the case audit file so a reviewer can reconstruct the investigation from the logs alone.

## Session storage (`Session`)

`Session` is a string-keyed object that **survives across `Execute` calls within the same session**. Each call
gets a fresh script scope (local `const`/`let` vanish when the script ends), but `Session` is the one place that
persists — use it to carry an expensive or canonical result forward instead of rebuilding it:

```js
// First call: build the super-timeline once and keep it.
const tl = await TimelineAnalysisWorkflow.CreateTriageTimelineAsync("/mnt/c", "/cases/host.plaso");
if (tl.IsSuccess) Session["timeline"] = tl.Result;     // cache the result object

// A later call: reuse it — no rebuild, and every step reasons over the *same* objects.
const t = Session["timeline"];
log(`reusing cached timeline with ${t.Events.length} events`);
```

- Read a key that was never set and you get `undefined` (no error) — guard with `Session["k"] === undefined` or `??`.
- Store SDK result objects, arrays, and primitives. Storage is **per session** (not shared between investigations)
  and lasts until the session is closed or swept for inactivity.
- **Evict** a cached object when you're done with it: `delete Session["k"]`. That drops the reference, and once
  nothing else holds it, .NET's garbage collector reclaims the memory. Do this for large objects (a full
  super-timeline, a big parsed dump) you won't reuse, rather than letting them live for the whole session.
- Beyond speed, reusing the cached object keeps successive analysis steps **consistent** — they operate on the
  identical data rather than a possibly-different recomputation, which matters for accurate, reproducible findings.

## WorkflowResult&lt;T&gt; (returned by every workflow method)

Every **workflow** method returns a `WorkflowResult<T>` wrapping the typed payload `T`. It has three properties:
`IsSuccess` (boolean — true if the workflow ran to completion), `Result` (the typed payload `T`, or `null` when
`IsSuccess` is false), and `Message` (a human-readable summary on success, or the failure explanation). Schema in
the `camel-sdk-schema` resource.

```js
const r = await DiskAnalysisWorkflow.VerifyImageAsync("/cases/disk.E01");
if (!r.IsSuccess) error(r.Message); else log(r.Message);  // inspect r.Result …
```

---

# Toolkits

Toolkit methods execute a SIFT tool on the workstation and return a parsed model wrapped in a `ToolResult<T>`
(check `.IsSuccess`, read `.Result`, or `.Message` when the tool is unavailable or the command failed); a few
pure-action methods (mount / dump / extract) return `bool`. The toolkit objects are `MemoryAnalysisToolkit`, `DiskAnalysisToolkit`,
`WindowsAnalysisToolkit`, `TimelineAnalysisToolkit`, `YaraToolkit`, `UnixToolsToolkit`, `LinuxAnalysisToolkit`,
`PacketAnalysisToolkit`, and `AnomalyDetectionToolkit`. The JSON schema for each return type named below is in the
`camel-sdk-schema` resource.

---

## MemoryAnalysisToolkit

Volatility 3 wrapper for Windows memory-image analysis. `filename` is the memory image path. Methods taking an
optional `pid: int` restrict output to one process. Each plugin method returns a **`ToolResult<T>`** — check
`.IsSuccess`, read `.Result` or `.Message`. An empty `.Result` array means "ran clean, nothing found"; a *failed*
result means the plugin could not run (Volatility absent, or — for a Linux plugin — no ISF symbol table for the
kernel). The `ExtractStringsAsync` helper stays a plain `bool` (true on success).

- `WindowsInfoAsync(filename: string)` → `ToolResult<WindowsInfo[]>` — OS/build metadata.
- `WindowsPsListAsync(filename: string)` → `ToolResult<WindowsPsList[]>` — active EPROCESS list walk.
- `WindowsPsScanAsync(filename: string)` → `ToolResult<WindowsPsScan[]>` — pool-tag process scan (finds hidden/exited).
- `WindowsPsTreeAsync(filename: string, pid?: int)` → `ToolResult<WindowsPsTree[]>` — process tree (nodes carry `__children`).
- `WindowsSvcScanAsync(filename: string)` → `ToolResult<WindowsSvcScan[]>` — service records (incl. hidden/deleted).
- `WindowsCmdLineAsync(filename: string, pid?: int)` → `ToolResult<WindowsCmdLine[]>` — per-process command lines.
- `WindowsEnvVarsAsync(filename: string, pid?: int)` → `ToolResult<WindowsEnvVars[]>` — per-process environment variables.
- `WindowsGetSidsAsync(filename: string, pid?: int)` → `ToolResult<WindowsGetSids[]>` — per-process owning SIDs.
- `WindowsPrivsAsync(filename: string, pid?: int)` → `ToolResult<WindowsPrivs[]>` — per-process privileges.
- `WindowsHandlesAsync(filename: string, pid?: int, objectType?: string)` → `ToolResult<WindowsHandles[]>` — open handles;
  `objectType` filters by type (e.g. `"File"`, `"Mutant"`, case-insensitive).
- `WindowsDllListAsync(filename: string, pid?: int)` → `ToolResult<WindowsDllList[]>` — loaded DLLs.
- `WindowsModulesAsync(filename: string)` → `ToolResult<WindowsModules[]>` — kernel modules (list).
- `WindowsModScanAsync(filename: string)` → `ToolResult<WindowsModScan[]>` — kernel modules (pool scan).
- `WindowsGetServiceSidsAsync(filename: string)` → `ToolResult<WindowsGetServiceSids[]>` — service SIDs.
- `WindowsNetStatAsync(filename: string)` → `ToolResult<WindowsNetStat[]>` — active network connections.
- `WindowsNetScanAsync(filename: string)` → `ToolResult<WindowsNetScan[]>` — pool-scan of connections (incl. closed/historical).
- `WindowsMalFindAsync(filename: string)` → `ToolResult<WindowsMalFind[]>` — private executable regions with no file backing.
- `WindowsLdrModulesAsync(filename: string, pid?: int)` → `ToolResult<WindowsLdrModules[]>` — PEB-list vs VAD DLL presence.
- `WindowsHollowProcessesAsync(filename: string)` → `ToolResult<WindowsHollowProcesses[]>` — process-hollowing victims.
- `WindowsThreadsAsync(filename: string, pid?: int)` → `ToolResult<WindowsThreads[]>` — thread start addresses.
- `WindowsSsdtAsync(filename: string)` → `ToolResult<WindowsSsdt[]>` — SSDT entries (foreign module = hook).
- `WindowsCallbacksAsync(filename: string)` → `ToolResult<WindowsCallbacks[]>` — registered kernel callbacks.
- `WindowsDriverIrpAsync(filename: string)` → `ToolResult<WindowsDriverIrp[]>` — driver IRP major-function tables.
- `WindowsPsxViewAsync(filename: string)` → `ToolResult<WindowsPsxView[]>` — cross-view process visibility.
- `WindowsMutantScanAsync(filename: string)` → `ToolResult<WindowsMutantScan[]>` — named mutex IOCs.
- `WindowsCmdScanAsync(filename: string)` → `ToolResult<WindowsCmdScan[]>` — typed command lines (COMMAND_HISTORY).
- `WindowsConsolesAsync(filename: string)` → `ToolResult<WindowsConsoles[]>` — console buffers (commands + output).
- `WindowsFileScanAsync(filename: string)` → `ToolResult<WindowsFileScan[]>` — FILE_OBJECTs (with offsets).
- `WindowsVadInfoAsync(filename: string, pid?: int)` → `ToolResult<WindowsVadInfo[]>` — VAD regions.
- `WindowsRegistryHiveListAsync(filename: string)` → `ToolResult<WindowsRegistryHiveList[]>` — loaded registry hives.
- `WindowsRegistryPrintKeyAsync(filename: string, key: string)` → `ToolResult<WindowsRegistryPrintKey[]>` — values under a key.
- `WindowsRegistryUserAssistAsync(filename: string)` → `ToolResult<WindowsRegistryUserAssist[]>` — UserAssist entries.
- `WindowsShimcacheMemAsync(filename: string)` → `ToolResult<WindowsShimcacheMem[]>` — AppCompatCache from kernel memory.
- `WindowsHashdumpAsync(filename: string)` → `ToolResult<WindowsHashdump[]>` — local NTLM hashes (SAM).
- `WindowsLsadumpAsync(filename: string)` → `ToolResult<WindowsLsadump[]>` — LSA secrets.
- `WindowsCachedumpAsync(filename: string)` → `ToolResult<WindowsCachedump[]>` — cached domain creds (mscash2).
- `WindowsSkeletonKeyCheckAsync(filename: string)` → `ToolResult<WindowsSkeletonKeyCheck[]>` — DC Skeleton Key (empty = clean).
- `WindowsProcessGhostingAsync(filename: string)` → `ToolResult<WindowsProcessGhosting[]>` — Process Ghosting (empty = clean).
- `WindowsVerInfoAsync(filename: string, pid?: int)` → `ToolResult<WindowsVerInfo[]>` — PE version-info strings.
- `WindowsVadYaraScanAsync(filename: string, yaraRulesFile: string, pid?: int, wide?: bool)` → `ToolResult<WindowsVadYaraScan[]>`
  — YARA-scan VAD regions (`wide` also matches UTF-16).
- `DumpFilesAsync(filename: string, outputDir: string, virtualAddress?: long, physicalAddress?: long, pid?: int, filterRegex?: string)`
  → `ToolResult<string[]>` — extract cached files; returns workstation paths of the dumped files.
- `DumpProcessExecutableAsync(filename: string, pid: int, outputDir: string)` → `ToolResult<string[]>` — dump a process's PE image.
- `DumpProcessMemoryAsync(filename: string, pid: int, outputDir: string)` → `ToolResult<string[]>` — dump all mapped memory.
- `ExtractStringsAsync(inputFile: string, outputFile: string, unicode?: bool, minLength?: int)` → `bool` —
  run `strings` (ASCII, or UTF-16LE when `unicode=true`; `minLength` default 8) into `outputFile`.
- `TimelinerBodyfileAsync(image: string, outputDir: string)` → `ToolResult<string>` (path) — mactime bodyfile of all
  timestamped artifacts (`volatility.body`).

### Linux memory plugins

For a **Linux** memory image. Same call shape as the Windows methods. **Symbols caveat:** every Linux plugin
needs an ISF symbol table matching the captured kernel's banner (none ship with Volatility); `vol` auto-fetches
known kernels from the public symbol server, otherwise generate symbols with `dwarf2json`. With no symbols the
method returns a *failed* `ToolResult` (`.Message` names the symbol-table need) — distinct from a successful
empty `.Result` (ran clean, nothing found).

- `LinuxPsListAsync(filename: string, pid?: int)` → `ToolResult<LinuxPsList[]>` — task-list processes (live view).
- `LinuxPsScanAsync(filename: string)` → `ToolResult<LinuxPsScan[]>` — pool-scan processes (finds unlinked/hidden).
- `LinuxPsTreeAsync(filename: string, pid?: int)` → `ToolResult<LinuxPsTree[]>` — process tree (`__children`).
- `LinuxPsAuxAsync(filename: string, pid?: int)` → `ToolResult<LinuxPsAux[]>` — processes with full argument vectors.
- `LinuxBashAsync(filename: string, pid?: int)` → `ToolResult<LinuxBash[]>` — bash history recovered from process memory.
- `LinuxLsofAsync(filename: string, pid?: int)` → `ToolResult<LinuxLsof[]>` — open file descriptors per process.
- `LinuxSockstatAsync(filename: string)` → `ToolResult<LinuxSockstat[]>` — sockets with owning process/endpoints (netstat view).
- `LinuxLsmodAsync(filename: string)` → `ToolResult<LinuxModule[]>` — loaded kernel modules.
- `LinuxCheckModulesAsync(filename: string)` → `ToolResult<LinuxModule[]>` — modules in memory but missing from the list (hidden).
- `LinuxHiddenModulesAsync(filename: string)` → `ToolResult<LinuxModule[]>` — modules carved from memory (empty = none hidden).
- `LinuxCheckSyscallAsync(filename: string)` → `ToolResult<LinuxCheckSyscall[]>` — hooked syscall-table entries (empty = clean).
- `LinuxCheckAfinfoAsync(filename: string)` → `ToolResult<LinuxCheckAfinfo[]>` — overwritten protocol handlers (empty = clean).
- `LinuxCheckCredsAsync(filename: string)` → `ToolResult<LinuxCheckCreds[]>` — processes sharing one cred struct (empty = clean).
- `LinuxTtyCheckAsync(filename: string)` → `ToolResult<LinuxTtyCheck[]>` — hooked TTY handlers / keyloggers (empty = clean).
- `LinuxMalfindAsync(filename: string, pid?: int)` → `ToolResult<LinuxMalfind[]>` — injected WX regions (empty = clean).
- `LinuxNetfilterAsync(filename: string)` → `ToolResult<LinuxNetfilter[]>` — registered netfilter hooks (foreign = backdoor).
- `LinuxKmsgAsync(filename: string)` → `ToolResult<LinuxKmsg[]>` — kernel ring buffer (dmesg) from memory.

> Most Volatility plugins are independent — fan out multiple `Windows*Async`/`Linux*Async` calls and `await` them
> together (e.g. `Promise.all`); the environment bounds SSH concurrency.

---

## DiskAnalysisToolkit

The Sleuth Kit (TSK), libewf (EWF/E01), loopback/NTFS mounting, file recovery, **signature carving**, and mactime.
The optional `offset: int` argument is a **partition start sector** (from `MmlsAsync` / `ListPartitionsAsync`);
omit it for a single-volume image. All carving/recovery tools ship with SIFT — no installs needed.

The **data** methods return `ToolResult<T>` (check `.IsSuccess`, read `.Result` or `.Message`); the **mount/extract/
recovery-action** methods return `bool` (true on success), and the two `FindFilesAsync` overloads return `FsFile[]`
directly (empty when nothing matches).

- `EwfInfoAsync(image: string)` → `ToolResult<EwfInfo>` — EWF metadata + acquisition hashes.
- `EwfVerifyAsync(image: string)` → `ToolResult<EwfVerify>` — recompute & compare acquisition hash.
- `EwfMountRawAsync(image: string, mountDir: string)` → `bool` — FUSE-mount E01 RO as `<mountDir>/ewf1`.
- `EwfMountLoopbackAsync(rawPartition: string, mountDir: string, offset?: int)` → `bool` — kernel-NTFS loopback mount.
- `EwfMountNtfsAsync(rawPartition: string, mountDir: string, offset?: int)` → `bool` — ntfs-3g `force` mount (dirty NTFS).
- `DDMountAsync(imageFile: string, mountDir: string, offset?: int)` → `bool` — RO loopback mount of a raw `.dd`.
- `MakeMountDirAsync(name: string)` → `ToolResult<string>` (path) — create `/mnt/<name>`.
- `MakeDirAsync(path: string)` → `bool` — `mkdir -p` an absolute path.
- `UnmountAsync(mountDir: string)` → `bool` — `umount`.
- `ImgStatAsync(image: string)` → `ToolResult<ImgStat>` — image format details.
- `MmlsAsync(image: string)` → `ToolResult<MmlsEntry[]>` — partition table (TSK).
- `ListPartitionsAsync(disk: string)` → `ToolResult<PartitionInfo[]>` — partition table (`fdisk -l`).
- `FsStatAsync(image: string, offset?: int)` → `ToolResult<FsStat>` — filesystem details.
- `FlsAsync(image: string, offset?: int, inode?: long, recursive?: bool, deletedOnly?: bool)` → `ToolResult<FlsEntry[]>` — directory listing.
- `IstatAsync(image: string, inode: long, offset?: int)` → `ToolResult<Istat>` — inode metadata.
- `FfindAsync(image: string, inode: long, offset?: int)` → `ToolResult<string>` — file name for an inode.
- `IlsAsync(image: string, offset?: int)` → `ToolResult<IlsEntry[]>` — inode listing.
- `IcatAsync(image: string, inode: long, outputFile: string, offset?: int)` → `bool` — extract an inode's content.
- `FindFilesAsync(directory: string, namePattern?: string, maxDepth?: int)` → `FsFile[]` — find by one glob (default `"*"`).
  The search is **recursive** and the glob matches the file **name** (e.g. `*.evtx`), so you do *not* need a `**/` prefix.
  Conveniences are normalised: a leading `**/` is stripped, brace alternation (`*.{evtx,log}`) is expanded, and a glob
  containing `/` (e.g. `Users/*/NTUSER.DAT`) is matched against the whole path. Supports `*`, `?`, `[...]`. `maxDepth` 0 = unlimited.
- `FindFilesAsync(directory: string, namePatterns: string[], maxDepth?: int)` → `FsFile[]` — find by any of several globs (one traversal).
- `Sha256Async(path: string)` → `ToolResult<string>` — SHA-256 of a mounted file.
- `GrepLinesAsync(path: string, patterns: string[], ignoreCase?: bool, maxMatches?: int)` → `ToolResult<string[]>` —
  server-side `grep -E -f`; `.Result` is the matching lines (`[]` on no match; failed result on an unreadable file).
- `TskRecoverAsync(image: string, outputDir: string, all: bool, dirInode?: long, offset?: int)` → `ToolResult<int>` —
  bulk-recover files (count in `.Result`); `all=true` includes deleted/unallocated.
- `IcatByAddrAsync(image: string, inode: string, outputFile: string, offset?: int)` → `bool` — extract a file by
  TSK inode **address string** (plain ext inode, or NTFS `mft-type-id`, as `FlsEntry.Inode` carries).
- `BlklsAsync(image: string, outputFile: string, offset?: int, slackOnly?: bool)` → `ToolResult<long>` (bytes) — extract a
  filesystem's **unallocated** blocks (or `-s` slack) for carving.
- `ForemostAsync(input: string, outputDir: string, fileTypes?: string)` → `ToolResult<CarvedFile[]>` — signature-carve with
  foremost (`fileTypes` default `"all"`; `outputDir` must not pre-exist).
- `ScalpelAsync(input: string, outputDir: string, confFile?: string)` → `ToolResult<CarvedFile[]>` — signature-carve with scalpel.
- `PhotoRecAsync(input: string, outputDir: string, fileTypes?: string)` → `ToolResult<string[]>` — carve with photorec (recovered paths).
- `BulkExtractorAsync(input: string, outputDir: string)` → `ToolResult<BulkFeatureFile[]>` — extract features (email/url/domain/
  ccn/phone/ip) with counts + top values, regardless of filesystem.
- `SigfindAsync(image: string, signature: string, offset?: int)` → `ToolResult<long[]>` — block offsets of a hex byte signature.
- `ExtundeleteAsync(image: string, outputDir: string, restoreAll?: bool)` → `ToolResult<int>` — ext3/4 undelete (count recovered).
- `BdeInfoAsync(source: string, offset?: int, recoveryPassword?: string, password?: string, bekFile?: string, fullKey?: string)`
  → `ToolResult<BitLockerInfo>` — read BitLocker (BDE) volume metadata + key protectors via `bdeinfo` (`source` = a raw device
  like `ewf1`, or a raw image; `offset` = partition start sector). No credential needed to read metadata. A failed
  result when there is no BDE volume at the offset (i.e. not BitLocker-encrypted) — else check `.Result.IsBitLockerVolume`.
- `BdeMountAsync(volume: string, mountDir: string, recoveryPassword?: string, password?: string, bekFile?: string, fullKey?: string, offset?: int)`
  → `bool` — unlock + mount a BitLocker volume RO with `bdemount`, exposing the decrypted volume as `<mountDir>/bde1`
  (a raw device the TSK tools and a loopback mount use just like `ewf1`). Supply one credential. False on a wrong
  credential.
- `SearchBitLockerRecoveryKeysAsync(input: string, maxMatches?: int)` → `ToolResult<string[]>` — string-search `input` (image/
  device/extract/memory dump) for 48-digit BitLocker recovery keys (`strings | grep`). The FOR508 "no key supplied"
  fallback. `.Result` is the distinct candidate keys (`[]` if none; failed result if unreadable).
- `DeleteFileAsync(path: string)` → `bool` — delete a non-evidence temp file (e.g. an unallocated extract).
- `FlsBodyfileAsync(image: string, outputFile: string, offset?: int, mountPoint?: string)` → `bool` — `fls -r -m` bodyfile.
- `MactimeAsync(bodyfile: string, timezone?: string)` → `ToolResult<MactimeEntry[]>` — render a sorted timeline (default UTC).
- `MactimeToFileAsync(bodyfile: string, outputFile: string, timezone?: string)` → `bool` — render a large timeline to a file.

---

## WindowsAnalysisToolkit

Eric Zimmerman (EZ) tools, RegRipper, and bespoke parsers for Windows host artifacts. Every method below returns a
**`ToolResult<T>`** — check `.IsSuccess`, read the payload from `.Result`, or read `.Message` (it distinguishes "tool
not installed on this platform" from "the command failed / the artifact was unreadable"). An empty `.Result`
collection means "ran clean, found nothing", not a failure.

- `LoadLolbasAsync()` → `ToolResult<LolbasReference>` — the LOLBAS index (methods `IsLolbin`, `IsCanonicalPath`).
- `MFTECmdAsync(file: string)` → `ToolResult<MFTEntry[]>` — parse a `$MFT` to JSON rows.
- `MFTECmdUsnAsync(usnFile: string)` → `ToolResult<UsnJournalEntry[]>` — parse a `$UsnJrnl:$J` change journal.
- `MFTECmdCsvAsync(file: string, outputFile?: string, outputDir?: string, allTimestamps?: bool, recoverSlack?: bool, vss?: bool)`
  → `ToolResult<MFTECmdResult>` — parse NTFS metadata to a CSV file (one of `outputFile`/`outputDir` required).
- `MFTECmdBodyfileAsync(file: string, outputFile?: string, outputDir?: string, driveLetter?: string, vss?: bool)`
  → `ToolResult<MFTECmdResult>` — parse to a mactime bodyfile.
- `LECmdAsync(file: string)` → `ToolResult<LnkFile[]>` — parse a LNK shortcut.
- `LECmdDirectoryAsync(directory: string)` → `ToolResult<LnkFile[]>` — parse every `.lnk` under a directory (e.g. a Recent folder).
- `SBECmdAsync(hiveDirectory: string)` → `ToolResult<ShellBag[]>` — shellbags (JSON).
- `SBECmdCsvAsync(directory: string, outputDir: string)` → `ToolResult<SBECmdCsvResult>` — shellbags to per-hive CSVs.
- `AppCompatCacheParserAsync(systemHive: string, ignoreTransactionLogs?: bool)` → `ToolResult<ShimcacheEntry[]>` — Shimcache.
- `AmcacheParserAsync(amcacheHive: string, ignoreTransactionLogs?: bool)` → `ToolResult<AmcacheEntry[]>` — Amcache (SHA-1 + metadata).
- `RBCmdAsync(file: string)` → `ToolResult<RecycleBinEntry[]>` — recycle-bin records.
- `JLECmdAsync(directory: string)` → `ToolResult<JumpListEntry[]>` — jump lists.
- `WxTCmdAsync(activitiesCacheDb: string)` → `ToolResult<TimelineActivity[]>` — Win10 Timeline activities.
- `RECmdAsync(hiveDirectory: string, batchFile: string)` → `ToolResult<RegistryEntry[]>` — RECmd batch over a hive directory.
- `RECmdSingleHiveAsync(hiveFile: string, batchFile: string)` → `ToolResult<RegistryEntry[]>` — RECmd over one hive (replays logs).
- `SQLECmdAsync(directory: string)` → `ToolResult<object[]>` — SQLECmd over SQLite DBs (heterogeneous key/value records).
- `EvtxECmdAsync(file?: string, directory?: string, includeIds?: string, excludeIds?: string, startDate?: string, endDate?: string)`
  → `ToolResult<EventLogEntry[]>` — parse EVTX to JSON (one of `file`/`directory` required; IDs comma-separated; dates UTC `"yyyy-MM-dd HH:mm:ss"`).
- `EvtxECmdServerFilteredAsync(payloadGrepPattern: string, file?: string, directory?: string, includeIds?: string, excludeIds?: string, startDate?: string, endDate?: string)`
  → `ToolResult<EventLogEntry[]>` — as above, server-side `grep -F` of the payload first (for huge event streams).
- `EvtxECmdCsvAsync(file?: string, directory?: string, includeIds?: string, excludeIds?: string, startDate?: string, endDate?: string, outputFile?: string, outputDir?: string)`
  → `ToolResult<EvtxECmdCsvResult>` — parse EVTX to a CSV file.
- `RegRipperAsync(hive: string, plugin: string)` → `ToolResult<RegRipperResult>` — run one RegRipper plugin (raw text in `.Lines`).
- `ScheduledTasksAsync(tasksDirectory: string)` → `ToolResult<ScheduledTaskEntry[]>` — parse `\Windows\System32\Tasks` XML.
- `WmiSubscriptionsAsync(objectsDataPath: string)` → `ToolResult<WmiSubscriptions>` — recover WMI subscriptions from `OBJECTS.DATA`.
- `BstringsAsync(file: string, minLength?: int)` → `ToolResult<string[]>` — extract strings.
- `PffInfoAsync(pstFile: string)` → `ToolResult<PstStoreInfo>` — PST/OST store metadata (PST vs OST, encryption) via libpff.
- `ReadPstAsync(pstFile: string, maxMessagesPerFolder?: int)` → `ToolResult<EmailExportResult>` — export a PST/OST and parse messages (From/To/Subject/Date/attachments) via libpst.
- `EsedbInfoAsync(edbFile: string)` → `ToolResult<EseDatabaseInfo>` — list ESE (EDB) tables (WebCacheV01.dat, Windows.edb) via libesedb.
- `WebCacheHistoryAsync(webCacheDbFile: string)` → `ToolResult<WebCacheEntry[]>` — IE/Edge `WebCacheV01.dat` URL history (esedbexport).
- `UsbDeviceForensicsAsync(systemHive: string, softwareHive: string, ntuserHive?: string)` → `ToolResult<UsbDeviceRecord[]>` — profile USB devices from the registry (hives auto-staged to a writable temp dir).
- `SqliteQueryAsync(dbFile: string, sql: string)` → `ToolResult<object[]>` — read-only `sqlite3 -json` query of a browser/app SQLite DB (DB staged to a temp copy). Use this for browser History DBs (SQLECmd's EZ build is unusable on SIFT).
- `HindsightAsync(chromeProfileDir: string)` → `ToolResult<object[]>` — Chrome/Chromium activity timeline (JSON-lines), optional.

---

## TimelineAnalysisToolkit

Plaso (`log2timeline`/`psort`/`pinfo`/`psteal`/`image_export`) and `hayabusa`. The central artifact is a `.plaso`
**storage file** that can be re-filtered cheaply once built.

- `Log2TimelineAsync(source: string, storageFile: string, parsers?: string, hash?: bool, filterFile?: string, partitions?: string, vssStores?: string, timezone?: string)`
  → `bool` — parse `source` into `storageFile` (appends if it exists). Scope with `parsers` (preset/list, leading
  `-` negates), `filterFile`, `partitions`, `vssStores`; `hash=true` stores MD5/SHA-256.
- `PsortAsync(storageFile: string, filter?: string, slice?: string, sliceSize?: int)` → `ToolResult<TimelineEvent[]>` — export a
  sorted timeline. `filter` is a Plaso attribute filter; `slice` (ISO-8601) + `sliceSize` (minutes) = pivot mini-timeline.
- `PsortReducedAsync(storageFile: string, filter?: string, maxMessageChars?: int)` → `ToolResult<TimelineEvent[]>` — scale-safe
  export (strips bulky payloads, truncates `message` to `maxMessageChars`, default 1024). Prefer for whole-timeline triage.
- `PsortSearchAsync(storageFile: string, grepPattern: string, filter?: string)` → `ToolResult<TimelineEvent[]>` — keyword-search
  the rendered timeline (server-side `grep -i -E`, incl. the human-readable `message`).
- `PsortTagAsync(storageFile: string, taggingFile: string)` → `bool` — apply the `tagging` plugin (labels persisted into the .plaso).
- `PinfoAsync(storageFile: string)` → `ToolResult<PlasoInfo>` — parser-hit stats and total event count.
- `PstealAsync(source: string, parsers?: string, timezone?: string)` → `ToolResult<TimelineEvent[]>` — one-step ingest+export.
- `ImageExportAsync(source: string, outputDir: string, names?: string, extensions?: string)` → `bool` — extract files from an image.
- `HayabusaJsonTimelineAsync(evtxPath: string, directory?: bool, minLevel?: string)` → `ToolResult<HayabusaAlert[]>` — Sigma detections.
- `HayabusaComputerMetricsAsync(evtxPath: string, directory?: bool)` → `ToolResult<ComputerMetric[]>`.
- `HayabusaEidMetricsAsync(evtxPath: string, directory?: bool)` → `ToolResult<EidMetric[]>`.
- `HayabusaLogMetricsAsync(evtxPath: string, directory?: bool)` → `ToolResult<LogMetric[]>`.
- `HayabusaLogonSummaryAsync(evtxPath: string, directory?: bool)` → `ToolResult<LogonSummaryEntry[]>` (each flagged `.Successful`).

(The data methods above return `ToolResult<T>` — check `.IsSuccess`, read `.Result` or `.Message`; the three
`bool` methods report success directly. See the `ToolResult` schema.)

---

## YaraToolkit

Classic `yara` scanner + the bundled Yara-Rules community pack (at `/opt/yara-rules`, with aggregator indexes
such as `malware_index.yar`, `webshells_index.yar`).

- `ScanAsync(rules: string, scanPath: string, options?: YaraOptions)` → `ToolResult<YaraMatch[]>` — scan a file or
  (with `options.Recurse`) a directory; one match per rule/file hit. Check `.IsSuccess`, read `.Result` (empty = ran clean)
  or `.Message` (yara not installed vs. scan failed).
- `CompileAsync(rules: string, output: string)` → `bool` — compile rules to a binary file (true on success).

`options` is passed as a JS object literal (all fields optional), e.g. `{ Recurse: true, Timeout: 120 }`. See the
`YaraOptions` schema for the full field set.

---

## UnixToolsToolkit

A growing collection of commonly used Unix utilities on the SIFT workstation, wrapped as typed methods so the
agent can run them server-side in one call instead of scripting shell. The current set covers **archive
decompression** for acquired disk and memory images (commonly shipped as `.bz2`, `.zip`, or `.7z`), **file/
directory copy** for staging evidence into standard locations, and **file hashing** for integrity checks — the
workstation does the work and you get the resulting file path(s)/sizes/digests back, with no follow-up directory
walk. Pass `sudo: true` when the source or destination is root-owned.

- `Bunzip2Async(file: string, outputFile?: string, sudo?: bool)` → `DecompressResult` — decompress a bzip2
  file, keeping the original. When `outputFile` is omitted the destination is `file` with a trailing `.bz2`
  stripped. `Files` holds the single decompressed file with its size.
- `UnzipAsync(archive: string, destDir: string, files?: string[], sudo?: bool)` → `DecompressResult` — extract a
  zip into `destDir` (created if missing, overwriting existing files). Pass `files` to extract only selected
  members (e.g. one large image out of a multi-file archive); `OutputPath` is `destDir` and `Files` lists every
  extracted file with its size.
- `SevenZipExtractAsync(archive: string, destDir: string, files?: string[], sudo?: bool)` → `DecompressResult` —
  extract a 7-Zip archive (`.7z`, and other formats 7-Zip reads — zip/rar/tar/gz) into `destDir`, preserving the
  archive's directory structure and overwriting existing files. Same `files`/`OutputPath`/`Files` semantics as
  `UnzipAsync`.
- `CopyFileAsync(source: string, dest: string, sudo?: bool, verify?: bool)` → `CopyResult` — copy a single file
  to `dest` (the full destination file path), preserving mode/timestamps (`cp -p`) and creating the parent dir if
  missing. Use to stage an image from an external/removable dir into `/mnt`, `/cases`, etc.
- `CopyDirAsync(source: string, dest: string, sudo?: bool, verify?: bool)` → `CopyResult` — recursively copy a
  directory to `dest` (the target dir path, created as a copy of `source`), preserving mode/timestamps (`cp -rp`).
  `Files` lists every copied file with its size.
- `Md5SumAsync(file: string, sudo?: bool)` / `Sha1SumAsync(file: string, sudo?: bool)` /
  `Sha256SumAsync(file: string, sudo?: bool)` → `string` (lower-case hex digest, or `null` on failure) — hash a
  single file read-only. Use to verify an acquired image/file against a known hash from the case description.
  (For the registered case evidence as a whole, prefer the `VerifyEvidence` MCP tool, which re-hashes every
  evidence file and compares against the supplied hashes in one step.)

Pass `verify: true` to SHA-256 each source file against its copy after the copy; the result's `Verified` is then
`true`/`false` and `Mismatches` lists any destination paths whose hash didn't match (empty `[]` on success).
`Verified` is `null` when verification wasn't requested.

```js
// Stage a compressed image from a removable mount, then decompress it in place under /cases.
const c = await UnixToolsToolkit.CopyFileAsync("/media/usb/memdump.raw.bz2", "/cases/memdump.raw.bz2");
const d = await UnixToolsToolkit.Bunzip2Async(c.Destination);
const procs = await MemoryAnalysisToolkit.WindowsPsScanAsync(d.OutputPath);
```

---

## LinuxAnalysisToolkit

Typed extractors for **Linux host artifacts on a mounted root filesystem** (a forensic image mounted read-only,
or a live root). Each method takes a `rootDir` (the mount point, e.g. `/mnt/linux`, or `/` for the live host) or
an explicit artifact path, and is read-only. Reads default to **sudo** (forensic mounts are root-owned). Grounded
in Bruce Nikkel, *Practical Linux Forensics*. Tooling note: everything here is satisfied by the base SIFT image —
no installs are needed for the default Debian/Ubuntu (dpkg) path.

(Each data method below returns `ToolResult<T>` — check `.IsSuccess`, read `.Result` or `.Message`; the reason
distinguishes "tool not installed" / "artifact not readable under this root" from a real failure.)

- `SystemInfoAsync(rootDir: string, sudo?: bool)` → `ToolResult<LinuxSystemInfo>` — os-release/hostname/timezone/machine-id.
- `UserAccountsAsync(rootDir: string, sudo?: bool)` → `ToolResult<LinuxUserAccount[]>` — passwd⋈shadow (hash-free `PasswordState`).
- `SudoersAsync(rootDir: string, sudo?: bool)` → `ToolResult<SudoRule[]>` — sudoers + sudoers.d grants.
- `CronEntriesAsync(rootDir: string, sudo?: bool)` → `ToolResult<CronEntry[]>` — every cron location (system/user/script dirs).
- `LastLoginsAsync(wtmpPath?: string, rootDir?: string, sudo?: bool)` → `ToolResult<LinuxLogin[]>` — successful logins (`last`).
- `FailedLoginsAsync(btmpPath?: string, rootDir?: string, sudo?: bool)` → `ToolResult<LinuxLogin[]>` — failed logins (`lastb`).
- `UtmpDumpAsync(path: string, sudo?: bool)` → `ToolResult<UtmpRecord[]>` — raw utmp/wtmp/btmp (boot records, tamper checks).
- `JournalAsync(journalDir: string, maxEntries?: int, unit?: string, sudo?: bool)` → `ToolResult<JournalEntry[]>` — systemd journal.
- `InstalledPackagesAsync(rootDir: string, sudo?: bool)` → `ToolResult<LinuxPackage[]>` — dpkg status inventory.
- `PackageLogAsync(rootDir: string, sudo?: bool)` → `ToolResult<PackageEvent[]>` — dpkg.log + apt history install timeline.
- `ShellHistoryAsync(rootDir: string, sudo?: bool)` → `ToolResult<ShellHistoryEntry[]>` — every user's bash/zsh/python history.
- `ClamScanAsync(path: string, recurse?: bool, sudo?: bool)` → `ToolResult<ClamAvMatch[]>` — ClamAV infected-file scan.
- `SetuidFilesAsync(rootDir: string, sudo?: bool)` → `ToolResult<LinuxFile[]>` — SUID/SGID binaries.
- `WorldWritableFilesAsync(rootDir: string, sudo?: bool)` → `ToolResult<LinuxFile[]>` — world-writable files.
- `FilesInDirsAsync(dirs: string[], sudo?: bool)` → `ToolResult<LinuxFile[]>` — files under given dirs (e.g. /tmp staging).
- `ReadFilesAsync(paths: string[], sudo?: bool)` → array of `{ Path, Content }` — slurp arbitrary small artifact
  files/globs in one round trip (systemd units, rc files, authorized_keys, …).

---

## PacketAnalysisToolkit

Wrappers for the SIFT network tools over a capture file (`pcap`/`pcapng`) — Wireshark's analytic power head-less
via **tshark** plus tcpdump/capinfos/tcptrace/tcpflow/ngrep/p0f/nfdump and the **Suricata** IDS. First use
auto-provisions `tshark` + `suricata` (+ ET rules) if missing (the worthwhile installs; Zeek has no apt package
and is not auto-provisioned). Grounded in SANS FOR501.2. Pass `sudo: true` for a root-owned capture on a mounted image.

Each data method returns a **`ToolResult<T>`**: check `.IsSuccess`, read the payload from `.Result`, or read why it
produced nothing from `.Message` (it distinguishes "tool not installed on this platform" from "the command
ran but failed"). An empty `.Result` array means "ran clean, found nothing" — not a failure.

- `CapInfoAsync(pcap: string)` → `ToolResult<PcapInfo>` — capture metadata (packets/bytes/duration/time span/hashes).
- `ProtocolHierarchyAsync(pcap: string)` → `ToolResult<ProtocolLayer[]>` — protocol mix tree (frames/bytes, nesting `Depth`).
- `ConversationsAsync(pcap: string, proto?: string)` → `ToolResult<Conversation[]>` — flows (default tcp): endpoints, directional + total frames/bytes, duration.
- `EndpointsAsync(pcap: string, proto?: string)` → `ToolResult<Endpoint[]>` — per-host packet/byte (tx/rx) totals (default ip).
- `ReadPacketsAsync(pcap: string, displayFilter?: string, count?: int)` → `ToolResult<PacketSummary[]>` — per-packet column view.
- `FieldsAsync(pcap: string, displayFilter: string, fields: string[])` → `ToolResult<string[][]>` — generic `tshark -T fields`
  extractor (one row per packet); the primitive for custom hunts (DNS names, HTTP hosts, SYN timing, …).
- `FollowStreamAsync(pcap: string, proto: string, index: int)` → `ToolResult<string>` — reassembled stream content.
- `ExportObjectsAsync(pcap: string, kind: string, outDir: string)` → `ToolResult<string[]>` — carve transferred objects (http/smb/tftp/imf).
- `TcpFlowAsync(pcap: string, outDir: string)` → `ToolResult<string[]>` — reassemble every TCP flow to files.
- `TcpTraceAsync(pcap: string)` → `ToolResult<TcpTraceConn[]>` — per-connection TCP summary.
- `NgrepAsync(pcap: string, pattern: string, bpf?: string)` → `ToolResult<NgrepMatch[]>` — regex payload search.
- `P0fAsync(pcap: string)` → `ToolResult<P0fRecord[]>` — passive OS/device fingerprints.
- `NfdumpAsync(flowSource: string, filter?: string)` → `ToolResult<NetflowRecord[]>` — NetFlow records (nfcapd files, not pcap).
- `SuricataAsync(pcap: string, outDir: string)` → `ToolResult<SuricataAlert[]>` — run the IDS, parse `eve.json` alerts.
- `EditcapSliceAsync(...)` / `MergeAsync(pcaps: string[], outFile: string)` → `bool` utility slice / merge (true on success).

---

## AnomalyDetectionToolkit

A **pure-compute** (no workstation I/O) triage engine over a canonical timeline. It turns a timeline into a
ranked, explained review shortlist using label-free `(event_id, Δt)` detectors (rare type, rare transition, timing
burst, periodic beacon, suspicious content), reported in **bits of surprisal**; self-baselining by default. **All
methods are synchronous** (no `await`).

- `TriageTimeline(rawEvents: TimelineEvent[], budget?: int, highSignalOnly?: bool)` → `TriageReport` — canonicalize
  raw Plaso events (e.g. from `PsortReducedAsync`) and triage them. `budget` (default 200) is the shortlist size;
  `highSignalOnly=true` first drops the filesystem-metadata firehose.
- `Triage(events: CanonicalEvent[], budget?: int)` → `TriageReport` — triage already-canonicalized events (self-baseline).
- `Triage(baseline: CanonicalEvent[], target: CanonicalEvent[], budget?: int)` → `TriageReport` — triage `target`
  against a separate benign `baseline`.
- `Summarize(report: TriageReport, topN?: int)` → `string` — compact, agent-readable rendering (pass to `log`).

```js
const ev = await TimelineAnalysisToolkit.PsortReducedAsync("/cases/host.plaso");
if (!ev.IsSuccess) { error(ev.Message); }
else {
  const report = AnomalyDetectionToolkit.TriageTimeline(ev.Result, 200, true);
  log(AnomalyDetectionToolkit.Summarize(report, 25));
}
```

---

# Workflows

Workflows codify multi-step DFIR procedures over the toolkits. **Every workflow method is async and returns
`WorkflowResult<T>`** (access the payload via `result.Result`). The workflow objects are `DiskAnalysisWorkflow`,
`MemoryAnalysisWorkflow`, `WindowsAnalysisWorkflow`, `TimelineAnalysisWorkflow`, `AntiForensicsAnalysisWorkflow`,
`WebServerAnalysisWorkflow`, `LinuxAnalysisWorkflow`, and `PacketAnalysisWorkflow`. The JSON schema for each payload type
named below is in the `camel-sdk-schema` resource.

---

## DiskAnalysisWorkflow

Disk-image acquisition, mounting, verification, and recovery (read-only forensic practice).

- `MountEwfImageAsync(imageFile: string, mountDir: string)` → `WorkflowResult<EwfImageMount>` — validate, mount E01
  RO as `<mountDir>/ewf1`, read the partition table.
- `MountFileSystemAsync(imageMount: EwfImageMount, offset: int, mountDir?: string)` → `WorkflowResult<FileSystemMount>`
  — verify (fsstat) and mount one partition RO (NTFS-aware, ntfs-3g fallback).
- `VerifyImageAsync(imageFile: string)` → `WorkflowResult<ImageVerification>` — ewfinfo + ewfverify.
- `GenerateFilesystemTimelineAsync(imageFile: string, offset?: int, timezone?: string, bodyfilePath?: string)`
  → `WorkflowResult<FilesystemTimeline>` — fls bodyfile → mactime.
- `RecoverFilesAsync(imageFile: string, outputDir: string, offset?: int, includeDeleted?: bool)` → `WorkflowResult<FileRecovery>`
  — tsk_recover (`includeDeleted` default true).
- `CarveFilesAsync(image: string, outputDir: string, carver?: string, fileTypes?: string)` → `WorkflowResult<CarveReport>`
  — signature-carve the whole image (carver `foremost` (default)/`scalpel`/`photorec`); inventory by type.
- `CarveUnallocatedSpaceAsync(image: string, outputDir: string, offset?: int, carver?: string)` → `WorkflowResult<CarveReport>`
  — the FOR508.5 recipe: `blkls` extract unallocated → carve deleted files out of it (temp extract auto-cleaned).
- `ExtractForensicFeaturesAsync(image: string, outputDir: string)` → `WorkflowResult<FeatureExtractionReport>`
  — bulk_extractor features (emails/URLs/domains/CCNs/phones/IPs) with counts + top values.
- `ListDeletedFilesAsync(image: string, offset?: int, maxFiles?: int)` → `WorkflowResult<DeletedFilesReport>`
  — deleted files from fs metadata (path/inode/size/deleted-time/recoverable), largest first.
- `RecoverDeletedFileAsync(image: string, inode: string, outputFile: string, offset?: int)` → `WorkflowResult<string>`
  — extract one deleted file by TSK inode address (`icat`).
- `UnmountImageAsync(imageMount: EwfImageMount, ...filesystemMounts: FileSystemMount[])` → `WorkflowResult<string[]>`
  — unmount filesystem mounts then the raw device; returns the unmounted dirs.
- `InspectBitLockerVolumeAsync(imageMount: EwfImageMount, offset: int)` → `WorkflowResult<BitLockerInfo>` — confirm a
  partition is BitLocker-encrypted and report its encryption method + key protectors (no credential needed). A BDE
  volume still shows as "NTFS" in mmls, so use this to tell encrypted from unencrypted before mounting.
- `UnlockBitLockerVolumeAsync(imageMount: EwfImageMount, offset: int, recoveryPassword?: string, password?: string, bekFile?: string, fullKey?: string, bdeMountDir?: string, fsMountDir?: string, mountFilesystem?: bool)`
  → `WorkflowResult<BitLockerVolumeMount>` — confirm (bdeinfo) → decrypt (bdemount → `bde1`) → optionally loop-mount
  the cleartext volume for browsing. Supply one credential. The result's `DecryptedDevice` feeds the TSK tools with
  **no offset**; `FilesystemMountDir` (when mounted) is browsable. Tear down with `UnmountBitLockerVolumeAsync`.
- `UnmountBitLockerVolumeAsync(mount: BitLockerVolumeMount)` → `WorkflowResult<string[]>` — unmount the decrypted
  filesystem then the bde FUSE device (release before the underlying `UnmountImageAsync`).
- `SearchBitLockerRecoveryKeysAsync(input: string, maxMatches?: int)` → `WorkflowResult<string[]>` — find 48-digit
  recovery keys by string search when no key is supplied (try each as `recoveryPassword`).

---

## MemoryAnalysisWorkflow

FOR508.3 "Finding the First Hit" memory forensics. All take a memory `imageFile: string`.

- `FindHiddenProcessAsync(imageFile: string)` → `WorkflowResult<HiddenProcessReport>`.
- `FindHiddenServicesAsync(imageFile: string, ...suspiciousPathFragments: string[])` → `WorkflowResult<SuspiciousServiceReport>`.
- `FindAnomalousMemoryIndicatorsAsync(imageFile: string, dumpProcessDir?: string, dumpMemoryDir?: string, dumpStringsDir?: string)`
  → `WorkflowResult<AnomalousMemoryReport>`.
- `FindAllUniqueRemoteIPsAsync(imageFile: string)` → `WorkflowResult<RemoteIpReport>`.
- `ExtractCredentialMaterialAsync(imageFile: string)` → `WorkflowResult<CredentialReport>`.
- `GenerateTimelineAsync(imageFile: string, timelineOutputPath: string)` → `WorkflowResult<MemoryTimeline>`.
- `FindCodeInjectionAsync(imageFile: string)` → `WorkflowResult<CodeInjectionReport>`.
- `DetectKernelRootkitAsync(imageFile: string)` → `WorkflowResult<KernelRootkitReport>`.
- `CrossViewHiddenProcessAsync(imageFile: string)` → `WorkflowResult<CrossViewHiddenProcessReport>`.
- `ReconstructConsoleHistoryAsync(imageFile: string)` → `WorkflowResult<ConsoleHistoryReport>`.
- `ScanMemoryWithYaraAsync(imageFile: string, yaraRulesFile: string, pid?: int, wide?: bool)` → `WorkflowResult<MemoryYaraReport>`.
- `DetectSkeletonKeyAsync(imageFile: string)` → `WorkflowResult<SkeletonKeyReport>`.
- `TriageProcessAncestryAsync(imageFile: string)` → `WorkflowResult<ProcessTriageReport>`.
- `FindMalwareAsync(imageFile: string, dumpDir?: string, yaraRulesFile?: string, dumpYaraRules?: string, legacyMode?: bool)`
  → `WorkflowResult<FindMalwareReport>` — the full 6-step orchestrator. `legacyMode=true` for pre-Win10 images.

---

## WindowsAnalysisWorkflow

Host-artifact analysis: registry, execution evidence, persistence, lateral movement, DC-attack hunting.
`*EvtxPath` / `*Hive` / `volumeRoot` arguments are paths on a mounted volume.

- `GetKeyRegistryArtifactsAsync(hiveDirectory: string, batchFile?: string)` → `WorkflowResult<KeyRegistryArtifactsReport>`.
- `GetKnownExecutablesFromShimcacheAsync(systemHive: string, ignoreTransactionLogs?: bool)` → `WorkflowResult<ShimcacheEntry[]>`.
- `GetExecutedBinariesFromAmcacheAsync(amcacheHive: string, ignoreTransactionLogs?: bool)` → `WorkflowResult<AmcacheEntry[]>`.
- `AnalyzeExternalShareConnectionsAsync(ntuserHive: string, batchFile?: string)` → `WorkflowResult<ExternalShareConnectionsReport>`.
- `AnalyzeExecutionEvidenceAsync(systemHive: string, amcacheHive?: string, suspiciousPathFragments?: string[], toolWatchlist?: string[])`
  → `WorkflowResult<ExecutionReport>`.
- `FindWmiPersistenceAsync(objectsDataPath: string, allowlistNames?: string[])` → `WorkflowResult<WmiPersistenceReport>`.
- `FindDllHijackingAsync(volumeRoot: string, transientDllDirs?: string[])` → `WorkflowResult<DllHijackReport>`.
- `DetectCredentialDumpingAsync(volumeRoot: string)` → `WorkflowResult<CredentialDumpReport>`.
- `TriageSuspiciousExecutablesAsync(volumeRoot: string, transientExecDirs?: string[])` → `WorkflowResult<SuspiciousExecutableReport>`.
- `AnalyzeLogonsAsync(securityEvtxPath: string)` → `WorkflowResult<LogonReport>`.
- `HuntLateralMovementAsync(securityEvtxPath: string, systemEvtxPath?: string)` → `WorkflowResult<LateralMovementReport>`.
- `DetectKerberosAttacksAsync(securityEvtxPath: string, preauthFailureThreshold?: int)` → `WorkflowResult<KerberosReport>`.
- `DetectLogClearingAsync(securityEvtxPath: string, systemEvtxPath?: string)` → `WorkflowResult<LogClearingReport>`.
- `AnalyzePowerShellAsync(powershellEvtxPath: string)` → `WorkflowResult<PowerShellReport>`.
- `FindRegistryPersistenceMechanismsAsync(softwareHive: string, systemHive: string, ntuserHive?: string, tasksDirectory?: string, suspiciousPathFragments?: string[])`
  → `WorkflowResult<RegistryPersistenceReport>`.
- `ValidateProcessTreeAsync(processes: ProcessNode[], checkInstanceCounts?: bool)` → `WorkflowResult<ProcessTreeValidationReport>`
  — validate processes-under-investigation against the bundled MemProcFS/SANS Hunt-Evil expectation dataset: never-spawns-children
  injection (lsass/csrss/dwm child = critical), suspicious-parent blacklist (Office/browser/LOLBin → shell), valid-parent whitelist,
  plus optional path/user and instance-count checks. Also accepts a `WindowsPsList[]` (resolves parent names by PID/PPID).
  `checkInstanceCounts` only meaningful on a complete process listing.
- `GetProcessExpectations()` → `{ [processName: string]: ProcessExpectation }` — the raw expectation dataset, keyed by lowercase name.
- `AnalyzeShellItemsAsync(userProfileRoot: string, hiveDirectory?: string)` → `WorkflowResult<ShellItemReport>`
  — FOR500.3 shell-item analysis: correlate LNK + Jump Lists (files opened) and Shellbags (folders browsed) for a
  user profile, and surface references to external/removable/remote volumes (the hook to USB correlation).
- `AnalyzeUsbDevicesAsync(systemHive: string, softwareHive: string, ntuserHive?: string, setupApiLog?: string)` → `WorkflowResult<UsbDeviceReport>`
  — FOR500.3 USB methodology: profile each USB device (vendor/product/serial/VID-PID), map volume name/drive
  letter/GUID/user, and resolve first/last-connect times (usbdeviceforensics + RegRipper usbstor + setupapi.dev.log).
- `AnalyzeEmailArchivesAsync(volumeRoot: string, singleArchive?: string)` → `WorkflowResult<EmailArchiveReport>`
  — FOR500.4 e-mail: find PST/OST stores on a volume (or analyse one), read store metadata, and parse messages at
  header level (From/To/Subject/Date/X-Originating-IP + attachment names).
- `AnalyzeBrowserActivityAsync(userProfileRoot: string, webCacheDb?: string, useHindsight?: bool)` → `WorkflowResult<BrowserActivityReport>`
  — FOR500.4 browser forensics: unify visited-URL history + downloads across Chromium `History` (Chrome/Edge),
  Firefox `places.sqlite`, and IE/Edge `WebCacheV01.dat`, timestamps normalised to UTC.

---

## TimelineAnalysisWorkflow

Plaso super-timeline creation and the FOR508 analysis loop (pivots, categorization, anomaly triage).

- `CreateSuperTimelineAsync(source: string, storageFile: string, parsers?: string, filterFile?: string, partitions?: string, vssStores?: string, from?: string, to?: string, hash?: bool, timezone?: string)`
  → `WorkflowResult<SuperTimeline>` — full/scoped build. `from`/`to` (UTC `"yyyy-MM-dd HH:mm:ss"`) filter exported events only.
- `CreateTriageTimelineAsync(source: string, storageFile: string, filterFile?: string, mftBodyfile?: string, from?: string, to?: string, timezone?: string)`
  → `WorkflowResult<SuperTimeline>` — fast triage recipe (SANS file-filter; optional `$MFT` bodyfile appended).
- `PivotAroundAsync(storageFile: string, pivot: DateTimeOffset, sliceSizeMinutes?: int)` → `WorkflowResult<SuperTimeline>`
  — slice ±N minutes around a moment (pass `pivot` as an ISO-8601 string or Date).
- `CategorizeTimelineAsync(storageFile: string, taggingFile?: string, categories?: string[])` → `WorkflowResult<CategorizedTimeline>`.
- `DetectTimelinePivotsAsync(storageFile: string, evtxPath: string, evtxDirectory?: bool, minLevel?: string, sliceSizeMinutes?: int, maxPivots?: int)`
  → `WorkflowResult<TimelinePivotReport>` — hayabusa Sigma alerts → slice around each.
- `TriageTimelineAsync(storageFile: string, budget?: int, highSignalOnly?: bool, filter?: string)` → `WorkflowResult<TimelineTriageReport>`
  — anomaly-engine triage of the whole timeline.
- `AutoPivotExpansionAsync(storageFile: string, budget?: int, topPivots?: int, sliceSizeMinutes?: int, highSignalOnly?: bool)`
  → `WorkflowResult<AutoPivotReport>` — triage, then expand top pivots into surrounding slices.
- `HuntLateralMovementTimelineAsync(storageFile: string, budget?: int)` → `WorkflowResult<TimelineTriageReport>` — triage scoped to event-logs+prefetch+LNK.
- `ProgramExecutionTimelineAsync(storageFile: string, budget?: int)` → `WorkflowResult<TimelineTriageReport>` — triage scoped to execution artifacts.
- `SearchTimelineAsync(storageFile: string, keywords: string[], from?: string, to?: string)` → `WorkflowResult<TimelineSearchReport>`.

---

## AntiForensicsAnalysisWorkflow

NTFS-metadata anti-forensics detection (FOR508.5).

- `DetectTimestompingAsync(mftFile: string, neighborWindow?: int)` → `WorkflowResult<TimestompReport>` — flag
  backdated `$SI` timestamps, corroborated against the MFT-neighbour creation cluster (`neighborWindow` default 8).
- `AnalyzeUsnJournalAsync(usnFile: string, budget?: int)` → `WorkflowResult<UsnAnomalyReport>` — triage the
  `$UsnJrnl:$J` change journal with the anomaly ensemble (mass delete = wiping, mass create = staging).

---

## WebServerAnalysisWorkflow

Triage a web server compromised through its application (SQLi → webshell → foothold). Operates on log files and
the web root on a mounted volume.

- `AnalyzeWebServerLogsAsync(accessLogPath: string, extraPatterns?: string[], maxFindings?: int)` → `WorkflowResult<WebServerLogReport>`
  — server-side signature-match the access log, classify hits, and hex-decode smuggled payloads (e.g. sqlmap's
  injected PHP backdoor). `maxFindings` caps detail rows (default 100).
- `ScanWebRootForWebshellsAsync(webRoot: string, rulesFile?: string)` → `WorkflowResult<WebshellScanReport>`
  — YARA-scan the web root with the bundled web-shell pack (default `webshells_index.yar`).

---

## LinuxAnalysisWorkflow

Triage a **mounted Linux root filesystem** for compromise: the correlation/scoring layer over
`LinuxAnalysisToolkit`. `rootDir` is the mount point (e.g. `/mnt/linux`, or `/` for the live host). Each report
carries the raw artifacts plus the flagged items (with the reason flagged).

- `TriageHostAsync(rootDir: string)` → `WorkflowResult<LinuxHostTriageReport>` — runs the account, login, auth,
  persistence, history and file hunts **in parallel** and rolls up the top findings (`TopFindings`). Start here.
- `AnalyzeUserAccountsAsync(rootDir: string)` → `WorkflowResult<UserAccountReport>` — UID-0 extras, empty passwords,
  service accounts with login shells, NOPASSWD/ALL sudo grants.
- `AnalyzeLoginActivityAsync(rootDir: string)` → `WorkflowResult<LoginActivityReport>` — wtmp/btmp: source-IP
  ranking, brute-force sources, success-after-failures, remote root logins.
- `AnalyzeAuthLogAsync(rootDir: string)` → `WorkflowResult<AuthEventReport>` — auth.log/secure: sshd accepted/failed,
  sudo/su, account changes, SSH brute-force (server-side prefiltered).
- `HuntPersistenceAsync(rootDir: string)` → `WorkflowResult<LinuxPersistenceReport>` — cron, systemd units/timers,
  rc.local, init, shell rc, ld.so.preload, authorized_keys, udev, motd — scored for implant tells.
- `AnalyzeShellHistoryAsync(rootDir: string)` → `WorkflowResult<ShellHistoryReport>` — attacker-pattern commands
  (recon/download/privesc/persistence/lateral-c2/cleanup/credaccess) across all users' histories.
- `AnalyzeInstalledPackagesAsync(rootDir: string)` → `WorkflowResult<PackageReport>` — dpkg inventory + install
  timeline; flags dual-use/offensive tooling installs (nmap, netcat, masscan, …).
- `HuntAnomalousFilesAsync(rootDir: string)` → `WorkflowResult<FileAnomalyReport>` — off-baseline SUID/SGID,
  world-writable system files, executables staged in /tmp·/dev/shm·/var/tmp.
- `ScanForMalwareAsync(target: string, yaraRulesFile?: string)` → `WorkflowResult<LinuxMalwareReport>` — ClamAV +
  YARA over a target (default rules: the bundled master `index.yar`).
- `AnalyzeJournalAsync(rootDir: string, maxEntries?: int)` → `WorkflowResult<JournalReport>` — systemd journal:
  sudo/ssh/service-start counts + notable entries.

```js
// One-call Linux host triage over a mounted image.
const t = await LinuxAnalysisWorkflow.TriageHostAsync("/mnt/linux");
log(t.Message);
for (const f of t.Result.TopFindings) log(f);
```

---

## PacketAnalysisWorkflow

Analyse a network capture (`pcap`/`pcapng`) for intrusion evidence (SANS FOR501.2). `pcap` is the capture path.

- `TriagePcapAsync(pcap: string, top?: int)` → `WorkflowResult<PcapTriageReport>` — overview: metadata, protocol
  mix, top conversations/endpoints, busiest DNS/HTTP hosts. Start here.
- `HuntDnsTunnelingAsync(pcap: string)` → `WorkflowResult<DnsTunnelingReport>` — DNS-tunnel / DNS-backdoor
  detection (long/high-entropy labels, unique-subdomain volume, TXT/NULL records) — the book's flagship lab.
- `FollowStreamAsync(pcap: string, proto: string, index: int)` → `WorkflowResult<StreamReport>` — reassemble a
  stream with credential/command lines highlighted.
- `ExtractHttpObjectsAsync(pcap: string, outDir: string)` → `WorkflowResult<HttpObjectReport>` — carve HTTP
  objects + list requests.
- `ExtractCredentialsAsync(pcap: string)` → `WorkflowResult<PcapCredentialReport>` — cleartext creds (HTTP Basic
  decoded, FTP USER/PASS, form/login params).
- `DetectBeaconingAsync(pcap: string)` → `WorkflowResult<BeaconReport>` — timing-based C2-beacon detection (regular
  connection cadence / low jitter).
- `FingerprintHostsAsync(pcap: string)` → `WorkflowResult<HostFingerprintReport>` — passive OS fingerprints (p0f).
- `RunIdsAsync(pcap: string, outDir?: string)` → `WorkflowResult<IdsReport>` — Suricata signature IDS → alerts
  grouped by signature/severity (the maintained Snort analog).

```js
// Capture triage → DNS-tunnel hunt → IDS.
const t = await PacketAnalysisWorkflow.TriagePcapAsync("/cases/suspect.pcap");
log(t.Message);
const d = await PacketAnalysisWorkflow.HuntDnsTunnelingAsync("/cases/suspect.pcap");
for (const dom of d.Result.SuspiciousDomains) log(`${dom.Domain} (score ${dom.Score}): ${dom.Reasons.join(", ")}`);
const ids = await PacketAnalysisWorkflow.RunIdsAsync("/cases/suspect.pcap");
log(ids.Message);
```

---

## End-to-end patterns

```js
// Disk → triage timeline → anomaly pivots in context.
const tl = await TimelineAnalysisWorkflow.CreateTriageTimelineAsync("/mnt/c", "/cases/host.plaso");
if (!tl.IsSuccess) { error(tl.Message); }
else {
  const x = await TimelineAnalysisWorkflow.AutoPivotExpansionAsync("/cases/host.plaso", 200, 10, 5, true);
  log(x.Message);
  for (const p of x.Result.Pivots)
    log(`${p.Pivot.Time} ${p.Pivot.EventType} [${p.Pivot.Bits.toFixed(0)} bits] — ${p.SurroundingCount} events`);
}
```
```js
// Memory → full 6-step malware hunt with dumping + YARA.
const r = await MemoryAnalysisWorkflow.FindMalwareAsync("/cases/mem.raw", "/cases/dumps");
if (r.IsSuccess)
  for (const s of r.Result.HighConfidenceSuspects)
    log(`${s.Process} (PID ${s.Pid}) [${s.Categories.join(", ")}] ${s.Signals.join("; ")}`);
```
```js
// Parallel independent toolkit calls.
const [ps, net, svc] = await Promise.all([
  MemoryAnalysisToolkit.WindowsPsScanAsync("/cases/mem.raw"),
  MemoryAnalysisToolkit.WindowsNetScanAsync("/cases/mem.raw"),
  MemoryAnalysisToolkit.WindowsSvcScanAsync("/cases/mem.raw"),
]);
log(`${ps?.length ?? 0} procs, ${net?.length ?? 0} connections, ${svc?.length ?? 0} services`);
```
