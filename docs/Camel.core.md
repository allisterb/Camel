# Camel JavaScript SDK — Core Reference

This is the **core** reference for the Camel JavaScript (JS) SDK — the typed API exposed to code that the agent
generates and executes inside the Camel MCP server's constrained JavaScript engine (via the `ExecuteJavaScript`
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
- **Toolkit methods return their payload or `null` on tool failure; workflow methods return `WorkflowResult<T>`.**
  Always check before using the value.
- Output via the globals `log` / `error` / `table`. There is no interactive prompting. `eval`/`new Function` are disabled.

Path arguments are paths **on the SIFT workstation** (local or over SSH). Each MCP session has its own isolated
environment; toolkits are constructed lazily on first access and cached for the session.

## Global Functions

`log(message: string)` — write an informational line to the script's output buffer (the text returned to the
agent when the script finishes).

`error(message: string)` — write an error line to the output buffer (same mechanism as `log`; use it to mark a problem).

`table(headers: string[], dataRows: object[][])` — write a tabular block to the output buffer (`headers` are the
column headers; `dataRows` is one inner array of cell values per row).

> Output is accumulated and returned as the tool result. If the script throws, output produced before the
> failure is still returned, followed by the error message.

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

Toolkit methods execute a SIFT tool on the workstation and return a parsed model — an array or object — or `null`
if the command failed. The toolkit objects are `MemoryAnalysisToolkit`, `DiskAnalysisToolkit`,
`WindowsAnalysisToolkit`, `TimelineAnalysisToolkit`, `YaraToolkit`, and `AnomalyDetectionToolkit`. The JSON
schema for each return type named below is in the `camel-sdk-schema` resource.

---

## MemoryAnalysisToolkit

Volatility 3 wrapper for Windows memory-image analysis. `filename` is the memory image path. Methods taking an
optional `pid: int` restrict output to one process.

- `WindowsInfoAsync(filename: string)` → `WindowsInfo[]` — OS/build metadata.
- `WindowsPsListAsync(filename: string)` → `WindowsPsList[]` — active EPROCESS list walk.
- `WindowsPsScanAsync(filename: string)` → `WindowsPsScan[]` — pool-tag process scan (finds hidden/exited).
- `WindowsPsTreeAsync(filename: string, pid?: int)` → `WindowsPsTree[]` — process tree (nodes carry `__children`).
- `WindowsSvcScanAsync(filename: string)` → `WindowsSvcScan[]` — service records (incl. hidden/deleted).
- `WindowsCmdLineAsync(filename: string, pid?: int)` → `WindowsCmdLine[]` — per-process command lines.
- `WindowsEnvVarsAsync(filename: string, pid?: int)` → `WindowsEnvVars[]` — per-process environment variables.
- `WindowsGetSidsAsync(filename: string, pid?: int)` → `WindowsGetSids[]` — per-process owning SIDs.
- `WindowsPrivsAsync(filename: string, pid?: int)` → `WindowsPrivs[]` — per-process privileges.
- `WindowsHandlesAsync(filename: string, pid?: int, objectType?: string)` → `WindowsHandles[]` — open handles;
  `objectType` filters by type (e.g. `"File"`, `"Mutant"`, case-insensitive).
- `WindowsDllListAsync(filename: string, pid?: int)` → `WindowsDllList[]` — loaded DLLs.
- `WindowsModulesAsync(filename: string)` → `WindowsModules[]` — kernel modules (list).
- `WindowsModScanAsync(filename: string)` → `WindowsModScan[]` — kernel modules (pool scan).
- `WindowsGetServiceSidsAsync(filename: string)` → `WindowsGetServiceSids[]` — service SIDs.
- `WindowsNetStatAsync(filename: string)` → `WindowsNetStat[]` — active network connections.
- `WindowsNetScanAsync(filename: string)` → `WindowsNetScan[]` — pool-scan of connections (incl. closed/historical).
- `WindowsMalFindAsync(filename: string)` → `WindowsMalFind[]` — private executable regions with no file backing.
- `WindowsLdrModulesAsync(filename: string, pid?: int)` → `WindowsLdrModules[]` — PEB-list vs VAD DLL presence.
- `WindowsHollowProcessesAsync(filename: string)` → `WindowsHollowProcesses[]` — process-hollowing victims.
- `WindowsThreadsAsync(filename: string, pid?: int)` → `WindowsThreads[]` — thread start addresses.
- `WindowsSsdtAsync(filename: string)` → `WindowsSsdt[]` — SSDT entries (foreign module = hook).
- `WindowsCallbacksAsync(filename: string)` → `WindowsCallbacks[]` — registered kernel callbacks.
- `WindowsDriverIrpAsync(filename: string)` → `WindowsDriverIrp[]` — driver IRP major-function tables.
- `WindowsPsxViewAsync(filename: string)` → `WindowsPsxView[]` — cross-view process visibility.
- `WindowsMutantScanAsync(filename: string)` → `WindowsMutantScan[]` — named mutex IOCs.
- `WindowsCmdScanAsync(filename: string)` → `WindowsCmdScan[]` — typed command lines (COMMAND_HISTORY).
- `WindowsConsolesAsync(filename: string)` → `WindowsConsoles[]` — console buffers (commands + output).
- `WindowsFileScanAsync(filename: string)` → `WindowsFileScan[]` — FILE_OBJECTs (with offsets).
- `WindowsVadInfoAsync(filename: string, pid?: int)` → `WindowsVadInfo[]` — VAD regions.
- `WindowsRegistryHiveListAsync(filename: string)` → `WindowsRegistryHiveList[]` — loaded registry hives.
- `WindowsRegistryPrintKeyAsync(filename: string, key: string)` → `WindowsRegistryPrintKey[]` — values under a key.
- `WindowsRegistryUserAssistAsync(filename: string)` → `WindowsRegistryUserAssist[]` — UserAssist entries.
- `WindowsShimcacheMemAsync(filename: string)` → `WindowsShimcacheMem[]` — AppCompatCache from kernel memory.
- `WindowsHashdumpAsync(filename: string)` → `WindowsHashdump[]` — local NTLM hashes (SAM).
- `WindowsLsadumpAsync(filename: string)` → `WindowsLsadump[]` — LSA secrets.
- `WindowsCachedumpAsync(filename: string)` → `WindowsCachedump[]` — cached domain creds (mscash2).
- `WindowsSkeletonKeyCheckAsync(filename: string)` → `WindowsSkeletonKeyCheck[]` — DC Skeleton Key (empty = clean).
- `WindowsProcessGhostingAsync(filename: string)` → `WindowsProcessGhosting[]` — Process Ghosting (empty = clean).
- `WindowsVerInfoAsync(filename: string, pid?: int)` → `WindowsVerInfo[]` — PE version-info strings.
- `WindowsVadYaraScanAsync(filename: string, yaraRulesFile: string, pid?: int, wide?: bool)` → `WindowsVadYaraScan[]`
  — YARA-scan VAD regions (`wide` also matches UTF-16).
- `DumpFilesAsync(filename: string, outputDir: string, virtualAddress?: long, physicalAddress?: long, pid?: int, filterRegex?: string)`
  → `string[]` — extract cached files; returns workstation paths of the dumped files.
- `DumpProcessExecutableAsync(filename: string, pid: int, outputDir: string)` → `string[]` — dump a process's PE image.
- `DumpProcessMemoryAsync(filename: string, pid: int, outputDir: string)` → `string[]` — dump all mapped memory.
- `ExtractStringsAsync(inputFile: string, outputFile: string, unicode?: bool, minLength?: int)` → `bool` —
  run `strings` (ASCII, or UTF-16LE when `unicode=true`; `minLength` default 8) into `outputFile`.
- `TimelinerBodyfileAsync(image: string, outputDir: string)` → `string` (path) — mactime bodyfile of all
  timestamped artifacts (`volatility.body`), or null.

> Most Volatility plugins are independent — fan out multiple `Windows*Async` calls and `await` them together
> (e.g. `Promise.all`); the environment bounds SSH concurrency.

---

## DiskAnalysisToolkit

The Sleuth Kit (TSK), libewf (EWF/E01), loopback/NTFS mounting, file recovery, and mactime. The optional
`offset: int` argument is a **partition start sector** (from `MmlsAsync` / `ListPartitionsAsync`); omit it for a
single-volume image.

- `EwfInfoAsync(image: string)` → `EwfInfo` — EWF metadata + acquisition hashes (null on failure).
- `EwfVerifyAsync(image: string)` → `EwfVerify` — recompute & compare acquisition hash.
- `EwfMountRawAsync(image: string, mountDir: string)` → `bool` — FUSE-mount E01 RO as `<mountDir>/ewf1`.
- `EwfMountLoopbackAsync(rawPartition: string, mountDir: string, offset?: int)` → `bool` — kernel-NTFS loopback mount.
- `EwfMountNtfsAsync(rawPartition: string, mountDir: string, offset?: int)` → `bool` — ntfs-3g `force` mount (dirty NTFS).
- `DDMountAsync(imageFile: string, mountDir: string, offset?: int)` → `bool` — RO loopback mount of a raw `.dd`.
- `MakeMountDirAsync(name: string)` → `string` (path) — create `/mnt/<name>`.
- `MakeDirAsync(path: string)` → `bool` — `mkdir -p` an absolute path.
- `UnmountAsync(mountDir: string)` → `bool` — `umount`.
- `ImgStatAsync(image: string)` → `ImgStat` — image format details.
- `MmlsAsync(image: string)` → `MmlsEntry[]` — partition table (TSK).
- `ListPartitionsAsync(disk: string)` → `PartitionInfo[]` — partition table (`fdisk -l`).
- `FsStatAsync(image: string, offset?: int)` → `FsStat` — filesystem details.
- `FlsAsync(image: string, offset?: int, inode?: long, recursive?: bool, deletedOnly?: bool)` → `FlsEntry[]` — directory listing.
- `IstatAsync(image: string, inode: long, offset?: int)` → `Istat` — inode metadata.
- `FfindAsync(image: string, inode: long, offset?: int)` → `string` — file name for an inode.
- `IlsAsync(image: string, offset?: int)` → `IlsEntry[]` — inode listing.
- `IcatAsync(image: string, inode: long, outputFile: string, offset?: int)` → `bool` — extract an inode's content.
- `FindFilesAsync(directory: string, namePattern?: string, maxDepth?: int)` → `FsFile[]` — find by one glob (default `"*"`).
- `FindFilesAsync(directory: string, namePatterns: string[], maxDepth?: int)` → `FsFile[]` — find by any of several globs.
- `Sha256Async(path: string)` → `string` — SHA-256 of a mounted file.
- `GrepLinesAsync(path: string, patterns: string[], ignoreCase?: bool, maxMatches?: int)` → `string[]` —
  server-side `grep -E -f`; returns only matching lines (`[]` on no match, null on unreadable file).
- `TskRecoverAsync(image: string, outputDir: string, all: bool, dirInode?: long, offset?: int)` → `int` —
  bulk-recover files (count); `all=true` includes deleted/unallocated.
- `FlsBodyfileAsync(image: string, outputFile: string, offset?: int, mountPoint?: string)` → `bool` — `fls -r -m` bodyfile.
- `MactimeAsync(bodyfile: string, timezone?: string)` → `MactimeEntry[]` — render a sorted timeline (default UTC).
- `MactimeToFileAsync(bodyfile: string, outputFile: string, timezone?: string)` → `bool` — render a large timeline to a file.

---

## WindowsAnalysisToolkit

Eric Zimmerman (EZ) tools, RegRipper, and bespoke parsers for Windows host artifacts.

- `LoadLolbasAsync()` → `LolbasReference` — the LOLBAS index (methods `IsLolbin`, `IsCanonicalPath`).
- `MFTECmdAsync(file: string)` → `MFTEntry[]` — parse a `$MFT` to JSON rows.
- `MFTECmdUsnAsync(usnFile: string)` → `UsnJournalEntry[]` — parse a `$UsnJrnl:$J` change journal.
- `MFTECmdCsvAsync(file: string, outputFile?: string, outputDir?: string, allTimestamps?: bool, recoverSlack?: bool, vss?: bool)`
  → `MFTECmdResult` — parse NTFS metadata to a CSV file (one of `outputFile`/`outputDir` required).
- `MFTECmdBodyfileAsync(file: string, outputFile?: string, outputDir?: string, driveLetter?: string, vss?: bool)`
  → `MFTECmdResult` — parse to a mactime bodyfile.
- `LECmdAsync(file: string)` → `LnkFile[]` — parse a LNK shortcut.
- `SBECmdAsync(hiveDirectory: string)` → `ShellBag[]` — shellbags (JSON).
- `SBECmdCsvAsync(directory: string, outputDir: string)` → `SBECmdCsvResult` — shellbags to per-hive CSVs.
- `AppCompatCacheParserAsync(systemHive: string, ignoreTransactionLogs?: bool)` → `ShimcacheEntry[]` — Shimcache.
- `AmcacheParserAsync(amcacheHive: string, ignoreTransactionLogs?: bool)` → `AmcacheEntry[]` — Amcache (SHA-1 + metadata).
- `RBCmdAsync(file: string)` → `RecycleBinEntry[]` — recycle-bin records.
- `JLECmdAsync(directory: string)` → `JumpListEntry[]` — jump lists.
- `WxTCmdAsync(activitiesCacheDb: string)` → `TimelineActivity[]` — Win10 Timeline activities.
- `RECmdAsync(hiveDirectory: string, batchFile: string)` → `RegistryEntry[]` — RECmd batch over a hive directory.
- `RECmdSingleHiveAsync(hiveFile: string, batchFile: string)` → `RegistryEntry[]` — RECmd over one hive (replays logs).
- `SQLECmdAsync(directory: string)` → `object[]` — SQLECmd over SQLite DBs (heterogeneous key/value records).
- `EvtxECmdAsync(file?: string, directory?: string, includeIds?: string, excludeIds?: string, startDate?: string, endDate?: string)`
  → `EventLogEntry[]` — parse EVTX to JSON (one of `file`/`directory` required; IDs comma-separated; dates UTC `"yyyy-MM-dd HH:mm:ss"`).
- `EvtxECmdServerFilteredAsync(payloadGrepPattern: string, file?: string, directory?: string, includeIds?: string, excludeIds?: string, startDate?: string, endDate?: string)`
  → `EventLogEntry[]` — as above, server-side `grep -F` of the payload first (for huge event streams).
- `EvtxECmdCsvAsync(file?: string, directory?: string, includeIds?: string, excludeIds?: string, startDate?: string, endDate?: string, outputFile?: string, outputDir?: string)`
  → `EvtxECmdCsvResult` — parse EVTX to a CSV file.
- `RegRipperAsync(hive: string, plugin: string)` → `RegRipperResult` — run one RegRipper plugin (raw text in `.Lines`).
- `ScheduledTasksAsync(tasksDirectory: string)` → `ScheduledTaskEntry[]` — parse `\Windows\System32\Tasks` XML.
- `WmiSubscriptionsAsync(objectsDataPath: string)` → `WmiSubscriptions` — recover WMI subscriptions from `OBJECTS.DATA`.
- `BstringsAsync(file: string, minLength?: int)` → `string[]` — extract strings.

---

## TimelineAnalysisToolkit

Plaso (`log2timeline`/`psort`/`pinfo`/`psteal`/`image_export`) and `hayabusa`. The central artifact is a `.plaso`
**storage file** that can be re-filtered cheaply once built.

- `Log2TimelineAsync(source: string, storageFile: string, parsers?: string, hash?: bool, filterFile?: string, partitions?: string, vssStores?: string, timezone?: string)`
  → `bool` — parse `source` into `storageFile` (appends if it exists). Scope with `parsers` (preset/list, leading
  `-` negates), `filterFile`, `partitions`, `vssStores`; `hash=true` stores MD5/SHA-256.
- `PsortAsync(storageFile: string, filter?: string, slice?: string, sliceSize?: int)` → `TimelineEvent[]` — export a
  sorted timeline. `filter` is a Plaso attribute filter; `slice` (ISO-8601) + `sliceSize` (minutes) = pivot mini-timeline.
- `PsortReducedAsync(storageFile: string, filter?: string, maxMessageChars?: int)` → `TimelineEvent[]` — scale-safe
  export (strips bulky payloads, truncates `message` to `maxMessageChars`, default 1024). Prefer for whole-timeline triage.
- `PsortSearchAsync(storageFile: string, grepPattern: string, filter?: string)` → `TimelineEvent[]` — keyword-search
  the rendered timeline (server-side `grep -i -E`, incl. the human-readable `message`).
- `PsortTagAsync(storageFile: string, taggingFile: string)` → `bool` — apply the `tagging` plugin (labels persisted into the .plaso).
- `PinfoAsync(storageFile: string)` → `PlasoInfo` — parser-hit stats and total event count.
- `PstealAsync(source: string, parsers?: string, timezone?: string)` → `TimelineEvent[]` — one-step ingest+export.
- `ImageExportAsync(source: string, outputDir: string, names?: string, extensions?: string)` → `bool` — extract files from an image.
- `HayabusaJsonTimelineAsync(evtxPath: string, directory?: bool, minLevel?: string)` → `HayabusaAlert[]` — Sigma detections.
- `HayabusaComputerMetricsAsync(evtxPath: string, directory?: bool)` → `ComputerMetric[]`.
- `HayabusaEidMetricsAsync(evtxPath: string, directory?: bool)` → `EidMetric[]`.
- `HayabusaLogMetricsAsync(evtxPath: string, directory?: bool)` → `LogMetric[]`.
- `HayabusaLogonSummaryAsync(evtxPath: string, directory?: bool)` → `LogonSummaryEntry[]` (each flagged `.Successful`).

---

## YaraToolkit

Classic `yara` scanner + the bundled Yara-Rules community pack (at `/opt/yara-rules`, with aggregator indexes
such as `malware_index.yar`, `webshells_index.yar`).

- `ScanAsync(rules: string, scanPath: string, options?: YaraOptions)` → `YaraMatch[]` — scan a file or (with
  `options.Recurse`) a directory; one match per rule/file hit.
- `CompileAsync(rules: string, output: string)` → `bool` — compile rules to a binary file.

`options` is passed as a JS object literal (all fields optional), e.g. `{ Recurse: true, Timeout: 120 }`. See the
`YaraOptions` schema for the full field set.

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
const events = await TimelineAnalysisToolkit.PsortReducedAsync("/cases/host.plaso");
const report = AnomalyDetectionToolkit.TriageTimeline(events, 200, true);
log(AnomalyDetectionToolkit.Summarize(report, 25));
```

---

# Workflows

Workflows codify multi-step DFIR procedures over the toolkits. **Every workflow method is async and returns
`WorkflowResult<T>`** (access the payload via `result.Result`). The workflow objects are `DiskAnalysisWorkflow`,
`MemoryAnalysisWorkflow`, `WindowsAnalysisWorkflow`, `TimelineAnalysisWorkflow`, `AntiForensicsAnalysisWorkflow`,
`WebServerWorkflow`. The JSON schema for each payload type named below is in the `camel-sdk-schema` resource.

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
- `UnmountImageAsync(imageMount: EwfImageMount, ...filesystemMounts: FileSystemMount[])` → `WorkflowResult<string[]>`
  — unmount filesystem mounts then the raw device; returns the unmounted dirs.

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

## WebServerWorkflow

Triage a web server compromised through its application (SQLi → webshell → foothold). Operates on log files and
the web root on a mounted volume.

- `AnalyzeWebServerLogsAsync(accessLogPath: string, extraPatterns?: string[], maxFindings?: int)` → `WorkflowResult<WebServerLogReport>`
  — server-side signature-match the access log, classify hits, and hex-decode smuggled payloads (e.g. sqlmap's
  injected PHP backdoor). `maxFindings` caps detail rows (default 100).
- `ScanWebRootForWebshellsAsync(webRoot: string, rulesFile?: string)` → `WorkflowResult<WebshellScanReport>`
  — YARA-scan the web root with the bundled web-shell pack (default `webshells_index.yar`).

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
