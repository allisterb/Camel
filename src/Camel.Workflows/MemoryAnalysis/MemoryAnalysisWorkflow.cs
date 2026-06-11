namespace Camel.Workflows;

using System;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

public class MemoryAnalysisWorkflow : Workflow
{
    public MemoryAnalysisWorkflow(CamelApi api) : base(api) {}

    /// <summary>
    /// Detects hidden processes in a Windows memory image by cross-referencing two enumeration techniques —
    /// the canonical first step of the memory-forensics methodology. <c>windows.pslist</c> walks the active
    /// EPROCESS linked list (fast, but a rootkit can unlink an entry to hide it); <c>windows.psscan</c> scans
    /// the pool for <c>Proc</c> tags and so also finds processes that are unlinked, hidden, or already exited.
    /// Processes present in psscan but absent from pslist (matched by PID) are split by exit state: those with
    /// no exit time are reported as <see cref="HiddenProcessReport.HiddenProcesses"/> (still running yet
    /// unlinked — the DKOM-rootkit indicator), while those that had exited are reported separately as
    /// <see cref="HiddenProcessReport.ExitedProcesses"/> (routine, but worth correlating with the timeline).
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    public async Task<WorkflowResult<HiddenProcessReport>> FindHiddenProcessAsync(string imageFile)
    {
        using var op = Begin("Finding hidden processes in {0}", imageFile);

        // Active-process linked-list walk: fast, but misses unlinked (hidden) and exited processes.
        var psList = await MemoryAnalysis.WindowsPsListAsync(imageFile);
        if (psList is null)
            return WorkflowResult<HiddenProcessReport>.Failure(
                $"windows.pslist failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        // Pool-tag scan: finds EPROCESS structures the list walk can't, including hidden/exited processes.
        var psScan = await MemoryAnalysis.WindowsPsScanAsync(imageFile);
        if (psScan is null)
            return WorkflowResult<HiddenProcessReport>.Failure(
                $"windows.psscan failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        // Processes the pool scan found but the linked-list walk missed (matched on PID), then split by exit
        // state: no ExitTime => still running yet unlinked (genuinely hidden); ExitTime set => already exited.
        var listedPids = psList.Select(p => p.PID).ToHashSet();
        var notListed = psScan.Where(p => !listedPids.Contains(p.PID)).ToArray();
        var hidden = notListed.Where(p => p.ExitTime is null).ToArray();
        var exited = notListed.Where(p => p.ExitTime is not null).ToArray();

        op.Complete();
        return WorkflowResult<HiddenProcessReport>.Success(
            new HiddenProcessReport(hidden, exited, psList.Length, psScan.Length),
            hidden.Length == 0
                ? $"No hidden processes ({exited.Length} exited process(es) recovered only by psscan)."
                : $"Found {hidden.Length} hidden process(es) — in psscan, unlinked from pslist, still running: " +
                  string.Join(", ", hidden.Select(h => $"{h.ImageFileName} (PID {h.PID})")) +
                  $". Plus {exited.Length} exited process(es) recovered only by psscan.");
    }

    /// <summary>
    /// Scans a Windows memory image for services with suspicious binary paths. <c>windows.svcscan</c> pool-
    /// scans for service records — surfacing hidden, deleted, and not-yet-loaded services the live SCM view
    /// can miss — and this flags any whose backing binary or hosting DLL resides in a location legitimate
    /// services do not use, per the services-triage step of the methodology. Defaults to the standard unusual-
    /// location set (<c>\temp\</c>, <c>\appdata\</c>, <c>\users\</c>); pass <paramref name="suspiciousPathFragments"/>
    /// to override.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    /// <param name="suspiciousPathFragments">Path substrings (case-insensitive) that mark a service binary as
    /// suspicious. Defaults to <c>\temp\</c>, <c>\appdata\</c>, <c>\users\</c> when none are supplied.</param>
    public async Task<WorkflowResult<SuspiciousServiceReport>> FindHiddenServicesAsync(
        string imageFile, params string[] suspiciousPathFragments)
    {
        if (suspiciousPathFragments.Length == 0)
            suspiciousPathFragments = [@"\temp\", @"\appdata\", @"\users\"];

        using var op = Begin("Finding services with suspicious binary paths in {0}", imageFile);

        // Pool-tag service scan: surfaces every service, including hidden/deleted/not-yet-loaded ones.
        var services = await MemoryAnalysis.WindowsSvcScanAsync(imageFile);
        if (services is null)
            return WorkflowResult<SuspiciousServiceReport>.Failure(
                $"windows.svcscan failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        // A service is suspicious when its binary (ImagePath, from memory or the registry) or hosting DLL lives
        // in a directory legitimate Windows services do not use.
        bool Suspicious(string? path) =>
            path is not null && suspiciousPathFragments.Any(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));
        var suspicious = services
            .Where(s => Suspicious(s.Binary) || Suspicious(s.BinaryRegistry) || Suspicious(s.Dll))
            .ToArray();

        op.Complete();
        return WorkflowResult<SuspiciousServiceReport>.Success(
            new SuspiciousServiceReport(suspicious, services.Length),
            suspicious.Length == 0
                ? $"No services with suspicious binary paths among {services.Length} scanned."
                : $"Found {suspicious.Length} service(s) with suspicious binary paths: " +
                  string.Join(", ", suspicious.Select(s => $"{s.Name} ({s.Binary ?? s.BinaryRegistry ?? s.Dll})")) + ".");
    }

    /// <summary>
    /// Scans a Windows memory image for code-injection and process-hollowing indicators with
    /// <c>windows.malfind</c>, which reports private, executable memory regions that no file on disk backs.
    /// Among those hits it flags the two indicators the methodology calls out: regions beginning with an
    /// <c>MZ</c>/PE header (an executable image injected into memory — the classic hollowing / PE-injection
    /// sign) and regions with read-write-execute protection (the classic shellcode-injection sign). malfind
    /// has a high false-positive rate (JIT, .NET CLR), so the returned hits are leads to triage, not verdicts.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    /// <param name="dumpProcessDir">If set, each anomalous process's executable (PE) image is dumped to this
    /// directory on the workstation for downstream triage; the resulting paths are returned in the report.</param>
    /// <param name="dumpMemoryDir">If set, each anomalous process's mapped memory is dumped to this directory
    /// on the workstation; the resulting paths are returned in the report.</param>
    /// <param name="dumpStringsDir">If set <em>and</em> <paramref name="dumpMemoryDir"/> is also set, ASCII and
    /// Unicode strings (min 8 chars, to reduce noise) are extracted from each dumped memory image into this
    /// directory; the resulting paths are returned in the report. Ignored without a memory dump to read from.</param>
    public async Task<WorkflowResult<AnomalousMemoryReport>> FindAnomalousMemoryIndicatorsAsync(
        string imageFile, string? dumpProcessDir = null, string? dumpMemoryDir = null, string? dumpStringsDir = null)
    {
        using var op = Begin("Finding process-hollowing indicators in {0}", imageFile);

        var hits = await MemoryAnalysis.WindowsMalFindAsync(imageFile);
        if (hits is null)
            return WorkflowResult<AnomalousMemoryReport>.Failure(
                $"windows.malfind failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        // Every malfind hit is already a private, executable region with no file backing. Split out the two
        // strongest indicators: an MZ/PE header at the start (image injected => hollowing) and read-write-
        // execute protection (writable code => shellcode). A region can be both.
        var mz = hits.Where(HasMzHeader).ToArray();
        var rwx = hits.Where(h => IsReadWriteExecute(h.Protection)).ToArray();

        // Optionally extract each anomalous process (every distinct PID malfind flagged) for downstream triage.
        var anomalousPids = hits.Select(h => h.PID).Distinct().ToArray();
        var dumpedExe = dumpProcessDir is null ? []
            : await DumpEachAsync(imageFile, anomalousPids, dumpProcessDir, MemoryAnalysis.DumpProcessExecutableAsync);
        var dumpedMem = dumpMemoryDir is null ? []
            : await DumpEachAsync(imageFile, anomalousPids, dumpMemoryDir, MemoryAnalysis.DumpProcessMemoryAsync);

        // When both a memory dump and a strings directory are requested, extract ASCII + Unicode strings from
        // each dumped memory image for IOC hunting (requires the memory dumps to read from).
        var extractedStrings = dumpStringsDir is not null && dumpMemoryDir is not null
            ? await ExtractStringsFromDumpsAsync(dumpedMem, dumpStringsDir)
            : [];

        op.Complete();
        var flagged = mz.Concat(rwx).Select(h => $"{h.Process} (PID {h.PID})").Distinct().ToArray();
        var dumpNote = dumpProcessDir is null && dumpMemoryDir is null ? ""
            : $" Dumped {dumpedExe.Length} executable(s) and {dumpedMem.Length} memory image(s) for {anomalousPids.Length} process(es).";
        if (extractedStrings.Length > 0)
            dumpNote += $" Extracted {extractedStrings.Length} strings file(s).";
        return WorkflowResult<AnomalousMemoryReport>.Success(
            new AnomalousMemoryReport(mz, rwx, hits)
            {
                DumpedExecutables = dumpedExe,
                DumpedProcessMemory = dumpedMem,
                ExtractedStrings = extractedStrings,
            },
            (flagged.Length == 0
                ? $"No hollowing/injection indicators among {hits.Length} malfind region(s)."
                : $"Found injection indicators across {hits.Length} malfind region(s): {mz.Length} MZ/PE-headed " +
                  $"(hollowing) and {rwx.Length} RWX (shellcode), in: {string.Join(", ", flagged)}.") + dumpNote);
    }

    /// <summary>
    /// Collects every unique remote IP address a Windows memory image's network connections reference, for IOC
    /// pivoting. Uses <c>windows.netscan</c> (a pool-tag scan, so it recovers historical/closed connections as
    /// well as active ones at capture time), then de-duplicates the foreign addresses, excluding loopback,
    /// unspecified, and wildcard endpoints (127.0.0.1, ::1, 0.0.0.0, ::, *) that are not routable remotes.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    public async Task<WorkflowResult<RemoteIpReport>> FindAllUniqueRemoteIPsAsync(string imageFile)
    {
        using var op = Begin("Finding unique remote IPs in {0}", imageFile);

        // Pool-tag scan of network structures: includes closed/historical connections, not just active ones.
        var connections = await MemoryAnalysis.WindowsNetScanAsync(imageFile);
        if (connections is null)
            return WorkflowResult<RemoteIpReport>.Failure(
                $"windows.netscan failed for '{imageFile}'; the image may be unreadable, its symbols unavailable, or the OS version unsupported.");

        var remoteIPs = connections
            .Select(c => c.ForeignAddr)
            .Where(IsRoutableRemote)
            .Distinct()
            .OrderBy(ip => ip, StringComparer.Ordinal)
            .ToArray();

        op.Complete();
        return WorkflowResult<RemoteIpReport>.Success(
            new RemoteIpReport(remoteIPs, connections),
            remoteIPs.Length == 0
                ? $"No remote IPs among {connections.Length} netscan connection(s)."
                : $"Found {remoteIPs.Length} unique remote IP(s) across {connections.Length} netscan connection(s): {string.Join(", ", remoteIPs)}.");
    }

    /// <summary>
    /// Extracts the credential material an attacker could harvest from a Windows memory image: local account
    /// NTLM hashes from the SAM (<c>windows.hashdump</c>), LSA secrets (<c>windows.lsadump</c>) — decoding any
    /// that are plaintext (service-account passwords, the DefaultPassword auto-logon value, …) — and cached
    /// domain credentials (<c>windows.cachedump</c>, mscash2). Use it to scope credential exposure: pivot the NT
    /// hashes for pass-the-hash, crack the cached creds, and read the plaintext secrets directly.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    public async Task<WorkflowResult<CredentialReport>> ExtractCredentialMaterialAsync(string imageFile)
    {
        using var op = Begin("Extracting credential material from {0}", imageFile);

        // SAM local-account hashes; if this fails the image is unreadable / its symbols are unavailable.
        var hashes = await MemoryAnalysis.WindowsHashdumpAsync(imageFile);
        if (hashes is null)
            return WorkflowResult<CredentialReport>.Failure(
                $"windows.hashdump failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        var lsa = await MemoryAnalysis.WindowsLsadumpAsync(imageFile) ?? [];
        var cached = await MemoryAnalysis.WindowsCachedumpAsync(imageFile) ?? [];

        // Decode each LSA secret's bytes; plaintext secrets (e.g. UTF-16 passwords) surface, key material doesn't.
        var secrets = lsa.Select(s => new LsaSecret { Key = s.Key, Hex = s.Hex ?? s.Secret, DecodedText = DecodeSecret(s.Hex ?? s.Secret) }).ToArray();

        op.Complete();
        var report = new CredentialReport { LocalHashes = hashes, LsaSecrets = secrets, CachedCredentials = cached };
        return WorkflowResult<CredentialReport>.Success(report,
            $"Recovered {hashes.Length} local hash(es), {secrets.Length} LSA secret(s) ({report.PlaintextSecrets.Length} plaintext), " +
            $"and {cached.Length} cached domain credential(s) from '{imageFile}'.");
    }

    // Decodes an LSA-secret hex byte string ("76 00 46 00 ...") to UTF-16 text, returning it only when the
    // result is fully printable (a real plaintext secret); binary key material returns null.
    static string? DecodeSecret(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex)) return null;
        try
        {
            var bytes = hex.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(b => Convert.ToByte(b, 16)).ToArray();
            if (bytes.Length == 0) return null;
            var text = System.Text.Encoding.Unicode.GetString(bytes).TrimEnd('\0');
            return text.Length > 0 && text.All(c => !char.IsControl(c) || c is '\t' or '\n' or '\r') ? text : null;
        }
        catch { return null; }
    }

    // A foreign address is a routable remote endpoint when it isn't blank, loopback, unspecified, or a wildcard.
    static bool IsRoutableRemote(string? addr) =>
        !string.IsNullOrWhiteSpace(addr) && addr is not ("0.0.0.0" or "127.0.0.1" or "::" or "::1" or "*");

    /// <summary>
    /// Generates a timeline of all artifacts in a Windows memory image and writes it to
    /// <paramref name="timelineOutputPath"/> on the workstation. Runs <c>timeliner --create-bodyfile</c> to
    /// produce a mactime bodyfile of every timestamped artifact Volatility can find (processes, threads,
    /// handles, network sockets, registry keys, …), then sorts it into a timeline with <c>mactime</c> (UTC).
    /// The intermediate bodyfile is written alongside the timeline and returned for re-rendering with filters.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    /// <param name="timelineOutputPath">Workstation path to write the sorted timeline file to.</param>
    public async Task<WorkflowResult<MemoryTimeline>> GenerateTimelineAsync(string imageFile, string timelineOutputPath)
    {
        using var op = Begin("Generating memory timeline for {0} -> {1}", imageFile, timelineOutputPath);

        // The bodyfile (volatility.body) is written into the timeline's directory — which also ensures that
        // directory exists for the subsequent mactime output.
        int slash = timelineOutputPath.LastIndexOf('/');
        string outputDir = slash switch { > 0 => timelineOutputPath[..slash], 0 => "/", _ => "." };

        var bodyfile = await MemoryAnalysis.TimelinerBodyfileAsync(imageFile, outputDir);
        if (bodyfile is null)
            return WorkflowResult<MemoryTimeline>.Failure(
                $"timeliner failed to create a bodyfile for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        if (!await DiskAnalysis.MactimeToFileAsync(bodyfile, timelineOutputPath))
            return WorkflowResult<MemoryTimeline>.Failure(
                $"mactime failed to render the timeline from bodyfile '{bodyfile}'.");

        op.Complete();
        return WorkflowResult<MemoryTimeline>.Success(
            new MemoryTimeline(timelineOutputPath, bodyfile),
            $"Memory timeline written to '{timelineOutputPath}' (bodyfile: '{bodyfile}').");
    }

    // Dumps each PID via the given toolkit dump method into dir, collecting the produced file paths.
    static async Task<string[]> DumpEachAsync(string imageFile, int[] pids, string dir,
        Func<string, int, string, Task<string[]?>> dump)
    {
        var paths = new List<string>();
        foreach (var pid in pids)
            if (await dump(imageFile, pid, dir) is { } files)
                paths.AddRange(files);
        return paths.ToArray();
    }

    // Extracts ASCII and Unicode strings (min 8 chars) from each dumped memory image into stringsDir,
    // returning the per-process strings files produced (named strings_<dump>_ascii.txt / _unicode.txt).
    async Task<string[]> ExtractStringsFromDumpsAsync(string[] memoryDumps, string stringsDir)
    {
        var outputs = new List<string>();
        foreach (var dump in memoryDumps)
        {
            var stem = System.IO.Path.GetFileNameWithoutExtension(dump);
            var ascii = $"{stringsDir.TrimEnd('/')}/strings_{stem}_ascii.txt";
            var unicode = $"{stringsDir.TrimEnd('/')}/strings_{stem}_unicode.txt";
            if (await MemoryAnalysis.ExtractStringsAsync(dump, ascii, unicode: false)) outputs.Add(ascii);
            if (await MemoryAnalysis.ExtractStringsAsync(dump, unicode, unicode: true)) outputs.Add(unicode);
        }
        return outputs.ToArray();
    }

    // A malfind region carries an injected PE image when malfind tagged it with an MZ header, or its dumped
    // bytes begin with the "MZ" signature (4d 5a).
    static bool HasMzHeader(WindowsMalFind hit) =>
        (hit.Notes is not null && hit.Notes.Contains("MZ", StringComparison.OrdinalIgnoreCase)) ||
        hit.Hexdump.TrimStart().StartsWith("4d 5a", StringComparison.OrdinalIgnoreCase);

    // RWX = simultaneously writable and executable (e.g. PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY).
    static bool IsReadWriteExecute(string protection) =>
        protection.Contains("EXECUTE", StringComparison.OrdinalIgnoreCase) &&
        protection.Contains("WRITE", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Hunts code injection in a Windows memory image by merging three orthogonal Volatility signals from the
    /// FOR508.3 methodology's Step 4: <c>windows.ldrmodules</c> (DLLs visible in the VAD tree but missing from
    /// one or more PEB doubly-linked lists, or with no <c>MappedPath</c> — the reflective-DLL / unlinked-DLL
    /// indicator), <c>windows.hollowprocesses</c> (PEB image base disagrees with the VAD or on-disk image —
    /// process hollowing), and <c>windows.malfind</c> (private, executable regions with no file backing — MZ-
    /// headed = injected image, RWX = shellcode), via <see cref="FindAnomalousMemoryIndicatorsAsync"/>. The
    /// report aggregates suspect PIDs and ranks them by total signal count across the three sources.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    public async Task<WorkflowResult<CodeInjectionReport>> FindCodeInjectionAsync(string imageFile)
    {
        using var op = Begin("Hunting code injection in {0}", imageFile);

        // The three injection signals are independent plugins, so run them concurrently (the environment's
        // limiter bounds total fan-out). (1) Per-process PEB↔VAD DLL list comparison: an entry with no
        // MappedPath, or absent from one of the three PEB lists despite being in VAD, signals injection /
        // unlinking — process executables are legitimately absent from InInit (svchost.exe etc.) so we exclude
        // that single-flag case. (2) Per-process PEB-vs-VAD-vs-disk image-base check (empty on clean images).
        // (3) The malfind workflow (private executable regions with no file backing).
        var ldrTask = MemoryAnalysis.WindowsLdrModulesAsync(imageFile);
        var hollowTask = MemoryAnalysis.WindowsHollowProcessesAsync(imageFile);
        var malfindTask = FindAnomalousMemoryIndicatorsAsync(imageFile);
        await Task.WhenAll(ldrTask, hollowTask, malfindTask);

        var ldr = ldrTask.Result;
        if (ldr is null)
            return WorkflowResult<CodeInjectionReport>.Failure(
                $"windows.ldrmodules failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");
        var unlinked = ldr.Where(IsLdrUnlinked).ToArray();
        var hollow = hollowTask.Result ?? [];
        var malfind = malfindTask.Result;
        if (!malfind.IsSuccess)
            return WorkflowResult<CodeInjectionReport>.Failure(malfind.Message ?? "windows.malfind failed.");

        op.Complete();
        var report = new CodeInjectionReport
        {
            UnlinkedDlls = unlinked,
            HollowedProcesses = hollow,
            AnomalousRegions = malfind.Result!,
        };
        return WorkflowResult<CodeInjectionReport>.Success(report,
            $"Hunted code injection across {ldr.Length} DLL mapping(s): {unlinked.Length} unlinked/orphan, " +
            $"{hollow.Length} hollowed process(es), {report.AnomalousRegions.SuspectRegions.Length} malfind region(s); " +
            $"{report.SuspectPids.Length} suspect PID(s).");
    }

    // ldrmodules flags injection when a DLL has no MappedPath (loaded outside the Windows API — reflective)
    // OR is unlinked from all three PEB lists despite being present in VAD. Excludes the legitimate case of a
    // process executable being absent only from InInit.
    static bool IsLdrUnlinked(WindowsLdrModules m) =>
        string.IsNullOrEmpty(m.MappedPath) || (!m.InLoad && !m.InInit && !m.InMem);

    /// <summary>
    /// Hunts kernel rootkit hooks in a Windows memory image by walking the three kernel hooking surfaces
    /// FOR508.3 Step 5 calls out: the System Service Descriptor Table (<c>windows.ssdt</c>), the registered
    /// kernel callbacks (<c>windows.callbacks</c> — image/thread/process/registry notify routines and
    /// Bug-check callbacks), and the per-driver IRP major-function tables (<c>windows.driverirp</c>). Entries
    /// owned by the canonical Microsoft kernel modules (<c>ntoskrnl</c>, <c>win32k</c>, <c>hal</c>) are
    /// filtered out as legitimate; what's left is rootkit, EDR, or third-party AV hooking — leads to triage.
    /// IRP entries are kept only when the implementation module differs from the driver that owns the table.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    public async Task<WorkflowResult<KernelRootkitReport>> DetectKernelRootkitAsync(string imageFile)
    {
        using var op = Begin("Detecting kernel rootkit hooks in {0}", imageFile);

        // The three hooking surfaces are independent plugins — fan them out concurrently (the environment's
        // limiter bounds total fan-out).
        var ssdtTask = MemoryAnalysis.WindowsSsdtAsync(imageFile);
        var callbacksTask = MemoryAnalysis.WindowsCallbacksAsync(imageFile);
        var driverIrpTask = MemoryAnalysis.WindowsDriverIrpAsync(imageFile);
        await Task.WhenAll(ssdtTask, callbacksTask, driverIrpTask);

        var ssdt = ssdtTask.Result;
        if (ssdt is null)
            return WorkflowResult<KernelRootkitReport>.Failure(
                $"windows.ssdt failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");
        var callbacks = callbacksTask.Result ?? [];
        var driverIrp = driverIrpTask.Result ?? [];

        var ssdtHooks = ssdt.Where(e => !IsCanonicalKernelModule(e.Module)).Select(e => new KernelHook
        {
            HookSurface = "SSDT",
            Target = e.Symbol ?? $"index {e.Index}",
            Module = e.Module,
            Symbol = e.Symbol,
            Address = e.Address,
        });
        var cbHooks = callbacks.Where(c => !IsCanonicalKernelModule(c.Module)).Select(c => new KernelHook
        {
            HookSurface = "Callback",
            Target = c.Type,
            Module = c.Module,
            Symbol = c.Symbol,
            Address = c.Callback,
        });
        // An IRP entry is a hook when its implementation module is neither ntoskrnl nor the driver itself.
        var irpHooks = driverIrp.Where(e => !IsCanonicalKernelModule(e.Module)
                && !string.Equals(e.Module, e.DriverName, StringComparison.OrdinalIgnoreCase))
            .Select(e => new KernelHook
            {
                HookSurface = "IRP",
                Target = $"{e.DriverName}.{e.IRP}",
                Module = e.Module,
                Symbol = e.Symbol,
                Address = e.Address,
            });

        var hooks = ssdtHooks.Concat(cbHooks).Concat(irpHooks).ToArray();
        op.Complete();
        var report = new KernelRootkitReport
        {
            Hooks = hooks,
            SsdtScanned = ssdt.Length,
            CallbacksScanned = callbacks.Length,
            DriverIrpScanned = driverIrp.Length,
        };
        return WorkflowResult<KernelRootkitReport>.Success(report,
            hooks.Length == 0
                ? $"No foreign-module hooks across {ssdt.Length} SSDT entries, {callbacks.Length} callbacks, {driverIrp.Length} IRP entries."
                : $"Found {hooks.Length} foreign-module hook(s) across SSDT/callbacks/IRP from {report.ForeignModules.Length} module(s): " +
                  string.Join(", ", report.ForeignModules.Take(5).Select(m => $"{m.Module}×{m.HookCount}")) + ".");
    }

    // The canonical kernel modules that legitimately own SSDT entries, callbacks, and IRP routines.
    static bool IsCanonicalKernelModule(string? module) =>
        module is not null && (
            module.Equals("ntoskrnl", StringComparison.OrdinalIgnoreCase) ||
            module.Equals("win32k", StringComparison.OrdinalIgnoreCase) ||
            module.Equals("hal", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Cross-view hidden-process scan via <c>windows.psxview</c>, the canonical FOR508.3 Step 5 detector. The
    /// plugin reports each process viewed by four enumeration sources (pslist, psscan, thrdscan, csrss); a
    /// process visible in some but not others — beyond the legitimate "exited but not yet freed" case — is
    /// the cross-view hidden-process indicator. Sightings still flagged as hidden are: any process missing
    /// from <c>psscan</c> (a hidden process should not survive pool scanning), or any still-running process
    /// (no exit time) missing from <c>pslist</c> (an unlinked EPROCESS — the DKOM signature).
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    public async Task<WorkflowResult<CrossViewHiddenProcessReport>> CrossViewHiddenProcessAsync(string imageFile)
    {
        using var op = Begin("Cross-view hidden-process scan in {0}", imageFile);

        var rows = await MemoryAnalysis.WindowsPsxViewAsync(imageFile);
        if (rows is null)
            return WorkflowResult<CrossViewHiddenProcessReport>.Failure(
                $"windows.psxview failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        var sightings = rows.Select(r => new HiddenProcessSighting
        {
            Pid = r.PID,
            Name = r.Name,
            ExitTime = r.ExitTime,
            PsList = r.PsList,
            PsScan = r.PsScan,
            ThrdScan = r.ThrdScan,
            Csrss = r.Csrss,
        }).ToArray();

        var hidden = sightings.Where(s => !s.PsScan || (!s.HasExited && !s.PsList)).ToArray();

        op.Complete();
        var report = new CrossViewHiddenProcessReport { AllSightings = sightings, HiddenSightings = hidden };
        return WorkflowResult<CrossViewHiddenProcessReport>.Success(report,
            hidden.Length == 0
                ? $"No cross-view hidden processes among {sightings.Length} sighting(s)."
                : $"Found {hidden.Length} hidden-process sighting(s) across {sightings.Length} scanned: " +
                  string.Join(", ", hidden.Take(10).Select(h => $"{h.Name} (PID {h.Pid}, missed by {string.Join("/", h.MissedBy)})")) + ".");
    }

    /// <summary>
    /// Reconstructs interactive-attacker console activity from a Windows memory image — the FOR508.3 Step 6
    /// "what did they type" question. Merges <c>windows.cmdscan</c> (typed command lines from
    /// <c>COMMAND_HISTORY</c> buffers) with <c>windows.consoles</c> (the broader <c>CONSOLE_INFORMATION</c>
    /// buffers that capture typed commands plus the output the console wrote back). Returns one
    /// <see cref="ConsoleSession"/> per (PID, console process) plus the flattened command list.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    public async Task<WorkflowResult<ConsoleHistoryReport>> ReconstructConsoleHistoryAsync(string imageFile)
    {
        using var op = Begin("Reconstructing console history from {0}", imageFile);

        var cmd = await MemoryAnalysis.WindowsCmdScanAsync(imageFile);
        if (cmd is null)
            return WorkflowResult<ConsoleHistoryReport>.Failure(
                $"windows.cmdscan failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");
        var consoles = await MemoryAnalysis.WindowsConsolesAsync(imageFile) ?? [];

        // Aggregate per (PID, process). cmdscan provides typed lines via Cmd; consoles provides screen-buffer Data.
        var byPid = cmd.Select(c => (c.PID, c.Process, App: c.Application, Cmd: c.Cmd, Data: (string?)null))
            .Concat(consoles.Select(c => (c.PID, c.Process, App: c.ConsoleProcess, Cmd: c.Cmd, Data: c.Data)))
            .GroupBy(r => (r.PID, r.Process));

        var sessions = byPid.Select(g =>
        {
            var typed = g.Select(r => r.Cmd).Where(s => !string.IsNullOrWhiteSpace(s))
                .SelectMany(s => s!.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Where(line => !string.IsNullOrWhiteSpace(line))
                .ToArray();
            var output = string.Join('\n', g.Select(r => r.Data).Where(s => !string.IsNullOrWhiteSpace(s))!);
            return new ConsoleSession
            {
                Pid = g.Key.PID,
                Process = g.Key.Process,
                Application = g.Select(r => r.App).FirstOrDefault(a => !string.IsNullOrEmpty(a)),
                TypedCommands = typed,
                ScreenOutput = string.IsNullOrEmpty(output) ? null : output,
            };
        }).ToArray();

        var typedCommands = sessions
            .SelectMany(s => s.TypedCommands.Select(c => new TypedCommand { Pid = s.Pid, Process = s.Process, Command = c }))
            .ToArray();

        op.Complete();
        var report = new ConsoleHistoryReport { ConsoleSessions = sessions, TypedCommands = typedCommands };
        return WorkflowResult<ConsoleHistoryReport>.Success(report,
            typedCommands.Length == 0 && sessions.Length == 0
                ? "No console history recovered (no cmdscan/consoles buffers found)."
                : $"Recovered {sessions.Length} console session(s), {typedCommands.Length} typed command(s) " +
                  $"({cmd.Length} cmdscan buffer(s), {consoles.Length} consoles buffer(s)).");
    }

    /// <summary>
    /// Scans every process's VAD regions in a Windows memory image against the YARA rules at
    /// <paramref name="yaraRulesFile"/> (<c>windows.vadyarascan</c>) — the FOR508.3 IOC/scaling layer.
    /// Use this with a curated rule pack to triage at scale (Mandiant Capa, the YARA-rules community
    /// repository, family-specific rules from previous engagements, etc.). The result groups matches per
    /// rule and per process for fast triage.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to scan.</param>
    /// <param name="yaraRulesFile">Workstation path to a YARA rules file (compiled or source).</param>
    /// <param name="pid">Optional: limit the scan to one process.</param>
    /// <param name="wide">When true, also match UTF-16 strings (YARA <c>wide</c> modifier).</param>
    public async Task<WorkflowResult<MemoryYaraReport>> ScanMemoryWithYaraAsync(
        string imageFile, string yaraRulesFile, int? pid = null, bool wide = false)
    {
        using var op = Begin("YARA-scanning {0} with rules {1}", imageFile, yaraRulesFile);

        var matches = await MemoryAnalysis.WindowsVadYaraScanAsync(imageFile, yaraRulesFile, pid, wide);
        if (matches is null)
            return WorkflowResult<MemoryYaraReport>.Failure(
                $"windows.vadyarascan failed for '{imageFile}' with rules '{yaraRulesFile}'; check the rules file and image.");

        op.Complete();
        var report = new MemoryYaraReport { Matches = matches, RulesFile = yaraRulesFile };
        return WorkflowResult<MemoryYaraReport>.Success(report,
            matches.Length == 0
                ? $"No YARA matches in '{imageFile}' for rules '{yaraRulesFile}'."
                : $"Found {matches.Length} YARA match(es) across {report.MatchesByRule.Length} rule(s) " +
                  $"and {report.MatchesByProcess.Length} process(es): top rules — " +
                  string.Join(", ", report.MatchesByRule.Take(5).Select(r => $"{r.Rule}×{r.Count}")) + ".");
    }

    /// <summary>
    /// DC-only: detects a Skeleton Key implant in LSASS by running <c>windows.skeleton_key_check</c>. Empty
    /// result = clean. The plugin flags a patched <c>CDLocateCSystem</c>, the canonical implant signature
    /// that lets the attacker authenticate as any AD user with a master password.
    /// </summary>
    /// <param name="imageFile">Path to a Domain Controller's memory image.</param>
    public async Task<WorkflowResult<SkeletonKeyReport>> DetectSkeletonKeyAsync(string imageFile)
    {
        using var op = Begin("Checking {0} for Skeleton Key", imageFile);

        var findings = await MemoryAnalysis.WindowsSkeletonKeyCheckAsync(imageFile);
        if (findings is null)
            return WorkflowResult<SkeletonKeyReport>.Failure(
                $"windows.skeleton_key_check failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        op.Complete();
        var report = new SkeletonKeyReport { Findings = findings };
        return WorkflowResult<SkeletonKeyReport>.Success(report,
            report.IsCompromised
                ? $"SKELETON KEY DETECTED in '{imageFile}' — patched CDLocateCSystem in LSASS."
                : $"No Skeleton Key implant detected in '{imageFile}'.");
    }

    /// <summary>
    /// Runs the six-step "Finding the First Hit" memory-analysis methodology (FOR508.3) end-to-end against a
    /// Windows memory image, orchestrating the lower-level workflows and correlating their findings into a
    /// single ranked suspect list. The steps:
    /// <list type="number">
    /// <item><b>Identify rogue processes</b> — <see cref="CrossViewHiddenProcessAsync"/> (psxview cross-view).</item>
    /// <item><b>Analyze process DLLs and handles</b> — each suspect is enriched with its command line, owning
    /// SIDs, and orphan/unlinked DLLs (a per-process deep-dive, pulled in two image-wide plugin calls).</item>
    /// <item><b>Review network artifacts</b> — <see cref="FindAllUniqueRemoteIPsAsync"/>; a suspect's routable
    /// remote connections corroborate it (but network alone does not nominate, to keep browsers/updaters out).</item>
    /// <item><b>Look for code injection</b> — <see cref="FindCodeInjectionAsync"/> (unlinked DLLs + hollowing + malfind).</item>
    /// <item><b>Check for signs of a rootkit</b> — <see cref="DetectKernelRootkitAsync"/> (SSDT/callback/IRP hooks;
    /// module-level, reported alongside the per-process suspects rather than folded into them).</item>
    /// <item><b>Dump suspicious processes</b> — when <paramref name="dumpDir"/> is set, each high-confidence
    /// suspect's executable image is extracted; when <paramref name="yaraRulesFile"/> is set, the image is
    /// YARA-scanned. Both are optional and non-fatal.</item>
    /// </list>
    /// Steps 1 and 4 nominate per-process suspects; a process flagged by ≥2 independent steps is high-confidence
    /// — the "first hit". Suspects are ranked by distinct-category count, then raw signal count, then PID.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    /// <param name="dumpDir">Optional: when set, Step 6 extracts each high-confidence suspect's executable image
    /// to this workstation directory (falling back to the top 5 suspects if none are high-confidence).</param>
    /// <param name="yaraRulesFile">Optional: when set, Step 6 YARA-scans the image's VAD regions with these rules
    /// (a failed scan is recorded as a null <see cref="FindMalwareReport.YaraScan"/>, not a workflow failure).</param>
    public async Task<WorkflowResult<FindMalwareReport>> FindMalwareAsync(
        string imageFile, string? dumpDir = null, string? yaraRulesFile = null)
    {
        using var op = Begin("Finding malware (6-step memory analysis) in {0}", imageFile);

        // Steps 1/3/4/5 plus the Step-2 enrichment reads are independent — each only needs the image, none
        // consumes another's output — so fan them out concurrently rather than serializing ~10 sequential vol3
        // runs. The environment's concurrency limiter (MaxConcurrentExecutions) bounds the SSH channel fan-out,
        // and SSH.NET gives each command its own channel, so this is safe. A failure in any broad scan means the
        // image is unreadable / its symbols are unavailable, so the whole analysis fails (the message names it).
        var rogueTask = CrossViewHiddenProcessAsync(imageFile);
        var networkTask = FindAllUniqueRemoteIPsAsync(imageFile);
        var injectionTask = FindCodeInjectionAsync(imageFile);
        var rootkitTask = DetectKernelRootkitAsync(imageFile);
        var cmdlinesTask = MemoryAnalysis.WindowsCmdLineAsync(imageFile);
        var sidsTask = MemoryAnalysis.WindowsGetSidsAsync(imageFile);
        await Task.WhenAll(rogueTask, networkTask, injectionTask, rootkitTask, cmdlinesTask, sidsTask);

        var rogue = rogueTask.Result;
        if (!rogue.IsSuccess) return WorkflowResult<FindMalwareReport>.Failure(rogue.Message ?? "rogue-process scan failed.");
        var network = networkTask.Result;
        if (!network.IsSuccess) return WorkflowResult<FindMalwareReport>.Failure(network.Message ?? "network-artifact scan failed.");
        var injection = injectionTask.Result;
        if (!injection.IsSuccess) return WorkflowResult<FindMalwareReport>.Failure(injection.Message ?? "code-injection scan failed.");
        var rootkit = rootkitTask.Result;
        if (!rootkit.IsSuccess) return WorkflowResult<FindMalwareReport>.Failure(rootkit.Message ?? "rootkit scan failed.");

        // Step 2 enrichment data — pulled image-wide (cheaper than per-PID), indexed by PID below.
        var cmdlines = cmdlinesTask.Result ?? [];
        var sids = sidsTask.Result ?? [];

        var inj = injection.Result!;

        // Per-PID signal accumulator. Each Flag records a human-readable reason plus its methodology category;
        // a PID flagged across multiple categories is the cross-corroborated "first hit".
        var reasons = new Dictionary<int, List<string>>();
        var cats = new Dictionary<int, HashSet<string>>();
        var names = new Dictionary<int, string>();
        void Flag(int pid, string process, string category, string reason)
        {
            if (!reasons.TryGetValue(pid, out var list)) reasons[pid] = list = [];
            list.Add(reason);
            if (!cats.TryGetValue(pid, out var set)) cats[pid] = set = [];
            set.Add(category);
            if (!names.TryGetValue(pid, out var n) || string.IsNullOrEmpty(n)) names[pid] = process;
        }

        // Step 1 nominations: cross-view hidden processes.
        foreach (var h in rogue.Result!.HiddenSightings)
            Flag(h.Pid, h.Name, "rogue-process", $"rogue process: missed by {string.Join("/", h.MissedBy)} (cross-view)");

        // Step 4 nominations: each code-injection sub-signal, broken out per PID.
        foreach (var g in inj.UnlinkedDlls.GroupBy(u => u.PID))
            Flag(g.Key, g.First().Process, "code-injection", $"unlinked/orphan DLL ×{g.Count()}");
        foreach (var hp in inj.HollowedProcesses)
            Flag(hp.PID, hp.Process, "code-injection", $"process hollowing{(string.IsNullOrEmpty(hp.Notes) ? "" : $": {hp.Notes}")}");
        foreach (var g in inj.AnomalousRegions.MzHeaderRegions.GroupBy(r => r.PID))
            Flag(g.Key, g.First().Process, "code-injection", $"injected PE image (MZ) ×{g.Count()}");
        foreach (var g in inj.AnomalousRegions.RwxRegions.GroupBy(r => r.PID))
            Flag(g.Key, g.First().Process, "code-injection", $"RWX region (shellcode) ×{g.Count()}");

        // Enrichment indexes (Step 2 + Step 3 data), keyed by PID.
        var cmdByPid = cmdlines.GroupBy(c => c.PID).ToDictionary(g => g.Key, g => g.First().Args);
        var sidsByPid = sids.GroupBy(s => s.PID)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Name).Where(n => !string.IsNullOrEmpty(n)).Distinct().ToArray());
        var orphanByPid = inj.UnlinkedDlls.GroupBy(u => u.PID)
            .ToDictionary(g => g.Key, g => g.Select(u => string.IsNullOrEmpty(u.MappedPath) ? "<no MappedPath>" : u.MappedPath!).Distinct().ToArray());
        var connByPid = network.Result!.Connections
            .Where(c => c.PID is not null && IsRoutableRemote(c.ForeignAddr))
            .GroupBy(c => c.PID!.Value)
            .ToDictionary(g => g.Key, g => g.ToArray());

        // Step 3 corroboration: attach routable remote connections to already-nominated suspects only.
        foreach (var pid in reasons.Keys.ToArray())
            if (connByPid.GetValueOrDefault(pid, []) is { Length: > 0 } conns)
                Flag(pid, names.GetValueOrDefault(pid, ""), "network",
                    $"remote connection(s): {string.Join(", ", conns.Select(c => $"{c.ForeignAddr}:{c.ForeignPort}").Distinct().Take(3))}");

        var suspects = reasons.Select(kv => new MalwareSuspect
        {
            Pid = kv.Key,
            Process = names.GetValueOrDefault(kv.Key, ""),
            Categories = cats[kv.Key].OrderBy(c => c).ToArray(),
            Signals = kv.Value.ToArray(),
            CommandLine = cmdByPid.GetValueOrDefault(kv.Key),
            Sids = sidsByPid.GetValueOrDefault(kv.Key, []),
            OrphanDlls = orphanByPid.GetValueOrDefault(kv.Key, []),
            RemoteConnections = connByPid.GetValueOrDefault(kv.Key, []),
        })
        .OrderByDescending(s => s.Categories.Length)
        .ThenByDescending(s => s.SignalCount)
        .ThenBy(s => s.Pid)
        .ToArray();

        // Step 6 (optional): dump the high-confidence suspects' executables (fall back to the top 5 by rank).
        var dumpedAll = new List<string>();
        if (dumpDir is not null && suspects.Length > 0)
        {
            var targets = suspects.Where(s => s.IsHighConfidence).ToArray();
            if (targets.Length == 0) targets = suspects.Take(5).ToArray();
            var dumpedByPid = new Dictionary<int, string[]>();
            foreach (var s in targets)
            {
                var files = await MemoryAnalysis.DumpProcessExecutableAsync(imageFile, s.Pid, dumpDir) ?? [];
                dumpedByPid[s.Pid] = files;
                dumpedAll.AddRange(files);
            }
            suspects = suspects.Select(s => dumpedByPid.TryGetValue(s.Pid, out var f) ? s with { DumpedFiles = f } : s).ToArray();
        }

        // Step 6 (optional): YARA-scan the image. Non-fatal — a failure leaves YaraScan null.
        MemoryYaraReport? yara = null;
        if (yaraRulesFile is not null)
        {
            var y = await ScanMemoryWithYaraAsync(imageFile, yaraRulesFile);
            yara = y.IsSuccess ? y.Result : null;
        }

        op.Complete();
        var report = new FindMalwareReport
        {
            RogueProcesses = rogue.Result!,
            NetworkArtifacts = network.Result!,
            CodeInjection = inj,
            KernelRootkit = rootkit.Result!,
            Suspects = suspects,
            DumpedArtifacts = dumpedAll.ToArray(),
            YaraScan = yara,
        };
        var hi = report.HighConfidenceSuspects;
        var dumpNote = dumpDir is null ? "" : $" Dumped {dumpedAll.Count} executable(s).";
        var yaraNote = yara is null ? "" : $" YARA: {yara.Matches.Length} match(es).";
        return WorkflowResult<FindMalwareReport>.Success(report,
            $"6-step analysis of '{imageFile}': {suspects.Length} suspect process(es), {hi.Length} high-confidence " +
            $"(≥2 steps){(hi.Length == 0 ? "" : ": " + string.Join(", ", hi.Take(5).Select(s => $"{s.Process} (PID {s.Pid})")))}. " +
            $"Plus {rootkit.Result!.Hooks.Length} kernel hook(s) and {network.Result!.RemoteIPs.Length} remote IP(s)." +
            dumpNote + yaraNote);
    }
}
