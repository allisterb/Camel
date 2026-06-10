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
}
