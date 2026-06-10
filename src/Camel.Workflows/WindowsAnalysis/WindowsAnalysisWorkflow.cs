namespace Camel.Workflows;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Camel.Toolkits;
using Camel.Toolkits.Models;
using Camel.Workflows.Models;

public class WindowsAnalysisWorkflow : Workflow
{
    public WindowsAnalysisWorkflow(CamelApi api) : base(api) {}

    // The DFIR batch file the WindowsAnalysisToolkit constructor installs alongside RECmd.
    public const string DfirBatchFile = "/opt/zimmermantools/RECmd/DFIRBatch.reb";

    // The key forensic registry artifacts from the methodology, each matched by a distinctive (case-insensitive)
    // fragment of its registry key path — directly mirroring the reference's Key Registry Artifacts table.
    private static readonly (string Name, string KeyPathFragment)[] Artifacts =
    [
        ("Run/RunOnce",   @"currentversion\run"),
        ("UserAssist",    "userassist"),
        ("RecentDocs",    "recentdocs"),
        ("TypedPaths",    "typedpaths"),
        ("MRU Lists",     "mru"),
        ("BAM/DAM",       @"\bam\"),
        ("USBSTOR",       @"enum\usbstor"),
        ("USB VID/PID",   @"enum\usb\"),
        ("MountedDevices", "mounteddevices"),
        ("MountPoints2",  "mountpoints2"),
        ("Services",      @"\services\"),
        ("Shimcache",     "appcompatcache"),
        ("Timezone",      "timezoneinformation"),
        ("Computer name", @"computername\computername"),
        ("Last shutdown", @"control\windows"),
        ("Amcache programs", "inventoryapplicationfile"),
    ];

    /// <summary>
    /// Batch-parses every registry hive in <paramref name="hiveDirectory"/> with RECmd's DFIR batch file
    /// (which runs the whole community-maintained query collection in one pass) and buckets the results into
    /// the key forensic artifacts from the methodology — Run keys, UserAssist, RecentDocs, USBSTOR/USB,
    /// Shimcache, Services, Timezone, BAM, Amcache, and so on. Each artifact carries the matching
    /// <see cref="RegistryEntry"/> rows; an artifact is empty when the parsed hives don't contain it (e.g.
    /// UserAssist needs an NTUSER.DAT, Amcache needs Amcache.hve). The full RECmd output is also returned.
    /// </summary>
    /// <param name="hiveDirectory">Directory of extracted/mounted registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, …).</param>
    /// <param name="batchFile">RECmd batch file to use (defaults to the toolkit-installed DFIRBatch.reb).</param>
    public async Task<WorkflowResult<KeyArtifactsReport>> ExtractKeyArtifactsAsync(string hiveDirectory, string batchFile = DfirBatchFile)
    {
        using var op = Begin("Extracting key registry artifacts from {0}", hiveDirectory);

        var entries = await WindowsAnalysis.RECmdAsync(hiveDirectory, batchFile);
        if (entries is null)
            return WorkflowResult<KeyArtifactsReport>.Failure(
                $"RECmd batch parse failed for hive directory '{hiveDirectory}'; check the hives exist and the batch file '{batchFile}' is installed.");

        var buckets = Artifacts
            .Select(a => new KeyArtifact(a.Name,
                entries.Where(e => e.KeyPath is { } k && k.Contains(a.KeyPathFragment, StringComparison.OrdinalIgnoreCase)).ToArray()))
            .ToArray();

        op.Complete();
        int populated = buckets.Count(b => b.Entries.Length > 0);
        return WorkflowResult<KeyArtifactsReport>.Success(
            new KeyArtifactsReport(buckets, entries),
            $"Parsed {entries.Length} registry entries; populated {populated} of {buckets.Length} key artifact categories.");
    }

    /// <summary>
    /// Lists the executables Windows has recorded in the Application Compatibility Cache (Shimcache) from a
    /// SYSTEM hive, via AppCompatCacheParser. Shimcache presence confirms a file <em>existed</em> on disk (it
    /// does not by itself confirm execution on Win8+), making it a useful "known executables" inventory for
    /// triage and cross-referencing against the filesystem. By default the registry transaction logs are
    /// ignored (<c>--nl</c>) for speed, per the reference; pass <paramref name="ignoreTransactionLogs"/> = false
    /// to replay them when the hive is dirty.
    /// </summary>
    /// <param name="systemHive">Path to the SYSTEM hive (e.g. .../Windows/System32/config/SYSTEM).</param>
    /// <param name="ignoreTransactionLogs">Ignore registry transaction logs (<c>--nl</c>); default true (faster).</param>
    public async Task<WorkflowResult<ShimcacheEntry[]>> GetKnownExecutablesAsync(string systemHive, bool ignoreTransactionLogs = true)
    {
        using var op = Begin("Getting known executables (Shimcache) from {0}", systemHive);

        var entries = await WindowsAnalysis.AppCompatCacheParserAsync(systemHive, ignoreTransactionLogs);
        if (entries is null)
            return WorkflowResult<ShimcacheEntry[]>.Failure(
                $"AppCompatCacheParser failed for SYSTEM hive '{systemHive}'; check the hive exists and is a valid SYSTEM hive.");

        op.Complete();
        return WorkflowResult<ShimcacheEntry[]>.Success(entries,
            $"Found {entries.Length} known executable(s) in the Application Compatibility Cache (Shimcache).");
    }

    /// <summary>
    /// Lists the binaries recorded in Amcache (Amcache.hve) via AmcacheParser — each with its SHA-1 hash and
    /// first-seen/execution metadata, the strongest registry-based execution evidence. The SHA-1s are ready
    /// pivots for VirusTotal / threat-intel lookups. By default the registry transaction logs are replayed,
    /// which matters because Amcache.hve is frequently dirty (its latest records live only in the logs); pass
    /// <paramref name="ignoreTransactionLogs"/> = true (<c>--nl</c>) to skip them for speed on a clean hive.
    /// </summary>
    /// <param name="amcacheHive">Path to Amcache.hve (e.g. .../Windows/appcompat/Programs/Amcache.hve).</param>
    /// <param name="ignoreTransactionLogs">Ignore registry transaction logs (<c>--nl</c>); default false (replays logs).</param>
    public async Task<WorkflowResult<AmcacheEntry[]>> GetExecutedBinariesAsync(string amcacheHive, bool ignoreTransactionLogs = false)
    {
        using var op = Begin("Getting executed binaries (Amcache) from {0}", amcacheHive);

        var entries = await WindowsAnalysis.AmcacheParserAsync(amcacheHive, ignoreTransactionLogs);
        if (entries is null)
            return WorkflowResult<AmcacheEntry[]>.Failure(
                $"AmcacheParser failed for hive '{amcacheHive}'; check the hive exists and is a valid Amcache.hve.");

        op.Complete();
        return WorkflowResult<AmcacheEntry[]>.Success(entries,
            $"Found {entries.Length} binary record(s) in Amcache (with SHA-1 hashes for IOC pivoting).");
    }

    // WMI consumer/filter names that are benign-but-noisy (stock OS / vendor subscriptions), per the methodology's
    // false-positive list. Names are matched case-insensitively as substrings.
    private static readonly string[] DefaultWmiAllowlist =
        ["BVTFilter", "SCM Event Log Consumer", "SCM Event Log Filter", "TSLogonEvents.vbs", "TSLogonFilter",
         "RAevent.vbs", "RmAssistEventFilter", "KernCap.vbs", "WSCEAA.exe", "NTEventLogConsumer"];

    // The two consumer types the methodology says account for essentially all malicious WMI persistence.
    private static readonly string[] WmiAttackerConsumerTypes = ["CommandLineEventConsumer", "ActiveScriptEventConsumer"];

    /// <summary>
    /// Hunts WMI event-consumer persistence in a repository's <c>OBJECTS.DATA</c> (<paramref name="objectsDataPath"/>).
    /// WMI persistence binds an event filter (trigger) to an event consumer (action); the methodology focuses on
    /// the two consumer types attackers use — <c>CommandLineEventConsumer</c> and <c>ActiveScriptEventConsumer</c>.
    /// This recovers the subscriptions, drops the benign/noisy stock subscriptions via an allow-list, and flags the
    /// rest, decoding any encoded-PowerShell action to expose its real intent (e.g. a download cradle). Findings are
    /// leads to triage. DLL/registry persistence is covered by <see cref="FindPersistenceMechanismsAsync"/>.
    /// </summary>
    /// <param name="objectsDataPath">Path to the WMI repository file, <c>\Windows\System32\wbem\Repository\OBJECTS.DATA</c>.</param>
    /// <param name="allowlistNames">Consumer/filter name substrings to treat as benign. Defaults to the methodology's known-good list.</param>
    public async Task<WorkflowResult<WmiPersistenceReport>> FindWmiPersistenceAsync(
        string objectsDataPath, string[]? allowlistNames = null)
    {
        allowlistNames ??= DefaultWmiAllowlist;

        using var op = Begin("Hunting WMI event-consumer persistence in {0}", objectsDataPath);

        var subs = await WindowsAnalysis.WmiSubscriptionsAsync(objectsDataPath);
        if (subs is null)
            return WorkflowResult<WmiPersistenceReport>.Failure(
                $"Could not read the WMI repository '{objectsDataPath}'; expected \\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA.");

        // Only the attacker-favored consumer types are persistence leads; the stock built-in types are noise.
        var consumers = subs.Consumers.Where(c => WmiAttackerConsumerTypes.Contains(c.Type)).ToArray();
        bool Allowlisted(string? n) => n is not null && allowlistNames.Any(a => n.Contains(a, StringComparison.OrdinalIgnoreCase));

        var suspicious = new List<WmiPersistenceEntry>();
        foreach (var c in consumers)
        {
            var filter = subs.Bindings.FirstOrDefault(b => b.ConsumerName == c.Name)?.FilterName;
            if (Allowlisted(c.Name) || Allowlisted(filter)) continue;   // known-good subscription

            var decoded = c.Command is null ? null : DecodeEncodedPowerShell(c.Command);
            var reasons = new List<string> { $"{c.Type} is an attacker-favored persistence vector and is not allow-listed" };
            if (EncodedRegex.IsMatch($"{c.Command} {decoded}"))
                reasons.Add("encoded / obfuscated or remote-download payload");
            suspicious.Add(new WmiPersistenceEntry
            {
                Type = c.Type, Name = c.Name, Command = c.Command,
                DecodedCommand = decoded, FilterName = filter, Reasons = reasons.ToArray(),
            });
        }

        op.Complete();
        var report = new WmiPersistenceReport
        {
            SuspiciousConsumers = suspicious.ToArray(),
            Consumers = consumers,
            Bindings = subs.Bindings,
            Filters = subs.Filters,
        };
        return WorkflowResult<WmiPersistenceReport>.Success(report,
            suspicious.Count == 0
                ? $"No suspicious WMI consumers among {consumers.Length} CommandLine/ActiveScript consumer(s)."
                : $"Found {suspicious.Count} suspicious WMI consumer(s): " +
                  string.Join("; ", suspicious.Select(s =>
                      $"{s.Name} ({s.Type})" + (s.FilterName is not null ? $" <- filter '{s.FilterName}'" : ""))) + ".");
    }

    // PowerShell -EncodedCommand / -e / -ec payloads are base64 of a UTF-16LE string; decode to reveal the intent.
    private static readonly Regex EncodedPsRegex = new(@"-e(c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static string? DecodeEncodedPowerShell(string command)
    {
        var m = EncodedPsRegex.Match(command);
        if (!m.Success) return null;
        try { return System.Text.Encoding.Unicode.GetString(Convert.FromBase64String(m.Groups[2].Value)); }
        catch { return null; }
    }

    /// <summary>
    /// Hunts DLL-hijacking persistence on a mounted Windows volume (<paramref name="volumeRoot"/>, e.g. the
    /// directory an image is mounted at). DLL hijacking is a file-system artifact, so this looks for the two
    /// high-precision signals from the methodology: (1) a <c>\Windows</c>-root DLL that <em>shadows</em> a
    /// System32 DLL of the same name but differs from it — the classic search-order hijack of a Windows-folder
    /// binary (e.g. a malicious <c>ntshrui.dll</c> loaded by Explorer); and (2) DLLs dropped in transient/
    /// world-writable locations where DLLs never normally reside. Byte-identical \Windows-root copies and
    /// non-shadowing Windows-root DLLs (e.g. <c>twain_32.dll</c>) are not flagged. Phantom hijacks and app-local
    /// side-loading (which need a known-good signature/hash baseline) are out of scope. Findings are leads.
    /// </summary>
    /// <param name="volumeRoot">The mounted volume root (its <c>Windows</c> folder and transient dirs are scanned).</param>
    /// <param name="transientDllDirs">Directories that should not normally contain DLLs. Defaults to
    /// <c>\Windows\Temp</c>, <c>\Temp</c>, <c>\PerfLogs</c>, <c>\$Recycle.Bin</c> (user temp/AppData are excluded
    /// as too noisy). Paths are taken as-is when supplied.</param>
    public async Task<WorkflowResult<DllHijackReport>> FindDllHijackingAsync(string volumeRoot, string[]? transientDllDirs = null)
    {
        var root = volumeRoot.TrimEnd('/');
        var win = $"{root}/Windows";
        transientDllDirs ??= [$"{win}/Temp", $"{root}/Temp", $"{root}/temp", $"{root}/PerfLogs", $"{root}/$Recycle.Bin"];

        using var op = Begin("Hunting DLL hijacking on {0}", volumeRoot);

        // Build the set of genuine System32/SysWOW64 DLLs (name -> file), used to detect \Windows-root shadows.
        var systemDlls = (await DiskAnalysis.FindFilesAsync($"{win}/System32", "*.dll", maxDepth: 1))
            .Concat(await DiskAnalysis.FindFilesAsync($"{win}/SysWOW64", "*.dll", maxDepth: 1))
            .GroupBy(f => f.Name.ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.First());

        var findings = new List<DllHijackFinding>();

        // (1) Search-order shadows: a DLL in the Windows folder root that impersonates a System32 DLL but differs.
        var rootDlls = await DiskAnalysis.FindFilesAsync(win, "*.dll", maxDepth: 1);
        int scanned = rootDlls.Length;
        foreach (var dll in rootDlls)
        {
            if (!systemDlls.TryGetValue(dll.Name.ToLowerInvariant(), out var genuine)) continue; // not a shadow (e.g. twain_32.dll)
            if (!await DiffersFromAsync(dll, genuine)) continue;                                  // byte-identical copy => benign
            findings.Add(new DllHijackFinding
            {
                Path = dll.Path, Name = dll.Name, Size = dll.Size, Kind = "Search-order shadow",
                ShadowedSystemDll = genuine.Path,
                Reasons = [$"a DLL in the Windows folder shadows the System32 DLL '{dll.Name}' but differs from it (search-order hijack)"],
            });
        }

        // (2) DLLs in transient/world-writable locations (any name) — DLLs do not normally live here.
        foreach (var dir in transientDllDirs)
        {
            var dlls = await DiskAnalysis.FindFilesAsync(dir, "*.dll", maxDepth: 4);
            scanned += dlls.Length;
            findings.AddRange(dlls.Select(d => new DllHijackFinding
            {
                Path = d.Path, Name = d.Name, Size = d.Size, Kind = "Transient-location DLL",
                Reasons = [$"DLL found in a transient/world-writable location ('{dir}') where DLLs do not normally reside"],
            }));
        }

        op.Complete();
        var report = new DllHijackReport { Findings = findings.ToArray(), DllsScanned = scanned };
        return WorkflowResult<DllHijackReport>.Success(report,
            findings.Count == 0
                ? $"No DLL-hijacking indicators among {scanned} candidate DLL(s) examined."
                : $"Found {findings.Count} DLL-hijacking lead(s): " +
                  string.Join("; ", findings.Select(f => $"{f.Path} [{f.Kind}]")) + ".");
    }

    // Two filesystem files differ when their sizes differ, or (same size) their SHA-256 digests differ.
    private async Task<bool> DiffersFromAsync(FsFile a, FsFile b)
    {
        if (a.Size != b.Size) return true;
        var (ha, hb) = (await DiskAnalysis.Sha256Async(a.Path), await DiskAnalysis.Sha256Async(b.Path));
        return ha is null || hb is null || !ha.Equals(hb, StringComparison.OrdinalIgnoreCase);
    }

    // The persistence mechanism categories this workflow recovers, in report order. These mirror the
    // "Autorunsc Detection: Malware Persistence Mechanisms" methodology (minus DLL hijacking, which is a
    // file-system artifact, and WMI event consumers, which have their own workflow).
    public const string CatRunKeys = "Run Keys (Autostart)";
    public const string CatServices = "Services";
    public const string CatScheduledTasks = "Scheduled Tasks";
    public const string CatAppInitDlls = "AppInit DLLs";
    public const string CatShellCommands = "Shell Open Commands";
    private static readonly string[] CategoryOrder =
        [CatRunKeys, CatServices, CatScheduledTasks, CatAppInitDlls, CatShellCommands];

    // Directories legitimate persistence almost never executes from — the "common malware locations" from the
    // methodology, restricted to transient/world-writable paths that stay high-precision even for per-user Run
    // keys. (Bare \AppData\ is deliberately excluded: modern per-user software — OneDrive, Dashlane, Teams, … —
    // legitimately autostarts from there, so it is too noisy to flag by location alone. Pass it explicitly via
    // suspiciousPathFragments when hunting machine-level ASEPs where an AppData binary really is anomalous.)
    private static readonly string[] DefaultSuspiciousPaths =
        [@"\temp\", @"\tmp\", @"\users\public\", @"\$recycle", @"\recycler\", @"\perflogs\",
         @"\windows\fonts\", @"\windows\temp\", @"\windows\debug\", @"\programdata\temp\"];

    /// <summary>
    /// Hunts a Windows system's registry hives for malware-persistence mechanisms, using RegRipper's purpose-
    /// built AutoStart Extension Point plugins and classifying the results into the persistence categories from
    /// the methodology: Run/RunOnce keys (<c>run</c>, from SOFTWARE and any user NTUSER.DAT), Services
    /// (<c>svc</c>, from SYSTEM), Scheduled Tasks (<c>tasks</c> / TaskCache), AppInit_DLLs (<c>appinitdlls</c>),
    /// and shell open-command hijacks (<c>cmd_shell</c>). Each recovered entry is scored for suspicion against
    /// the common malware-location set and LOLBin/encoded-command indicators; the report exposes every entry
    /// (<see cref="PersistenceReport.AllEntries"/>) plus the flagged subset (<see cref="PersistenceReport.SuspiciousEntries"/>).
    /// DLL search-order hijacking (a file-system artifact) and WMI event consumers are out of scope here — they
    /// have their own workflows.
    /// </summary>
    /// <param name="softwareHive">Path to the SOFTWARE hive (Run keys, AppInit_DLLs, shell commands, TaskCache).</param>
    /// <param name="systemHive">Path to the SYSTEM hive (Services).</param>
    /// <param name="ntuserHive">Optional path to a user's NTUSER.DAT (per-user Run keys); omit to skip.</param>
    /// <param name="tasksDirectory">Optional path to the on-disk <c>\Windows\System32\Tasks</c> tree. When given,
    /// scheduled tasks are read from their XML definitions — recovering each task's action/command line, which the
    /// registry TaskCache does not store, so a task launching a binary from a suspicious location can be flagged.
    /// When omitted, scheduled tasks fall back to the TaskCache (existence only, no command).</param>
    /// <param name="suspiciousPathFragments">Path substrings (case-insensitive) that mark a command as running
    /// from a suspicious location. Defaults to the common user-writable/transient malware locations.</param>
    public async Task<WorkflowResult<PersistenceReport>> FindPersistenceMechanismsAsync(
        string softwareHive, string systemHive, string? ntuserHive = null,
        string? tasksDirectory = null, string[]? suspiciousPathFragments = null)
    {
        suspiciousPathFragments ??= DefaultSuspiciousPaths;

        using var op = Begin("Finding persistence mechanisms in {0} / {1}", softwareHive, systemHive);

        // Run each targeted ASEP plugin against the hive it reads. rip.pl is lenient (exits 0 even on a missing
        // hive, yielding no findings), so a null result means rip.pl itself could not run.
        var runSoftware = await WindowsAnalysis.RegRipperAsync(softwareHive, "run");
        var appInit = await WindowsAnalysis.RegRipperAsync(softwareHive, "appinitdlls");
        var cmdShell = await WindowsAnalysis.RegRipperAsync(softwareHive, "cmd_shell");
        var svc = await WindowsAnalysis.RegRipperAsync(systemHive, "svc");
        var runUser = ntuserHive is not null ? await WindowsAnalysis.RegRipperAsync(ntuserHive, "run") : null;

        if (runSoftware is null && svc is null)
            return WorkflowResult<PersistenceReport>.Failure(
                $"RegRipper could not run against '{softwareHive}' / '{systemHive}'; check the hive paths and that rip.pl is installed.");

        // Scheduled tasks: prefer the on-disk Task XML (which carries the action/command line) when a Tasks
        // directory is supplied; otherwise fall back to the registry TaskCache (existence only, no command).
        var taskEntries = tasksDirectory is not null
            ? (await WindowsAnalysis.ScheduledTasksAsync(tasksDirectory) ?? []).Select(MapXmlTask)
            : ParseTasks(await WindowsAnalysis.RegRipperAsync(softwareHive, "tasks"));

        // LOLBAS index for living-off-the-land detection (null-tolerant: scoring skips LOLBin checks if absent).
        var lolbas = await WindowsAnalysis.LoadLolbasAsync();

        // Parse each plugin's output into entries, then score every entry for suspicion.
        var entries = ParseAutostart(runSoftware, CatRunKeys)
            .Concat(ParseAutostart(runUser, CatRunKeys))
            .Concat(ParseServices(svc))
            .Concat(taskEntries)
            .Concat(ParseAutostart(appInit, CatAppInitDlls))
            .Concat(ParseAutostart(cmdShell, CatShellCommands))
            .Select(e => { var r = Score(e, suspiciousPathFragments, lolbas); return e with { Reasons = r, Suspicious = r.Length > 0 }; })
            .ToArray();

        // Bucket into the fixed category order so the report always has one mechanism per category.
        var mechanisms = CategoryOrder
            .Select(c => new PersistenceMechanism(c, entries.Where(e => e.Category == c).ToArray()))
            .ToArray();
        var report = new PersistenceReport(mechanisms);

        op.Complete();
        return WorkflowResult<PersistenceReport>.Success(report,
            report.SuspiciousEntries.Length == 0
                ? $"Enumerated {report.AllEntries.Length} persistence entr(ies) across {mechanisms.Length} mechanism categories; none scored suspicious."
                : $"Enumerated {report.AllEntries.Length} persistence entr(ies); {report.SuspiciousEntries.Length} scored suspicious: " +
                  string.Join(", ", report.SuspiciousEntries.Select(e => $"{e.Name} [{e.Category}]")) + ".");
    }

    // Parses the "key header / LastWrite Time / indented name-value" layout shared by the run, appinitdlls and
    // cmd_shell plugins. A non-indented path-like line sets the current key; indented lines under it are
    // emitted as entries (RegRipper renders the value as "name - value", "name : value" or "name: value").
    private static IEnumerable<PersistenceEntry> ParseAutostart(RegRipperResult? r, string category)
    {
        if (r is null) yield break;
        string? key = null, lastWrite = null;
        foreach (var raw in r.Lines)
        {
            if (raw.Trim().Length == 0) continue;
            if (char.IsWhiteSpace(raw[0]))
            {
                var (name, value) = SplitNameValue(raw.Trim());
                if (name is null) continue;
                yield return new PersistenceEntry
                {
                    Category = category, Hive = r.Hive, Plugin = r.Plugin, KeyPath = key,
                    Name = name, Command = value is "{blank}" ? null : value, LastWrite = lastWrite,
                };
            }
            else if (raw.StartsWith("LastWrite Time", StringComparison.OrdinalIgnoreCase))
                lastWrite = raw["LastWrite Time".Length..].Trim();
            else if (IsKeyHeader(raw))
            {
                key = raw.Trim();
                lastWrite = null;
            }
        }
    }

    // Parses the svc plugin's CSV block (Time,Name,DisplayName,ImagePath/ServiceDll,Type,Start,ObjectName),
    // which begins after the plugin banner; every service is a persistence-surface entry keyed by its image path.
    private static IEnumerable<PersistenceEntry> ParseServices(RegRipperResult? r)
    {
        if (r is null) yield break;
        int header = Array.FindIndex(r.Lines, l => l.StartsWith("Time,Name,", StringComparison.OrdinalIgnoreCase));
        if (header < 0) yield break;
        foreach (var row in Toolkit.ParseCsv(string.Join('\n', r.Lines.Skip(header))))
        {
            var name = (row.TryGetValue("Name", out var n) ? n : "").Trim();
            if (name.Length == 0) continue;
            var image = row.TryGetValue("ImagePath/ServiceDll", out var ip) && ip.Length > 0 ? ip : null;
            yield return new PersistenceEntry
            {
                Category = CatServices, Hive = r.Hive, Plugin = r.Plugin,
                KeyPath = $@"Services\{name}", Name = name, Command = image,
                LastWrite = row.TryGetValue("Time", out var t) && t.Length > 0 ? t : null,
            };
        }
    }

    // Parses the tasks plugin's block layout (Path:/URI :/Task Reg Time :), one entry per scheduled task. The
    // TaskCache subkey records the task's existence and registration time but not its action/command line — that
    // lives in the \Windows\System32\Tasks XML files (a file-system artifact), so Command is left null here.
    private static IEnumerable<PersistenceEntry> ParseTasks(RegRipperResult? r)
    {
        if (r is null) yield break;
        string? path = null, regTime = null;
        foreach (var raw in r.Lines)
        {
            var line = raw.Trim();
            if (line.StartsWith("Path:", StringComparison.OrdinalIgnoreCase))
            {
                if (path is not null) yield return TaskEntry(r, path, regTime);
                path = line["Path:".Length..].Trim();
                regTime = null;
            }
            else if (line.StartsWith("Task Reg Time", StringComparison.OrdinalIgnoreCase) && line.IndexOf(':') is var c && c >= 0)
                regTime = line[(c + 1)..].Trim();
        }
        if (path is not null) yield return TaskEntry(r, path, regTime);
    }

    private static PersistenceEntry TaskEntry(RegRipperResult r, string path, string? regTime) => new()
    {
        Category = CatScheduledTasks, Hive = r.Hive, Plugin = r.Plugin,
        KeyPath = @"TaskCache\Tasks", Name = path, Command = null, LastWrite = regTime,
    };

    // Maps a scheduled task parsed from its on-disk XML to a persistence entry, joining the Exec command and its
    // arguments into the command line that scoring inspects (so a task launching e.g. C:\Windows\Temp\1.bat is flagged).
    private static PersistenceEntry MapXmlTask(ScheduledTaskEntry t) => new()
    {
        Category = CatScheduledTasks, Hive = t.TaskFile, Plugin = "tasks-xml",
        KeyPath = t.Uri, Name = t.Uri ?? System.IO.Path.GetFileName(t.TaskFile),
        Command = t.Command is null ? null
            : string.IsNullOrEmpty(t.Arguments) ? t.Command : $"{t.Command} {t.Arguments}",
    };

    // Splits a RegRipper "name <sep> value" line, trying the separators its plugins use in priority order:
    // " - " (run), " : " (appinitdlls), then ": " (cmd_shell's "Cmd: ..."). Null name => not a value line.
    private static (string? name, string? value) SplitNameValue(string s)
    {
        foreach (var sep in new[] { " - ", " : ", ": " })
        {
            int i = s.IndexOf(sep, StringComparison.Ordinal);
            if (i > 0) return (s[..i].Trim(), s[(i + sep.Length)..].Trim());
        }
        return (null, null);
    }

    // A key-header line is a non-indented, path-like line (contains a backslash) that isn't one of RegRipper's
    // "<key> not found." / "<key> has no values|subkeys." status lines.
    private static bool IsKeyHeader(string line) =>
        line.Contains('\\') &&
        !line.TrimEnd().EndsWith("not found.", StringComparison.OrdinalIgnoreCase) &&
        !line.Contains(" has no ", StringComparison.OrdinalIgnoreCase);

    // High-confidence obfuscation/download indicators in a command line (encoded PowerShell, base64, remote fetch).
    private static readonly Regex EncodedRegex = new(
        @"(-enc\b|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,}|-w\s+hidden|-windowstyle\s+hidden|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|https?://)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Scores a persistence entry for suspicion, returning a reason per indicator. Only high-precision signals set
    // the verdict — a suspicious execution location, an obfuscated/download command line, a populated AppInit_DLLs
    // value, or a LOLBAS binary running from a non-canonical path (masquerading). A LOLBin in its expected
    // location is far too common on healthy systems to flag on its own (per the methodology's "LOLBins need
    // command-line context" caution), so that's only appended as context once something else already flagged it.
    private static string[] Score(PersistenceEntry e, string[] suspiciousPaths, LolbasReference? lolbas)
    {
        if (e.Command is not { } cmd) return [];   // nothing to score (e.g. a TaskCache entry with no action)

        var reasons = new List<string>();
        var hit = suspiciousPaths.FirstOrDefault(f => cmd.Contains(f, StringComparison.OrdinalIgnoreCase));
        if (hit is not null) reasons.Add($"executes from a suspicious location ('{hit.Trim('\\')}')");
        if (EncodedRegex.IsMatch(cmd)) reasons.Add("encoded / obfuscated or remote-download command line");
        // AppInit_DLLs forces a DLL into every GUI process; a non-empty value is itself the persistence risk.
        if (e.Category == CatAppInitDlls && e.Name.Equals("AppInit_DLLs", StringComparison.OrdinalIgnoreCase))
            reasons.Add("AppInit_DLLs is populated (loads a DLL into every GUI process)");

        // LOLBAS: inspect the program the command launches (its leading token).
        var program = ProgramToken(cmd);
        var bin = FileNameOf(program);
        if (lolbas is not null && lolbas.IsLolbin(bin))
        {
            if (HasDirectory(program) && !lolbas.IsCanonicalPath(bin, program))
                // Right name, wrong place: a known LOLBin invoked by full path from a non-canonical location.
                reasons.Add($"living-off-the-land binary '{bin}' runs from a non-canonical path (possible masquerading)");
            else if (reasons.Count > 0)
                reasons.Add($"invokes living-off-the-land binary '{bin}'");
        }
        return reasons.ToArray();
    }

    // The leading program token of a command line: the quoted path, or everything up to the first space.
    private static string ProgramToken(string command)
    {
        var c = command.TrimStart();
        if (c.StartsWith('"')) { int end = c.IndexOf('"', 1); return end > 0 ? c[1..end] : c[1..]; }
        int sp = c.IndexOf(' ');
        return sp > 0 ? c[..sp] : c;
    }

    // The file name (last path segment) of a program path, handling either slash style.
    private static string FileNameOf(string path)
    {
        var p = path.Replace('/', '\\');
        int i = p.LastIndexOf('\\');
        return i >= 0 ? p[(i + 1)..] : p;
    }

    // True when the program token specifies a directory (a full/relative path) rather than a bare binary name.
    private static bool HasDirectory(string program) => program.Contains('\\') || program.Contains('/');
}
