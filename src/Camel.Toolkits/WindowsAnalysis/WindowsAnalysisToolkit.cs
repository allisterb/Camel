namespace Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class WindowsAnalysisToolkit : Toolkit
{
    public WindowsAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("WindowsAnalysis", auditEnvironment, config) { }

    // The LOLBAS (Living Off the Land Binaries And Scripts) dataset, used by detection workflows to recognise
    // abusable system binaries and spot ones running from a non-canonical (masquerading) path.
    private const string LolbasPath = "/opt/zimmermantools/lolbas.json";

    /// <summary>
    /// Installs RECmd (the Eric Zimmerman registry batch parser) into <c>/opt/zimmermantools</c> when the
    /// latest SIFT image omits it, plus the DFIR batch file it relies on for batch-mode parsing, and the LOLBAS
    /// reference dataset used by the detection workflows. No-op for anything already present.
    /// </summary>
    protected override void InstallMissingTools()
    {
        InstallZimmermanTool("RECmd", "https://download.ericzimmermanstools.com/net9/RECmd.zip", "/opt/zimmermantools/RECmd/RECmd.dll");
        InstallFile("DFIRBatch.reb", "https://github.com/EricZimmerman/RECmd/raw/refs/heads/master/BatchExamples/DFIRBatch.reb", "/opt/zimmermantools/RECmd/DFIRBatch.reb");
        InstallFile("lolbas.json", "https://lolbas-project.github.io/api/lolbas.json", LolbasPath);
    }

    /// <summary>
    /// Loads the LOLBAS reference dataset (<c>lolbas.json</c>, installed by this toolkit) into a queryable
    /// <see cref="LolbasReference"/> index. Returns null if the dataset is unavailable or unparseable, so callers
    /// degrade gracefully (skip living-off-the-land checks) rather than fail.
    /// </summary>
    public async Task<LolbasReference?> LoadLolbasAsync()
    {
        var r = await auditEnvironment.ExecuteCommandAsync("cat", Q(LolbasPath), false);
        return r.IsCompleted ? LolbasReference.Parse(r.Output) : null;
    }

    #region JSON tools
    public Task<MFTEntry[]?> MFTECmdAsync(string file) => ExecuteToolJsonAsync<MFTEntry>("MFTECmd", $"-f {Q(file)}");

    /// <summary>
    /// Parses an NTFS metadata file (<paramref name="file"/>: <c>$MFT</c>, <c>$J</c>, <c>$Boot</c>, <c>$SDS</c>,
    /// <c>$I30</c>) with MFTECmd to a CSV file. <paramref name="outputDir"/> (<c>--csv</c>) /
    /// <paramref name="outputFile"/> (<c>--csvf</c>) control where it is written; <paramref name="allTimestamps"/>
    /// (<c>--at</c>) includes both $SI and $FN timestamps; <paramref name="recoverSlack"/> (<c>--rs</c>) recovers
    /// slack-space entries; <paramref name="vss"/> (<c>--vss</c>) processes Volume Shadow Copy entries (for
    /// <c>$J</c>). Returns an <see cref="MFTECmdResult"/> describing the output, or null on failure.
    /// </summary>
    public async Task<MFTECmdResult?> MFTECmdCsvAsync(
        string file, string? outputFile = null, string? outputDir = null,
        bool allTimestamps = false, bool recoverSlack = false, bool vss = false)
    {
        if (outputFile is null && outputDir is null)
            throw new ArgumentException("MFTECmdCsvAsync requires either an output file (--csvf) or output directory (--csv).");

        var args = $"-f {Q(file)} " +
            (allTimestamps ? "--at " : "") +
            (recoverSlack ? "--rs " : "") +
            (vss ? "--vss " : "") +
            (outputDir is not null ? $"--csv {Q(outputDir)} " : "") +
            (outputFile is not null ? $"--csvf {Q(outputFile)} " : "");
        var stdout = await ExecuteToolTextAsync("MFTECmd", args.TrimEnd());
        return stdout is null ? null : MFTECmdResult.Parse(stdout, outputDir, outputFile);
    }

    /// <summary>
    /// Parses an NTFS metadata file (<paramref name="file"/>) with MFTECmd to a mactime <em>bodyfile</em> (for
    /// mactime/plaso integration). <paramref name="outputDir"/> (<c>--body</c>) / <paramref name="outputFile"/>
    /// (<c>--bodyf</c>) control where it is written; <paramref name="driveLetter"/> (<c>--bdl</c>) is the drive
    /// letter prepended to bodyfile paths (e.g. <c>C</c>); <paramref name="vss"/> (<c>--vss</c>) processes Volume
    /// Shadow Copy entries. Returns an <see cref="MFTECmdResult"/> describing the output, or null on failure.
    /// </summary>
    public async Task<MFTECmdResult?> MFTECmdBodyfileAsync(
        string file, string? outputFile = null, string? outputDir = null,
        string? driveLetter = null, bool vss = false)
    {
        if (outputFile is null && outputDir is null)
            throw new ArgumentException("MFTECmdBodyfileAsync requires either an output file (--bodyf) or output directory (--body).");

        var args = $"-f {Q(file)} " +
            (vss ? "--vss " : "") +
            (outputDir is not null ? $"--body {Q(outputDir)} " : "") +
            (driveLetter is not null ? $"--bdl {driveLetter} " : "") +
            (outputFile is not null ? $"--bodyf {Q(outputFile)} " : "");
        var stdout = await ExecuteToolTextAsync("MFTECmd", args.TrimEnd());
        return stdout is null ? null : MFTECmdResult.Parse(stdout, outputDir, outputFile);
    }

    public Task<LnkFile[]?> LECmdAsync(string file) => ExecuteToolJsonAsync<LnkFile>("LECmd", $"-f {Q(file)}");

    public Task<ShellBag[]?> SBECmdAsync(string hiveDirectory) => ExecuteToolJsonAsync<ShellBag>("SBECmd", $"-d {Q(hiveDirectory)}");

    /// <summary>
    /// Parses the shellbags in the registry hives under <paramref name="directory"/> (<c>-d</c>) with SBECmd,
    /// writing per-hive CSV files into <paramref name="outputDir"/> (<c>--csv</c>). Returns an
    /// <see cref="SBECmdCsvResult"/> describing the output directory, the CSV files produced, and the total
    /// shellbags found, or null on failure. (SBECmd takes a directory only — there is no single-file <c>-f</c>.)
    /// </summary>
    public async Task<SBECmdCsvResult?> SBECmdCsvAsync(string directory, string outputDir)
    {
        var stdout = await ExecuteToolTextAsync("SBECmd", $"-d {Q(directory)} --csv {Q(outputDir)}");
        if (stdout is null) return null;

        // SBECmd names each output CSV after its hive (and writes a !SBECmd_Messages.txt log); collect the CSVs.
        var find = await auditEnvironment.ExecuteCommandAsync("find", $"{Q(outputDir)} -maxdepth 1 -type f -name '*.csv'", false);
        var csvFiles = find.IsCompleted
            ? find.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
        return SBECmdCsvResult.Parse(stdout, outputDir, csvFiles);
    }

    // EvtxECmd's bundled event maps, used for structured field extraction (PayloadData columns). Always
    // supplied via --maps so events parse into rich fields rather than raw XML.
    private const string EvtxMapsDir = "/opt/zimmermantools/EvtxeCmd/Maps";

    /// <summary>
    /// Parses Windows event logs with EvtxECmd to structured JSON, always using the bundled maps
    /// (<c>--maps</c>). Supply <paramref name="file"/> (<c>-f</c>) for a single .evtx or
    /// <paramref name="directory"/> (<c>-d</c>) for a directory of them. <paramref name="includeIds"/> /
    /// <paramref name="excludeIds"/> (<c>--inc</c>/<c>--exc</c>) are comma-separated Event ID filters, and
    /// <paramref name="startDate"/> / <paramref name="endDate"/> (<c>--sd</c>/<c>--ed</c>) bound the time
    /// range (UTC, e.g. <c>"2023-01-24 00:00:00"</c>).
    /// </summary>
    public Task<EventLogEntry[]?> EvtxECmdAsync(
        string? file = null, string? directory = null,
        string? includeIds = null, string? excludeIds = null,
        string? startDate = null, string? endDate = null)
    {
        if (file is null && directory is null)
            throw new ArgumentException("EvtxECmdAsync requires either a file (-f) or a directory (-d).");

        return ExecuteToolJsonAsync<EventLogEntry>("EvtxECmd",
            EvtxArgs(file, directory, includeIds, excludeIds, startDate, endDate) + $"--maps {Q(EvtxMapsDir)}");
    }

    /// <summary>
    /// As <see cref="EvtxECmdAsync"/> but server-side <c>grep</c>-filters the produced JSON-lines for
    /// <paramref name="payloadGrepPattern"/> before transferring them — for event sources that produce hundreds of
    /// thousands of rows (e.g. a DC's 4769 stream) where the analyst only cares about lines matching a specific
    /// payload signal (e.g. RC4 service tickets). The grep pattern is a fixed string passed to <c>grep -F</c>,
    /// matched against each whole JSON-lines record. Returns null if EvtxECmd failed; empty array on no matches.
    /// </summary>
    public async Task<EventLogEntry[]?> EvtxECmdServerFilteredAsync(
        string payloadGrepPattern,
        string? file = null, string? directory = null,
        string? includeIds = null, string? excludeIds = null,
        string? startDate = null, string? endDate = null)
    {
        if (file is null && directory is null)
            throw new ArgumentException("EvtxECmdServerFilteredAsync requires either a file (-f) or a directory (-d).");

        var dir = "/tmp/camel_ez_" + Guid.NewGuid().ToString("N");
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {dir}", false);
        try
        {
            var args = EvtxArgs(file, directory, includeIds, excludeIds, startDate, endDate)
                + $"--json {Q(dir)} --jsonf raw.json --maps {Q(EvtxMapsDir)}";
            if (await ExecuteToolTextAsync("EvtxECmd", args) is null) return null;
            // Server-side filter: emit only lines containing the pattern (grep -F = literal, no regex meta to escape).
            await auditEnvironment.ExecuteCommandAsync("bash",
                $"-c \"grep -F {Q(payloadGrepPattern)} {dir}/raw.json > {dir}/filtered.json || true\"", false);
            var r = await auditEnvironment.ExecuteCommandAsync("cat", $"{dir}/filtered.json", false);
            if (!r.IsCompleted) return [];
            return ParseJsonLines<EventLogEntry>(r.Output);
        }
        finally { try { auditEnvironment.ExecuteCommand("rm", $"-rf {dir}", out _, false); } catch { } }
    }

    /// <summary>
    /// Parses Windows event logs with EvtxECmd to a CSV file (rather than reading the events back), taking the
    /// same source/filter args as <see cref="EvtxECmdAsync"/> plus <paramref name="outputDir"/> (<c>--csv</c>)
    /// and <paramref name="outputFile"/> (<c>--csvf</c>) to control where the CSV is written. Always uses the
    /// bundled maps. Returns an <see cref="EvtxECmdCsvResult"/> describing the produced CSV (its path and the
    /// records-included / errors / dropped counts), or null if EvtxECmd failed.
    /// </summary>
    public async Task<EvtxECmdCsvResult?> EvtxECmdCsvAsync(
        string? file = null, string? directory = null,
        string? includeIds = null, string? excludeIds = null,
        string? startDate = null, string? endDate = null,
        string? outputFile = null, string? outputDir = null)
    {
        if (file is null && directory is null)
            throw new ArgumentException("EvtxECmdCsvAsync requires either a file (-f) or a directory (-d).");
        if (outputFile is null && outputDir is null)
            throw new ArgumentException("EvtxECmdCsvAsync requires either an output file (--csvf) or output directory (--csv).");

        var args = EvtxArgs(file, directory, includeIds, excludeIds, startDate, endDate) +
            (outputDir is not null ? $"--csv {Q(outputDir)} " : "") +
            (outputFile is not null ? $"--csvf {Q(outputFile)} " : "") +
            $"--maps {Q(EvtxMapsDir)}";

        var stdout = await ExecuteToolTextAsync("EvtxECmd", args);
        return stdout is null ? null : EvtxECmdCsvResult.Parse(stdout, outputDir, outputFile);
    }

    // Shared EvtxECmd source/filter args (source + Event ID + date filters); callers append output args + --maps.
    private static string EvtxArgs(string? file, string? directory, string? includeIds, string? excludeIds, string? startDate, string? endDate) =>
        (file is not null ? $"-f {Q(file)} " : "") +
        (directory is not null ? $"-d {Q(directory)} " : "") +
        (includeIds is not null ? $"--inc {includeIds} " : "") +
        (excludeIds is not null ? $"--exc {excludeIds} " : "") +
        (startDate is not null ? $"--sd {Q(startDate)} " : "") +
        (endDate is not null ? $"--ed {Q(endDate)} " : "");

    /// <summary>
    /// Runs SQLECmd over the SQLite databases in <paramref name="directory"/>. Output is heterogeneous
    /// (one record shape per matched SQLECmd map), so rows are returned as raw key/value records.
    /// </summary>
    public Task<Dictionary<string, System.Text.Json.JsonElement>[]?> SQLECmdAsync(string directory) =>
        ExecuteToolJsonAsync<Dictionary<string, System.Text.Json.JsonElement>>("SQLECmd", $"-d {Q(directory)}");
    #endregion

    #region CSV tools
    /// <summary>
    /// Parses the Application Compatibility Cache (Shimcache) from <paramref name="systemHive"/> into
    /// <see cref="ShimcacheEntry"/> rows. When <paramref name="ignoreTransactionLogs"/> is true the registry
    /// transaction logs are ignored (<c>--nl</c>) — faster, and appropriate when the hive is not dirty.
    /// </summary>
    public Task<ShimcacheEntry[]?> AppCompatCacheParserAsync(string systemHive, bool ignoreTransactionLogs = false) =>
        ExecuteToolCsvAsync("AppCompatCacheParser", $"-f {Q(systemHive)}" + (ignoreTransactionLogs ? " --nl" : ""), ShimcacheEntry.FromRow);

    public Task<RecycleBinEntry[]?> RBCmdAsync(string file) =>
        ExecuteToolCsvAsync("RBCmd", $"-f {Q(file)}", RecycleBinEntry.FromRow);

    /// <summary>
    /// Parses <paramref name="amcacheHive"/> (Amcache.hve) into <see cref="AmcacheEntry"/> rows — executed/
    /// present binaries with their SHA-1 and metadata. When <paramref name="ignoreTransactionLogs"/> is true
    /// the registry transaction logs are ignored (<c>--nl</c>) — faster, and appropriate when the hive is not dirty.
    /// </summary>
    public Task<AmcacheEntry[]?> AmcacheParserAsync(string amcacheHive, bool ignoreTransactionLogs = false) =>
        ExecuteToolCsvAsync("AmcacheParser", $"-f {Q(amcacheHive)}" + (ignoreTransactionLogs ? " --nl" : ""), AmcacheEntry.FromRow, "*UnassociatedFileEntries.csv");

    public Task<JumpListEntry[]?> JLECmdAsync(string directory) =>
        ExecuteToolCsvAsync("JLECmd", $"-d {Q(directory)}", JumpListEntry.FromRow, "*AutomaticDestinations.csv");

    public Task<TimelineActivity[]?> WxTCmdAsync(string activitiesCacheDb) =>
        ExecuteToolCsvAsync("WxTCmd", $"-f {Q(activitiesCacheDb)}", TimelineActivity.FromRow, "*Activity.csv");

    /// <summary>
    /// Runs RECmd in batch mode over the registry hives in <paramref name="hiveDirectory"/> using the
    /// <c>.reb</c> batch file <paramref name="batchFile"/> (the <c>--bn</c> argument), returning one
    /// <see cref="RegistryEntry"/> per key/value the batch's plugins matched.
    /// </summary>
    public Task<RegistryEntry[]?> RECmdAsync(string hiveDirectory, string batchFile) =>
        ExecuteToolCsvAsync("RECmd", $"-d {Q(hiveDirectory)} --bn {Q(batchFile)}", RegistryEntry.FromRow, "*Output.csv");

    /// <summary>
    /// Runs the RECmd batch over a <em>single</em> hive <paramref name="hiveFile"/>. RECmd batch mode (<c>--bn</c>)
    /// only accepts a directory (<c>-d</c>), so the hive and its transaction logs are staged into a temp directory
    /// first — which means RECmd replays the logs (recovering dirty-hive data, e.g. MRU keys wiped by anti-forensic
    /// tools) without the cost of parsing every hive in a user profile.
    /// </summary>
    public async Task<RegistryEntry[]?> RECmdSingleHiveAsync(string hiveFile, string batchFile)
    {
        string dir = "/tmp/camel_recmd_" + Guid.NewGuid().ToString("N");
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {dir}", false);
        try
        {
            // Copy the hive plus any sibling transaction logs ("<hive>*") so RECmd can replay them.
            await auditEnvironment.ExecuteCommandAsync("cp", $"{Q(hiveFile)}* {dir}/", false);
            return await RECmdAsync(dir, batchFile);
        }
        finally { try { auditEnvironment.ExecuteCommand("rm", $"-rf {dir}", out _, false); } catch { } }
    }
    #endregion

    #region Stdout tools
    /// <summary>
    /// Extracts ASCII/Unicode strings from <paramref name="file"/> using bstrings. This build of
    /// bstrings reads from stdin only, so the file is fed via shell redirection.
    /// </summary>
    public async Task<string[]?> BstringsAsync(string file, int minLength = 3) =>
        (await ExecuteToolTextAsync("Bstrings", $"-q -m {minLength} < {Q(file)}"))
            ?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Runs a single RegRipper (<c>rip.pl</c>) <paramref name="plugin"/> against the registry hive
    /// <paramref name="hive"/> (<c>-r</c>), returning its raw text output as a <see cref="RegRipperResult"/>
    /// (or null if rip.pl could not run). RegRipper covers a far wider set of AutoStart Extension Points
    /// (Run keys, Services, Scheduled Tasks/TaskCache, AppInit_DLLs, Image File Execution Options, shell
    /// open-command hijacks, …) than the EZ batch parsers, which is why persistence workflows reach for it.
    /// NOTE: rip.pl does <em>not</em> replay registry transaction logs, so point it at a clean (e.g. rla-
    /// processed) hive when the source is dirty. Each plugin emits its own text format — callers parse the
    /// plugin output they requested.
    /// </summary>
    public async Task<RegRipperResult?> RegRipperAsync(string hive, string plugin)
    {
        var stdout = await ExecuteToolTextAsync("RegRipper", $"-r {Q(hive)} -p {plugin}");
        return stdout is null ? null : RegRipperResult.Parse(plugin, hive, stdout);
    }

    // Delimiter prefixing each task file in the bulk-extraction stream (see ScheduledTasksAsync).
    private const string TaskDelimiter = "===CAMEL_TASK===";

    /// <summary>
    /// Parses the Windows scheduled tasks defined under <paramref name="tasksDirectory"/> (the on-disk
    /// <c>\Windows\System32\Tasks</c> tree) into <see cref="ScheduledTaskEntry"/> rows. Task definition files are
    /// UTF-16 XML; in a single pass each is transcoded to UTF-8 (falling back to raw bytes so one odd file can't
    /// abort the scan) and parsed for its <c>Exec</c> action — recovering the command line that the registry
    /// TaskCache does not store. Returns an empty array when the directory holds no tasks, or null if it could
    /// not be read.
    /// </summary>
    public async Task<ScheduledTaskEntry[]?> ScheduledTasksAsync(string tasksDirectory)
    {
        // For each task file: emit "<delim><path>\n" then the file transcoded UTF-16 -> UTF-8 (|| cat as fallback).
        var args = $"{Q(tasksDirectory)} -type f -exec sh -c '" +
            $"printf \"{TaskDelimiter}%s\\n\" \"$1\"; iconv -f UTF-16 -t UTF-8 \"$1\" 2>/dev/null || cat \"$1\"" +
            "' _ {} \\;";
        var r = await auditEnvironment.ExecuteCommandAsync("find", args, false);
        return r.IsCompleted ? ScheduledTaskEntry.ParseMany(r.Output, TaskDelimiter) : null;
    }

    /// <summary>
    /// Recovers the WMI subscription artifacts (event consumers, filters, and their bindings) from a WMI
    /// repository's <c>OBJECTS.DATA</c> file (<paramref name="objectsDataPath"/>) by scraping its strings — the
    /// offline technique from the methodology, since the binary repository format has no Linux parser. Runs an
    /// ASCII and a UTF-16LE <c>strings</c> pass (each offset-tagged so they can be merged in file order) and
    /// parses out the subscriptions. Returns null only if the file could not be read.
    /// </summary>
    public async Task<WmiSubscriptions?> WmiSubscriptionsAsync(string objectsDataPath)
    {
        var ascii = await auditEnvironment.ExecuteCommandAsync("strings", $"-t d -n 6 {Q(objectsDataPath)}", false);
        if (!ascii.IsCompleted) return null;
        var unicode = await auditEnvironment.ExecuteCommandAsync("strings", $"-t d -e l -n 6 {Q(objectsDataPath)}", false);
        return WmiSubscriptions.Parse(ascii.Output, unicode.IsCompleted ? unicode.Output : "");
    }
    #endregion

    // Single-quote a path so spaces and NTFS '$' names (e.g. $MFT) survive the shell literally.
    private static string Q(string path) => $"'{path}'";

    public override string[] ToolList { get; } =
    [
        "AmcacheParser", "AppCompatCacheParser", "MFTECmd", "JLECmd", "LECmd", "WxTCmd",
        "SBECmd", "RBCmd", "Bstrings", "EvtxECmd", "RECmd", "SQLECmd", "RegRipper"
    ];
}
