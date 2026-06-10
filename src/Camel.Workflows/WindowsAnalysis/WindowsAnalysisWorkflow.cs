namespace Camel.Workflows;

using System;
using System.Linq;

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
}
