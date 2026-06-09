namespace Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class WindowsAnalysisToolkit : Toolkit
{
    public WindowsAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("WindowsAnalysis", auditEnvironment, config) { }

    /// <summary>
    /// Installs RECmd (the Eric Zimmerman registry batch parser) into <c>/opt/zimmermantools</c> when the
    /// latest SIFT image omits it, plus the DFIR batch file it relies on for batch-mode parsing. No-op for
    /// anything already present.
    /// </summary>
    protected override void InstallMissingTools()
    {
        InstallZimmermanTool("RECmd", "https://download.ericzimmermanstools.com/net9/RECmd.zip", "/opt/zimmermantools/RECmd/RECmd.dll");
        InstallFile("DFIRBatch.reb", "https://github.com/EricZimmerman/RECmd/raw/refs/heads/master/BatchExamples/DFIRBatch.reb", "/opt/zimmermantools/RECmd/DFIRBatch.reb");
    }

    #region JSON tools
    public MFTEntry[]? MFTECmd(string file) => ExecuteToolJson<MFTEntry>("MFTECmd", $"-f {Q(file)}");

    public LnkFile[]? LECmd(string file) => ExecuteToolJson<LnkFile>("LECmd", $"-f {Q(file)}");

    public ShellBag[]? SBECmd(string hiveDirectory) => ExecuteToolJson<ShellBag>("SBECmd", $"-d {Q(hiveDirectory)}");

    public EventLogEntry[]? EvtxECmd(string file) => ExecuteToolJson<EventLogEntry>("EvtxECmd", $"-f {Q(file)}");

    /// <summary>
    /// Runs SQLECmd over the SQLite databases in <paramref name="directory"/>. Output is heterogeneous
    /// (one record shape per matched SQLECmd map), so rows are returned as raw key/value records.
    /// </summary>
    public Dictionary<string, System.Text.Json.JsonElement>[]? SQLECmd(string directory) =>
        ExecuteToolJson<Dictionary<string, System.Text.Json.JsonElement>>("SQLECmd", $"-d {Q(directory)}");
    #endregion

    #region CSV tools
    public ShimcacheEntry[]? AppCompatCacheParser(string systemHive) =>
        ExecuteToolCsv("AppCompatCacheParser", $"-f {Q(systemHive)}", ShimcacheEntry.FromRow);

    public RecycleBinEntry[]? RBCmd(string file) =>
        ExecuteToolCsv("RBCmd", $"-f {Q(file)}", RecycleBinEntry.FromRow);

    public AmcacheEntry[]? AmcacheParser(string amcacheHive) =>
        ExecuteToolCsv("AmcacheParser", $"-f {Q(amcacheHive)}", AmcacheEntry.FromRow, "*UnassociatedFileEntries.csv");

    public JumpListEntry[]? JLECmd(string directory) =>
        ExecuteToolCsv("JLECmd", $"-d {Q(directory)}", JumpListEntry.FromRow, "*AutomaticDestinations.csv");

    public TimelineActivity[]? WxTCmd(string activitiesCacheDb) =>
        ExecuteToolCsv("WxTCmd", $"-f {Q(activitiesCacheDb)}", TimelineActivity.FromRow, "*Activity.csv");

    /// <summary>
    /// Runs RECmd in batch mode over the registry hives in <paramref name="hiveDirectory"/> using the
    /// <c>.reb</c> batch file <paramref name="batchFile"/> (the <c>--bn</c> argument), returning one
    /// <see cref="RegistryEntry"/> per key/value the batch's plugins matched.
    /// </summary>
    public RegistryEntry[]? RECmd(string hiveDirectory, string batchFile) =>
        ExecuteToolCsv("RECmd", $"-d {Q(hiveDirectory)} --bn {Q(batchFile)}", RegistryEntry.FromRow, "*Output.csv");
    #endregion

    #region Stdout tools
    /// <summary>
    /// Extracts ASCII/Unicode strings from <paramref name="file"/> using bstrings. This build of
    /// bstrings reads from stdin only, so the file is fed via shell redirection.
    /// </summary>
    public string[]? Bstrings(string file, int minLength = 3) =>
        ExecuteToolText("Bstrings", $"-q -m {minLength} < {Q(file)}")
            ?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    #endregion

    // Single-quote a path so spaces and NTFS '$' names (e.g. $MFT) survive the shell literally.
    private static string Q(string path) => $"'{path}'";

    public override string[] ToolList { get; } =
    [
        "AmcacheParser", "AppCompatCacheParser", "MFTECmd", "JLECmd", "LECmd", "WxTCmd",
        "SBECmd", "RBCmd", "Bstrings", "EvtxECmd", "RECmd", "SQLECmd"
    ];
}
