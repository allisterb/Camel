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
    public Task<MFTEntry[]?> MFTECmdAsync(string file) => ExecuteToolJsonAsync<MFTEntry>("MFTECmd", $"-f {Q(file)}");

    public Task<LnkFile[]?> LECmdAsync(string file) => ExecuteToolJsonAsync<LnkFile>("LECmd", $"-f {Q(file)}");

    public Task<ShellBag[]?> SBECmdAsync(string hiveDirectory) => ExecuteToolJsonAsync<ShellBag>("SBECmd", $"-d {Q(hiveDirectory)}");

    public Task<EventLogEntry[]?> EvtxECmdAsync(string file) => ExecuteToolJsonAsync<EventLogEntry>("EvtxECmd", $"-f {Q(file)}");

    /// <summary>
    /// Runs SQLECmd over the SQLite databases in <paramref name="directory"/>. Output is heterogeneous
    /// (one record shape per matched SQLECmd map), so rows are returned as raw key/value records.
    /// </summary>
    public Task<Dictionary<string, System.Text.Json.JsonElement>[]?> SQLECmdAsync(string directory) =>
        ExecuteToolJsonAsync<Dictionary<string, System.Text.Json.JsonElement>>("SQLECmd", $"-d {Q(directory)}");
    #endregion

    #region CSV tools
    public Task<ShimcacheEntry[]?> AppCompatCacheParserAsync(string systemHive) =>
        ExecuteToolCsvAsync("AppCompatCacheParser", $"-f {Q(systemHive)}", ShimcacheEntry.FromRow);

    public Task<RecycleBinEntry[]?> RBCmdAsync(string file) =>
        ExecuteToolCsvAsync("RBCmd", $"-f {Q(file)}", RecycleBinEntry.FromRow);

    public Task<AmcacheEntry[]?> AmcacheParserAsync(string amcacheHive) =>
        ExecuteToolCsvAsync("AmcacheParser", $"-f {Q(amcacheHive)}", AmcacheEntry.FromRow, "*UnassociatedFileEntries.csv");

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
    #endregion

    #region Stdout tools
    /// <summary>
    /// Extracts ASCII/Unicode strings from <paramref name="file"/> using bstrings. This build of
    /// bstrings reads from stdin only, so the file is fed via shell redirection.
    /// </summary>
    public async Task<string[]?> BstringsAsync(string file, int minLength = 3) =>
        (await ExecuteToolTextAsync("Bstrings", $"-q -m {minLength} < {Q(file)}"))
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
