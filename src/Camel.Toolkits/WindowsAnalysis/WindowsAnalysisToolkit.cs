namespace Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class WindowsAnalysisToolkit : Toolkit
{
    public WindowsAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("WindowsAnalysis", auditEnvironment, config) { }

    #region JSON tools
    public MFTEntry[]? MFTECmd(string file) => ExecuteToolJson<MFTEntry>("MFTECmd", $"-f {Q(file)}");

    public LnkFile[]? LECmd(string file) => ExecuteToolJson<LnkFile>("LECmd", $"-f {Q(file)}");

    public ShellBag[]? SBECmd(string hiveDirectory) => ExecuteToolJson<ShellBag>("SBECmd", $"-d {Q(hiveDirectory)}");
    #endregion

    #region CSV tools
    public ShimcacheEntry[]? AppCompatCacheParser(string systemHive) =>
        ExecuteToolCsv("AppCompatCacheParser", $"-f {Q(systemHive)}", ShimcacheEntry.FromRow);

    public RecycleBinEntry[]? RBCmd(string file) =>
        ExecuteToolCsv("RBCmd", $"-f {Q(file)}", RecycleBinEntry.FromRow);
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
