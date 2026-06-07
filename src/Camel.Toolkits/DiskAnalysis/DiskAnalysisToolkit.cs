namespace Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class DiskAnalysisToolkit : Toolkit
{
    public DiskAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("DiskAnalysis", auditEnvironment, config) { }

    #region EWF tools
    public EwfInfo? EwfInfo(string image) =>
        ExecuteToolText("EwfInfo", Q(image)) is { } o ? Models.EwfInfo.Parse(o) : null;

    public EwfVerify? EwfVerify(string image) =>
        ExecuteToolText("EwfVerify", Q(image)) is { } o ? Models.EwfVerify.Parse(o) : null;
    #endregion

    #region Image and partition tools
    public ImgStat? ImgStat(string image) =>
        ExecuteToolText("ImgStat", Q(image)) is { } o ? Models.ImgStat.Parse(o) : null;

    public MmlsEntry[]? Mmls(string image) =>
        ExecuteToolText("Mmls", Q(image)) is { } o ? MmlsEntry.ParseAll(o) : null;
    #endregion

    #region Filesystem tools
    public FsStat? FsStat(string image, int? offset = null) =>
        ExecuteToolText("FsStat", Offset(offset) + Q(image)) is { } o ? Models.FsStat.Parse(o) : null;

    public FlsEntry[]? Fls(string image, int? offset = null, long? inode = null, bool recursive = false, bool deletedOnly = false) =>
        ExecuteToolText("Fls",
            (recursive ? "-r " : "") + (deletedOnly ? "-d " : "") + Offset(offset) + Q(image) +
            (inode is not null ? $" {inode}" : "")) is { } o ? FlsEntry.ParseAll(o) : null;

    public Istat? Istat(string image, long inode, int? offset = null) =>
        ExecuteToolText("Istat", Offset(offset) + Q(image) + $" {inode}") is { } o ? Models.Istat.Parse(o) : null;

    public string? Ffind(string image, long inode, int? offset = null) =>
        ExecuteToolText("Ffind", Offset(offset) + Q(image) + $" {inode}")?.Trim();

    public IlsEntry[]? Ils(string image, int? offset = null) =>
        ExecuteToolText("Ils", Offset(offset) + Q(image)) is { } o ? IlsEntry.ParseAll(o) : null;
    #endregion

    #region Timeline
    public MactimeEntry[]? Mactime(string bodyfile, string timezone = "UTC") =>
        ExecuteToolText("Mactime", $"-y -d -z {timezone} -b {Q(bodyfile)}") is { } o ? MactimeEntry.ParseAll(o) : null;
    #endregion

    // Single-quote a path so spaces in image/file names survive the shell.
    private static string Q(string path) => $"'{path}'";
    private static string Offset(int? offset) => offset is not null ? $"-o {offset} " : "";

    public override string[] ToolList { get; } =
    [
        "EwfInfo", "EwfVerify", "EwfMount", "ImgStat", "Mmls", "FsStat", "Fls",
        "Icat", "Istat", "Ffind", "Ils", "Blkls", "TskRecover", "Mactime",
        "Blkcat", "BulkExtractor", "PhotoRec"
    ];
}