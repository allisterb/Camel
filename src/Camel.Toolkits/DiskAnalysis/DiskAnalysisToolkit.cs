namespace Camel.Toolkits;

using System.Text.RegularExpressions;

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

    /// <summary>
    /// Mounts <paramref name="image"/> (E01/EWF) read-only at <paramref name="mountDir"/>, exposing
    /// the raw disk as &lt;mountDir&gt;/ewf1. The mount directory must already exist. Returns true on
    /// success. The FUSE mount is owned by root; unmount with <c>umount &lt;mountDir&gt;</c> when done.
    /// </summary>
    public bool EwfMountRaw(string image, string mountDir) =>
        ExecuteToolText("EwfMountRaw", Q(image) + " " + Q(mountDir)) is not null;

    /// <summary>
    /// Mounts a raw EWF partition (e.g. the ewf1 device from <see cref="EwfMountRaw"/>) read-only at
    /// <paramref name="mountDir"/> using the kernel NTFS driver via loopback. <paramref name="offset"/>
    /// is the partition start in sectors (converted to a byte offset). Returns true on success.
    /// </summary>
    public bool EwfMountLoopback(string rawPartition, string mountDir, int? offset = null) =>
        ExecuteToolText("EwfMountLoopback",
            $"-o ro,loop,show_sys_files,streams_interace=windows{(offset is not null ? $",offset={offset.Value * 512}" : "")} {Q(rawPartition)} {Q(mountDir)}") is not null;

    /// <summary>
    /// Mounts a raw EWF partition read-only at <paramref name="mountDir"/> using ntfs-3g with the
    /// <c>force</c> option (useful for dirty/hibernated NTFS the kernel driver refuses). When
    /// <paramref name="offset"/> (partition start in sectors) is supplied it is converted to a byte
    /// offset. Returns true on success.
    /// </summary>
    public bool EwfMountNtfs(string rawPartition, string mountDir, int? offset = null) =>
        ExecuteToolText("EwfMountNtfs",
            $"-t ntfs-3g -o ro,force{(offset is not null ? $",offset={offset.Value * 512}" : "")} {Q(rawPartition)} {Q(mountDir)}") is not null;
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

    /// <summary>
    /// Extracts the content of <paramref name="inode"/> from <paramref name="image"/> and writes
    /// the raw bytes to <paramref name="outputFile"/> on the workstation (icat stdout redirected to
    /// the file). Returns true on success.
    /// </summary>
    public bool Icat(string image, long inode, string outputFile, int? offset = null) =>
        ExecuteToolText("Icat", Offset(offset) + Q(image) + $" {inode} > {Q(outputFile)}") is not null;
    #endregion

    #region File recovery
    /// <summary>
    /// Bulk-recovers files from <paramref name="image"/> into <paramref name="outputDir"/> on the
    /// workstation. When <paramref name="all"/> is true (-e) unallocated/deleted files are recovered
    /// as well; otherwise only allocated files. When <paramref name="dirInode"/> is supplied (-d) only
    /// that directory's tree is recovered. Returns the number of files recovered, or null on failure.
    /// </summary>
    public int? TskRecover(string image, string outputDir, bool all, long? dirInode = null, int? offset = null)
    {
        var o = ExecuteToolText("TskRecover",
            (all ? "-e " : "") + Offset(offset) + (dirInode is not null ? $"-d {dirInode} " : "") +
            Q(image) + " " + Q(outputDir));
        if (o is null) return null;
        // tsk_recover writes the files itself; under sudo they land root-owned, so hand the
        // recovered tree to the login user ($(id -un) expands before sudo runs).
        if (Tools["TskRecover"].Sudo)
            auditEnvironment.ExecuteCommand("chown", $"-R $(id -un):$(id -gn) {Q(outputDir)}", out _, true);
        return Regex.Match(o, @"Files Recovered:\s*(\d+)") is { Success: true } m ? int.Parse(m.Groups[1].Value) : 0;
    }
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
        "EwfInfo", "EwfVerify", "EwfMountRaw", "EwfMountLoopback", "EwfMountNtfs", "ImgStat",
        "Mmls", "FsStat", "Fls", "Icat", "Istat", "Ffind", "Ils", "Blkls", "TskRecover",
        "Mactime", "Blkcat", "BulkExtractor", "PhotoRec"
    ];
}