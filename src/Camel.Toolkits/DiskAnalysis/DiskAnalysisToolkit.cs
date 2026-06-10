namespace Camel.Toolkits;

using System.Text.RegularExpressions;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class DiskAnalysisToolkit : Toolkit
{
    public DiskAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("DiskAnalysis", auditEnvironment, config) { }

    #region EWF tools
    public async Task<EwfInfo?> EwfInfoAsync(string image) =>
        await ExecuteToolTextAsync("EwfInfo", Q(image)) is { } o ? Models.EwfInfo.Parse(o) : null;

    public async Task<EwfVerify?> EwfVerifyAsync(string image) =>
        await ExecuteToolTextAsync("EwfVerify", Q(image)) is { } o ? Models.EwfVerify.Parse(o) : null;

    /// <summary>
    /// Mounts <paramref name="image"/> (E01/EWF) read-only at <paramref name="mountDir"/>, exposing
    /// the raw disk as &lt;mountDir&gt;/ewf1. The mount directory must already exist. Returns true on
    /// success. The FUSE mount is owned by root; unmount with <c>umount &lt;mountDir&gt;</c> when done.
    /// </summary>
    public async Task<bool> EwfMountRawAsync(string image, string mountDir) =>
        await ExecuteToolTextAsync("EwfMountRaw", Q(image) + " " + Q(mountDir)) is not null;

    /// <summary>
    /// Mounts a raw EWF partition (e.g. the ewf1 device from <see cref="EwfMountRawAsync"/>) read-only at
    /// <paramref name="mountDir"/> using the kernel NTFS driver via loopback. <paramref name="offset"/>
    /// is the partition start in sectors (converted to a byte offset). Returns true on success.
    /// </summary>
    public async Task<bool> EwfMountLoopbackAsync(string rawPartition, string mountDir, int? offset = null) =>
        await ExecuteToolTextAsync("EwfMountLoopback",
            $"-o ro,loop,show_sys_files,streams_interace=windows{(offset is not null ? $",offset={offset.Value * 512}" : "")} {Q(rawPartition)} {Q(mountDir)}") is not null;

    /// <summary>
    /// Mounts a raw EWF partition read-only at <paramref name="mountDir"/> using ntfs-3g with the
    /// <c>force</c> option (useful for dirty/hibernated NTFS the kernel driver refuses). When
    /// <paramref name="offset"/> (partition start in sectors) is supplied it is converted to a byte
    /// offset. Returns true on success.
    /// </summary>
    public async Task<bool> EwfMountNtfsAsync(string rawPartition, string mountDir, int? offset = null) =>
        await ExecuteToolTextAsync("EwfMountNtfs",
            $"-t ntfs-3g -o ro,force{(offset is not null ? $",offset={offset.Value * 512}" : "")} {Q(rawPartition)} {Q(mountDir)}") is not null;
    #endregion

    #region Image and partition tools
    public async Task<ImgStat?> ImgStatAsync(string image) =>
        await ExecuteToolTextAsync("ImgStat", Q(image)) is { } o ? Models.ImgStat.Parse(o) : null;

    public async Task<MmlsEntry[]?> MmlsAsync(string image) =>
        await ExecuteToolTextAsync("Mmls", Q(image)) is { } o ? MmlsEntry.ParseAll(o) : null;

    /// <summary>
    /// Lists the partition table of a raw disk device (e.g. the <c>ewf1</c> exposed by <see cref="EwfMountRawAsync"/>)
    /// via <c>fdisk -l</c>. Each <see cref="PartitionInfo.Start"/> (in sectors) is the offset to pass to
    /// <see cref="EwfMountLoopbackAsync"/> / <see cref="EwfMountNtfsAsync"/> for that partition.
    /// </summary>
    public async Task<PartitionInfo[]?> ListPartitionsAsync(string disk) =>
        await ExecuteToolTextAsync("ListPartitions", $"-l {Q(disk)}") is { } o ? PartitionInfo.ParseAll(o) : null;

    /// <summary>
    /// Mounts a raw <c>.dd</c> disk image read-only at <paramref name="mountDir"/> via loopback. When
    /// <paramref name="offset"/> (a partition start in sectors, e.g. from <see cref="ListPartitionsAsync"/>) is
    /// supplied it is converted to a byte offset so a partition within the image is mounted. The mount
    /// directory must already exist. Returns true on success.
    /// </summary>
    public async Task<bool> DDMountAsync(string imageFile, string mountDir, int? offset = null) =>
        await ExecuteToolTextAsync("DDMount",
            $"-o ro,loop{(offset is not null ? $",offset={offset.Value * 512}" : "")} {Q(imageFile)} {Q(mountDir)}") is not null;

    /// <summary>
    /// Creates the mount-point directory <c>/mnt/&lt;name&gt;</c> on the workstation (via <c>sudo mkdir -p</c>),
    /// for use when additional mount points are needed. Returns the created path, or null on failure.
    /// </summary>
    public async Task<string?> MakeMountDirAsync(string name) =>
        await ExecuteToolTextAsync("MakeMountDir", $"-p {Q($"/mnt/{name}")}") is not null ? $"/mnt/{name}" : null;

    /// <summary>
    /// Creates the directory <paramref name="path"/> (and any missing parents) on the workstation via
    /// <c>sudo mkdir -p</c>. Unlike <see cref="MakeMountDirAsync"/> this accepts an arbitrary absolute path
    /// rather than prefixing <c>/mnt/</c>. Returns true on success.
    /// </summary>
    public async Task<bool> MakeDirAsync(string path) =>
        await ExecuteToolTextAsync("MakeMountDir", $"-p {Q(path)}") is not null;

    /// <summary>
    /// Unmounts the filesystem or device mounted at <paramref name="mountDir"/> (<c>umount</c> under sudo).
    /// Used to tear down mounts created by the EWF/DD/loopback mount methods. Returns true on success.
    /// </summary>
    public async Task<bool> UnmountAsync(string mountDir) =>
        await ExecuteToolTextAsync("Unmount", Q(mountDir)) is not null;
    #endregion

    #region Filesystem tools
    public async Task<FsStat?> FsStatAsync(string image, int? offset = null) =>
        await ExecuteToolTextAsync("FsStat", Offset(offset) + Q(image)) is { } o ? Models.FsStat.Parse(o) : null;

    public async Task<FlsEntry[]?> FlsAsync(string image, int? offset = null, long? inode = null, bool recursive = false, bool deletedOnly = false) =>
        await ExecuteToolTextAsync("Fls",
            (recursive ? "-r " : "") + (deletedOnly ? "-d " : "") + Offset(offset) + Q(image) +
            (inode is not null ? $" {inode}" : "")) is { } o ? FlsEntry.ParseAll(o) : null;

    /// <summary>
    /// Runs <c>fls -r -m</c> against <paramref name="image"/> to produce a mactime <em>bodyfile</em> at
    /// <paramref name="outputFile"/> on the workstation: a recursive walk of the filesystem (including
    /// deleted entries) with each row prefixed by the mount point <paramref name="mountPoint"/>. Feed the
    /// result to <see cref="MactimeAsync"/> to build a sorted timeline. Returns true on success.
    /// </summary>
    public async Task<bool> FlsBodyfileAsync(string image, string outputFile, int? offset = null, string mountPoint = "/") =>
        await ExecuteToolTextAsync("Fls", $"-r -m {Q(mountPoint)} {Offset(offset)}{Q(image)} > {Q(outputFile)}") is not null;

    public async Task<Istat?> IstatAsync(string image, long inode, int? offset = null) =>
        await ExecuteToolTextAsync("Istat", Offset(offset) + Q(image) + $" {inode}") is { } o ? Models.Istat.Parse(o) : null;

    public async Task<string?> FfindAsync(string image, long inode, int? offset = null) =>
        (await ExecuteToolTextAsync("Ffind", Offset(offset) + Q(image) + $" {inode}"))?.Trim();

    public async Task<IlsEntry[]?> IlsAsync(string image, int? offset = null) =>
        await ExecuteToolTextAsync("Ils", Offset(offset) + Q(image)) is { } o ? IlsEntry.ParseAll(o) : null;

    /// <summary>
    /// Extracts the content of <paramref name="inode"/> from <paramref name="image"/> and writes
    /// the raw bytes to <paramref name="outputFile"/> on the workstation (icat stdout redirected to
    /// the file). Returns true on success.
    /// </summary>
    public async Task<bool> IcatAsync(string image, long inode, string outputFile, int? offset = null) =>
        await ExecuteToolTextAsync("Icat", Offset(offset) + Q(image) + $" {inode} > {Q(outputFile)}") is not null;
    #endregion

    #region File recovery
    /// <summary>
    /// Bulk-recovers files from <paramref name="image"/> into <paramref name="outputDir"/> on the
    /// workstation. When <paramref name="all"/> is true (-e) unallocated/deleted files are recovered
    /// as well; otherwise only allocated files. When <paramref name="dirInode"/> is supplied (-d) only
    /// that directory's tree is recovered. Returns the number of files recovered, or null on failure.
    /// </summary>
    public async Task<int?> TskRecoverAsync(string image, string outputDir, bool all, long? dirInode = null, int? offset = null)
    {
        var o = await ExecuteToolTextAsync("TskRecover",
            (all ? "-e " : "") + Offset(offset) + (dirInode is not null ? $"-d {dirInode} " : "") +
            Q(image) + " " + Q(outputDir));
        if (o is null) return null;
        // tsk_recover writes the files itself; under sudo they land root-owned, so hand the
        // recovered tree to the login user ($(id -un) expands before sudo runs).
        if (Tools["TskRecover"].Sudo)
            await auditEnvironment.ExecuteCommandAsync("chown", $"-R $(id -un):$(id -gn) {Q(outputDir)}", true);
        return Regex.Match(o, @"Files Recovered:\s*(\d+)") is { Success: true } m ? int.Parse(m.Groups[1].Value) : 0;
    }
    #endregion

    #region Timeline
    public async Task<MactimeEntry[]?> MactimeAsync(string bodyfile, string timezone = "UTC") =>
        await ExecuteToolTextAsync("Mactime", $"-y -d -z {timezone} -b {Q(bodyfile)}") is { } o ? MactimeEntry.ParseAll(o) : null;

    /// <summary>
    /// Runs <c>mactime</c> over <paramref name="bodyfile"/> and writes the sorted timeline to
    /// <paramref name="outputFile"/> on the workstation (timezone <paramref name="timezone"/>, default UTC).
    /// Unlike <see cref="MactimeAsync"/> the timeline is left as a file rather than parsed — used for large
    /// timelines (e.g. a memory bodyfile from timeliner) where returning every row is not wanted. Returns
    /// true on success.
    /// </summary>
    public async Task<bool> MactimeToFileAsync(string bodyfile, string outputFile, string timezone = "UTC") =>
        await ExecuteToolTextAsync("Mactime", $"-z {timezone} -b {Q(bodyfile)} > {Q(outputFile)}") is not null;
    #endregion

    // Single-quote a path so spaces in image/file names survive the shell.
    private static string Q(string path) => $"'{path}'";
    private static string Offset(int? offset) => offset is not null ? $"-o {offset} " : "";

    public override string[] ToolList { get; } =
    [
        "EwfInfo", "EwfVerify", "EwfMountRaw", "EwfMountLoopback", "EwfMountNtfs", "ListPartitions",
        "DDMount", "MakeMountDir", "Unmount", "ImgStat", "Mmls", "FsStat", "Fls", "Icat", "Istat", "Ffind", "Ils",
        "Blkls", "TskRecover", "Mactime", "Blkcat", "BulkExtractor", "PhotoRec"
    ];
}