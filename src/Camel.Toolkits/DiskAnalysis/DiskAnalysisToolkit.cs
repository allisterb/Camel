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
            $"-o ro,loop,show_sys_files,streams_interface=windows{(offset is not null ? $",offset={offset.Value * 512}" : "")} {Q(rawPartition)} {Q(mountDir)}") is not null;

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
    public async Task<bool> FlsBodyfileAsync(string image, string outputFile, int? offset = null, string mountPoint = "/")
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputFile);   // never redirect the bodyfile over evidence
        return await ExecuteToolTextAsync("Fls", $"-r -m {Q(mountPoint)} {Offset(offset)}{Q(image)} > {Q(outputFile)}") is not null;
    }

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
    public async Task<bool> IcatAsync(string image, long inode, string outputFile, int? offset = null)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputFile);   // never redirect extracted bytes over evidence
        return await ExecuteToolTextAsync("Icat", Offset(offset) + Q(image) + $" {inode} > {Q(outputFile)}") is not null;
    }

    /// <summary>
    /// Lists files matching <paramref name="namePattern"/> under a <em>mounted</em> directory
    /// <paramref name="directory"/>, recursively, optionally limited to <paramref name="maxDepth"/> levels
    /// (0 = unlimited). Returns each as an <see cref="FsFile"/> (path/name/size). The match is case-insensitive and,
    /// by default, against the file <em>name</em> only (e.g. <c>*.dll</c>); it supports <c>*</c>, <c>?</c> and
    /// <c>[...]</c>. The search is already recursive, and the common shell-glob conveniences are normalised for you:
    /// a leading <c>**/</c> is dropped, brace alternation (<c>*.{dll,exe}</c>) is expanded, and a pattern containing
    /// a <c>/</c> is matched against the whole path (so <c>Users/*/NTUSER.DAT</c> works). Returns an empty array when
    /// the directory is absent or nothing matches (a missing path is normal when probing several locations).
    /// </summary>
    public Task<FsFile[]> FindFilesAsync(string directory, string namePattern = "*", int maxDepth = 0) =>
        FindFilesAsync(directory, [namePattern], maxDepth);

    /// <summary>
    /// As <see cref="FindFilesAsync(string, string, int)"/> but matching <em>any</em> of several
    /// case-insensitive globs in a single directory traversal (e.g. <c>["ntds.dit", "*.kirbi"]</c>).
    /// </summary>
    public async Task<FsFile[]> FindFilesAsync(string directory, string[] namePatterns, int maxDepth = 0)
    {
        if (namePatterns.Length == 0) return [];
        var depth = maxDepth > 0 ? $"-maxdepth {maxDepth} " : "";
        var names = BuildNamePredicate(namePatterns);
        if (names.Length == 0) return [];
        var r = await auditEnvironment.ExecuteCommandAsync("find",
            $"{Q(directory)} {depth}-type f \\( {names} \\) -printf '%s\\t%p\\n'", false);
        // Parse stdout regardless of exit code: find exits non-zero when it cannot read SOME entry in the tree
        // (e.g. a root-only `lost+found` / `System Volume Information` on a real mount), yet still prints every
        // match it did find to stdout. Gating on success would discard those valid results. Errors go to stderr
        // (not r.Output), and a genuinely failed/empty run leaves stdout empty -> an empty array, as documented.
        return r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(FsFile.FromFindLine).Where(f => f is not null).Select(f => f!).ToArray();
    }

    // find's -iname matches the basename only and is already recursive; it does NOT understand the glob idioms
    // agents habitually reach for — the recursive "**/" prefix, brace alternation "{a,b}", or path-component globs
    // — so those silently match nothing. Normalise each pattern: expand braces, drop a leading "**/", collapse any
    // remaining "**" to "*", and route a pattern that still contains a path separator through -ipath (whole-path
    // match) rather than -iname (basename match). Builds the "\( -iname ... -o -ipath ... \)" predicate body.
    private static string BuildNamePredicate(IEnumerable<string> patterns)
    {
        var terms = patterns
            .SelectMany(ExpandBraces)
            .Select(p => p.Replace("**/", "").Replace("**", "*").Trim())
            .Where(p => p.Length > 0)
            .Distinct()
            .Select(p => p.Contains('/') ? $"-ipath {Q("*" + p)}" : $"-iname {Q(p)}");
        return string.Join(" -o ", terms);
    }

    // Expands brace alternation, e.g. "*.{dll,exe}" -> ["*.dll","*.exe"], including multiple groups (cartesian).
    // Returns the pattern unchanged when it contains no braces.
    private static IEnumerable<string> ExpandBraces(string pattern)
    {
        int open = pattern.IndexOf('{');
        int close = open >= 0 ? pattern.IndexOf('}', open) : -1;
        if (open < 0 || close <= open) { yield return pattern; yield break; }
        var prefix = pattern[..open];
        var suffix = pattern[(close + 1)..];
        foreach (var alt in pattern[(open + 1)..close].Split(','))
            foreach (var expanded in ExpandBraces(prefix + alt.Trim() + suffix))
                yield return expanded;
    }

    /// <summary>Returns the SHA-256 hex digest of <paramref name="path"/> on the mounted filesystem, or null on failure.</summary>
    public async Task<string?> Sha256Async(string path)
    {
        var r = await auditEnvironment.ExecuteCommandAsync("sha256sum", Q(path), false);
        return r.IsCompleted ? r.Output.Split(' ', 2, StringSplitOptions.TrimEntries)[0] : null;
    }

    /// <summary>
    /// Server-side <c>grep</c> of a text file (e.g. a web-server access log), returning only the lines that match
    /// any of <paramref name="patterns"/> (extended regex, case-insensitive by default). The patterns are shipped
    /// to the workstation as a base64-encoded pattern file and matched with <c>grep -E -f</c>, so the match runs on
    /// the workstation and only the matching lines transfer back — the same scaling discipline the event-log
    /// workflows use to avoid pulling an entire multi-hundred-megabyte source over SSH. A no-match (<c>grep</c>
    /// exit 1) is success-with-no-rows, not an error. When <paramref name="maxMatches"/> is set the result is
    /// capped server-side. Returns the matching lines (empty when none match), or null when the file is unreadable.
    /// </summary>
    /// <param name="path">Path to the text file on the workstation / mounted volume to search.</param>
    /// <param name="patterns">Extended-regex patterns; a line matching <em>any</em> of them is returned (grep -f OR semantics).</param>
    /// <param name="ignoreCase">Match case-insensitively (<c>grep -i</c>). Defaults to true.</param>
    /// <param name="maxMatches">When set, stop after this many matching lines (server-side <c>head</c>).</param>
    public async Task<string[]?> GrepLinesAsync(string path, IEnumerable<string> patterns, bool ignoreCase = true, int? maxMatches = null)
    {
        var pats = patterns.Where(p => !string.IsNullOrWhiteSpace(p)).ToArray();
        if (pats.Length == 0) return [];
        if (!auditEnvironment.FileExists(path)) return null;

        // Ship the pattern set as a base64 temp file so regex metacharacters never hit the shell; grep -f gives
        // OR semantics across the lines. rc==1 (no match) is normalised to success; rc>=2 (real error) propagates.
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", pats)));
        var tmp = "/tmp/camel_grep_" + Guid.NewGuid().ToString("N") + ".pat";
        var flags = ignoreCase ? "-E -i" : "-E";
        var cap = maxMatches is int n and > 0 ? $" | head -n {n}" : "";
        var script = $"echo {b64} | base64 -d > {tmp}; grep {flags} -f {tmp} {Q(path)}{cap}; rc=${{PIPESTATUS[0]}}; rm -f {tmp}; exit $((rc==1?0:rc))";
        var r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"{script}\"", false);
        return r.IsCompleted ? r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries) : null;
    }
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
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);   // never recover files (and chown) onto evidence
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
    public async Task<bool> MactimeToFileAsync(string bodyfile, string outputFile, string timezone = "UTC")
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputFile);   // never redirect the timeline over evidence
        return await ExecuteToolTextAsync("Mactime", $"-z {timezone} -b {Q(bodyfile)} > {Q(outputFile)}") is not null;
    }
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