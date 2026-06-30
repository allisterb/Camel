namespace Camel.DFIR.Toolkits;
using Camel.Toolkits;

using System.Text.RegularExpressions;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.DFIR.Toolkits.Models;

public class DiskAnalysisToolkit : Toolkit
{
    public DiskAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("DiskAnalysis", auditEnvironment, config) { }

    /// <summary>
    /// Ensures the libbde BitLocker tools (<c>bdeinfo</c>/<c>bdemount</c>) are present. SIFT ships them, so this
    /// is a one-time <c>test -e</c> no-op on a normal workstation; on a stripped image it apt-installs
    /// <c>libbde-tools</c>. Best-effort - a failure just means the BitLocker methods return null until present.
    /// </summary>
    protected override void InstallMissingTools() => InstallAptPackage("libbde-tools", "/usr/bin/bdemount");

    #region EWF tools
    public Task<ToolResult<EwfInfo>> EwfInfoAsync(string image) =>
        TextResultAsync("EwfInfo", "ewfinfo", Q(image), Models.EwfInfo.Parse);

    public Task<ToolResult<EwfVerify>> EwfVerifyAsync(string image) =>
        TextResultAsync("EwfVerify", "ewfverify", Q(image), Models.EwfVerify.Parse);

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

    #region BitLocker (BDE) tools
    /// <summary>
    /// Reads BitLocker Drive Encryption (BDE) volume metadata from <paramref name="source"/> - a raw device such
    /// as the <c>ewf1</c> exposed by <see cref="EwfMountRawAsync"/>, or a raw image - with <c>bdeinfo</c>: the
    /// encryption method, volume identifier, creation time, and the key protectors present (TPM / recovery password
    /// / password / startup key). <paramref name="offset"/> is the BitLocker partition start sector (converted to
    /// the byte offset bdeinfo expects), or null for a single-volume image. Reading metadata needs no credential;
    /// supply one only to also confirm it unlocks the volume. Runs unattended (<c>-u</c>) so it never blocks for
    /// input. Returns null when there is no BDE volume at the offset (i.e. not a BitLocker volume) or the tool
    /// failed - inspect the returned model's <see cref="Models.BitLockerInfo.IsBitLockerVolume"/> otherwise.
    /// </summary>
    public Task<ToolResult<BitLockerInfo>> BdeInfoAsync(string source, int? offset = null,
        string? recoveryPassword = null, string? password = null, string? bekFile = null, string? fullKey = null) =>
        TextResultAsync("BdeInfo", "bdeinfo",
            $"-u {BdeOffset(offset)}{BdeCredArgs(recoveryPassword, password, bekFile, fullKey)}{Q(source)}",
            Models.BitLockerInfo.Parse);

    /// <summary>
    /// Unlocks and mounts a BitLocker (BDE) volume from <paramref name="volume"/> (a raw device/image) read-only
    /// with <c>bdemount</c>, exposing the decrypted volume as <c>&lt;mountDir&gt;/bde1</c> - a raw NTFS device the
    /// Sleuth Kit tools and a loopback mount then operate on exactly like the <c>ewf1</c> from
    /// <see cref="EwfMountRawAsync"/>. Supply exactly one credential: a 48-digit <paramref name="recoveryPassword"/>
    /// (<c>NNNNNN-NNNNNN-...</c>), a <paramref name="password"/>, a startup-key <paramref name="bekFile"/> (.BEK),
    /// or the raw <paramref name="fullKey"/> (FVEK:TWEAK base16). <paramref name="offset"/> is the partition start
    /// sector. The mount directory must already exist. Returns true on success (false on a wrong credential or an
    /// already-mounted target). The FUSE mount is root-owned; unmount with <see cref="UnmountAsync"/>.
    /// </summary>
    public async Task<bool> BdeMountAsync(string volume, string mountDir, string? recoveryPassword = null,
        string? password = null, string? bekFile = null, string? fullKey = null, int? offset = null) =>
        await ExecuteToolTextAsync("BdeMount",
            $"-u {BdeOffset(offset)}{BdeCredArgs(recoveryPassword, password, bekFile, fullKey)}{Q(volume)} {Q(mountDir)}") is not null;

    /// <summary>
    /// Searches <paramref name="input"/> (a raw image/device, an unallocated-space extract, a memory dump, or any
    /// blob) for BitLocker 48-digit recovery keys by string search - the FOR508 data-recovery technique:
    /// <c>strings</c> piped to a regex for the <c>NNNNNN-NNNNNN-NNNNNN-NNNNNN-NNNNNN-NNNNNN-NNNNNN-NNNNNN</c> format
    /// (eight groups of six decimal digits). Useful when no key is supplied - a recovery key saved to a file,
    /// captured in a print spool, or recoverable from memory surfaces here. Runs under sudo (a raw <c>ewf1</c>/
    /// <c>bde1</c> device is root-owned). When <paramref name="maxMatches"/> is set the result is capped. Returns
    /// the distinct candidate keys (empty when none), or null when the input is unreadable.
    /// </summary>
    public async Task<ToolResult<string[]>> SearchBitLockerRecoveryKeysAsync(string input, int? maxMatches = null)
    {
        // Eight groups of six decimal digits, '-' separated (the 48-digit BitLocker recovery key format).
        const string pattern = "[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}";
        var cap = maxMatches is int n and > 0 ? $" | head -n {n}" : "";
        // Ship the pipeline base64-encoded so the regex braces never reach the outer shell; -o prints just the key.
        var script = $"strings {Q(input)} | grep -E -o {Q(pattern)} | sort -u{cap}";
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(script));
        var r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"echo {b64} | base64 -d | bash\"", true);
        return r.IsCompleted
            ? r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : ToolResult<string[]>.Fail($"BitLocker recovery-key search failed: {Short(r.Output)}");
    }

    // bdeinfo/bdemount take -o in BYTES (the rest of this toolkit's offsets are partition start sectors); convert.
    private static string BdeOffset(int? offset) => offset is not null ? $"-o {(long)offset.Value * 512} " : "";

    // Build the single credential flag for bdeinfo/bdemount from whichever credential was supplied ('' for none).
    private static string BdeCredArgs(string? recoveryPassword, string? password, string? bekFile, string? fullKey)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(recoveryPassword)) parts.Add($"-r {Q(recoveryPassword)}");
        if (!string.IsNullOrWhiteSpace(password)) parts.Add($"-p {Q(password)}");
        if (!string.IsNullOrWhiteSpace(bekFile)) parts.Add($"-s {Q(bekFile)}");
        if (!string.IsNullOrWhiteSpace(fullKey)) parts.Add($"-k {Q(fullKey)}");
        return parts.Count > 0 ? string.Join(" ", parts) + " " : "";
    }
    #endregion

    #region Image and partition tools
    public Task<ToolResult<ImgStat>> ImgStatAsync(string image) =>
        TextResultAsync("ImgStat", "img_stat", Q(image), Models.ImgStat.Parse);

    public Task<ToolResult<MmlsEntry[]>> MmlsAsync(string image) =>
        TextResultAsync("Mmls", "mmls", Q(image), MmlsEntry.ParseAll);

    /// <summary>
    /// Lists the partition table of a raw disk device (e.g. the <c>ewf1</c> exposed by <see cref="EwfMountRawAsync"/>)
    /// via <c>fdisk -l</c>. Each <see cref="PartitionInfo.Start"/> (in sectors) is the offset to pass to
    /// <see cref="EwfMountLoopbackAsync"/> / <see cref="EwfMountNtfsAsync"/> for that partition.
    /// </summary>
    public Task<ToolResult<PartitionInfo[]>> ListPartitionsAsync(string disk) =>
        TextResultAsync("ListPartitions", "fdisk", $"-l {Q(disk)}", PartitionInfo.ParseAll);

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
    public async Task<ToolResult<string>> MakeMountDirAsync(string name)
    {
        if (!IsToolAvailable("MakeMountDir")) return ToolResult<string>.Fail($"mkdir is not available on platform '{platform}'.");
        return await ExecuteToolTextAsync("MakeMountDir", $"-p {Q($"/mnt/{name}")}") is not null
            ? ToolResult<string>.Pass($"/mnt/{name}")
            : ToolResult<string>.Fail($"Could not create mount dir '/mnt/{name}'.");
    }

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
    public Task<ToolResult<FsStat>> FsStatAsync(string image, int? offset = null) =>
        TextResultAsync("FsStat", "fsstat", Offset(offset) + Q(image), Models.FsStat.Parse);

    public Task<ToolResult<FlsEntry[]>> FlsAsync(string image, int? offset = null, long? inode = null, bool recursive = false, bool deletedOnly = false) =>
        TextResultAsync("Fls", "fls",
            (recursive ? "-r " : "") + (deletedOnly ? "-d " : "") + Offset(offset) + Q(image) +
            (inode is not null ? $" {inode}" : ""), FlsEntry.ParseAll);

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

    public Task<ToolResult<Istat>> IstatAsync(string image, long inode, int? offset = null) =>
        TextResultAsync("Istat", "istat", Offset(offset) + Q(image) + $" {inode}", Models.Istat.Parse);

    public Task<ToolResult<string>> FfindAsync(string image, long inode, int? offset = null) =>
        TextResultAsync("Ffind", "ffind", Offset(offset) + Q(image) + $" {inode}", s => s.Trim());

    public Task<ToolResult<IlsEntry[]>> IlsAsync(string image, int? offset = null) =>
        TextResultAsync("Ils", "ils", Offset(offset) + Q(image), IlsEntry.ParseAll);

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
    /// As <see cref="IcatAsync(string, long, string, int?)"/> but accepts a full TSK inode <em>address string</em>
    /// (e.g. an NTFS <c>&lt;mft&gt;-&lt;type&gt;-&lt;id&gt;</c> like <c>"12-128-1"</c>, or a plain ext inode) — the form
    /// <see cref="FlsEntry.Inode"/> carries — so a deleted entry from <c>fls</c> can be extracted directly.
    /// </summary>
    public async Task<bool> IcatByAddrAsync(string image, string inode, string outputFile, int? offset = null)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputFile);
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
    public async Task<ToolResult<string>> Sha256Async(string path)
    {
        var r = await auditEnvironment.ExecuteCommandAsync("sha256sum", Q(path), false);
        return r.IsCompleted
            ? r.Output.Split(' ', 2, StringSplitOptions.TrimEntries)[0]
            : ToolResult<string>.Fail($"sha256sum of '{path}' failed: {Short(r.Output)}");
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
    public async Task<ToolResult<string[]>> GrepLinesAsync(string path, IEnumerable<string> patterns, bool ignoreCase = true, int? maxMatches = null)
    {
        var pats = patterns.Where(p => !string.IsNullOrWhiteSpace(p)).ToArray();
        if (pats.Length == 0) return ToolResult<string[]>.Pass([]);
        if (!auditEnvironment.FileExists(path)) return ToolResult<string[]>.Fail($"File '{path}' is not readable on the workstation.");

        // Ship the pattern set as a base64 temp file so regex metacharacters never hit the shell; grep -f gives
        // OR semantics across the lines. rc==1 (no match) is normalised to success; rc>=2 (real error) propagates.
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", pats)));
        var tmp = "/tmp/camel_grep_" + Guid.NewGuid().ToString("N") + ".pat";
        var flags = ignoreCase ? "-E -i" : "-E";
        var cap = maxMatches is int n and > 0 ? $" | head -n {n}" : "";
        var script = $"echo {b64} | base64 -d > {tmp}; grep {flags} -f {tmp} {Q(path)}{cap}; rc=${{PIPESTATUS[0]}}; rm -f {tmp}; exit $((rc==1?0:rc))";
        var r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"{script}\"", false);
        return r.IsCompleted
            ? r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            : ToolResult<string[]>.Fail($"grep of '{path}' failed: {Short(r.Output)}");
    }
    #endregion

    #region File recovery
    /// <summary>
    /// Bulk-recovers files from <paramref name="image"/> into <paramref name="outputDir"/> on the
    /// workstation. When <paramref name="all"/> is true (-e) unallocated/deleted files are recovered
    /// as well; otherwise only allocated files. When <paramref name="dirInode"/> is supplied (-d) only
    /// that directory's tree is recovered. Returns the number of files recovered, or null on failure.
    /// </summary>
    public async Task<ToolResult<int>> TskRecoverAsync(string image, string outputDir, bool all, long? dirInode = null, int? offset = null)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);   // never recover files (and chown) onto evidence
        if (!IsToolAvailable("TskRecover")) return ToolResult<int>.Fail($"tsk_recover is not available on platform '{platform}'.");
        var o = await ExecuteToolTextAsync("TskRecover",
            (all ? "-e " : "") + Offset(offset) + (dirInode is not null ? $"-d {dirInode} " : "") +
            Q(image) + " " + Q(outputDir));
        if (o is null) return ToolResult<int>.Fail($"tsk_recover failed for '{image}' (see server log).");
        // tsk_recover writes the files itself; under sudo they land root-owned, so hand the
        // recovered tree to the login user ($(id -un) expands before sudo runs).
        if (Tools["TskRecover"].Sudo)
            await auditEnvironment.ExecuteCommandAsync("chown", $"-R $(id -un):$(id -gn) {Q(outputDir)}", true);
        return Regex.Match(o, @"Files Recovered:\s*(\d+)") is { Success: true } m ? int.Parse(m.Groups[1].Value) : 0;
    }
    #endregion

    #region File carving
    /// <summary>
    /// Extracts the <em>unallocated</em> blocks of a filesystem in <paramref name="image"/> to
    /// <paramref name="outputFile"/> on the workstation (<c>blkls</c>) — the raw bytes a signature carver then
    /// recovers deleted files from. When <paramref name="slackOnly"/> is set, file <em>slack</em> space is
    /// extracted instead (<c>-s</c>). <paramref name="offset"/> is a partition start sector. Returns the size in
    /// bytes of the extract, or null on failure.
    /// </summary>
    /// <summary>Deletes a (non-evidence) file on the workstation — used to clean up intermediate extracts (e.g.
    /// the unallocated-space blob produced for carving). Guarded so it can never remove registered evidence.</summary>
    public async Task<bool> DeleteFileAsync(string path)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(path);
        return (await auditEnvironment.ExecuteCommandAsync("rm", $"-f {Q(path)}", false)).IsCompleted;
    }

    public async Task<ToolResult<long>> BlklsAsync(string image, string outputFile, int? offset = null, bool slackOnly = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputFile);
        if (!IsToolAvailable("Blkls")) return ToolResult<long>.Fail($"blkls is not available on platform '{platform}'.");
        if (await ExecuteToolTextAsync("Blkls",
                (slackOnly ? "-s " : "") + Offset(offset) + Q(image) + " > " + Q(outputFile)) is null)
            return ToolResult<long>.Fail($"blkls failed for '{image}' (see server log).");
        var r = await auditEnvironment.ExecuteCommandAsync("find", $"{Q(outputFile)} -printf '%s'", false);
        return r.IsCompleted && long.TryParse(r.Output.Trim(), out var n) ? n : 0;
    }

    /// <summary>
    /// Signature-carves files out of <paramref name="input"/> (a raw image, device, or an unallocated-space
    /// extract from <see cref="BlklsAsync"/>) into <paramref name="outputDir"/> with <c>foremost</c>.
    /// <paramref name="fileTypes"/> selects the carver signatures (default <c>all</c> — foremost carves nothing
    /// without an explicit <c>-t</c>). The directory must not already exist (foremost creates it). Returns the
    /// carved files (type/name/size/offset from <c>audit.txt</c>), or null on failure.
    /// </summary>
    public async Task<ToolResult<CarvedFile[]>> ForemostAsync(string input, string outputDir, string fileTypes = "all", bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);
        if (ParentDir(outputDir) is { Length: > 0 } parent)
            await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(parent)}", false);
        var res = await RunAsync("Foremost", $"-t {fileTypes} -i {Q(input)} -o {Q(outputDir)}", sudo);
        if (!res.IsSuccess) return ToolResult<CarvedFile[]>.Fail(res.Message!);
        await ChownBackAsync(outputDir, sudo || Tools["Foremost"].Sudo);
        var audit = await auditEnvironment.ExecuteCommandAsync("cat", $"{Q(outputDir.TrimEnd('/'))}/audit.txt", false);
        if (!audit.IsCompleted) return ToolResult<CarvedFile[]>.Pass([]);
        return ParseForemostAudit(audit.Output, outputDir);
    }

    /// <summary>
    /// Signature-carves <paramref name="input"/> into <paramref name="outputDir"/> with <c>scalpel</c> using the
    /// rule set in <paramref name="confFile"/> (default the system <c>/etc/scalpel/scalpel.conf</c> — note its
    /// signatures are all commented out by default, so supply a conf with the wanted types enabled). Returns the
    /// carved files (discovered under the output tree), or null on failure.
    /// </summary>
    public async Task<ToolResult<CarvedFile[]>> ScalpelAsync(string input, string outputDir, string? confFile = null, bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);
        if (ParentDir(outputDir) is { Length: > 0 } parent)
            await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(parent)}", false);
        var conf = confFile is not null ? $"-c {Q(confFile)} " : "";
        var res = await RunAsync("Scalpel", $"{conf}-o {Q(outputDir)} {Q(input)}", sudo);
        if (!res.IsSuccess) return ToolResult<CarvedFile[]>.Fail(res.Message!);
        await ChownBackAsync(outputDir, sudo || Tools["Scalpel"].Sudo);
        return await ListCarvedAsync(outputDir);
    }

    /// <summary>
    /// Carves files from <paramref name="input"/> into <paramref name="outputDir"/> with <c>photorec</c> run
    /// non-interactively. <paramref name="fileTypes"/> is reserved for future per-type selection; by default
    /// photorec's full signature set is used. Returns the recovered file paths, or null on failure.
    /// </summary>
    public async Task<ToolResult<string[]>> PhotoRecAsync(string input, string outputDir, string? fileTypes = null, bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(outputDir)}", false);
        // Non-interactive batch form: write the recovered tree under <outputDir>/recup, carve the whole input.
        var res = await RunAsync("PhotoRec", $"/log /d {Q(outputDir.TrimEnd('/') + "/recup")} /cmd {Q(input)} options,search", sudo);
        if (!res.IsSuccess) return ToolResult<string[]>.Fail(res.Message!);
        await ChownBackAsync(outputDir, sudo || Tools["PhotoRec"].Sudo);
        var r = await auditEnvironment.ExecuteCommandAsync("find", $"{Q(outputDir)} -type f ! -name 'report.xml' ! -name '*.log' -printf '%p\\n'", false);
        return r.IsCompleted ? r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToArray() : System.Array.Empty<string>();
    }

    /// <summary>
    /// Runs <c>bulk_extractor</c> over <paramref name="input"/> (image, device, or extract) into
    /// <paramref name="outputDir"/>, scanning for forensic features (emails, URLs, domains, credit-card numbers,
    /// phone numbers, IP addresses, …) regardless of filesystem. The directory must not already exist. Returns
    /// the non-empty feature files with their hit counts, or null on failure.
    /// </summary>
    public async Task<ToolResult<BulkFeatureFile[]>> BulkExtractorAsync(string input, string outputDir, bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);
        if (ParentDir(outputDir) is { Length: > 0 } parent)
            await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(parent)}", false);
        var res = await RunAsync("BulkExtractor", $"-o {Q(outputDir)} {Q(input)}", sudo);
        if (!res.IsSuccess) return ToolResult<BulkFeatureFile[]>.Fail(res.Message!);
        await ChownBackAsync(outputDir, sudo || Tools["BulkExtractor"].Sudo);
        // For each non-empty feature file emit "path<TAB>count<TAB>top|values" — the top values come from the
        // category's *_histogram.txt (lines "n=<count>\t<value>", most-frequent first). One pass, one round trip.
        var dir = Q(outputDir.TrimEnd('/'));
        var script =
            $"for f in {dir}/*.txt; do case \"$f\" in *_histogram.txt|*_stopped.txt) continue;; esac; " +
            "n=$(grep -vc '^#' \"$f\" 2>/dev/null); [ \"$n\" -gt 0 ] || continue; " +
            "h=\"${f%.txt}_histogram.txt\"; " +
            "tv=$(grep -v '^#' \"$h\" 2>/dev/null | head -5 | sed 's/^n=[0-9]*\\t//' | paste -sd '|' -); " +
            "printf '%s\\t%s\\t%s\\n' \"$f\" \"$n\" \"$tv\"; done";
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(script));
        var r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"echo {b64} | base64 -d | bash\"", false);
        if (!r.IsCompleted) return ToolResult<BulkFeatureFile[]>.Pass([]);
        return r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Split('\t'))
            .Where(p => p.Length >= 2 && long.TryParse(p[1], out _))
            .Select(p => new BulkFeatureFile
            {
                Path = p[0], Name = p[0].Split('/').Last(),
                Category = p[0].Split('/').Last().Replace(".txt", ""), Count = long.Parse(p[1]),
                TopValues = p.Length > 2 ? p[2].Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) : [],
            }).ToArray();
    }

    /// <summary>
    /// Searches <paramref name="image"/> for the byte signature <paramref name="signature"/> (a hex string, e.g.
    /// <c>ffd8ffe0</c>) with <c>sigfind</c>, returning the block offsets where it occurs. <paramref name="offset"/>
    /// is a partition start sector. Returns null on failure.
    /// </summary>
    public async Task<ToolResult<long[]>> SigfindAsync(string image, string signature, int? offset = null)
    {
        if (!IsToolAvailable("Sigfind")) return ToolResult<long[]>.Fail($"sigfind is not available on platform '{platform}'.");
        var o = await ExecuteToolTextAsync("Sigfind", Offset(offset) + Q(signature) + " " + Q(image));
        if (o is null) return ToolResult<long[]>.Fail($"sigfind failed for '{image}' (see server log).");
        return Regex.Matches(o, @"Block:\s*(\d+)").Select(m => long.Parse(m.Groups[1].Value)).ToArray();
    }

    /// <summary>
    /// Undeletes files from an ext3/ext4 filesystem image with <c>extundelete</c>, writing the recovered tree
    /// under <paramref name="outputDir"/> (in a <c>RECOVERED_FILES</c> subdirectory). With
    /// <paramref name="restoreAll"/> (default) every recoverable inode is restored. NOTE: modern ext4 clears block
    /// pointers on delete, so recovery is often partial or empty — carving (<see cref="ForemostAsync"/>) is the
    /// fallback. Returns the number of files recovered, or null on failure.
    /// </summary>
    public async Task<ToolResult<int>> ExtundeleteAsync(string image, string outputDir, bool restoreAll = true, bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(outputDir)}", false);
        // extundelete writes RECOVERED_FILES into the CWD, so run it inside outputDir.
        var arg = restoreAll ? "--restore-all" : "";
        var res = await RunAsync("Extundelete", $"{arg} {Q(image)}", sudo, workingDir: outputDir);
        if (!res.IsSuccess) return ToolResult<int>.Fail(res.Message!);
        await ChownBackAsync(outputDir, sudo || Tools["Extundelete"].Sudo);
        var r = await auditEnvironment.ExecuteCommandAsync("find", $"{Q(outputDir.TrimEnd('/') + "/RECOVERED_FILES")} -type f 2>/dev/null | wc -l", false);
        return r.IsCompleted && int.TryParse(r.Output.Trim(), out var n) ? n : 0;
    }
    #endregion

    #region Timeline
    public Task<ToolResult<MactimeEntry[]>> MactimeAsync(string bodyfile, string timezone = "UTC") =>
        TextResultAsync("Mactime", "mactime", $"-y -d -z {timezone} -b {Q(bodyfile)}", MactimeEntry.ParseAll);

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

    // Runs an ExecuteToolText-based tool and maps its stdout with `parse`, wrapping the result as a ToolResult: a
    // failed result names the tool when unavailable on the platform, or reports the command failure otherwise (the
    // tool-not-installed vs. command-failed distinction a bare null hid — now it matters across platforms).
    private async Task<ToolResult<T>> TextResultAsync<T>(string tool, string label, string args, Func<string, T> parse)
    {
        if (!IsToolAvailable(tool)) return ToolResult<T>.Fail($"{label} is not available on platform '{platform}'.");
        var o = await ExecuteToolTextAsync(tool, args);
        return o is null ? ToolResult<T>.Fail($"{label} command failed on platform '{platform}' (see server log).") : parse(o);
    }

    // Condenses tool error output into a single-line reason for a failed ToolResult.
    private static string Short(string? s) =>
        string.IsNullOrWhiteSpace(s) ? "(no output)" : (s.Length > 200 ? s[..200] + "…" : s).Replace("\r", " ").Replace("\n", " ").Trim();

    #region Carving helpers
    /// <summary>
    /// Runs tool <paramref name="name"/>, elevating when the per-call <paramref name="sudo"/> or config default is
    /// set. When <paramref name="workingDir"/> is given the command runs inside it (for tools like extundelete
    /// that write into the CWD). Returns stdout, or null (with an error logged) on failure.
    /// </summary>
    private async Task<ToolResult<string>> RunAsync(string name, string args, bool sudo, string? workingDir = null)
    {
        if (!Tools[name].Available) return ToolResult<string>.Fail($"{name} is not available on platform '{platform}'.");
        var cmd = Tools[name].Command;
        var elevate = Tools[name].Sudo || sudo;
        CommandResult r;
        if (workingDir is not null)
        {
            var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"cd {Q(workingDir)} && {cmd} {args}"));
            r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"echo {b64} | base64 -d | bash\"", elevate);
        }
        else r = await auditEnvironment.ExecuteCommandAsync(cmd, args, elevate);
        if (r.IsCompleted) return r.Output ?? "";
        Error($"Failed to execute tool command {cmd} {args}: {r.Output}.");
        return ToolResult<string>.Fail($"{name} command failed: {Short(r.Output)}");
    }

    // Hand a tool's output tree back to the login user when the tool ran under sudo (would otherwise be root-owned).
    private async Task ChownBackAsync(string dir, bool sudo)
    {
        if (sudo) await auditEnvironment.ExecuteCommandAsync("chown", $"-R $(id -un):$(id -gn) {Q(dir)}", true);
    }

    // The parent directory of an absolute path, or "" when there is none to create.
    private static string ParentDir(string path)
    {
        var i = path.TrimEnd('/').LastIndexOf('/');
        return i > 0 ? path.TrimEnd('/')[..i] : "";
    }

    // Parse foremost's audit.txt rows: "<n>:\t<name>\t<size unit>\t<file offset>\t<comment>".
    private static CarvedFile[] ParseForemostAudit(string audit, string outputDir)
    {
        var files = new List<CarvedFile>();
        foreach (var line in audit.Split('\n'))
        {
            var m = Regex.Match(line.Trim(), @"^\d+:\s+(?<name>\S+)\s+(?<size>[\d.]+\s+\w+)\s+(?<off>\d+)\s*(?<comment>.*)$");
            if (!m.Success) continue;
            var name = m.Groups["name"].Value;
            var type = name.Contains('.') ? name[(name.LastIndexOf('.') + 1)..] : "";
            files.Add(new CarvedFile
            {
                Type = type, Name = name, Size = ParseSize(m.Groups["size"].Value),
                Offset = long.Parse(m.Groups["off"].Value),
                Path = $"{outputDir.TrimEnd('/')}/{type}/{name}",
                Comment = m.Groups["comment"].Value.Trim() is { Length: > 0 } c ? c : null,
            });
        }
        return files.ToArray();
    }

    // List carved files under an output tree by walking it (used by scalpel, which has no clean audit inventory).
    private async Task<CarvedFile[]> ListCarvedAsync(string dir)
    {
        var r = await auditEnvironment.ExecuteCommandAsync("find",
            $"{Q(dir)} -type f ! -name audit.txt ! -name '*.log' -printf '%s\\t%p\\n'", false);
        if (!r.IsCompleted) return [];
        return r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Split('\t', 2)).Where(p => p.Length == 2)
            .Select(p =>
            {
                var name = p[1].Split('/').Last();
                var type = name.Contains('.') ? name[(name.LastIndexOf('.') + 1)..] : "";
                return new CarvedFile { Type = type, Name = name, Size = long.TryParse(p[0], out var s) ? s : 0, Path = p[1] };
            }).ToArray();
    }

    // "10 KB" -> bytes (foremost uses 1024-based units).
    private static long ParseSize(string s)
    {
        var m = Regex.Match(s, @"(?<n>[\d.]+)\s*(?<u>\w+)");
        if (!m.Success || !double.TryParse(m.Groups["n"].Value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n)) return 0;
        return (long)(n * m.Groups["u"].Value.ToUpperInvariant() switch { "KB" => 1024L, "MB" => 1048576L, "GB" => 1073741824L, _ => 1L });
    }
    #endregion

    public override string[] ToolList { get; } =
    [
        "EwfInfo", "EwfVerify", "EwfMountRaw", "EwfMountLoopback", "EwfMountNtfs", "ListPartitions",
        "DDMount", "MakeMountDir", "Unmount", "ImgStat", "Mmls", "FsStat", "Fls", "Icat", "Istat", "Ffind", "Ils",
        "Blkls", "TskRecover", "Mactime", "Blkcat", "BulkExtractor", "PhotoRec",
        "Foremost", "Scalpel", "Sigfind", "Extundelete", "BdeInfo", "BdeMount"
    ];
}