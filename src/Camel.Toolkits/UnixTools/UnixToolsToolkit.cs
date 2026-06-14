namespace Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

/// <summary>
/// A growing collection of commonly used Unix utilities on the SIFT workstation, wrapped as typed methods so
/// the agent can invoke them server-side in a single call rather than scripting raw shell. The current set
/// covers archive/compression utilities — letting the agent uncompress acquired disk and memory images
/// (commonly shipped as <c>.bz2</c>, <c>.zip</c>, or <c>.7z</c>) and get the resulting file path(s) and sizes
/// back without a follow-up directory walk. Add further general-purpose Unix tools here as workflows need them.
/// </summary>
public class UnixToolsToolkit : Toolkit
{
    public UnixToolsToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("UnixTools", auditEnvironment, config) { }

    /// <summary>
    /// Decompresses the bzip2 file <paramref name="file"/> (e.g. <c>memdump.raw.bz2</c>, <c>image.E01.bz2</c>)
    /// to <paramref name="outputFile"/> on the workstation, keeping the original archive. When
    /// <paramref name="outputFile"/> is null the destination is <paramref name="file"/> with a trailing
    /// <c>.bz2</c> stripped (or <c>.out</c> appended when it has no <c>.bz2</c> suffix). Streams via
    /// <c>bunzip2 -c</c> so the output path is chosen explicitly. Set <paramref name="sudo"/> when the source
    /// archive is root-owned (the decompressed output is still written as the login user via the redirect).
    /// Returns a <see cref="DecompressResult"/> describing the single decompressed file (with its size), or
    /// null on failure.
    /// </summary>
    public async Task<DecompressResult?> Bunzip2Async(string file, string? outputFile = null, bool sudo = false)
    {
        var output = outputFile ?? (file.EndsWith(".bz2", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file + ".out");
        auditEnvironment.FailIfEvidenceSpoliationRisk(output);   // never decompress over registered evidence
        // Decompress to the chosen path, then list it (size\tpath) so the result carries the output size
        // back in one round-trip. The redirect/listing run in the remote shell, same as the disk icat path.
        return await RunAsync("Bunzip2",
                $"-c {Q(file)} > {Q(output)} && find {Q(output)} -type f -printf '%s\\t%p\\n'", sudo) is { } o
            ? DecompressResult.FromFindListing(file, output, o)
            : null;
    }

    /// <summary>
    /// Extracts the zip archive <paramref name="archive"/> into <paramref name="destDir"/> on the workstation
    /// (created if missing), overwriting existing files. When <paramref name="files"/> is supplied only those
    /// members are extracted (e.g. a single large image out of a multi-file archive); otherwise the whole
    /// archive is extracted. Set <paramref name="sudo"/> when the archive is root-owned. Returns a
    /// <see cref="DecompressResult"/> listing every extracted file and its size (<paramref name="destDir"/> is
    /// the <c>OutputPath</c>), or null on failure.
    /// </summary>
    public async Task<DecompressResult?> UnzipAsync(string archive, string destDir, string[]? files = null, bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(destDir);   // never extract into registered evidence
        var members = files is { Length: > 0 } ? " " + string.Join(" ", files.Select(Q)) : "";
        // unzip -o overwrites; -q suppresses the per-file listing (we get paths from the find below instead).
        return await RunAsync("Unzip",
                $"-o -q {Q(archive)}{members} -d {Q(destDir)} && find {Q(destDir)} -type f -printf '%s\\t%p\\n'", sudo) is { } o
            ? DecompressResult.FromFindListing(archive, destDir, o)
            : null;
    }

    /// <summary>
    /// Extracts the 7-Zip archive <paramref name="archive"/> (<c>.7z</c>, and any other format 7-Zip reads —
    /// zip, rar, tar, gz, …) into <paramref name="destDir"/> on the workstation, preserving the archive's
    /// directory structure (<c>7z x</c>) and overwriting existing files. When <paramref name="files"/> is
    /// supplied only those members are extracted. Set <paramref name="sudo"/> when the archive is root-owned.
    /// Returns a <see cref="DecompressResult"/> listing every extracted file and its size
    /// (<paramref name="destDir"/> is the <c>OutputPath</c>), or null on failure.
    /// </summary>
    public async Task<DecompressResult?> SevenZipExtractAsync(string archive, string destDir, string[]? files = null, bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(destDir);   // never extract into registered evidence
        var members = files is { Length: > 0 } ? " " + string.Join(" ", files.Select(Q)) : "";
        // 7z x preserves paths; -y assumes yes to prompts; -bso0/-bsp0 silence the banner/progress so only the
        // find listing (size\tpath) drives the result. The -o<dir> switch takes no space before the path.
        return await RunAsync("SevenZip",
                $"x -y -bso0 -bsp0 {Q(archive)}{members} -o{Q(destDir)} && find {Q(destDir)} -type f -printf '%s\\t%p\\n'", sudo) is { } o
            ? DecompressResult.FromFindListing(archive, destDir, o)
            : null;
    }

    /// <summary>
    /// Copies the single file <paramref name="source"/> to <paramref name="dest"/> on the workstation
    /// (e.g. staging an image from an external/removable directory to <c>/mnt</c> or <c>/cases</c>),
    /// preserving mode and timestamps (<c>cp -p</c>). <paramref name="dest"/> is the full destination file
    /// path; its parent directory is created if missing. Set <paramref name="sudo"/> when the source or the
    /// destination tree is root-owned. When <paramref name="verify"/> is set the SHA-256 of the source and the
    /// copy are compared after the copy and reported via <see cref="CopyResult.Verified"/>. Returns a
    /// <see cref="CopyResult"/> describing the copied file (with its size), or null on failure.
    /// </summary>
    public async Task<CopyResult?> CopyFileAsync(string source, string dest, bool sudo = false, bool verify = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(dest);   // never copy over registered evidence
        if (ParentDir(dest) is { Length: > 0 } parent)
            await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(parent)}", sudo);
        if (await RunAsync("CopyFile",
                $"-p {Q(source)} {Q(dest)} && find {Q(dest)} -type f -printf '%s\\t%p\\n'", sudo) is not { } o)
            return null;
        var result = CopyResult.FromFindListing(source, dest, o);
        if (!verify) return result;
        var (ok, bad) = await VerifyFileAsync(source, dest, sudo);
        return result with { Verified = ok, Mismatches = bad };
    }

    /// <summary>
    /// Recursively copies the directory <paramref name="source"/> to <paramref name="dest"/> on the
    /// workstation, preserving mode and timestamps (<c>cp -rp</c>) — e.g. bringing an evidence folder in from
    /// an external mount to a working location under <c>/mnt</c> or <c>/cases</c>. <paramref name="dest"/> is
    /// the target directory path (created as a copy of <paramref name="source"/>); its parent is created if
    /// missing. Set <paramref name="sudo"/> when the source or destination tree is root-owned. When
    /// <paramref name="verify"/> is set the SHA-256 of every source file is compared against its copy and
    /// reported via <see cref="CopyResult.Verified"/> / <see cref="CopyResult.Mismatches"/>. Returns a
    /// <see cref="CopyResult"/> listing every copied file and its size, or null on failure.
    /// </summary>
    public async Task<CopyResult?> CopyDirAsync(string source, string dest, bool sudo = false, bool verify = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(dest);   // never copy over registered evidence
        if (ParentDir(dest) is { Length: > 0 } parent)
            await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(parent)}", sudo);
        if (await RunAsync("CopyDir",
                $"-rp {Q(source)} {Q(dest)} && find {Q(dest)} -type f -printf '%s\\t%p\\n'", sudo) is not { } o)
            return null;
        var result = CopyResult.FromFindListing(source, dest, o);
        if (!verify) return result;
        var (ok, bad) = await VerifyTreeAsync(source, dest, sudo);
        return result with { Verified = ok, Mismatches = bad };
    }

    /// <summary>
    /// Computes the MD5 hex digest of <paramref name="file"/> on the workstation (<c>md5sum</c>), or null on
    /// failure. Use it to verify an acquired image/file against a known MD5 from the case description. Set
    /// <paramref name="sudo"/> when the file is root-owned (e.g. on a forensic mount). Read-only — never modifies the file.
    /// </summary>
    public async Task<string?> Md5SumAsync(string file, bool sudo = false) =>
        HashFromSum(await RunAsync("MD5Sum", Q(file), sudo));

    /// <summary>
    /// Computes the SHA-256 hex digest of <paramref name="file"/> on the workstation (<c>sha256sum</c>), or null on
    /// failure. Use it to verify an acquired image/file against a known SHA-256 from the case description. Set
    /// <paramref name="sudo"/> when the file is root-owned (e.g. on a forensic mount). Read-only — never modifies the file.
    /// </summary>
    public async Task<string?> Sha256SumAsync(string file, bool sudo = false) =>
        HashFromSum(await RunAsync("SHA256Sum", Q(file), sudo));

    /// <summary>
    /// Computes the SHA-1 hex digest of <paramref name="file"/> on the workstation (<c>sha1sum</c>), or null on
    /// failure. Use it to verify an acquired image/file against a known SHA-1 from the case description. Set
    /// <paramref name="sudo"/> when the file is root-owned (e.g. on a forensic mount). Read-only — never modifies the file.
    /// </summary>
    public async Task<string?> Sha1SumAsync(string file, bool sudo = false) =>
        HashFromSum(await RunAsync("SHA1Sum", Q(file), sudo));

    // md5sum/sha1sum/sha256sum print "<hex>␣␣<path>"; take the leading hex token, lower-cased.
    private static string? HashFromSum(string? output) =>
        output is null ? null
            : output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } t
                ? t[0].Trim().ToLowerInvariant() : null;

    public override string[] ToolList { get; } = ["Bunzip2", "Unzip", "SevenZip", "CopyFile", "CopyDir", "MD5Sum", "SHA1Sum", "SHA256Sum"];

    #region Verification helpers
    /// <summary>
    /// Compares the SHA-256 of <paramref name="source"/> and <paramref name="dest"/>; returns whether they
    /// match and, when they don't (or either could not be hashed), <paramref name="dest"/> as the lone mismatch.
    /// </summary>
    private async Task<(bool Ok, string[] Mismatches)> VerifyFileAsync(string source, string dest, bool sudo)
    {
        var hs = await Sha256Async(source, sudo);
        var hd = await Sha256Async(dest, sudo);
        bool ok = hs is not null && hs == hd;
        return (ok, ok ? [] : [dest]);
    }

    /// <summary>
    /// Compares the SHA-256 of every file under <paramref name="source"/> against the same-relative-path file
    /// under <paramref name="dest"/>; returns whether all matched and the destination paths of any that
    /// differed or were missing/unhashable.
    /// </summary>
    private async Task<(bool Ok, string[] Mismatches)> VerifyTreeAsync(string source, string dest, bool sudo)
    {
        var src = await Sha256TreeAsync(source, sudo);
        var dst = await Sha256TreeAsync(dest, sudo);
        if (src is null || dst is null) return (false, []);
        var bad = src.Where(kv => !dst.TryGetValue(kv.Key, out var h) || h != kv.Value)
                     .Select(kv => $"{dest.TrimEnd('/')}/{kv.Key}").ToArray();
        return (bad.Length == 0, bad);
    }

    /// <summary>SHA-256 hex of a single file on the workstation, or null on failure.</summary>
    private async Task<string?> Sha256Async(string path, bool sudo)
    {
        var r = await auditEnvironment.ExecuteCommandAsync("sha256sum", Q(path), sudo);
        return r.IsCompleted && r.Output.Length >= 64 ? r.Output[..64] : null;
    }

    /// <summary>
    /// Map of relative-path → SHA-256 hex for every file under <paramref name="dir"/> (hashed server-side in
    /// one pass), or null on failure. <c>sha256sum</c> emits <c>&lt;64-hex&gt;␣␣&lt;path&gt;</c> per line.
    /// </summary>
    private async Task<Dictionary<string, string>?> Sha256TreeAsync(string dir, bool sudo)
    {
        var r = await auditEnvironment.ExecuteCommandAsync("bash",
            $"-c \"cd {Q(dir)} && find . -type f -print0 | xargs -0 sha256sum\"", sudo);
        if (!r.IsCompleted) return null;
        var map = new Dictionary<string, string>();
        foreach (var line in r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Length < 66) continue;            // <64-hex><2 spaces><path>
            map[line[66..].TrimStart('.', '/')] = line[..64];
        }
        return map;
    }
    #endregion

    /// <summary>
    /// Executes tool <paramref name="name"/> with <paramref name="args"/>, running under sudo when either the
    /// per-call <paramref name="sudo"/> flag or the tool's config <c>Sudo</c> default is set. Returns the raw
    /// stdout, or null (with an error logged) on failure. Mirrors <see cref="Toolkit.ExecuteToolTextAsync"/>
    /// but lets the caller force elevation for a root-owned image without changing the config default.
    /// </summary>
    private async Task<string?> RunAsync(string name, string args, bool sudo)
    {
        var r = await auditEnvironment.ExecuteCommandAsync(Tools[name].Command, args, Tools[name].Sudo || sudo);
        if (r.IsCompleted) return r.Output;
        Error($"Failed to execute tool command {Tools[name].Command} {args}: {r.Output}.");
        return null;
    }

    // Single-quote a path so spaces in image/archive names survive the shell.
    private static string Q(string path) => $"'{path}'";

    // The parent directory of an absolute path, or "" when there is no parent to create (a root-level or
    // relative bare name). Trailing slashes are ignored so "/mnt/cases/" yields "/mnt".
    private static string ParentDir(string path)
    {
        var i = path.TrimEnd('/').LastIndexOf('/');
        return i > 0 ? path.TrimEnd('/')[..i] : "";
    }
}
