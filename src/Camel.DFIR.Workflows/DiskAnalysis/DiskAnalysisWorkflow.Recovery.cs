namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

public partial class DiskAnalysisWorkflow
{
    #region Carving
    /// <summary>
    /// Signature-carves files out of <paramref name="image"/> (a raw image, device, or any blob) into
    /// <paramref name="outputDir"/> and inventories them by type. <paramref name="carver"/> selects the engine —
    /// <c>foremost</c> (default; broad built-in signatures), <c>scalpel</c>, or <c>photorec</c>. To carve only a
    /// specific partition's unallocated space, use <see cref="CarveUnallocatedSpaceAsync"/> instead.
    /// </summary>
    /// <param name="image">Path to the image/device/extract to carve.</param>
    /// <param name="outputDir">Directory to write carved files into (must not already exist for foremost/scalpel).</param>
    /// <param name="carver">"foremost" (default), "scalpel", or "photorec".</param>
    /// <param name="fileTypes">foremost type filter (default "all").</param>
    public async Task<WorkflowResult<CarveReport>> CarveFilesAsync(string image, string outputDir, string carver = "foremost", string? fileTypes = null)
    {
        using var _audit = AuditScope();
        using var op = Begin("Carving files from {0} into {1} with {2}", image, outputDir, carver);

        var carved = await RunCarverAsync(carver, image, outputDir, fileTypes);
        if (carved is null)
            return WorkflowResult<CarveReport>.Failure(
                $"{carver} carving of '{image}' failed; check the path, that '{outputDir}' does not already exist, and the carver is installed.");

        op.Complete();
        return BuildCarveReport(outputDir, carver, carved, image);
    }

    /// <summary>
    /// The FOR508.5 unallocated-space recovery recipe: extracts a filesystem's <em>unallocated</em> blocks
    /// (<c>blkls</c>) from <paramref name="image"/> at <paramref name="offset"/> to a temporary file, then
    /// signature-carves deleted files out of that extract into <paramref name="outputDir"/>. The intermediate
    /// extract is removed afterwards. Returns the carved-file inventory.
    /// </summary>
    /// <param name="image">Path to the image/device to recover from.</param>
    /// <param name="outputDir">Directory for the carved output (must not already exist for foremost/scalpel).</param>
    /// <param name="offset">Partition start sector, or null for a single-volume image.</param>
    /// <param name="carver">"foremost" (default), "scalpel", or "photorec".</param>
    public async Task<WorkflowResult<CarveReport>> CarveUnallocatedSpaceAsync(string image, string outputDir, int? offset = null, string carver = "foremost")
    {
        using var _audit = AuditScope();
        using var op = Begin("Carving unallocated space of {0} (offset {1}) into {2}", image, offset?.ToString() ?? "none", outputDir);

        // Extract to a login-writable temp file (blkls redirects its stdout as the login user, so the destination
        // dir must be login-owned — outputDir is later created root-owned by the carver and chowned back).
        var extract = $"/tmp/camel_unalloc_{Guid.NewGuid():N}.blk";
        var bytesR = await DiskAnalysis.BlklsAsync(image, extract, offset);
        try
        {
            if (!bytesR.Ok)
                return WorkflowResult<CarveReport>.Failure(bytesR.FailureReason ??
                    $"blkls failed to extract unallocated space from '{image}' (offset {offset}). Check the offset (mmls) and that a filesystem exists there.");
            var bytes = bytesR.Value;
            if (bytes == 0)
                return WorkflowResult<CarveReport>.Failure(
                    $"No unallocated space extracted from '{image}' (offset {offset}) — nothing to carve.");

            var carved = await RunCarverAsync(carver, extract, outputDir, null);
            if (carved is null)
                return WorkflowResult<CarveReport>.Failure($"{carver} carving of the unallocated extract failed.");

            op.Complete();
            var result = BuildCarveReport(outputDir, carver, carved, image);
            return WorkflowResult<CarveReport>.Success(result.Result!,
                $"Extracted {bytes / 1024 / 1024} MB of unallocated space and carved {carved.Length} file(s) " +
                $"({string.Join(", ", result.Result!.ByType.Take(5).Select(t => $"{t.Name}×{t.Count}"))}) into '{outputDir}'.");
        }
        finally { await DiskAnalysis.DeleteFileAsync(extract); }
    }
    #endregion

    #region Feature extraction
    /// <summary>
    /// Runs <c>bulk_extractor</c> over <paramref name="image"/> to extract forensic features regardless of
    /// filesystem — email addresses, URLs, domains, credit-card numbers, phone numbers, IP addresses, and more —
    /// and summarises each category with its hit count and most-frequent values. Recovers indicators from
    /// allocated files, deleted content, and slack alike. Output (the raw feature files) is left under
    /// <paramref name="outputDir"/> for deeper review.
    /// </summary>
    /// <param name="image">Path to the image/device to scan.</param>
    /// <param name="outputDir">Directory for bulk_extractor's output (must not already exist).</param>
    public async Task<WorkflowResult<FeatureExtractionReport>> ExtractForensicFeaturesAsync(string image, string outputDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Extracting forensic features from {0} into {1}", image, outputDir);

        var features = (await DiskAnalysis.BulkExtractorAsync(image, outputDir)).Value;
        if (features is null)
            return WorkflowResult<FeatureExtractionReport>.Failure(
                $"bulk_extractor failed on '{image}'; check the path and that '{outputDir}' does not already exist.");

        var categories = features
            .Where(f => f.Count > 0)
            .OrderByDescending(f => f.Count)
            .Select(f => new FeatureCategory { Category = f.Category, Count = f.Count, TopValues = f.TopValues })
            .ToArray();

        op.Complete();
        var report = new FeatureExtractionReport { OutputDir = outputDir, Features = categories };
        return WorkflowResult<FeatureExtractionReport>.Success(report,
            categories.Length == 0
                ? $"No forensic features found in '{image}'."
                : $"Extracted features from '{image}': " +
                  string.Join(", ", categories.Take(6).Select(c => $"{c.Category}×{c.Count}")) +
                  $". Raw feature files in '{outputDir}'.");
    }
    #endregion

    #region Deleted files
    /// <summary>
    /// Enumerates deleted files on a filesystem in <paramref name="image"/> from its metadata: walks the
    /// filesystem into a mactime bodyfile (<c>fls -r -m</c>), keeps the deleted entries, and returns each with its
    /// path, TSK inode address, size, change-time (the best "deleted ~when" signal) and recoverability (whether
    /// the inode has been reallocated). Pass an inode to <see cref="RecoverDeletedFileAsync"/> to extract content.
    /// </summary>
    /// <param name="image">Path to the image/device to scan.</param>
    /// <param name="offset">Partition start sector, or null for a single-volume image.</param>
    /// <param name="maxFiles">Cap on returned entries (largest first). Default 2000.</param>
    public async Task<WorkflowResult<DeletedFilesReport>> ListDeletedFilesAsync(string image, int? offset = null, int maxFiles = 2000)
    {
        using var _audit = AuditScope();
        using var op = Begin("Listing deleted files in {0} (offset {1})", image, offset?.ToString() ?? "none");

        var bodyfile = $"/tmp/camel_deleted_{Guid.NewGuid():N}.body";
        if (!await DiskAnalysis.FlsBodyfileAsync(image, bodyfile, offset))
            return WorkflowResult<DeletedFilesReport>.Failure(
                $"Failed to walk '{image}' (offset {offset}) for deleted files. Check the offset (mmls) and that a filesystem exists there.");

        // The bodyfile names every deleted entry with a "(deleted)" / "(deleted-realloc)" suffix; pull just those
        // server-side rather than transferring the whole bodyfile.
        var lines = (await DiskAnalysis.GrepLinesAsync(bodyfile, ["deleted"], ignoreCase: false)).Value;
        if (lines is null)
            return WorkflowResult<DeletedFilesReport>.Failure($"Could not read the bodyfile '{bodyfile}'.");

        var entries = lines.Select(ParseDeletedRow).Where(e => e is not null).Select(e => e!)
            .OrderByDescending(e => e.Size).Take(maxFiles).ToArray();

        op.Complete();
        var report = new DeletedFilesReport { DeletedFiles = entries, Count = entries.Length };
        return WorkflowResult<DeletedFilesReport>.Success(report,
            entries.Length == 0
                ? $"No deleted files found in '{image}' (offset {offset})."
                : $"Found {lines.Length} deleted entry/entries in '{image}'; {entries.Count(e => e.Recoverable)} recoverable. " +
                  $"Largest: {string.Join("; ", entries.Take(3).Select(e => $"{e.Path} ({e.Size} bytes)"))}.");
    }

    /// <summary>
    /// Recovers the content of a single deleted file by its TSK inode address (e.g. an
    /// <see cref="DeletedFileEntry.Inode"/> from <see cref="ListDeletedFilesAsync"/>) to
    /// <paramref name="outputFile"/> on the workstation via <c>icat</c>. Returns the output path on success.
    /// </summary>
    /// <param name="image">Path to the image/device the file lives in.</param>
    /// <param name="inode">TSK inode address (plain ext inode, or NTFS <c>mft-type-id</c>).</param>
    /// <param name="outputFile">Where to write the recovered content.</param>
    /// <param name="offset">Partition start sector, or null for a single-volume image.</param>
    public async Task<WorkflowResult<string>> RecoverDeletedFileAsync(string image, string inode, string outputFile, int? offset = null)
    {
        using var _audit = AuditScope();
        using var op = Begin("Recovering deleted inode {0} from {1} to {2}", inode, image, outputFile);

        if (!await DiskAnalysis.IcatByAddrAsync(image, inode, outputFile, offset))
            return WorkflowResult<string>.Failure(
                $"icat failed to recover inode {inode} from '{image}' (offset {offset}). The inode may be unallocated/overwritten.");

        op.Complete();
        return WorkflowResult<string>.Success(outputFile, $"Recovered inode {inode} from '{image}' to '{outputFile}'.");
    }
    #endregion

    #region Helpers
    // Dispatch to the chosen carver, normalising every result to CarvedFile[]. null on tool failure.
    private async Task<CarvedFile[]?> RunCarverAsync(string carver, string input, string outputDir, string? fileTypes) =>
        carver.ToLowerInvariant() switch
        {
            "scalpel" => (await DiskAnalysis.ScalpelAsync(input, outputDir)).Value,
            "photorec" => (await DiskAnalysis.PhotoRecAsync(input, outputDir)).Value is { } paths
                ? paths.Select(PathToCarved).ToArray() : null,
            _ => (await DiskAnalysis.ForemostAsync(input, outputDir, fileTypes ?? "all")).Value,
        };

    private static CarvedFile PathToCarved(string path)
    {
        var name = path.Split('/').Last();
        return new CarvedFile { Path = path, Name = name, Type = name.Contains('.') ? name[(name.LastIndexOf('.') + 1)..] : "" };
    }

    private static WorkflowResult<CarveReport> BuildCarveReport(string outputDir, string carver, CarvedFile[] carved, string image)
    {
        var byType = carved.GroupBy(c => c.Type.Length > 0 ? c.Type : "(unknown)")
            .Select(g => new NameCount { Name = g.Key, Count = g.Count() })
            .OrderByDescending(n => n.Count).ThenBy(n => n.Name).ToArray();
        var report = new CarveReport { OutputDir = outputDir, Carver = carver, CarvedFiles = carved, ByType = byType, TotalFiles = carved.Length };
        return WorkflowResult<CarveReport>.Success(report,
            carved.Length == 0
                ? $"{carver} carved no files from '{image}'."
                : $"{carver} carved {carved.Length} file(s) into '{outputDir}': " +
                  string.Join(", ", byType.Take(8).Select(t => $"{t.Name}×{t.Count}")) + ".");
    }

    // Parse a deleted mactime bodyfile row: "MD5|name (deleted[-realloc])|inode|mode|uid|gid|size|atime|mtime|ctime|crtime".
    private static DeletedFileEntry? ParseDeletedRow(string line)
    {
        var f = line.Split('|');
        if (f.Length < 11) return null;
        var name = f[1];
        if (!name.Contains("(deleted")) return null;   // bodyfile marks deleted entries explicitly
        bool realloc = name.Contains("realloc");
        long.TryParse(f[6], out var size);
        DateTime? ctime = long.TryParse(f[9], out var ct) && ct > 0
            ? DateTimeOffset.FromUnixTimeSeconds(ct).UtcDateTime : null;
        return new DeletedFileEntry
        {
            Path = name.Replace(" (deleted-realloc)", "").Replace(" (deleted)", "").Trim(),
            Inode = f[2], Size = size, DeletedTime = ctime, Recoverable = !realloc,
        };
    }
    #endregion
}
