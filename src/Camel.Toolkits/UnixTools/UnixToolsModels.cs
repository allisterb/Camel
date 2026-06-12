namespace Camel.Toolkits.Models;

using System;
using System.Linq;

/// <summary>A single file produced by a decompression/extraction/copy operation, with its size in bytes.</summary>
public record ExtractedFile(string Path, long Size)
{
    /// <summary>
    /// Parses a newline-delimited <c>size\tpath</c> listing (as emitted by <c>find ... -printf '%s\t%p\n'</c>)
    /// into <see cref="ExtractedFile"/> entries, tolerating blank lines, leading command banners, and other
    /// malformed rows (only rows whose first tab-separated field parses as a number are kept).
    /// </summary>
    public static ExtractedFile[] ParseFindListing(string listing) =>
        listing.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Split('\t', 2))
            .Where(p => p.Length == 2 && long.TryParse(p[0], out _))
            .Select(p => new ExtractedFile(p[1], long.Parse(p[0])))
            .ToArray();
}

/// <summary>
/// The result of a decompression/extraction (<c>bunzip2</c> / <c>unzip</c> / <c>7z</c>): the source archive,
/// where the content landed (a single file for <c>bunzip2</c>, the destination directory for <c>unzip</c>/<c>7z</c>),
/// the individual files produced, and their total size in bytes. Built from a <c>%s\t%p</c> file listing so the
/// agent gets the decompressed paths back in one call without a follow-up directory walk.
/// </summary>
public record DecompressResult
{
    public required string Source { get; init; }
    public required string OutputPath { get; init; }
    public ExtractedFile[] Files { get; init; } = [];
    public long TotalBytes => Files.Sum(f => f.Size);

    public static DecompressResult FromFindListing(string source, string outputPath, string listing) => new()
    {
        Source = source,
        OutputPath = outputPath,
        Files = ExtractedFile.ParseFindListing(listing),
    };
}

/// <summary>
/// The result of a copy (<c>cp</c>): the source path, the destination path the copy landed at, the individual
/// files written, and their total size in bytes. For a single-file copy <see cref="Files"/> holds the one
/// destination file; for a directory copy it holds every file under the destination tree. Built from a
/// <c>%s\t%p</c> file listing so the agent confirms what was copied in one call.
/// <para><see cref="Verified"/> is null when integrity verification was not requested; otherwise it is the
/// result of comparing the SHA-256 of every source file against its copy, with any failures listed in
/// <see cref="Mismatches"/> (the destination paths whose hash did not match the source, or that could not be
/// hashed).</para>
/// </summary>
public record CopyResult
{
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public ExtractedFile[] Files { get; init; } = [];
    public long TotalBytes => Files.Sum(f => f.Size);
    public bool? Verified { get; init; }
    public string[] Mismatches { get; init; } = [];

    public static CopyResult FromFindListing(string source, string destination, string listing) => new()
    {
        Source = source,
        Destination = destination,
        Files = ExtractedFile.ParseFindListing(listing),
    };
}
