namespace Camel.Toolkits.Models;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

/// <summary>A file on a mounted filesystem: its full <see cref="Path"/>, <see cref="Name"/>, and <see cref="Size"/> in bytes.</summary>
public class FsFile
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public long Size { get; set; }

    /// <summary>Parses a <c>find -printf '%s\t%p\n'</c> line ("&lt;size&gt;\t&lt;path&gt;") into an <see cref="FsFile"/>.</summary>
    public static FsFile? FromFindLine(string line)
    {
        int tab = line.IndexOf('\t');
        if (tab < 0) return null;
        var path = line[(tab + 1)..].TrimEnd('\r');
        int slash = path.LastIndexOf('/');
        return new FsFile
        {
            Path = path,
            Name = slash >= 0 ? path[(slash + 1)..] : path,
            Size = long.TryParse(line[..tab], out var s) ? s : 0,
        };
    }
}

/// <summary>Shared parsing helpers for The Sleuth Kit / EWF plain-text tool output.</summary>
internal static class TskParse
{
    private static readonly string[] LineSeparators = ["\r\n", "\n"];

    public static string[] Lines(string s) => s.Split(LineSeparators, StringSplitOptions.None);

    /// <summary>Builds a dictionary from "Label: value" lines (label = text before the first colon).</summary>
    public static Dictionary<string, string> LabelMap(string s)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in Lines(s))
        {
            int i = line.IndexOf(':');
            if (i <= 0) continue;
            var key = line[..i].Trim();
            var val = line[(i + 1)..].Trim();
            if (key.Length > 0 && !map.ContainsKey(key)) map[key] = val;
        }
        return map;
    }

    public static string? Get(this Dictionary<string, string> m, string key) => m.TryGetValue(key, out var v) ? v : null;

    public static long ToLong(string? s) => long.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out var v) ? v : 0;
    public static int ToInt(string? s) => int.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out var v) ? v : 0;

    /// <summary>Parses a TSK timestamp like "2004-08-19 16:47:33.460000000 (UTC)".</summary>
    public static DateTime? ToTskDate(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var t = s.Trim();
        int paren = t.IndexOf(" (", StringComparison.Ordinal);
        if (paren > 0) t = t[..paren];
        // .NET parses at most 7 fractional digits; TSK emits 9.
        var m = Regex.Match(t, @"^(?<base>.+\.\d{7})\d*$");
        if (m.Success) t = m.Groups["base"].Value;
        return DateTime.TryParse(t, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
    }
}

/// <summary>ewfinfo: E01 image metadata and embedded hash values.</summary>
public class EwfInfo
{
    public string? CaseNumber { get; set; }
    public string? Description { get; set; }
    public string? ExaminerName { get; set; }
    public string? EvidenceNumber { get; set; }
    public string? Notes { get; set; }
    public string? AcquisitionDate { get; set; }
    public string? SystemDate { get; set; }
    public string? OperatingSystemUsed { get; set; }
    public string? SoftwareVersionUsed { get; set; }
    public string? FileFormat { get; set; }
    public int SectorsPerChunk { get; set; }
    public string? CompressionMethod { get; set; }
    public string? CompressionLevel { get; set; }
    public string? MediaType { get; set; }
    public bool IsPhysical { get; set; }
    public int BytesPerSector { get; set; }
    public long NumberOfSectors { get; set; }
    public string? MediaSize { get; set; }
    public string? MD5 { get; set; }
    public string? SHA1 { get; set; }

    public static EwfInfo Parse(string s)
    {
        var m = TskParse.LabelMap(s);
        return new EwfInfo
        {
            CaseNumber = m.Get("Case number"),
            Description = m.Get("Description"),
            ExaminerName = m.Get("Examiner name"),
            EvidenceNumber = m.Get("Evidence number"),
            Notes = m.Get("Notes"),
            AcquisitionDate = m.Get("Acquisition date"),
            SystemDate = m.Get("System date"),
            OperatingSystemUsed = m.Get("Operating system used"),
            SoftwareVersionUsed = m.Get("Software version used"),
            FileFormat = m.Get("File format"),
            SectorsPerChunk = TskParse.ToInt(m.Get("Sectors per chunk")),
            CompressionMethod = m.Get("Compression method"),
            CompressionLevel = m.Get("Compression level"),
            MediaType = m.Get("Media type"),
            IsPhysical = string.Equals(m.Get("Is physical"), "yes", StringComparison.OrdinalIgnoreCase),
            BytesPerSector = TskParse.ToInt(m.Get("Bytes per sector")),
            NumberOfSectors = TskParse.ToLong(m.Get("Number of sectors")),
            MediaSize = m.Get("Media size"),
            MD5 = m.Get("MD5"),
            SHA1 = m.Get("SHA1"),
        };
    }
}

/// <summary>ewfverify: integrity verification result.</summary>
public class EwfVerify
{
    public string? StoredMD5 { get; set; }
    public string? CalculatedMD5 { get; set; }
    public string? StoredSHA1 { get; set; }
    public string? CalculatedSHA1 { get; set; }
    public string? Result { get; set; }
    public bool Success { get; set; }

    public static EwfVerify Parse(string s)
    {
        var m = TskParse.LabelMap(s);
        var resultLine = TskParse.Lines(s).FirstOrDefault(l => l.Contains("ewfverify:", StringComparison.OrdinalIgnoreCase));
        var result = resultLine is null ? null : resultLine[(resultLine.IndexOf(':') + 1)..].Trim();
        return new EwfVerify
        {
            StoredMD5 = m.Get("MD5 hash stored in file"),
            CalculatedMD5 = m.Get("MD5 hash calculated over data"),
            StoredSHA1 = m.Get("SHA1 hash stored in file"),
            CalculatedSHA1 = m.Get("SHA1 hash calculated over data"),
            Result = result,
            Success = string.Equals(result, "SUCCESS", StringComparison.OrdinalIgnoreCase),
        };
    }
}

/// <summary>img_stat: image format and sector size.</summary>
public class ImgStat
{
    public string? ImageType { get; set; }
    public long SizeOfData { get; set; }
    public int SectorSize { get; set; }
    public string? MD5 { get; set; }

    public static ImgStat Parse(string s)
    {
        var m = TskParse.LabelMap(s);
        return new ImgStat
        {
            ImageType = m.Get("Image Type"),
            SizeOfData = TskParse.ToLong(m.Get("Size of data in bytes")),
            SectorSize = TskParse.ToInt(m.Get("Sector size")),
            MD5 = m.Get("MD5 hash of data"),
        };
    }
}

/// <summary>mmls: a single partition-table entry.</summary>
public class MmlsEntry
{
    public int Index { get; set; }
    public string Slot { get; set; } = "";
    public long Start { get; set; }
    public long End { get; set; }
    public long Length { get; set; }
    public string Description { get; set; } = "";

    private static readonly Regex Row = new(
        @"^(?<idx>\d+):\s+(?<slot>\S+)\s+(?<start>\d+)\s+(?<end>\d+)\s+(?<len>\d+)\s+(?<desc>.+?)\s*$",
        RegexOptions.Compiled);

    public static MmlsEntry[] ParseAll(string s) =>
        TskParse.Lines(s)
            .Select(l => Row.Match(l))
            .Where(mt => mt.Success)
            .Select(mt => new MmlsEntry
            {
                Index = TskParse.ToInt(mt.Groups["idx"].Value),
                Slot = mt.Groups["slot"].Value,
                Start = TskParse.ToLong(mt.Groups["start"].Value),
                End = TskParse.ToLong(mt.Groups["end"].Value),
                Length = TskParse.ToLong(mt.Groups["len"].Value),
                Description = mt.Groups["desc"].Value,
            })
            .ToArray();
}

/// <summary>
/// fdisk -l: a single partition row. <see cref="Start"/> (in sectors) is the value to pass as the offset
/// to EwfMountLoopback / EwfMountNtfs. Column set varies between MBR (Boot/Id present) and GPT layouts.
/// </summary>
public class PartitionInfo
{
    public string DeviceName { get; set; } = "";
    public bool Boot { get; set; }
    public long Start { get; set; }
    public long End { get; set; }
    public long Sectors { get; set; }
    public string Size { get; set; } = "";
    public string? Id { get; set; }
    public string Type { get; set; } = "";

    public static PartitionInfo[] ParseAll(string s)
    {
        var lines = TskParse.Lines(s);
        int header = Array.FindIndex(lines, l => l.TrimStart().StartsWith("Device", StringComparison.Ordinal));
        if (header < 0) return [];

        var cols = lines[header].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        bool hasBoot = cols.Contains("Boot");
        bool hasId = cols.Contains("Id");

        var result = new List<PartitionInfo>();
        foreach (var line in lines.Skip(header + 1))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var t = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            int i = 0;
            var p = new PartitionInfo { DeviceName = t[i++] };
            if (hasBoot && i < t.Length && t[i] == "*") { p.Boot = true; i++; }
            if (i + 2 >= t.Length) continue;            // need Start, End, Sectors
            p.Start = TskParse.ToLong(t[i++]);
            p.End = TskParse.ToLong(t[i++]);
            p.Sectors = TskParse.ToLong(t[i++]);
            if (i < t.Length) p.Size = t[i++];
            if (hasId && i < t.Length) p.Id = t[i++];
            p.Type = string.Join(' ', t.Skip(i));
            result.Add(p);
        }
        return result.ToArray();
    }
}

/// <summary>fsstat: filesystem metadata (common fields plus the full label map).</summary>
public class FsStat
{
    public string? FileSystemType { get; set; }
    public string? VolumeSerialNumber { get; set; }
    public string? OemName { get; set; }
    public string? Version { get; set; }
    public int SectorSize { get; set; }
    public int ClusterSize { get; set; }
    public string? Range { get; set; }
    public long RootDirectory { get; set; }
    public string? TotalClusterRange { get; set; }
    public string? TotalSectorRange { get; set; }
    public Dictionary<string, string> Properties { get; set; } = new();

    public static FsStat Parse(string s)
    {
        var m = TskParse.LabelMap(s);
        return new FsStat
        {
            FileSystemType = m.Get("File System Type"),
            VolumeSerialNumber = m.Get("Volume Serial Number"),
            OemName = m.Get("OEM Name"),
            Version = m.Get("Version"),
            SectorSize = TskParse.ToInt(m.Get("Sector Size")),
            ClusterSize = TskParse.ToInt(m.Get("Cluster Size")),
            Range = m.Get("Range"),
            RootDirectory = TskParse.ToLong(m.Get("Root Directory")),
            TotalClusterRange = m.Get("Total Cluster Range"),
            TotalSectorRange = m.Get("Total Sector Range"),
            Properties = m,
        };
    }
}

/// <summary>fls: a file/directory entry (includes deleted entries).</summary>
public class FlsEntry
{
    public string NameType { get; set; } = "";
    public bool Deleted { get; set; }
    public bool Reallocated { get; set; }
    public string Inode { get; set; } = "";
    public string Name { get; set; } = "";

    // e.g. "d/d 3671-144-7:\tDocuments and Settings", "r/- * 0:\t__esitempfile.tmp", "r/r 9-128-1 (realloc):\t..."
    private static readonly Regex Row = new(
        @"^(?<type>[a-zA-Z\-]/[a-zA-Z\-])\s+(?<del>\*\s+)?(?<inode>[\d\-]+)(?<realloc>\(realloc\))?:\t(?<name>.*)$",
        RegexOptions.Compiled);

    public static FlsEntry[] ParseAll(string s) =>
        TskParse.Lines(s)
            .Select(l => Row.Match(l))
            .Where(mt => mt.Success)
            .Select(mt => new FlsEntry
            {
                NameType = mt.Groups["type"].Value,
                Deleted = mt.Groups["del"].Success,
                Reallocated = mt.Groups["realloc"].Success,
                Inode = mt.Groups["inode"].Value,
                Name = mt.Groups["name"].Value,
            })
            .ToArray();
}

/// <summary>istat: inode metadata. Captures the entry header and $STANDARD_INFORMATION times.</summary>
public class Istat
{
    public int Entry { get; set; }
    public int Sequence { get; set; }
    public bool Allocated { get; set; }
    public int Links { get; set; }
    public DateTime? Created { get; set; }
    public DateTime? FileModified { get; set; }
    public DateTime? MftModified { get; set; }
    public DateTime? Accessed { get; set; }
    public string RawText { get; set; } = "";

    public static Istat Parse(string s)
    {
        var lines = TskParse.Lines(s);
        var r = new Istat { RawText = s };

        var entry = Regex.Match(s, @"Entry:\s*(\d+)\s+Sequence:\s*(\d+)");
        if (entry.Success)
        {
            r.Entry = TskParse.ToInt(entry.Groups[1].Value);
            r.Sequence = TskParse.ToInt(entry.Groups[2].Value);
        }
        r.Allocated = s.Contains("Allocated", StringComparison.OrdinalIgnoreCase)
                      && !s.Contains("Not Allocated", StringComparison.OrdinalIgnoreCase);
        var links = Regex.Match(s, @"Links:\s*(\d+)");
        if (links.Success) r.Links = TskParse.ToInt(links.Groups[1].Value);

        // Only the first (STANDARD_INFORMATION) timestamp block.
        int stdIdx = Array.FindIndex(lines, l => l.Contains("$STANDARD_INFORMATION Attribute Values"));
        var scope = stdIdx >= 0 ? lines.Skip(stdIdx) : lines;
        DateTime? Find(string label) =>
            scope.Select(l => Regex.Match(l, $@"^{Regex.Escape(label)}:\s*(.+)$"))
                 .Where(mt => mt.Success).Select(mt => TskParse.ToTskDate(mt.Groups[1].Value)).FirstOrDefault();
        r.Created = Find("Created");
        r.FileModified = Find("File Modified");
        r.MftModified = Find("MFT Modified");
        r.Accessed = Find("Accessed");
        return r;
    }
}

/// <summary>ils: an inode listing entry (pipe-delimited body rows).</summary>
public class IlsEntry
{
    public int StIno { get; set; }
    public string StAlloc { get; set; } = "";
    public int StUid { get; set; }
    public int StGid { get; set; }
    public long StMtime { get; set; }
    public long StAtime { get; set; }
    public long StCtime { get; set; }
    public long StCrtime { get; set; }
    public string StMode { get; set; } = "";
    public int StNlink { get; set; }
    public long StSize { get; set; }

    public static IlsEntry[] ParseAll(string s)
    {
        var lines = TskParse.Lines(s);
        int header = Array.FindIndex(lines, l => l.StartsWith("st_ino|", StringComparison.Ordinal));
        if (header < 0) return [];
        return lines.Skip(header + 1)
            .Select(l => l.Split('|'))
            .Where(f => f.Length >= 11)
            .Select(f => new IlsEntry
            {
                StIno = TskParse.ToInt(f[0]),
                StAlloc = f[1],
                StUid = TskParse.ToInt(f[2]),
                StGid = TskParse.ToInt(f[3]),
                StMtime = TskParse.ToLong(f[4]),
                StAtime = TskParse.ToLong(f[5]),
                StCtime = TskParse.ToLong(f[6]),
                StCrtime = TskParse.ToLong(f[7]),
                StMode = f[8],
                StNlink = TskParse.ToInt(f[9]),
                StSize = TskParse.ToLong(f[10]),
            })
            .ToArray();
    }
}

/// <summary>mactime: a single timeline row (from "mactime -y -d" CSV output).</summary>
public class MactimeEntry
{
    public string Date { get; set; } = "";
    public long Size { get; set; }
    public string ActivityType { get; set; } = "";
    public string Mode { get; set; } = "";
    public int Uid { get; set; }
    public int Gid { get; set; }
    public string Meta { get; set; } = "";
    public string FileName { get; set; } = "";

    public static MactimeEntry[] ParseAll(string s)
    {
        var rows = new List<MactimeEntry>();
        foreach (var line in TskParse.Lines(s))
        {
            if (line.Length == 0 || line.StartsWith("Date,", StringComparison.Ordinal)) continue;
            var f = SplitCsv(line);
            if (f.Count < 8) continue;
            rows.Add(new MactimeEntry
            {
                Date = f[0],
                Size = TskParse.ToLong(f[1]),
                ActivityType = f[2],
                Mode = f[3],
                Uid = TskParse.ToInt(f[4]),
                Gid = TskParse.ToInt(f[5]),
                Meta = f[6],
                FileName = f[7],
            });
        }
        return rows.ToArray();
    }

    // Minimal CSV splitter: handles double-quoted fields (the file name may contain commas).
    private static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        var sb = new System.Text.StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"') quoted = !quoted;
            else if (c == ',' && !quoted) { fields.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        fields.Add(sb.ToString());
        return fields;
    }
}

/// <summary>
/// A file recovered by signature carving (foremost/scalpel) from a raw image or an unallocated-space extract.
/// <see cref="Offset"/> is the byte offset of the file within the carved input; <see cref="Path"/> is where the
/// carver wrote the recovered file on the workstation.
/// </summary>
public record CarvedFile
{
    /// <summary>File type / category (e.g. "jpg", "png", "pdf", "zip").</summary>
    public string Type { get; init; } = "";
    public string Name { get; init; } = "";
    public long Size { get; init; }
    public string Path { get; init; } = "";
    /// <summary>Byte offset of the carved file within the input that was carved.</summary>
    public long Offset { get; init; }
    /// <summary>Any extra note foremost recorded (e.g. image dimensions).</summary>
    public string? Comment { get; init; }
}

/// <summary>
/// A bulk_extractor feature recorder output: one feature file (e.g. <c>email.txt</c>) with the number of features
/// it found. The histogram-derived top values are surfaced separately by the feature-extraction workflow.
/// </summary>
public record BulkFeatureFile
{
    /// <summary>The feature file name, e.g. "email.txt".</summary>
    public string Name { get; init; } = "";
    /// <summary>The feature category (file name without ".txt"), e.g. "email", "url", "domain", "ccn".</summary>
    public string Category { get; init; } = "";
    public long Count { get; init; }
    public string Path { get; init; } = "";
    /// <summary>The most frequent values for this feature (from the category histogram), most-frequent first.</summary>
    public string[] TopValues { get; init; } = [];
}
