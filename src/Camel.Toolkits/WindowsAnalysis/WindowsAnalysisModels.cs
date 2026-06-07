namespace Camel.Toolkits.Models;

using System;
using System.Collections.Generic;
using System.Globalization;

/// <summary>Shared parsing helpers for EZ Tools CSV string fields.</summary>
internal static class EzParse
{
    public static string? Get(this IReadOnlyDictionary<string, string> r, string key) =>
        r.TryGetValue(key, out var v) && v.Length > 0 ? v : null;

    public static long ToLong(string? s) => long.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out var v) ? v : 0;
    public static int ToInt(string? s) => int.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out var v) ? v : 0;
    public static bool ToBool(string? s) => bool.TryParse(s, out var v) && v;

    public static DateTime? ToDate(string? s) =>
        DateTime.TryParse(s, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
}

/// <summary>MFTECmd: a single $MFT FILE record (--json output).</summary>
public class MFTEntry
{
    public int EntryNumber { get; set; }
    public int SequenceNumber { get; set; }
    public int ParentEntryNumber { get; set; }
    public int ParentSequenceNumber { get; set; }
    public bool InUse { get; set; }
    public string ParentPath { get; set; } = "";
    public string FileName { get; set; } = "";
    public string Extension { get; set; } = "";
    public bool IsDirectory { get; set; }
    public bool HasAds { get; set; }
    public bool IsAds { get; set; }
    public long FileSize { get; set; }
    public DateTime? Created0x10 { get; set; }
    public DateTime? LastModified0x10 { get; set; }
    public DateTime? LastRecordChange0x10 { get; set; }
    public DateTime? LastAccess0x10 { get; set; }
    public int SiFlags { get; set; }
    public int NameType { get; set; }
    public bool Timestomped { get; set; }
    public bool uSecZeros { get; set; }
    public bool Copied { get; set; }
    public string SourceFile { get; set; } = "";
}

/// <summary>LECmd: a parsed Windows shortcut (.lnk) file (--json output).</summary>
public class LnkFile
{
    public string SourceFile { get; set; } = "";
    public DateTime? SourceCreated { get; set; }
    public DateTime? SourceModified { get; set; }
    public DateTime? SourceAccessed { get; set; }
    public DateTime? TargetCreated { get; set; }
    public DateTime? TargetModified { get; set; }
    public DateTime? TargetAccessed { get; set; }
    public long FileSize { get; set; }
    public string? RelativePath { get; set; }
    public string? WorkingDirectory { get; set; }
    public string? Arguments { get; set; }
    public string? FileAttributes { get; set; }
    public string? HeaderFlags { get; set; }
    public string? MachineID { get; set; }
    public string? LocalPath { get; set; }
}

/// <summary>SBECmd: a single shellbag entry (--json output).</summary>
public class ShellBag
{
    public string? BagPath { get; set; }
    public int Slot { get; set; }
    public int NodeSlot { get; set; }
    public int MRUPosition { get; set; }
    public string? AbsolutePath { get; set; }
    public string? ShellType { get; set; }
    public string? Value { get; set; }
    public int ChildBags { get; set; }
    public DateTime? FirstInteracted { get; set; }
    public DateTime? LastInteracted { get; set; }
    public DateTime? LastWriteTime { get; set; }
}

/// <summary>AppCompatCacheParser: a single Shimcache (AppCompatCache) entry (CSV output).</summary>
public class ShimcacheEntry
{
    public int ControlSet { get; set; }
    public int CacheEntryPosition { get; set; }
    public string Path { get; set; } = "";
    public DateTime? LastModifiedTimeUTC { get; set; }
    public string? Executed { get; set; }
    public bool Duplicate { get; set; }
    public string SourceFile { get; set; } = "";

    public static ShimcacheEntry FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        ControlSet = EzParse.ToInt(r.Get("ControlSet")),
        CacheEntryPosition = EzParse.ToInt(r.Get("CacheEntryPosition")),
        Path = r.Get("Path") ?? "",
        LastModifiedTimeUTC = EzParse.ToDate(r.Get("LastModifiedTimeUTC")),
        Executed = r.Get("Executed"),
        Duplicate = EzParse.ToBool(r.Get("Duplicate")),
        SourceFile = r.Get("SourceFile") ?? "",
    };
}

/// <summary>RBCmd: a single recycle-bin deleted-file record (CSV output).</summary>
public class RecycleBinEntry
{
    public string SourceName { get; set; } = "";
    public string FileType { get; set; } = "";
    public string FileName { get; set; } = "";
    public long FileSize { get; set; }
    public DateTime? DeletedOn { get; set; }

    public static RecycleBinEntry FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        SourceName = r.Get("SourceName") ?? "",
        FileType = r.Get("FileType") ?? "",
        FileName = r.Get("FileName") ?? "",
        FileSize = EzParse.ToLong(r.Get("FileSize")),
        DeletedOn = EzParse.ToDate(r.Get("DeletedOn")),
    };
}
