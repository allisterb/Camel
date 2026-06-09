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

/// <summary>AmcacheParser: a single unassociated file entry from Amcache.hve (CSV output).</summary>
public class AmcacheEntry
{
    public string? ApplicationName { get; set; }
    public string? ProgramId { get; set; }
    public DateTime? FileKeyLastWriteTimestamp { get; set; }
    public string? SHA1 { get; set; }
    public bool IsOsComponent { get; set; }
    public string? FullPath { get; set; }
    public string? Name { get; set; }
    public string? FileExtension { get; set; }
    public DateTime? LinkDate { get; set; }
    public string? ProductName { get; set; }
    public long Size { get; set; }
    public string? Version { get; set; }
    public string? ProductVersion { get; set; }
    public string? BinaryType { get; set; }
    public bool IsPeFile { get; set; }
    public long Usn { get; set; }
    public string? Language { get; set; }
    public string? Description { get; set; }

    public static AmcacheEntry FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        ApplicationName = r.Get("ApplicationName"),
        ProgramId = r.Get("ProgramId"),
        FileKeyLastWriteTimestamp = EzParse.ToDate(r.Get("FileKeyLastWriteTimestamp")),
        SHA1 = r.Get("SHA1"),
        IsOsComponent = EzParse.ToBool(r.Get("IsOsComponent")),
        FullPath = r.Get("FullPath"),
        Name = r.Get("Name"),
        FileExtension = r.Get("FileExtension"),
        LinkDate = EzParse.ToDate(r.Get("LinkDate")),
        ProductName = r.Get("ProductName"),
        Size = EzParse.ToLong(r.Get("Size")),
        Version = r.Get("Version"),
        ProductVersion = r.Get("ProductVersion"),
        BinaryType = r.Get("BinaryType"),
        IsPeFile = EzParse.ToBool(r.Get("IsPeFile")),
        Usn = EzParse.ToLong(r.Get("Usn")),
        Language = r.Get("Language"),
        Description = r.Get("Description"),
    };
}

/// <summary>EvtxECmd: a single Windows event log record (--json output).</summary>
public class EventLogEntry
{
    public long RecordNumber { get; set; }
    public string? EventRecordId { get; set; }
    public DateTime? TimeCreated { get; set; }
    public int EventId { get; set; }
    public string? Level { get; set; }
    public string? Provider { get; set; }
    public string? Channel { get; set; }
    public string? Computer { get; set; }
    public string? UserId { get; set; }
    public int ProcessId { get; set; }
    public int ThreadId { get; set; }
    public string? Keywords { get; set; }
    public string? MapDescription { get; set; }
    public string? Payload { get; set; }
    public string? SourceFile { get; set; }
}

/// <summary>JLECmd: a single AutomaticDestinations jump-list entry (CSV output).</summary>
public class JumpListEntry
{
    public string? SourceFile { get; set; }
    public string? AppId { get; set; }
    public string? AppIdDescription { get; set; }
    public int EntryNumber { get; set; }
    public DateTime? CreationTime { get; set; }
    public DateTime? LastModified { get; set; }
    public string? Path { get; set; }
    public int InteractionCount { get; set; }
    public DateTime? TargetCreated { get; set; }
    public DateTime? TargetModified { get; set; }
    public DateTime? TargetAccessed { get; set; }
    public long FileSize { get; set; }
    public string? RelativePath { get; set; }
    public string? WorkingDirectory { get; set; }
    public string? Arguments { get; set; }
    public string? MachineID { get; set; }
    public string? VolumeSerialNumber { get; set; }

    public static JumpListEntry FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        SourceFile = r.Get("SourceFile"),
        AppId = r.Get("AppId"),
        AppIdDescription = r.Get("AppIdDescription"),
        EntryNumber = EzParse.ToInt(r.Get("EntryNumber")),
        CreationTime = EzParse.ToDate(r.Get("CreationTime")),
        LastModified = EzParse.ToDate(r.Get("LastModified")),
        Path = r.Get("Path"),
        InteractionCount = EzParse.ToInt(r.Get("InteractionCount")),
        TargetCreated = EzParse.ToDate(r.Get("TargetCreated")),
        TargetModified = EzParse.ToDate(r.Get("TargetModified")),
        TargetAccessed = EzParse.ToDate(r.Get("TargetAccessed")),
        FileSize = EzParse.ToLong(r.Get("FileSize")),
        RelativePath = r.Get("RelativePath"),
        WorkingDirectory = r.Get("WorkingDirectory"),
        Arguments = r.Get("Arguments"),
        MachineID = r.Get("MachineID"),
        VolumeSerialNumber = r.Get("VolumeSerialNumber"),
    };
}

/// <summary>
/// WxTCmd: a single Windows 10 Timeline activity (CSV output). NOTE: this image's
/// ActivitiesCache.db files contain no activities, so the field mapping is schema-derived
/// and not verified against real data.
/// </summary>
public class TimelineActivity
{
    public string? Id { get; set; }
    public string? ActivityType { get; set; }
    public string? Executable { get; set; }
    public string? DisplayText { get; set; }
    public string? ContentInfo { get; set; }
    public string? Payload { get; set; }
    public DateTime? StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public string? Duration { get; set; }
    public DateTime? LastModifiedTime { get; set; }
    public string? AppId { get; set; }

    public static TimelineActivity FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        Id = r.Get("Id"),
        ActivityType = r.Get("ActivityType"),
        Executable = r.Get("Executable"),
        DisplayText = r.Get("DisplayText"),
        ContentInfo = r.Get("ContentInfo"),
        Payload = r.Get("Payload"),
        StartTime = EzParse.ToDate(r.Get("StartTime")),
        EndTime = EzParse.ToDate(r.Get("EndTime")),
        Duration = r.Get("Duration"),
        LastModifiedTime = EzParse.ToDate(r.Get("LastModifiedTime")),
        AppId = r.Get("AppId"),
    };
}

/// <summary>RECmd: a single registry key/value matched by a batch (<c>--bn</c>) plugin (CSV output).</summary>
public class RegistryEntry
{
    public string HivePath { get; set; } = "";
    public string? HiveType { get; set; }
    public string? Description { get; set; }
    public string? Category { get; set; }
    public string? KeyPath { get; set; }
    public string? ValueName { get; set; }
    public string? ValueType { get; set; }
    public string? ValueData { get; set; }
    public string? ValueData2 { get; set; }
    public string? ValueData3 { get; set; }
    public string? Comment { get; set; }
    public bool Recursive { get; set; }
    public bool Deleted { get; set; }
    public DateTime? LastWriteTimestamp { get; set; }
    public string? PluginDetailFile { get; set; }

    public static RegistryEntry FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        HivePath = r.Get("HivePath") ?? "",
        HiveType = r.Get("HiveType"),
        Description = r.Get("Description"),
        Category = r.Get("Category"),
        KeyPath = r.Get("KeyPath"),
        ValueName = r.Get("ValueName"),
        ValueType = r.Get("ValueType"),
        ValueData = r.Get("ValueData"),
        ValueData2 = r.Get("ValueData2"),
        ValueData3 = r.Get("ValueData3"),
        Comment = r.Get("Comment"),
        Recursive = EzParse.ToBool(r.Get("Recursive")),
        Deleted = EzParse.ToBool(r.Get("Deleted")),
        LastWriteTimestamp = EzParse.ToDate(r.Get("LastWriteTimestamp")),
        PluginDetailFile = r.Get("PluginDetailFile"),
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
