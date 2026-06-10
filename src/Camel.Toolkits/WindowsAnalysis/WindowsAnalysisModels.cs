namespace Camel.Toolkits.Models;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

/// <summary>
/// Describes the CSV output of an EvtxECmd run: where the CSV was written (<see cref="OutputDirectory"/> /
/// <see cref="OutputFile"/>) and EvtxECmd's parse summary (<see cref="RecordsIncluded"/>, <see cref="Errors"/>,
/// <see cref="EventsDropped"/>), parsed from its console output.
/// </summary>
public class EvtxECmdCsvResult
{
    public string? OutputDirectory { get; set; }
    public string? OutputFile { get; set; }
    public int RecordsIncluded { get; set; }
    public int Errors { get; set; }
    public int EventsDropped { get; set; }

    public static EvtxECmdCsvResult Parse(string stdout, string? outputDir, string? outputFile)
    {
        var m = Regex.Match(stdout, @"Records included:\s*(\d+)\s+Errors:\s*(\d+)\s+Events dropped:\s*(\d+)");
        return new EvtxECmdCsvResult
        {
            OutputDirectory = outputDir,
            // EvtxECmd writes <--csv dir>/<--csvf name>; resolve the full path when both are known.
            OutputFile = outputFile is not null && outputDir is not null
                ? $"{outputDir.TrimEnd('/')}/{outputFile}"
                : outputFile,
            RecordsIncluded = m.Success ? int.Parse(m.Groups[1].Value) : 0,
            Errors = m.Success ? int.Parse(m.Groups[2].Value) : 0,
            EventsDropped = m.Success ? int.Parse(m.Groups[3].Value) : 0,
        };
    }
}

/// <summary>
/// Describes the output of an MFTECmd run (CSV or bodyfile): where the output file was written
/// (<see cref="OutputDirectory"/> / <see cref="OutputFile"/>) and the record counts MFTECmd reported
/// (<see cref="FileRecords"/> FILE records, <see cref="FreeRecords"/> free/deleted records), parsed from its
/// console output.
/// </summary>
public class MFTECmdResult
{
    public string? OutputDirectory { get; set; }
    public string? OutputFile { get; set; }
    public int FileRecords { get; set; }
    public int FreeRecords { get; set; }

    public static MFTECmdResult Parse(string stdout, string? outputDir, string? outputFile)
    {
        // e.g. "FILE records found: 15,617 (Free records: 0)" — counts carry thousands separators.
        var m = Regex.Match(stdout, @"FILE records found:\s*([\d,]+)\s*\(Free records:\s*([\d,]+)\)");
        static int N(string s) => int.Parse(s, NumberStyles.AllowThousands, CultureInfo.InvariantCulture);
        return new MFTECmdResult
        {
            OutputDirectory = outputDir,
            OutputFile = outputFile is not null && outputDir is not null
                ? $"{outputDir.TrimEnd('/')}/{outputFile}"
                : outputFile,
            FileRecords = m.Success ? N(m.Groups[1].Value) : 0,
            FreeRecords = m.Success ? N(m.Groups[2].Value) : 0,
        };
    }
}

/// <summary>
/// Describes the CSV output of an SBECmd (shellbags) run: the output directory (<see cref="OutputDirectory"/>),
/// the per-hive CSV files SBECmd wrote into it (<see cref="CsvFiles"/> — SBECmd names them after each hive and
/// has no single output file), and the total shellbags found (<see cref="TotalShellBags"/>, from its console output).
/// </summary>
public class SBECmdCsvResult
{
    public string? OutputDirectory { get; set; }
    public string[] CsvFiles { get; set; } = [];
    public int TotalShellBags { get; set; }

    public static SBECmdCsvResult Parse(string stdout, string? outputDir, string[] csvFiles) => new()
    {
        OutputDirectory = outputDir,
        CsvFiles = csvFiles,
        TotalShellBags = Regex.Match(stdout, @"Total ShellBags found:\s*(\d+)") is { Success: true } m
            ? int.Parse(m.Groups[1].Value) : 0,
    };
}

/// <summary>
/// The raw result of running a single RegRipper (<c>rip.pl</c>) plugin against one registry hive: the
/// <see cref="Plugin"/> name, the source <see cref="Hive"/>, the plugin <see cref="Version"/> (from its
/// banner), and the plugin's full text <see cref="Output"/> pre-split into <see cref="Lines"/>. RegRipper
/// plugins each emit their own bespoke text format (key/value listings, CSV, block records), so the toolkit
/// returns the output faithfully and leaves plugin-specific parsing to the caller.
/// </summary>
public class RegRipperResult
{
    public string Plugin { get; set; } = "";
    public string Hive { get; set; } = "";
    public string? Version { get; set; }
    public string Output { get; set; } = "";
    public string[] Lines { get; set; } = [];

    public static RegRipperResult Parse(string plugin, string hive, string stdout)
    {
        // Banner is the first line, e.g. "run v.20200511".
        var version = Regex.Match(stdout, @"v\.?\s*(\d[\d.]*)") is { Success: true } m ? m.Groups[1].Value : null;
        return new RegRipperResult
        {
            Plugin = plugin,
            Hive = hive,
            Version = version,
            Output = stdout,
            Lines = stdout.Replace("\r", "").Split('\n'),
        };
    }
}

/// <summary>
/// One Windows scheduled task parsed from its Task Scheduler 2.0 XML definition (a file under
/// <c>\Windows\System32\Tasks</c>). <see cref="Command"/> / <see cref="Arguments"/> are the first <c>Exec</c>
/// action's program and arguments — the execution payload that the registry TaskCache does <em>not</em> store,
/// so recovering it requires parsing these XML files. Tasks whose action is a COM handler (not <c>Exec</c>)
/// have a null <see cref="Command"/>.
/// </summary>
public class ScheduledTaskEntry
{
    public string TaskFile { get; set; } = "";
    public string? Uri { get; set; }
    public string? Author { get; set; }
    public string? Command { get; set; }
    public string? Arguments { get; set; }
    public string? WorkingDirectory { get; set; }

    /// <summary>
    /// Parses the concatenated output of the task extraction command — chunks separated by
    /// <paramref name="delimiter"/>, each beginning with the task file path on its own line followed by the
    /// (UTF-8-transcoded) task XML — into one entry per task.
    /// </summary>
    public static ScheduledTaskEntry[] ParseMany(string output, string delimiter) =>
        output.Split(delimiter, StringSplitOptions.RemoveEmptyEntries)
            .Select(ParseChunk).Where(t => t is not null).Select(t => t!).ToArray();

    private static ScheduledTaskEntry? ParseChunk(string chunk)
    {
        int nl = chunk.IndexOf('\n');
        if (nl < 0) return null;
        var file = chunk[..nl].Trim();
        // Strip any stray NULs (a non-transcoded byte) and the UTF-8/UTF-16 BOM before parsing.
        var xml = chunk[(nl + 1)..].Replace("\0", "").Trim().TrimStart('﻿');
        if (file.Length == 0) return null;
        if (xml.Length == 0) return new ScheduledTaskEntry { TaskFile = file };

        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch { return new ScheduledTaskEntry { TaskFile = file }; } // keep it enumerated even if unparseable

        // Task XML lives in the Task Scheduler default namespace; match by local name to stay namespace-agnostic.
        string? First(string name) => doc.Descendants().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim();
        var exec = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Exec");
        string? ExecChild(string name) => exec?.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim();
        return new ScheduledTaskEntry
        {
            TaskFile = file,
            Uri = First("URI"),
            Author = First("Author"),
            Command = ExecChild("Command"),
            Arguments = ExecChild("Arguments"),
            WorkingDirectory = ExecChild("WorkingDirectory"),
        };
    }
}

/// <summary>
/// An in-memory index of the LOLBAS (Living Off the Land Binaries And Scripts) dataset, built from the
/// project's <c>lolbas.json</c>. Maps each known abusable binary name to its canonical install path(s), so
/// detection workflows can ask two questions: is this program a LOLBin, and — if it is — is it running from the
/// location Windows actually ships it (a mismatch is a strong masquerading indicator).
/// </summary>
public class LolbasReference
{
    // Lowercased binary name (e.g. "rundll32.exe") -> its canonical Full_Path entries (normalized).
    private readonly Dictionary<string, string[]> _byName;
    private LolbasReference(Dictionary<string, string[]> byName) => _byName = byName;

    public int Count => _byName.Count;

    /// <summary>True if <paramref name="fileName"/> (a bare binary name) is a known LOLBAS entry.</summary>
    public bool IsLolbin(string fileName) => _byName.ContainsKey(Norm(fileName));

    /// <summary>The canonical install paths LOLBAS records for <paramref name="fileName"/> (empty if unknown).</summary>
    public string[] CanonicalPaths(string fileName) => _byName.TryGetValue(Norm(fileName), out var p) ? p : [];

    /// <summary>
    /// True when <paramref name="programPath"/> (a full path that includes a directory) sits in one of the
    /// binary's canonical locations. Compared after stripping the volume root and expanding
    /// <c>%SystemRoot%</c>/<c>%windir%</c>, so <c>%SystemRoot%\system32\x.exe</c> and <c>C:\Windows\System32\x.exe</c>
    /// match. Returns true (i.e. "not a masquerade") when the binary has no recorded canonical path.
    /// </summary>
    public bool IsCanonicalPath(string fileName, string programPath)
    {
        var paths = CanonicalPaths(fileName);
        if (paths.Length == 0) return true;
        var p = StripRoot(NormPath(programPath));
        return paths.Any(c => StripRoot(c) == p);
    }

    /// <summary>Parses the LOLBAS <c>lolbas.json</c> array into an index, or null if it can't be parsed.</summary>
    public static LolbasReference? Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var dict = new Dictionary<string, string[]>();
            foreach (var entry in doc.RootElement.EnumerateArray())
            {
                if (!entry.TryGetProperty("Name", out var nameEl) || Norm(nameEl.GetString() ?? "") is not { Length: > 0 } name)
                    continue;
                var paths = new List<string>();
                if (entry.TryGetProperty("Full_Path", out var fp) && fp.ValueKind == JsonValueKind.Array)
                    foreach (var pe in fp.EnumerateArray())
                        if (pe.TryGetProperty("Path", out var pathEl) && pathEl.GetString() is { Length: > 0 } pv)
                            paths.Add(NormPath(pv));
                dict[name] = paths.Distinct().ToArray();
            }
            return dict.Count > 0 ? new LolbasReference(dict) : null;
        }
        catch { return null; }
    }

    private static string Norm(string s) => s.Trim().ToLowerInvariant();
    private static string NormPath(string s) => s.Trim().ToLowerInvariant().Replace('/', '\\');
    // Expand the common system-dir env vars and drop the "c:" volume prefix so paths compare regardless of root.
    private static string StripRoot(string p)
    {
        p = p.Replace("%systemroot%", "c:\\windows").Replace("%windir%", "c:\\windows").Replace("%systemdrive%", "c:");
        int colon = p.IndexOf(':');
        return colon >= 0 ? p[(colon + 1)..] : p;
    }
}

/// <summary>One WMI event consumer recovered from the repository: its class <see cref="Type"/> (e.g.
/// <c>CommandLineEventConsumer</c>), its <see cref="Name"/>, and the action <see cref="Command"/> (command line
/// or script text) recovered from the adjacent strings when one was found.</summary>
public class WmiConsumer
{
    public string Type { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Command { get; set; }
}

/// <summary>A WMI <c>FilterToConsumerBinding</c>: the consumer (action) and the event filter (trigger) it is bound to.</summary>
public class WmiBinding
{
    public string ConsumerName { get; set; } = "";
    public string FilterName { get; set; } = "";
}

/// <summary>
/// The WMI subscription artifacts recovered from a repository's <c>OBJECTS.DATA</c> by string-scraping (the
/// offline technique from the methodology, since the binary repository format has no Linux parser): the event
/// <see cref="Consumers"/> (with any recovered action), the event <see cref="Filters"/>, and the
/// <see cref="Bindings"/> tying them together. This is a best-effort reconstruction — consumer→command
/// association is by string proximity — intended to surface persistence leads, not a full repository parse.
/// </summary>
public class WmiSubscriptions
{
    public WmiConsumer[] Consumers { get; set; } = [];
    public string[] Filters { get; set; } = [];
    public WmiBinding[] Bindings { get; set; } = [];

    // A WMI consumer/filter is stored as a typed instance reference, e.g. CommandLineEventConsumer.Name="X".
    private static readonly Regex ConsumerMarker = new(@"^([A-Za-z]+EventConsumer)\.Name=""([^""]+)""", RegexOptions.Compiled);
    private static readonly Regex FilterMarker = new(@"^__EventFilter\.Name=""([^""]+)""", RegexOptions.Compiled);
    // A string that looks like a consumer action (command line or script), used to recover a consumer's payload.
    private static readonly Regex Payload = new(
        @"powershell|cmd\.exe|cscript|wscript|rundll32|regsvr32|mshta|\.vbs|\.ps1|\.bat|\.exe|https?://|new-object|activexobject|frombase64|downloadstring|\biex\b|-e[a-z]*\s",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex OffsetLine = new(@"^\s*(\d+)\s(.*)$", RegexOptions.Compiled);

    /// <summary>
    /// Parses the offset-tagged <c>strings -t d</c> output (ASCII and UTF-16LE passes) of an OBJECTS.DATA file.
    /// Merging both encodings by file offset keeps each consumer's command/script adjacent to its record so it
    /// can be recovered by proximity.
    /// </summary>
    public static WmiSubscriptions Parse(string ascii, string unicode)
    {
        var ordered = Merge(ascii, unicode);
        var consumers = new List<WmiConsumer>();
        var bindings = new List<WmiBinding>();
        var filters = new List<string>();
        for (int i = 0; i < ordered.Length; i++)
        {
            if (FilterMarker.Match(ordered[i]) is { Success: true } fm)
                filters.Add(fm.Groups[1].Value);
            if (ConsumerMarker.Match(ordered[i]) is not { Success: true } cm) continue;

            var name = cm.Groups[2].Value;
            // Recover the action: the nearest preceding string (within a small window) that looks like a command.
            string? command = null;
            for (int j = i - 1; j >= 0 && j >= i - 8; j--)
                if (ordered[j] != name && Payload.IsMatch(ordered[j])) { command = ordered[j]; break; }
            consumers.Add(new WmiConsumer { Type = cm.Groups[1].Value, Name = name, Command = command });
            // The bound filter is recorded immediately after the consumer reference.
            for (int k = i + 1; k <= i + 2 && k < ordered.Length; k++)
                if (FilterMarker.Match(ordered[k]) is { Success: true } bf)
                { bindings.Add(new WmiBinding { ConsumerName = name, FilterName = bf.Groups[1].Value }); break; }
        }
        return new WmiSubscriptions
        {
            // OBJECTS.DATA keeps several copies of each record; collapse to one consumer per type+name,
            // preferring the copy whose command we recovered.
            Consumers = consumers.GroupBy(c => (c.Type, c.Name))
                .Select(g => g.FirstOrDefault(c => c.Command is not null) ?? g.First()).ToArray(),
            Filters = filters.Distinct().ToArray(),
            Bindings = bindings.DistinctBy(b => (b.ConsumerName, b.FilterName)).ToArray(),
        };
    }

    // Parse "<offset> <string>" lines from both passes and return the strings in ascending file-offset order.
    private static string[] Merge(string ascii, string unicode)
    {
        var list = new List<(long off, string text)>();
        foreach (var src in new[] { ascii, unicode })
            foreach (var line in src.Split('\n'))
                if (OffsetLine.Match(line) is { Success: true } m)
                    list.Add((long.Parse(m.Groups[1].Value), m.Groups[2].Value.TrimEnd('\r')));
        return list.OrderBy(x => x.off).Select(x => x.text).ToArray();
    }
}

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
