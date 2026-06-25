namespace Camel.DFIR.Toolkits.Models;

using System.Collections.Generic;
using System.Text.Json;

// DFIR-specific Timeline-toolkit outputs (hayabusa Sigma detections + metrics, plaso pinfo). The
// shared canonical TimelineEvent/EventTag live in the neutral Camel.Toolkits (Camel.Toolkits.Models),
// because they bridge to the lean Camel.Inference core. EzParse/Get (used by the FromRow factories
// below) are internal helpers in this same assembly (WindowsAnalysisModels.cs).

/// <summary>A single hayabusa Sigma detection from json-timeline (JSONL output, standard profile).</summary>
public class HayabusaAlert
{
    public string? Timestamp { get; set; }
    public string? RuleTitle { get; set; }
    public string? Level { get; set; }
    public string? Computer { get; set; }
    public string? Channel { get; set; }
    public int EventID { get; set; }
    public long RecordID { get; set; }
    public string? RuleID { get; set; }
    /// <summary>Rule-specific extracted fields (shape varies per detection).</summary>
    public JsonElement Details { get; set; }
    /// <summary>Additional raw event fields not surfaced in <see cref="Details"/>.</summary>
    public JsonElement ExtraFieldInfo { get; set; }
}

/// <summary>hayabusa computer-metrics: per-computer event totals (CSV).</summary>
public class ComputerMetric
{
    public string Computer { get; set; } = "";
    public string? OsInformation { get; set; }
    public string? UpTime { get; set; }
    public string? Timezone { get; set; }
    public long Events { get; set; }

    public static ComputerMetric FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        Computer = r.Get("Computer") ?? "",
        OsInformation = r.Get("OS information"),
        UpTime = r.Get("UpTime"),
        Timezone = r.Get("Timezone"),
        Events = EzParse.ToLong(r.Get("Events")),
    };
}

/// <summary>hayabusa eid-metrics: event-ID frequency (CSV).</summary>
public class EidMetric
{
    public long Total { get; set; }
    public string? Percent { get; set; }
    public string? Channel { get; set; }
    public int EventId { get; set; }
    public string? Event { get; set; }

    public static EidMetric FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        Total = EzParse.ToLong(r.Get("Total")),
        Percent = r.Get("%"),
        Channel = r.Get("Channel"),
        EventId = EzParse.ToInt(r.Get("ID")),
        Event = r.Get("Event"),
    };
}

/// <summary>hayabusa log-metrics: per-evtx-file metadata (CSV).</summary>
public class LogMetric
{
    public string Filename { get; set; } = "";
    public string? Computers { get; set; }
    public long Events { get; set; }
    public string? FirstTimestamp { get; set; }
    public string? LastTimestamp { get; set; }
    public string? Channels { get; set; }
    public string? Providers { get; set; }
    public string? Size { get; set; }

    public static LogMetric FromRow(IReadOnlyDictionary<string, string> r) => new()
    {
        Filename = r.Get("Filename") ?? "",
        Computers = r.Get("Computers"),
        Events = EzParse.ToLong(r.Get("Events")),
        FirstTimestamp = r.Get("First Timestamp"),
        LastTimestamp = r.Get("Last Timestamp"),
        Channels = r.Get("Channels"),
        Providers = r.Get("Providers"),
        Size = r.Get("Size"),
    };
}

/// <summary>hayabusa logon-summary: a logon record (successful or failed; CSV).</summary>
public class LogonSummaryEntry
{
    public bool Successful { get; set; }
    public long Count { get; set; }
    public string? Event { get; set; }
    public string? TargetAccount { get; set; }
    public string? TargetDomain { get; set; }
    public string? TargetComputer { get; set; }
    public string? LogonType { get; set; }
    public string? SourceAccount { get; set; }
    public string? SourceDomain { get; set; }
    public string? SourceComputer { get; set; }
    public string? SourceIpAddress { get; set; }

    public static LogonSummaryEntry FromRow(IReadOnlyDictionary<string, string> r, bool successful) => new()
    {
        Successful = successful,
        Count = EzParse.ToLong(r.Get(successful ? "Successful" : "Failed")),
        Event = r.Get("Event"),
        TargetAccount = r.Get("Target Account"),
        TargetDomain = r.Get("Target Domain"),
        TargetComputer = r.Get("Target Computer"),
        LogonType = r.Get("Logon Type"),
        SourceAccount = r.Get("Source Account"),
        SourceDomain = r.Get("Source Domain"),
        SourceComputer = r.Get("Source Computer"),
        SourceIpAddress = r.Get("Source IP Address"),
    };
}

/// <summary>pinfo --output-format json: parser hit statistics for a .plaso storage file.</summary>
public class PlasoInfo
{
    /// <summary>Per-parser event counts (includes a "total" entry).</summary>
    public Dictionary<string, long> ParserCounts { get; set; } = new();

    /// <summary>Total event count across all parsers.</summary>
    public long TotalEvents => ParserCounts.TryGetValue("total", out var t) ? t : 0;

    public static PlasoInfo Parse(string json)
    {
        var info = new PlasoInfo();
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("storage_counters", out var sc) &&
            sc.TryGetProperty("parsers", out var parsers) &&
            parsers.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in parsers.EnumerateObject())
                if (p.Value.TryGetInt64(out var n)) info.ParserCounts[p.Name] = n;
        }
        return info;
    }
}
