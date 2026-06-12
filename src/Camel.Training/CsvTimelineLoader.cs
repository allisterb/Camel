namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

using Camel.Toolkits;
using Camel.Toolkits.Models;

/// <summary>
/// Loads a Plaso <c>l2tcsv</c> timeline export (the format of the Studiawan/Breitinger/Scanlon Windows 11
/// evaluation dataset and of <c>psort -o l2tcsv</c>) into the pipeline's <see cref="CanonicalEvent"/>s — entirely
/// locally, no SIFT workstation needed, since the CSVs are pre-extracted. The l2tcsv schema is
/// <c>datetime, timestamp_desc, source, source_long, message, parser, display_name, tag</c>; it lacks the
/// <c>data_type</c> field that json_line carries, so a behavioural data_type is synthesized from the authoritative
/// <c>source</c> column plus the <c>parser</c> — which lets the existing <see cref="EventCanonicalizer"/>
/// classifiers (and all their tests) apply unchanged.
/// </summary>
public static class CsvTimelineLoader
{
    /// <summary>Reads an l2tcsv file and canonicalizes it (sorted, with inter-event deltas); optionally filtered
    /// (e.g. <see cref="NoiseFilters.KeepHighSignal"/> to drop the filesystem-metadata firehose).</summary>
    public static CanonicalEvent[] LoadCanonical(string path, Func<CanonicalEvent, bool>? keep = null) =>
        EventCanonicalizer.Canonicalize(LoadEvents(path), keep);

    /// <summary>Parses l2tcsv <em>text</em> into canonical events (for in-memory use / testing).</summary>
    public static CanonicalEvent[] LoadCanonicalFromText(string csv, Func<CanonicalEvent, bool>? keep = null) =>
        EventCanonicalizer.Canonicalize(ParseEvents(csv), keep);

    /// <summary>Reads an l2tcsv file into raw <see cref="TimelineEvent"/>s (unsorted, as written).</summary>
    public static TimelineEvent[] LoadEvents(string path) => ParseEvents(File.ReadAllText(path));

    private static TimelineEvent[] ParseEvents(string csv)
    {
        var events = new List<TimelineEvent>();
        foreach (var row in Toolkit.ParseCsv(csv))
        {
            var datetime = Get(row, "datetime");
            if (!TryParseMicros(datetime, out long ts)) continue;     // unparseable / pre-epoch (e.g. 1601 expiry) -> skip

            var source = Get(row, "source");
            var parser = Get(row, "parser");
            var displayName = Get(row, "display_name");
            var tag = Get(row, "tag");

            events.Add(new TimelineEvent
            {
                Timestamp = ts,
                TimestampDesc = Get(row, "timestamp_desc"),
                DataType = SynthesizeDataType(source, parser),
                Parser = parser,
                Filename = displayName,
                DisplayName = displayName,
                Message = Get(row, "message"),
                Tag = tag is { Length: > 0 } && tag != "-" ? new EventTag { Labels = [tag] } : null,
            });
        }
        return events.ToArray();
    }

    // Builds a json_line-style data_type from the l2tcsv source code + parser so the canonicalizer's substring
    // classifiers fire correctly (e.g. REG + "winreg/bam" -> "windows:registry:bam" -> RegClass.Bam).
    private static string SynthesizeDataType(string? source, string? parser)
    {
        var p = (parser ?? "").Trim();
        var tail = p.Contains('/') ? p[(p.LastIndexOf('/') + 1)..] : p;     // "winreg/bam" -> "bam"
        return (source ?? "").Trim().ToUpperInvariant() switch
        {
            "REG" => $"windows:registry:{tail}",
            "EVT" => "windows:evtx:record",
            "FILE" => $"fs:{(tail.Length > 0 ? tail : "stat")}",
            "WEBHIST" => $"webhist:{tail}",
            "LNK" => "windows:lnk:link",
            "PRE" => "windows:prefetch:execution",
            "LOG" => $"syslog:{tail}",
            _ => p.Length > 0 ? p : "unknown",
        };
    }

    // l2tcsv datetimes are ISO-8601 with an explicit offset ("2023-12-26 00:36:37.906410+00:00"). Returns the
    // POSIX time in microseconds; false for unparseable values or times at/before the Unix epoch.
    private static bool TryParseMicros(string? datetime, out long micros)
    {
        micros = 0;
        if (string.IsNullOrWhiteSpace(datetime) ||
            !DateTimeOffset.TryParse(datetime, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
            return false;
        long us = (dto.ToUniversalTime() - DateTimeOffset.UnixEpoch).Ticks / 10;   // 100ns ticks -> microseconds
        if (us <= 0) return false;
        micros = us;
        return true;
    }

    private static string? Get(IReadOnlyDictionary<string, string> row, string key) =>
        row.TryGetValue(key, out var v) ? v : null;
}
