namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

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

    /// <summary>
    /// Streams an l2tcsv file and maps the first <paramref name="maxRows"/> parseable data rows to raw events,
    /// canonicalized (optionally filtered). For sampling a contiguous (chronological — l2tcsv is time-sorted) prefix
    /// of a super timeline far too large to <see cref="File.ReadAllText(string)"/>: the full Studiawan benign
    /// timeline is ~770 MB / 2.2 M rows. Reads only as far into the file as the <paramref name="maxRows"/>th row.
    /// </summary>
    public static CanonicalEvent[] LoadCanonicalSampled(string path, int maxRows, Func<CanonicalEvent, bool>? keep = null) =>
        EventCanonicalizer.Canonicalize(LoadEventsSampled(path, maxRows), keep);

    /// <summary>Streams the first <paramref name="maxRows"/> parseable l2tcsv data rows into raw events.</summary>
    public static TimelineEvent[] LoadEventsSampled(string path, int maxRows)
    {
        using var reader = new StreamReader(path);
        var events = new List<TimelineEvent>(Math.Min(maxRows, 1 << 16));
        string[]? header = null;
        foreach (var record in StreamRecords(reader))
        {
            if (header is null) { header = record; continue; }       // first record is the column header
            if (TryMapRow(ToRow(header, record), out var ev)) events.Add(ev);
            if (events.Count >= maxRows) break;
        }
        return events.ToArray();
    }

    private static TimelineEvent[] ParseEvents(string csv)
    {
        var events = new List<TimelineEvent>();
        foreach (var row in Toolkit.ParseCsv(csv))
            if (TryMapRow(row, out var ev)) events.Add(ev);
        return events.ToArray();
    }

    // Maps one parsed l2tcsv row to a raw event; false for rows with an unparseable/pre-epoch datetime (e.g. the
    // 1601 expiry rows), which are skipped.
    private static bool TryMapRow(IReadOnlyDictionary<string, string> row, out TimelineEvent ev)
    {
        ev = null!;
        if (!TryParseMicros(Get(row, "datetime"), out long ts)) return false;

        var parser = Get(row, "parser");
        var displayName = Get(row, "display_name");
        var tag = Get(row, "tag");
        ev = new TimelineEvent
        {
            Timestamp = ts,
            TimestampDesc = Get(row, "timestamp_desc"),
            DataType = SynthesizeDataType(Get(row, "source"), parser),
            Parser = parser,
            Filename = displayName,
            DisplayName = displayName,
            Message = Get(row, "message"),
            Tag = tag is { Length: > 0 } && tag != "-" ? new EventTag { Labels = [tag] } : null,
        };
        return true;
    }

    // Quote-aware streaming CSV record reader — the buffered, early-stoppable equivalent of Toolkit.ParseCsv (same
    // RFC-4180 semantics: ""-escaped quotes, commas and newlines inside quoted fields), so we never materialise the
    // whole file. Yields one string[] per record.
    private static IEnumerable<string[]> StreamRecords(TextReader reader)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        var buf = new char[1 << 16];
        bool inQuotes = false, quotePending = false;     // quotePending: saw a '"' inside quotes, awaiting next char
        int n;
        while ((n = reader.Read(buf, 0, buf.Length)) > 0)
        {
            for (int i = 0; i < n; i++)
            {
                char c = buf[i];
                if (quotePending)
                {
                    quotePending = false;
                    if (c == '"') { sb.Append('"'); continue; }      // "" -> literal quote, still inside the field
                    inQuotes = false;                                // the quote closed the field; fall through
                }
                if (inQuotes)
                {
                    if (c == '"') quotePending = true;
                    else sb.Append(c);
                }
                else if (c == '"') inQuotes = true;
                else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
                else if (c == '\r') { }
                else if (c == '\n') { fields.Add(sb.ToString()); sb.Clear(); yield return fields.ToArray(); fields.Clear(); }
                else sb.Append(c);
            }
        }
        if (sb.Length > 0 || fields.Count > 0) { fields.Add(sb.ToString()); yield return fields.ToArray(); }
    }

    private static IReadOnlyDictionary<string, string> ToRow(string[] header, string[] record)
    {
        var d = new Dictionary<string, string>(header.Length, StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < header.Length && i < record.Length; i++) d[header[i]] = record[i];
        return d;
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
