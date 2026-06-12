namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Camel.Toolkits.Models;

/// <summary>
/// Converts raw Plaso <see cref="TimelineEvent"/>s (from psort) into the normalized <see cref="CanonicalEvent"/>
/// substrate the ML pipeline consumes. Events are sorted by time, the inter-event delta is computed, and each
/// high-cardinality/leaky field is mapped to a small behavioural vocabulary. Pure and deterministic — the same
/// input always yields the same output, so it is safe to cache and to unit-test without a workstation.
/// </summary>
public static partial class EventCanonicalizer
{
    /// <summary>
    /// Canonicalizes a batch of timeline events. Events without a timestamp are dropped; the rest are returned in
    /// ascending time order. When <paramref name="keep"/> is supplied it filters the canonicalized events (e.g.
    /// <see cref="NoiseFilters.KeepHighSignal"/> to drop the filestat/usnjrnl firehose) — and
    /// <see cref="CanonicalEvent.DtPrev"/> is then computed over the <em>surviving</em> events, so the inter-event
    /// delta reflects the filtered stream rather than the dropped noise.
    /// </summary>
    public static CanonicalEvent[] Canonicalize(IEnumerable<TimelineEvent> events, Func<CanonicalEvent, bool>? keep = null)
    {
        var built = events.Where(e => e.Timestamp > 0).OrderBy(e => e.Timestamp).Select(Build).ToArray();
        var kept = keep is null ? built : Array.FindAll(built, e => keep(e));
        return WithDeltas(kept);
    }

    /// <summary>
    /// Finalizes already-canonical events from a non-Plaso source (e.g. a pre-distilled CSV): time-sorts, filters,
    /// and recomputes <see cref="CanonicalEvent.DtPrev"/> over the survivors — the <see cref="Canonicalize"/> tail
    /// without the <see cref="TimelineEvent"/> build step.
    /// </summary>
    public static CanonicalEvent[] Order(IEnumerable<CanonicalEvent> events, Func<CanonicalEvent, bool>? keep = null)
    {
        var built = events.Where(e => e.Ts > 0).OrderBy(e => e.Ts).ToArray();
        var kept = keep is null ? built : Array.FindAll(built, e => keep(e));
        return WithDeltas(kept);
    }

    // Canonicalizes one event (DtPrev is filled in later by WithDeltas, once the kept set is known).
    private static CanonicalEvent Build(TimelineEvent e)
    {
        var path = e.Filename ?? e.DisplayName ?? "";
        return new CanonicalEvent
        {
            Ts = e.Timestamp,
            DataType = string.IsNullOrEmpty(e.DataType) ? "unknown" : e.DataType,
            Source = ClassifySource(e.DataType),
            Macb = ClassifyMacb(e.TimestampDesc),
            Location = ClassifyLocation(path),
            Ext = ExtractExt(path),
            EventId = ExtractEventId(e.Message),
            MsgLength = ContentSignals.MsgLength(e.Message),
            BadWordCount = ContentSignals.BadWordCount(e.Message),
            Reg = ClassifyReg(e.DataType),
            DtPrev = 0f,
            HourOfDay = e.Time.UtcDateTime.Hour,
            Labels = e.Labels,
        };
    }

    // Fills in DtPrev = ln(1 + Δseconds) over an already-time-sorted array (in place via record-with).
    private static CanonicalEvent[] WithDeltas(CanonicalEvent[] sorted)
    {
        long? prev = null;
        for (int i = 0; i < sorted.Length; i++)
        {
            float dt = prev is { } p ? (float)Math.Log(1 + Math.Max(0, sorted[i].Ts - p) / 1_000_000.0) : 0f;
            sorted[i] = sorted[i] with { DtPrev = dt };
            prev = sorted[i].Ts;
        }
        return sorted;
    }

    // --- field normalizers (all case-insensitive substring tests over the lower-cased value) ---

    /// <summary>Maps a Plaso data_type to a coarse <see cref="SourceClass"/>.</summary>
    public static SourceClass ClassifySource(string? dataType)
    {
        var d = (dataType ?? "").ToLowerInvariant();
        if (d.Length == 0) return SourceClass.Other;
        if (d.Contains("registry")) return SourceClass.Registry;
        if (d.Contains("evtx") || d.Contains("evt:") || d.Contains(":evt")) return SourceClass.EventLog;
        if (d.Contains("lnk")) return SourceClass.Lnk;
        if (d.Contains("prefetch")) return SourceClass.Prefetch;
        if (d.StartsWith("fs:") || d.Contains("filestat") || d.Contains("bodyfile") || d.Contains("ntfs")) return SourceClass.FileSystem;
        if (d.Contains("msiecf") || d.Contains("firefox") || d.Contains("chrome") || d.Contains("safari") ||
            d.Contains("opera") || d.Contains("webhist") || d.Contains("cookie") || d.Contains("page_visited") || d.Contains(":url"))
            return SourceClass.WebHistory;
        if (d.Contains("syslog") || d.EndsWith(":log") || d.Contains(":log:")) return SourceClass.Log;
        return SourceClass.Other;
    }

    /// <summary>Maps a Plaso timestamp description (e.g. "Content Modification Time") to MACB role flags.</summary>
    public static Macb ClassifyMacb(string? timestampDesc)
    {
        var t = (timestampDesc ?? "").ToLowerInvariant();
        if (t.Length == 0) return Macb.None;
        var m = Macb.None;
        if (t.Contains("creation") || t.Contains("birth") || t.Contains("created")) m |= Macb.Birth;
        // Metadata-change descriptions ("Metadata Modification Time", "Change Time") are the C in MACB, not M —
        // matched first so the "modif" substring they share with content-modification doesn't also set Modified.
        if (t.Contains("metadata") || t.Contains("entry modif") || t.Contains("change"))
            m |= Macb.Changed;
        else if (t.Contains("modif") || t.Contains("written") || t.Contains("content"))
            m |= Macb.Modified;
        if (t.Contains("access") || t.Contains("visited") || t.Contains("executed") || t.Contains("connection")) m |= Macb.Accessed;
        return m;
    }

    // Location classes, in priority order — the first matching fragment wins. AppData/Temp/Recycle are tested
    // before the broader Users/Windows buckets they nest inside so they don't get swallowed.
    private static readonly (string Fragment, LocBucket Bucket)[] LocationRules =
    [
        ("$recycle", LocBucket.Recycle), ("/recycler/", LocBucket.Recycle),
        ("/appdata/", LocBucket.AppData),
        ("/windows/temp/", LocBucket.Temp), ("/temp/", LocBucket.Temp), ("/tmp/", LocBucket.Temp),
        ("/syswow64/", LocBucket.SysWow64),
        ("/system32/", LocBucket.System32),
        ("/program files", LocBucket.ProgramFiles),
        ("/programdata/", LocBucket.ProgramData),
        ("/users/", LocBucket.UsersProfile), ("/documents and settings/", LocBucket.UsersProfile),
        ("/windows/", LocBucket.WindowsOther),
    ];

    /// <summary>Maps a file path to a behavioural <see cref="LocBucket"/> (normalizing separators and case).</summary>
    public static LocBucket ClassifyLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return LocBucket.Unknown;
        var p = path.Replace('\\', '/').ToLowerInvariant();
        // Strip a Plaso display-name scheme prefix like "OS:" / "TSK:" so the path fragments match.
        int scheme = p.IndexOf(":/", StringComparison.Ordinal);
        if (scheme is > 0 and < 6) p = p[(scheme + 1)..];
        if (p.StartsWith("//") || p.Contains("://")) return LocBucket.Network;          // UNC / remote
        foreach (var (frag, bucket) in LocationRules)
            if (p.Contains(frag)) return bucket;
        // A bare drive/volume root (e.g. "/", "/c", "c:/") with no further path.
        return p.Trim('/').Count(c => c == '/') == 0 && p.Length <= 4 ? LocBucket.Root : LocBucket.Other;
    }

    /// <summary>Extracts a short lower-cased file extension from a path, or null when there isn't a plausible one.</summary>
    public static string? ExtractExt(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        var name = path.Replace('\\', '/');
        int slash = name.LastIndexOf('/');
        if (slash >= 0) name = name[(slash + 1)..];
        int dot = name.LastIndexOf('.');
        if (dot <= 0 || dot == name.Length - 1) return null;
        var ext = name[(dot + 1)..].ToLowerInvariant();
        return ext.Length is > 0 and <= 5 && ext.All(char.IsLetterOrDigit) ? ext : null;
    }

    [GeneratedRegex(@"^\s*\[(\d{1,6})\s*/")]
    private static partial Regex EventIdRegex();

    /// <summary>Parses the leading Event ID from a Plaso EVTX message (rendered as "[4624 / 0x1210] …"), or null.</summary>
    public static int? ExtractEventId(string? message) =>
        message is not null && EventIdRegex().Match(message) is { Success: true } m && int.TryParse(m.Groups[1].Value, out var id)
            ? id : null;

    // Registry artifact classes keyed by a fragment of the registry data_type (checked in order).
    private static readonly (string Fragment, RegClass Class)[] RegRules =
    [
        ("appcompatcache", RegClass.Shimcache), ("amcache", RegClass.Amcache), ("userassist", RegClass.UserAssist),
        ("bam", RegClass.Bam), ("mountpoints", RegClass.MountPoints), ("usbstor", RegClass.UsbStor),
        ("usb_devices", RegClass.UsbStor), ("bagmru", RegClass.Bagmru), ("mrulist", RegClass.Mru), ("mru", RegClass.Mru),
        ("task_cache", RegClass.TaskCache), ("winlogon", RegClass.Winlogon), ("service", RegClass.Service),
        ("run", RegClass.Run), ("network", RegClass.Network),
    ];

    /// <summary>Maps a registry data_type to a <see cref="RegClass"/>; <see cref="RegClass.None"/> for non-registry events.</summary>
    public static RegClass ClassifyReg(string? dataType)
    {
        var d = (dataType ?? "").ToLowerInvariant();
        if (!d.Contains("registry")) return RegClass.None;
        foreach (var (frag, cls) in RegRules)
            if (d.Contains(frag)) return cls;
        return RegClass.Other;
    }
}
