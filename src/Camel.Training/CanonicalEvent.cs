namespace Camel.Training;

using System;

/// <summary>
/// The model-ready, normalized form of a single timeline event — the substrate the representation-learning,
/// anomaly-detection and triage pipelines train on. Raw Plaso events are too high-cardinality and too
/// <em>label-leaky</em> to feed a model directly (a literal <c>\Temp\evil.exe</c> path lets a model shortcut on
/// the string instead of the behaviour), so canonicalization collapses the unbounded free-text fields into small
/// behavioural vocabularies (<see cref="Source"/>, <see cref="Location"/>, <see cref="Reg"/>, <see cref="Macb"/>)
/// while preserving the temporal signal (<see cref="DtPrev"/>, <see cref="HourOfDay"/>). The labels are carried
/// for <em>supervision targets</em>, never as an input feature.
/// </summary>
public sealed record CanonicalEvent
{
    /// <summary>Event time as a POSIX timestamp in microseconds (UTC) — preserved verbatim for windowing/ordering.</summary>
    public required long Ts { get; init; }

    /// <summary>The raw Plaso <c>data_type</c> (e.g. "windows:registry:appcompatcache") — the primary "what" token.</summary>
    public required string DataType { get; init; }

    /// <summary>Coarse source class derived from <see cref="DataType"/>.</summary>
    public SourceClass Source { get; init; }

    /// <summary>Which MACB timestamp role(s) this event represents (from the Plaso timestamp description).</summary>
    public Macb Macb { get; init; }

    /// <summary>Behavioural location class of the event's path (collapses the leaky filename to ~a dozen classes).</summary>
    public LocBucket Location { get; init; }

    /// <summary>Lower-cased file extension of the event's path (e.g. "exe", "dll", "ps1"), or null.</summary>
    public string? Ext { get; init; }

    /// <summary>Windows event-log Event ID parsed from the message (e.g. 4624), or null for non-EVTX events.</summary>
    public int? EventId { get; init; }

    /// <summary>
    /// Character length of the event's rendered message — a leakage-safe content <em>scalar</em> (the count, never
    /// the literal text). Encoded-PowerShell blobs and verbose error records run far longer than routine messages,
    /// so an outlier length is a cheap signal the structural fields miss (after Studiawan 2020, Ch. 7).
    /// </summary>
    public int MsgLength { get; init; }

    /// <summary>
    /// Count of suspicious DFIR keywords (download cradles, LOLBin/offensive-tooling names) found in the message —
    /// a curated, training-free "content surprisal" scalar (see <see cref="ContentSignals"/>). Targets the gap the
    /// type/sequence/timing detectors are blind to: malicious <em>content</em> inside a common event type.
    /// </summary>
    public int BadWordCount { get; init; }

    /// <summary>Registry artifact class for registry events (Run / Service / Shimcache / …), else <see cref="RegClass.None"/>.</summary>
    public RegClass Reg { get; init; }

    /// <summary>
    /// Natural-log-compressed seconds since the previous event in time order — <c>ln(1 + Δseconds)</c>. 0 for the
    /// first event. This is the inter-event temporal feature (bursts vs. quiet periods) the sequence models key on.
    /// </summary>
    public float DtPrev { get; init; }

    /// <summary>Hour of day (0–23, UTC) — a cyclic feature for diurnal-pattern modelling.</summary>
    public int HourOfDay { get; init; }

    /// <summary>The Plaso tagging labels on the event ("application_execution", …) — supervision target, not input.</summary>
    public string[] Labels { get; init; } = [];

    /// <summary>The event time as a UTC <see cref="DateTimeOffset"/>.</summary>
    public DateTimeOffset Time => DateTimeOffset.FromUnixTimeMilliseconds(Ts / 1000);
}

/// <summary>MACB timestamp role(s): Modified / Accessed / metadata Changed / Birth (created). A single event can
/// carry several (e.g. a bodyfile MACB-grouped row).</summary>
[Flags]
public enum Macb { None = 0, Modified = 1, Accessed = 2, Changed = 4, Birth = 8 }

/// <summary>Coarse source class derived from the Plaso <c>data_type</c>.</summary>
public enum SourceClass { Other = 0, FileSystem, Registry, EventLog, WebHistory, Lnk, Prefetch, Log }

/// <summary>
/// Behavioural location class for a file path. Collapses the high-cardinality, label-leaky filename into the
/// handful of classes the methodology actually reasons about (e.g. "a system-process name running from
/// <see cref="Temp"/>" is the signal, not the exact path).
/// </summary>
public enum LocBucket { Unknown = 0, System32, SysWow64, WindowsOther, ProgramFiles, ProgramData, UsersProfile, AppData, Temp, Recycle, Network, Root, Other }

/// <summary>Registry artifact class for registry events — the forensic key categories.</summary>
public enum RegClass { None = 0, Run, Service, Shimcache, Amcache, UserAssist, Bam, MountPoints, UsbStor, Network, Bagmru, Mru, TaskCache, Winlogon, Other }
