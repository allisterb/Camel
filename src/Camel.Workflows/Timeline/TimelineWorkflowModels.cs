namespace Camel.Workflows.Models;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;

/// <summary>
/// A built Plaso super timeline: the persistent <see cref="StorageFile"/> (.plaso) plus the sorted, optionally
/// date-filtered <see cref="Events"/> exported from it by psort. <see cref="ParserCounts"/> /
/// <see cref="TotalEventsInStorage"/> come from pinfo and describe everything the storage file holds (before any
/// psort filter), so they let an analyst see the artifact mix even when <see cref="Events"/> has been narrowed to
/// a window. The same <see cref="StorageFile"/> can be re-filtered cheaply (psort takes almost no time) to carve
/// further mini-timelines without re-parsing the source.
/// </summary>
public record SuperTimeline
{
    /// <summary>Path to the persistent Plaso storage file (.plaso) on the workstation.</summary>
    public required string StorageFile { get; init; }

    /// <summary>The sorted timeline events exported by psort (after any date-range filter applied during the run).</summary>
    public TimelineEvent[] Events { get; init; } = [];

    /// <summary>Total number of events held in the storage file (from pinfo), before any psort filter.</summary>
    public long TotalEventsInStorage { get; init; }

    /// <summary>Per-parser event counts in the storage file (from pinfo) — the artifact mix that was collected.</summary>
    public IReadOnlyDictionary<string, long> ParserCounts { get; init; } = new Dictionary<string, long>();

    /// <summary>The psort filter expression applied to produce <see cref="Events"/>, or null when unfiltered.</summary>
    public string? Filter { get; init; }

    /// <summary>Number of events in the exported (filtered) timeline.</summary>
    public int EventCount => Events.Length;

    /// <summary>Earliest event time in the exported timeline (UTC), or null when empty.</summary>
    public DateTimeOffset? Start => Events.Length > 0 ? Events.Min(e => e.Time) : null;

    /// <summary>Latest event time in the exported timeline (UTC), or null when empty.</summary>
    public DateTimeOffset? End => Events.Length > 0 ? Events.Max(e => e.Time) : null;

    /// <summary>The parsers that contributed events, ordered by descending count (excludes pinfo's "total" entry).</summary>
    public KeyValuePair<string, long>[] TopParsers =>
        ParserCounts.Where(kv => kv.Key != "total").OrderByDescending(kv => kv.Value).ToArray();
}

/// <summary>
/// A timeline bucketed into the methodology's "Evidence of…" categories by the Plaso tagging plugin. Each
/// <see cref="TimelineCategory"/> holds the events the tag rules assigned to it (an event can appear in more than
/// one category). This is the code-mode equivalent of Timeline Explorer's colour-coding — a structured,
/// queryable view of what kinds of activity the timeline contains.
/// </summary>
public record CategorizedTimeline
{
    /// <summary>The storage file (.plaso) that was tagged and categorised.</summary>
    public required string StorageFile { get; init; }

    /// <summary>The populated categories (empty categories are omitted), ordered by descending event count.</summary>
    public TimelineCategory[] Categories { get; init; } = [];

    /// <summary>Total number of tagged events exported (the same event counts once per category it carries).</summary>
    public int TotalTaggedEvents { get; init; }

    /// <summary>Category names that were populated, for a quick at-a-glance summary.</summary>
    public string[] PopulatedCategories => Categories.Select(c => c.Name).ToArray();
}

/// <summary>One "Evidence of…" category and the timeline events the tagging plugin assigned to it.</summary>
public record TimelineCategory
{
    public required string Name { get; init; }
    public TimelineEvent[] Events { get; init; } = [];
    public int Count => Events.Length;
}

/// <summary>
/// The result of auto-detecting pivot points in a timeline: each high-fidelity hayabusa Sigma alert becomes a
/// <see cref="TimelinePivot"/> whose surrounding mini-timeline (the super-timeline events within ±N minutes of
/// the alert) is sliced out for review — automating the FOR508 "find a pivot, examine its temporal proximity"
/// loop.
/// </summary>
public record TimelinePivotReport
{
    /// <summary>The storage file (.plaso) the pivots were sliced from.</summary>
    public required string StorageFile { get; init; }

    /// <summary>The detected pivots, ordered by time.</summary>
    public TimelinePivot[] Pivots { get; init; } = [];

    /// <summary>Total hayabusa alerts seen at/above the requested severity (before de-duplication to distinct pivots).</summary>
    public int AlertsConsidered { get; init; }

    /// <summary>The ±minutes window sliced around each pivot.</summary>
    public int SliceSizeMinutes { get; init; }
}

/// <summary>A single detected pivot: the triggering Sigma alert and the timeline events around it.</summary>
public record TimelinePivot
{
    /// <summary>The hayabusa Sigma detection that flagged this moment as interesting.</summary>
    public required HayabusaAlert Alert { get; init; }

    /// <summary>The pivot timestamp (the alert time), in UTC.</summary>
    public DateTimeOffset PivotTime { get; init; }

    /// <summary>The super-timeline events within the slice window around <see cref="PivotTime"/>.</summary>
    public TimelineEvent[] Surrounding { get; init; } = [];

    /// <summary>Number of surrounding events.</summary>
    public int SurroundingCount => Surrounding.Length;
}

/// <summary>
/// The result of keyword/IOC searching a timeline. Each <see cref="TimelineKeywordHits"/> holds the events whose
/// rendered text matched one keyword; an event matching several keywords appears under each. <see cref="Matches"/>
/// is the de-duplicated union of all hits, in time order — the keyword-driven pivot-point shortlist.
/// </summary>
public record TimelineSearchReport
{
    /// <summary>The storage file (.plaso) that was searched.</summary>
    public required string StorageFile { get; init; }

    /// <summary>Per-keyword hit lists (only keywords with at least one hit are included).</summary>
    public TimelineKeywordHits[] Hits { get; init; } = [];

    /// <summary>The de-duplicated union of all matching events, in time order.</summary>
    public TimelineEvent[] Matches { get; init; } = [];

    /// <summary>The keywords that produced at least one hit.</summary>
    public string[] MatchedKeywords => Hits.Select(h => h.Keyword).ToArray();
}

/// <summary>The events matching one search keyword.</summary>
public record TimelineKeywordHits
{
    public required string Keyword { get; init; }
    public TimelineEvent[] Events { get; init; } = [];
    public int Count => Events.Length;
}
