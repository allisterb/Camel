namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// A contiguous slice of a host's timeline — the unit the sequence/anomaly/triage models operate on. A single
/// event rarely means much; an <em>episode</em> of nearby events (a logon followed by a file write followed by an
/// execution) is the behavioural unit an analyst reasons about, so embeddings and novelty scores are computed
/// per window. Mirrors the FOR508 "pivot point" slice, lifted to already-canonicalized events.
/// </summary>
public sealed record EventWindow
{
    /// <summary>The host/image this window came from — the unit train/test splits must respect (never split by event).</summary>
    public required string HostId { get; init; }

    /// <summary>The window's centre time (epoch µs, UTC) — the pivot it was built around, or its median event time.</summary>
    public required long CenterTs { get; init; }

    /// <summary>The events in the window, in ascending time order.</summary>
    public required CanonicalEvent[] Events { get; init; }

    public int Count => Events.Length;
    public long StartTs => Events.Length > 0 ? Events[0].Ts : CenterTs;
    public long EndTs => Events.Length > 0 ? Events[^1].Ts : CenterTs;
}

/// <summary>How to cut a timeline into fixed-count sliding windows: <paramref name="Size"/> events per window,
/// advancing <paramref name="Stride"/> events between windows (Stride &lt; Size overlaps; Stride == Size tiles).</summary>
public readonly record struct WindowSpec(int Size, int Stride)
{
    public static WindowSpec Tiled(int size) => new(size, size);
    public static WindowSpec Overlapping(int size, int stride) => new(size, stride);
}
