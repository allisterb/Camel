namespace Camel.Inference;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Cuts a host's <see cref="CanonicalEvent"/> stream (assumed time-sorted, as <see cref="EventCanonicalizer"/>
/// produces) into <see cref="EventWindow"/>s. Fixed-count sliding windows feed self-supervised pretraining and
/// the novelty baseline; a pivot-centred window reproduces the FOR508 "examine the temporal proximity of a
/// pivot" slice for scoring a specific moment.
/// </summary>
public static class Windower
{
    /// <summary>
    /// Sliding fixed-count windows: each holds <paramref name="size"/> consecutive events, advancing
    /// <paramref name="stride"/> events between windows. The final window is truncated at the end of the stream
    /// (so a short tail still produces one window rather than being dropped). Returns empty for an empty stream.
    /// </summary>
    public static EventWindow[] SlidingByCount(string hostId, CanonicalEvent[] events, int size, int stride)
    {
        if (size <= 0) throw new ArgumentOutOfRangeException(nameof(size));
        if (stride <= 0) throw new ArgumentOutOfRangeException(nameof(stride));
        if (events.Length == 0) return [];

        var windows = new List<EventWindow>();
        for (int start = 0; start < events.Length; start += stride)
        {
            int end = Math.Min(start + size, events.Length);
            var slice = events[start..end];
            windows.Add(new EventWindow { HostId = hostId, CenterTs = slice[slice.Length / 2].Ts, Events = slice });
            if (end == events.Length) break;   // reached the tail — don't emit further (smaller, redundant) windows
        }
        return windows.ToArray();
    }

    /// <summary>Convenience overload taking a <see cref="WindowSpec"/>.</summary>
    public static EventWindow[] SlidingByCount(string hostId, CanonicalEvent[] events, WindowSpec spec) =>
        SlidingByCount(hostId, events, spec.Size, spec.Stride);

    /// <summary>
    /// A single window of every event within <paramref name="halfWindowMinutes"/> minutes either side of
    /// <paramref name="centerTs"/> (epoch µs) — the pivot slice, computed client-side over already-canonicalized
    /// events (the server-side equivalent is <c>TimelineWorkflow.PivotAroundAsync</c>).
    /// </summary>
    public static EventWindow AroundPivot(string hostId, CanonicalEvent[] events, long centerTs, double halfWindowMinutes)
    {
        long half = (long)(halfWindowMinutes * 60_000_000);   // minutes -> microseconds
        long lo = centerTs - half, hi = centerTs + half;
        var slice = events.Where(e => e.Ts >= lo && e.Ts <= hi).ToArray();
        return new EventWindow { HostId = hostId, CenterTs = centerTs, Events = slice };
    }
}
