namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// The unified "event type" token the (event_id, Δt) detectors key on. Generalises the Windows Event ID so the same
/// detectors work over a <em>full</em> super timeline, not just EVTX: an event-log record is its Event ID, a
/// registry event its artifact class, and everything else its coarse source (with the file extension for files,
/// since a rare extension is itself signal). Low-cardinality and purely categorical — the property that makes
/// frequency/transition/rate modelling fast and label-free.
/// </summary>
public static class EventType
{
    public static string TokenOf(CanonicalEvent e) =>
        e.EventId is { } id ? "evtx:" + id
        : e.Reg is not RegClass.None ? "reg:" + e.Reg.ToString().ToLowerInvariant()
        : e.Source switch
        {
            SourceClass.FileSystem => e.Ext is { Length: > 0 } x ? "file:" + x : "file",
            SourceClass.WebHistory => "web",
            SourceClass.Lnk => "lnk",
            SourceClass.Prefetch => "prefetch",
            SourceClass.Registry => "reg",
            SourceClass.EventLog => "evtx",
            SourceClass.Log => "log",
            _ => "other",
        };
}

/// <summary>
/// One detector's verdict on a single event: how surprising it is (in <see cref="Bits"/>) and a human-readable
/// <see cref="Reason"/> the agent can act on. Findings are the atomic output of every <see cref="IEventDetector"/>;
/// the <see cref="DetectorEnsemble"/> merges them per event into a ranked triage shortlist.
/// </summary>
public sealed record Finding(int EventIndex, long Ts, string Token, double Bits, string Detector, string Reason);

/// <summary>
/// A label-free anomaly detector over a canonical timeline. Fit on a benign <c>baseline</c> (or the stream itself —
/// "self-baseline" — for single-host triage with no clean reference), it emits a <see cref="Finding"/> for each
/// <c>target</c> event it considers notable. Surprisal is reported in bits so detectors share one currency and
/// compose additively.
/// </summary>
public interface IEventDetector
{
    string Name { get; }
    IEnumerable<Finding> Detect(CanonicalEvent[] baseline, CanonicalEvent[] target);
}

/// <summary>
/// Flags events whose <em>type</em> is rare in the baseline (<c>-log₂ p(token)</c>). The validated primitive: an
/// event type the host has never produced (e.g. 1102 "audit log cleared") is maximally surprising. Catches
/// anti-forensics and first-of-a-kind activity; blind to common-type events (that is the other detectors' job).
/// </summary>
public sealed class RareTypeDetector(double minBits = 6.0) : IEventDetector
{
    public string Name => "rare-type";

    public IEnumerable<Finding> Detect(CanonicalEvent[] baseline, CanonicalEvent[] target)
    {
        var counts = new Dictionary<string, int>();
        foreach (var e in baseline) { var t = EventType.TokenOf(e); counts[t] = counts.GetValueOrDefault(t) + 1; }
        int total = baseline.Length;
        if (total == 0) yield break;

        for (int i = 0; i < target.Length; i++)
        {
            var token = EventType.TokenOf(target[i]);
            int c = counts.GetValueOrDefault(token);
            double bits = -Math.Log2((c + 1e-6) / total);
            if (bits >= minBits)
                yield return new Finding(i, target[i].Ts, token, bits, Name,
                    $"event type '{token}' is rare ({c}/{total} in baseline, {bits:F1} bits)");
        }
    }
}

/// <summary>
/// Flags rare <em>transitions</em> between consecutive event types (<c>-log₂ p(token_t | token_{t-1})</c>, a bigram
/// model over the time-sorted stream). Surfaces ordinary events in an order the host never does — scripted attack
/// chains and lateral-movement sequences whose individual events are all common. (v1 is global; per-entity
/// sub-sequences — per session/account — are the next refinement.)
/// </summary>
public sealed class RareTransitionDetector(double minBits = 8.0) : IEventDetector
{
    public string Name => "rare-transition";

    public IEnumerable<Finding> Detect(CanonicalEvent[] baseline, CanonicalEvent[] target)
    {
        var bigram = new Dictionary<(string, string), int>();
        var context = new Dictionary<string, int>();
        string? prev = null;
        foreach (var e in baseline)
        {
            var t = EventType.TokenOf(e);
            if (prev is not null) { bigram[(prev, t)] = bigram.GetValueOrDefault((prev, t)) + 1; context[prev] = context.GetValueOrDefault(prev) + 1; }
            prev = t;
        }

        prev = null;
        for (int i = 0; i < target.Length; i++)
        {
            var token = EventType.TokenOf(target[i]);
            if (prev is not null && context.TryGetValue(prev, out int ctx) && ctx > 0)
            {
                int c = bigram.GetValueOrDefault((prev, token));
                double bits = -Math.Log2((c + 1e-6) / ctx);
                if (bits >= minBits)
                    yield return new Finding(i, target[i].Ts, token, bits, Name,
                        $"transition '{prev}'→'{token}' is rare ({c}/{ctx} in baseline, {bits:F1} bits)");
            }
            prev = token;
        }
    }
}

/// <summary>
/// Flags volume bursts: per event type it learns the baseline arrival rate, then scores each target event by how
/// many events of its type fell in the trailing <see cref="windowSeconds"/> versus what the baseline rate predicts
/// (the Poisson upper-tail large-deviation exponent, in bits). Surfaces logon storms, password-spray (4625 floods),
/// and rapid service installs — bursts of an otherwise-ordinary event type.
/// </summary>
public sealed class TimingBurstDetector(double windowSeconds = 60.0, double minBits = 6.0) : IEventDetector
{
    public string Name => "timing-burst";

    public IEnumerable<Finding> Detect(CanonicalEvent[] baseline, CanonicalEvent[] target)
    {
        var counts = new Dictionary<string, int>();
        long minTs = long.MaxValue, maxTs = long.MinValue;
        foreach (var e in baseline) { var t = EventType.TokenOf(e); counts[t] = counts.GetValueOrDefault(t) + 1; if (e.Ts < minTs) minTs = e.Ts; if (e.Ts > maxTs) maxTs = e.Ts; }
        if (baseline.Length == 0) yield break;
        double spanSec = Math.Max(1.0, (maxTs - minTs) / 1_000_000.0);
        long w = (long)(windowSeconds * 1_000_000);

        var recent = new Dictionary<string, Queue<long>>();
        for (int i = 0; i < target.Length; i++)
        {
            var e = target[i];
            var token = EventType.TokenOf(e);
            var q = recent.TryGetValue(token, out var qq) ? qq : (recent[token] = new Queue<long>());
            q.Enqueue(e.Ts);
            while (q.Count > 0 && q.Peek() < e.Ts - w) q.Dequeue();

            if (counts.TryGetValue(token, out int bc) && bc >= 2)
            {
                double expected = bc / spanSec * windowSeconds;        // events of this type expected per window
                double bits = PoissonExcessBits(q.Count, expected);
                if (bits >= minBits)
                    yield return new Finding(i, e.Ts, token, bits, Name,
                        $"{q.Count} '{token}' events in {windowSeconds:F0}s (≈{expected:F2} expected, {bits:F1} bits)");
            }
        }
    }

    // The Poisson large-deviation (Chernoff) exponent for observing n ≥ mean, in bits — a closed-form proxy for
    // -log₂ P(X ≥ n) with no factorials/special functions. 0 when the count is at or below expectation.
    private static double PoissonExcessBits(int n, double mean)
    {
        if (mean <= 0 || n <= mean) return 0;
        double nats = n * Math.Log(n / mean) - (n - mean);
        return nats / Math.Log(2);
    }
}

/// <summary>
/// One surprising <em>episode</em> the ensemble surfaced — a run of same-type events in a time bucket, collapsed to
/// a single shortlist entry (peak event as exemplar) so a 2000-event burst takes one slot, not 2000. Carries the
/// member event indices so recall can credit covering the whole episode.
/// </summary>
public sealed record TriageItem(int EventIndex, long Ts, string Token, double TotalBits, int Count, int[] MemberIndices, Finding[] Findings)
{
    public DateTimeOffset Time => DateTimeOffset.FromUnixTimeMilliseconds(Ts / 1000);
    public override string ToString() =>
        $"[{TotalBits,7:F1} bits ×{Count,-5}] {Time:u} {Token} — {string.Join("; ", Findings.Select(f => f.Reason))}";
}

/// <summary>The triage shortlist: the most-surprising events across all detectors, plus the compression achieved.</summary>
public sealed record TriageReport
{
    public required TriageItem[] Shortlist { get; init; }
    public required int TotalEvents { get; init; }
    /// <summary>Distinct events any detector flagged (the candidate pool the shortlist is the head of).</summary>
    public required int Candidates { get; init; }

    /// <summary>Shortlist size as a fraction of the timeline — how much an analyst's review set shrank.</summary>
    public double CompressionRatio => TotalEvents > 0 ? (double)Shortlist.Length / TotalEvents : 0;
}

/// <summary>
/// Runs a set of <see cref="IEventDetector"/>s, merges their findings per event (summing bits, so an event flagged
/// by several detectors floats up), ranks most-surprising-first, and returns the top-<c>budget</c> as the triage
/// shortlist — the toolkit's core output: "of N events, here are the K worth a human's attention, and why."
/// </summary>
public sealed class DetectorEnsemble
{
    private readonly IEventDetector[] detectors;

    public DetectorEnsemble(params IEventDetector[] detectors) => this.detectors = detectors;

    /// <summary>The default (event_id, Δt) suite: rare type + rare transition + timing burst.</summary>
    public static DetectorEnsemble Default() =>
        new(new RareTypeDetector(), new RareTransitionDetector(), new TimingBurstDetector());

    public TriageReport Triage(CanonicalEvent[] baseline, CanonicalEvent[] target, int budget, double episodeGapSeconds = 60.0)
    {
        long bucket = Math.Max(1, (long)(episodeGapSeconds * 1_000_000));
        int quota = Math.Max(1, (int)Math.Ceiling((double)budget / detectors.Length));

        // Per-detector quota: each detector collapses its findings into episodes (same token within a time bucket,
        // so one burst is one entry) and contributes only its top `quota`. This keeps the shortlist DIVERSE across
        // kinds of anomaly — a detector that emits astronomically-large bits (a volume burst) can't crowd out a
        // detector whose signal is smaller in magnitude but just as interesting (a rare event type).
        var picked = new List<(string Token, long Bucket, double Bits, Finding Peak, int[] Members)>();
        foreach (var d in detectors)
            picked.AddRange(d.Detect(baseline, target)
                .GroupBy(f => (f.Token, f.Ts / bucket))
                .Select(g =>
                {
                    var peak = g.MaxBy(f => f.Bits)!;
                    return (peak.Token, g.Key.Item2, peak.Bits, peak, g.Select(f => f.EventIndex).Distinct().ToArray());
                })
                .OrderByDescending(e => e.Bits)
                .Take(quota));

        // Merge episodes the detectors agree on (same token+bucket): sum bits, union members, keep all reasons.
        var items = picked
            .GroupBy(e => (e.Token, e.Bucket))
            .Select(g =>
            {
                var members = g.SelectMany(e => e.Members).Distinct().ToArray();
                var findings = g.Select(e => e.Peak).OrderByDescending(f => f.Bits).ToArray();
                return new TriageItem(findings[0].EventIndex, findings[0].Ts, findings[0].Token, g.Sum(e => e.Bits), members.Length, members, findings);
            })
            .OrderByDescending(i => i.TotalBits)
            .ToArray();

        return new TriageReport { Shortlist = items.Take(budget).ToArray(), TotalEvents = target.Length, Candidates = items.Length };
    }
}
