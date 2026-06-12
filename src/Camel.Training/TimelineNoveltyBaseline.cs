namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// The end-to-end, label-free anomaly baseline: canonical events → windows → embeddings → per-window novelty.
/// A benign reference stream is windowed and embedded to fit a <see cref="NoveltyScorer"/>; the target stream is
/// then windowed, embedded, scored, and ranked so the most behaviourally-novel episodes surface first. The
/// embedder is injected (<see cref="HashingEmbedder"/> today, an ONNX sentence-transformer later) — everything
/// else is fixed. This is the first runnable instance of the "representation → anomaly" half of the pipeline.
/// </summary>
public sealed class TimelineNoveltyBaseline
{
    private readonly IEventEmbedder embedder;

    public TimelineNoveltyBaseline(IEventEmbedder embedder) => this.embedder = embedder;

    /// <summary>
    /// Fits the novelty scorer on <paramref name="baselineEvents"/> (benign reference) and scores every window of
    /// <paramref name="targetEvents"/>, returning them ranked most-novel-first. When the target is the same host's
    /// later activity (or the same stream), this surfaces the episodes least like its established normal.
    /// </summary>
    /// <param name="hostId">The host the streams belong to (carried onto every window).</param>
    /// <param name="baselineEvents">Benign reference events to define "normal".</param>
    /// <param name="targetEvents">Events to score for novelty.</param>
    /// <param name="spec">How to cut both streams into windows.</param>
    /// <param name="k">Nearest-neighbour count for the novelty score.</param>
    public NoveltyResult Score(string hostId, CanonicalEvent[] baselineEvents, CanonicalEvent[] targetEvents,
        WindowSpec spec, int k = 5)
    {
        var baselineVectors = EmbedWindows(hostId, baselineEvents, spec);
        if (baselineVectors.Length == 0)
            throw new ArgumentException("baseline events produced no windows", nameof(baselineEvents));

        var scorer = new NoveltyScorer(baselineVectors, k);
        var targetWindows = Windower.SlidingByCount(hostId, targetEvents, spec);

        var scored = targetWindows
            .Select(w => new ScoredWindow(w, scorer.Score(EmbedWindow(w))))
            .OrderByDescending(s => s.Novelty)
            .ToArray();
        return new NoveltyResult { Windows = scored };
    }

    private float[] EmbedWindow(EventWindow w) => embedder.Embed(TextRenderer.RenderSequence(w.Events));

    private float[][] EmbedWindows(string hostId, CanonicalEvent[] events, WindowSpec spec) =>
        Windower.SlidingByCount(hostId, events, spec).Select(EmbedWindow).ToArray();
}

/// <summary>A window paired with its novelty score (higher = more anomalous).</summary>
public sealed record ScoredWindow(EventWindow Window, float Novelty);

/// <summary>The novelty-ranked windows of a target stream.</summary>
public sealed record NoveltyResult
{
    /// <summary>Windows ranked by descending novelty (most anomalous first).</summary>
    public required ScoredWindow[] Windows { get; init; }

    public int Count => Windows.Length;

    /// <summary>The <paramref name="n"/> most novel windows — the triage shortlist.</summary>
    public ScoredWindow[] Top(int n) => Windows.Take(n).ToArray();
}
