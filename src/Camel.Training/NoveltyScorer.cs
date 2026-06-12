namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// A label-free anomaly scorer: it is "fit" on a set of <em>benign</em> baseline vectors (a host's normal
/// activity, embedded per window) and scores a query window by its mean cosine <em>distance</em> to its
/// <c>k</c> nearest baseline vectors. A window that looks like normal activity sits close to the baseline
/// (score → 0); a novel behavioural episode sits far from everything seen before (score → 1). This is the
/// unsupervised half of the methodology — no labels required, "normal" defined relative to the host itself.
/// Vectors are assumed L2-normalized (as all <see cref="IEventEmbedder"/>s return), so cosine = dot product.
/// </summary>
public sealed class NoveltyScorer
{
    private readonly float[][] baseline;
    private readonly int k;

    /// <param name="baseline">Benign window vectors to compare against (must be non-empty, all the same length).</param>
    /// <param name="k">How many nearest baseline neighbours to average over (clamped to the baseline size).</param>
    public NoveltyScorer(float[][] baseline, int k = 5)
    {
        if (baseline is null || baseline.Length == 0) throw new ArgumentException("baseline must be non-empty", nameof(baseline));
        this.baseline = baseline;
        this.k = Math.Clamp(k, 1, baseline.Length);
    }

    /// <summary>The novelty score of <paramref name="query"/> in [0, 2] (0 = identical to baseline, 1 = orthogonal).</summary>
    public float Score(float[] query)
    {
        // Cosine similarity (= dot for normalized vectors) to every baseline vector; take the k largest.
        var sims = new float[baseline.Length];
        for (int i = 0; i < baseline.Length; i++) sims[i] = VectorMath.Dot(query, baseline[i]);
        Array.Sort(sims);                                  // ascending
        float topMean = 0;
        for (int i = 0; i < k; i++) topMean += sims[sims.Length - 1 - i];   // the k largest similarities
        topMean /= k;
        return 1f - topMean;                               // distance = 1 - mean top-k similarity
    }
}
