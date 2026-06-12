namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Evaluates how well window embeddings separate labelled classes via leave-one-out k-NN classification — the
/// representation-quality metric for the Studiawan per-user-action dataset (does a window of "launch-cmd" activity
/// embed nearer other "launch-cmd" windows than to "firefox-install" windows?). Reports accuracy and macro-F1
/// against the chance baseline (1/#classes), giving the first paper-comparable numbers for the encoder. Operates
/// on L2-normalized vectors (cosine = dot), as all <see cref="IEventEmbedder"/>s produce.
/// </summary>
public static class ActionClassificationEval
{
    /// <summary>Leave-one-out k-NN over <paramref name="vectors"/> labelled by <paramref name="labels"/>.</summary>
    public static EvalResult KnnLeaveOneOut(float[][] vectors, string[] labels, int k = 5)
    {
        if (vectors.Length != labels.Length) throw new ArgumentException("vectors/labels length mismatch");
        int n = vectors.Length;
        var classes = labels.Distinct().OrderBy(s => s, StringComparer.Ordinal).ToArray();
        var predicted = new string[n];

        for (int i = 0; i < n; i++)
            predicted[i] = PredictExcludingSelf(vectors, labels, i, Math.Clamp(k, 1, Math.Max(1, n - 1)));

        int correct = 0;
        for (int i = 0; i < n; i++) if (predicted[i] == labels[i]) correct++;

        var perClass = classes.Select(c =>
        {
            int tp = 0, fp = 0, fn = 0;
            for (int i = 0; i < n; i++)
            {
                bool actual = labels[i] == c, pred = predicted[i] == c;
                if (actual && pred) tp++;
                else if (!actual && pred) fp++;
                else if (actual && !pred) fn++;
            }
            double prec = tp + fp > 0 ? (double)tp / (tp + fp) : 0;
            double rec = tp + fn > 0 ? (double)tp / (tp + fn) : 0;
            double f1 = prec + rec > 0 ? 2 * prec * rec / (prec + rec) : 0;
            return new ClassMetric(c, tp + fn, prec, rec, f1);
        }).ToArray();

        return new EvalResult
        {
            Samples = n,
            Classes = classes,
            Accuracy = n > 0 ? (double)correct / n : 0,
            MacroF1 = perClass.Length > 0 ? perClass.Average(m => m.F1) : 0,
            PerClass = perClass,
        };
    }

    // Majority label among the k nearest neighbours (excluding the query itself); ties broken by summed similarity.
    private static string PredictExcludingSelf(float[][] vectors, string[] labels, int self, int k)
    {
        var top = new List<(float Sim, int Idx)>(k + 1);
        for (int j = 0; j < vectors.Length; j++)
        {
            if (j == self) continue;
            float sim = VectorMath.Dot(vectors[self], vectors[j]);
            // insertion into a small descending-by-sim buffer of size k
            int pos = top.FindIndex(t => sim > t.Sim);
            if (pos >= 0) top.Insert(pos, (sim, j));
            else if (top.Count < k) top.Add((sim, j));
            if (top.Count > k) top.RemoveAt(top.Count - 1);
        }
        return top.GroupBy(t => labels[t.Idx])
            .OrderByDescending(g => g.Count()).ThenByDescending(g => g.Sum(t => t.Sim))
            .First().Key;
    }
}

/// <summary>The outcome of a k-NN representation evaluation.</summary>
public sealed record EvalResult
{
    public required int Samples { get; init; }
    public required string[] Classes { get; init; }
    public required double Accuracy { get; init; }
    public required double MacroF1 { get; init; }
    public required ClassMetric[] PerClass { get; init; }

    /// <summary>Random-guess accuracy (1/#classes) — the baseline the embedding must beat to carry signal.</summary>
    public double Chance => Classes.Length > 0 ? 1.0 / Classes.Length : 0;

    public override string ToString() =>
        $"acc={Accuracy:P1} macroF1={MacroF1:P1} (chance={Chance:P1}, {Samples} windows, {Classes.Length} classes)";
}

/// <summary>Per-class precision/recall/F1 and support.</summary>
public sealed record ClassMetric(string Label, int Support, double Precision, double Recall, double F1);
