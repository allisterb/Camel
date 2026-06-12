namespace Camel.Training;
using Camel.Inference;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>
/// Ties the pipeline together into a reusable evaluation harness over a directory of per-user-action l2tcsv
/// timeline segments (the Studiawan Windows 11 dataset layout: <c>events/{N-action}.csv</c>). Each file is
/// loaded, canonicalized, windowed, and embedded; every window is labelled with its file's action; then
/// leave-one-out k-NN measures how well the chosen <see cref="IEventEmbedder"/> separates the actions. Swapping
/// the embedder (<see cref="HashingEmbedder"/> vs <see cref="MiniLmEmbedder"/>) and re-running quantifies the
/// representation upgrade.
/// </summary>
public static class DatasetEvaluator
{
    /// <summary>
    /// Builds labelled window embeddings from every <c>*.csv</c> in <paramref name="eventsDir"/> and evaluates
    /// action-classification with leave-one-out k-NN.
    /// </summary>
    /// <param name="eventsDir">Directory of per-action l2tcsv files (e.g. the dataset's <c>timeline/events</c>).</param>
    /// <param name="embedder">The embedder under test.</param>
    /// <param name="spec">How to window each action's events.</param>
    /// <param name="k">k for the k-NN classifier.</param>
    public static EvalResult EvaluateActionClassification(string eventsDir, IEventEmbedder embedder, WindowSpec spec,
        int k = 5, Func<CanonicalEvent[], string>? render = null, Func<CanonicalEvent, bool>? keep = null)
    {
        var (vectors, labels) = BuildLabelledWindows(eventsDir, embedder, spec, render, keep);
        if (vectors.Length == 0) throw new InvalidOperationException($"No windows produced from '{eventsDir}'.");
        return ActionClassificationEval.KnnLeaveOneOut(vectors, labels, k);
    }

    /// <summary>
    /// Loads, windows and embeds every per-action file; returns the window vectors and their action labels.
    /// <paramref name="render"/> chooses how a window is turned into text for the embedder (defaults to the
    /// compact <see cref="TextRenderer"/>; pass <see cref="NaturalRenderer.RenderSequence"/> for prose).
    /// <paramref name="keep"/> optionally filters events at canonicalization (e.g.
    /// <see cref="NoiseFilters.KeepHighSignal"/> to drop the filesystem-metadata firehose).
    /// </summary>
    public static (float[][] Vectors, string[] Labels) BuildLabelledWindows(string eventsDir, IEventEmbedder embedder,
        WindowSpec spec, Func<CanonicalEvent[], string>? render = null, Func<CanonicalEvent, bool>? keep = null)
    {
        render ??= TextRenderer.RenderSequence;
        var vectors = new List<float[]>();
        var labels = new List<string>();
        foreach (var csv in Directory.EnumerateFiles(eventsDir, "*.csv").OrderBy(f => f, StringComparer.Ordinal))
        {
            var label = LabelFromFileName(Path.GetFileNameWithoutExtension(csv));
            var canonical = CsvTimelineLoader.LoadCanonical(csv, keep);
            foreach (var window in Windower.SlidingByCount(label, canonical, spec))
            {
                vectors.Add(embedder.Embed(render(window.Events)));
                labels.Add(label);
            }
        }
        return (vectors.ToArray(), labels.ToArray());
    }

    // Strips the dataset's numeric ordering prefix: "3-launch-cmd" -> "launch-cmd".
    internal static string LabelFromFileName(string name)
    {
        int dash = name.IndexOf('-');
        return dash > 0 && name[..dash].All(char.IsDigit) ? name[(dash + 1)..] : name;
    }
}
