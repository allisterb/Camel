using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Camel.Training;
using Camel.Inference;

namespace Camel.Tests.Training;

public class AnomalyEvalTests : TestsRuntime
{
    // --- ranking metric (pure) ---

    [Fact]
    public void RankingMetricsComputesPrecisionRecallAndAp()
    {
        // 10 windows in novelty-rank order; planted positives at ranks 1, 2 and 5.
        var windows = Enumerable.Range(0, 10)
            .Select(i => new ScoredWindow(Win(injected: i is 0 or 1 or 4), 1f - i * 0.1f))
            .ToArray();
        var result = new NoveltyResult { Windows = windows };

        var m = AnomalyDetectionEval.RankingMetrics(result, SyntheticIntrusion.WindowIsInjected, k: 5);

        Assert.Equal(10, m.Windows);
        Assert.Equal(3, m.Positives);
        Assert.Equal(1, m.BestRank);                            // first positive is rank 1
        Assert.Equal(3, m.HitsAtK);                             // all three are within the top 5
        Assert.Equal(0.6, m.PrecisionAtK, 3);                  // 3/5
        Assert.Equal(1.0, m.RecallAtK, 3);                     // 3/3
        Assert.Equal((1.0 + 1.0 + 3.0 / 5) / 3, m.AveragePrecision, 6);   // AP = mean precision@positive-rank
        Assert.Equal(0.3, m.ChanceAp, 3);                      // prevalence 3/10
    }

    [Fact]
    public void RankingMetricsHandlesNoPositives()
    {
        var result = new NoveltyResult { Windows = [new ScoredWindow(Win(false), 0.5f)] };
        var m = AnomalyDetectionEval.RankingMetrics(result, SyntheticIntrusion.WindowIsInjected, k: 5);
        Assert.Equal(0, m.Positives);
        Assert.Equal(-1, m.BestRank);
        Assert.Equal(0, m.AveragePrecision);
        Assert.Equal(0, m.RecallAtK);
    }

    // --- event-id rarity head ---

    [Fact]
    public void EventIdRarityRanksUnseenEventTypeFirst()
    {
        // Baseline is all routine logons (4624/4634); the target injects a single never-seen 1102 (log clear) — the
        // case the bag-of-tokens embedding misses on a real host but the surprisal head catches.
        var baseline = Enumerable.Range(0, 200).Select(Benign).ToArray();
        var target = Enumerable.Range(0, 40).Select(Benign)
            .Append(new CanonicalEvent { Ts = 40, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = 1102 })
            .Concat(Enumerable.Range(41, 9).Select(Benign))
            .ToArray();

        var scorer = new EventIdRarityScorer(baseline);
        Assert.Equal(0, scorer.Surprisal(null), 6);                         // events without an EventId contribute nothing
        // An unseen id is far more surprising than a baseline-common one (surprisal = -log₂ p, so ~1 bit for a
        // half-the-baseline id vs ~25 bits for one never seen).
        Assert.True(scorer.Surprisal(1102) > scorer.Surprisal(4624) + 10);

        bool isLogClear(EventWindow w) => w.Events.Any(e => e.EventId is 1102);
        var m = AnomalyDetectionEval.RankingMetrics(
            EventIdRarityScorer.Rank("h", baseline, target, WindowSpec.Tiled(5)), isLogClear, k: 5);
        Assert.Equal(1, m.Positives);
        Assert.Equal(1, m.BestRank);                                        // the 1102 window ranks most-novel
        Assert.Equal(1.0, m.AveragePrecision, 6);
    }

    // --- synthetic injection surfaces under the real novelty baseline (deterministic, no dataset) ---

    [Fact]
    public void InjectedAttackEpisodesRankNovelOverBenignBaseline()
    {
        // A homogeneous benign stream (normal registry activity + routine logon/logoff); the malicious episodes
        // carry event IDs (4104, 1102, 7045, …) the baseline never sees, so their windows should rank most-novel.
        var benignBaseline = Enumerable.Range(0, 240).Select(Benign).ToArray();
        var benignTarget = Enumerable.Range(240, 240).Select(Benign).ToArray();
        var target = SyntheticIntrusion.Inject(benignTarget, SyntheticIntrusion.Episodes());

        var baseline = new TimelineNoveltyBaseline(new HashingEmbedder(256));
        var result = baseline.Score("host", benignBaseline, target, WindowSpec.Tiled(5), k: 3);
        var m = AnomalyDetectionEval.RankingMetrics(result, SyntheticIntrusion.WindowIsInjected, k: 10);

        Assert.True(m.Positives >= 5, $"expected >=5 injected windows: {m}");
        Assert.True(m.AveragePrecision > m.ChanceAp * 3, $"novelty carries no signal: {m}");
        Assert.True(m.BestRank <= 3, $"no injected window near the top: {m}");
        Assert.True(m.RecallAtK >= 0.5, $"too few injected windows recovered in the top-k: {m}");
    }

    // --- real benign timeline: sample, inject, score, report (slow one-off, kept out of the suite) ---

    // Measured one-off (600k-row sample → 61,251 high-signal events; baseline 42,875 / target 18,376; 5 injected
    // episodes; HashingEmbedder+TextRenderer; ~36s incl. streaming load). The first real anomaly-detection number,
    // and it carries strong signal — sharply window-size dependent because a short episode dilutes in a big window:
    //   Tiled(5)   AP=23.3% (chance 0.2%, ~117x) · P@20=35% R@20=78% (7/9) · bestRank=2/3681
    //   Tiled(10)  AP=20.6% (chance 0.4%)        · P@20=25% R@20=71% (5/7) · bestRank=8/1841
    //   Tiled(20)  AP=9.6%  (chance 0.7%)        · P@20=10% R@20=33% (2/6) · bestRank=5/921
    // CONCLUSION: novelty over the high-signal stream surfaces planted attacks far above chance, and SMALL windows
    // win for anomaly (opposite of the balanced-classification proxy) — they concentrate a short malicious burst
    // instead of averaging it into benign churn. Next levers: MiniLm+natural render, real SRL-2018 IOCs.
    [Fact(Skip = "one-off slow eval: streams the ~770MB Studiawan benign timeline; run manually with --filter")]
    public void NoveltySurfacesInjectedAttacksInRealTimeline()
    {
        var path = FindFullTimeline();
        Assert.True(path is not null, "Studiawan scenario-1 full/timeline.csv not found under reference/datasets.");

        // Sample a contiguous chronological prefix; KeepHighSignal drops the ~85% filestat/usnjrnl churn.
        var benign = CsvTimelineLoader.LoadCanonicalSampled(path!, maxRows: 600_000, NoiseFilters.KeepHighSignal);
        Assert.True(benign.Length >= 2_000, $"too few high-signal events sampled: {benign.Length}");

        int split = benign.Length * 7 / 10;                    // 70% baseline, 30% benign target
        var target = SyntheticIntrusion.Inject(benign[split..], SyntheticIntrusion.Episodes());

        var baseline = new TimelineNoveltyBaseline(new HashingEmbedder(256));
        var lines = new List<string>
        {
            $"benign sampled: {benign.Length} high-signal events (baseline {split}, target {benign.Length - split})",
        };
        AnomalyEvalResult? last = null;
        foreach (int size in new[] { 5, 10, 20 })              // smaller windows concentrate a short episode's signal
        {
            var result = baseline.Score("studiawan", benign[..split], target, WindowSpec.Tiled(size), k: 5);
            last = AnomalyDetectionEval.RankingMetrics(result, SyntheticIntrusion.WindowIsInjected, k: 20);
            lines.Add($"hashing+token Tiled({size}): {last}");
        }
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "camel_eval_anomaly.txt"), string.Join("\n", lines) + "\n");

        Assert.NotNull(last);
        Assert.True(last!.Positives > 0, "no injected windows produced");
        Assert.True(last.AveragePrecision > last.ChanceAp, $"novelty no better than chance: {last}");
    }

    // helpers
    private static EventWindow Win(bool injected) => new()
    {
        HostId = "h",
        CenterTs = 0,
        Events = injected
            ? [new CanonicalEvent { Ts = 0, DataType = "windows:evtx:record", Source = SourceClass.EventLog, Labels = [SyntheticIntrusion.Marker] }]
            : [new CanonicalEvent { Ts = 0, DataType = "windows:registry:key_value", Source = SourceClass.Registry }],
    };

    // Routine benign activity: mostly registry reads, with periodic logon/logoff — the "normal" the baseline learns.
    private static CanonicalEvent Benign(int i) => (i % 7) switch
    {
        0 => new() { Ts = i, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = 4624, HourOfDay = 14, DtPrev = 6f },
        3 => new() { Ts = i, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = 4634, HourOfDay = 14, DtPrev = 6f },
        _ => new() { Ts = i, DataType = "windows:registry:key_value", Source = SourceClass.Registry, Location = LocBucket.System32, HourOfDay = 14, DtPrev = 4f },
    };

    private static string? FindFullTimeline()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            var candidate = Path.Combine(d.FullName, "reference", "datasets", "scenario-1", "timeline", "full", "timeline.csv");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}
