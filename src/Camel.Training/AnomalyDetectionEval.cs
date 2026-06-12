namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Scores a <see cref="NoveltyResult"/> against ground truth — the anomaly-detection metric that answers the actual
/// project goal: does novelty ranking surface the known-malicious episodes near the top? Unlike the balanced
/// action-classification proxy (<see cref="ActionClassificationEval"/>), this is a rare-positive ranking problem, so
/// it reports the ranking metrics that aren't fooled by class imbalance — precision@k / recall@k (the triage
/// shortlist view) and Average Precision (the threshold-free summary) — against the random-ranking floor.
/// </summary>
public static class AnomalyDetectionEval
{
    /// <summary>
    /// Computes ranking metrics over <paramref name="result"/> (windows already ordered most-novel-first), treating
    /// every window for which <paramref name="isMalicious"/> is true as a ground-truth positive.
    /// </summary>
    public static AnomalyEvalResult RankingMetrics(NoveltyResult result, Func<EventWindow, bool> isMalicious, int k = 10)
    {
        var labels = result.Windows.Select(w => isMalicious(w.Window)).ToArray();   // in novelty-rank order
        int n = labels.Length;
        int positives = labels.Count(b => b);

        int kk = Math.Clamp(k, 1, Math.Max(1, n));
        int hitsAtK = labels.Take(kk).Count(b => b);

        // Average Precision: mean of precision@rank evaluated at each positive's rank.
        double sumPrec = 0;
        int seen = 0, bestRank = -1;
        for (int i = 0; i < n; i++)
        {
            if (!labels[i]) continue;
            seen++;
            sumPrec += (double)seen / (i + 1);
            if (bestRank < 0) bestRank = i + 1;          // 1-based rank of the top-ranked positive
        }

        return new AnomalyEvalResult
        {
            Windows = n,
            Positives = positives,
            K = kk,
            HitsAtK = hitsAtK,
            PrecisionAtK = kk > 0 ? (double)hitsAtK / kk : 0,
            RecallAtK = positives > 0 ? (double)hitsAtK / positives : 0,
            AveragePrecision = positives > 0 ? sumPrec / positives : 0,
            BestRank = bestRank,
        };
    }
}

/// <summary>Ranking-quality metrics for a novelty result against known-malicious windows (higher = better).</summary>
public sealed record AnomalyEvalResult
{
    /// <summary>Total scored windows in the target stream.</summary>
    public required int Windows { get; init; }
    /// <summary>Ground-truth malicious windows.</summary>
    public required int Positives { get; init; }
    /// <summary>The cut-off used for the @k metrics (clamped to the window count).</summary>
    public required int K { get; init; }
    /// <summary>Malicious windows found in the top-<see cref="K"/> most-novel.</summary>
    public required int HitsAtK { get; init; }
    public required double PrecisionAtK { get; init; }
    public required double RecallAtK { get; init; }
    /// <summary>Average Precision over the full ranking — the threshold-free summary.</summary>
    public required double AveragePrecision { get; init; }
    /// <summary>1-based rank of the top-ranked malicious window (the analyst's "first hit"); -1 if none exist.</summary>
    public required int BestRank { get; init; }

    /// <summary>Average Precision of a random ranking (= positive prevalence) — the floor AP must beat to carry signal.</summary>
    public double ChanceAp => Windows > 0 ? (double)Positives / Windows : 0;

    public override string ToString() =>
        $"AP={AveragePrecision:P1} (chance={ChanceAp:P1}) · P@{K}={PrecisionAtK:P0} R@{K}={RecallAtK:P0} " +
        $"({HitsAtK}/{Positives} hits) · bestRank={BestRank}/{Windows}";
}

/// <summary>
/// Synthesises short known-malicious Windows event-log episodes — encoded as <see cref="CanonicalEvent"/>s carrying
/// distinctive event IDs (4104 script-block logging, 1102 log clear, 7045 service install, 4720 account creation,
/// …) — and splices them into a benign target stream as planted positives for the anomaly eval. Each injected event
/// is tagged with <see cref="Marker"/> (a supervision label, never rendered into the embedding) so the windows
/// containing them can be recovered as ground truth. The episodes mirror real attacker behaviours that a benign
/// baseline rarely contains, so a content-aware novelty scorer should rank the windows holding them near the top.
/// </summary>
public static class SyntheticIntrusion
{
    /// <summary>The supervision label stamped on every injected event (not an input feature — see the renderers).</summary>
    public const string Marker = "__injected__";

    public static bool IsInjected(CanonicalEvent e) => Array.IndexOf(e.Labels, Marker) >= 0;
    public static bool WindowIsInjected(EventWindow w) => w.Events.Any(IsInjected);

    /// <summary>The catalog of malicious episodes, each a contiguous run of event-log records.</summary>
    public static CanonicalEvent[][] Episodes() =>
    [
        // Encoded-PowerShell C2: a powershell process creation followed by script-block-logging records
        // (the SRL-2018 "squirreldirectory.com" DownloadString/IEX pattern).
        [Evt(4688, LocBucket.System32), Evt(4104, ext: "ps1"), Evt(4104, ext: "ps1"), Evt(4104, ext: "ps1"), Evt(4104, ext: "ps1")],

        // Anti-forensics: security and system event logs cleared (1102 / 104) around a service state change.
        [Evt(4688, LocBucket.System32), Evt(1102), Evt(104), Evt(7036), Evt(1102)],

        // Credential dumping: privileged logon, repeated sensitive object access (lsass), an explicit-credential logon.
        [Evt(4672), Evt(4663), Evt(4663), Evt(4663), Evt(4648)],

        // Service-based persistence: a new service installed and started, then a logon under it.
        [Evt(7045, LocBucket.Temp, "exe"), Evt(4697), Evt(7036), Evt(4624), Evt(4672)],

        // Rogue account persistence: account created, group-membership and account changes.
        [Evt(4720), Evt(4732), Evt(4724), Evt(4738), Evt(4720)],
    ];

    /// <summary>
    /// Splices <paramref name="episodes"/> into <paramref name="benign"/> at evenly spaced positions as contiguous
    /// blocks, time-stamping each injected event just before its anchor benign event so the stream stays ordered
    /// (the <see cref="Windower"/> tiles in array order). Returns the combined stream.
    /// </summary>
    public static CanonicalEvent[] Inject(CanonicalEvent[] benign, IReadOnlyList<CanonicalEvent[]> episodes)
    {
        if (benign.Length == 0 || episodes.Count == 0) return benign;

        int span = Math.Max(1, benign.Length / (episodes.Count + 1));
        var at = new Dictionary<int, CanonicalEvent[]>();
        for (int i = 0; i < episodes.Count; i++) at[Math.Min(benign.Length - 1, (i + 1) * span)] = episodes[i];

        var result = new List<CanonicalEvent>(benign.Length + episodes.Sum(e => e.Length));
        for (int idx = 0; idx < benign.Length; idx++)
        {
            if (at.TryGetValue(idx, out var episode))
            {
                long anchor = benign[idx].Ts;
                for (int j = 0; j < episode.Length; j++) result.Add(episode[j] with { Ts = anchor + j });
            }
            result.Add(benign[idx]);
        }
        return result.ToArray();
    }

    private static CanonicalEvent Evt(int eventId, LocBucket loc = LocBucket.Unknown, string? ext = null) => new()
    {
        Ts = 0,                                  // assigned at injection
        DataType = "windows:evtx:record",
        Source = SourceClass.EventLog,
        EventId = eventId,
        Location = loc,
        Ext = ext,
        DtPrev = 1.5f,                           // a "moments later" burst — scripted activity
        HourOfDay = 2,                           // off-hours
        Labels = [Marker],
    };
}
