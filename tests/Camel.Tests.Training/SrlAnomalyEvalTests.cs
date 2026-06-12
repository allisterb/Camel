using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Training;

namespace Camel.Tests.Training;

/// <summary>
/// Real-data anomaly validation on the SRL-2018 compromised RDS host (base-rd-01): does LABEL-FREE novelty ranking
/// over the host's own Windows event logs surface the attacker's log-clearing (1102 "audit log cleared" / 104
/// "log cleared") — the anti-forensics IOCs — near the top, with no rules and no labels? Unlike the synthetic eval
/// the positives are REAL and the ground truth is non-circular: we never construct the malicious events, we only
/// label-by-EventId for scoring. The input is a slim 3-column CSV (ts, timestamp_desc, event_identifier) distilled
/// on the SIFT box from a full plaso export of Security.evtx + System.evtx — see the regen recipe below.
/// </summary>
public class SrlAnomalyEvalTests
{
    // Regenerate the slim CSV on the SIFT box, then pull it to %TEMP%\camel_srl_slim.csv:
    //   log2timeline.py -q --storage-file /tmp/camel_srl_evtx.plaso --parsers winevtx <Security.evtx>
    //   log2timeline.py -q --storage-file /tmp/camel_srl_evtx.plaso --parsers winevtx <System.evtx>     (appends)
    //   psort.py -q -o json_line -w /tmp/srl_full.jsonl /tmp/camel_srl_evtx.plaso
    //   python3 -> for each line write "{timestamp},{timestamp_desc},{event_identifier}"  (=> /tmp/srl_slim.csv)
    //   plink ... "cat /tmp/srl_slim.csv" > %TEMP%\camel_srl_slim.csv
    private static readonly string SlimCsv = Path.Combine(Path.GetTempPath(), "camel_srl_slim.csv");

    // Measured one-off (130,948 evtx events; baseline 70k / target 20k incl. the 8 log-clear rows; ~2.5min incl.
    // canonicalize+embed). The headline real-data finding — bag-of-tokens window novelty FAILS, event-id rarity NAILS it:
    //   Tiled(3)   embed AP=0.3% rank=542/6667 (0/3)   |   rarity AP=100% rank=1 (3/3)
    //   Tiled(5)   embed AP=0.3% rank=338/4000 (0/2)   |   rarity AP=100% rank=1 (2/2)
    //   Tiled(20)  embed AP=0.2% rank=608/1000 (0/1)   |   rarity AP=100% rank=1 (1/1)
    // CONCLUSION: on a busy, type-diverse REAL host the embedding washes the one discriminative field (EventId) out
    // among generic structural tokens, so a lone rare anti-forensics event (1102/104) sits mid-pack. A trivial
    // event-id surprisal model (-log₂ p(EventId), zero baseline freq => maximal) ranks every log-clear window FIRST.
    // Validates the (event_id, Δt) head as the right primitive for rare-event-TYPE IOCs; the embedding head is for
    // rare-CONTENT-within-common-types (which neither catches yet — the malicious 4104 PS is invisible post-canon).
    [Fact(Skip = "one-off real-data eval: needs the staged SRL slim CSV (see regen recipe); run manually with --filter")]
    public void NoveltySurfacesLogClearingInSrlHost()
    {
        Assert.True(File.Exists(SlimCsv), $"staged SRL slim CSV not found at {SlimCsv} — regenerate it (see recipe).");

        var canon = EventCanonicalizer.Canonicalize(LoadSlim(SlimCsv), NoiseFilters.KeepHighSignal);
        Assert.True(canon.Length > 50_000, $"expected the full SRL evtx stream: {canon.Length}");

        // The 1102/104 log-clears are the OLDEST surviving records (clearing resets the log), so they sit at the
        // very front of the time-sorted stream. Fit the benign baseline on a disjoint LATER slice of normal
        // activity (no IOCs, no label leakage), and score an early slice that contains the log-clear burst.
        var target = canon[..20_000];
        var baseline = canon[20_000..Math.Min(canon.Length, 90_000)];
        int targetIocs = target.Count(IsLogClear);
        Assert.True(targetIocs > 0, "no log-clear events in the target slice");

        var scorer = new TimelineNoveltyBaseline(new HashingEmbedder(256));
        var lines = new List<string>
        {
            $"SRL base-rd-01 Security+System.evtx: {canon.Length} high-signal events; baseline {baseline.Length}, " +
            $"target {target.Length} ({targetIocs} log-clear events). Ground truth = EventId in {{1102,104}}.",
        };
        AnomalyEvalResult? embedBest = null, rarityBest = null;
        foreach (int size in new[] { 3, 5, 10, 20 })
        {
            // Head 1: bag-of-tokens window embedding novelty (washes EventId out among generic tokens).
            var embed = AnomalyDetectionEval.RankingMetrics(
                scorer.Score("base-rd-01", baseline, target, WindowSpec.Tiled(size), k: 5), IsLogClearWindow, k: 20);
            // Head 2: event-id rarity / surprisal (keys directly on the rare event type).
            var rarity = AnomalyDetectionEval.RankingMetrics(
                EventIdRarityScorer.Rank("base-rd-01", baseline, target, WindowSpec.Tiled(size)), IsLogClearWindow, k: 20);
            lines.Add($"Tiled({size,2})  embed: {embed}");
            lines.Add($"Tiled({size,2})  rarity: {rarity}");
            embedBest = embed; rarityBest = rarity;
        }
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "camel_eval_srl.txt"), string.Join("\n", lines) + "\n");

        // The whole point: rarity surfaces the log-clears, embedding does not.
        Assert.NotNull(rarityBest);
        Assert.True(rarityBest!.Positives > 0, "no log-clear windows produced");
        Assert.True(rarityBest.BestRank == 1, $"event-id rarity failed to rank a log-clear window first: {rarityBest}");
    }

    // Measured one-off — the (event_id, Δt) ensemble as a TRIAGE tool on the real host (self-baseline, ~2s):
    //   budget  50: recall 25% (2/8) · shortlist 50    (compression 0.04%)
    //   budget 200: recall 100% (8/8) · shortlist 182  (compression 0.14%, ~720x reduction) · firstRank 86
    //   budget 500: recall 100% (8/8) · shortlist 448  (compression 0.34%)
    // CONCLUSION: reduces a 130,948-event timeline to a ~182-event review set that contains EVERY log-clearing IOC,
    // with human-readable reasons — the actual goal ("narrow down events worth examining"). The shortlist top is the
    // attacker's bulk audit-policy bursts (4907/4945 at 2018-08-06 19:14, IR-relevant) + a rare 4672→4907 transition.
    // Per-detector quota was REQUIRED: without it, timing-burst's astronomical bits (34k for a 2318-event 4907 burst)
    // crowded out the rare-type log-clears (~17 bits) entirely (recall 0%). Episode-collapse (one burst = one entry)
    // was also required (raw per-event ranking filled all 500 slots with copies of one burst).
    [Fact(Skip = "one-off real-data eval: needs the staged SRL slim CSV (see regen recipe); run manually with --filter")]
    public void TriageShortlistsLogClearingInSrlHost()
    {
        Assert.True(File.Exists(SlimCsv), $"staged SRL slim CSV not found at {SlimCsv} — regenerate it (see recipe).");

        // Self-baseline: no clean reference, just the host's own full timeline — the realistic triage case. The
        // detectors fit their stats on the stream and score the same stream; the few IOCs stay rare.
        var canon = EventCanonicalizer.Canonicalize(LoadSlim(SlimCsv), NoiseFilters.KeepHighSignal);
        var positive = canon.Select(IsLogClear).ToArray();

        var ensemble = DetectorEnsemble.Default();
        var lines = new System.Collections.Generic.List<string>
        {
            $"SRL base-rd-01: {canon.Length} events, {positive.Count(b => b)} log-clear (1102/104). Self-baseline (event_id, Δt) ensemble.",
        };
        foreach (int budget in new[] { 50, 100, 200, 500 })
        {
            var report = ensemble.Triage(canon, canon, budget);
            lines.Add($"budget {budget,4}: {AnomalyDetectionEval.ScoreTriage(report, positive)}  (candidates={report.Candidates})");
        }
        // Qualitative: what the top of the shortlist actually looks like (the reasons the agent would read).
        var top = ensemble.Triage(canon, canon, 500);
        lines.Add("--- top 15 shortlist items ---");
        lines.AddRange(top.Shortlist.Take(15).Select(s => s.ToString()));
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "camel_triage_srl.txt"), string.Join("\n", lines) + "\n");

        var recall500 = AnomalyDetectionEval.ScoreTriage(top, positive);
        Assert.True(recall500.Recall == 1.0, $"triage missed a log-clear within a 500-event budget: {recall500}");
    }

    private static bool IsLogClear(CanonicalEvent e) => e.EventId is 1102 or 104;
    private static bool IsLogClearWindow(EventWindow w) => w.Events.Any(IsLogClear);

    // Parses the slim "ts,desc,eid" CSV into raw events; Message is reconstructed as Plaso's "[<id> / 0x0]" prefix
    // so the existing EventCanonicalizer.ExtractEventId recovers the EventId unchanged.
    private static TimelineEvent[] LoadSlim(string path)
    {
        var events = new List<TimelineEvent>(140_000);
        bool header = true;
        foreach (var line in File.ReadLines(path))
        {
            if (header) { header = false; continue; }
            if (line.Length == 0) continue;
            int c1 = line.IndexOf(','); int c2 = line.LastIndexOf(',');
            if (c1 <= 0 || c2 <= c1) continue;
            if (!long.TryParse(line.AsSpan(0, c1), out long ts)) continue;
            var desc = line[(c1 + 1)..c2];
            var eid = line[(c2 + 1)..];
            events.Add(new TimelineEvent
            {
                Timestamp = ts,
                TimestampDesc = desc,
                DataType = "windows:evtx:record",
                Message = $"[{eid} / 0x0]",
            });
        }
        return events.ToArray();
    }
}
