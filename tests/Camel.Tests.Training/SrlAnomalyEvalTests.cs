using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Training;
using Camel.Inference;

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

    // 3-log slim CSV (ts,desc,eid,msg_len,c2,snippet) adds the PowerShell Operational log + content columns. Regen:
    //   cp /tmp/camel_srl_evtx.plaso /tmp/camel_srl_3logs.plaso
    //   log2timeline.py -q --storage-file /tmp/camel_srl_3logs.plaso --parsers winevtx <...PowerShell%4Operational.evtx>
    //   psort.py -q -o json_line -w full.jsonl /tmp/camel_srl_3logs.plaso
    //   python3 -> per line: timestamp, timestamp_desc, event_identifier, len(message), (1 if 'squirreldirectory' in
    //              message.lower() else 0), message.lower()[:200] with commas/newlines->space  (=> /tmp/srl3_slim.csv)
    //   plink ... "cat /tmp/srl3_slim.csv" > %TEMP%\camel_srl_slim3.csv
    private static readonly string Slim3Csv = Path.Combine(Path.GetTempPath(), "camel_srl_slim3.csv");

    // Measured one-off — the content detector (Studiawan Ch.7 bad-words + message-length) closes the C2 gap:
    //   content-only: C2 recall 100% (24/24) · shortlist 65 · firstRank 8   ← previously UNDETECTABLE
    //   ensemble 200: C2 100% (24/24) | log-clear 100% (8/8) | ALL 100% (32/32) · shortlist 148 (compression 0.10%, ~985x), full 5-detector ensemble
    // CONCLUSION: adding the two leakage-safe content scalars lets the toolkit recover BOTH IOC classes — the C2
    // PowerShell (squirreldirectory download cradle, caught by keywords + 25k-char encoded-blob length on 4103/4104)
    // AND the anti-forensics log-clears — in a 180-event review set out of 145,756. The thesis idea works.
    [Fact(Skip = "one-off real-data eval: needs the staged 3-log SRL slim CSV (see recipe); run manually with --filter")]
    public void TriageSurfacesC2AndLogClearingInSrlHost()
    {
        Assert.True(File.Exists(Slim3Csv), $"staged SRL 3-log slim CSV not found at {Slim3Csv} — regenerate it.");

        var canon = EventCanonicalizer.Order(LoadSlim3(Slim3Csv), NoiseFilters.KeepHighSignal);
        var isC2 = canon.Select(e => Array.IndexOf(e.Labels, "__c2__") >= 0).ToArray();
        var isLogClear = canon.Select(IsLogClear).ToArray();
        var isInteresting = canon.Select((e, i) => isC2[i] || isLogClear[i]).ToArray();

        var lines = new System.Collections.Generic.List<string>
        {
            $"SRL base-rd-01 (Security+System+PowerShell): {canon.Length} events. " +
            $"C2 (squirreldirectory) {isC2.Count(b => b)}, log-clear {isLogClear.Count(b => b)}. Self-baseline.",
        };

        // The content detector alone — does it surface the C2 PowerShell the type/sequence/timing heads are blind to?
        var contentOnly = new DetectorEnsemble(new ContentDetector()).Triage(canon, canon, 500);
        lines.Add($"content-only:   C2 {AnomalyDetectionEval.ScoreTriage(contentOnly, isC2)}");

        // The full ensemble as the triage tool.
        var ensemble = DetectorEnsemble.Default();
        foreach (int budget in new[] { 100, 200, 500 })
        {
            var r = ensemble.Triage(canon, canon, budget);
            lines.Add($"ensemble {budget,4}: C2 {AnomalyDetectionEval.ScoreTriage(r, isC2)} | " +
                      $"log-clear {AnomalyDetectionEval.ScoreTriage(r, isLogClear)} | all {AnomalyDetectionEval.ScoreTriage(r, isInteresting)}");
        }
        var top = ensemble.Triage(canon, canon, 500);
        lines.Add("--- top 15 ---");
        lines.AddRange(top.Shortlist.Take(15).Select(s => s.ToString()));
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "camel_triage_srl3.txt"), string.Join("\n", lines) + "\n");

        Assert.True(AnomalyDetectionEval.ScoreTriage(contentOnly, isC2).Recall > 0, "content detector did not surface the C2");
        Assert.True(AnomalyDetectionEval.ScoreTriage(top, isInteresting).Recall >= 0.5, "triage recovered <50% of interesting events");
    }

    // Builds canonical events directly from the 3-log slim CSV; BadWordCount is computed by the real ContentSignals
    // dictionary over the staged message snippet (so the eval exercises production code), MsgLength is the box-side
    // full message length. c2 ground truth is carried as a label (never an input feature).
    private static CanonicalEvent[] LoadSlim3(string path)
    {
        var events = new System.Collections.Generic.List<CanonicalEvent>(150_000);
        bool header = true;
        foreach (var line in File.ReadLines(path))
        {
            if (header) { header = false; continue; }
            if (line.Length == 0) continue;
            var f = line.Split(',', 6);
            if (f.Length < 5 || !long.TryParse(f[0], out long ts) || !int.TryParse(f[3], out int msgLen)) continue;
            var snippet = f.Length == 6 ? f[5] : "";
            events.Add(new CanonicalEvent
            {
                Ts = ts,
                DataType = "windows:evtx:record",
                Source = SourceClass.EventLog,
                EventId = int.TryParse(f[2], out int id) ? id : null,
                MsgLength = msgLen,
                BadWordCount = ContentSignals.BadWordCount(snippet),
                HourOfDay = DateTimeOffset.FromUnixTimeMilliseconds(ts / 1000).UtcDateTime.Hour,
                Labels = f[4] == "1" ? ["__c2__"] : [],
            });
        }
        return events.ToArray();
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
