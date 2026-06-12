using System;
using System.Linq;

using Camel.Training;

namespace Camel.Tests.Training;

public class EventDetectorTests
{
    // --- RareTypeDetector ---

    [Fact]
    public void RareTypeFlagsUnseenEventTypeNotCommonOnes()
    {
        var baseline = Enumerable.Range(0, 100).Select(i => Evtx(i, 4624)).ToArray();   // baseline is all 4624 logons
        var target = Enumerable.Range(0, 20).Select(i => Evtx(i, 4624))
            .Append(Evtx(20, 1102))                                                      // a never-seen log-clear
            .ToArray();

        var findings = new RareTypeDetector().Detect(baseline, target).ToArray();

        var hit = Assert.Single(findings);                                              // only the 1102 is notable
        Assert.Equal(20, hit.EventIndex);
        Assert.Equal("evtx:1102", hit.Token);
        Assert.True(hit.Bits > 20, $"unseen type should be highly surprising: {hit.Bits}");
    }

    // --- RareTransitionDetector ---

    [Fact]
    public void RareTransitionFlagsUnusualOrderOfCommonTypes()
    {
        // Baseline strictly alternates 4624/4634, so 4624→4634 and 4634→4624 are common but 4624→4624 never occurs.
        var baseline = Enumerable.Range(0, 100).Select(i => Evtx(i, i % 2 == 0 ? 4624 : 4634)).ToArray();
        var target = new[] { Evtx(0, 4624), Evtx(1, 4634), Evtx(2, 4624), Evtx(3, 4624), Evtx(4, 4634) };

        var findings = new RareTransitionDetector().Detect(baseline, target).ToArray();

        var hit = Assert.Single(findings);                                              // only the 4624→4624 at index 3
        Assert.Equal(3, hit.EventIndex);
        Assert.Contains("evtx:4624'→'evtx:4624", hit.Reason);
    }

    // --- TimingBurstDetector ---

    [Fact]
    public void TimingBurstFlagsRateSpikeOverBaseline()
    {
        // Baseline: a 4625 every ~100s (a slow trickle). Target: 20 of them inside ~4s — a spray.
        var baseline = Enumerable.Range(0, 10).Select(i => Evtx(i * 100 * Sec, 4625)).ToArray();
        var target = Enumerable.Range(0, 20).Select(i => Evtx(2000 * Sec + i * Sec / 5, 4625)).ToArray();

        var findings = new TimingBurstDetector().Detect(baseline, target).ToArray();

        Assert.NotEmpty(findings);
        var peak = findings.MaxBy(f => f.Bits)!;
        Assert.Equal("evtx:4625", peak.Token);
        Assert.True(peak.Bits > 6, $"a 30x rate spike should be surprising: {peak.Bits}");
    }

    // --- DetectorEnsemble + triage recall ---

    [Fact]
    public void EnsembleMergesRanksAndRecoversThePlantedEvent()
    {
        var baseline = Enumerable.Range(0, 100).Select(i => Evtx(i, 4624)).ToArray();
        var target = Enumerable.Range(0, 49).Select(i => Evtx(i, 4624))
            .Append(Evtx(49, 1102))                                                      // the one interesting event
            .ToArray();

        var report = DetectorEnsemble.Default().Triage(baseline, target, budget: 5);

        Assert.Equal(50, report.TotalEvents);
        Assert.Equal(49, report.Shortlist[0].EventIndex);                               // the 1102 ranks first
        // shortlist is descending by total bits
        var bits = report.Shortlist.Select(s => s.TotalBits).ToArray();
        Assert.True(bits.SequenceEqual(bits.OrderByDescending(b => b)));

        var positive = new bool[target.Length];
        positive[49] = true;
        var recall = AnomalyDetectionEval.ScoreTriage(report, positive);
        Assert.Equal(1, recall.Positives);
        Assert.Equal(1.0, recall.Recall, 6);
        Assert.Equal(1, recall.FirstRank);
    }

    const long Sec = 1_000_000;   // microseconds per second
    private static CanonicalEvent Evtx(long ts, int id) =>
        new() { Ts = ts, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = id };
}
