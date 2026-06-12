using System;
using System.Linq;

using Camel.Environments;
using Camel.Training;

namespace Camel.Tests.Training;

public class AnomalySpineTests : TestsRuntime
{
    public AnomalySpineTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelApi(sshenv, sshconfig);
    }

    // --- Windower ---

    [Fact]
    public void SlidingByCountTilesAndTruncatesTail()
    {
        var evs = Enumerable.Range(0, 10).Select(i => C(i, "windows:registry:key_value")).ToArray();

        var tiled = Windower.SlidingByCount("h", evs, size: 4, stride: 4);
        Assert.Equal(3, tiled.Length);                       // [0-3] [4-7] [8-9]
        Assert.Equal(4, tiled[0].Count);
        Assert.Equal(2, tiled[^1].Count);                    // truncated tail

        var overlap = Windower.SlidingByCount("h", evs, size: 4, stride: 2);
        Assert.Equal(4, overlap.Length);                     // starts 0,2,4,6
        Assert.All(overlap, w => Assert.Equal("h", w.HostId));
    }

    [Fact]
    public void AroundPivotKeepsOnlyInWindowEvents()
    {
        var evs = Enumerable.Range(0, 11).Select(i => C((long)i * 60_000_000, "x:y")).ToArray();  // one/min
        var w = Windower.AroundPivot("h", evs, centerTs: 5 * 60_000_000, halfWindowMinutes: 2);
        Assert.Equal(5, w.Count);                            // minutes 3,4,5,6,7
        Assert.All(w.Events, e => Assert.InRange(e.Ts, 3 * 60_000_000L, 7 * 60_000_000L));
    }

    // --- HashingEmbedder ---

    [Fact]
    public void HashingEmbedderIsDeterministicAndNormalized()
    {
        var emb = new HashingEmbedder(256);
        var a1 = emb.Embed("registry key_value loc:system32 h:3");
        var a2 = emb.Embed("registry key_value loc:system32 h:3");
        var b = emb.Embed("eventlog evtx record eid4624 loc:temp ext:exe");

        Assert.Equal(256, a1.Length);
        Assert.Equal(a1, a2);                                                   // deterministic
        Assert.NotEqual(a1, b);                                                 // different text → different vector
        Assert.Equal(1.0, Math.Sqrt(a1.Sum(x => (double)x * x)), 3);            // L2-normalized
    }

    // --- NoveltyScorer ---

    [Fact]
    public void NoveltyScorerScoresIdenticalNearZeroAndOrthogonalNearOne()
    {
        float[] e0 = Unit(0), e1 = Unit(1);
        var scorer = new NoveltyScorer([e0], k: 1);
        Assert.Equal(0f, scorer.Score(e0), 3);               // identical to baseline
        Assert.Equal(1f, scorer.Score(e1), 3);               // orthogonal to baseline
    }

    // --- end-to-end novelty baseline ---

    [Fact]
    public void NoveltyBaselineRanksAnomalousEpisodeOnTop()
    {
        // Baseline + most of the target is repetitive "normal" registry activity; a contiguous block of EVTX
        // logon / temp-exe events is injected — a behaviourally distinct episode the scorer should surface.
        var normal = Enumerable.Range(0, 60).Select(i => Normal(i)).ToArray();
        var target = Enumerable.Range(0, 40).Select(i => Normal(i))
            .Concat(Enumerable.Range(40, 10).Select(i => Anomalous(i)))         // the injected episode (indices 40-49)
            .Concat(Enumerable.Range(50, 10).Select(i => Normal(i)))
            .ToArray();

        var baseline = new TimelineNoveltyBaseline(new HashingEmbedder(256));
        var result = baseline.Score("host", normal, target, WindowSpec.Tiled(5), k: 3);

        Assert.True(result.Count > 0);
        Assert.All(result.Windows, w => Assert.InRange(w.Novelty, -0.01f, 2.01f));
        // ranked most-novel-first, and the top window is from the injected episode.
        var novelties = result.Windows.Select(w => w.Novelty).ToArray();
        Assert.True(novelties.SequenceEqual(novelties.OrderByDescending(n => n)));
        Assert.All(result.Top(1)[0].Window.Events, e => Assert.Equal(SourceClass.EventLog, e.Source));
        Assert.True(result.Top(1)[0].Novelty > result.Windows.Last().Novelty + 0.2f);   // clearly above normal
    }

    // --- integration: run the spine over a real dlpc timeline ---

    [Fact]
    public async Task ScoresRealDlpcTimelineWindows()
    {
        if (!sshenv.ExecuteCommand("test", $"-f {RegPlaso}", out _, false))
            Assert.True(await api.Timeline.Log2TimelineAsync(SystemHive, RegPlaso, parsers: "winreg"));
        var events = await api.Timeline.PsortAsync(RegPlaso, "data_type contains 'appcompatcache'");
        Assert.NotNull(events);
        var canon = EventCanonicalizer.Canonicalize(events);
        Assert.True(canon.Length >= 20);

        // Fit on the first 60% of the stream, score the whole thing.
        int split = canon.Length * 3 / 5;
        var baseline = new TimelineNoveltyBaseline(new HashingEmbedder(256));
        var result = baseline.Score("dlpc", canon[..split], canon, WindowSpec.Tiled(10), k: 3);

        Assert.True(result.Count > 0);
        Assert.All(result.Windows, w => Assert.InRange(w.Novelty, -0.01f, 2.01f));
        var n = result.Windows.Select(w => w.Novelty).ToArray();
        Assert.True(n.SequenceEqual(n.OrderByDescending(x => x)));      // ranked
    }

    // helpers
    private static CanonicalEvent C(long ts, string dataType) => new() { Ts = ts, DataType = dataType };
    private static CanonicalEvent Normal(int i) => new()
    {
        Ts = i, DataType = "windows:registry:key_value", Source = SourceClass.Registry, Location = LocBucket.System32, HourOfDay = 3,
    };
    private static CanonicalEvent Anomalous(int i) => new()
    {
        Ts = i, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = 4624,
        Location = LocBucket.Temp, Ext = "exe", HourOfDay = 3,
    };
    private static float[] Unit(int idx) { var v = new float[8]; v[idx] = 1f; return v; }

    const string SystemHive = "/mnt/dlpc/Windows/System32/config/SYSTEM";
    const string RegPlaso = "/tmp/camel_train_reg.plaso";

    AuditEnvironment sshenv;
    CamelApi api;
}
