using System;
using System.IO;
using System.Linq;

using Camel.Training;
using Camel.Inference;

namespace Camel.Tests.Training;

public class MiniLmEmbedderTests : TestsRuntime
{
    // Smoke test for the real ONNX embedder. Downloads the ~90 MB all-MiniLM model on first run (cached in a
    // stable temp dir so reruns are fast). Verifies the vectors are well-formed and carry semantic structure.
    [Fact]
    public void EmbedsNormalized384dVectorsWithSemanticStructure()
    {
        var modelDir = Path.Combine(Path.GetTempPath(), "camel-models");
        using var emb = new MiniLmEmbedder(modelDir);

        Assert.Equal(384, emb.Dimension);

        var exec1 = emb.Embed("eventlog evtx record eid4624 loc:system32 macb:...b h:3");
        var exec2 = emb.Embed("eventlog evtx record eid4625 loc:system32 macb:...b h:3");
        var web = emb.Embed("webhistory firefox page_visited loc:appdata h:14");

        Assert.Equal(384, exec1.Length);
        Assert.Equal(1.0, Math.Sqrt(exec1.Sum(x => (double)x * x)), 3);          // L2-normalized
        // The two logon-ish sentences embed closer to each other than to a web-history sentence.
        Assert.True(VectorMath.Dot(exec1, exec2) > VectorMath.Dot(exec1, web),
            "expected the two logon sentences to be more similar than logon vs web-history");

        // It plugs into the rendered-event path used by the novelty pipeline.
        var v = emb.Embed(TextRenderer.Render(new CanonicalEvent
        {
            Ts = 1, DataType = "windows:registry:appcompatcache", Source = SourceClass.Registry, Reg = RegClass.Shimcache,
        }));
        Assert.Equal(384, v.Length);
    }

    // The full anomaly spine running on LEARNED embeddings: a benign registry baseline, then a target stream with
    // an injected EVTX/temp-exe episode that the MiniLM-backed novelty scorer must surface on top.
    [Fact]
    public void NoveltyBaselineSurfacesAnomalyWithLearnedEmbeddings()
    {
        using var emb = new MiniLmEmbedder(Path.Combine(Path.GetTempPath(), "camel-models"));

        static CanonicalEvent Normal(int i) => new()
        { Ts = i, DataType = "windows:registry:key_value", Source = SourceClass.Registry, Location = LocBucket.System32, HourOfDay = 3 };
        static CanonicalEvent Anomalous(int i) => new()
        { Ts = i, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = 4624, Location = LocBucket.Temp, Ext = "exe", HourOfDay = 3 };

        var baseline = Enumerable.Range(0, 40).Select(Normal).ToArray();
        var target = Enumerable.Range(0, 20).Select(Normal)
            .Concat(Enumerable.Range(20, 10).Select(Anomalous))     // injected episode (indices 20-29)
            .Concat(Enumerable.Range(30, 10).Select(Normal))
            .ToArray();

        var result = new TimelineNoveltyBaseline(emb).Score("host", baseline, target, WindowSpec.Tiled(5), k: 3);

        Assert.All(result.Top(1)[0].Window.Events, e => Assert.Equal(SourceClass.EventLog, e.Source));
        Assert.True(result.Top(1)[0].Novelty > result.Windows.Last().Novelty + 0.05f);
    }
}
