using System;
using System.IO;
using System.Linq;

using Camel.Training;
using Camel.Inference;

namespace Camel.Tests.Training;

public class NomicEmbedderTests : TestsRuntime
{
    private static string ModelDir => Path.Combine(Path.GetTempPath(), "camel-models");

    [Fact]
    public void NomicEmbedsNormalized768dWithSemanticStructure()
    {
        using var emb = new NomicEmbedder(ModelDir);
        Assert.Equal(768, emb.Dimension);

        var a = emb.Embed("A successful logon occurred in the System32 directory.");
        var b = emb.Embed("A failed logon occurred in the System32 directory.");
        var c = emb.Embed("A web browsing record was accessed in the user's AppData folder.");

        Assert.Equal(768, a.Length);
        Assert.Equal(1.0, Math.Sqrt(a.Sum(x => (double)x * x)), 3);              // L2-normalized
        Assert.True(VectorMath.Dot(a, b) > VectorMath.Dot(a, c),                 // logon vs logon > logon vs web
            "expected the two logon sentences to be more similar than logon vs web-history");
    }

    // Measured one-off via DatasetEvaluator (nomic + NaturalRenderer + "classification:" prefix, Tiled(20), k=5,
    // chance 6.7%): 23.9% acc / 23.2% macroF1 — the best of the four embedder×render combos and the most balanced
    // (highest macro-F1), edging hashing+token (23.5/22.2) and MiniLM+natural (23.4/22.2). BUT the gain is marginal
    // and nomic-q4 inference is ~10× slower than MiniLM (the 1608-window eval took ~13.5 min vs ~82s). The deeper
    // finding: all embedders plateau at ~23-24% because ~80% of each window is shared FILE/usnjrnl/filestat noise
    // common to every action — the ceiling is the representation (noise), not the embedder. Kept out of the suite;
    // see the memory note. The slow dataset eval is reproducible via DatasetEvaluator.EvaluateActionClassification.
}
