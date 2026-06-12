using System;

using Camel.Training;

namespace Camel.Tests.Training;

public class NaturalRenderTests : TestsRuntime
{
    [Fact]
    public void RendersLeakageSafeNaturalSentences()
    {
        var first = NaturalRenderer.Render(new CanonicalEvent
        {
            Ts = 1, DataType = "windows:registry:appcompatcache", Source = SourceClass.Registry,
            Reg = RegClass.Shimcache, Location = LocBucket.System32, Macb = Macb.Modified, HourOfDay = 3, DtPrev = 0f,
        });
        Assert.StartsWith("A", first);                                  // capitalized, no cadence lead-in (first event)
        Assert.Contains("shimcache", first, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("System32 directory", first);
        Assert.Contains("was modified", first);
        Assert.Contains("at 03:00", first);

        var later = NaturalRenderer.Render(new CanonicalEvent
        {
            Ts = 2, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = 4624,
            Location = LocBucket.Temp, Macb = Macb.Birth, HourOfDay = 14, DtPrev = 1.5f,
        });
        Assert.StartsWith("Moments later,", later);                     // small Δt → cadence lead-in
        Assert.Contains("successful logon", later);                     // 4624 mapped to meaning
        Assert.Contains("event 4624", later);
        Assert.Contains("temporary folder", later);
    }

    // Measured one-off via DatasetEvaluator over the Studiawan dataset (Tiled(20), k=5, chance 6.7%):
    //   hashing + token render : 23.5% acc / 22.2% F1   (discriminative tokens preserved)
    //   hashing + natural render: 22.5% / 21.0%          (NL filler slightly dilutes — as expected)
    //   MiniLM  + token render : 19.6% / 18.5%           (no NL prior for token salad)
    //   MiniLM  + natural render: 23.4% / 22.2%          (+3.8pts — prose engages the NL prior, gap erased)
    // Takeaway: render must match the embedder (NaturalRenderer for MiniLM, TextRenderer for hashing); on this
    // closed-vocab task even the right render only TIES bag-of-tokens — the domain-specific encoder and the
    // cross-host generalization of NL+MiniLM are where the real upside should appear. Slow (MiniLM) eval kept out
    // of the suite; see the memory note.
}
