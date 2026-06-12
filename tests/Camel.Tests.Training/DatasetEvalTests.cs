using System;
using System.IO;
using System.Linq;

using Camel.Training;
using Camel.Inference;

namespace Camel.Tests.Training;

public class DatasetEvalTests : TestsRuntime
{
    // --- pure l2tcsv loader tests ---

    const string Header = "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag";

    [Fact]
    public void LoadsL2tcsvAndSynthesizesBehaviouralFields()
    {
        var csv = Header + "\n" +
            @"2023-12-26 00:36:37.906410+00:00,Last Written Time,REG,Shimcache,[HKLM AppCompatCache] entries,winreg/appcompatcache,NTFS:\Windows\System32\config\SYSTEM,-" + "\n" +
            @"2023-12-26 00:36:38.000000+00:00,Content Modification Time,FILE,File stat,NTFS:\Users\User\AppData\Local\Temp\x.exe Type: file,filestat,NTFS:\Users\User\AppData\Local\Temp\x.exe,-" + "\n" +
            @"2023-12-26 00:36:39.000000+00:00,Creation Time,EVT,WinEVTX,[4624 / 0x1210] An account was logged on,winevtx,NTFS:\Windows\System32\winevt\Logs\Security.evtx,-" + "\n" +
            @"1601-01-01T00:00:00.000000+00:00,Expiration Time,WEBHIST,Chrome Cookies,http://x (cookie) Flags,sqlite/chrome_66_cookies,NTFS:\Users\User\Cookies,-" + "\n";

        var c = CsvTimelineLoader.LoadCanonicalFromText(csv);

        Assert.Equal(3, c.Length);                                  // the 1601 pre-epoch expiry row is dropped
        for (int i = 1; i < c.Length; i++) Assert.True(c[i].Ts >= c[i - 1].Ts);   // sorted

        var reg = Assert.Single(c, e => e.Source == SourceClass.Registry);
        Assert.Equal(RegClass.Shimcache, reg.Reg);                  // winreg/appcompatcache -> Shimcache
        Assert.Equal(LocBucket.System32, reg.Location);

        var file = Assert.Single(c, e => e.Source == SourceClass.FileSystem);
        Assert.Equal(LocBucket.AppData, file.Location);             // \AppData\Local\Temp -> AppData
        Assert.Equal("exe", file.Ext);

        var evt = Assert.Single(c, e => e.Source == SourceClass.EventLog);
        Assert.Equal(4624, evt.EventId);                           // parsed from "[4624 / 0x1210] ..."
    }

    [Fact]
    public void LabelFromFileNameStripsNumericPrefix()
    {
        Assert.Equal("launch-cmd", DatasetEvaluator.LabelFromFileName("3-launch-cmd"));
        Assert.Equal("firefox-install", DatasetEvaluator.LabelFromFileName("8-firefox-install"));
        Assert.Equal("plain", DatasetEvaluator.LabelFromFileName("plain"));
    }

    // --- real dataset: representation quality via k-NN action classification ---

    [Fact]
    public void HashingEmbeddingsSeparateUserActionsAboveChance()
    {
        var dir = FindEventsDir();
        Assert.True(dir is not null, "Studiawan scenario-1 dataset not found under reference/datasets.");

        var result = DatasetEvaluator.EvaluateActionClassification(dir!, new HashingEmbedder(256), WindowSpec.Tiled(20), k: 5);
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "camel_eval_hashing.txt"),
            result + "\n" + string.Join("\n", result.PerClass.OrderByDescending(p => p.F1).Select(p => $"  {p.Label}: F1={p.F1:P0} n={p.Support}")));

        Assert.True(result.Samples > 100, $"too few windows: {result}");
        Assert.True(result.Accuracy > result.Chance * 1.5, $"no separation signal: {result}");
        Assert.True(result.MacroF1 > 0, result.ToString());
    }

    // NOTE: the MiniLM embedder runs through this same harness (DatasetEvaluator.EvaluateActionClassification
    // with a MiniLmEmbedder), but it is intentionally NOT a permanent test: it costs ~82s for 1608 ONNX
    // inferences and — the notable finding — does NOT beat this hashing baseline on these structured token
    // sequences (≈19.6% acc vs 23.5%), since all-MiniLM is trained on natural language, not our canonical
    // token salad. That motivates a domain-specific encoder over an off-the-shelf NL one. See the memory note.

    [Fact]
    public void SemanticRenderExpandsValuesGatesArtifactExtAndDelimitsStructural()
    {
        var reg = new CanonicalEvent
        { Ts = 1, DataType = "windows:registry:appcompatcache", Source = SourceClass.Registry, Reg = RegClass.Shimcache, Location = LocBucket.ProgramFiles };
        var s = SemanticRenderer.Render(reg, structural: false);
        Assert.Contains("application compatibility cache", s);   // expanded, not the enum spelling "Shimcache"
        Assert.Contains("program files", s);                     // expanded, not "ProgramFiles"
        Assert.DoesNotContain("reg:", s);                        // no field-name labels
        Assert.DoesNotContain("loc:", s);

        var evt = new CanonicalEvent
        { Ts = 2, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = 4688, Ext = "evtx", Macb = Macb.Modified, HourOfDay = 3 };
        var es = SemanticRenderer.Render(evt, structural: true);
        Assert.Contains("process creation", es);                 // 4688 rendered as a meaningful name
        Assert.DoesNotContain("evtx", es);                       // the container-file extension does not leak
        Assert.Contains("[m...]", es);                           // structural data is bracket-delimited
        Assert.Contains("[hour 3]", es);
    }

    // Measured one-off (filtered/high-signal, Tiled(5), MiniLM) — answers the "separate semantic from structural"
    // ideas. natural 22.1/17.3 · semantic 15.7/11.1 · semantic+struct 16.1/16.4. CONCLUSION: for an NL
    // sentence-transformer, full natural-language prose BEATS the terse semantic render. Idea 1 (expand compound
    // values, "Shimcache"→"application compatibility cache") is GOOD — and NaturalRenderer already does it. But
    // idea 2 (drop field names / go terse) and idea 3 (bracket-delimit structural like "[m...] [hour 0]") HURT the
    // NL model: it wants grammatical scaffolding and structural facts woven into prose ("was modified, at 03:00")
    // rather than bracketed non-semantic tokens. Structural data DOES carry signal (semantic+struct macroF1 16.4 ≫
    // semantic-only 11.1), so keep it — just weave it into prose, don't bracket it. SemanticRenderer retained as an
    // alternative; NaturalRenderer remains the preferred render for MiniLM/nomic. See the memory note.

    [Fact]
    public void KeepHighSignalFilterDropsFilesystemChurnAndRecomputesDeltas()
    {
        var csv = Header + "\n" +
            @"2023-12-26 00:36:37.000000+00:00,Content Modification Time,FILE,File stat,NTFS:\...\OneDrive\logs\sync.odlgz Type: file,filestat,NTFS:\...\sync.odlgz,-" + "\n" +
            @"2023-12-26 00:36:40.000000+00:00,Creation Time,EVT,WinEVTX,[4688 / 0x1250] process,winevtx,NTFS:\...\Security.evtx,-" + "\n" +
            @"2023-12-26 00:36:43.000000+00:00,Last Written Time,REG,Run,[HKLM Run] entry,winreg/windows_run,NTFS:\...\SOFTWARE,-" + "\n";

        var all = CsvTimelineLoader.LoadCanonicalFromText(csv);
        var kept = CsvTimelineLoader.LoadCanonicalFromText(csv, NoiseFilters.KeepHighSignal);

        Assert.Contains(all, e => e.Source == SourceClass.FileSystem);            // the filestat churn is present unfiltered
        Assert.DoesNotContain(kept, e => e.Source == SourceClass.FileSystem);     // and dropped when filtered
        Assert.Equal(all.Length - 1, kept.Length);
        Assert.All(kept, e => Assert.True(NoiseFilters.KeepHighSignal(e)));
        Assert.Equal(0f, kept[0].DtPrev);                                        // Δt recomputed over survivors (first = 0)
    }

    // Measured one-off via DatasetEvaluator with NoiseFilters.KeepHighSignal (drops the filestat/usnjrnl firehose,
    // ~85% of events: 1608 → 238 windows at Tiled(20)). The result is nuanced, NOT a clean win for classification:
    //   config                    hashing+token   MiniLM+natural
    //   unfiltered  Tiled(20)      23.5 / 22.2     23.4 / 22.2   (1608 win)
    //   filtered    Tiled(20)      23.9 / 17.1     23.5 / 16.0   ( 238 win)
    //   filtered    Tiled(5)       17.7 / 17.4     22.1 / 17.3   ( 923 win)
    // Filtering sharpens the discriminative actions (launch-explorer F1 37→54%) and nudges accuracy up, BUT tanks
    // macro-F1 — it exposes severe class imbalance (some actions, e.g. open-google, generate almost no high-signal
    // events → 2-6 windows → F1=0); the FILE "noise" was inadvertently BALANCING the classes. One clean signal:
    // with small/sparse filtered windows, MiniLM+natural decisively beats hashing (22.1 vs 17.7) — semantic
    // embedding earns its keep when there's little lexical signal. Filtering's real payoff is for NOVELTY/anomaly
    // (class balance irrelevant; removing ubiquitous churn makes genuine anomalies stand out), not this balanced
    // classification proxy. Slow eval not kept; see the memory note.

    // Measured one-off: spacing "field: value" in TextRenderer (so a BERT tokenizer can segment the field name
    // from its value) lifts MiniLM from 19.6% (glued "eid4624") to 21.1% acc / 20.0% F1 — a real +1.5pt gain,
    // confirming glued tokens were hurting the WordPiece tokenizer. Hashing is unchanged (23.5% — it whitespace-
    // splits regardless). Still below MiniLM+natural (23.4%) and the ~23-24% noise ceiling. Slow eval not kept.

    // Walks up from the test output dir to locate the dataset's events directory.
    private static string? FindEventsDir()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            var candidate = Path.Combine(d.FullName, "reference", "datasets", "scenario-1", "timeline", "events");
            if (Directory.Exists(candidate)) return candidate;
        }
        return null;
    }
}
