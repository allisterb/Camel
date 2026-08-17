namespace Camel.Tests.Server;

/// <summary>
/// The guardrail for the SDK reference's subject-area map (see docs/SearchToolDesign.md, Layer 1): every JS global
/// the Execute engine binds must resolve to a documented area in BOTH the core and the schema doc, and every area
/// must correspond to a bound global. This turns heading drift into a build failure instead of a silent wrong
/// answer — an E2E agent once concluded a model "isn't in the schema doc" because the browser types sat under a
/// heading named for a different toolkit. Pure string work over the embedded docs: no server, no config.
/// </summary>
public class SdkDocAreaTests
{
    public static TheoryData<string, string> DfirSlices() => Slices(SdkDocs.DfirAreas);
    public static TheoryData<string, string> PenTestSlices() => Slices(SdkDocs.PenTestAreas);

    private static TheoryData<string, string> Slices(SdkArea[] areas)
    {
        var data = new TheoryData<string, string>();
        foreach (var area in areas) { data.Add(area.Name, "core"); data.Add(area.Name, "schema"); }
        return data;
    }

    [Theory, MemberData(nameof(DfirSlices))]
    public void EveryDfirArea_ResolvesInBothDocs(string area, string kind) =>
        AssertSliceIsUseful(area, kind, Doc(CamelResources.Dfir, kind));

    [Theory, MemberData(nameof(PenTestSlices))]
    public void EveryPenTestArea_ResolvesInBothDocs(string area, string kind) =>
        AssertSliceIsUseful(area, kind, Doc(CamelResources.PenTest, kind));

    private static string Doc(SdkDocSet set, string kind) => kind == "core" ? set.Core() : set.Schema();

    private static void AssertSliceIsUseful(string area, string kind, string doc)
    {
        var slice = SdkDocs.Slice(doc, area);
        Assert.False(slice is null, $"No '{area}' section in the {kind} doc — add the heading or fix its drift.");
        // A heading with nothing under it is drift too (the area moved and left a stub behind).
        Assert.True(slice!.Length > 200, $"The '{area}' section of the {kind} doc is only {slice.Length} chars.");
    }

    [Fact]
    public void DfirAreas_CoverExactlyTheBoundGlobals() =>
        AssertAreasMatchGlobals(SdkDocs.DfirAreas, DFIRMCPTools.DomainGlobalNames);

    [Fact]
    public void PenTestAreas_CoverExactlyTheBoundGlobals() =>
        AssertAreasMatchGlobals(SdkDocs.PenTestAreas, PenTestMCPTools.DomainGlobalNames);

    private static void AssertAreasMatchGlobals(SdkArea[] areas, IEnumerable<string> globals)
    {
        var documented = areas.SelectMany(a => a.Globals).ToHashSet(StringComparer.Ordinal);
        var bound = globals.ToHashSet(StringComparer.Ordinal);
        Assert.Empty(bound.Except(documented));       // a bound global with no area — the agent cannot find its docs
        Assert.Empty(documented.Except(bound));       // an area for a global that is no longer bound
    }

    public static TheoryData<string, string> DocSets() => new() { { "DFIR", "core" }, { "DFIR", "schema" }, { "PenTest", "core" }, { "PenTest", "schema" } };

    /// <summary>
    /// Selective reading is only safe if the slices reach EVERYTHING: an agent that reads the map plus a few areas
    /// must not be able to miss a method or a model that the whole document documents. So every method bullet and
    /// every model schema in each document must fall inside an area, an extra section, or the index preamble.
    /// </summary>
    [Theory, MemberData(nameof(DocSets))]
    public void EveryDocumentedMethodAndModel_IsReachableThroughTheMap(string label, string kind)
    {
        var set = label == "DFIR" ? CamelResources.Dfir : CamelResources.PenTest;
        var doc = Doc(set, kind);
        var preamble = kind == "core" ? set.CorePreamble : set.SchemaPreamble;
        var covered = string.Join("\n", set.Addressable.Select(a => a.HeadingText).Concat(preamble)
            .Select(heading => SdkDocs.Slice(doc, heading))
            .Where(slice => slice is not null));

        var orphans = doc.Split('\n').Select(l => l.TrimEnd('\r'))
            .Where(l => (l.StartsWith("- `") && l.Contains('(')) || IsSchemaHeading(l))
            .Where(l => !covered.Contains(l, StringComparison.Ordinal))
            .ToArray();
        Assert.Empty(orphans);   // an orphan is documented but unreachable from the map — file it under an area
    }

    // "### CorsResult Schema" / "### ProcessNode Schema (input to …)" — but not the doc title "… Schema Reference".
    private static bool IsSchemaHeading(string line) =>
        line.StartsWith('#') && (line.EndsWith(" Schema", StringComparison.Ordinal) || line.Contains(" Schema (", StringComparison.Ordinal));

    /// <summary>
    /// The inventory asserts completeness, so every documented signature must reach it. Agent finding B-4:
    /// `CookiesForAsync` was documented as the SECOND signature on a shared bullet line and silently missing from
    /// the map, which (in the agent's words) made it distrust the whole inventory.
    /// </summary>
    [Theory]
    [InlineData("DFIR")]
    [InlineData("PenTest")]
    public void EverySignatureBullet_ReachesTheInventory(string label)
    {
        var set = label == "DFIR" ? CamelResources.Dfir : CamelResources.PenTest;
        var index = SdkDocs.BuildIndex(set);

        var missing = new List<string>();
        foreach (var line in set.Core().Split('\n').Select(l => l.Trim()))
        {
            if (!line.StartsWith("- `")) continue;
            foreach (var name in SdkDocs.MethodNames(line).Select(n => n.Split('.')[^1]))
                if (!index.Contains(name, StringComparison.Ordinal)) missing.Add(name);
            // A bullet that opens with a call must yield at least one name, or the extraction rule has a hole.
            if (SignatureBullet.IsMatch(line))
                Assert.NotEmpty(SdkDocs.MethodNames(line));
        }
        Assert.Empty(missing);
    }

    private static readonly System.Text.RegularExpressions.Regex SignatureBullet =
        new(@"^- `(?:[A-Za-z_]\w*\.)?[A-Za-z_]\w*\([^`]*\)`");

    [Fact]
    public void TheMap_StaysAMap()
    {
        // The whole point is the startup cost: the two documents are ~162 KB (DFIR) / ~226 KB (PenTest) together.
        foreach (var index in new[] { DFIRResources.SdkIndex(), PenTestResources.SdkIndex() })
        {
            Assert.True(index.Length < 32_000, $"The map has grown to {index.Length} chars — re-check what belongs in it.");
            Assert.Contains("camel://sdk/core/", index);       // the areas are addressable from it
            Assert.Contains("Execution model", index);         // the mandatory protocol travels with it
        }
        Assert.Contains("Authorization", PenTestResources.SdkIndex());   // red: fail-closed protocol, before any call
        Assert.Contains("Audit trail", DFIRResources.SdkIndex());        // blue: case attribution
    }

    [Fact]
    public void Headings_IgnoreFencedCodeBlocks()
    {
        // '#' inside an example (a shell comment, a CSS id) must not be read as a heading, or a slice ends early.
        var doc = "# Title\n\n## ScanningToolkit\n\n```bash\n# not a heading\n```\n\nbody\n\n## Next\n";
        Assert.Equal(3, SdkDocs.Headings(doc).Count);
        Assert.Contains("body", SdkDocs.Slice(doc, "ScanningToolkit"));
        Assert.DoesNotContain("## Next", SdkDocs.Slice(doc, "ScanningToolkit"));
    }

    [Fact]
    public void Slice_ConcatenatesDuplicateHeadings_AndMatchesMergedNames()
    {
        // Both real shapes in Camel.schema.md: the same area documented twice, and two areas sharing one heading.
        var core = CamelResources.Dfir.Schema();
        var memory = SdkDocs.Slice(core, "MemoryAnalysisToolkit")!;
        Assert.Contains("WindowsPsList", memory);                 // the first (Windows) section
        Assert.Contains("LinuxPsList", memory);                   // the duplicate "(Linux plugins)" section
        Assert.Contains("CarvedFile", SdkDocs.Slice(core, "DiskAnalysisWorkflow")!);   // the slash-merged heading
        Assert.Contains("CarvedFile", SdkDocs.Slice(core, "DiskAnalysisToolkit")!);
    }
}
