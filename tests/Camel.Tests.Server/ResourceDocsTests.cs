namespace Camel.Tests.Server;

/// <summary>
/// Verifies the investigation-aware SDK reference resources: each resource class resolves its embedded markdown
/// docs (a wrong LogicalName/embed would throw) and serves the BLUE vs RED reference. These call the static
/// resource methods directly, so they need no running server or config — they pin the doc wiring the
/// CamelMCPServer registers per investigation (DFIRResources / PenTestResources under the same camel://sdk/* URIs).
/// </summary>
public class ResourceDocsTests
{
    [Fact]
    public void DfirResources_ServeTheBlueDocs()
    {
        Assert.Contains("Core Reference", DFIRResources.SdkCoreAll());
        Assert.Contains("Schema Reference", DFIRResources.SdkSchemaAll());
        Assert.Contains("Discipline", DFIRResources.SdkDiscipline());
        // Blue, not red.
        Assert.DoesNotContain("ScanningToolkit", DFIRResources.SdkCoreAll());
        Assert.DoesNotContain("ScanningToolkit", DFIRResources.SdkIndex());
    }

    [Fact]
    public void PenTestResources_ServeTheRedDocs()
    {
        var core = PenTestResources.SdkCoreAll();
        Assert.Contains("PenTest", core);
        Assert.Contains("ScanningToolkit", core);
        Assert.Contains("SetEngagement", core);            // fail-closed authorization documented
        Assert.DoesNotContain("MemoryAnalysisWorkflow", core);   // no DFIR surface leaks in

        Assert.Contains("HostScan", PenTestResources.SdkSchemaAll());
        Assert.Contains("Engagement Discipline", PenTestResources.SdkDiscipline());
    }

    /// <summary>
    /// The map (not the whole document) is what the legacy "read this first" URIs now serve, and the whole-document
    /// URIs stay available — the two halves of the Layer-1 split that fix the startup cost without stranding an
    /// agent that wants everything.
    /// </summary>
    [Fact]
    public void TheFirstReadIsTheMap_AndTheWholeDocumentsRemain()
    {
        foreach (var (index, core, schema, signpost) in new[]
        {
            (DFIRResources.SdkIndex(), DFIRResources.SdkCoreAll(), DFIRResources.SdkSchemaAll(), DFIRResources.SdkSchema()),
            (PenTestResources.SdkIndex(), PenTestResources.SdkCoreAll(), PenTestResources.SdkSchemaAll(), PenTestResources.SdkSchema()),
        })
        {
            Assert.True(index.Length * 4 < core.Length + schema.Length, "The map must be far smaller than the documents it maps.");
            Assert.Contains("reference map", index);
            Assert.Contains("camel://sdk/schema/", signpost);   // the legacy schema URI signposts, it does not dump
            Assert.True(signpost.Length < 2_000);
        }
        Assert.Equal(DFIRResources.SdkIndex(), DFIRResources.SdkCore());        // camel://sdk/core serves the map
        Assert.Equal(PenTestResources.SdkIndex(), PenTestResources.SdkCore());
    }
}
