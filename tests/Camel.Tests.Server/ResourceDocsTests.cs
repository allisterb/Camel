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
        Assert.Contains("Core Reference", DFIRResources.SdkCore());
        Assert.Contains("Schema Reference", DFIRResources.SdkSchema());
        Assert.Contains("Discipline", DFIRResources.SdkDiscipline());
        // Blue, not red.
        Assert.DoesNotContain("ScanningToolkit", DFIRResources.SdkCore());
    }

    [Fact]
    public void PenTestResources_ServeTheRedDocs()
    {
        var core = PenTestResources.SdkCore();
        Assert.Contains("PenTest", core);
        Assert.Contains("ScanningToolkit", core);
        Assert.Contains("SetEngagement", core);            // fail-closed authorization documented
        Assert.DoesNotContain("MemoryAnalysisWorkflow", core);   // no DFIR surface leaks in

        Assert.Contains("HostScan", PenTestResources.SdkSchema());
        Assert.Contains("Engagement Discipline", PenTestResources.SdkDiscipline());
    }
}
