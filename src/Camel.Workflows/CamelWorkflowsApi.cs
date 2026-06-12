namespace Camel;

using Camel.Workflows;

public class CamelWorkflowsApi : Runtime
{
    public CamelWorkflowsApi(CamelToolkitsApi toolkitsApi)
    {
        DiskAnalysis = new DiskAnalysisWorkflow(toolkitsApi);
        MemoryAnalysis = new MemoryAnalysisWorkflow(toolkitsApi);
        WindowsAnalysis = new WindowsAnalysisWorkflow(toolkitsApi);
        TimelineAnalysis = new TimelineAnalysisWorkflow(toolkitsApi);
        AntiForensicsAnalysis = new AntiForensicsAnalysisWorkflow(toolkitsApi);
        WebServer = new WebServerWorkflow(toolkitsApi);
    }

    #region Properties
    public readonly DiskAnalysisWorkflow DiskAnalysis;
    public readonly MemoryAnalysisWorkflow MemoryAnalysis;
    public readonly WindowsAnalysisWorkflow WindowsAnalysis;
    public readonly TimelineAnalysisWorkflow TimelineAnalysis;
    public readonly AntiForensicsAnalysisWorkflow AntiForensicsAnalysis;
    public readonly WebServerWorkflow WebServer;
    #endregion
}
