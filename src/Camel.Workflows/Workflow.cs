using Camel.Toolkits;

namespace Camel.Workflows;

public class WorkflowResult<T>
{
    public bool IsSuccess { get; }
    public T? Result { get; }
    public string? Message { get; }

    private WorkflowResult(bool isSuccess, T? result, string? message)
    {
        this.IsSuccess = isSuccess;
        this.Result = result;
        this.Message = message;
    }

    /// <summary>A successful result carrying <paramref name="result"/> and an optional summary message.</summary>
    public static WorkflowResult<T> Success(T result, string? message = null) => new(true, result, message);

    /// <summary>A failed result carrying an explanatory <paramref name="message"/> and no value.</summary>
    public static WorkflowResult<T> Failure(string message) => new(false, default, message);
}

public class Workflow : Runtime
{
    public Workflow(CamelToolkitsApi api)    
    {
        this.api = api;
    }
    protected readonly CamelToolkitsApi api;

    protected DiskAnalysisToolkit DiskAnalysis => api.DiskAnalysis;

    protected MemoryAnalysisToolkit MemoryAnalysis => api.MemoryAnalysis;

    protected WindowsAnalysisToolkit WindowsAnalysis => api.WindowsAnalysis;

    protected YaraToolkit Yara => api.Yara;

    protected TimelineToolkit Timeline => api.Timeline;

    protected LinuxAnalysisToolkit LinuxAnalysis => api.LinuxAnalysis;

    protected PacketAnalysisToolkit PacketAnalysis => api.PacketAnalysis;

    /// <summary>
    /// Opens an audit scope attributing every tool execution under it to this workflow and the calling method,
    /// so the per-case audit trail records the full hierarchy (Workflow → WorkflowOperation → Toolkit → Operation
    /// → command). Call once at the top of a public workflow method: <c>using var _ = AuditScope();</c>. The
    /// operation name is captured automatically from the caller.
    /// </summary>
    protected IDisposable AuditScope([System.Runtime.CompilerServices.CallerMemberName] string operation = "") =>
        new AuditScopeHandle(
            PushAuditProperty("Workflow", GetType().Name),
            PushAuditProperty("WorkflowOperation", operation));

    /// <summary>Disposes a pair of log-context property scopes together (innermost first).</summary>
    private sealed class AuditScopeHandle(IDisposable workflow, IDisposable operation) : IDisposable
    {
        public void Dispose() { operation.Dispose(); workflow.Dispose(); }
    }
}
