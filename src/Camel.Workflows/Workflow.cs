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
    public Workflow(CamelApi api)    
    {
        this.api = api;
    }
    protected readonly CamelApi api;

    protected DiskAnalysisToolkit DiskAnalysis => api.DiskAnalysis;

    protected MemoryAnalysisToolkit MemoryAnalysis => api.MemoryAnalysis;

    protected WindowsAnalysisToolkit WindowsAnalysis => api.WindowsAnalysis;

    protected YaraToolkit Yara => api.Yara;

    protected TimelineToolkit Timeline => api.Timeline;
}
