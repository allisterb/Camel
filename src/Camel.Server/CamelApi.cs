namespace Camel;

using System;
using System.Linq;

using Camel.Environments;
using Camel.Toolkits;

public class CamelApi
{
    #region Constructors
    public CamelApi(AuditEnvironment env)
    {
        this.MemoryAnalysis = new MemoryAnalysisToolkit(env);
    }
    #endregion

    #region Properties
    public MemoryAnalysisToolkit MemoryAnalysis { get; }
    #endregion
}
