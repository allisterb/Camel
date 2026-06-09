namespace Camel;

using System;
using System.Linq;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits;

public class CamelApi : Runtime
{
    #region Constructors
    public CamelApi(AuditEnvironment env, IConfigurationRoot? config = null)
    {
        this.MemoryAnalysis = new MemoryAnalysisToolkit(env, config);
        this.DiskAnalysis = new DiskAnalysisToolkit(env, config);   
    }
    #endregion

    #region Properties
    public MemoryAnalysisToolkit MemoryAnalysis { get; }
    public DiskAnalysisToolkit DiskAnalysis { get; }
    #endregion
}
