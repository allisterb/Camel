namespace Camel;

using System;
using System.Linq;

using Camel.Environments;
using Camel.Toolkits;
using Microsoft.Extensions.Configuration;

public class CamelApi : Runtime
{
    #region Constructors
    public CamelApi(AuditEnvironment env, IConfigurationRoot? config = null)
    {
        this.MemoryAnalysis = new MemoryAnalysisToolkit(env, config);
    }
    #endregion

    #region Properties
    public MemoryAnalysisToolkit MemoryAnalysis { get; }
    #endregion
}
