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
        this.MemoryForensics = new MemoryForensicsToolkit(env);
    }
    #endregion

    #region Methods



    #endregion

    #region Fields
    public MemoryForensicsToolkit MemoryForensics { get; }
    #endregion
}
