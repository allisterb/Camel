namespace Camel.Toolkits;

using Camel.Environments;
using Camel.Toolkits.Models;
using Microsoft.Extensions.Configuration;

public class MemoryForensicsToolkit : Toolkit
{
    public MemoryForensicsToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("MemoryForensics", auditEnvironment, config) {}
        
    public WindowsPsList[]? WindowsPsList(string filename) => ExecuteTool<WindowsPsList[]>("Volatility3", $"-f {filename} -r json windows.pslist");
    
    public override string[] ToolList { get; } = ["Volatility3"];
}
