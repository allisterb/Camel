namespace Camel.Toolkits;

using Camel.Environments;
using Camel.Toolkits.Models;

public class MemoryForensicsToolkit : Toolkit
{
    public MemoryForensicsToolkit(AuditEnvironment auditEnvironment) : base("MemoryForensics", auditEnvironment) {}
        
    public WindowsPsList[]? WindowsPsList(string filename) => ExecuteTool<WindowsPsList[]>("Volatility3", $"-f {filename} -r json windows.pstree");
    
    public override string[] ToolList { get; } = ["Volatility3"];
}
