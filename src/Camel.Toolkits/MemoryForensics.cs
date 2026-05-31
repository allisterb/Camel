using Camel.Environments;

namespace Camel.Toolkit;

public class MemoryForensicsToolkit : Toolkit
{
    public MemoryForensicsToolkit(AuditEnvironment auditEnvironment) : base("MemoryForensics", auditEnvironment)
    {
        
    }
    
    public void Volatility3(string arguments, out string output)
    {
        Tool tool = GetTool("Volatility3");
        bool result = auditEnvironment.ExecuteCommand(tool.Command, arguments, out output);
        if (!result)
        {
            throw new Exception($"Failed to execute {tool.Name} with arguments: {arguments}");
        }
    }

    public override string[] ToolList { get; } = ["Volatility3"];

}
