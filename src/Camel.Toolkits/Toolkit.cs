using Camel.Environments;
using Microsoft.Extensions.Configuration;

namespace Camel.Toolkit;

public record Tool
{     
    public string Name { get; init; }
    public string Command { get; init; }
    
    
    public Tool(string name, string command)
    {
        this.Name = name;
        this.Command = command;
    }   
}   

public abstract class Toolkit : Runtime
{
    #region Constructors
    public Toolkit(string name, AuditEnvironment env)
    {
        this.name = name;
        this.auditEnvironment = env;
        if (config is null)
        {
            throw new Exception("Configuration file not loaded");
        }
        toolConfig = config.GetRequiredSection($"Tools:{name}");
        foreach (string toolName in ToolList)
        {
            tools[toolName] = GetTool(toolName);
        }   
    }
    #endregion

    #region Properties
    public abstract string[] ToolList { get; }
    #endregion

    #region Methods
    

    public Tool GetTool(string name) => new Tool(name, GetRequiredValue(toolConfig, $"{name}"));        
  
    #endregion

    #region Fields
    public readonly string name;
    public readonly IConfigurationSection toolConfig;
    public readonly AuditEnvironment auditEnvironment;
    public readonly Dictionary<string, Tool> tools = new Dictionary<string, Tool>();
    #endregion
}