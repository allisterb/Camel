using Camel.Environments;
using Microsoft.Extensions.Configuration;

namespace Camel.Toolkits;

public record Tool
{     
    public string Name { get; init; }
    public string Descriptioon { get; init; }
    public string Command { get; init; }
    
    
    public Tool(string name, string description, string command)
    {
        this.Name = name;
        this.Descriptioon = description;
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
            Tools[toolName] = GetTool(toolName);
        }   
    }
    #endregion

    #region Properties
    public abstract string[] ToolList { get; }
    public Dictionary<string, Tool> Tools { get; } = new Dictionary<string, Tool>();
    #endregion

    #region Methods


    public Tool GetTool(string name) => new Tool(name, GetRequiredValue(toolConfig, $"{name}:Description"), GetRequiredValue(toolConfig, $"{name}:Command"));

    public T? ExecuteTool<T>(string name, string args) where T : class     
    {
        if (auditEnvironment.ExecuteCommand(Tools[name].Command, args, out string output))
        {
            return System.Text.Json.JsonSerializer.Deserialize<T>(output);
        }
        else
        {
            Error($"Failed to execute Volatility3 with arguments: {args}");
            return null;
        }
    }

    #endregion

    #region Fields
    public readonly string name;
    public readonly IConfigurationSection toolConfig;
    public readonly AuditEnvironment auditEnvironment;   
    #endregion
}