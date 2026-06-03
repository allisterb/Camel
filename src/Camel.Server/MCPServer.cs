namespace Camel;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks;


using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;

using Jint;
using Camel.Environments;
using Microsoft.Extensions.Logging;

public class CamelMCPTools 
{   
    
   public CamelMCPTools(AuditEnvironment auditEnvironment)
   {
        this.auditEnvironment = auditEnvironment;        
        jsoptions = new Options();
        jsoptions.Host.StringCompilationAllowed = false;      
        api = new CamelApi(auditEnvironment);   
    }

    [McpServerTool, Description("Execute JavaScript code against the Camel API.")]
    public async Task<string> ExecuteJavaScript(string script)
    {
        StringBuilder output = new StringBuilder();
        var jsinterp = new Engine(jsoptions)            
          .SetValue("log", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("error", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("table", new Action<string[], object[][]>((headers, dataRows) =>
          {
              output.AppendLine(headers.ToString());

          }))
          .SetValue("api", api);
        await jsinterp.ExecuteAsync(script);
        return output.ToString();
    }
    
    readonly AuditEnvironment auditEnvironment;
    readonly Options jsoptions;
    readonly CamelApi api;
}

public class CamelMCPServer : Runtime
{
    public static async Task Run(AuditEnvironment auditEnvironment)
    {        
        var builder = Host.CreateEmptyApplicationBuilder(null);
        var s = new CamelMCPTools(auditEnvironment);
        var tool = McpServerTool.Create(s.ExecuteJavaScript);

        builder
            .Logging.AddProvider(loggerProvider)
            .SetMinimumLevel(LogLevel.Trace);

        builder
            .Services
            .AddMcpServer()            
            .WithStdioServerTransport()
            .WithTools(tool);

        var app = builder.Build();

        await app.RunAsync();
    }
}
