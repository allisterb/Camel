namespace Camel;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks;


using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;
using ModelContextProtocol.AspNetCore;

using Jint;
using Camel.Environments;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

public enum TransportType
{
    Stdio = 0,
    Http = 1,
}

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
    const string CorsPolicyName = "CamelMcpCors";

    public static async Task RunStdioAsync(AuditEnvironment auditEnvironment)
    {        
        var builder = Host.CreateEmptyApplicationBuilder(null);
        var s = new CamelMCPTools(auditEnvironment);
        var tool = McpServerTool.Create(s.ExecuteJavaScript);

        builder
            .Logging.AddProvider(loggerProvider)
            .SetMinimumLevel(LogLevel.Trace);

        var mcpServices = builder
            .Services
            .AddMcpServer()
            .WithTools(tool)
            .WithStdioServerTransport();
        
        var app = builder.Build();
        
        await app.RunAsync();
    }

    public static async Task RunHttpAsync(AuditEnvironment auditEnvironment)
    {
        var builder = WebApplication.CreateBuilder();
        var s = new CamelMCPTools(auditEnvironment);
        var tool = McpServerTool.Create(s.ExecuteJavaScript);

        builder
            .Logging.AddProvider(loggerProvider)
            .SetMinimumLevel(LogLevel.Trace);

        // Allow browser-based MCP clients (served from a different origin) to call
        // the HTTP/SSE endpoints. AllowAnyOrigin is convenient for local/trusted use;
        // restrict it with WithOrigins(...) if Camel is exposed beyond a trusted host.
        // Mcp-Session-Id must be exposed so clients can read the session id the server
        // assigns on initialize and echo it back on subsequent requests.
        builder.Services.AddCors(options =>
        {
            options.AddPolicy(CorsPolicyName, policy =>
            {
                policy
                    .AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .WithExposedHeaders("Mcp-Session-Id");
            });
        });

        var mcpServices = builder
            .Services
            .AddMcpServer()
            .WithTools(tool)
            .WithHttpTransport(options =>
            {
                // Use stateful sessions so the Streamable HTTP transport can
                // stream responses and push server-initiated messages back to
                // the client over its SSE (GET) channel. In stateless mode each
                // request gets a fresh context, which disables both of those and
                // is incompatible with the legacy SSE transport below.
                options.Stateless = false;

                // Also map the legacy HTTP+SSE endpoints (GET /sse, POST /message)
                // for older clients that don't support Streamable HTTP yet.
                options.EnableLegacySse = true;
            });

        var app = builder.Build();

        app.UseCors(CorsPolicyName);

        // Maps the Streamable HTTP endpoints at the root path and, because
        // EnableLegacySse is set above, the legacy "/sse" and "/message" endpoints.
        app.MapMcp();

        app.Lifetime.ApplicationStarted.Register(() =>
        {
            var addresses = app.Services
                .GetRequiredService<IServer>()
                .Features
                .Get<IServerAddressesFeature>()?
                .Addresses;

            if (addresses is null || addresses.Count == 0)
            {
                Info("Camel MCP server (HTTP transport) started, but no listening address was reported.");
            }
            else
            {
                foreach (var address in addresses)
                {
                    Info("Camel MCP server listening on {Address} (Streamable HTTP at '/', legacy SSE at '/sse' and '/message').", address);
                }
            }
        });

        await app.RunAsync();
    }
}
