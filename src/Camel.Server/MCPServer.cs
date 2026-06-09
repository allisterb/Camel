namespace Camel;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

using ModelContextProtocol.Server;
using ModelContextProtocol.Protocol;
using Jint;
using Camel.Environments;

public enum TransportType
{
    Stdio = 0,
    Http = 1,
}

public class CamelMCPTools
{
   public CamelMCPTools(SessionRegistry registry)
   {
        this.registry = registry;
        jsoptions = new Options();
        jsoptions.Host.StringCompilationAllowed = false;
    }

    [McpServerTool(Name = "ExecuteJavaScript"), Description("Execute JavaScript code against the Camel API.")]
    public async Task<CallToolResult> ExecuteJavaScript(string script, RequestContext<CallToolRequestParams> context)
    {
        // Each MCP session gets its own environment/API (its own SSH connection); resolve it by session id.
        // The RequestContext is injected by the SDK per request; context.Server carries the session id.
        var session = registry.GetOrCreate(SessionId(context.Server));
        StringBuilder output = new StringBuilder();
        var jsinterp = new Engine(jsoptions)
          .SetValue("log", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("error", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("table", new Action<string[], object[][]>((headers, dataRows) =>
          {
              output.AppendLine(headers.ToString());

          }))
          .SetValue("memoryAnalysis", session.Api.MemoryAnalysis);
        try
        {
            await jsinterp.ExecuteAsync(script);
        }
        catch (Exception ex)
        {
            // Jint surfaces script errors as JavaScriptException, sometimes wrapped
            // (e.g. when thrown from an async/awaited call). Prefer that message.
            var jsex = ex as Jint.Runtime.JavaScriptException
                       ?? ex.InnerException as Jint.Runtime.JavaScriptException;
            var message = jsex is not null
                ? $"JavaScript error: {jsex.Message}"
                : $"Error executing script: {ex.Message}";

            // Include anything written via log()/error() before the failure for context.
            if (output.Length > 0)
            {
                message = output.ToString() + Environment.NewLine + message;
            }

            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = message }],
            };
        }

        return new CallToolResult
        {
            Content = [new TextContentBlock { Text = output.ToString() }],
        };
    }

    // Stdio (and any transport that doesn't assign one) yields a null/empty session id; bucket those under "default".
    static string SessionId(McpServer server) => string.IsNullOrEmpty(server.SessionId) ? "default" : server.SessionId;

    readonly SessionRegistry registry;
    readonly Options jsoptions;
}

public class CamelMCPServer : Runtime
{
    const string CorsPolicyName = "CamelMcpCors";
   
    public static async Task RunStdioAsync(IConfigurationRoot config)
    {
        var builder = Host.CreateEmptyApplicationBuilder(null);
        // One environment per MCP session, created lazily and swept when idle.
        var registry = new SessionRegistry(config);
        builder.Services.AddSingleton(registry);
        builder.Services.AddHostedService<IdleSessionSweeper>();
        builder
            .Logging.AddProvider(loggerProvider)
            .SetMinimumLevel(LogLevel.Trace);

        var mcpServices = builder
            .Services
            .AddMcpServer()
            .WithTools(new CamelMCPTools(registry))
            .WithStdioServerTransport();

        var app = builder.Build();
        app.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping.Register(registry.Dispose);

        await app.RunAsync();
    }

    public static async Task RunHttpAsync(IConfigurationRoot config) => await BuildHttpApp(config).RunAsync();

    /// <summary>
    /// Builds the fully-configured HTTP MCP <see cref="WebApplication"/> (DI, CORS, transport, endpoints,
    /// lifecycle) without starting it. <see cref="RunHttpAsync"/> just runs the result; integration tests
    /// host it themselves (e.g. on an ephemeral port) and connect a real MCP client.
    /// </summary>
    public static WebApplication BuildHttpApp(IConfigurationRoot config)
    {
        var builder = WebApplication.CreateBuilder();
        // One environment per MCP session, created lazily and swept when idle.
        var registry = new SessionRegistry(config);
        builder.Services.AddSingleton(registry);
        builder.Services.AddHostedService<IdleSessionSweeper>();
        builder
            .Logging.ClearProviders()
            .AddProvider(loggerProvider)
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
            .WithTools(new CamelMCPTools(registry))
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

        // Tear down all session environments (cancel in-flight commands, disconnect SSH) on shutdown.
        app.Lifetime.ApplicationStopping.Register(registry.Dispose);

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

        return app;
    }
}
