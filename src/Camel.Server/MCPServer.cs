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

public enum TransportType
{
    Stdio = 0,
    Http = 1,
}

public class CamelMCPTools : Runtime
{
   public CamelMCPTools(SessionRegistry registry)
   {
        this.registry = registry;
        jsoptions = new Options();
        jsoptions.Host.StringCompilationAllowed = false;        
        // Lets generated JS `await` async toolkit methods (CLR Task<T> -> awaitable JS promise). Required so
        // tool calls run on the async path, where per-session cancellation (CancelExecutions) takes effect.
        jsoptions.ExperimentalFeatures = ExperimentalFeature.TaskInterop;                
    }

    [McpServerTool(Name = "ExecuteJavaScript"), Description(
        "Execute JavaScript code against the Camel DFIR API (toolkits + workflows + anomaly engine). " +
        "Before writing any script you MUST read the 'camel-sdk-core' resource (camel://sdk/core) for the " +
        "execution model and the full list of objects and methods, and the 'camel-sdk-schema' resource " +
        "(camel://sdk/schema) for the JSON schema of every value those methods return — without the schemas you " +
        "cannot read results correctly. Call ONLY methods listed in camel-sdk-core, and access ONLY object " +
        "properties listed in camel-sdk-schema; do not invent methods or properties that are not documented there.")]
    public async Task<CallToolResult> ExecuteJavaScript(string script, RequestContext<CallToolRequestParams> context)
    {
        // Each MCP session gets its own environment/API (its own SSH connection); resolve it by session id.
        // The RequestContext is injected by the SDK per request; context.Server carries the session id.
        var sessioid = SessionId(context.Server);
        var session = registry.GetOrCreate(sessioid);
        StringBuilder output = new StringBuilder();
        var jsinterp = new Engine(jsoptions)

          .SetValue("log", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("error", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("table", new Action<string[], object[][]>((headers, dataRows) =>
          {
              output.AppendLine(headers.ToString());

          }))
          // Pure-compute anomaly triage over a canonical timeline (no AuditEnvironment); see Camel.Inference.
          // Typical flow: const ev = await timeline.PsortAsync(plaso); log(anomaly.Summarize(anomaly.TriageTimeline(ev, 200)));
          .SetValue("AnomalyDetectionToolkit", new Camel.Inference.AnomalyDetectionToolkit())

          // Workflows are cheap to construct (they just hold a reference to the toolkits api and resolve toolkits
          // lazily on use), so bind them all unconditionally.
          .SetValue("MemoryAnalysisWorkflow", session.WorkflowsApi.MemoryAnalysis)
          .SetValue("DiskAnalysisWorkflow", session.WorkflowsApi.DiskAnalysis)
          .SetValue("WindowsAnalysisWorkflow", session.WorkflowsApi.WindowsAnalysis)
          .SetValue("TimelineAnalysisWorkflow", session.WorkflowsApi.TimelineAnalysis)
          .SetValue("AntiForensicsAnalysisWorkflow", session.WorkflowsApi.AntiForensicsAnalysis)
          .SetValue("WebServerWorkflow", session.WorkflowsApi.WebServer);

        // Bind a SIFT toolkit global only when the script actually references it by name. Constructing a toolkit
        // can run one-time provisioning (Toolkit.InstallMissingTools = synchronous wget/apt for the EZ tools,
        // YARA rules pack, hayabusa, …). Binding every toolkit on every call would make the first call in a fresh
        // session block on installing tools the script never uses — e.g. a mount-only script (DiskAnalysis only)
        // would otherwise stall on the YARA/hayabusa downloads and exceed the client's tool timeout. Workflows
        // resolve their toolkits lazily through the api, so a workflow that needs a toolkit still provisions it.
        void BindToolkitIfUsed(string name, Func<object> resolve)
        {
            if (script.Contains(name, StringComparison.Ordinal)) jsinterp.SetValue(name, resolve());
        }
        BindToolkitIfUsed("MemoryAnalysisToolkit", () => session.ToolkitsApi.MemoryAnalysis);
        BindToolkitIfUsed("DiskAnalysisToolkit", () => session.ToolkitsApi.DiskAnalysis);
        BindToolkitIfUsed("WindowsAnalysisToolkit", () => session.ToolkitsApi.WindowsAnalysis);
        BindToolkitIfUsed("TimelineAnalysisToolkit", () => session.ToolkitsApi.Timeline);
        BindToolkitIfUsed("YaraToolkit", () => session.ToolkitsApi.Yara);

        try
        {
            // Wrap in an async IIFE so scripts can `await` async toolkit methods: top-level await isn't allowed
            // in a plain Jint script, and modules can't drive a CLR-task top-level await synchronously. The
            // surrounding newlines guard against a trailing line comment swallowing the closer. ExecuteAsync
            // drains the awaited CLR tasks before returning; purely synchronous scripts run unchanged.
            await jsinterp.ExecuteAsync($"(async () => {{\n{script}\n}})();");
        }
        catch (Exception ex)
        {
            // Errors surface as JavaScriptException (synchronous throw) or, via the async IIFE, as
            // PromiseRejectedException; both carry the script-level error text in their message.
            var jsex = ex as Jint.Runtime.JavaScriptException
                       ?? ex.InnerException as Jint.Runtime.JavaScriptException;
            var message = jsex is not null
                ? $"JavaScript error: {jsex.Message}"
                : ex is Jint.Runtime.PromiseRejectedException
                    ? $"JavaScript error: {ex.Message}"
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

/// <summary>
/// MCP resources exposing the Camel JavaScript SDK reference to the agent. The two markdown docs are embedded in
/// this assembly (see Camel.Server.csproj) and served verbatim, so an agent can read the SDK surface before
/// generating code for the <c>ExecuteJavaScript</c> tool without the docs having to exist on disk at runtime.
/// </summary>
public class CamelResources
{
    [McpServerResource(UriTemplate = "camel://sdk/core", Name = "camel-sdk-core",
        Title = "Camel JS SDK reference — core", MimeType = "text/markdown")]
    [Description("Core reference for the Camel JavaScript SDK used by the ExecuteJavaScript tool: the execution " +
        "model (await semantics, return-value shapes, PascalCase naming, positional optional params) and the full " +
        "method signature index — every toolkit and workflow object, each method's parameters and return type. " +
        "Read this FIRST and keep it in context when generating JS. The method return types reference model types " +
        "whose JSON schemas live in the companion 'camel-sdk-schema' resource (camel://sdk/schema).")]
    public static string SdkCore() => ReadEmbedded("Camel.core.md");

    [McpServerResource(UriTemplate = "camel://sdk/schema", Name = "camel-sdk-schema",
        Title = "Camel JS SDK reference — schemas", MimeType = "text/markdown")]
    [Description("JSON schemas for every parameter and return model type in the Camel JavaScript SDK — the " +
        "companion to 'camel-sdk-core'. Consult this when you need the exact fields of an object a toolkit or " +
        "workflow method returns (e.g. TimelineEvent, FindMalwareReport, TriageReport). Schemas are grouped by " +
        "the object that returns them.")]
    public static string SdkSchema() => ReadEmbedded("Camel.schema.md");

    static string ReadEmbedded(string name)
    {
        using var stream = typeof(CamelResources).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded SDK doc '{name}' was not found in the assembly.");
        using var reader = new System.IO.StreamReader(stream);
        return reader.ReadToEnd();
    }
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
            .WithResources<CamelResources>()
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
            .WithResources<CamelResources>()
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
