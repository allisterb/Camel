namespace Camel;

using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

using ModelContextProtocol.Server;

/// <summary>Which investigation a server launch composes: the blue (DFIR) or red (PenTest) tool surface.
/// Selected by the launching CLI verb (dfir-server / pentest-server), not per session.</summary>
public enum InvestigationType
{
    DFIR = 0,
    PenTest = 1,
}

public class CamelMCPServer : Runtime
{
    const string CorsPolicyName = "CamelMcpCors";

    // Registers the investigation's MCP tool surface and enforces its platform capability before serving.
    // WithTools<T> discovers [McpServerTool] methods from typeof(T), so the *concrete* type must be passed
    // (an abstract CamelMCPTools-typed argument would miss the subclass tools, e.g. SetEvidence/SetEngagement).
    // The generic param keeps the static type concrete through this helper.
    static void RegisterAndEnforce<T>(IMcpServerBuilder mcp, T tools, IConfigurationRoot config)
        where T : CamelMCPTools
    {
        EnforceCapabilities(tools, config);   // refuse a zero-tool platform/investigation combo before serving
        mcp.WithTools(tools);
    }

    // Registers the investigation's SDK reference resources (blue DFIRResources / red PenTestResources) under the
    // shared camel://sdk/* URIs, so the agent reads the reference for the toolkits THIS server actually binds.
    static void RegisterResources(IMcpServerBuilder mcp, InvestigationType investigation)
    {
        if (investigation == InvestigationType.PenTest)
        {
            mcp.WithResources<PenTestResources>();
        }
        else
        {
            mcp.WithResources<DFIRResources>();
        }
    }

    /// <summary>
    /// Runs the launch-time platform capability check for the selected investigation and logs the per-toolkit
    /// summary. Refuses to start (throws) when no toolkit has any tool on the active platform — e.g. a PenTest
    /// server pointed at a SIFT profile — with a directive message; warns and continues on a partial (degraded)
    /// combo so legitimate cases (DFIR on Kali) still run. See docs/PenTestEnvironments.md part 1.
    /// </summary>
    static void EnforceCapabilities(CamelMCPTools tools, IConfigurationRoot config)
    {
        var report = tools.CheckCapabilities(config);
        Info("Platform '{Platform}' capability check for {Investigation}:{NewLine}{Summary}",
            report.Platform, tools.InvestigationName, Environment.NewLine, report.Summary());
        if (!report.AnyAvailable)
            throw new InvalidOperationException(report.RefusalMessage(tools.InvestigationName));
        foreach (var u in report.Unavailable)
            Warn("Toolkit '{Toolkit}' has no tools on platform '{Platform}' and will be inert.", u.Toolkit, report.Platform);

        // Knowledge bases (intelligence sources) are config-driven, not platform tools — report their availability
        // separately for the servers that bind them, so an operator sees which sources are live (and which are dark
        // for want of an API key) at launch.
        if (tools.BindsKnowledgeBases)
        {
            var sources = new Camel.Intel.KnowledgeBaseClient(config).DescribeSources().ToList();
            if (sources.Count > 0)
            {
                var summary = string.Join(Environment.NewLine,
                    sources.Select(s => $"  {s.Name} [{s.Transport}]: {(s.Available ? "available" : "UNAVAILABLE")} ({s.Detail})"));
                Info("Knowledge bases for {Investigation}:{NewLine}{Summary}",
                    tools.InvestigationName, Environment.NewLine, summary);
            }
        }
    }

    public static async Task RunStdioAsync(IConfigurationRoot config, InvestigationType investigation = InvestigationType.DFIR)
    {
        var builder = Host.CreateEmptyApplicationBuilder(null);
        // One environment per MCP session, created lazily and swept when idle.
        var registry = new SessionRegistry(config);
        builder.Services.AddSingleton(registry);
        builder.Services.AddHostedService<IdleSessionSweeper>();
        builder
            .Logging.AddProvider(loggerProvider)
            .SetMinimumLevel(LogLevel.Trace);

        var mcp = builder.Services.AddMcpServer();
        if (investigation == InvestigationType.PenTest)
            RegisterAndEnforce(mcp, new PenTestMCPTools(registry), config);
        else
            RegisterAndEnforce(mcp, new DFIRMCPTools(registry), config);
        RegisterResources(mcp, investigation);
        mcp.WithStdioServerTransport();

        var app = builder.Build();
        app.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping.Register(() =>
        {
            registry.Dispose();
            CloseAndFlushAuditLog();   // flush buffered audit events to the per-case files on a clean shutdown
        });

        await app.RunAsync();
    }

    public static async Task RunHttpAsync(IConfigurationRoot config, InvestigationType investigation = InvestigationType.DFIR)
        => await BuildHttpApp(config, investigation).RunAsync();

    /// <summary>
    /// Builds the fully-configured HTTP MCP <see cref="WebApplication"/> (DI, CORS, transport, endpoints,
    /// lifecycle) without starting it. <see cref="RunHttpAsync"/> just runs the result; integration tests
    /// host it themselves (e.g. on an ephemeral port) and connect a real MCP client.
    /// </summary>
    public static WebApplication BuildHttpApp(IConfigurationRoot config, InvestigationType investigation = InvestigationType.DFIR)
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

        var mcp = builder.Services.AddMcpServer();
        if (investigation == InvestigationType.PenTest)
            RegisterAndEnforce(mcp, new PenTestMCPTools(registry), config);
        else
            RegisterAndEnforce(mcp, new DFIRMCPTools(registry), config);
        RegisterResources(mcp, investigation);
        var mcpServices = mcp
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
        app.Lifetime.ApplicationStopping.Register(() => { registry.Dispose(); CloseAndFlushAuditLog(); });

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
