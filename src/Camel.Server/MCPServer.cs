namespace Camel;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

using ModelContextProtocol;
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
        jsoptions.Constraints.PromiseTimeout = TimeSpan.FromHours(24);
    }

    [McpServerTool(Name = "SetCaseId"), Description(
        "Set the case identifier for this session's audit trail. Call this ONCE at the start of an investigation " +
        "with a short, human-readable case id (e.g. 'srl-2018-rd01'). Every subsequent Execute tool " +
        "execution in this session is recorded in a per-case audit log file named for this id (audit-<caseId>.clef), " +
        "so findings can be traced to the exact tool executions that produced them. One case per session; call " +
        "again to switch cases. Returns the case id that was set.")]
    public string SetCaseId(string caseId, RequestContext<CallToolRequestParams> context)
    {
        var session = registry.GetOrCreate(SessionId(context.Server));
        var previous = session.CaseId;
        session.CaseId = string.IsNullOrWhiteSpace(caseId) ? session.SessionId : caseId.Trim();
        // Record the case association in the (new) case's audit file so the switch itself is auditable.
        using (PushAuditProperty("CaseId", session.CaseId))
            AuditEvent("case", "Case id set to {CaseId} (was {Previous}) for session {SessionId}",
                session.CaseId, previous, session.SessionId);
        return $"Case id set to '{session.CaseId}' for this session. Audit trail file: audit-{session.CaseId}.clef";
    }

    [McpServerTool(Name = "Execute"), Description(
        "Execute JavaScript code against the Camel DFIR API (toolkits + workflows + anomaly engine). " +
        "Before writing any script you MUST read the 'camel-sdk-core' resource (camel://sdk/core) for the " +
        "execution model and the full list of objects and methods, and the 'camel-sdk-schema' resource " +
        "(camel://sdk/schema) for the JSON schema of every value those methods return — without the schemas you " +
        "cannot read results correctly. Call ONLY methods listed in camel-sdk-core, and access ONLY object " +
        "properties listed in camel-sdk-schema; do not invent methods or properties that are not documented there.")]
    public async Task<CallToolResult> Execute(
        string script,
        RequestContext<CallToolRequestParams> context,
        IProgress<ProgressNotificationValue> progress,
        CancellationToken cancellationToken)
    {
        // Each MCP session gets its own environment/API (its own SSH connection); resolve it by session id.
        // The RequestContext is injected by the SDK per request; context.Server carries the session id.
        // progress + cancellationToken are injected by the SDK: progress sends notifications/progress to the
        // client (a no-op when it sent no progress token); cancellationToken trips when the client aborts the call.
        var sessioid = SessionId(context.Server);
        var session = registry.GetOrCreate(sessioid);

        // Open the audit scope for this code-mode call: every tool execution it drives is recorded in the case's
        // audit file tagged with this CaseId and a unique InvocationId, which is returned to the agent so its
        // report can cite it and a judge can trace any finding back to the exact command. The scopes must bracket
        // the whole run so the properties flow across the async boundary into the command-execution events.
        var invocationId = Guid.NewGuid().ToString("N")[..8];
        using var _case = PushAuditProperty("CaseId", session.CaseId);
        using var _inv = PushAuditProperty("InvocationId", invocationId);

        StringBuilder output = new StringBuilder();
        var jsinterp = new Engine(jsoptions)
          .SetValue("log", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("error", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("table", new Action<string[], object[][]>((headers, dataRows) =>
              output.AppendLine(RenderAsciiTable(headers, dataRows))))
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
        BindToolkitIfUsed("UnixToolsToolkit", () => session.ToolkitsApi.UnixTools);

        // Mark the session busy for the duration of the call so the idle sweeper can't dispose its SSH
        // environment out from under a long-running analysis (LastAccess is only stamped at call start).
        session.EnterCall();
        // If the client aborts the call (its timeout fires, or the user cancels), promptly cancel the session's
        // in-flight SSH command(s). Jint only observes its cancellation token at a JS/await boundary, so without
        // this a blocked command (e.g. reading a multi-GB tool output) would keep running for minutes after the
        // client has gone. CancelExecutions swaps in a fresh token source, so the session stays usable afterwards.
        using var cancelReg = cancellationToken.Register(() =>
        {
            try { session.Environment.CancelExecutions(); } catch { /* best-effort */ }
        });
        var auditSw = Stopwatch.StartNew();
        AuditInvocation("started", script);   // records the exact code this invocation ran, under the case file
        try
        {
            // Wrap in an async IIFE so scripts can `await` async toolkit methods: top-level await isn't allowed
            // in a plain Jint script, and modules can't drive a CLR-task top-level await synchronously. The
            // surrounding newlines guard against a trailing line comment swallowing the closer. ExecuteAsync
            // drains the awaited CLR tasks before returning; purely synchronous scripts run unchanged. The
            // cancellationToken lets Jint stop awaiting promises if the client aborts the request.
            var exec = jsinterp.ExecuteAsync($"(async () => {{\n{script}\n}})();", source: null, cancellationToken);

            // Heartbeat: a code-mode analysis can run for many minutes (super-timeline builds, multi-GB memory
            // triage). With no traffic on the response stream the MCP client's per-call idle timeout fires and it
            // aborts the request ("transport dropped mid-call; response was lost"). Emitting a progress
            // notification every HeartbeatInterval resets that client-side timer for the duration of the work.
            await RunWithHeartbeatAsync(exec, progress, HeartbeatInterval, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The client aborted the call; the response channel is already gone, so there is nothing to return.
            AuditInvocation("cancelled", success: false, durationMs: auditSw.ElapsedMilliseconds);
            throw;
        }
        catch (Exception ex)
        {
            AuditInvocation("failed", success: false, durationMs: auditSw.ElapsedMilliseconds);
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
                Content = [new TextContentBlock { Text = message }, InvocationBlock(invocationId, session.CaseId)],
            };
        }
        finally
        {
            // Clears the busy flag and re-stamps LastAccess, so the idle window starts when the call ends.
            session.LeaveCall();
        }

        AuditInvocation("completed", success: true, durationMs: auditSw.ElapsedMilliseconds);
        return new CallToolResult
        {
            Content = [new TextContentBlock { Text = output.ToString() }, InvocationBlock(invocationId, session.CaseId)],
        };
    }

    /// <summary>
    /// The audit-handle block appended to every <c>Execute</c> result: the case id and this call's
    /// invocation id. The agent cites these in its report so a judge can grep the per-case audit file
    /// (<c>audit-&lt;CaseId&gt;.clef</c>) for the invocation and see exactly which tool executions produced a finding.
    /// </summary>
    static TextContentBlock InvocationBlock(string invocationId, string caseId) =>
        new() { Text = $"\n[audit] case={caseId} invocation={invocationId}" };

    /// <summary>
    /// Awaits <paramref name="work"/> while emitting a progress notification every <see cref="HeartbeatInterval"/>
    /// so a long-running tool call keeps resetting the MCP client's idle timeout (otherwise the client aborts the
    /// request mid-call). Returns when the work completes (re-throwing any error it produced); throws
    /// <see cref="OperationCanceledException"/> if the client cancels first.
    /// </summary>
    internal static async Task RunWithHeartbeatAsync(Task work, IProgress<ProgressNotificationValue> progress, TimeSpan interval, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        float tick = 0;
        while (true)
        {
            // Cancel the pending delay as soon as the work finishes so we don't leak a timer per heartbeat.
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var delay = Task.Delay(interval, linked.Token);
            if (await Task.WhenAny(work, delay).ConfigureAwait(false) == work)
            {
                linked.Cancel();
                await work.ConfigureAwait(false);   // observe the result / surface the script exception
                return;
            }
            // The delay won the race: either the interval elapsed (emit a heartbeat) or the caller cancelled —
            // in which case the delay completed as cancelled and we must surface that rather than tick again.
            ct.ThrowIfCancellationRequested();
            progress.Report(new ProgressNotificationValue
            {
                Progress = ++tick,
                Message = $"Camel: executing… ({sw.Elapsed.TotalSeconds:F0}s elapsed)",
            });
        }
    }

    // How often to send a keep-alive progress notification while a script runs. Comfortably under typical MCP
    // client per-call idle timeouts (tens of seconds to minutes) so a multi-minute analysis is never aborted.
    static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(20);

    // Stdio (and any transport that doesn't assign one) yields a null/empty session id; bucket those under "default".
    static string SessionId(McpServer server) => string.IsNullOrEmpty(server.SessionId) ? "default" : server.SessionId;

    /// <summary>
    /// Renders the JS <c>table(headers, rows)</c> call as a fixed-width ASCII grid (psql/GitHub style) for the
    /// script's text output. <paramref name="headers"/> are the column titles; <paramref name="rows"/> is a jagged
    /// array of cell values (Jint marshals JS strings/numbers/bools/null). Columns are sized to the widest cell,
    /// cells are left-aligned, and short/long rows are padded/extended so the grid stays rectangular.
    /// </summary>
    internal static string RenderAsciiTable(string[]? headers, object[][]? rows)
    {
        headers ??= [];
        rows ??= [];

        // Column count spans the header and the widest row (ragged rows are tolerated).
        int cols = headers.Length;
        foreach (var r in rows) cols = Math.Max(cols, r?.Length ?? 0);
        if (cols == 0) return "(empty table)";

        // Stringify every cell up front (header row first), normalising control chars so they can't break the grid.
        string[] Header() => Array.ConvertAll(Pad(headers, cols), Cell);
        var grid = new List<string[]> { Header() };
        grid.AddRange(rows.Select(r => Array.ConvertAll(Pad(r ?? [], cols), Cell)));

        // Width of each column = widest cell in it.
        var widths = new int[cols];
        foreach (var row in grid)
            for (int c = 0; c < cols; c++)
                widths[c] = Math.Max(widths[c], row[c].Length);

        string separator = "+" + string.Join("+", widths.Select(w => new string('-', w + 2))) + "+";
        string Line(string[] row) =>
            "| " + string.Join(" | ", row.Select((c, i) => c.PadRight(widths[i]))) + " |";

        var sb = new StringBuilder();
        sb.AppendLine(separator);
        sb.AppendLine(Line(grid[0]));     // header
        sb.AppendLine(separator);
        for (int i = 1; i < grid.Count; i++) sb.AppendLine(Line(grid[i]));
        sb.Append(separator);
        return sb.ToString();

        // Pad/extend a row to exactly `cols` entries so every grid row is rectangular.
        static object?[] Pad(object?[] row, int cols)
        {
            if (row.Length == cols) return row;
            var padded = new object?[cols];
            Array.Copy(row, padded, Math.Min(row.Length, cols));
            return padded;
        }

        // One cell -> its display string. Numbers/bools use invariant formatting; null -> empty; control chars -> spaces.
        static string Cell(object? v)
        {
            string s = v switch
            {
                null => "",
                bool b => b ? "true" : "false",
                string str => str,
                IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
                _ => v.ToString() ?? "",
            };
            return s.Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');
        }
    }

    readonly SessionRegistry registry;
    readonly Options jsoptions;
}

/// <summary>
/// MCP resources exposing the Camel JavaScript SDK reference to the agent. The two markdown docs are embedded in
/// this assembly (see Camel.Server.csproj) and served verbatim, so an agent can read the SDK surface before
/// generating code for the <c>Execute</c> tool without the docs having to exist on disk at runtime.
/// </summary>
public class CamelResources
{
    [McpServerResource(UriTemplate = "camel://sdk/core", Name = "camel-sdk-core",
        Title = "Camel JS SDK reference — core", MimeType = "text/markdown")]
    [Description("Core reference for the Camel JavaScript SDK used by the Execute tool: the execution " +
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
        app.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping.Register(() =>
        {
            registry.Dispose();
            CloseAndFlushAuditLog();   // flush buffered audit events to the per-case files on a clean shutdown
        });

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
