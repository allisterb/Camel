namespace Camel;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

using Camel.Environments;

/// <summary>
/// Per-MCP-session state: a dedicated <see cref="AuditEnvironment"/> (its own SSH/local connection) and the
/// <see cref="CamelToolkitsApi"/> bound to it. Disposing cancels the session's in-flight commands and tears down its
/// connection.
/// </summary>
public sealed class SessionContext : IDisposable
{
    public readonly AuditEnvironment Environment;
    public readonly CamelToolkitsApi ToolkitsApi;
    public readonly CamelWorkflowsApi WorkflowsApi;

    /// <summary>The pen-test (red-team) toolkits bound to this session. Constructed alongside the DFIR api but
    /// only bound into the JS engine by the PenTest server; its toolkits are fail-closed on the engagement gate,
    /// so they do nothing until <c>SetEngagement</c> is called regardless of which server is running.</summary>
    public readonly CamelPenTestToolkitsApi PenTestToolkitsApi;

    /// <summary>The pen-test (red-team) workflows bound to this session — thin composition over the offensive
    /// toolkits, so they inherit the engagement gate transitively. Bound into the JS engine only by the PenTest
    /// server (the offensive analog of <see cref="WorkflowsApi"/>).</summary>
    public readonly CamelPenTestWorkflowsApi PenTestWorkflowsApi;

    /// <summary>External knowledge-base / intelligence-source facades (NVD, …) over a shared client. Bound into the
    /// JS engine by the PenTest server; investigation-neutral, so the blue server can bind threat-intel facades
    /// over the same api later.</summary>
    public readonly CamelKnowledgeApi KnowledgeApi;

    public DateTimeOffset LastAccess = DateTimeOffset.UtcNow;

    /// <summary>The MCP session id (set when the context is created); the default audit case id.</summary>
    public string SessionId = "";

    /// <summary>
    /// The audit case id this session's tool executions are recorded under. Defaults to <see cref="SessionId"/>
    /// (one case per session) and can be set by the agent via the <c>SetCaseId</c> tool to a human-readable case
    /// label, so the per-case audit file is named for the investigation rather than an opaque session id.
    /// </summary>
    public string CaseId = "";

    /// <summary>
    /// The case directory (holding logs/, exports/, reports/) on the machine the server runs on, from the
    /// <c>CaseDir</c> config key the CLI bakes in at launch. Case-side and local even when the audit
    /// <see cref="Environment"/> targets a remote SSH box. Used by <c>SetEngagement</c> to resolve a supplied
    /// authorization document and preserve a hashed copy under <c>reports/authorization/</c>. Empty when the
    /// server was launched with no case dir.
    /// </summary>
    public readonly string CaseDir;

    /// <summary>
    /// Per-session scratch storage, exposed to the JS engine as the global <c>Session</c>. A script can stash an
    /// expensive result (a workflow output, a parsed super-timeline) under a string key and reuse it in a later
    /// <c>Execute</c> call instead of recomputing it — keeping successive analysis steps consistent with the same
    /// underlying objects. Survives an idle connection-sweep (the SSH link is released but this state is kept, and
    /// the next call reconnects); cleared only when the session is fully evicted after a long idle or disposed.
    /// Per-session calls are serialized, so a plain dictionary is sufficient.
    /// </summary>
    public readonly Dictionary<string, object?> Storage = new();

    private int _activeCalls;

    /// <summary>True while one or more tool calls are executing on this session. Busy sessions are never swept
    /// for inactivity — a long-running call must not have its SSH environment disposed out from under it.</summary>
    public bool IsBusy => Volatile.Read(ref _activeCalls) > 0;

    /// <summary>Marks the start of a tool call on this session (increments the active-call count).</summary>
    public void EnterCall() => Interlocked.Increment(ref _activeCalls);

    /// <summary>Marks the end of a tool call and re-stamps <see cref="LastAccess"/> so the idle window starts now.</summary>
    public void LeaveCall()
    {
        Interlocked.Decrement(ref _activeCalls);
        LastAccess = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Releases the session's idle SSH connection (the expensive, leak-prone resource) while keeping the context —
    /// and its in-memory <see cref="Storage"/> and <see cref="CaseId"/> — alive. The next call transparently
    /// reconnects (see <see cref="AuditEnvironment.DisconnectIdle"/>). This lets a session sit idle between Execute
    /// calls without losing cached results, which a full dispose/recreate would discard. Returns true if a live
    /// connection was released.
    /// </summary>
    public bool DisconnectIdle() => Environment.DisconnectIdle();

    public SessionContext(IConfigurationRoot config)
    {
        CaseDir = config["CaseDir"] ?? "";
        Environment = AuditEnvironment.CreateFromConfig(config);
        ToolkitsApi = new CamelToolkitsApi(Environment, config);
        WorkflowsApi = new CamelWorkflowsApi(ToolkitsApi);
        PenTestToolkitsApi = new CamelPenTestToolkitsApi(Environment, config);
        PenTestWorkflowsApi = new CamelPenTestWorkflowsApi(PenTestToolkitsApi);
        KnowledgeApi = new CamelKnowledgeApi(Environment, config);
    }

    public void Dispose()
    {
        try { Environment.CancelExecutions(); } catch { /* best-effort */ }
        try { Environment.Dispose(); } catch { /* best-effort */ }
    }
   
}

/// <summary>
/// Singleton registry mapping an MCP session id to its <see cref="SessionContext"/>. The environment (and its
/// SSH connection) is created lazily on the session's first tool call and disposed when the session ends
/// (see <see cref="End"/>) or is swept for inactivity (see <see cref="SweepIdle"/>). The <see cref="Lazy{T}"/>
/// guarantees only one connection is built even under concurrent first-calls for the same session.
/// </summary>
public sealed class SessionRegistry : IDisposable
{
    private readonly IConfigurationRoot config;
    private readonly int maxSessions;
    private readonly ConcurrentDictionary<string, Lazy<SessionContext>> sessions = new();

    public SessionRegistry(IConfigurationRoot config, int maxSessions = 16)
    {
        this.config = config;
        this.maxSessions = maxSessions;
    }

    /// <summary>Number of live sessions (those whose environment has been created). Primarily for tests/diagnostics.</summary>
    public int Count => sessions.Count;

    /// <summary>True if a context exists for <paramref name="sessionId"/>.</summary>
    public bool Contains(string sessionId) => sessions.ContainsKey(sessionId);

    /// <summary>Returns the session's context, creating its environment on first use. Throws if the session cap is reached.</summary>
    public SessionContext GetOrCreate(string sessionId)
    {
        var lazy = sessions.GetOrAdd(sessionId, id =>
        {
            if (sessions.Count >= maxSessions)
                throw new InvalidOperationException($"Maximum concurrent session limit ({maxSessions}) reached.");
            return new Lazy<SessionContext>(() =>
            {
                Runtime.Info("Creating environment for MCP session {0}.", id);
                // Default the audit case id to the session id (one case per session) until SetCaseId overrides it.
                return new SessionContext(config) { SessionId = id, CaseId = id };
            });
        });
        var ctx = lazy.Value;                    // SSH connect happens here, exactly once per session
        ctx.LastAccess = DateTimeOffset.UtcNow;
        return ctx;
    }

    /// <summary>Ends a session: removes it and disposes its environment (cancels in-flight commands, disconnects).</summary>
    public void End(string sessionId)
    {
        if (sessions.TryRemove(sessionId, out var lazy) && lazy.IsValueCreated)
        {
            Runtime.Info("Disposing environment for MCP session {0}.", sessionId);
            lazy.Value.Dispose();
        }
    }

    /// <summary>
    /// Two-tier idle maintenance, skipping any session with a call in flight:
    /// <list type="bullet">
    /// <item>idle longer than <paramref name="disconnectTtl"/> → release the SSH connection
    /// (<see cref="SessionContext.DisconnectIdle"/>) but keep the context, so the session's in-memory
    /// <see cref="SessionContext.Storage"/> survives and the next call reconnects transparently; and</item>
    /// <item>idle longer than <paramref name="evictTtl"/> → fully end the session (remove + dispose), bounding
    /// session-slot and memory growth for sessions a client has truly abandoned.</item>
    /// </list>
    /// A long-running analysis is never disconnected mid-call (the busy guard), and a freshly-disconnected idle
    /// session is not re-logged each tick (<see cref="SessionContext.DisconnectIdle"/> no-ops once disconnected).
    /// </summary>
    public void SweepIdle(TimeSpan disconnectTtl, TimeSpan evictTtl)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kv in sessions)
        {
            if (!kv.Value.IsValueCreated) continue;
            var ctx = kv.Value.Value;
            if (ctx.IsBusy) continue;                       // a call in flight must keep its connection
            var idle = now - ctx.LastAccess;
            if (idle > evictTtl)
            {
                Runtime.Info("Evicting idle MCP session {0} (inactive longer than {1}).", kv.Key, evictTtl);
                End(kv.Key);
            }
            else if (idle > disconnectTtl && ctx.DisconnectIdle())
            {
                Runtime.Info("Released idle SSH connection for MCP session {0} (inactive longer than {1}); session state retained.",
                    kv.Key, disconnectTtl);
            }
        }
    }

    public void Dispose()
    {
        foreach (var kv in sessions)
            if (kv.Value.IsValueCreated) { try { kv.Value.Value.Dispose(); } catch { /* best-effort */ } }
        sessions.Clear();
    }
}

/// <summary>
/// Background service that periodically performs two-tier idle maintenance (see <see cref="SessionRegistry.SweepIdle"/>):
/// it releases a session's idle SSH connection after a short window — keeping the session's in-memory
/// <see cref="SessionContext.Storage"/> so a returning client doesn't lose cached results — and fully evicts a
/// session only after it has been abandoned for hours, so heavyweight connections and memory don't leak when a
/// client never sends a clean session close. (Eager close on disconnect is a follow-up.)
/// </summary>
public sealed class IdleSessionSweeper : BackgroundService
{
    private readonly SessionRegistry registry;
    private readonly TimeSpan interval = TimeSpan.FromMinutes(1);
    // Release an idle session's SSH connection after 15 min (its in-memory Session storage is retained so a
    // returning client keeps its cached results) ...
    private readonly TimeSpan disconnectTtl = TimeSpan.FromMinutes(15);
    // ... and fully evict a session only after it has been abandoned for hours, to bound slot/memory growth.
    private readonly TimeSpan evictTtl = TimeSpan.FromHours(4);

    public IdleSessionSweeper(SessionRegistry registry) => this.registry = registry;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
                registry.SweepIdle(disconnectTtl, evictTtl);
        }
        catch (OperationCanceledException) { /* shutting down */ }
    }
}
