namespace Camel;

using System;
using System.Collections.Concurrent;
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
    public DateTimeOffset LastAccess = DateTimeOffset.UtcNow;

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

    public SessionContext(IConfigurationRoot config)
    {
        Environment = AuditEnvironment.CreateFromConfig(config);
        ToolkitsApi = new CamelToolkitsApi(Environment, config);
        WorkflowsApi = new CamelWorkflowsApi(ToolkitsApi);
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
                return new SessionContext(config);
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

    /// <summary>Disposes any session whose environment has been idle longer than <paramref name="ttl"/>.</summary>
    public void SweepIdle(TimeSpan ttl)
    {
        var cutoff = DateTimeOffset.UtcNow - ttl;
        foreach (var kv in sessions)
        {
            // Never sweep a session with a call in flight, even if its last-access predates the cutoff — a
            // long-running analysis would otherwise have its SSH connection cancelled and disposed mid-call.
            if (kv.Value.IsValueCreated && !kv.Value.Value.IsBusy && kv.Value.Value.LastAccess < cutoff)
            {
                Runtime.Info("Sweeping idle MCP session {0} (inactive longer than {1}).", kv.Key, ttl);
                End(kv.Key);
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
/// Background service that periodically disposes idle session environments, so heavyweight SSH connections
/// don't leak when a client never sends a clean session close. (Eager close on disconnect is a follow-up.)
/// </summary>
public sealed class IdleSessionSweeper : BackgroundService
{
    private readonly SessionRegistry registry;
    private readonly TimeSpan interval = TimeSpan.FromMinutes(1);
    private readonly TimeSpan ttl = TimeSpan.FromMinutes(15);

    public IdleSessionSweeper(SessionRegistry registry) => this.registry = registry;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
                registry.SweepIdle(ttl);
        }
        catch (OperationCanceledException) { /* shutting down */ }
    }
}
