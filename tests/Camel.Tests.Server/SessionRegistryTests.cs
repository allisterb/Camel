namespace Camel.Tests.Server;

using System;
using System.Threading.Tasks;

using Camel;
using Camel.Tests;

/// <summary>
/// Unit tests for the per-session environment registry. These run against a Local environment
/// (testappsettings.json sets SIFT:Environment=Local), so no SSH workstation is required.
/// </summary>
public class SessionRegistryTests : TestsRuntime
{
    private static SessionRegistry NewRegistry(int maxSessions = 16) => new(config!, maxSessions);

    [Fact]
    public void SameSessionIdReturnsSameContext()
    {
        var reg = NewRegistry();
        var a = reg.GetOrCreate("s1");
        var b = reg.GetOrCreate("s1");
        Assert.Same(a, b);
        Assert.Equal(1, reg.Count);
    }

    [Fact]
    public void DifferentSessionIdsAreIsolated()
    {
        var reg = NewRegistry();
        var a = reg.GetOrCreate("s1");
        var b = reg.GetOrCreate("s2");
        Assert.NotSame(a, b);
        Assert.NotSame(a.Environment, b.Environment); // each session gets its own environment
        Assert.Equal(2, reg.Count);
    }

    [Fact]
    public void ConcurrentFirstCallsCreateSingleContext()
    {
        var reg = NewRegistry();
        var contexts = new System.Collections.Concurrent.ConcurrentBag<SessionContext>();
        Parallel.For(0, 64, _ => contexts.Add(reg.GetOrCreate("race")));

        Assert.Equal(1, reg.Count);                         // the Lazy<> collapses the race to one build
        var first = System.Linq.Enumerable.First(contexts);
        Assert.All(contexts, c => Assert.Same(first, c));
    }

    [Fact]
    public void EnforcesMaxSessions()
    {
        var reg = NewRegistry(maxSessions: 1);
        reg.GetOrCreate("s1");
        Assert.Throws<InvalidOperationException>(() => reg.GetOrCreate("s2"));
        Assert.Equal(1, reg.Count);
    }

    [Fact]
    public void EndRemovesAndDisposesSession()
    {
        var reg = NewRegistry();
        reg.GetOrCreate("s1");
        Assert.True(reg.Contains("s1"));

        reg.End("s1");
        Assert.False(reg.Contains("s1"));
        Assert.Equal(0, reg.Count);
    }

    [Fact]
    public void SweepIdleRetainsDisconnectedSessionsButEvictsAbandonedOnes()
    {
        var reg = NewRegistry();
        var disconnectTtl = TimeSpan.FromMinutes(15);
        var evictTtl = TimeSpan.FromHours(4);

        var fresh = reg.GetOrCreate("fresh");
        var idle = reg.GetOrCreate("idle");
        var abandoned = reg.GetOrCreate("abandoned");
        idle.LastAccess = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(30);   // past disconnect, before evict
        abandoned.LastAccess = DateTimeOffset.UtcNow - TimeSpan.FromHours(5); // past evict

        reg.SweepIdle(disconnectTtl, evictTtl);

        // The idle session keeps its slot (and its in-memory Storage) — only its connection is released; the
        // abandoned session is fully evicted; the fresh one is untouched.
        Assert.True(reg.Contains("fresh"));
        Assert.True(reg.Contains("idle"));
        Assert.False(reg.Contains("abandoned"));
        Assert.Equal(2, reg.Count);
    }

    [Fact]
    public void SweepIdleNeverEvictsBusySessions()
    {
        var reg = NewRegistry();
        var disconnectTtl = TimeSpan.FromMinutes(15);
        var evictTtl = TimeSpan.FromHours(4);

        var busy = reg.GetOrCreate("busy");
        busy.LastAccess = DateTimeOffset.UtcNow - TimeSpan.FromHours(5);  // stale enough to evict...
        busy.EnterCall();                                                 // ...but a call is in flight

        reg.SweepIdle(disconnectTtl, evictTtl);
        Assert.True(reg.Contains("busy"));   // a long-running call keeps its session and connection

        busy.LeaveCall();                    // call ends; LeaveCall re-stamps LastAccess to now
        reg.SweepIdle(disconnectTtl, evictTtl);
        Assert.True(reg.Contains("busy"));   // still fresh immediately after the call returned
    }

    [Fact]
    public void DisposeClearsAllSessions()
    {
        var reg = NewRegistry();
        reg.GetOrCreate("s1");
        reg.GetOrCreate("s2");

        reg.Dispose();
        Assert.Equal(0, reg.Count);
    }
}
