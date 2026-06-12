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
    public void SweepIdleEvictsStaleSessions()
    {
        var reg = NewRegistry();
        var fresh = reg.GetOrCreate("fresh");
        var stale = reg.GetOrCreate("stale");
        stale.LastAccess = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(30);

        reg.SweepIdle(TimeSpan.FromMinutes(15));

        Assert.True(reg.Contains("fresh"));
        Assert.False(reg.Contains("stale"));
        Assert.Equal(1, reg.Count);
    }

    [Fact]
    public void SweepIdleSkipsBusySessions()
    {
        var reg = NewRegistry();
        var busy = reg.GetOrCreate("busy");
        busy.LastAccess = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(30); // stale by last-access...
        busy.EnterCall();                                                   // ...but a call is in flight

        reg.SweepIdle(TimeSpan.FromMinutes(15));
        Assert.True(reg.Contains("busy"));   // not swept: a long-running call must keep its SSH environment

        busy.LeaveCall();                    // call ends; LeaveCall re-stamps LastAccess to now
        reg.SweepIdle(TimeSpan.FromMinutes(15));
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
