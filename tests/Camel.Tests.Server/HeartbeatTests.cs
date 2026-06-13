namespace Camel.Tests.Server;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Camel;
using ModelContextProtocol;

/// <summary>
/// Unit tests for <see cref="CamelMCPTools.RunWithHeartbeatAsync"/> — the keep-alive that emits progress
/// notifications while a long Execute call runs so the MCP client doesn't time out and abort the
/// request mid-call. No server/SSH required; drives the helper directly with short intervals.
/// </summary>
public class HeartbeatTests
{
    private sealed class ProgressCollector : IProgress<ProgressNotificationValue>
    {
        private readonly List<ProgressNotificationValue> _reports = new();
        public int Count { get { lock (_reports) return _reports.Count; } }
        public void Report(ProgressNotificationValue value) { lock (_reports) _reports.Add(value); }
    }

    [Fact]
    public async Task EmitsHeartbeatsWhileWorkRuns()
    {
        var progress = new ProgressCollector();
        // ~300ms of work with a 40ms heartbeat ⇒ several notifications before completion.
        await CamelMCPTools.RunWithHeartbeatAsync(Task.Delay(300), progress, TimeSpan.FromMilliseconds(40), CancellationToken.None);
        Assert.True(progress.Count >= 2, $"expected multiple heartbeats, got {progress.Count}");
    }

    [Fact]
    public async Task NoHeartbeatForFastWork()
    {
        var progress = new ProgressCollector();
        await CamelMCPTools.RunWithHeartbeatAsync(Task.CompletedTask, progress, TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.Equal(0, progress.Count);
    }

    [Fact]
    public async Task SurfacesWorkException()
    {
        var progress = new ProgressCollector();
        var work = Task.Run(() => throw new InvalidOperationException("boom"));
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            CamelMCPTools.RunWithHeartbeatAsync(work, progress, TimeSpan.FromMilliseconds(40), CancellationToken.None));
        Assert.Equal("boom", ex.Message);
    }

    [Fact]
    public async Task PropagatesCancellation()
    {
        var progress = new ProgressCollector();
        using var cts = new CancellationTokenSource();
        var work = new TaskCompletionSource().Task; // never completes
        cts.CancelAfter(60);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CamelMCPTools.RunWithHeartbeatAsync(work, progress, TimeSpan.FromMilliseconds(20), cts.Token));
    }
}
