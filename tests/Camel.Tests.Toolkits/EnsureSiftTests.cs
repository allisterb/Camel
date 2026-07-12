using System.Collections.Generic;
using System.Diagnostics;

using Microsoft.Extensions.Configuration;

using Camel.Tests;

namespace Camel.Tests.Toolkits;

/// <summary>
/// Offline tests for <see cref="TestsRuntime.EnsureSIFT"/> — the fast-fail reachability guard the SIFT-dependent
/// tests call so they error in seconds instead of hanging on SSH.NET's long connect timeout when the SIFT VM is down.
/// </summary>
public class EnsureSiftTests : TestsRuntime
{
    static IConfigurationRoot Cfg(string host, int port) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["SIFT:Host"] = host, ["SIFT:Port"] = port.ToString() })
        .Build();

    [Fact]
    public void EnsureSIFT_UnreachableHost_ThrowsFastWithClearMessage()
    {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737) — reserved and unroutable, so the probe never connects.
        var cfg = Cfg("192.0.2.1", 22);
        var sw = Stopwatch.StartNew();
        var ex = Assert.Throws<InvalidOperationException>(() => EnsureSIFT(cfg, 1500));
        sw.Stop();

        Assert.Contains("not reachable", ex.Message);
        Assert.Contains("192.0.2.1:22", ex.Message);
        // Fast fail — bounded by the probe timeout, not SSH.NET's minutes-long connect.
        Assert.True(sw.ElapsedMilliseconds < 6000, $"EnsureSIFT should fail fast; took {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void EnsureSIFT_DefaultsToTheKnownSiftHost_WhenConfigOmitsIt()
    {
        // With no SIFT:Host in config it falls back to 192.168.8.117 — surfaced in the failure message so the
        // operator sees exactly what was probed. (Uses a closed port to force the failure path deterministically.)
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["SIFT:Port"] = "1" }).Build();
        var ex = Assert.Throws<InvalidOperationException>(() => EnsureSIFT(cfg, 1500));
        Assert.Contains("192.168.8.117:1", ex.Message);
    }
}
