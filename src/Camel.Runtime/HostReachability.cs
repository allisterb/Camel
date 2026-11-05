namespace Camel.Tests;

using System;
using System.Collections.Concurrent;
using System.Net.Sockets;

using Microsoft.Extensions.Configuration;

/// <summary>
/// Fast-fail reachability probing for the lab hosts the live test suites drive. Deliberately a plain static class
/// with no static constructor: a probe must never be the thing that triggers configuration loading or logger
/// setup as a side effect, so suites that do not derive from <see cref="TestsRuntime"/> can call it freely.
/// <para>Why it exists: a live suite whose VM is powered off does not fail fast. SSH.NET spends roughly 21
/// seconds per test discovering the host is absent — one run took 7m24s to report, as seven test failures, that
/// a Kali VM was switched off. An absent lab VM is not a regression, so the correct outcome is a skip that names
/// the host, not a wall of red (nor the silent green of a gate that only checks whether a value is configured).</para>
/// </summary>
public static class HostReachability
{
    // Keyed by host:port so a whole suite pays the probe once: the first test probes, the rest read the cache.
    private static readonly ConcurrentDictionary<string, bool> reachable = new();

    /// <summary>
    /// Probes the host the tests will ACTUALLY connect to: the active platform profile named by the
    /// <c>Platform</c> key (SIFT, Kali, …), which is what <c>AuditEnvironment.CreateFromConfig</c> honours.
    /// Reports rather than throws, so the caller can skip.
    /// </summary>
    /// <param name="reason">Why it is unreachable, ready to use as a skip message; empty when reachable.</param>
    public static bool IsActivePlatformReachable(IConfigurationRoot cfg, out string reason, int timeoutMs = 3000)
    {
        var platform = cfg["Platform"] ?? "SIFT";
        var host = cfg[$"{platform}:Host"];
        var port = int.TryParse(cfg[$"{platform}:Port"], out var p) ? p : 22;

        if (string.IsNullOrWhiteSpace(host))
        {
            reason = $"No '{platform}:Host' is configured for the active platform '{platform}'.";
            return false;
        }
        if (!IsReachable(host, port, timeoutMs))
        {
            reason = $"The active platform '{platform}' is not reachable at {host}:{port} (TCP probe timed out " +
                     $"after {timeoutMs}ms). Power that VM on, or correct its host address. Skipped rather than " +
                     "failed: an absent lab VM is not a regression.";
            return false;
        }
        reason = string.Empty;
        return true;
    }

    /// <summary>Cached TCP reachability check for one endpoint.</summary>
    public static bool IsReachable(string host, int port, int timeoutMs = 3000) =>
        reachable.GetOrAdd($"{host}:{port}", _ => ProbeTcp(host, port, timeoutMs));

    // True only if the port accepts a connection within the timeout. Any timeout, refusal or error counts as
    // unreachable (fail closed). This is a single connect to one configured endpoint — never a scan or a sweep.
    private static bool ProbeTcp(string host, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            return client.ConnectAsync(host, port).Wait(timeoutMs) && client.Connected;
        }
        catch { return false; }
    }
}
