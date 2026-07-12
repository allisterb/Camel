namespace Camel.Tests;

using System;
using System.Collections.Concurrent;
using System.Net.Sockets;

using Microsoft.Extensions.Configuration;

using Camel.Environments;

public class TestsRuntime : Runtime
{
    static TestsRuntime()
    {
        Runtime.WithFileAndConsoleLogging("Camel", "Tests", true);
        config = LoadConfigFile("testappsettings.json");
    }

    #region SIFT reachability
    // Cache the probe per host:port so an entire suite fails fast when SIFT is down — the first SIFT test pays the
    // (short) probe, the rest throw immediately from the cache instead of each re-probing / hanging.
    private static readonly ConcurrentDictionary<string, bool> siftReachable = new();

    /// <summary>
    /// Fast-fail reachability guard for the SIFT workstation. Probes the SIFT SSH endpoint (<c>SIFT:Host</c>/
    /// <c>SIFT:Port</c> from <paramref name="sshConfig"/>, default <c>192.168.8.117:22</c>) with a short TCP connect
    /// timeout and <b>throws</b> a clear <see cref="InvalidOperationException"/> when it is not reachable — so
    /// SIFT-dependent tests fail in seconds instead of hanging on SSH.NET's long connect timeout when the VM is down.
    /// Returns <paramref name="sshConfig"/> so a test can wrap its config load in one line:
    /// <c>var cfg = EnsureSIFT(LoadConfigFile("sshtestappsettings.json"));</c>. Call it before <c>CreateFromConfig</c>.
    /// </summary>
    public static IConfigurationRoot EnsureSIFT(IConfigurationRoot sshConfig, int timeoutMs = 3000)
    {
        var host = sshConfig["SIFT:Host"] ?? "192.168.8.117";
        var port = int.TryParse(sshConfig["SIFT:Port"], out var p) ? p : 22;
        if (!siftReachable.GetOrAdd($"{host}:{port}", _ => ProbeTcp(host, port, timeoutMs)))
            throw new InvalidOperationException(
                $"SIFT workstation is not reachable at {host}:{port} (TCP probe timed out after {timeoutMs}ms). " +
                "Is the SIFT VM powered on and on the network? These tests require a live SIFT workstation.");
        return sshConfig;
    }

    // A quick TCP connect probe: true only if the port accepts a connection within the timeout. Any timeout/refusal/
    // error counts as unreachable (fail closed).
    private static bool ProbeTcp(string host, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            return client.ConnectAsync(host, port).Wait(timeoutMs) && client.Connected;
        }
        catch { return false; }
    }
    #endregion

    public static void EnvironmentMessageHandler(object? sender, EnvironmentEventArgs e)
    {

        if (e.MessageType == EventMessageType.DEBUG)
        {
            Debug(e.Message);
        }
        else if (e.MessageType == EventMessageType.ERROR)
        {
            if (e.Exception != null)
            {
                Error(e.Exception, e.Message);
            }
            else
            {

                Error(e.Message);

            }
        }
        else
        {
            Info(e.Message);
        }


    }
  
}
