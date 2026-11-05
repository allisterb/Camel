namespace Camel.Tests;

using System;

using Microsoft.Extensions.Configuration;

using Camel.Environments;

public class TestsRuntime : Runtime
{
    static TestsRuntime()
    {
        Runtime.WithFileAndConsoleLogging("Camel", "Tests", true);
        config = LoadConfigFile("testappsettings.json");
    }

    #region Host reachability
    // The probe itself lives in HostReachability (no static ctor, so suites that do not derive from this class
    // can use it without triggering config/logger setup). These two keep the existing call sites working.

    /// <inheritdoc cref="HostReachability.IsActivePlatformReachable"/>
    public static bool IsActivePlatformReachable(IConfigurationRoot cfg, out string reason, int timeoutMs = 3000) =>
        HostReachability.IsActivePlatformReachable(cfg, out reason, timeoutMs);

    /// <summary>
    /// Reachability guard for the SIFT workstation that <b>throws</b> a clear <see cref="InvalidOperationException"/>
    /// when it is down, for call sites that want a hard failure rather than a skip. Returns
    /// <paramref name="sshConfig"/> so a test can wrap its config load in one line:
    /// <c>var cfg = EnsureSIFT(LoadConfigFile("sshtestappsettings.json"));</c>. Call it before <c>CreateFromConfig</c>.
    /// Prefer <see cref="IsActivePlatformReachable"/> plus a skip for suites gated on an optional lab VM.
    /// </summary>
    public static IConfigurationRoot EnsureSIFT(IConfigurationRoot sshConfig, int timeoutMs = 3000)
    {
        var host = sshConfig["SIFT:Host"] ?? "192.168.8.117";
        var port = int.TryParse(sshConfig["SIFT:Port"], out var p) ? p : 22;
        if (!HostReachability.IsReachable(host, port, timeoutMs))
            throw new InvalidOperationException(
                $"SIFT workstation is not reachable at {host}:{port} (TCP probe timed out after {timeoutMs}ms). " +
                "Is the SIFT VM powered on and on the network? These tests require a live SIFT workstation.");
        return sshConfig;
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
