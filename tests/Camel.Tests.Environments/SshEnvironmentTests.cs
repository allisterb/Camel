namespace Camel.Tests.Environments;

using System.Diagnostics;

using Camel.Environments;

public class SshEnvironmentTests : TestsRuntime
{        
    public SshEnvironmentTests()
    {
        if (config is null)
        {
            throw new Exception("Configuration not loaded");
        }
        host = GetRequiredValue(config, "Sift:Host");
        port = Int32.Parse(GetRequiredValue(config, "Sift:Port"));
        user = GetRequiredValue(config, "Sift:User");
        password = GetRequiredValue(config, "Sift:Password");
        le = new LocalEnvironment(EnvironmentMessageHandler);
    }
    [Fact]
    public void CanConnect()
    {
        SshAuditEnvironment env = new SshAuditEnvironment(EnvironmentMessageHandler, "camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), le);
        Assert.True(env.IsConnected);
    }

    [Fact]
    public void CanExecuteCommand()
    {
        SshAuditEnvironment env = new SshAuditEnvironment(EnvironmentMessageHandler, "camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), le);
        var result = env.ExecuteCommand("echo", "hello", out string output);
        Assert.True(result);
        Assert.Equal("hello", output.Trim());
        result = env.ExecuteCommand("foo", "bar", out output);
        Assert.False(result);
    }

    [Fact]
    public async Task CanExecuteAsync()
    {
        SshAuditEnvironment env = new SshAuditEnvironment(EnvironmentMessageHandler, "camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), le);
        var r = await env.ExecuteAsync("echo", "hello");        
        Assert.True(r.ExitCode == 0);
        Assert.Equal("hello", r.StdOut);        
    }

    [Fact]
    public async Task LimiterBoundsConcurrentExecutions()
    {
        var env = NewEnv();
        env.MaxConcurrentExecutions = 2;

        var sw = Stopwatch.StartNew();
        await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => env.ExecuteCommandAsync("sleep", "1")));
        sw.Stop();

        // Six one-second sleeps, two at a time => ~3 sequential batches (~3s). If they ran concurrently it
        // would be ~1s, so the lower bound proves the limiter is throttling.
        Assert.True(sw.Elapsed > TimeSpan.FromSeconds(2.5), $"expected throttling to ~3s but took {sw.Elapsed}.");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"unexpectedly slow: {sw.Elapsed}.");
    }

    [Fact]
    public async Task UnlimitedRunsConcurrently()
    {
        var env = NewEnv();
        env.MaxConcurrentExecutions = 0; // unlimited (default)

        var sw = Stopwatch.StartNew();
        await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => env.ExecuteCommandAsync("sleep", "1")));
        sw.Stop();

        // All six run at once over the connection's channels => ~1s + overhead, well under the throttled ~3s.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2.5), $"expected concurrent execution but took {sw.Elapsed}.");
    }

    SshAuditEnvironment NewEnv() =>
        new SshAuditEnvironment(EnvironmentMessageHandler, "camel", host, port, user, password,
            new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), le);

    LocalEnvironment le;
    string host, user, password;
    int port;
}
