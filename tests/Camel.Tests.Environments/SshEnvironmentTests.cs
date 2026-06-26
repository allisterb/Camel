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
    }

    // Build the environment the way Camel does at runtime: CreateFromConfig honours the active "Platform"
    // profile (Kali / SIFT / …), so these tests exercise the platform-aware connection path end to end rather
    // than reaching past it to a hardcoded section.
    SshAuditEnvironment NewEnv() => (SshAuditEnvironment)AuditEnvironment.CreateFromConfig(config!);

    [Fact]
    public void CreateFromConfigConnectsToActivePlatformHost()
    {
        var platform = config!["Platform"] ?? "SIFT";
        var env = NewEnv();
        Assert.True(env.IsConnected);
        // Proves CreateFromConfig selected the *active* platform's profile (its Host), not a hardcoded one.
        Assert.Equal(GetRequiredValue(config, $"{platform}:Host"), env.HostName);
    }

    [Fact]
    public void CanConnect()
    {
        Assert.True(NewEnv().IsConnected);
    }

    [Fact]
    public void CanExecuteCommand()
    {
        var env = NewEnv();
        var result = env.ExecuteCommand("echo", "hello", out string output);
        Assert.True(result);
        Assert.Equal("hello", output.Trim());
        result = env.ExecuteCommand("foo", "bar", out output);
        Assert.False(result);
    }

    [Fact]
    public async Task CanExecuteAsync()
    {
        var r = await NewEnv().ExecuteAsync("echo", "hello");
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

    [Fact]
    public async Task DisconnectIdleReleasesConnectionAndNextCommandReconnects()
    {
        var env = NewEnv();
        Assert.True(env.IsConnected);

        // The idle sweeper releases the connection without disposing the environment.
        Assert.True(env.DisconnectIdle());
        Assert.False(env.IsConnected);
        Assert.False(env.DisconnectIdle());   // idempotent: nothing to release the second time

        // The next command transparently reconnects (sync and async paths) and succeeds.
        Assert.True(env.ExecuteCommand("echo", "back", out var output));
        Assert.Equal("back", output.Trim());
        Assert.True(env.IsConnected);

        env.DisconnectIdle();
        var r = await env.ExecuteCommandAsync("echo", "again");
        Assert.True(r.IsCompleted);
        Assert.Equal("again", r.Output.Trim());
    }
}
