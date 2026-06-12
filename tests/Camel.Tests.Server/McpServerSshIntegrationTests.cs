namespace Camel.Tests.Server;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

using Camel;
using Camel.Environments;
using Camel.Tests;

/// <summary>
/// Layer 3: drives a real forensic tool (Volatility 3) end-to-end through the MCP server over SSH, exercising
/// the full ExecuteJavaScript -> CamelApi -> MemoryAnalysisToolkit -> SshAuditEnvironment path. Requires the
/// live SIFT workstation (sshtestappsettings.json); skips cleanly when it is unreachable.
///
/// The session environment is built from the SSH config, while the toolkit reads its tool definitions
/// (the real /opt/volatility3/bin/vol command) from the ambient Runtime.config (testappsettings.json).
/// </summary>
public class McpServerSshIntegrationTests : TestsRuntime, IAsyncLifetime
{
    private const string MemoryImage = "/mnt/artifacts/pat-2009-11-19.mddramimage";

    private WebApplication? app;
    private string baseUrl = "";
    private bool connected;

    public async Task InitializeAsync()
    {
        var sshConfig = LoadConfigFile("sshtestappsettings.json");

        // Probe connectivity so the test skips (rather than fails) when no workstation is available.
        using (var probe = AuditEnvironment.CreateFromConfig(sshConfig) as SshAuditEnvironment)
            connected = probe?.IsConnected ?? false;
        if (!connected) return;

        app = CamelMCPServer.BuildHttpApp(sshConfig);
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        baseUrl = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.First();
    }

    public async Task DisposeAsync()
    {
        if (app is not null)
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    private async Task<McpClient> NewClientAsync()
    {
        var transport = new HttpClientTransport(
            new HttpClientTransportOptions { Endpoint = new Uri(baseUrl) },
            NullLoggerFactory.Instance);
        return await McpClient.CreateAsync(transport);
    }

    private static string Text(CallToolResult r) =>
        string.Concat(r.Content.OfType<TextContentBlock>().Select(c => c.Text));

    [Fact]
    public async Task AwaitsAsyncToolThroughServerOverSsh()
    {
        // xunit 2.9.2 has no dynamic Assert.Skip; soft-skip (no-op pass) when the workstation is unavailable
        // so the suite stays green in CI without a SIFT box, mirroring how the toolkit tests depend on it.
        if (!connected) { Warn("SIFT workstation not reachable; skipping SSH integration test."); return; }
        await using var client = await NewClientAsync();

        // Proof the async tool surface works end-to-end: JS awaits a CLR Task that runs vol over SSH.
        var script = $"var info = await MemoryAnalysisToolkit.WindowsInfoAsync('{MemoryImage}'); log('rows=' + info.length);";
        var r = await client.CallToolAsync("ExecuteJavaScript",
            new Dictionary<string, object?> { ["script"] = script });

        Assert.NotEqual(true, r.IsError);
        Assert.Matches(@"rows=[1-9]\d*", Text(r));
    }

    [Fact]
    public async Task MountWorkflowDoesNotBlockOnToolInstalls()
    {
        if (!connected) { Warn("SIFT workstation not reachable; skipping SSH integration test."); return; }
        await using var client = await NewClientAsync();

        // A mount-only script touches only the disk-analysis surface — it must NOT trigger the YARA/EZ-tools/
        // hayabusa provisioning that other toolkits run on construction, so it returns promptly even on a fresh
        // session. (Regression for the first-call-blocks-on-installs bug: binding every toolkit per call used to
        // construct them all, stalling a mount on unrelated downloads past the client tool timeout.)
        const string img = "/mnt/artifacts/srl-2018/base-rd-01-cdrive.E01";
        var script = $@"
            var r = await DiskAnalysisWorkflow.MountEwfImageAsync('{img}','/mnt/camel_diag');
            await DiskAnalysisToolkit.UnmountAsync('/mnt/camel_diag');
            log('mounted=' + r.IsSuccess + ' raw=' + (r.IsSuccess ? r.Result.RawDevice : r.Message));
        ";
        var sw = Stopwatch.StartNew();
        var r = await client.CallToolAsync("ExecuteJavaScript",
            new Dictionary<string, object?> { ["script"] = script });
        sw.Stop();

        Assert.NotEqual(true, r.IsError);
        Assert.Contains("mounted=true", Text(r));
        // Generous bound: the mount itself is ~100ms; this just guards against a regression that reintroduces a
        // multi-minute install stall on the mount path.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30), $"mount path took {sw.Elapsed} — unexpected install stall?");
    }

    [Fact]
    public async Task CancelExecutionsAbortsInFlightCommand()
    {
        if (!connected) { Warn("SIFT workstation not reachable; skipping SSH integration test."); return; }

        // The payoff of the async work: CancelExecutions() must abort an in-flight async command (the sync
        // path never observes the token). Use a long remote sleep so the cancel lands mid-flight.
        using var env = (SshAuditEnvironment)AuditEnvironment.CreateFromConfig(LoadConfigFile("sshtestappsettings.json"));
        var sw = Stopwatch.StartNew();
        var task = env.ExecuteCommandAsync("sleep", "30", false);
        await Task.Delay(500);              // let the command get in-flight
        env.CancelExecutions();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await task);
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15), $"cancellation should be prompt but took {sw.Elapsed}.");
    }
}
