namespace Camel.Tests.Server;

using System;
using System.Collections.Generic;
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
    public async Task RunsVolatilityThroughServerOverSsh()
    {
        // xunit 2.9.2 has no dynamic Assert.Skip; soft-skip (no-op pass) when the workstation is unavailable
        // so the suite stays green in CI without a SIFT box, mirroring how the toolkit tests depend on it.
        if (!connected)
        {
            Warn("SIFT workstation not reachable; skipping SSH integration test.");
            return;
        }
        await using var client = await NewClientAsync();

        // windows.info is fast and returns one row per metadata field — enough to prove the tool ran over SSH.
        var script = $"var info = memoryAnalysis.WindowsInfo('{MemoryImage}'); log('rows=' + info.length);";
        var r = await client.CallToolAsync("ExecuteJavaScript",
            new Dictionary<string, object?> { ["script"] = script });

        Assert.NotEqual(true, r.IsError);
        Assert.Matches(@"rows=[1-9]\d*", Text(r));   // non-zero number of rows -> volatility actually parsed the image
    }
}
