namespace Camel.Tests.Server;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

using Camel;
using Camel.Tests;

/// <summary>
/// End-to-end protocol tests: a real MCP client drives the actual HTTP transport pipeline (hosted in-process
/// on an ephemeral port). The scripts use only pure JS / log() so they don't touch a forensic tool — the
/// Local environment (testappsettings.json) makes session creation cheap and CI-able without an SSH host.
/// xunit creates a fresh instance per test, so each test gets its own server + registry.
/// </summary>
public class McpServerProtocolTests : TestsRuntime, IAsyncLifetime
{
    private WebApplication app = null!;
    private string baseUrl = "";

    public async Task InitializeAsync()
    {
        app = CamelMCPServer.BuildHttpApp(config!);
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");            // ephemeral port
        await app.StartAsync();
        baseUrl = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.First();
    }

    public async Task DisposeAsync()
    {
        await app.StopAsync();
        await app.DisposeAsync();
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

    private static IReadOnlyDictionary<string, object?> Script(string js) =>
        new Dictionary<string, object?> { ["script"] = js };

    [Fact]
    public async Task ExecuteJavaScriptReturnsLoggedOutput()
    {
        await using var client = await NewClientAsync();

        var r = await client.CallToolAsync("ExecuteJavaScript", Script("log('hello'); log(1 + 2);"));

        Assert.NotEqual(true, r.IsError);
        var text = Text(r);
        Assert.Contains("hello", text);
        Assert.Contains("3", text);
    }

    [Fact]
    public async Task ThrowingScriptReturnsError()
    {
        await using var client = await NewClientAsync();

        var r = await client.CallToolAsync("ExecuteJavaScript", Script("throw new Error('boom');"));

        Assert.Equal(true, r.IsError);
        Assert.Contains("boom", Text(r));
    }

    [Fact]
    public async Task EachSessionGetsItsOwnEnvironment()
    {
        var registry = app.Services.GetRequiredService<SessionRegistry>();
        Assert.Equal(0, registry.Count);

        await using var c1 = await NewClientAsync();
        await using var c2 = await NewClientAsync();
        // Environments are created lazily on first tool call, so invoke a (pure-JS) tool on each session.
        await c1.CallToolAsync("ExecuteJavaScript", Script("log(1);"));
        await c2.CallToolAsync("ExecuteJavaScript", Script("log(2);"));

        Assert.Equal(2, registry.Count); // two distinct MCP sessions -> two distinct environments
    }
}
