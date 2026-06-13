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
/// on an ephemeral port). 
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
    public async Task ExecuteReturnsLoggedOutput()
    {
        await using var client = await NewClientAsync();

        var r = await client.CallToolAsync("Execute", Script("log('hello'); log(1 + 2);"));

        Assert.NotEqual(true, r.IsError);
        var text = Text(r);
        Assert.Contains("hello", text);
        Assert.Contains("3", text);
    }

    [Fact]
    public async Task SetCaseIdAndAuditHandleReturned()
    {
        await using var client = await NewClientAsync();

        // SetCaseId is exposed as its own tool and reports the case file it routes to.
        var setr = await client.CallToolAsync("SetCaseId",
            new Dictionary<string, object?> { ["caseId"] = "case-test-1" });
        Assert.Contains("case-test-1", Text(setr));

        // Every Execute result carries an audit handle (case + execution id) the agent can cite so a
        // judge can trace the finding to its tool executions. Same session ⇒ the SetCaseId case id is reflected.
        var r = await client.CallToolAsync("Execute", Script("log('hi');"));
        var text = Text(r);
        Assert.Contains("hi", text);
        Assert.Contains("[audit] case=case-test-1 execution=", text);
    }

    [Fact]
    public async Task TableRendersAsciiGrid()
    {
        await using var client = await NewClientAsync();

        // Mixed cell types (string/number/bool/null) and a ragged short row — exercises sizing + padding.
        var r = await client.CallToolAsync("Execute", Script(
            "table(['Process','PID','Hidden'], [['svchost.exe', 880, false], ['evil', 1337, true], ['x']]);"));

        Assert.NotEqual(true, r.IsError);
        var text = Text(r);
        var expected = string.Join("\n",
            "+-------------+------+--------+",
            "| Process     | PID  | Hidden |",
            "+-------------+------+--------+",
            "| svchost.exe | 880  | false  |",
            "| evil        | 1337 | true   |",
            "| x           |      |        |",
            "+-------------+------+--------+");
        Assert.Contains(expected, text.Replace("\r\n", "\n"));
    }

    [Fact]
    public async Task ThrowingScriptReturnsError()
    {
        await using var client = await NewClientAsync();

        var r = await client.CallToolAsync("Execute", Script("throw new Error('boom');"));

        Assert.Equal(true, r.IsError);
        Assert.Contains("boom", Text(r));
    }

    [Fact]
    public async Task AwaitedAsyncToolResolvesViaTaskInterop()
    {
        await using var client = await NewClientAsync();

        // WindowsInfoAsync returns a CLR Task<WindowsInfo[]?>. With ExperimentalFeature.TaskInterop the JS
        // `await` must resolve it to the value (null here, since vol can't run on the Local test host) rather
        // than hand back an un-awaitable Task object. isNull=true proves the Task->promise interop works.
        var r = await client.CallToolAsync("Execute",
            Script("var info = await MemoryAnalysisToolkit.WindowsInfoAsync('/no/such/image'); log('isNull=' + (info === null));"));

        Assert.NotEqual(true, r.IsError);
        Assert.Contains("isNull=true", Text(r));
    }

    [Fact]
    public async Task AwaitedRejectionIsReportedAsError()
    {
        await using var client = await NewClientAsync();

        // A rejected promise awaited in the script must surface as a catchable error through ExecuteAsync.
        var r = await client.CallToolAsync("Execute",
            Script("await Promise.reject(new Error('async boom'));"));

        Assert.Equal(true, r.IsError);
        Assert.Contains("async boom", Text(r));
    }

    [Fact]
    public async Task SdkReferenceResourcesAreListedAndReadable()
    {
        await using var client = await NewClientAsync();

        // Both SDK docs must be advertised in resources/list...
        var list = await client.ListResourcesAsync(new ListResourcesRequestParams());
        var uris = list.Resources.Select(r => r.Uri).ToList();
        Assert.Contains("camel://sdk/core", uris);
        Assert.Contains("camel://sdk/schema", uris);
        Assert.Contains("camel://sdk/discipline", uris);

        // ...and read back with their embedded markdown content.
        var core = await client.ReadResourceAsync("camel://sdk/core");
        var coreText = string.Concat(core.Contents.OfType<TextResourceContents>().Select(c => c.Text));
        Assert.Contains("Camel JavaScript SDK", coreText);
        Assert.Contains("Execute", coreText);

        var schema = await client.ReadResourceAsync("camel://sdk/schema");
        var schemaText = string.Concat(schema.Contents.OfType<TextResourceContents>().Select(c => c.Text));
        Assert.Contains("WorkflowResult Schema", schemaText);
        Assert.Contains("TimelineEvent Schema", schemaText);

        var discipline = await client.ReadResourceAsync("camel://sdk/discipline");
        var disciplineText = string.Concat(discipline.Contents.OfType<TextResourceContents>().Select(c => c.Text));
        Assert.Contains("Forensic Discipline", disciplineText);
        Assert.Contains("auditReviewRec", disciplineText);
    }

    [Fact]
    public async Task SessionStoragePersistsValuesAcrossExecuteCalls()
    {
        await using var client = await NewClientAsync();

        // Stash a value via the Session global in one Execute call...
        var w = await client.CallToolAsync("Execute", Script("Session['hits'] = 3 + 4; log('stored');"));
        Assert.NotEqual(true, w.IsError);

        // ...and read it back in a later call on the SAME session (same SessionContext.Storage instance).
        var r = await client.CallToolAsync("Execute", Script("log('hits=' + Session['hits']);"));
        Assert.NotEqual(true, r.IsError);
        Assert.Contains("hits=7", Text(r));
    }

    [Fact]
    public async Task SessionStorageIsIsolatedPerSessionAndMissingKeysAreUndefined()
    {
        await using var c1 = await NewClientAsync();
        await using var c2 = await NewClientAsync();

        await c1.CallToolAsync("Execute", Script("Session['x'] = 'from-c1';"));
        // A different session must not see c1's value, and an absent key reads back as undefined (not a throw).
        var r = await c2.CallToolAsync("Execute",
            Script("log('x=' + (Session['x'] === undefined ? 'unset' : Session['x']));"));

        Assert.NotEqual(true, r.IsError);
        Assert.Contains("x=unset", Text(r));
    }

    [Fact]
    public async Task SessionStorageEntriesCanBeEvictedWithDelete()
    {
        await using var client = await NewClientAsync();

        await client.CallToolAsync("Execute", Script("Session['big'] = [1, 2, 3];"));
        // `delete` on the CLR-backed Session must remove the entry (dropping the reference so the GC can reclaim
        // the cached object), and the key must then read back as undefined.
        var r = await client.CallToolAsync("Execute", Script(
            "delete Session['big']; log('after=' + (Session['big'] === undefined ? 'gone' : 'present'));"));

        Assert.NotEqual(true, r.IsError);
        Assert.Contains("after=gone", Text(r));
    }

    [Fact]
    public async Task SessionStorageSurvivesIdleConnectionSweepButNotFullEviction()
    {
        await using var client = await NewClientAsync();
        var registry = app.Services.GetRequiredService<SessionRegistry>();

        // Stash an array (round-tripped through map() to prove it's a real JS array, not an opaque handle).
        await client.CallToolAsync("Execute", Script("Session['arr'] = [1,2,3].map(x => x * 2);"));

        // Disconnect-tier sweep (idle past the first threshold, before the eviction threshold): the session's
        // connection is released but its Storage is retained — the value must still be there next call.
        registry.SweepIdle(TimeSpan.Zero, TimeSpan.FromHours(4));
        var r1 = await client.CallToolAsync("Execute", Script("log('sum=' + Session['arr'].reduce((a, b) => a + b, 0));"));
        Assert.NotEqual(true, r1.IsError);
        Assert.Contains("sum=12", Text(r1));          // [2,4,6] survived as a usable array across the sweep

        // Full-eviction-tier sweep: the session (and its Storage) is dropped; the key reads back undefined.
        registry.SweepIdle(TimeSpan.Zero, TimeSpan.Zero);
        var r2 = await client.CallToolAsync("Execute",
            Script("log('after=' + (Session['arr'] === undefined ? 'gone' : 'present'));"));
        Assert.NotEqual(true, r2.IsError);
        Assert.Contains("after=gone", Text(r2));
    }

    [Fact]
    public async Task EachSessionGetsItsOwnEnvironment()
    {
        var registry = app.Services.GetRequiredService<SessionRegistry>();
        Assert.Equal(0, registry.Count);

        await using var c1 = await NewClientAsync();
        await using var c2 = await NewClientAsync();
        // Environments are created lazily on first tool call, so invoke a (pure-JS) tool on each session.
        await c1.CallToolAsync("Execute", Script("log(1);"));
        await c2.CallToolAsync("Execute", Script("log(2);"));

        Assert.Equal(2, registry.Count); // two distinct MCP sessions -> two distinct environments
    }
}
