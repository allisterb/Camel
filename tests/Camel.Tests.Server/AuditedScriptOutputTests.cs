namespace Camel.Tests.Server;

using System;
using System.Collections.Generic;
using System.IO;
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
/// Verifies the agent-facing output globals route correctly through the real MCP <c>Execute</c> binding
/// (<c>MCPServer.cs</c>): <c>auditInfo</c>/<c>auditError</c> both return their line to the agent <b>and</b> persist
/// it to the per-case CLEF audit log (as <c>information</c>/<c>error</c> events), while plain <c>log</c> only returns
/// to the agent and writes nothing to the trail. Drives a real client over the HTTP transport with the process-wide
/// audit logger pointed at a temp directory.
/// </summary>
[Collection("Audit")] // serialize: the audit logger is a process-wide static (shared with AuditTrailTests)
public class AuditedScriptOutputTests : TestsRuntime, IAsyncLifetime
{
    private WebApplication app = null!;
    private string baseUrl = "";
    private string auditDir = "";

    public async Task InitializeAsync()
    {
        auditDir = Path.Combine(Path.GetTempPath(), "camel_audit_" + Guid.NewGuid().ToString("N"));
        Runtime.WithAuditLog(auditDir); // route per-case CLEF files here for this test

        app = CamelMCPServer.BuildHttpApp(config!);
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0"); // ephemeral port
        await app.StartAsync();
        baseUrl = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.First();
    }

    public async Task DisposeAsync()
    {
        await app.StopAsync();
        await app.DisposeAsync();
        Runtime.CloseAndFlushAuditLog();
        try { Directory.Delete(auditDir, true); } catch { }
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
    public async Task AuditInfoAndErrorPersistToTrailWhileLogDoesNot()
    {
        await using var client = await NewClientAsync();

        // Pin the case so the trail routes to a known per-case file.
        await client.CallToolAsync("SetCaseId",
            new Dictionary<string, object?> { ["caseId"] = "audit-script-output" });

        // Distinctive markers so we can locate each line unambiguously in the CLEF.
        const string info = "AUDITINFO_MARKER_finding";
        const string err = "AUDITERROR_MARKER_problem";
        const string logOnly = "LOGONLY_MARKER_notpersisted";

        var r = await client.CallToolAsync("Execute", Script(
            $"auditInfo('{info}'); auditError('{err}'); log('{logOnly}');"));

        // All three are surfaced to the agent in the response output (same output buffer).
        Assert.NotEqual(true, r.IsError);
        var text = Text(r);
        Assert.Contains(info, text);
        Assert.Contains(err, text);
        Assert.Contains(logOnly, text);

        Runtime.CloseAndFlushAuditLog(); // flush buffered events to disk before reading

        var file = Path.Combine(auditDir, "audit-audit-script-output.clef");
        Assert.True(File.Exists(file), $"expected per-case audit file at {file}");
        var lines = File.ReadAllLines(file);

        // auditInfo -> exactly one `information` event, carrying its message.
        var infoLine = Assert.Single(lines, l => l.Contains("\"EventType\":\"information\""));
        Assert.Contains(info, infoLine);

        // auditError -> exactly one `error` event, carrying its message.
        var errLine = Assert.Single(lines, l => l.Contains("\"EventType\":\"error\""));
        Assert.Contains(err, errLine);

        // The verbatim script is recorded once by the `started` execution event, so every marker appears there.
        // auditInfo/auditError each add a *second* dedicated event; plain log() adds none. Hence info/err appear
        // twice (script echo + their own event) and logOnly appears exactly once (the script echo only) — proof
        // that log() persists nothing of its own to the trail.
        Assert.Equal(2, lines.Count(l => l.Contains(info)));
        Assert.Equal(2, lines.Count(l => l.Contains(err)));
        Assert.Equal(1, lines.Count(l => l.Contains(logOnly)));
        Assert.DoesNotContain(logOnly, infoLine);
        Assert.DoesNotContain(logOnly, errLine);
    }

    [Fact]
    public async Task AuditFindingAndAuditReviewRecPersistStructuredEvents()
    {
        await using var client = await NewClientAsync();

        await client.CallToolAsync("SetCaseId",
            new Dictionary<string, object?> { ["caseId"] = "audit-finding" });

        const string obs = "OBSERVATION_marker_logcleared";
        const string interp = "INTERPRETATION_marker_antiforensics";
        const string ids = "exec_aaaa1111, exec_bbbb2222";
        const string review = "REVIEW_marker_attribution_uncertain";

        var r = await client.CallToolAsync("Execute", Script(
            $"auditFinding('{obs}', '{interp}', 'HIGH', '{ids}'); auditReviewRec('{review}');"));

        Assert.NotEqual(true, r.IsError);
        var text = Text(r);
        Assert.Contains(obs, text);
        Assert.Contains(interp, text);
        Assert.Contains("[human-judgement-recommended]", text); // auditReviewRec echoes a labelled line

        Runtime.CloseAndFlushAuditLog();

        var file = Path.Combine(auditDir, "audit-audit-finding.clef");
        Assert.True(File.Exists(file), $"expected per-case audit file at {file}");
        var lines = File.ReadAllLines(file);

        // auditFinding -> a single `finding` event with observation/interpretation/confidence/evidence as
        // distinct structured fields (not just concatenated text).
        var findingLine = Assert.Single(lines, l => l.Contains("\"EventType\":\"finding\""));
        Assert.Contains("\"Confidence\":\"HIGH\"", findingLine);
        Assert.Contains("\"Observation\":\"" + obs + "\"", findingLine);
        Assert.Contains("\"Interpretation\":\"" + interp + "\"", findingLine);
        // Cited evidence is its own field, distinct from the ambient ExecutionId that stamps the recording call.
        Assert.Contains("\"EvidenceExecutionIds\":\"" + ids + "\"", findingLine);

        // auditReviewRec -> a single `human-judgement-recommended` event carrying its reason.
        var reviewLine = Assert.Single(lines, l => l.Contains("\"EventType\":\"human-judgement-recommended\""));
        Assert.Contains(review, reviewLine);
    }

    [Fact]
    public async Task IrAccuracyFunctionsPersistAsTheirOwnEventTypes()
    {
        await using var client = await NewClientAsync();

        await client.CallToolAsync("SetCaseId",
            new Dictionary<string, object?> { ["caseId"] = "audit-ir" });

        const string fp = "FP_marker_benign_scheduledtask";
        const string me = "ME_marker_security_evtx_cleared";
        const string hl = "HL_marker_invented_field";

        var r = await client.CallToolAsync("Execute", Script(
            $"auditFalsePositive('{fp}'); auditMissingEvidence('{me}'); auditHallucination('{hl}');"));

        Assert.NotEqual(true, r.IsError);
        var text = Text(r);
        Assert.Contains(fp, text);
        Assert.Contains(me, text);
        Assert.Contains(hl, text);

        Runtime.CloseAndFlushAuditLog();

        var file = Path.Combine(auditDir, "audit-audit-ir.clef");
        Assert.True(File.Exists(file), $"expected per-case audit file at {file}");
        var lines = File.ReadAllLines(file);

        Assert.Contains(fp, Assert.Single(lines, l => l.Contains("\"EventType\":\"false-positive\"")));
        Assert.Contains(me, Assert.Single(lines, l => l.Contains("\"EventType\":\"missing-evidence\"")));
        Assert.Contains(hl, Assert.Single(lines, l => l.Contains("\"EventType\":\"hallucination\"")));
    }

    [Fact]
    public async Task ReferencingNonexistentToolkitIsAutoClassifiedAsHallucination()
    {
        await using var client = await NewClientAsync();

        await client.CallToolAsync("SetCaseId",
            new Dictionary<string, object?> { ["caseId"] = "audit-hallucinate" });

        // FooToolkit is not a bound API name -> ReferenceError "FooToolkit is not defined". The server's
        // classifier sees the *Toolkit token + "is not defined" and records a hallucination event, and the
        // returned error nudges the agent back to the documented SDK so the failure is self-correcting.
        var r = await client.CallToolAsync("Execute", Script("FooToolkit.scan('/evidence');"));

        Assert.Equal(true, r.IsError);
        Assert.Contains("[possible hallucination]", Text(r));

        Runtime.CloseAndFlushAuditLog();

        var file = Path.Combine(auditDir, "audit-audit-hallucinate.clef");
        Assert.True(File.Exists(file), $"expected per-case audit file at {file}");
        var lines = File.ReadAllLines(file);
        Assert.Contains(lines, l => l.Contains("\"EventType\":\"hallucination\""));
    }
}
