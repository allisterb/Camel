namespace Camel.Tests.Intel;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;

using Camel.Intel;

/// <summary>
/// Offline tests for the three KB-subsystem polish features: raw-response retention (content-addressed to disk),
/// the launch-time source availability report, and the HTTP POST transport (via the OSV facade).
/// </summary>
public class KnowledgeBasePolishTests
{
    static IConfigurationRoot Config(params (string, string?)[] kv) =>
        new ConfigurationBuilder().AddInMemoryCollection(kv.ToDictionary(x => x.Item1, x => x.Item2)).Build();

    #region 1. Raw-response retention
    [Fact]
    public async Task SuccessfulFetch_RetainsRawBodyContentAddressed()
    {
        var dir = Path.Combine(Path.GetTempPath(), "camel_kb_" + Guid.NewGuid().ToString("N"));
        const string body = """{ "vulnerabilities": [] }""";
        try
        {
            var client = new KnowledgeBaseClient(
                Config(("KnowledgeBases:nvd:BaseUrl", "https://x"), ("KnowledgeBases:nvd:Auth", "None"),
                       ("KnowledgeBaseRetentionDir", dir)),
                http: new HttpClient(new FakeHandler(body)));

            var r = await client.QueryAsync("nvd", "cves/2.0", new Dictionary<string, string> { ["k"] = "v" }, _ => "ok");

            Assert.True(r.Ok);
            var files = Directory.GetFiles(dir);
            Assert.Single(files);
            Assert.StartsWith("nvd-", Path.GetFileName(files[0]));               // <source>-<digest>.json
            Assert.Equal(body, File.ReadAllText(files[0]));                      // the exact raw response, verbatim
            Assert.EndsWith(".json", files[0]);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public async Task Retention_Off_WhenNoDirConfigured()
    {
        // No KnowledgeBaseRetentionDir -> the query still works, nothing is written (retention simply off).
        var client = new KnowledgeBaseClient(
            Config(("KnowledgeBases:nvd:BaseUrl", "https://x"), ("KnowledgeBases:nvd:Auth", "None")),
            http: new HttpClient(new FakeHandler("{}")));
        var r = await client.QueryAsync("nvd", "cves/2.0", new Dictionary<string, string>(), _ => "ok");
        Assert.True(r.Ok);   // no throw, no retention dir needed
    }
    #endregion

    #region 2. Source availability report
    [Fact]
    public void DescribeSources_ReportsAvailabilityPerKb()
    {
        var client = new KnowledgeBaseClient(
            Config(("KnowledgeBases:nvd:BaseUrl", "https://x"), ("KnowledgeBases:nvd:Auth", "None"),
                   ("KnowledgeBases:shodan:BaseUrl", "https://y"), ("KnowledgeBases:shodan:Auth", "QueryParam"),
                   ("KnowledgeBases:shodan:KeyRef", "SHODAN_API_KEY"),
                   ("KnowledgeBases:exploitdb:Transport", "Cli"), ("KnowledgeBases:exploitdb:Command", "searchsploit")),
            new FakeSecrets());   // no keys resolve

        var byName = client.DescribeSources().ToDictionary(s => s.Name);

        Assert.True(byName["nvd"].Available);                                    // keyless HTTP
        Assert.False(byName["shodan"].Available);                               // needs a key it can't resolve
        Assert.Contains("needs SHODAN_API_KEY", byName["shodan"].Detail);
        Assert.Equal(KbTransport.Cli, byName["exploitdb"].Transport);
        Assert.Contains("searchsploit", byName["exploitdb"].Detail);
    }
    #endregion

    #region 3. POST transport (OSV)
    const string OsvSample = """
    { "vulns": [ {
        "id": "GHSA-xxxx-yyyy-zzzz", "summary": "Remote code execution",
        "aliases": ["CVE-2022-12345"],
        "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ]
    } ] }
    """;

    [Fact]
    public async Task Osv_PostsBody_AndMapsVulns()
    {
        var handler = new FakeHandler(OsvSample);
        var osv = new OsvKnowledgeBase(new KnowledgeBaseClient(
            Config(("KnowledgeBases:osv:BaseUrl", "https://api.osv.dev/"), ("KnowledgeBases:osv:Auth", "None")),
            http: new HttpClient(handler)));

        var r = await osv.QueryPackageAsync("PyPI", "django", "3.0");

        Assert.True(r.Ok);
        var v = r.Result!.Single();
        Assert.Equal("GHSA-xxxx-yyyy-zzzz", v.Id);
        Assert.Contains("CVE-2022-12345", v.Aliases);
        Assert.StartsWith("CVSS:3.1/", v.Severity);

        Assert.Equal("POST", handler.LastMethod);              // it was a POST, not a GET
        Assert.Contains("django", handler.LastBody);           // the package name went in the request body
        Assert.Contains("PyPI", handler.LastBody);
        Assert.StartsWith("POST v1/query", r.Query);           // provenance records the POST + body
    }
    #endregion

    #region Test doubles
    private sealed class FakeHandler(string body, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public int Calls;
        public string? LastUrl;
        public string? LastMethod;
        public string? LastBody;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            LastUrl = request.RequestUri?.ToString();
            LastMethod = request.Method.Method;
            if (request.Content is not null) LastBody = await request.Content.ReadAsStringAsync(ct);
            return new HttpResponseMessage(status) { Content = new StringContent(body) };
        }
    }

    private sealed class FakeSecrets : ISecretsProvider
    {
        public string? Resolve(string keyRef) => null;
    }
    #endregion
}
