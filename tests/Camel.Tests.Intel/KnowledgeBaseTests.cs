namespace Camel.Tests.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;

using Camel.Intel;

/// <summary>
/// Offline tests for the knowledge-base subsystem: the NVD response mapping, the <see cref="KbResult{T}"/>
/// provenance envelope, response caching, secret resolution, and the redaction guarantee (an injected API key
/// reaches the request URL but never the audited query). HTTP is faked, so nothing leaves the machine.
/// </summary>
public class KnowledgeBaseTests
{
    // A minimal but real-shaped NVD CVE API 2.0 response (one CVE, with an English + Spanish description, a v3.1
    // metric, and two references).
    const string NvdSample = """
    {
      "resultsPerPage": 1, "totalResults": 1,
      "vulnerabilities": [
        { "cve": {
            "id": "CVE-2020-15778",
            "published": "2020-07-24T23:15:00.000",
            "lastModified": "2023-11-07T03:18:00.000",
            "descriptions": [
              { "lang": "en", "value": "scp in OpenSSH through 8.3p1 allows command injection via backtick." },
              { "lang": "es", "value": "scp en OpenSSH ..." }
            ],
            "metrics": { "cvssMetricV31": [ { "cvssData": {
              "baseScore": 7.8, "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" } } ] },
            "references": [ { "url": "https://example.com/a" }, { "url": "https://example.com/b" } ]
        } }
      ]
    }
    """;

    static IConfigurationRoot Config(params (string, string?)[] kv) =>
        new ConfigurationBuilder().AddInMemoryCollection(kv.ToDictionary(x => x.Item1, x => x.Item2)).Build();

    static (string, string?)[] NvdConfig(int cacheMinutes = 0) =>
    [
        ("KnowledgeBases:nvd:BaseUrl", "https://services.nvd.nist.gov/rest/json/"),
        ("KnowledgeBases:nvd:Auth", "None"),
        ("KnowledgeBases:nvd:CacheTtlMinutes", cacheMinutes.ToString()),
    ];

    #region NVD mapping
    [Fact]
    public void MapCves_ParsesIdScoreSummaryRefs()
    {
        using var doc = JsonDocument.Parse(NvdSample);
        var cve = NvdKnowledgeBase.MapCves(doc.RootElement).Single();

        Assert.Equal("CVE-2020-15778", cve.Id);
        Assert.Equal(7.8, cve.Cvss);
        Assert.StartsWith("CVSS:3.1/", cve.CvssVector);
        Assert.Contains("command injection", cve.Summary);   // the English description, not the Spanish one
        Assert.Equal(2, cve.References.Length);
        Assert.Equal(new DateTime(2020, 7, 24, 23, 15, 0, DateTimeKind.Utc), cve.Published);
    }

    [Fact]
    public void MapCves_EmptyOnNoVulnerabilities()
    {
        using var doc = JsonDocument.Parse("""{ "totalResults": 0, "vulnerabilities": [] }""");
        Assert.Empty(NvdKnowledgeBase.MapCves(doc.RootElement));
    }
    #endregion

    #region Provenance envelope
    [Fact]
    public async Task Query_WrapsResultInProvenanceEnvelope()
    {
        var handler = new FakeHandler(NvdSample);
        var nvd = new NvdKnowledgeBase(new KnowledgeBaseClient(Config(NvdConfig()), http: new HttpClient(handler)));

        var r = await nvd.CvesForProductAsync("openssh", "8.3p1");

        Assert.True(r.Ok);
        Assert.Equal("CVE-2020-15778", r.Result!.Single().Id);
        Assert.Equal("nvd", r.Source);
        Assert.Contains("keywordSearch", r.Query);
        Assert.DoesNotContain(' ', r.Query);                 // the query is URL-encoded
        Assert.StartsWith("sha256:", r.ResponseDigest);
        Assert.Equal(8, r.QueryId.Length);
        Assert.False(r.FromCache);
        Assert.NotEqual(default, r.RetrievedUtc);
    }
    #endregion

    #region Caching
    [Fact]
    public async Task Query_SecondIdenticalCall_IsServedFromCache()
    {
        var handler = new FakeHandler(NvdSample);
        var nvd = new NvdKnowledgeBase(new KnowledgeBaseClient(Config(NvdConfig(cacheMinutes: 60)), http: new HttpClient(handler)));

        var first = await nvd.CvesForProductAsync("openssh", "8.3p1");
        var second = await nvd.CvesForProductAsync("openssh", "8.3p1");

        Assert.Equal(1, handler.Calls);                      // the upstream API was hit once
        Assert.False(first.FromCache);
        Assert.True(second.FromCache);
        Assert.Equal(first.ResponseDigest, second.ResponseDigest);
        Assert.Equal(first.RetrievedUtc, second.RetrievedUtc);   // cache hit reproduces the ORIGINAL fetch time
    }
    #endregion

    #region Availability + secrets
    [Fact]
    public void Unavailable_WhenRequiredKeyDoesNotResolve()
    {
        var client = new KnowledgeBaseClient(
            Config(("KnowledgeBases:needkey:BaseUrl", "https://x"),
                   ("KnowledgeBases:needkey:Auth", "Header"),
                   ("KnowledgeBases:needkey:AuthName", "X-Api-Key"),
                   ("KnowledgeBases:needkey:KeyRef", "MISSING_ENV_KEY_XYZ")),
            new FakeSecrets());                              // resolves nothing

        Assert.True(client.IsConfigured("needkey"));
        Assert.False(client.IsAvailable("needkey"));
    }

    [Fact]
    public void OptionalKey_KbIsAvailableWithoutTheKey()
    {
        // NVD-style: a configured key that is NOT required. Available with no key set; uses the key if present.
        var client = new KnowledgeBaseClient(
            Config(("KnowledgeBases:nvd:BaseUrl", "https://x"),
                   ("KnowledgeBases:nvd:Auth", "Header"),
                   ("KnowledgeBases:nvd:AuthName", "apiKey"),
                   ("KnowledgeBases:nvd:KeyRef", "NVD_API_KEY"),
                   ("KnowledgeBases:nvd:KeyRequired", "false")),
            new FakeSecrets());                              // no key resolves
        Assert.True(client.IsAvailable("nvd"));              // ...but the KB is still usable (key only raises limits)
    }

    [Fact]
    public async Task QueryParamAuth_KeyReachesRequest_ButNotTheAuditedQuery()
    {
        var handler = new FakeHandler("{}");
        var client = new KnowledgeBaseClient(
            Config(("KnowledgeBases:shodan:BaseUrl", "https://api.shodan.io/"),
                   ("KnowledgeBases:shodan:Auth", "QueryParam"),
                   ("KnowledgeBases:shodan:AuthName", "key"),
                   ("KnowledgeBases:shodan:KeyRef", "SHODAN_API_KEY")),
            new FakeSecrets(("SHODAN_API_KEY", "SECRET123")),
            new HttpClient(handler));

        var r = await client.QueryAsync("shodan", "shodan/host/1.2.3.4",
            new Dictionary<string, string>(), _ => "ok", disclosedTarget: "1.2.3.4");

        Assert.Contains("key=SECRET123", handler.LastUrl);   // the key WAS injected into the real request
        Assert.DoesNotContain("SECRET123", r.Query);         // ...but never appears in the audited/returned query
    }

    [Fact]
    public void DefaultSecretsProvider_ResolvesEnvVarFirst()
    {
        Environment.SetEnvironmentVariable("CAMEL_TEST_SECRET", "abc123");
        try
        {
            var sp = new DefaultSecretsProvider();
            Assert.Equal("abc123", sp.Resolve("CAMEL_TEST_SECRET"));
            Assert.Null(sp.Resolve("CAMEL_NO_SUCH_SECRET_XYZ"));
        }
        finally { Environment.SetEnvironmentVariable("CAMEL_TEST_SECRET", null); }
    }
    #endregion

    #region Test doubles
    private sealed class FakeHandler(string body, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public int Calls;
        public string? LastUrl;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            LastUrl = request.RequestUri?.ToString();
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
        }
    }

    private sealed class FakeSecrets(params (string, string)[] pairs) : ISecretsProvider
    {
        private readonly Dictionary<string, string> map = pairs.ToDictionary(p => p.Item1, p => p.Item2);
        public string? Resolve(string keyRef) => map.TryGetValue(keyRef, out var v) ? v : null;
    }
    #endregion
}
