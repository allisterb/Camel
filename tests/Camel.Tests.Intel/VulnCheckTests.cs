namespace Camel.Tests.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;

using Camel.Intel;

/// <summary>
/// Offline tests for the VulnCheck facade — the worked example of a PAID, keyed intelligence source. Covers the
/// vulncheck-kev response mapping, the <c>Authorization: Bearer &lt;token&gt;</c> injection (the new
/// <see cref="KnowledgeBase.AuthScheme"/>), and graceful unavailability when the analyst supplied no key. HTTP is
/// faked; no key is ever real. As a CVE-keyed KNOWLEDGE source it is ungated (no scope/disclosure fork, unlike Shodan).
/// </summary>
public class VulnCheckTests
{
    const string KevSample = """
    {
      "_benchmark": 0.1,
      "data": [
        {
          "cve": ["CVE-2021-1234"],
          "vulncheck_xdb": [ { "clone_ssh_url": "git@github.com:exploit/poc.git" } ],
          "vulncheck_reported_exploitation": [ { "url": "https://news.example/report" } ],
          "known_ransomware_campaign_use": "Known",
          "date_added": "2021-05-01T00:00:00Z"
        }
      ]
    }
    """;

    static IConfigurationRoot VulnCheckConfig() =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["KnowledgeBases:vulncheck:BaseUrl"] = "https://api.vulncheck.com/v3/",
            ["KnowledgeBases:vulncheck:Auth"] = "Header",
            ["KnowledgeBases:vulncheck:AuthName"] = "Authorization",
            ["KnowledgeBases:vulncheck:AuthScheme"] = "Bearer",
            ["KnowledgeBases:vulncheck:KeyRef"] = "VULNCHECK_API_KEY",
            ["KnowledgeBases:vulncheck:KeyRequired"] = "true",
        }).Build();

    static VulnCheckKnowledgeBase VulnCheck(FakeHandler handler, params (string, string)[] secrets) =>
        new(new KnowledgeBaseClient(VulnCheckConfig(), new FakeSecrets(secrets), new HttpClient(handler)));

    #region Mapping
    [Fact]
    public void MapCve_ParsesExploitedWeaponizedRansomwareAndSources()
    {
        using var doc = System.Text.Json.JsonDocument.Parse(KevSample);
        var vc = VulnCheckKnowledgeBase.MapCve("CVE-2021-1234", doc.RootElement);

        Assert.NotNull(vc);
        Assert.True(vc!.KnownExploited);                 // a returned vulncheck-kev record => exploited
        Assert.True(vc.HasWeaponizedExploit);            // vulncheck_xdb non-empty
        Assert.True(vc.KnownRansomware);                 // "Known"
        Assert.Contains("git@github.com:exploit/poc.git", vc.ExploitSources);
        Assert.Contains("https://news.example/report", vc.ExploitSources);
        Assert.Equal(new DateTime(2021, 5, 1, 0, 0, 0, DateTimeKind.Utc), vc.DateAdded);
    }

    [Fact]
    public void MapCve_EmptyData_ReturnsNull()
    {
        using var doc = System.Text.Json.JsonDocument.Parse("""{ "data": [] }""");
        Assert.Null(VulnCheckKnowledgeBase.MapCve("CVE-2000-1", doc.RootElement));
    }
    #endregion

    #region Bearer auth injection
    [Fact]
    public async Task CveAsync_InjectsBearerAuthorizationHeader_NeverLeaksKeyToTrail()
    {
        var handler = new FakeHandler(KevSample);
        var r = await VulnCheck(handler, ("VULNCHECK_API_KEY", "secret-token")).CveAsync("CVE-2021-1234");

        Assert.True(r.Ok);
        Assert.Equal("Bearer secret-token", handler.LastAuth);   // scheme prefixed, raw token appended
        Assert.DoesNotContain("secret-token", r.Query);          // the key never enters the audited query
    }
    #endregion

    #region Graceful unavailability (no key)
    [Fact]
    public async Task CveAsync_NoKey_IsUnavailable_AndNeverCallsOut()
    {
        var handler = new FakeHandler(KevSample);
        // KeyRequired=true and no VULNCHECK_API_KEY resolves -> the source is unavailable, the call fails closed.
        var r = await VulnCheck(handler /* no secrets */).CveAsync("CVE-2021-1234");

        Assert.False(r.Ok);
        Assert.Equal(0, handler.Calls);                          // no request went out
    }
    #endregion

    #region Test doubles
    private sealed class FakeHandler(string body, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public int Calls;
        public string? LastAuth;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            LastAuth = request.Headers.TryGetValues("Authorization", out var v) ? string.Join(",", v) : null;
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
