namespace Camel.Tests.Intel;

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;

using Camel.Intel;

/// <summary>
/// Offline tests for the two keyless knowledge KBs added alongside NVD: CISA KEV (known-exploited catalog) and
/// FIRST.org EPSS (exploit-probability scores). Both are knowledge-class (no engagement gate); HTTP is faked.
/// </summary>
public class KevEpssTests
{
    const string KevSample = """
    {
      "title": "CISA KEV", "catalogVersion": "2024.01.01", "count": 2,
      "vulnerabilities": [
        { "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
          "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10",
          "shortDescription": "JNDI RCE.", "requiredAction": "Apply updates.", "dueDate": "2021-12-24",
          "knownRansomwareCampaignUse": "Known" },
        { "cveID": "CVE-2020-1472", "vendorProject": "Microsoft", "product": "Netlogon",
          "vulnerabilityName": "Zerologon", "dateAdded": "2020-11-03",
          "shortDescription": "Privilege escalation.", "requiredAction": "Apply updates.", "dueDate": "2020-11-17",
          "knownRansomwareCampaignUse": "Unknown" }
      ]
    }
    """;

    const string EpssSample = """
    { "status": "OK", "status-code": 200, "version": "1.0", "total": 1,
      "data": [ { "cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99998", "date": "2024-06-01" } ] }
    """;

    static IConfigurationRoot Config(string source, string baseUrl, int cache = 1440) =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"KnowledgeBases:{source}:BaseUrl"] = baseUrl,
            [$"KnowledgeBases:{source}:Auth"] = "None",
            [$"KnowledgeBases:{source}:CacheTtlMinutes"] = cache.ToString(),
        }).Build();

    #region CISA KEV
    [Fact]
    public void Kev_MapAll_ParsesEntriesAndRansomwareFlag()
    {
        using var doc = System.Text.Json.JsonDocument.Parse(KevSample);
        var entries = KevKnowledgeBase.MapAll(doc.RootElement);
        Assert.Equal(2, entries.Length);
        var log4shell = entries.Single(e => e.CveId == "CVE-2021-44228");
        Assert.Equal("Log4Shell", log4shell.VulnerabilityName);
        Assert.True(log4shell.KnownRansomwareUse);
        Assert.False(entries.Single(e => e.CveId == "CVE-2020-1472").KnownRansomwareUse);
    }

    [Fact]
    public async Task Kev_IsKnownExploited_TrueForListed_FalseForOther_OneFetch()
    {
        var handler = new FakeHandler(KevSample);
        var kev = new KevKnowledgeBase(new KnowledgeBaseClient(
            Config("cisa-kev", "https://www.cisa.gov/sites/default/files/feeds/"), http: new HttpClient(handler)));

        var listed = await kev.IsKnownExploitedAsync("CVE-2021-44228");
        var notListed = await kev.IsKnownExploitedAsync("CVE-1999-0001");

        Assert.True(listed.Ok);
        Assert.True(listed.Result);
        Assert.True(notListed.Ok);            // a successful "no", not a failure
        Assert.False(notListed.Result);
        Assert.Equal(1, handler.Calls);       // the whole catalog is fetched once, then re-filtered from cache
    }

    [Fact]
    public async Task Kev_Entry_ReturnsZeroOrOne()
    {
        var handler = new FakeHandler(KevSample);
        var kev = new KevKnowledgeBase(new KnowledgeBaseClient(
            Config("cisa-kev", "https://www.cisa.gov/sites/default/files/feeds/"), http: new HttpClient(handler)));

        Assert.Single((await kev.EntryAsync("CVE-2020-1472")).Result!);
        Assert.Empty((await kev.EntryAsync("CVE-1999-0001")).Result!);
    }
    #endregion

    #region EPSS
    [Fact]
    public async Task Epss_Score_ParsesProbabilityAndPercentile()
    {
        var handler = new FakeHandler(EpssSample);
        var epss = new EpssKnowledgeBase(new KnowledgeBaseClient(
            Config("epss", "https://api.first.org/data/v1/"), http: new HttpClient(handler)));

        var r = await epss.ScoreAsync("CVE-2021-44228");

        Assert.True(r.Ok);
        var s = r.Result!.Single();
        Assert.Equal("CVE-2021-44228", s.CveId);
        Assert.Equal(0.97565, s.Epss, 5);
        Assert.Equal(0.99998, s.Percentile, 5);
        Assert.Contains("cve=CVE-2021-44228", handler.LastUrl);
    }
    #endregion

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
}
