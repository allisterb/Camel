namespace Camel.Tests.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Intel;

/// <summary>
/// Offline tests for the Shodan facade — the first TARGET-KEYED knowledge base. Covers the response mapping and,
/// crucially, the two-gate fork: a host lookup must be in engagement scope AND the engagement must permit external
/// disclosure (since the lookup sends a client IP to a third party). HTTP is faked; the gates are exercised against
/// a real LocalEnvironment engagement.
/// </summary>
public class ShodanTests
{
    const string ShodanSample = """
    {
      "ip_str": "203.0.113.5",
      "ports": [22, 443],
      "hostnames": ["host.example.com"],
      "org": "Example Org", "isp": "Example ISP", "os": null, "country_name": "Nowhere",
      "data": [
        { "port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.2p1", "data": "SSH-2.0-OpenSSH_8.2p1" },
        { "port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0", "data": "HTTP/1.1 200 OK" }
      ],
      "vulns": ["CVE-2021-28041"]
    }
    """;

    static IConfigurationRoot ShodanConfig() =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["KnowledgeBases:shodan:BaseUrl"] = "https://api.shodan.io/",
            ["KnowledgeBases:shodan:Auth"] = "QueryParam",
            ["KnowledgeBases:shodan:AuthName"] = "key",
            ["KnowledgeBases:shodan:KeyRef"] = "SHODAN_API_KEY",
            ["KnowledgeBases:shodan:DisclosesTarget"] = "true",
        }).Build();

    // A LocalEnvironment with an engagement authorizing 203.0.113.0/24; disclosure per the flag.
    static LocalEnvironment Armed(bool allowDisclosure)
    {
        var env = new LocalEnvironment();
        env.TrySetEngagement(new EngagementInfo("eng-s", "Acme", "A", "RoE",
            DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(1),
            [new ScopeTarget(ScopeKind.Cidr, "203.0.113.0/24")], AllowExternalTargetDisclosure: allowDisclosure));
        return env;
    }

    static ShodanKnowledgeBase Shodan(LocalEnvironment env, FakeHandler handler) =>
        new(new KnowledgeBaseClient(ShodanConfig(), new FakeSecrets(("SHODAN_API_KEY", "K")), new HttpClient(handler)),
            env);

    #region Mapping
    [Fact]
    public void MapHost_ParsesPortsServicesAndVulns()
    {
        using var doc = System.Text.Json.JsonDocument.Parse(ShodanSample);
        var host = ShodanKnowledgeBase.MapHost(doc.RootElement);

        Assert.Equal("203.0.113.5", host.IpStr);
        Assert.Equal([22, 443], host.Ports);
        Assert.Equal("Example Org", host.Org);
        Assert.Null(host.Os);
        Assert.Equal(2, host.Services.Length);
        Assert.Equal("OpenSSH", host.Services.First(s => s.Port == 22).Product);
        Assert.Contains("CVE-2021-28041", host.Vulns);
    }
    #endregion

    #region The two-gate fork
    [Fact]
    public async Task Host_InScopeAndDisclosureAllowed_Succeeds()
    {
        var handler = new FakeHandler(ShodanSample);
        var r = await Shodan(Armed(allowDisclosure: true), handler).HostAsync("203.0.113.5");

        Assert.True(r.Ok);
        Assert.Equal("shodan", r.Source);
        Assert.Equal("203.0.113.5", r.Result!.IpStr);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Host_DisclosureForbidden_Throws_AndNeverCallsOut()
    {
        var handler = new FakeHandler(ShodanSample);
        var shodan = Shodan(Armed(allowDisclosure: false), handler);   // in scope, but disclosure NOT permitted

        await Assert.ThrowsAsync<ExternalDisclosureForbiddenException>(() => shodan.HostAsync("203.0.113.5"));
        Assert.Equal(0, handler.Calls);                                // the client IP never left the machine
    }

    [Fact]
    public async Task Host_OutOfScope_Throws_BeforeDisclosureCheck()
    {
        var handler = new FakeHandler(ShodanSample);
        // Disclosure allowed, but the target is outside the authorized range: scope is checked first.
        await Assert.ThrowsAsync<OutOfScopeException>(() => Shodan(Armed(allowDisclosure: true), handler).HostAsync("198.51.100.9"));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task Host_NoEngagement_Throws()
    {
        var handler = new FakeHandler(ShodanSample);
        await Assert.ThrowsAsync<EngagementRequiredException>(() => Shodan(new LocalEnvironment(), handler).HostAsync("203.0.113.5"));
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
