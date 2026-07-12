using System;
using System.Linq;
using System.Text;

using Camel.Environments;
using Camel.Workflows;
using Camel.DFIR.Workflows;

namespace Camel.Tests.Workflows;

/// <summary>
/// Exercises <see cref="PacketAnalysisWorkflow"/> against the DFRWS-2008 challenge capture on the SIFT
/// workstation (normal-then-suspicious HTTP browsing that trips ET IDS rules).
/// </summary>
public class PacketAnalysisWorkflowTests : TestsRuntime, IDisposable
{
    public PacketAnalysisWorkflowTests()
    {
        var sshconfig = EnsureSIFT(LoadConfigFile("sshtestappsettings.json"));
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelToolkitsApi(sshenv, sshconfig);
        workflow = new PacketAnalysisWorkflow(api);
    }

    const string Pcap = "/home/sansforensics/artifacts/dfrws2008/suspect.pcap";
    readonly string outDir = "/tmp/camel_pkt_wf_" + Guid.NewGuid().ToString("N");

    [Fact]
    public async Task TriagesCapture()
    {
        var r = await workflow.TriagePcapAsync(Pcap);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal(10243, r.Result!.Info!.PacketCount);
        Assert.Contains(r.Result.ProtocolHierarchy, p => p.Protocol == "http");
        Assert.Contains(r.Result.TopEndpoints, e => e.Address == "192.168.151.130");
        Assert.NotEmpty(r.Result.TopHttpHosts);
    }

    [Fact]
    public async Task HuntsDnsTunneling()
    {
        var r = await workflow.HuntDnsTunnelingAsync(Pcap);
        Assert.True(r.IsSuccess, r.Message);
        // The capture has ordinary DNS browsing — queries parse, no tunnelling indicators expected.
        Assert.True(r.Result!.TotalQueries > 0);
        Assert.True(r.Result.UniqueDomains > 0);
    }

    [Fact]
    public async Task FlagsDnsTunneling()
    {
        // Synthesize the book's DNS-backdoor scenario: many queries for long, high-entropy subdomains of one
        // parent domain (data smuggled in the labels). Capture the real DNS query packets on loopback.
        var tunnel = "/tmp/camel_dnstunnel_" + Guid.NewGuid().ToString("N") + ".pcap";
        var script = $$"""
            F={{tunnel}}
            sudo rm -f "$F"
            sudo timeout 14 tcpdump -i lo -w "$F" udp port 53 >/dev/null 2>&1 &
            TP=$!
            sleep 1
            for i in $(seq 1 30); do
              sub=$(head -c 30 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z')
              dig +tries=1 +time=1 ${sub}.tunnel-test.example @127.0.0.53 >/dev/null 2>&1
            done
            sleep 1; sudo kill $TP 2>/dev/null; wait $TP 2>/dev/null
            sudo chown $(id -un) "$F"
            """;
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(script.Replace("\r\n", "\n")));
        sshenv.ExecuteCommand("bash", $"-c \"echo {b64} | base64 -d | bash\"", out _, false);
        try
        {
            var r = await workflow.HuntDnsTunnelingAsync(tunnel);
            Assert.True(r.IsSuccess, r.Message);
            var dom = r.Result!.SuspiciousDomains.FirstOrDefault(d => d.Domain == "tunnel-test.example");
            Assert.NotNull(dom);
            Assert.True(dom!.UniqueSubdomains >= 20);
            Assert.True(dom.MaxLabelLength >= 40);
        }
        finally { sshenv.ExecuteCommand("rm", $"-f {tunnel}", out _, false); }
    }

    [Fact]
    public async Task ExtractsHttpObjects()
    {
        var r = await workflow.ExtractHttpObjectsAsync(Pcap, outDir);
        Assert.True(r.IsSuccess, r.Message);
        Assert.NotEmpty(r.Result!.Transactions);
        Assert.Contains(r.Result.Transactions, t => t.Method == "GET");
    }

    [Fact]
    public async Task FollowsStream()
    {
        var r = await workflow.FollowStreamAsync(Pcap, "tcp", 0);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Contains("GET", r.Result!.Content);
    }

    [Fact]
    public async Task FingerprintsHosts()
    {
        var r = await workflow.FingerprintHostsAsync(Pcap);
        Assert.True(r.IsSuccess, r.Message);
        Assert.NotEmpty(r.Result!.Hosts);
        Assert.Contains(r.Result.Hosts, h => h.OsGuesses.Any(o => o.Contains("Linux")));
    }

    [Fact]
    public async Task DetectsBeaconingRunsClean()
    {
        // No assertion on positives (the fixture isn't a beacon capture) — the timing analysis must complete.
        var r = await workflow.DetectBeaconingAsync(Pcap);
        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
    }

    [Fact]
    public async Task ExtractsCredentialsRunsClean()
    {
        var r = await workflow.ExtractCredentialsAsync(Pcap);
        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
    }

    [Fact]
    public async Task RunsSuricataIds()
    {
        var r = await workflow.RunIdsAsync(Pcap, outDir + "_ids");
        Assert.True(r.IsSuccess, r.Message);
        // DFRWS-2008 trips multiple ET rules.
        Assert.True(r.Result!.AlertCount > 0);
        Assert.NotEmpty(r.Result.BySignature);
    }

    public void Dispose()
    {
        sshenv.ExecuteCommand("rm", $"-rf {outDir} {outDir}_ids", out _, false);
    }

    AuditEnvironment sshenv;
    CamelToolkitsApi api;
    PacketAnalysisWorkflow workflow;
}
