using System;
using System.Linq;

using Camel.Environments;
using Camel.Toolkits;
using Camel.DFIR.Toolkits;

namespace Camel.Tests.Toolkits;

/// <summary>
/// Exercises <see cref="PacketAnalysisToolkit"/> against the DFRWS-2008 challenge capture on the SIFT workstation.
/// The toolkit constructor auto-provisions tshark + suricata if missing (already present on this box).
/// </summary>
public class PacketAnalysisTests : TestsRuntime
{
    public PacketAnalysisTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new PacketAnalysisToolkit(sshenv, sshconfig);
    }

    const string Pcap = "/home/sansforensics/artifacts/dfrws2008/suspect.pcap";

    [Fact]
    public void CanLoadAllToolsFromConfig()
    {
        Assert.Equal(toolkit.ToolList.Length, toolkit.Tools.Count);
        Assert.All(toolkit.ToolList, name =>
        {
            Assert.True(toolkit.Tools.ContainsKey(name));
            Assert.Contains("bin/", toolkit.Tools[name].Command);
            Assert.NotEmpty(toolkit.Tools[name].Descriptioon);
        });
    }

    [Fact]
    public async Task CanReadCapInfo()
    {
        var info = (await toolkit.CapInfoAsync(Pcap)).Value;
        Assert.NotNull(info);
        Assert.Equal(10243, info.PacketCount);
        Assert.Equal("d25912485704b46ba7e85431f589d8f530fa87b3b1e4686a9e3ce5628b162361", info.Sha256, ignoreCase: true);
        Assert.True(info.DurationSeconds > 3500 && info.DurationSeconds < 3600);
        Assert.NotNull(info.FirstPacketTime);
    }

    [Fact]
    public async Task CanProtocolHierarchy()
    {
        var phs = (await toolkit.ProtocolHierarchyAsync(Pcap)).Value;
        Assert.NotNull(phs);
        Assert.Contains(phs, p => p.Protocol == "eth" && p.Depth == 0 && p.Frames == 10243);
        Assert.Contains(phs, p => p.Protocol == "ip" && p.Depth == 1);
        Assert.Contains(phs, p => p.Protocol == "tcp");
        Assert.Contains(phs, p => p.Protocol == "http" && p.Frames > 0);
    }

    [Fact]
    public async Task CanConversations()
    {
        var convs = (await toolkit.ConversationsAsync(Pcap, "tcp")).Value;
        Assert.NotNull(convs);
        Assert.NotEmpty(convs);
        Assert.All(convs, c => Assert.True(c.TotalFrames > 0 && c.TotalBytes > 0));
        // The busiest flow is the host talking to 219.93.175.67:80.
        Assert.Contains(convs, c => (c.EndpointA.Contains("219.93.175.67") || c.EndpointB.Contains("219.93.175.67")));
    }

    [Fact]
    public async Task CanEndpoints()
    {
        var eps = (await toolkit.EndpointsAsync(Pcap, "ip")).Value;
        Assert.NotNull(eps);
        var host = eps.FirstOrDefault(e => e.Address == "192.168.151.130");
        Assert.NotNull(host);
        Assert.Equal(10127, host!.Packets);
        Assert.True(host.Bytes > 0 && host.TxPackets > 0 && host.RxPackets > 0);
    }

    [Fact]
    public async Task CanExtractDnsQueryNames()
    {
        var rows = (await toolkit.FieldsAsync(Pcap, "dns.flags.response==0", ["dns.qry.name", "dns.qry.type"])).Value;
        Assert.NotNull(rows);
        Assert.NotEmpty(rows);
        Assert.All(rows, r => Assert.Equal(2, r.Length));
        Assert.Contains(rows, r => r[0] == "travelocity.com");
    }

    [Fact]
    public async Task CanFollowStream()
    {
        var stream = (await toolkit.FollowStreamAsync(Pcap, "tcp", 0)).Value;
        Assert.NotNull(stream);
        Assert.Contains("GET", stream);
        // The banner is stripped — no "Node 1:" left in the body.
        Assert.DoesNotContain("Node 1:", stream);
    }

    [Fact]
    public async Task CanTcpTrace()
    {
        var conns = (await toolkit.TcpTraceAsync(Pcap)).Value;
        Assert.NotNull(conns);
        Assert.NotEmpty(conns);
        Assert.Contains(conns, c => c.HostA == "192.168.151.130" && c.PortB == 80 && c.PacketsAToB > 0);
    }

    [Fact]
    public async Task CanNgrep()
    {
        var matches = (await toolkit.NgrepAsync(Pcap, "GET", "tcp port 80")).Value;
        Assert.NotNull(matches);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Payload.Contains("GET") && m.Destination!.EndsWith(":80"));
    }

    [Fact]
    public async Task CanP0fFingerprint()
    {
        var fps = (await toolkit.P0fAsync(Pcap)).Value;
        Assert.NotNull(fps);
        Assert.NotEmpty(fps);
        Assert.Contains(fps, f => f.Os != null && f.Os.Contains("Linux"));
    }

    [Fact]
    public async Task CanRunSuricata()
    {
        var dir = "/tmp/camel_suri_" + Guid.NewGuid().ToString("N");
        try
        {
            var alerts = (await toolkit.SuricataAsync(Pcap, dir)).Value;
            Assert.NotNull(alerts);
            // DFRWS-2008 trips ET rules (Fake FireFox version, etc.).
            Assert.NotEmpty(alerts);
            Assert.All(alerts, a => Assert.False(string.IsNullOrWhiteSpace(a.Signature)));
        }
        finally { sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false); }
    }

    AuditEnvironment sshenv;
    PacketAnalysisToolkit toolkit;
}
