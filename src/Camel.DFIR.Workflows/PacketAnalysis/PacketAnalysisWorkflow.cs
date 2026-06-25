namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

/// <summary>
/// Workflows for analysing a network capture (pcap/pcapng) for intrusion evidence, codifying the SANS FOR501.2
/// "Packet Analysis" methodology over <see cref="PacketAnalysisToolkit"/>. They add the analysis/scoring layer:
/// what is this capture, which flows matter, what was transferred, and which traffic is a tunnel / beacon / IDS
/// hit.
/// <list type="bullet">
/// <item><see cref="TriagePcapAsync"/> — capture overview (metadata, protocol mix, top talkers, busiest hosts).</item>
/// <item><see cref="FollowStreamAsync"/> — reassemble one stream with credential/keyword highlights.</item>
/// <item><see cref="HuntDnsTunnelingAsync"/> — DNS-tunnel / DNS-backdoor detection (the book's flagship lab).</item>
/// <item><see cref="ExtractHttpObjectsAsync"/> — carve transferred HTTP objects + list requests.</item>
/// <item><see cref="ExtractCredentialsAsync"/> — harvest cleartext credentials.</item>
/// <item><see cref="DetectBeaconingAsync"/> — timing-based C2-beacon detection.</item>
/// <item><see cref="FingerprintHostsAsync"/> — passive OS fingerprinting (p0f).</item>
/// <item><see cref="RunIdsAsync"/> — Suricata signature IDS (the maintained Snort analog).</item>
/// </list>
/// </summary>
public partial class PacketAnalysisWorkflow : Workflow
{
    public PacketAnalysisWorkflow(CamelToolkitsApi api) : base(api) { }

    /// <summary>
    /// Triages a capture in one call: file metadata (capinfos), the protocol-hierarchy mix, the top conversations
    /// and endpoints by volume, and the busiest DNS query names and HTTP hosts. The "what is this capture and who
    /// is talking to whom" entry point; drill into specifics with the targeted workflows.
    /// </summary>
    /// <param name="pcap">Path to the capture file on the workstation / mounted volume.</param>
    /// <param name="top">How many top conversations/endpoints/hosts to return (default 20).</param>
    public async Task<WorkflowResult<PcapTriageReport>> TriagePcapAsync(string pcap, int top = 20)
    {
        using var _audit = AuditScope();
        using var op = Begin("Triaging capture {0}", pcap);

        var infoT = PacketAnalysis.CapInfoAsync(pcap);
        var phsT = PacketAnalysis.ProtocolHierarchyAsync(pcap);
        var convT = PacketAnalysis.ConversationsAsync(pcap, "tcp");
        var epT = PacketAnalysis.EndpointsAsync(pcap, "ip");
        var dnsT = PacketAnalysis.FieldsAsync(pcap, "dns.flags.response==0", ["dns.qry.name"]);
        var httpT = PacketAnalysis.FieldsAsync(pcap, "http.request", ["http.host"]);
        await Task.WhenAll(infoT, phsT, convT, epT, dnsT, httpT);

        var info = infoT.Result; var phs = phsT.Result;
        if (info is null && phs is null)
            return WorkflowResult<PcapTriageReport>.Failure(
                $"Could not read capture '{pcap}'; the path may be wrong, the file not a capture, or the volume not mounted.");

        var topConvs = (convT.Result ?? []).OrderByDescending(c => c.TotalBytes).Take(top).ToArray();
        var topEps = (epT.Result ?? []).OrderByDescending(e => e.Bytes).Take(top).ToArray();
        var topDns = TopNames(dnsT.Result, top);
        var topHttp = TopNames(httpT.Result, top);

        op.Complete();
        var report = new PcapTriageReport
        {
            Info = info,
            ProtocolHierarchy = phs ?? [],
            TopConversations = topConvs,
            TopEndpoints = topEps,
            TopDnsQueries = topDns,
            TopHttpHosts = topHttp,
        };
        return WorkflowResult<PcapTriageReport>.Success(report,
            $"Capture '{pcap}': {info?.PacketCount ?? 0} packets over {info?.DurationSeconds ?? 0:0}s, " +
            $"{topEps.Length} top host(s), {topConvs.Length} top flow(s). " +
            $"Protocols: {string.Join(", ", (phs ?? []).Where(p => p.Depth <= 2).OrderByDescending(p => p.Frames).Take(6).Select(p => p.Protocol))}. " +
            (topDns.Length == 0 ? "" : $"Top DNS: {string.Join(", ", topDns.Take(3).Select(d => d.Name))}. ") +
            (topHttp.Length == 0 ? "" : $"Top HTTP host: {topHttp.FirstOrDefault()?.Name}."));
    }

    #region Shared helpers
    // Count occurrences of the first field across rows (dropping empties) and return the top N as NameCounts.
    private protected static NameCount[] TopNames(string[][]? rows, int top) =>
        (rows ?? [])
            .Select(r => r.Length > 0 ? r[0] : "")
            .Where(s => !string.IsNullOrEmpty(s))
            .GroupBy(s => s)
            .Select(g => new NameCount { Name = g.Key, Count = g.Count() })
            .OrderByDescending(n => n.Count).ThenBy(n => n.Name)
            .Take(top).ToArray();

    // Shannon entropy (bits/char) of a string — high values flag encoded/encrypted DNS labels.
    private protected static double ShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var freq = s.GroupBy(c => c).Select(g => (double)g.Count() / s.Length);
        return -freq.Sum(p => p * Math.Log2(p));
    }

    private protected static string Truncate(string? s, int max) =>
        s is null ? "" : s.Length <= max ? s : s[..max] + "…";
    #endregion
}
