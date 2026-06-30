namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Workflows.Models;

public partial class PacketAnalysisWorkflow
{
    private const int DnsTunnelThreshold = 4;

    /// <summary>
    /// Hunts DNS tunnelling / DNS-tunnelled C2 — the FOR501.2 flagship lab where a command shell is smuggled over
    /// port 53. Extracts every DNS query name, groups them by registered (parent) domain, and scores each domain
    /// for the tunnelling tells: a high volume of unique subdomains (data carried in the labels), abnormally long
    /// labels, high-entropy (encoded/encrypted) labels, and use of tunnel-friendly record types (TXT/NULL).
    /// Returns the domains scored suspicious.
    /// </summary>
    /// <param name="pcap">Path to the capture file.</param>
    public async Task<WorkflowResult<DnsTunnelingReport>> HuntDnsTunnelingAsync(string pcap)
    {
        using var _audit = AuditScope();
        using var op = Begin("Hunting DNS tunneling in {0}", pcap);

        var rows = (await PacketAnalysis.FieldsAsync(pcap, "dns.flags.response==0", ["dns.qry.name", "dns.qry.type"])).Result;
        if (rows is null)
            return WorkflowResult<DnsTunnelingReport>.Failure(
                $"Could not read DNS queries from '{pcap}'; the path may be wrong or the file not a capture.");

        var queries = rows.Where(r => r.Length >= 1 && r[0].Length > 0)
            .Select(r => (Name: r[0], Type: r.Length > 1 ? r[1] : "")).ToArray();

        // Group by registered (last-two-label) parent domain.
        var byDomain = queries.GroupBy(q => ParentDomain(q.Name));
        var findings = new List<DnsDomainFinding>();
        foreach (var g in byDomain)
        {
            var subs = g.Select(q => SubLabels(q.Name)).Where(s => s.Length > 0).ToArray();
            if (subs.Length == 0) continue;
            int uniqueSubs = subs.Distinct().Count();
            int maxLabel = subs.SelectMany(s => s.Split('.')).Select(l => l.Length).DefaultIfEmpty(0).Max();
            double avgEntropy = subs.Select(ShannonEntropy).DefaultIfEmpty(0).Average();
            var rareTypes = g.Select(q => TypeName(q.Type)).Where(t => t is "TXT" or "NULL" or "CNAME").Distinct().ToArray();

            int score = 0; var reasons = new List<string>();
            if (uniqueSubs >= 20) { score += 3; reasons.Add($"{uniqueSubs} unique subdomains (data in labels)"); }
            else if (uniqueSubs >= 8) { score += 1; reasons.Add($"{uniqueSubs} unique subdomains"); }
            if (maxLabel >= 40) { score += 2; reasons.Add($"long DNS label ({maxLabel} chars)"); }
            if (avgEntropy >= 3.5) { score += 2; reasons.Add($"high-entropy labels ({avgEntropy:0.0} bits/char)"); }
            if (rareTypes.Contains("TXT") || rareTypes.Contains("NULL")) { score += 3; reasons.Add($"tunnel-friendly record type(s): {string.Join("/", rareTypes)}"); }
            if (g.Count() >= 100) { score += 1; reasons.Add($"{g.Count()} queries"); }

            if (score > 0)
                findings.Add(new DnsDomainFinding
                {
                    Domain = g.Key, QueryCount = g.Count(), UniqueSubdomains = uniqueSubs,
                    MaxLabelLength = maxLabel, AvgEntropy = Math.Round(avgEntropy, 2),
                    RareTypes = rareTypes, Score = score, Reasons = reasons.ToArray(),
                });
        }

        var suspicious = findings.Where(f => f.Score >= DnsTunnelThreshold).OrderByDescending(f => f.Score).ToArray();
        op.Complete();
        var report = new DnsTunnelingReport
        {
            TotalQueries = queries.Length,
            UniqueDomains = byDomain.Count(),
            SuspiciousDomains = suspicious,
        };
        return WorkflowResult<DnsTunnelingReport>.Success(report,
            $"{queries.Length} DNS query/queries across {report.UniqueDomains} domain(s); " +
            (suspicious.Length == 0
                ? "no tunnelling indicators."
                : $"{suspicious.Length} suspicious domain(s): " +
                  string.Join("; ", suspicious.Take(3).Select(d => $"{d.Domain} (score {d.Score}: {string.Join(", ", d.Reasons)})")) + "."));
    }

    // Registered (parent) domain heuristic: the last two labels. Good enough for triage (co.uk etc. excepted).
    private static string ParentDomain(string name)
    {
        var labels = name.TrimEnd('.').Split('.');
        return labels.Length <= 2 ? name.TrimEnd('.') : string.Join('.', labels[^2..]);
    }

    // The subdomain labels (everything left of the parent domain).
    private static string SubLabels(string name)
    {
        var labels = name.TrimEnd('.').Split('.');
        return labels.Length <= 2 ? "" : string.Join('.', labels[..^2]);
    }

    private static string TypeName(string t) => t switch
    {
        "1" => "A", "2" => "NS", "5" => "CNAME", "6" => "SOA", "10" => "NULL", "12" => "PTR",
        "15" => "MX", "16" => "TXT", "28" => "AAAA", "33" => "SRV", "255" => "ANY", "257" => "CAA",
        _ => t,
    };
}
