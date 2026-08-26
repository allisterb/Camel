namespace Camel.Reporting.Model;

using System.Globalization;

/// <summary>A <c>vulnerability</c> CLEF event projected to the fields the report card + finding detail render
/// (see <c>CamelMCPTools.AuditVulnerability</c>). The red per-finding record: a scored, remediable weakness with its
/// evidence trail, as opposed to the narrative <c>finding</c> events.</summary>
public sealed record VulnerabilityView(
    string Title, string Severity, string Cvss, string AffectedAsset, string Description,
    string Remediation, string References, string EvidenceExecutionIds, string ExecutionId, DateTimeOffset? Time)
{
    /// <summary>Normalized severity band, lower-cased (mirrors the viewer's <c>sevOf</c>): one of
    /// critical/high/medium/low/info, or "unknown".</summary>
    public string Band => string.IsNullOrWhiteSpace(Severity) ? "unknown" : Severity.Trim().ToLowerInvariant();

    /// <summary>Parsed CVSS score, or -1 when absent/unparseable (mirrors the viewer's <c>cvssOf</c>).</summary>
    public double CvssScore =>
        double.TryParse(Cvss, NumberStyles.Float, CultureInfo.InvariantCulture, out var n) ? n : -1;

    public static VulnerabilityView From(AuditEvent e) => new(
        Title: e.Get("Title") ?? "",
        Severity: e.Get("Severity") ?? "",
        Cvss: e.Get("Cvss") ?? "",
        AffectedAsset: e.Get("AffectedAsset") ?? "",
        Description: e.Get("Description") ?? "",
        Remediation: e.Get("Remediation") ?? "",
        References: e.Get("References") ?? "",
        EvidenceExecutionIds: e.Get("EvidenceExecutionIds") ?? "",
        ExecutionId: e.ExecutionId,
        Time: e.Timestamp);
}

/// <summary>The compliance attestation aggregate — the STAR-analog headline computed from the CLEF event tallies
/// (mirrors the viewer's <c>renderAttestation</c>). Every out-of-scope refusal is the fail-closed gate turned into
/// positive proof; a waiver is residual risk to flag.</summary>
public sealed record ComplianceAttestation(
    int ScopeViolations, int Waivers, int Disclosures, int EngagementEvents)
{
    /// <summary>True when a waiver rode on the operator's attestation with no document — surfaced as residual risk.</summary>
    public bool HasResidualRisk => Waivers > 0;
}

/// <summary>
/// The single C# home for the report aggregation that the interactive viewer computes in <c>report.js</c>
/// (<c>renderReportCard</c> / <c>renderAttestation</c> / <c>vulnerabilityEvents</c>). Kept here deliberately so the
/// PDF and the HTML agree on the numbers; a follow-up can have the bake emit these as a sidecar the JS renders,
/// making this the sole source and eliminating the JS/C# drift risk.
/// </summary>
public static class ReportAggregates
{
    // Severity band → sort rank (mirrors report.js SEV_ORDER); the report card bands (mirrors SEV_CLASSES).
    private static readonly Dictionary<string, int> SevOrder = new(StringComparer.OrdinalIgnoreCase)
        { ["critical"] = 0, ["high"] = 1, ["medium"] = 2, ["low"] = 3, ["info"] = 4, ["unknown"] = 5 };

    /// <summary>The report-card severity bands, most-severe first.</summary>
    public static readonly string[] SeverityBands = ["critical", "high", "medium", "low", "info"];

    /// <summary>All <c>vulnerability</c> events, ranked most-critical-first: severity band, then CVSS descending, then
    /// time (mirrors <c>vulnerabilityEvents</c>).</summary>
    public static IReadOnlyList<VulnerabilityView> Vulnerabilities(IEnumerable<AuditEvent> events)
    {
        var vulns = events.Where(e => e.EventType == "vulnerability").Select(VulnerabilityView.From).ToList();
        vulns.Sort((a, b) =>
        {
            int sa = SevOrder.GetValueOrDefault(a.Band, 5), sb = SevOrder.GetValueOrDefault(b.Band, 5);
            if (sa != sb) return sa - sb;
            int cv = b.CvssScore.CompareTo(a.CvssScore);
            if (cv != 0) return cv;
            return Nullable.Compare(a.Time, b.Time);
        });
        return vulns;
    }

    /// <summary>Per-band counts for the severity report card. A severity that is not one of the five known bands is
    /// counted as <c>info</c> (mirrors <c>renderReportCard</c>'s <c>else counts.info++</c>).</summary>
    public static IReadOnlyDictionary<string, int> SeverityCounts(IEnumerable<VulnerabilityView> vulns)
    {
        var counts = SeverityBands.ToDictionary(b => b, _ => 0);
        foreach (var v in vulns)
        {
            var band = counts.ContainsKey(v.Band) ? v.Band : "info";
            counts[band]++;
        }
        return counts;
    }

    /// <summary>The compliance attestation tallies (mirrors <c>renderAttestation</c>): gate refusals recorded as
    /// <c>scope-violation</c> (an out-of-scope target/range, OR a client asset the engagement would not permit
    /// disclosing to a third party — the reason line distinguishes them), authorization waivers, external + KB
    /// disclosures, and engagement registration events.</summary>
    public static ComplianceAttestation Attestation(IEnumerable<AuditEvent> events)
    {
        var list = events as IReadOnlyCollection<AuditEvent> ?? events.ToList();
        int Count(string t) => list.Count(e => e.EventType == t);
        return new ComplianceAttestation(
            ScopeViolations: Count("scope-violation"),
            Waivers: Count("authorization-waiver"),
            Disclosures: Count("external-disclosure") + Count("kb-disclosure"),
            EngagementEvents: Count("engagement"));
    }
}
