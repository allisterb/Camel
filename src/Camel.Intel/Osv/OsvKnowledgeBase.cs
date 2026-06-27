namespace Camel.Intel;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

/// <summary>One vulnerability from the OSV.dev database (a package/version match).</summary>
/// <param name="Id">The OSV id (e.g. "GHSA-..." or "OSV-...").</param>
/// <param name="Summary">Short summary, or "".</param>
/// <param name="Details">Longer details, or "".</param>
/// <param name="Aliases">Alias ids — typically the CVE id(s) for this vuln.</param>
/// <param name="Severity">A CVSS vector/score string from OSV's severity[], or "".</param>
public record OsvVuln(string Id, string Summary, string Details, string[] Aliases, string Severity);

/// <summary>
/// Typed facade over the OSV.dev API — a keyless <b>knowledge</b> source queried by <b>HTTP POST</b> (a body
/// describes the package/version). Best for software-dependency vulnerabilities (npm, PyPI, Go, Maven, …) — e.g.
/// enriching a discovered web app's dependencies. Demonstrates the client's POST transport. Configured under
/// <c>KnowledgeBases:osv</c>.
/// </summary>
public class OsvKnowledgeBase
{
    private const string Source = "osv";

    private readonly KnowledgeBaseClient client;

    public OsvKnowledgeBase(KnowledgeBaseClient client) => this.client = client;

    /// <summary>
    /// Vulnerabilities affecting <paramref name="name"/> in <paramref name="ecosystem"/> (e.g. "PyPI", "npm",
    /// "Go", "Debian"), optionally at <paramref name="version"/> (omit to get all known vulns for the package).
    /// </summary>
    public Task<KbResult<OsvVuln[]>> QueryPackageAsync(string ecosystem, string name, string? version = null)
    {
        var pkg = $"\"package\":{{\"name\":{J(name)},\"ecosystem\":{J(ecosystem)}}}";
        var body = version is null ? $"{{{pkg}}}" : $"{{\"version\":{J(version)},{pkg}}}";
        return client.QueryPostAsync(Source, "v1/query", body, MapVulns);
    }

    internal static OsvVuln[] MapVulns(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("vulns", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            return [];
        return vulns.EnumerateArray().Select(v => new OsvVuln(
            Id: Str(v, "id"),
            Summary: Str(v, "summary"),
            Details: Str(v, "details"),
            Aliases: v.TryGetProperty("aliases", out var a) && a.ValueKind == JsonValueKind.Array
                ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToArray()
                : [],
            Severity: v.TryGetProperty("severity", out var s) && s.ValueKind == JsonValueKind.Array
                ? s.EnumerateArray().Select(x => Str(x, "score")).FirstOrDefault(x => x.Length > 0) ?? ""
                : "")).ToArray();
    }

    private static string Str(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    // JSON-escape a string into a quoted JSON literal (handles quotes/backslashes safely for the request body).
    private static string J(string s) => JsonSerializer.Serialize(s);
}
