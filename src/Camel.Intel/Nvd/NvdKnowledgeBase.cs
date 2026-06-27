namespace Camel.Intel;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

/// <summary>
/// Typed facade over the NIST National Vulnerability Database (NVD) CVE API 2.0 — a <b>knowledge</b> source (no
/// engagement target, so no scope/disclosure gate). Maps responses to <see cref="CveRecord"/>[] wrapped in the
/// <see cref="KbResult{T}"/> provenance envelope. Configured under <c>KnowledgeBases:nvd</c>; an API key
/// (<c>NVD_API_KEY</c>) is optional and only raises the rate limit.
/// </summary>
public class NvdKnowledgeBase
{
    private const string Source = "nvd";
    private const string Path = "cves/2.0";

    private readonly KnowledgeBaseClient client;

    public NvdKnowledgeBase(KnowledgeBaseClient client) => this.client = client;

    /// <summary>
    /// CVEs matching a product (and optional version) via NVD keyword search — e.g.
    /// <c>CvesForProductAsync("openssh", "8.2p1")</c>. A version-banner match is a LEAD, not confirmed
    /// exploitability (banners lie, vendors backport). Returns up to 50 records, newest-relevance first.
    /// </summary>
    public Task<KbResult<CveRecord[]>> CvesForProductAsync(string product, string? version = null)
    {
        var keyword = string.IsNullOrWhiteSpace(version) ? product : $"{product} {version}";
        return client.QueryAsync(Source, Path,
            new Dictionary<string, string> { ["keywordSearch"] = keyword, ["resultsPerPage"] = "50" },
            MapCves);
    }

    /// <summary>Look up a single CVE by id (e.g. <c>CVE-2020-15778</c>). Returns a one-element array, or empty.</summary>
    public Task<KbResult<CveRecord[]>> CveAsync(string cveId) =>
        client.QueryAsync(Source, Path, new Dictionary<string, string> { ["cveId"] = cveId }, MapCves);

    // Maps an NVD CVE-API 2.0 response (root.vulnerabilities[].cve) to CveRecord[]. Tolerant of missing fields.
    internal static CveRecord[] MapCves(JsonElement root)
    {
        if (!root.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            return [];
        var list = new List<CveRecord>();
        foreach (var v in vulns.EnumerateArray())
        {
            if (!v.TryGetProperty("cve", out var cve)) continue;
            var (score, vector) = BestCvss(cve);
            list.Add(new CveRecord(
                Id: Str(cve, "id"),
                Cvss: score,
                CvssVector: vector,
                Summary: EnglishDescription(cve),
                Published: Date(cve, "published"),
                LastModified: Date(cve, "lastModified"),
                References: cve.TryGetProperty("references", out var refs) && refs.ValueKind == JsonValueKind.Array
                    ? refs.EnumerateArray().Select(r => Str(r, "url")).Where(s => s.Length > 0).ToArray()
                    : []));
        }
        return list.ToArray();
    }

    // The English description from cve.descriptions[].
    private static string EnglishDescription(JsonElement cve)
    {
        if (!cve.TryGetProperty("descriptions", out var d) || d.ValueKind != JsonValueKind.Array) return "";
        var en = d.EnumerateArray().FirstOrDefault(x => Str(x, "lang") == "en");
        return en.ValueKind == JsonValueKind.Object ? Str(en, "value")
             : d.EnumerateArray().Select(x => Str(x, "value")).FirstOrDefault(s => s.Length > 0) ?? "";
    }

    // Best available CVSS base score + vector, preferring v3.1 -> v3.0 -> v2.
    private static (double?, string) BestCvss(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var m) || m.ValueKind != JsonValueKind.Object) return (null, "");
        foreach (var key in new[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
        {
            if (m.TryGetProperty(key, out var arr) && arr.ValueKind == JsonValueKind.Array
                && arr.EnumerateArray().FirstOrDefault() is { ValueKind: JsonValueKind.Object } first
                && first.TryGetProperty("cvssData", out var data))
            {
                double? score = data.TryGetProperty("baseScore", out var s) && s.ValueKind == JsonValueKind.Number
                    ? s.GetDouble() : null;
                return (score, Str(data, "vectorString"));
            }
        }
        return (null, "");
    }

    private static string Str(JsonElement e, string prop) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "" : "";

    private static DateTime? Date(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            && DateTime.TryParse(v.GetString(), CultureInfo.InvariantCulture,
                                 DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt)
            ? dt : null;
}
