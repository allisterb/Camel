namespace Camel.Intel;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

/// <summary>
/// An EPSS (Exploit Prediction Scoring System, FIRST.org) score for a CVE: the model's estimated probability the
/// vulnerability will be exploited in the wild in the next 30 days, and its percentile rank among all CVEs.
/// </summary>
/// <param name="CveId">The CVE id.</param>
/// <param name="Epss">Probability of exploitation in the next 30 days (0.0-1.0).</param>
/// <param name="Percentile">Percentile rank of this score among all scored CVEs (0.0-1.0).</param>
/// <param name="Date">The score's date (EPSS is recomputed daily), or null.</param>
public record EpssScore(string CveId, double Epss, double Percentile, DateTime? Date);

/// <summary>
/// Typed facade over the FIRST.org EPSS API — a keyless <b>knowledge</b> source (no target, no gate). EPSS
/// complements CVSS (severity) and KEV (known-exploited yes/no) with a forward-looking <i>probability</i> of
/// exploitation, useful for ranking which exposed CVEs to prioritise. Configured under <c>KnowledgeBases:epss</c>.
/// </summary>
public class EpssKnowledgeBase
{
    private const string Source = "epss";
    private const string Path = "epss";

    private readonly KnowledgeBaseClient client;

    public EpssKnowledgeBase(KnowledgeBaseClient client) => this.client = client;

    /// <summary>The EPSS score for <paramref name="cveId"/> as a 0-or-1-element array (empty = no score published).</summary>
    public Task<KbResult<EpssScore[]>> ScoreAsync(string cveId) =>
        client.QueryAsync(Source, Path, new Dictionary<string, string> { ["cve"] = cveId }, MapScores);

    /// <summary>EPSS scores for several CVEs at once (FIRST.org accepts a comma-separated list).</summary>
    public Task<KbResult<EpssScore[]>> ScoresAsync(IEnumerable<string> cveIds) =>
        client.QueryAsync(Source, Path,
            new Dictionary<string, string> { ["cve"] = string.Join(",", cveIds) }, MapScores);

    internal static EpssScore[] MapScores(JsonElement root)
    {
        if (!root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array) return [];
        return data.EnumerateArray().Select(d => new EpssScore(
            CveId: Str(d, "cve"),
            Epss: Dbl(d, "epss"),
            Percentile: Dbl(d, "percentile"),
            Date: Date(d, "date"))).ToArray();
    }

    private static string Str(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    // EPSS returns the score/percentile as JSON strings (e.g. "0.00583").
    private static double Dbl(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            && double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0;

    private static DateTime? Date(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            && DateTime.TryParse(v.GetString(), CultureInfo.InvariantCulture,
                                 DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt)
            ? dt : null;
}
