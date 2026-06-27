namespace Camel.Intel;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

/// <summary>One entry in CISA's Known Exploited Vulnerabilities (KEV) catalog.</summary>
/// <param name="CveId">The CVE id (e.g. "CVE-2021-44228").</param>
/// <param name="VendorProject">Vendor/project (e.g. "Apache").</param>
/// <param name="Product">Affected product (e.g. "Log4j2").</param>
/// <param name="VulnerabilityName">CISA's name for the vuln (e.g. "Log4Shell").</param>
/// <param name="DateAdded">When CISA added it to the catalog.</param>
/// <param name="ShortDescription">CISA's short description.</param>
/// <param name="RequiredAction">The remediation CISA requires.</param>
/// <param name="DueDate">The remediation due date for federal agencies.</param>
/// <param name="KnownRansomwareUse">True when CISA notes known use in ransomware campaigns.</param>
public record KevEntry(
    string CveId,
    string VendorProject,
    string Product,
    string VulnerabilityName,
    DateTime? DateAdded,
    string ShortDescription,
    string RequiredAction,
    DateTime? DueDate,
    bool KnownRansomwareUse);

/// <summary>
/// Typed facade over CISA's Known Exploited Vulnerabilities (KEV) catalog — a keyless <b>knowledge</b> source (no
/// target, no gate). The catalog is a single JSON feed of all entries, fetched once and cached; each lookup
/// re-filters the cached feed, so checking many CVEs against KEV costs one fetch. "Is this CVE actively exploited
/// in the wild" is a strong prioritisation signal next to a raw CVSS score. Configured under
/// <c>KnowledgeBases:cisa-kev</c>.
/// </summary>
public class KevKnowledgeBase
{
    private const string Source = "cisa-kev";
    private const string Path = "known_exploited_vulnerabilities.json";

    private readonly KnowledgeBaseClient client;

    public KevKnowledgeBase(KnowledgeBaseClient client) => this.client = client;

    /// <summary>The whole KEV catalog (cached). Use it to cross-reference a batch of CVEs in one pass.</summary>
    public Task<KbResult<KevEntry[]>> AllAsync() =>
        client.QueryAsync(Source, Path, new Dictionary<string, string>(), MapAll);

    /// <summary>The KEV entry for <paramref name="cveId"/> as a 0-or-1-element array (empty = not in KEV), with the
    /// full detail (date added, required action, ransomware flag). Reuses the cached catalog.</summary>
    public Task<KbResult<KevEntry[]>> EntryAsync(string cveId) =>
        client.QueryAsync(Source, Path, new Dictionary<string, string>(),
            root => MapAll(root).Where(e => Eq(e.CveId, cveId)).ToArray());

    /// <summary>Whether <paramref name="cveId"/> is in the KEV catalog (a true/false answer — check <c>.Ok</c> for
    /// query success, then read <c>.Result</c>). Reuses the cached catalog.</summary>
    public Task<KbResult<bool>> IsKnownExploitedAsync(string cveId) =>
        client.QueryAsync<bool>(Source, Path, new Dictionary<string, string>(),
            root => MapAll(root).Any(e => Eq(e.CveId, cveId)));

    private static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    internal static KevEntry[] MapAll(JsonElement root)
    {
        if (!root.TryGetProperty("vulnerabilities", out var v) || v.ValueKind != JsonValueKind.Array) return [];
        return v.EnumerateArray().Select(e => new KevEntry(
            CveId: Str(e, "cveID"),
            VendorProject: Str(e, "vendorProject"),
            Product: Str(e, "product"),
            VulnerabilityName: Str(e, "vulnerabilityName"),
            DateAdded: Date(e, "dateAdded"),
            ShortDescription: Str(e, "shortDescription"),
            RequiredAction: Str(e, "requiredAction"),
            DueDate: Date(e, "dueDate"),
            KnownRansomwareUse: string.Equals(Str(e, "knownRansomwareCampaignUse"), "Known", StringComparison.OrdinalIgnoreCase)))
            .ToArray();
    }

    private static string Str(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static DateTime? Date(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            && DateTime.TryParse(v.GetString(), CultureInfo.InvariantCulture,
                                 DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt)
            ? dt : null;
}
