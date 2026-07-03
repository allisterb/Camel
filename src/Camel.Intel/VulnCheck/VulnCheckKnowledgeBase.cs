namespace Camel.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

/// <summary>
/// One CVE's entry in VulnCheck's exploited-vulnerability intelligence (the <c>vulncheck-kev</c> index) — a
/// commercial superset of CISA KEV that is typically broader and faster to list a CVE as exploited, and that adds
/// weaponization detail (indexed public/commercial exploits) CISA KEV does not carry. A returned record means the
/// CVE <b>is</b> in VulnCheck's known-exploited catalog.
/// </summary>
/// <param name="CveId">The CVE this record is about.</param>
/// <param name="KnownExploited">True — a returned vulncheck-kev record means the CVE is in the exploited catalog.</param>
/// <param name="HasWeaponizedExploit">True when VulnCheck indexes at least one exploit (vulncheck_xdb) for it.</param>
/// <param name="KnownRansomware">True when VulnCheck notes known ransomware-campaign use.</param>
/// <param name="ExploitSources">Reference URLs for the reported exploitation / indexed exploits (leads).</param>
/// <param name="DateAdded">When VulnCheck added the CVE to the catalog, or null.</param>
public record VulnCheckCve(
    string CveId,
    bool KnownExploited,
    bool HasWeaponizedExploit,
    bool KnownRansomware,
    string[] ExploitSources,
    DateTime? DateAdded);

/// <summary>
/// Typed facade over the VulnCheck API — an example of a <b>paid, keyed</b> intelligence source integrated the same
/// way as the open-source knowledge bases. It is <b>CVE-keyed knowledge</b> (a lookup carries no client asset), so
/// like NVD/KEV/EPSS it is ungated — no scope or external-disclosure check. The API key never lives in code or
/// config: it is resolved at call time from the secret named by <c>KeyRef</c> (<c>VULNCHECK_API_KEY</c>) and
/// injected as <c>Authorization: Bearer &lt;token&gt;</c>, never entering the audited query or the trail. When the
/// analyst has supplied no key the source is simply unavailable (<see cref="KnowledgeBaseClient.IsAvailable"/>
/// false) and callers degrade gracefully. Configured under <c>KnowledgeBases:vulncheck</c>
/// (Auth=Header, AuthName=Authorization, AuthScheme=Bearer, KeyRequired=true, DisclosesTarget=false).
/// See <c>docs/KnowledgeBases.md</c>.
/// </summary>
public class VulnCheckKnowledgeBase
{
    private const string Source = "vulncheck";

    private readonly KnowledgeBaseClient client;

    public VulnCheckKnowledgeBase(KnowledgeBaseClient client) => this.client = client;

    /// <summary>
    /// VulnCheck's known-exploited intelligence for <paramref name="cveId"/> from the <c>vulncheck-kev</c> index.
    /// A non-null result means the CVE is in VulnCheck's exploited catalog (<see cref="VulnCheckCve.KnownExploited"/>
    /// true); a CVE VulnCheck does not list as exploited returns an empty/failed result (Ok=false). Ungated
    /// (CVE-keyed knowledge). Returns a failed result when the source is unconfigured or the key is absent.
    /// </summary>
    public Task<KbResult<VulnCheckCve>> CveAsync(string cveId) =>
        client.QueryAsync(Source, "index/vulncheck-kev",
            new Dictionary<string, string> { ["cve"] = cveId }, root => MapCve(cveId, root));

    /// <summary>Maps a <c>vulncheck-kev</c> response to a <see cref="VulnCheckCve"/>, or null when the catalog has no
    /// entry for the CVE (empty <c>data</c>). Tolerant of missing fields.</summary>
    internal static VulnCheckCve? MapCve(string cveId, JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array
            || data.GetArrayLength() == 0)
            return null;
        var e = data[0];

        var xdb = e.TryGetProperty("vulncheck_xdb", out var x) && x.ValueKind == JsonValueKind.Array ? x : default;
        var hasExploit = xdb.ValueKind == JsonValueKind.Array && xdb.GetArrayLength() > 0;

        var sources = new List<string>();
        if (xdb.ValueKind == JsonValueKind.Array)
            sources.AddRange(xdb.EnumerateArray()
                .Select(d => Str(d, "clone_ssh_url")).Where(s => s.Length > 0));
        if (e.TryGetProperty("vulncheck_reported_exploitation", out var rep) && rep.ValueKind == JsonValueKind.Array)
            sources.AddRange(rep.EnumerateArray().Select(d => Str(d, "url")).Where(s => s.Length > 0));

        var ransom = Str(e, "known_ransomware_campaign_use").Equals("known", StringComparison.OrdinalIgnoreCase);
        DateTime? added = e.TryGetProperty("date_added", out var da) && da.ValueKind == JsonValueKind.String
            && DateTime.TryParse(da.GetString(), out var dt) ? dt.ToUniversalTime() : null;

        return new VulnCheckCve(cveId, KnownExploited: true, hasExploit, ransom,
            sources.Distinct().ToArray(), added);
    }

    private static string Str(JsonElement e, string prop) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "" : "";
}
