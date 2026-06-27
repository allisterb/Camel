namespace Camel.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

using Camel.Environments;

/// <summary>
/// Typed facade over the Shodan host API — a <b>target-keyed</b> source: a lookup sends a client asset (the IP) to
/// a third party, so it is fail-closed on TWO gates before the request leaves: the IP must be in the engagement
/// scope (<see cref="AuditEnvironment.FailIfOutOfScope"/>), and the engagement must permit external disclosure
/// (<see cref="AuditEnvironment.FailIfExternalDisclosureForbidden"/>). The query is then issued with the target
/// marked disclosed, so the client emits a <c>kb-disclosure</c> event recording exactly what left the perimeter.
/// Configured under <c>KnowledgeBases:shodan</c> (Auth=QueryParam, KeyRef=SHODAN_API_KEY, DisclosesTarget=true).
/// </summary>
public class ShodanKnowledgeBase
{
    private const string Source = "shodan";

    private readonly KnowledgeBaseClient client;
    private readonly AuditEnvironment env;

    public ShodanKnowledgeBase(KnowledgeBaseClient client, AuditEnvironment env)
    {
        this.client = client;
        this.env = env;
    }

    /// <summary>
    /// What Shodan knows about <paramref name="ip"/>. Throws if the IP is out of engagement scope
    /// (<see cref="OutOfScopeException"/>), if no engagement is registered (<see cref="EngagementRequiredException"/>),
    /// or if the engagement forbids external disclosure (<see cref="ExternalDisclosureForbiddenException"/>) — the
    /// scope check runs first. Shodan's data is dated third-party scan history, not a live probe — treat it as a lead.
    /// </summary>
    public Task<KbResult<ShodanHost>> HostAsync(string ip)
    {
        env.FailIfOutOfScope(ip);                  // the looked-up host must be authorized...
        env.FailIfExternalDisclosureForbidden();   // ...and the RoE must permit sending it to a third party
        return client.QueryAsync(Source, $"shodan/host/{Uri.EscapeDataString(ip)}",
            new Dictionary<string, string>(), MapHost, disclosedTarget: ip);
    }

    // Maps a Shodan host response to ShodanHost. Tolerant of missing fields (Shodan omits what it has no data for).
    internal static ShodanHost MapHost(JsonElement root)
    {
        return new ShodanHost(
            IpStr: Str(root, "ip_str"),
            Ports: IntArray(root, "ports"),
            Hostnames: StrArray(root, "hostnames"),
            Org: Str(root, "org"),
            Isp: Str(root, "isp"),
            Os: root.TryGetProperty("os", out var os) && os.ValueKind == JsonValueKind.String ? os.GetString() : null,
            Country: Str(root, "country_name"),
            Services: root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array
                ? data.EnumerateArray().Select(d => new ShodanService(
                    Port: d.TryGetProperty("port", out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : 0,
                    Transport: Str(d, "transport"),
                    Product: Str(d, "product"),
                    Version: Str(d, "version"),
                    Banner: Str(d, "data"))).ToArray()
                : [],
            Vulns: StrArray(root, "vulns"));
    }

    private static string Str(JsonElement e, string prop) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "" : "";

    private static string[] StrArray(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToArray()
            : [];

    private static int[] IntArray(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Number).Select(x => x.GetInt32()).ToArray()
            : [];
}
