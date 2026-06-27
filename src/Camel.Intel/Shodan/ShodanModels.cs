namespace Camel.Intel;

/// <summary>One service Shodan observed on a host (an entry of the host's <c>data[]</c> array).</summary>
/// <param name="Port">The port the service was seen on.</param>
/// <param name="Transport">Transport protocol (e.g. "tcp", "udp").</param>
/// <param name="Product">Product Shodan fingerprinted (e.g. "OpenSSH", "nginx"), or "".</param>
/// <param name="Version">Product version, or "".</param>
/// <param name="Banner">The raw service banner Shodan captured (may be long), or "".</param>
public record ShodanService(int Port, string Transport, string Product, string Version, string Banner);

/// <summary>
/// What Shodan knows about a host (the <c>GET /shodan/host/{ip}</c> response) — a <b>target-keyed</b> result, so
/// the lookup discloses the client asset to Shodan and is gated by the engagement (scope + external-disclosure).
/// Shodan's data is third-party scan history, not a live probe of the target: treat it as a dated lead.
/// </summary>
/// <param name="IpStr">The host IP Shodan keyed on.</param>
/// <param name="Ports">Ports Shodan has seen open.</param>
/// <param name="Hostnames">Hostnames Shodan associates with the IP.</param>
/// <param name="Org">Owning organization, or "".</param>
/// <param name="Isp">ISP, or "".</param>
/// <param name="Os">OS Shodan guessed, or null.</param>
/// <param name="Country">Country name, or "".</param>
/// <param name="Services">Per-service detail from the host's <c>data[]</c> banners.</param>
/// <param name="Vulns">CVE ids Shodan flagged for the host (may be empty / absent).</param>
public record ShodanHost(
    string IpStr,
    int[] Ports,
    string[] Hostnames,
    string Org,
    string Isp,
    string? Os,
    string Country,
    ShodanService[] Services,
    string[] Vulns);
