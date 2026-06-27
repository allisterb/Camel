namespace Camel.Intel;

using System;

/// <summary>How a knowledge base authenticates a request.</summary>
public enum KbAuth { None, Header, QueryParam }

/// <summary>How a knowledge base's raw response is obtained — the only thing that varies across KBs; the
/// provenance/cache/audit/map pipeline is identical. <see cref="Http"/>: a GET against <c>BaseUrl</c>.
/// <see cref="Cli"/>: run <c>Command</c> on the platform (local/SSH) and capture stdout. <see cref="File"/>:
/// read a file (path in <c>Command</c>) on the platform.</summary>
public enum KbTransport { Http, Cli, File }

/// <summary>
/// A configured external intelligence source (Shodan, NVD, Vulners, …). <see cref="KeyRef"/> is the NAME of a
/// secret to resolve at call time (an env-var / secrets-file key), never the key itself — secrets never live in
/// config or source. See <c>docs/KnowledgeBases.md</c>.
/// </summary>
/// <param name="Name">Logical id used by the facade and in the audit trail (e.g. "nvd", "shodan").</param>
/// <param name="BaseUrl">API base URL the facade builds request paths under.</param>
/// <param name="Auth">How the key is presented (none / a header / a query param).</param>
/// <param name="AuthName">Header name (e.g. "apiKey") or query-param name (e.g. "key") when Auth != None.</param>
/// <param name="KeyRef">Name of the secret to resolve (e.g. "SHODAN_API_KEY"). Empty when the KB needs no key.</param>
/// <param name="RateLimitPerMinute">Client-side throttle; 0 = unlimited.</param>
/// <param name="CacheTtlMinutes">Response cache lifetime; 0 = no cache.</param>
/// <param name="DisclosesTarget">True for target-keyed KBs (Shodan/Censys): queries send a client asset to a third
/// party, so they are scope-gated AND require the engagement to permit external disclosure.</param>
/// <param name="KeyRequired">When true (default), the KB is unavailable without its key (e.g. Shodan). When false,
/// the key is OPTIONAL — the KB works without it and the key, if resolvable, is used anyway (e.g. NVD, where a key
/// only raises the rate limit).</param>
/// <param name="Transport">How the raw response is obtained: an HTTP GET (default), a CLI command, or a file read.</param>
/// <param name="Command">For <see cref="KbTransport.Cli"/>, the executable to run (e.g. "searchsploit"); for
/// <see cref="KbTransport.File"/>, the file path to read. Unused for HTTP.</param>
public record KnowledgeBase(
    string Name,
    string BaseUrl,
    KbAuth Auth = KbAuth.None,
    string AuthName = "",
    string KeyRef = "",
    int RateLimitPerMinute = 0,
    int CacheTtlMinutes = 0,
    bool DisclosesTarget = false,
    bool KeyRequired = true,
    KbTransport Transport = KbTransport.Http,
    string Command = "")
{
    /// <summary>True when the KB authenticates with a key AND cannot run without it — so its secret must resolve
    /// for the KB to be usable. An optional-key KB (<see cref="KeyRequired"/> false) is usable regardless.</summary>
    public bool RequiresKey => Auth != KbAuth.None && !string.IsNullOrWhiteSpace(KeyRef) && KeyRequired;

    /// <summary>True when the KB has a key to inject when one is configured and resolvable (required or optional).</summary>
    public bool UsesKey => Auth != KbAuth.None && !string.IsNullOrWhiteSpace(KeyRef);
}

/// <summary>
/// The provenance envelope wrapping EVERY knowledge-base result. The payload alone is not enough for a deliverable —
/// a finding cites the source, the exact query, when it was retrieved, and a digest of the raw response, plus the
/// <see cref="QueryId"/> that ties it to the <c>kb-query</c> audit event. The red-side analogue of an evidence hash.
/// </summary>
/// <param name="Source">The KB name the answer came from.</param>
/// <param name="Query">The exact query issued, with any secret redacted (auth keys are never included here).</param>
/// <param name="RetrievedUtc">When the underlying response was fetched (the ORIGINAL fetch time on a cache hit).</param>
/// <param name="Result">The typed payload (T), or null on failure / empty result.</param>
/// <param name="ResponseDigest">SHA-256 of the raw response body — the authoritative reference to the retained copy.</param>
/// <param name="QueryId">Short id of the <c>kb-query</c> audit event for this call; cite it in findings.</param>
/// <param name="FromCache">True when served from the response cache rather than a fresh fetch.</param>
public record KbResult<T>(
    string Source,
    string Query,
    DateTime RetrievedUtc,
    T? Result,
    string ResponseDigest,
    string QueryId,
    bool FromCache = false)
{
    /// <summary>True when the call produced a payload.</summary>
    public bool Ok => Result is not null;

    /// <summary>A failed/empty result (no payload) that still carries the source, query, and id for the trail.</summary>
    internal static KbResult<T> Failed(string source, string query, string queryId) =>
        new(source, query, DateTime.UtcNow, default, "", queryId, false);
}
