namespace Camel.Intel;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;

/// <summary>
/// The generic client for external intelligence sources: it does everything that is the same across knowledge
/// bases — request build + auth injection, rate limiting, response caching, and uniform <b>provenance auditing</b>
/// — so adding a KB is "a config entry + a thin typed facade". Every call returns a <see cref="KbResult{T}"/>
/// (source, redacted query, retrieval time, response digest) and emits a <c>kb-query</c> audit event attributed
/// to the ambient case/execution; the resolved auth key is injected into the request but never appears in the
/// audited query, the result, or the trail. Investigation-neutral. See <c>docs/KnowledgeBases.md</c>.
/// </summary>
public class KnowledgeBaseClient : Runtime
{
    #region Construction
    // HttpClient is thread-safe and intended to be shared process-wide; one shared instance avoids socket
    // exhaustion across sessions. Tests inject their own (a fake handler) via the constructor.
    private static readonly HttpClient SharedHttp = new() { Timeout = TimeSpan.FromSeconds(30) };

    private readonly HttpClient http;
    private readonly ISecretsProvider secrets;
    private readonly IReadOnlyDictionary<string, KnowledgeBase> bases;
    private readonly ConcurrentDictionary<string, CacheEntry> cache = new();
    private readonly ConcurrentDictionary<string, DateTime> nextCallAfter = new();   // per-source rate-limit clock
    private readonly object rateLock = new();

    public KnowledgeBaseClient(IConfigurationRoot config, ISecretsProvider? secrets = null, HttpClient? http = null)
    {
        this.secrets = secrets ?? new DefaultSecretsProvider(config);
        this.http = http ?? SharedHttp;
        bases = LoadBases(config);
    }

    // A cached raw response: the body plus the provenance (digest + original fetch time) a cache hit must reproduce.
    private sealed record CacheEntry(string Body, string Digest, DateTime RetrievedUtc, DateTime ExpiresUtc);
    #endregion

    #region Availability
    /// <summary>The KB names configured in this process.</summary>
    public IEnumerable<string> ConfiguredSources => bases.Keys;

    /// <summary>True if <paramref name="source"/> is configured.</summary>
    public bool IsConfigured(string source) => bases.ContainsKey(source);

    /// <summary>True if <paramref name="source"/> is configured AND, when it needs a key, that key resolves — the
    /// KB analogue of <c>Tool.Available</c>. A query to an unavailable KB returns a null result and audits it.</summary>
    public bool IsAvailable(string source) =>
        bases.TryGetValue(source, out var kb) && (!kb.RequiresKey || !string.IsNullOrWhiteSpace(secrets.Resolve(kb.KeyRef)));
    #endregion

    #region Query
    /// <summary>
    /// Issues a GET against knowledge base <paramref name="source"/> at <paramref name="path"/> with
    /// <paramref name="query"/> params, maps the JSON response with <paramref name="map"/>, and wraps it in a
    /// provenance-stamped <see cref="KbResult{T}"/>. Auth is injected from the configured secret (never into the
    /// audited query). <paramref name="disclosedTarget"/>, when set, marks this as a target-keyed query and adds a
    /// <c>kb-disclosure</c> event recording the client asset sent to the third party (the gating itself is the
    /// caller/facade's job). Returns a failed result (null payload) on an unknown/unavailable KB, a transport
    /// error, or an HTTP error — auditing each.
    /// </summary>
    public async Task<KbResult<T>> QueryAsync<T>(
        string source, string path, IReadOnlyDictionary<string, string> query,
        Func<JsonElement, T?> map, string? disclosedTarget = null)
    {
        var queryId = Guid.NewGuid().ToString("N")[..8];
        // The AUDITED query is the path + user params only — the auth key is injected separately and never logged.
        var auditedQuery = BuildQueryString(path, query);

        if (!bases.TryGetValue(source, out var kb))
        {
            AuditEvent("kb-unavailable", "kb-query {QueryId} to unknown source {Source}", queryId, source);
            Error($"Knowledge base '{source}' is not configured.");
            return KbResult<T>.Failed(source, auditedQuery, queryId);
        }

        // Resolve the key whenever one is configured (so an OPTIONAL key is used when present); only refuse the
        // call when the key is REQUIRED and absent.
        string? key = kb.UsesKey ? secrets.Resolve(kb.KeyRef) : null;
        if (kb.RequiresKey && string.IsNullOrWhiteSpace(key))
        {
            AuditEvent("kb-unavailable", "kb-query {QueryId} to {Source}: secret {KeyRef} is not set",
                queryId, source, kb.KeyRef);
            Error($"Knowledge base '{source}' is unavailable: secret '{kb.KeyRef}' is not set.");
            return KbResult<T>.Failed(source, auditedQuery, queryId);
        }

        // Cache hit: reproduce the ORIGINAL provenance (retrieval time + digest), flagged FromCache.
        var cacheKey = source + "|" + auditedQuery;
        if (kb.CacheTtlMinutes > 0 && cache.TryGetValue(cacheKey, out var hit) && hit.ExpiresUtc > DateTime.UtcNow)
        {
            AuditEvent("kb-query",
                "kb-query {QueryId} {Source} {Query} (cache hit) digest={Digest} retrieved={Retrieved:u}",
                queryId, source, auditedQuery, hit.Digest, hit.RetrievedUtc);
            return MapEntry(hit, true);
        }

        await ThrottleAsync(source, kb.RateLimitPerMinute);

        var url = BuildUrl(kb, path, query, key);
        var sw = Stopwatch.StartNew();
        HttpResponseMessage resp;
        string body;
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (kb.Auth == KbAuth.Header && key is not null) req.Headers.TryAddWithoutValidation(kb.AuthName, key);
            resp = await http.SendAsync(req);
            body = await resp.Content.ReadAsStringAsync();
        }
        catch (Exception ex)
        {
            AuditEvent("kb-error", "kb-query {QueryId} {Source} {Query} failed: {Message}",
                queryId, source, auditedQuery, ex.Message);
            Error($"Knowledge base '{source}' query failed: {ex.Message}");
            return KbResult<T>.Failed(source, auditedQuery, queryId);
        }
        sw.Stop();

        var digest = Digest(body);
        var now = DateTime.UtcNow;

        // A target-keyed query disclosed a client asset to a third party — record exactly what left the perimeter.
        if (disclosedTarget is not null)
            AuditEvent("kb-disclosure", "kb-disclosure {QueryId}: target {Target} sent to {Source}",
                queryId, disclosedTarget, source);

        AuditEvent("kb-query", "kb-query {QueryId} {Source} {Query} status={Status} digest={Digest} {DurationMs}ms",
            queryId, source, auditedQuery, (int)resp.StatusCode, digest, sw.ElapsedMilliseconds);

        if (!resp.IsSuccessStatusCode)
        {
            Error($"Knowledge base '{source}' returned HTTP {(int)resp.StatusCode}.");
            return new KbResult<T>(source, auditedQuery, now, default, digest, queryId, false);
        }

        var entry = new CacheEntry(body, digest, now, now.AddMinutes(Math.Max(kb.CacheTtlMinutes, 0)));
        if (kb.CacheTtlMinutes > 0) cache[cacheKey] = entry;
        return MapEntry(entry, false);

        // Parse + map a (fresh or cached) body into the typed result, carrying the entry's provenance.
        KbResult<T> MapEntry(CacheEntry e, bool fromCache)
        {
            T? payload;
            try { using var doc = JsonDocument.Parse(e.Body); payload = map(doc.RootElement); }
            catch (Exception ex) { Error($"Failed to parse {source} response: {ex.Message}"); payload = default; }
            return new KbResult<T>(source, auditedQuery, e.RetrievedUtc, payload, e.Digest, queryId, fromCache);
        }
    }
    #endregion

    #region Helpers
    // Per-source minimum spacing between calls (a simple, monotonic rate clock). No-op when unlimited.
    private async Task ThrottleAsync(string source, int perMinute)
    {
        if (perMinute <= 0) return;
        var minInterval = TimeSpan.FromMinutes(1.0 / perMinute);
        TimeSpan wait;
        lock (rateLock)
        {
            var now = DateTime.UtcNow;
            var earliest = nextCallAfter.TryGetValue(source, out var t) && t > now ? t : now;
            wait = earliest - now;
            nextCallAfter[source] = earliest + minInterval;
        }
        if (wait > TimeSpan.Zero) await Task.Delay(wait);
    }

    // Audited query: path + user params (URL-encoded). Never includes the auth key.
    private static string BuildQueryString(string path, IReadOnlyDictionary<string, string> query)
    {
        if (query is null || query.Count == 0) return path;
        var qs = string.Join("&", query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return $"{path}?{qs}";
    }

    // The actual request URL: base + path + user params + (for QueryParam auth) the injected key.
    private static string BuildUrl(KnowledgeBase kb, string path, IReadOnlyDictionary<string, string> query, string? key)
    {
        var parts = new List<string>();
        if (query is not null)
            foreach (var kv in query) parts.Add($"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}");
        if (kb.Auth == KbAuth.QueryParam && key is not null)
            parts.Add($"{Uri.EscapeDataString(kb.AuthName)}={Uri.EscapeDataString(key)}");
        var baseUrl = kb.BaseUrl.TrimEnd('/') + "/" + path.TrimStart('/');
        return parts.Count == 0 ? baseUrl : baseUrl + "?" + string.Join("&", parts);
    }

    private static string Digest(string body) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();

    private static IReadOnlyDictionary<string, KnowledgeBase> LoadBases(IConfigurationRoot config)
    {
        var dict = new Dictionary<string, KnowledgeBase>(StringComparer.OrdinalIgnoreCase);
        foreach (var kb in config.GetSection("KnowledgeBases").GetChildren())
        {
            var baseUrl = kb["BaseUrl"];
            if (string.IsNullOrWhiteSpace(baseUrl)) continue;
            dict[kb.Key] = new KnowledgeBase(
                kb.Key, baseUrl,
                Enum.TryParse<KbAuth>(kb["Auth"], true, out var a) ? a : KbAuth.None,
                kb["AuthName"] ?? "", kb["KeyRef"] ?? "",
                int.TryParse(kb["RateLimitPerMinute"], out var r) ? r : 0,
                int.TryParse(kb["CacheTtlMinutes"], out var c) ? c : 0,
                bool.TryParse(kb["DisclosesTarget"], out var d) && d,
                !bool.TryParse(kb["KeyRequired"], out var kr) || kr);   // default true when unspecified
        }
        return dict;
    }
    #endregion
}
