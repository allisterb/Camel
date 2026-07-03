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

using Camel.Environments;

/// <summary>
/// The generic client for external intelligence sources: it does everything that is the same across knowledge
/// bases — rate limiting, response caching, and uniform <b>provenance auditing</b> — regardless of <i>how</i> the
/// raw response is obtained. The transport (<see cref="KbTransport"/>) is the only thing that varies: an HTTP GET
/// (with auth injection), a CLI command run on the platform (local/SSH via the <see cref="AuditEnvironment"/>), or
/// a file read. Every call returns a provenance-stamped <see cref="KbResult{T}"/> and emits a <c>kb-query</c>
/// audit event attributed to the ambient case/execution; a resolved auth key is injected into the request but
/// never appears in the audited query, the result, or the trail. Investigation-neutral. See
/// <c>docs/KnowledgeBases.md</c>.
/// </summary>
public class KnowledgeBaseClient : Runtime
{
    #region Construction
    // HttpClient is thread-safe and intended to be shared process-wide; one shared instance avoids socket
    // exhaustion across sessions. Tests inject their own (a fake handler) via the constructor.
    private static readonly HttpClient SharedHttp = new() { Timeout = TimeSpan.FromSeconds(30) };

    private readonly HttpClient http;
    private readonly AuditEnvironment? env;                                  // for Cli/File transports (null = HTTP-only)
    private readonly ISecretsProvider secrets;
    private readonly IReadOnlyDictionary<string, KnowledgeBase> bases;
    private readonly string? retentionDir;                                   // where raw responses are retained (null = off)
    private readonly ConcurrentDictionary<string, CacheEntry> cache = new();
    private readonly ConcurrentDictionary<string, DateTime> nextCallAfter = new();   // per-source rate-limit clock
    private readonly object rateLock = new();

    public KnowledgeBaseClient(IConfigurationRoot config, ISecretsProvider? secrets = null,
        HttpClient? http = null, AuditEnvironment? env = null)
    {
        this.secrets = secrets ?? new DefaultSecretsProvider(config);
        this.http = http ?? SharedHttp;
        this.env = env;
        // Where to retain raw response bodies (content-addressed) for byte-for-byte provenance; off when unset.
        retentionDir = config["KnowledgeBaseRetentionDir"];
        bases = LoadBases(config);
    }

    // A cached raw response: the body plus the provenance (digest + original fetch time) a cache hit must reproduce.
    private sealed record CacheEntry(string Body, string Digest, DateTime RetrievedUtc, DateTime ExpiresUtc);

    // The outcome of one transport fetch: the raw response body, success, and a short status label for the trail.
    private sealed record FetchResult(string Body, bool Ok, string Status);
    #endregion

    #region Availability
    /// <summary>The KB names configured in this process.</summary>
    public IEnumerable<string> ConfiguredSources => bases.Keys;

    /// <summary>True if <paramref name="source"/> is configured.</summary>
    public bool IsConfigured(string source) => bases.ContainsKey(source);

    /// <summary>True if <paramref name="source"/> is configured AND, when it needs a key, that key resolves — the
    /// KB analogue of <c>Tool.Available</c>. (For a CLI source this does not probe whether the command is installed;
    /// a missing command surfaces as a failed query, audited, like any other transport error.)</summary>
    public bool IsAvailable(string source) =>
        bases.TryGetValue(source, out var kb) && (!kb.RequiresKey || !string.IsNullOrWhiteSpace(secrets.Resolve(kb.KeyRef)));
    #endregion

    #region Query — HTTP
    /// <summary>
    /// HTTP GET against <paramref name="source"/> at <paramref name="path"/> with <paramref name="query"/> params,
    /// mapping the JSON response with <paramref name="map"/>. Auth is injected from the configured secret (never
    /// into the audited query). <paramref name="disclosedTarget"/>, when set, marks this a target-keyed query and
    /// adds a <c>kb-disclosure</c> event. Returns a failed result on an unknown/unavailable KB, transport error, or
    /// HTTP error — auditing each.
    /// </summary>
    public Task<KbResult<T>> QueryAsync<T>(string source, string path, IReadOnlyDictionary<string, string> query,
        Func<JsonElement, T?> map, string? disclosedTarget = null) =>
        QueryRawAsync<T>(source, path, query, raw => MapJson(raw, map), disclosedTarget);

    /// <summary>As <see cref="QueryAsync"/> but the response body is mapped as raw text (for CSV / non-JSON HTTP
    /// sources). <paramref name="map"/> receives the raw response string.</summary>
    public Task<KbResult<T>> QueryRawAsync<T>(string source, string path, IReadOnlyDictionary<string, string> query,
        Func<string, T?> map, string? disclosedTarget = null)
    {
        var queryId = NewId();
        var label = BuildQueryString(path, query);   // audited query: path + params, never the auth key
        if (!TryPrepare<T>(source, label, queryId, out var kb, out var key, out var failed)) return Task.FromResult(failed);
        if (kb.Transport != KbTransport.Http)
            return Task.FromResult(NotThisTransport<T>(source, kb, "HTTP", label, queryId));
        return RunAsync(source, kb, queryId, label, () => HttpFetch(kb, path, query, key), map, disclosedTarget);
    }
    #endregion

    #region Query — CLI / File
    /// <summary>
    /// Runs the CLI source <paramref name="source"/>'s command with <paramref name="args"/> on the platform
    /// (local/SSH via the <see cref="AuditEnvironment"/>) and maps its stdout as raw text. The audited query is the
    /// command line; the underlying execution ALSO emits the environment's own <c>command</c> audit event, so a CLI
    /// KB lookup is doubly recorded. Returns a failed result if the source is not CLI / no environment is available
    /// / the command failed.
    /// </summary>
    public Task<KbResult<T>> QueryCliAsync<T>(string source, string args, Func<string, T?> map,
        string? disclosedTarget = null)
    {
        var queryId = NewId();
        if (!TryPrepare<T>(source, args, queryId, out var kb, out _, out var failed)) return Task.FromResult(failed);
        if (kb.Transport != KbTransport.Cli)
            return Task.FromResult(NotThisTransport<T>(source, kb, "CLI", args, queryId));
        var label = $"{kb.Command} {args}".Trim();   // the audited query is the command line
        return RunAsync(source, kb, queryId, label, () => CliFetch(kb, args), map, disclosedTarget);
    }

    /// <summary>As <see cref="QueryCliAsync"/> but the command's stdout is parsed as JSON (e.g. <c>searchsploit
    /// --json</c>) and mapped with <paramref name="map"/>.</summary>
    public Task<KbResult<T>> QueryCliJsonAsync<T>(string source, string args, Func<JsonElement, T?> map,
        string? disclosedTarget = null) =>
        QueryCliAsync<T>(source, args, raw => MapJson(raw, map), disclosedTarget);

    /// <summary>Reads the file source <paramref name="source"/>'s configured file (path in its <c>Command</c>) on
    /// the platform and maps its contents as raw text — for a local data file (e.g. a CSV index).</summary>
    public Task<KbResult<T>> QueryFileAsync<T>(string source, Func<string, T?> map)
    {
        var queryId = NewId();
        if (!TryPrepare<T>(source, source, queryId, out var kb, out _, out var failed)) return Task.FromResult(failed);
        if (kb.Transport != KbTransport.File)
            return Task.FromResult(NotThisTransport<T>(source, kb, "File", kb.Command, queryId));
        return RunAsync(source, kb, queryId, kb.Command, () => FileFetch(kb), map, disclosedTarget: null);
    }

    /// <summary>
    /// HTTP POST to <paramref name="source"/> at <paramref name="path"/> with the JSON request body
    /// <paramref name="jsonBody"/> (the body is the query, recorded in the provenance), mapping the JSON response.
    /// Auth is injected as a header / query param exactly as for GET (the key never enters the body or the audited
    /// query). Enables query-by-body APIs (OSV, Vulners). The body must not contain secrets.
    /// </summary>
    public Task<KbResult<T>> QueryPostAsync<T>(string source, string path, string jsonBody,
        Func<JsonElement, T?> map, string? disclosedTarget = null)
    {
        var queryId = NewId();
        var label = $"POST {path} {jsonBody}";
        if (!TryPrepare<T>(source, label, queryId, out var kb, out var key, out var failed)) return Task.FromResult(failed);
        if (kb.Transport != KbTransport.Http)
            return Task.FromResult(NotThisTransport<T>(source, kb, "HTTP", label, queryId));
        return RunAsync(source, kb, queryId, label, () => HttpPostFetch(kb, path, jsonBody, key),
            raw => MapJson(raw, map), disclosedTarget);
    }
    #endregion

    #region Capability report
    /// <summary>One configured KB's launch-time availability (for the capability report).</summary>
    /// <param name="Name">The KB id.</param>
    /// <param name="Transport">Its transport (Http/Cli/File).</param>
    /// <param name="Available">True when usable now (configured + key resolves if required). For a CLI source this
    /// does not probe whether the command is installed.</param>
    /// <param name="Detail">Short reason / descriptor (e.g. "http", "cli: searchsploit", "needs SHODAN_API_KEY").</param>
    public record SourceStatus(string Name, KbTransport Transport, bool Available, string Detail);

    /// <summary>The availability of every configured knowledge base, for the launch capability report.</summary>
    public IEnumerable<SourceStatus> DescribeSources() =>
        bases.Values.OrderBy(kb => kb.Name).Select(kb =>
        {
            var available = IsAvailable(kb.Name);
            var detail = kb.Transport switch
            {
                KbTransport.Cli => $"cli: {kb.Command}",
                KbTransport.File => $"file: {kb.Command}",
                _ when kb.RequiresKey && !available => $"needs {kb.KeyRef}",
                _ => kb.DisclosesTarget ? "http (target-keyed)" : "http",
            };
            return new SourceStatus(kb.Name, kb.Transport, available, detail);
        });
    #endregion

    #region Pipeline
    // Resolves the KB and its key (the availability gate). Returns false + a failed result (audited) when the source
    // is unknown or a required key is unset. The transport-specific public methods then build the fetch.
    private bool TryPrepare<T>(string source, string label, string queryId,
        out KnowledgeBase kb, out string? key, out KbResult<T> failed)
    {
        key = null; failed = default!;
        if (!bases.TryGetValue(source, out kb!))
        {
            AuditEvent("kb-unavailable", "kb-query {QueryId} to unknown source {Source}", queryId, source);
            Error($"Knowledge base '{source}' is not configured.");
            failed = KbResult<T>.Failed(source, label, queryId);
            return false;
        }
        // Resolve the key when one is configured (so an OPTIONAL key is used when present); only refuse when REQUIRED.
        key = kb.UsesKey ? secrets.Resolve(kb.KeyRef) : null;
        if (kb.RequiresKey && string.IsNullOrWhiteSpace(key))
        {
            AuditEvent("kb-unavailable", "kb-query {QueryId} to {Source}: secret {KeyRef} is not set",
                queryId, source, kb.KeyRef);
            Error($"Knowledge base '{source}' is unavailable: secret '{kb.KeyRef}' is not set.");
            failed = KbResult<T>.Failed(source, label, queryId);
            return false;
        }
        return true;
    }

    private KbResult<T> NotThisTransport<T>(string source, KnowledgeBase kb, string expected, string label, string queryId)
    {
        Error($"Knowledge base '{source}' is a {kb.Transport} source, not {expected}.");
        return KbResult<T>.Failed(source, label, queryId);
    }

    // The shared pipeline: cache → fetch (via the transport closure) → digest → provenance audit → map → KbResult.
    // Transport-agnostic; only <paramref name="fetch"/> differs between HTTP / CLI / File.
    private async Task<KbResult<T>> RunAsync<T>(string source, KnowledgeBase kb, string queryId, string label,
        Func<Task<FetchResult>> fetch, Func<string, T?> map, string? disclosedTarget)
    {
        var cacheKey = source + "|" + label;
        if (kb.CacheTtlMinutes > 0 && cache.TryGetValue(cacheKey, out var hit) && hit.ExpiresUtc > DateTime.UtcNow)
        {
            AuditEvent("kb-query", "kb-query {QueryId} {Source} {Query} (cache hit) digest={Digest} retrieved={Retrieved:u}",
                queryId, source, label, hit.Digest, hit.RetrievedUtc);
            return Map(hit, true);
        }

        await ThrottleAsync(source, kb.RateLimitPerMinute);

        var sw = Stopwatch.StartNew();
        FetchResult f;
        try { f = await fetch(); }
        catch (Exception ex)
        {
            AuditEvent("kb-error", "kb-query {QueryId} {Source} {Query} failed: {Message}", queryId, source, label, ex.Message);
            Error($"Knowledge base '{source}' query failed: {ex.Message}");
            return KbResult<T>.Failed(source, label, queryId);
        }
        sw.Stop();

        var digest = Digest(f.Body);
        var now = DateTime.UtcNow;

        // A target-keyed query disclosed a client asset to a third party — record exactly what left the perimeter.
        if (disclosedTarget is not null)
            AuditEvent("kb-disclosure", "kb-disclosure {QueryId}: target {Target} sent to {Source}",
                queryId, disclosedTarget, source);

        // Retain the raw body (content-addressed) on a successful fresh fetch so a reviewer can verify the claim
        // byte-for-byte; the CLEF carries the digest + path, not the body.
        var retained = f.Ok ? RetainBody(source, digest, f.Body) : null;

        AuditEvent("kb-query", "kb-query {QueryId} {Source} {Query} status={Status} digest={Digest} retained={Retained} {DurationMs}ms",
            queryId, source, label, f.Status, digest, retained ?? "-", sw.ElapsedMilliseconds);

        if (!f.Ok)
        {
            Error($"Knowledge base '{source}' returned no usable response ({f.Status}).");
            return new KbResult<T>(source, label, now, default, digest, queryId, false);
        }

        var entry = new CacheEntry(f.Body, digest, now, now.AddMinutes(Math.Max(kb.CacheTtlMinutes, 0)));
        if (kb.CacheTtlMinutes > 0) cache[cacheKey] = entry;
        return Map(entry, false);

        // Map a (fresh or cached) body into the typed result, carrying the entry's provenance.
        KbResult<T> Map(CacheEntry e, bool fromCache)
        {
            T? payload;
            try { payload = map(e.Body); }
            catch (Exception ex) { Error($"Failed to parse {source} response: {ex.Message}"); payload = default; }
            return new KbResult<T>(source, label, e.RetrievedUtc, payload, e.Digest, queryId, fromCache);
        }
    }
    #endregion

    #region Transports
    // The value for a header credential: "{AuthScheme} {key}" when a scheme is set (e.g. "Bearer <token>"), else the
    // raw key. Lets a paid API that uses Authorization: Bearer be configured without baking the scheme into the secret.
    private static string HeaderCredential(KnowledgeBase kb, string key) =>
        string.IsNullOrWhiteSpace(kb.AuthScheme) ? key : $"{kb.AuthScheme} {key}";

    private async Task<FetchResult> HttpFetch(KnowledgeBase kb, string path, IReadOnlyDictionary<string, string> query, string? key)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, BuildUrl(kb, path, query, key));
        if (kb.Auth == KbAuth.Header && key is not null) req.Headers.TryAddWithoutValidation(kb.AuthName, HeaderCredential(kb, key));
        var resp = await http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        return new FetchResult(body, resp.IsSuccessStatusCode, ((int)resp.StatusCode).ToString());
    }

    private async Task<FetchResult> HttpPostFetch(KnowledgeBase kb, string path, string jsonBody, string? key)
    {
        // No user query params; QueryParam auth (if any) is appended to the URL, the body carries the query.
        using var req = new HttpRequestMessage(HttpMethod.Post, BuildUrl(kb, path, EmptyQuery, key))
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, "application/json"),
        };
        if (kb.Auth == KbAuth.Header && key is not null) req.Headers.TryAddWithoutValidation(kb.AuthName, HeaderCredential(kb, key));
        var resp = await http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        return new FetchResult(body, resp.IsSuccessStatusCode, ((int)resp.StatusCode).ToString());
    }

    private async Task<FetchResult> CliFetch(KnowledgeBase kb, string args)
    {
        if (env is null) return new FetchResult("", false, "no-environment");
        var r = await env.ExecuteCommandAsync(kb.Command, args, false);
        return new FetchResult(r.Output ?? "", r.IsCompleted, r.IsCompleted ? "exit 0" : "exit !=0");
    }

    private async Task<FetchResult> FileFetch(KnowledgeBase kb)
    {
        if (env is null) return new FetchResult("", false, "no-environment");
        var r = await env.ExecuteCommandAsync("cat", $"'{kb.Command}'", false);
        return new FetchResult(r.Output ?? "", r.IsCompleted, r.IsCompleted ? "read" : "read-failed");
    }
    #endregion

    #region Helpers
    private static readonly IReadOnlyDictionary<string, string> EmptyQuery = new Dictionary<string, string>();

    private static string NewId() => Guid.NewGuid().ToString("N")[..8];

    // Writes the raw response body content-addressed to the retention dir as <source>-<hexdigest>.json (skipped if
    // already present, since the name is content-addressed). Returns the path, or null when retention is off / fails.
    private string? RetainBody(string source, string digest, string body)
    {
        if (string.IsNullOrWhiteSpace(retentionDir)) return null;
        try
        {
            System.IO.Directory.CreateDirectory(retentionDir);
            var hex = digest.StartsWith("sha256:", StringComparison.Ordinal) ? digest[7..] : digest;
            var path = System.IO.Path.Combine(retentionDir, $"{source}-{hex}.json");
            if (!System.IO.File.Exists(path)) System.IO.File.WriteAllText(path, body);
            return path;
        }
        catch (Exception ex) { Error($"Failed to retain {source} response: {ex.Message}"); return null; }
    }

    private static T? MapJson<T>(string raw, Func<JsonElement, T?> map)
    {
        using var doc = JsonDocument.Parse(raw);
        return map(doc.RootElement);
    }

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
            var transport = Enum.TryParse<KbTransport>(kb["Transport"], true, out var tp) ? tp : KbTransport.Http;
            var baseUrl = kb["BaseUrl"] ?? "";
            var command = kb["Command"] ?? "";
            // A KB is valid if it has what its transport needs: an HTTP base URL, or a CLI/File command/path.
            if (transport == KbTransport.Http ? string.IsNullOrWhiteSpace(baseUrl) : string.IsNullOrWhiteSpace(command))
                continue;
            dict[kb.Key] = new KnowledgeBase(
                kb.Key, baseUrl,
                Enum.TryParse<KbAuth>(kb["Auth"], true, out var a) ? a : KbAuth.None,
                kb["AuthName"] ?? "", kb["KeyRef"] ?? "", kb["AuthScheme"] ?? "",
                int.TryParse(kb["RateLimitPerMinute"], out var r) ? r : 0,
                int.TryParse(kb["CacheTtlMinutes"], out var c) ? c : 0,
                bool.TryParse(kb["DisclosesTarget"], out var d) && d,
                !bool.TryParse(kb["KeyRequired"], out var kr) || kr,   // default true when unspecified
                transport, command);
        }
        return dict;
    }
    #endregion
}
