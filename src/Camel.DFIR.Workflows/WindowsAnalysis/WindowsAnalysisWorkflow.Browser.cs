namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

// FOR500.4 — Browser forensics. Reconstructs a user's web activity from the host-based browser databases: the
// Chromium History SQLite DB (Chrome/Edge), Firefox places.sqlite, and the legacy IE/Edge WebCacheV01.dat ESE
// store. Each browser stores timestamps in its own epoch, normalised here to UTC. SQLECmd's EZ build is broken on
// SIFT (missing SQLite.Interop.dll), so the SQLite stores are read with the sqlite3 CLI; WebCacheV01.dat is read
// with libesedb (esedbexport).
public partial class WindowsAnalysisWorkflow
{
    #region Workflow methods
    /// <summary>
    /// Reconstructs browser activity for a user profile (<paramref name="userProfileRoot"/>) — the FOR500.4 browser
    /// methodology. It discovers and parses the Chromium <c>History</c> databases (Chrome and Edge — visited URLs
    /// and file downloads), Firefox <c>places.sqlite</c> (visited URLs), and the legacy IE/Edge
    /// <c>WebCacheV01.dat</c> (when present, or pointed at by <paramref name="webCacheDb"/>), unifying them into a
    /// single visited-URL <see cref="BrowserActivityReport.History"/> and file <see cref="BrowserActivityReport.Downloads"/>
    /// list with timestamps normalised to UTC. Optionally runs Hindsight over the Chrome profile for a richer
    /// Chromium timeline. The recovered URLs are leads for reconstructing user activity and the webmail/cloud
    /// accounts in use (per the methodology). Read-only throughout (databases are staged to a temp copy).
    /// </summary>
    /// <param name="userProfileRoot">The mounted user profile directory to search for browser databases.</param>
    /// <param name="webCacheDb">Optional explicit path to a <c>WebCacheV01.dat</c> (otherwise auto-discovered).</param>
    /// <param name="useHindsight">Also run Hindsight over the Chrome user-data profile (optional, slower).</param>
    public async Task<WorkflowResult<BrowserActivityReport>> AnalyzeBrowserActivityAsync(
        string userProfileRoot, string? webCacheDb = null, bool useHindsight = false)
    {
        var root = userProfileRoot.TrimEnd('/');
        using var _audit = AuditScope();
        using var op = Begin("Analyzing browser activity for {0}", userProfileRoot);

        var history = new List<BrowserHistoryEntry>();
        var downloads = new List<BrowserDownload>();
        var sources = new List<string>();

        // Chromium History DBs (Chrome / Edge), identified by their "…/User Data/…/History" location.
        var chromiumDbs = (await DiskAnalysis.FindFilesAsync(root, ["History"]))
            .Where(f => f.Path.Contains("/User Data/", StringComparison.OrdinalIgnoreCase)).Select(f => f.Path);
        foreach (var db in chromiumDbs)
        {
            var browser = db.Contains("/Edge/", StringComparison.OrdinalIgnoreCase) ? "Edge"
                        : db.Contains("/Chrome/", StringComparison.OrdinalIgnoreCase) ? "Chrome" : "Chromium";
            var urls = await WindowsAnalysis.SqliteQueryAsync(db,
                "SELECT url,title,visit_count,last_visit_time FROM urls WHERE last_visit_time>0 ORDER BY last_visit_time DESC LIMIT 5000");
            if (urls is { Length: > 0 })
            {
                sources.Add(db);
                history.AddRange(urls.Select(r => new BrowserHistoryEntry
                {
                    Browser = browser, Url = Str(r, "url") ?? "", Title = Str(r, "title"),
                    VisitCount = Num(r, "visit_count"), LastVisited = WebKitTime(Num(r, "last_visit_time")), Source = db,
                }).Where(h => h.Url.Length > 0));
            }
            var dls = await WindowsAnalysis.SqliteQueryAsync(db,
                "SELECT d.target_path AS target_path, d.total_bytes AS total_bytes, d.start_time AS start_time, " +
                "(SELECT url FROM downloads_url_chains c WHERE c.id=d.id ORDER BY chain_index DESC LIMIT 1) AS url " +
                "FROM downloads d ORDER BY d.start_time DESC LIMIT 2000");
            if (dls is { Length: > 0 })
                downloads.AddRange(dls.Select(r => new BrowserDownload
                {
                    Browser = browser, Url = Str(r, "url"), TargetPath = Str(r, "target_path"),
                    TotalBytes = Num(r, "total_bytes"), StartTime = WebKitTime(Num(r, "start_time")), Source = db,
                }));
        }

        // Firefox places.sqlite (visited URLs).
        foreach (var db in (await DiskAnalysis.FindFilesAsync(root, ["places.sqlite"])).Select(f => f.Path))
        {
            var urls = await WindowsAnalysis.SqliteQueryAsync(db,
                "SELECT url,title,visit_count,last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 5000");
            if (urls is not { Length: > 0 }) continue;
            sources.Add(db);
            history.AddRange(urls.Select(r => new BrowserHistoryEntry
            {
                Browser = "Firefox", Url = Str(r, "url") ?? "", Title = Str(r, "title"),
                VisitCount = Num(r, "visit_count"), LastVisited = FirefoxTime(Num(r, "last_visit_date")), Source = db,
            }).Where(h => h.Url.Length > 0));
        }

        // Legacy IE / Edge WebCacheV01.dat (ESE) — explicit path or auto-discovered under the profile.
        var webCaches = webCacheDb is not null ? [webCacheDb]
            : (await DiskAnalysis.FindFilesAsync(root, ["WebCacheV01.dat"])).Select(f => f.Path).ToArray();
        foreach (var wc in webCaches)
        {
            var entries = await WindowsAnalysis.WebCacheHistoryAsync(wc);
            if (entries is not { Length: > 0 }) continue;
            sources.Add(wc);
            history.AddRange(entries
                .Where(e => e.Container is null || e.Container.Contains("History", StringComparison.OrdinalIgnoreCase))
                .Select(e => new BrowserHistoryEntry
                {
                    Browser = "IE-Edge(WebCache)", Url = e.Url, VisitCount = e.AccessCount,
                    LastVisited = e.AccessedTime, Source = wc,
                }));
        }

        // Optional Hindsight pass over the Chrome user-data profile for a richer Chromium activity timeline.
        if (useHindsight)
        {
            var chromeProfile = $"{root}/AppData/Local/Google/Chrome/User Data";
            var hs = await WindowsAnalysis.HindsightAsync(chromeProfile);
            foreach (var r in hs ?? [])
                if (Str(r, "url") is { Length: > 0 } url && r.ContainsKey("timestamp"))
                    history.Add(new BrowserHistoryEntry
                    {
                        Browser = "Chrome(Hindsight)", Url = url, Title = Str(r, "title"),
                        LastVisited = ParseDate(Str(r, "timestamp")), Source = "hindsight",
                    });
        }

        var orderedHistory = history.OrderByDescending(h => h.LastVisited ?? DateTime.MinValue).ToArray();
        var orderedDownloads = downloads.OrderByDescending(d => d.StartTime ?? DateTime.MinValue).ToArray();

        op.Complete();
        var report = new BrowserActivityReport
        {
            History = orderedHistory, Downloads = orderedDownloads, Sources = sources.Distinct().ToArray(),
        };
        if (sources.Count == 0)
            return WorkflowResult<BrowserActivityReport>.Success(report,
                $"No browser databases (Chromium History / places.sqlite / WebCacheV01.dat) found under '{userProfileRoot}'.");
        return WorkflowResult<BrowserActivityReport>.Success(report,
            $"Recovered {orderedHistory.Length} history record(s) and {orderedDownloads.Length} download(s) from " +
            $"{report.Sources.Length} database(s) ({string.Join(", ", orderedHistory.Select(h => h.Browser).Distinct())}).");
    }
    #endregion

    // Reads a string column from a sqlite3 -json row (values arrive as JSON strings or numbers).
    private static string? Str(IReadOnlyDictionary<string, JsonElement> r, string key) =>
        r.TryGetValue(key, out var v) ? v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.ToString(),
            JsonValueKind.Null or JsonValueKind.Undefined => null,
            _ => v.ToString(),
        } : null;

    // Reads an integer column from a sqlite3 -json row (number, or numeric string).
    private static long Num(IReadOnlyDictionary<string, JsonElement> r, string key) =>
        r.TryGetValue(key, out var v)
            ? v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n
              : long.TryParse(v.ToString(), out var p) ? p : 0
            : 0;

    private static readonly DateTime WebKitEpoch = new(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime UnixEpoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    // Chrome/Edge timestamps are microseconds since 1601-01-01 UTC.
    private static DateTime? WebKitTime(long micros) =>
        micros > 0 && micros < 13000000000000000L + 4000000000000000L ? WebKitEpoch.AddTicks(micros * 10) : null;

    // Firefox PRTime is microseconds since 1970-01-01 UTC.
    private static DateTime? FirefoxTime(long micros) =>
        micros > 0 ? UnixEpoch.AddTicks(micros * 10) : null;

    // Hindsight emits an ISO-ish timestamp string; parse to UTC, null on anything unparseable.
    private static DateTime? ParseDate(string? s) =>
        DateTime.TryParse(s, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
}
