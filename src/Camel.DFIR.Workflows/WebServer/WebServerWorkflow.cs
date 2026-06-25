namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

using Camel.Toolkits;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

/// <summary>
/// Workflows for triaging a machine that ran a web server and is suspected of having been compromised through it
/// (SQL-injection → webshell → OS foothold being the dominant pattern). The evidence for these intrusions lives
/// in the HTTP access log and the injected server-side scripts rather than in memory or the registry, so these
/// workflows operate on the web server's <em>log files and web root</em> on a mounted volume:
/// <list type="bullet">
/// <item><see cref="AnalyzeWebServerLogsAsync"/> — signature-matches the access log for scanners, SQLi, RCE /
/// webshell access and file inclusion, and decodes hex-smuggled payloads (e.g. sqlmap's injected PHP).</item>
/// <item><see cref="ScanWebRootForWebshellsAsync"/> — YARA-scans the web root with the bundled web-shell pack.</item>
/// </list>
/// </summary>
public class WebServerWorkflow : Workflow
{
    public WebServerWorkflow(CamelToolkitsApi api) : base(api) { }

    // The bundled Yara-Rules community pack ships a web-shell aggregator index alongside the master index.
    private const string WebshellRulesIndex = YaraToolkit.RulesRepoPath + "/webshells_index.yar";

    #region Attack signatures
    // Attack categories. A matched log line can carry several.
    public const string CatScanner = "scanner";
    public const string CatSqli = "sqli";
    public const string CatWebshellRce = "webshell-rce";
    public const string CatFileInclusion = "file-inclusion";
    public const string CatXss = "xss";

    // Signature set: (category, extended-regex source, human reason). The same source strings drive both the
    // server-side grep prefilter (grep -E -f) and the per-line classification here (.NET Regex), so they must be
    // valid in BOTH engines — hence POSIX-safe constructs only (no \d/\w; explicit [0-9], %20/[ +] for the URL-
    // encoded spaces apache logs preserve). Patterns are case-insensitive.
    private static readonly (string Category, string Pattern, string Reason)[] Signatures =
    [
        // Automated scanners / exploitation tools by user-agent or fingerprint.
        (CatScanner, "sqlmap",                         "sqlmap SQL-injection tool"),
        (CatScanner, "nikto",                          "Nikto web scanner"),
        (CatScanner, "(dirbuster|gobuster|dirb/)",     "directory brute-forcer"),
        (CatScanner, "wpscan",                         "WPScan WordPress scanner"),
        (CatScanner, "(acunetix|nessus|nuclei)",       "vulnerability scanner"),
        (CatScanner, "\\b(havij|fimap|jsql)\\b",       "SQLi/LFI exploitation tool"),
        (CatScanner, "(masscan|zgrab|\\bnmap\\b)",     "network/port scanner"),

        // SQL injection.
        (CatSqli, "union(%20|[ +/*])+select",                          "UNION-based SQL injection"),
        (CatSqli, "into(%20|[ +])+(out|dump)file",                     "SQLi file write (INTO OUTFILE/DUMPFILE)"),
        (CatSqli, "lines(%20|[ +])+terminated(%20|[ +])+by",           "SQLi OUTFILE payload smuggling (LINES TERMINATED BY)"),
        (CatSqli, "information_schema",                                "SQLi schema enumeration"),
        (CatSqli, "load_file(%20)*(%28|\\()",                          "SQLi file read (LOAD_FILE)"),
        (CatSqli, "(or|and)(%20|[ +])+[0-9]+(%3d|=)[0-9]+",            "boolean SQLi tautology (e.g. OR 1=1)"),
        (CatSqli, "(sleep|benchmark|pg_sleep|waitfor)(%20)*(%28|\\()", "time-based blind SQLi"),
        (CatSqli, "0x[0-9a-f]{16,}",                                   "long hex blob (encoded payload smuggling)"),

        // Remote command execution / web shells.
        (CatWebshellRce, "(c99|r57|b374k|wso|webshell|backdoor)\\.php",      "known web-shell filename"),
        (CatWebshellRce, "tmp[a-z]{4,8}\\.php",                             "sqlmap-style PHP upload/exec dropper"),
        (CatWebshellRce, "(cmd|exec|command|page|c)(%3d|=)(dir|whoami|net|ipconfig|type|systeminfo|echo|ping|cmd|id|ls|cat|uname)", "command-execution parameter"),
        (CatWebshellRce, "(shell_exec|passthru|proc_open|popen|system|eval|assert)(%20)*(%28|\\()", "PHP code-execution sink"),
        (CatWebshellRce, "base64_decode",                                  "obfuscated PHP payload (base64_decode)"),
        (CatWebshellRce, "(cmd\\.exe|/bin/(ba)?sh)",                        "OS shell invocation"),
        (CatWebshellRce, "net(%20|[ +])+(user|localgroup)",                "account-manipulation command"),

        // Local/remote file inclusion and path traversal.
        (CatFileInclusion, "(\\.\\.(/|%2f|\\\\|%5c)){2,}",                 "path traversal (../../)"),
        (CatFileInclusion, "(/|%2f)etc(/|%2f)passwd",                      "LFI of /etc/passwd"),
        (CatFileInclusion, "(php|data|expect|file|zip|phar):(/|%2f){2}",   "PHP wrapper / RFI"),
        (CatFileInclusion, "(boot\\.ini|/proc/self/environ)",             "LFI of a sensitive system file"),

        // Reflected XSS (secondary signal).
        (CatXss, "(%3c|<)script",          "XSS <script> injection"),
        (CatXss, "(onerror|onload)(%3d|=)", "XSS event-handler injection"),
        (CatXss, "javascript:",            "XSS javascript: URI"),
    ];

    private static readonly Regex[] CompiledSignatures =
        Signatures.Select(s => new Regex(s.Pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled)).ToArray();

    // Apache/Nginx "combined" log line: IP ident authuser [time] "METHOD url proto" status size "ref" "ua".
    // Tolerant of malformed request lines ("-") and a missing referer/UA tail.
    private static readonly Regex CombinedLogLine = new(
        @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<time>[^\]]*)\]\s+""(?<method>\S+)?\s*(?<url>[^""]*?)\s*(?<proto>HTTP/[0-9.]+)?""\s+(?<status>[0-9]{3})\s+(?<size>\S+)(?:\s+""[^""]*""\s+""(?<ua>[^""]*)"")?",
        RegexOptions.Compiled);

    private static readonly Regex HexBlob = new("0x(?<hex>[0-9a-fA-F]{16,})", RegexOptions.Compiled);
    #endregion

    /// <summary>
    /// Triages a web-server access log (<paramref name="accessLogPath"/>) for evidence of intrusion. The log is
    /// matched server-side against the built-in signature set (and any <paramref name="extraPatterns"/>) so only
    /// the suspicious lines transfer back; each is parsed (client IP, timestamp, request, status, user-agent) and
    /// classified into one or more categories. Long hex blobs carried in a line — the <c>… INTO OUTFILE … LINES
    /// TERMINATED BY 0x&lt;hex PHP&gt;</c> trick sqlmap uses to write a backdoor through the injection — are
    /// hex-decoded and, when they yield printable text, surfaced in <see cref="WebServerLogReport.DecodedPayloads"/>:
    /// the injected script ("shellcode") recovered straight from the log. The report ranks attacker IPs, lists the
    /// scanner user-agents seen, and breaks hits down by category.
    /// </summary>
    /// <param name="accessLogPath">Path to the access log on the mounted volume (e.g. <c>…/apache/logs/access.log</c>).</param>
    /// <param name="extraPatterns">Optional extra extended-regex signatures to match in addition to the built-ins.</param>
    /// <param name="maxFindings">Cap on the number of detailed <see cref="WebLogFinding"/> rows returned (aggregates
    /// are still computed over every matched line). Defaults to 100.</param>
    public async Task<WorkflowResult<WebServerLogReport>> AnalyzeWebServerLogsAsync(
        string accessLogPath, string[]? extraPatterns = null, int maxFindings = 100)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing web-server access log {0}", accessLogPath);

        var patterns = Signatures.Select(s => s.Pattern).Concat(extraPatterns ?? []).Distinct();
        const int hitCap = 20000;   // bound the transfer on a hostile log; aggregates remain representative
        var lines = await DiskAnalysis.GrepLinesAsync(accessLogPath, patterns, ignoreCase: true, maxMatches: hitCap);
        if (lines is null)
            return WorkflowResult<WebServerLogReport>.Failure(
                $"Could not read access log '{accessLogPath}'; the path may be wrong or the volume not mounted.");

        var findings = lines.Select(ClassifyLine).Where(f => f is not null).Select(f => f!).ToArray();

        // Aggregates over every matched line.
        var ipRanking = findings
            .Where(f => f.ClientIp.Length > 0)
            .GroupBy(f => f.ClientIp)
            .Select(g => new IpHitCount(g.Key, g.Count()))
            .OrderByDescending(x => x.Hits).ThenBy(x => x.Ip)
            .ToArray();
        var scanners = findings
            .Where(f => f.Categories.Contains(CatScanner) && !string.IsNullOrWhiteSpace(f.UserAgent))
            .Select(f => f.UserAgent!).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(u => u).ToArray();
        var categoryBreakdown = findings
            .SelectMany(f => f.Categories)
            .GroupBy(c => c)
            .Select(g => new CategoryCount(g.Key, g.Count()))
            .OrderByDescending(x => x.Count).ThenBy(x => x.Category)
            .ToArray();
        var decoded = findings
            .Where(f => f.DecodedPayload is not null)
            .Select(f => new DecodedPayload(f.ClientIp, TruncHex(f.Url), f.DecodedPayload!))
            .GroupBy(d => d.Decoded).Select(g => g.First())   // distinct by decoded text
            .ToArray();

        // Detailed rows: payload-bearing first, then broadest-category, then most-recent-looking; capped.
        var sample = findings
            .OrderByDescending(f => f.DecodedPayload is not null)
            .ThenByDescending(f => f.Categories.Length)
            .Take(maxFindings)
            .ToArray();

        op.Complete();
        var report = new WebServerLogReport
        {
            LogPath = accessLogPath,
            SuspiciousLineCount = findings.Length,
            Truncated = lines.Length >= hitCap,
            Findings = sample,
            TopAttackerIps = ipRanking,
            ScannerUserAgents = scanners,
            CategoryBreakdown = categoryBreakdown,
            DecodedPayloads = decoded,
        };
        var topIp = ipRanking.FirstOrDefault();
        return WorkflowResult<WebServerLogReport>.Success(report,
            findings.Length == 0
                ? $"No intrusion signatures matched in '{accessLogPath}'."
                : $"{findings.Length} suspicious request(s){(report.Truncated ? "+ (capped)" : "")} from " +
                  $"{ipRanking.Length} client IP(s)" +
                  (topIp is null ? "" : $", led by {topIp.Ip} ({topIp.Hits} hit(s))") +
                  $". Categories: {string.Join(", ", categoryBreakdown.Select(c => $"{c.Category}×{c.Count}"))}. " +
                  (scanners.Length == 0 ? "" : $"Scanners: {string.Join(", ", scanners.Take(5))}. ") +
                  (decoded.Length == 0 ? "" : $"Recovered {decoded.Length} decoded payload(s) (injected script/shellcode)."));
    }

    /// <summary>
    /// YARA-scans a web root (<paramref name="webRoot"/>) for known web shells using the classic <c>yara</c>
    /// file scanner and, by default, the bundled web-shell rule pack (<c>webshells_index.yar</c>). The raw
    /// per-rule hits are collapsed to one <see cref="WebshellFile"/> per offending file with the set of rules that
    /// fired — a genuine C99/r57 shell typically trips many rules at once, which is itself a strong signal.
    /// </summary>
    /// <param name="webRoot">The web root directory on the mounted volume to scan recursively (e.g. <c>…/htdocs</c>).</param>
    /// <param name="rulesFile">YARA rules file to use; defaults to the bundled <c>webshells_index.yar</c>.</param>
    public async Task<WorkflowResult<WebshellScanReport>> ScanWebRootForWebshellsAsync(
        string webRoot, string? rulesFile = null)
    {
        rulesFile ??= WebshellRulesIndex;
        using var _audit = AuditScope();
        using var op = Begin("Scanning web root {0} for web shells", webRoot);

        var matches = await Yara.ScanAsync(rulesFile, webRoot, new YaraOptions { Recurse = true, Timeout = 120 });
        if (matches is null)
            return WorkflowResult<WebshellScanReport>.Failure(
                $"YARA scan of '{webRoot}' with '{rulesFile}' failed; check the web root path and that the rules file exists.");

        var files = matches
            .GroupBy(m => m.Target)
            .Select(g => new WebshellFile(g.Key, g.Select(m => m.Rule).Distinct().OrderBy(r => r).ToArray()))
            .OrderByDescending(f => f.Rules.Length).ThenBy(f => f.Path)
            .ToArray();

        op.Complete();
        var report = new WebshellScanReport { WebRoot = webRoot, RulesFile = rulesFile, Matches = matches, Files = files };
        return WorkflowResult<WebshellScanReport>.Success(report,
            files.Length == 0
                ? $"No web shells detected under '{webRoot}'."
                : $"Detected {files.Length} web shell(s) under '{webRoot}': " +
                  string.Join("; ", files.Take(5).Select(f => $"{f.Path} ({f.Rules.Length} rule(s))")) + ".");
    }

    #region Helpers
    // Parse and classify one matched log line. Returns null only if the line is empty.
    private static WebLogFinding? ClassifyLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;

        var cats = new List<string>();
        var reasons = new List<string>();
        for (int i = 0; i < CompiledSignatures.Length; i++)
            if (CompiledSignatures[i].IsMatch(line))
            {
                var (category, _, reason) = Signatures[i];
                if (!cats.Contains(category)) cats.Add(category);
                reasons.Add(reason);
            }
        if (cats.Count == 0) return null;   // grep's union matched but no single signature owns it (rare) — skip

        var m = CombinedLogLine.Match(line);
        var ip = m.Success ? m.Groups["ip"].Value : line.Split(' ', 2)[0];
        var url = m.Success ? m.Groups["url"].Value : line;

        // Recover a hex-smuggled payload (sqlmap INTO OUTFILE etc.) when one decodes to printable text.
        string? decodedPayload = null;
        foreach (Match hb in HexBlob.Matches(line))
            if (TryDecodeHex(hb.Groups["hex"].Value, out var text))
            {
                decodedPayload = text;
                break;   // the first decodable blob is the payload; one per line in practice
            }

        return new WebLogFinding
        {
            ClientIp = ip,
            Timestamp = m.Success && m.Groups["time"].Success ? m.Groups["time"].Value : null,
            Method = m.Success && m.Groups["method"].Success ? m.Groups["method"].Value : null,
            Url = url,
            Status = m.Success && int.TryParse(m.Groups["status"].Value, out var st) ? st : null,
            UserAgent = m.Success && m.Groups["ua"].Success ? m.Groups["ua"].Value : null,
            Categories = cats.ToArray(),
            Reasons = reasons.Distinct().ToArray(),
            DecodedPayload = decodedPayload,
        };
    }

    // Decode an even-length hex string; accept it as a payload only when the result is mostly printable (so we
    // surface injected source/script, not a random binary id). Decoded text is truncated for the report.
    private static bool TryDecodeHex(string hex, out string text)
    {
        text = "";
        if (hex.Length % 2 != 0) hex = hex[..^1];           // drop a trailing nibble (e.g. odd-length blob)
        if (hex.Length < 16) return false;
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            if (!byte.TryParse(hex.AsSpan(i * 2, 2), System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                return false;
        }
        int printable = bytes.Count(b => b >= 0x20 && b < 0x7f || b is 0x09 or 0x0a or 0x0d);
        if ((double)printable / bytes.Length < 0.85) return false;   // not text — skip
        var s = Encoding.ASCII.GetString(bytes).Replace('\0', ' ').Trim();
        text = s.Length > 600 ? s[..600] + "…" : s;
        return text.Length > 0;
    }

    private static string TruncHex(string url)
    {
        var m = HexBlob.Match(url);
        if (!m.Success) return "";
        var hex = "0x" + m.Groups["hex"].Value;
        return hex.Length > 48 ? hex[..48] + "…" : hex;
    }
    #endregion
}
