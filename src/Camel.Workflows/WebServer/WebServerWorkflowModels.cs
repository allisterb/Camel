namespace Camel.Workflows.Models;

using System.Linq;

using Camel.Toolkits.Models;

/// <summary>
/// The result of triaging a web-server access log for intrusion indicators. The log is matched server-side
/// against a built-in signature set (scanner user-agents, SQL-injection, RCE/webshell access, file inclusion,
/// XSS) and every matching line is classified into one or more <see cref="WebLogFinding"/> categories. Where a
/// matched line carries a long hex blob (the classic <c>INTO OUTFILE … LINES TERMINATED BY 0x…</c> payload-
/// smuggling trick) that decodes to printable text, the decoded payload is recovered into
/// <see cref="DecodedPayloads"/> — this is what surfaces an injected PHP backdoor / "shellcode" that never
/// touches the disk as a file.
/// </summary>
public record WebServerLogReport
{
    /// <summary>The access-log path that was analysed.</summary>
    public required string LogPath { get; init; }

    /// <summary>Total number of log lines that matched at least one attack signature.</summary>
    public int SuspiciousLineCount { get; init; }

    /// <summary>True when the server-side match hit its line cap and the analysis saw only a prefix of the hits.</summary>
    public bool Truncated { get; init; }

    /// <summary>A representative, capped sample of the matched lines (payload-bearing and broadest-category hits first).</summary>
    public WebLogFinding[] Findings { get; init; } = [];

    /// <summary>Client IPs ranked by number of suspicious hits — the attacker-IP shortlist.</summary>
    public IpHitCount[] TopAttackerIps { get; init; } = [];

    /// <summary>The distinct scanner/tool user-agents observed in the matched traffic (sqlmap, nikto, …).</summary>
    public string[] ScannerUserAgents { get; init; } = [];

    /// <summary>Per-category hit counts across every matched line.</summary>
    public CategoryCount[] CategoryBreakdown { get; init; } = [];

    /// <summary>Decoded hex payloads recovered from the matched lines (e.g. sqlmap's injected PHP backdoor).</summary>
    public DecodedPayload[] DecodedPayloads { get; init; } = [];
}

/// <summary>One suspicious access-log line, parsed and classified.</summary>
public record WebLogFinding
{
    public string ClientIp { get; init; } = "";
    public string? Timestamp { get; init; }
    public string? Method { get; init; }
    public string Url { get; init; } = "";
    public int? Status { get; init; }
    public string? UserAgent { get; init; }
    /// <summary>The attack categories this line matched (scanner, sqli, webshell-rce, file-inclusion, xss).</summary>
    public string[] Categories { get; init; } = [];
    /// <summary>Human-readable reasons (one per matched signature).</summary>
    public string[] Reasons { get; init; } = [];
    /// <summary>The decoded text of a hex blob carried in this line, when one decoded to printable content.</summary>
    public string? DecodedPayload { get; init; }
}

/// <summary>A client IP and how many suspicious hits it accounted for.</summary>
public record IpHitCount(string Ip, int Hits);

/// <summary>An attack category and how many matched lines fell into it.</summary>
public record CategoryCount(string Category, int Count);

/// <summary>A hex payload decoded out of an attack line: the (truncated) source hex, its decoded text, and the client IP that sent it.</summary>
public record DecodedPayload(string ClientIp, string Hex, string Decoded);

/// <summary>
/// The result of YARA-scanning a web root for known web shells. Wraps the classic <c>yara</c> file scanner over
/// the bundled web-shell rule pack; <see cref="Files"/> collapses the raw per-rule <see cref="Matches"/> into one
/// entry per offending file with the set of rules that fired on it (a C99 shell typically trips 20+).
/// </summary>
public record WebshellScanReport
{
    public required string WebRoot { get; init; }
    public required string RulesFile { get; init; }
    /// <summary>Every raw rule/file hit from the scan.</summary>
    public YaraMatch[] Matches { get; init; } = [];
    /// <summary>The flagged files, one entry each, with the rules that matched.</summary>
    public WebshellFile[] Files { get; init; } = [];
    /// <summary>Number of distinct files flagged.</summary>
    public int FilesFlagged => Files.Length;
}

/// <summary>A single flagged web-shell file and the YARA rules that matched it.</summary>
public record WebshellFile(string Path, string[] Rules);
