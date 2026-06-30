namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

public partial class LinuxAnalysisWorkflow
{
    private const int BruteForceThreshold = 5;   // failed attempts from one source before it's flagged

    #region Login records (wtmp / btmp)
    /// <summary>
    /// Analyses the login record databases on a mounted root: successful sessions from <c>var/log/wtmp</c> (via
    /// <c>last</c>) and failed attempts from <c>var/log/btmp</c> (via <c>lastb</c>). Ranks source IPs and targeted
    /// usernames, and flags brute-force sources, successful logins from an IP that also failed (a likely
    /// successful guess), and direct remote <c>root</c> logins.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c>.</param>
    public async Task<WorkflowResult<LoginActivityReport>> AnalyzeLoginActivityAsync(string rootDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing Linux login records under {0}", rootDir);

        var successful = (await LinuxAnalysis.LastLoginsAsync(Combine(rootDir, "var/log/wtmp"))).Result;
        var failed = (await LinuxAnalysis.FailedLoginsAsync(Combine(rootDir, "var/log/btmp"))).Result ?? [];
        if (successful is null)
            return WorkflowResult<LoginActivityReport>.Failure(
                $"Could not read '{Combine(rootDir, "var/log/wtmp")}'; the path may be wrong or the volume not mounted.");

        // Drop the pseudo "users" last emits for boot/shutdown/runlevel transitions.
        string[] pseudo = ["reboot", "shutdown", "runlevel"];
        var realSuccess = successful.Where(l => !pseudo.Contains(l.User, StringComparer.OrdinalIgnoreCase)).ToArray();

        bool IsIp(string? h) => h is not null && Regex.IsMatch(h, @"^\d{1,3}(\.\d{1,3}){3}$") && h != "0.0.0.0";
        var ipStats = realSuccess.Where(l => IsIp(l.Host)).Select(l => (l.Host!, ok: true))
            .Concat(failed.Where(l => IsIp(l.Host)).Select(l => (l.Host!, ok: false)))
            .GroupBy(x => x.Item1)
            .Select(g => new IpLoginStat { Ip = g.Key, Successful = g.Count(x => x.ok), Failed = g.Count(x => !x.ok) })
            .OrderByDescending(s => s.Successful + s.Failed).ToArray();

        var topFailedUsers = failed.GroupBy(l => l.User)
            .Select(g => new NameCount { Name = g.Key, Count = g.Count() })
            .OrderByDescending(n => n.Count).Take(15).ToArray();

        var findings = new List<LoginFinding>();
        foreach (var s in ipStats)
        {
            if (s.Failed >= BruteForceThreshold)
                findings.Add(new LoginFinding { Category = "brute-force-source", Detail = $"{s.Ip}: {s.Failed} failed attempt(s)" + (s.Successful > 0 ? $" then {s.Successful} success(es)" : "") });
            else if (s.Failed > 0 && s.Successful > 0)
                findings.Add(new LoginFinding { Category = "success-after-failures", Detail = $"{s.Ip}: succeeded after {s.Failed} failed attempt(s)" });
        }
        foreach (var l in realSuccess.Where(l => l.User == "root" && IsIp(l.Host)))
            findings.Add(new LoginFinding { Category = "root-remote-login", Detail = $"root logged in directly from {l.Host} ({l.Start:u})" });

        op.Complete();
        var report = new LoginActivityReport
        {
            SuccessfulCount = realSuccess.Length,
            FailedCount = failed.Length,
            TopSourceIps = ipStats.Take(25).ToArray(),
            TopFailedUsers = topFailedUsers,
            RecentSuccessful = realSuccess.OrderByDescending(l => l.Start ?? DateTime.MinValue).Take(50).ToArray(),
            Findings = findings.DistinctBy(f => f.Detail).ToArray(),
        };
        return WorkflowResult<LoginActivityReport>.Success(report,
            $"{realSuccess.Length} successful login(s), {failed.Length} failed attempt(s) from {ipStats.Length} source IP(s). " +
            (report.Findings.Length == 0 ? "No login anomalies flagged." : $"{report.Findings.Length} finding(s): " +
                string.Join("; ", report.Findings.Take(4).Select(f => f.Detail)) + "."));
    }
    #endregion

    #region Auth log (auth.log / secure)
    // Lines worth pulling out of the (potentially large) auth log — matched server-side so only these transfer back.
    private static readonly string[] AuthPatterns =
    [
        "sshd", "sudo:", "su:", "su\\[", "useradd", "usermod", "groupadd", "passwd",
        "Accepted ", "Failed password", "Invalid user", "authorized_keys", "session opened",
    ];

    /// <summary>
    /// Parses the authentication log on a mounted root (<c>var/log/auth.log</c> on Debian/Ubuntu, or
    /// <c>var/log/secure</c> on RHEL-family) for SSH logins (accepted/failed), <c>sudo</c>/<c>su</c> usage, and
    /// account changes (useradd/usermod/groupadd). The log is prefiltered server-side so only relevant lines
    /// transfer back. Flags repeated SSH failures from one source, invalid-user probing, and a successful login
    /// that follows failures from the same IP.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c>.</param>
    public async Task<WorkflowResult<AuthEventReport>> AnalyzeAuthLogAsync(string rootDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing Linux auth log under {0}", rootDir);

        // Debian/Ubuntu vs RHEL-family. Pick whichever exists.
        string[] candidates = [Combine(rootDir, "var/log/auth.log"), Combine(rootDir, "var/log/secure")];
        string? logPath = null;
        string[]? lines = null;
        foreach (var c in candidates)
        {
            lines = (await DiskAnalysis.GrepLinesAsync(c, AuthPatterns, ignoreCase: false, maxMatches: 50000)).Result;
            if (lines is not null) { logPath = c; break; }
        }
        if (lines is null || logPath is null)
            return WorkflowResult<AuthEventReport>.Failure(
                $"No readable auth log found under '{rootDir}' (looked for var/log/auth.log and var/log/secure).");

        var events = lines.Select(ParseAuthLine).Where(e => e is not null).Select(e => e!).ToArray();

        int accepted = events.Count(e => e.Type == "sshd-accepted");
        int failedN = events.Count(e => e.Type == "sshd-failed");
        int sudoN = events.Count(e => e.Type == "sudo");

        var sshFailIps = events.Where(e => e.Type == "sshd-failed" && e.SourceIp is not null)
            .GroupBy(e => e.SourceIp!)
            .Select(g => new IpLoginStat { Ip = g.Key, Failed = g.Count(), Successful = events.Count(e => e.Type == "sshd-accepted" && e.SourceIp == g.Key) })
            .OrderByDescending(s => s.Failed).ToArray();

        var findings = new List<AuthEvent>();
        foreach (var ip in sshFailIps.Where(s => s.Failed >= BruteForceThreshold))
            findings.Add(new AuthEvent { Type = "ssh-bruteforce", SourceIp = ip.Ip, Raw = $"{ip.Failed} failed SSH auth(s) from {ip.Ip}" + (ip.Successful > 0 ? $", then {ip.Successful} accepted" : "") });
        // Invalid-user probing and new SSH keys are always worth surfacing.
        findings.AddRange(events.Where(e => e.Type == "sshd-failed" && e.Raw.Contains("Invalid user")).Take(20));
        findings.AddRange(events.Where(e => e.Type == "new-ssh-key").Take(20));

        op.Complete();
        // The most security-relevant events, newest first, capped.
        var sample = events.Where(e => e.Type is "sshd-accepted" or "sshd-failed" or "sudo" or "useradd" or "usermod" or "new-ssh-key")
            .OrderByDescending(e => e.Time ?? DateTime.MinValue).Take(200).ToArray();

        var report = new AuthEventReport
        {
            LogPath = logPath,
            AcceptedLogins = accepted,
            FailedLogins = failedN,
            SudoCommands = sudoN,
            TopSshSourceIps = sshFailIps.Take(25).ToArray(),
            Events = sample,
            Findings = findings.ToArray(),
        };
        return WorkflowResult<AuthEventReport>.Success(report,
            $"Parsed {events.Length} auth event(s) from '{logPath}': {accepted} accepted, {failedN} failed SSH login(s), {sudoN} sudo command(s). " +
            (findings.Count == 0 ? "No auth anomalies flagged." : $"{findings.Count} finding(s) incl. " +
                string.Join("; ", findings.Take(3).Select(f => f.SourceIp ?? f.Type)) + "."));
    }

    // syslog line prefix: "MMM d HH:mm:ss host proc[pid]: message". No year in the timestamp.
    private static readonly Regex SyslogPrefix = new(
        @"^(?<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?<proc>[\w./-]+)(?:\[\d+\])?:\s*(?<msg>.*)$",
        RegexOptions.Compiled);
    private static readonly Regex IpRe = new(@"\b(?<ip>\d{1,3}(?:\.\d{1,3}){3})\b", RegexOptions.Compiled);

    private static AuthEvent? ParseAuthLine(string line)
    {
        var m = SyslogPrefix.Match(line);
        var msg = m.Success ? m.Groups["msg"].Value : line;
        var proc = m.Success ? m.Groups["proc"].Value : "";
        DateTime? time = m.Success ? ParseSyslogTime(m.Groups["ts"].Value) : null;
        string? ip = IpRe.Match(line) is { Success: true } im ? im.Groups["ip"].Value : null;

        string? user = null, type = null;
        if (proc.StartsWith("sshd"))
        {
            if (msg.StartsWith("Accepted")) { type = "sshd-accepted"; user = Cap(msg, @"Accepted \S+ for (?<u>\S+) from"); }
            else if (msg.StartsWith("Failed password")) { type = "sshd-failed"; user = Cap(msg, @"for (?:invalid user )?(?<u>\S+) from"); }
            else if (msg.StartsWith("Invalid user")) { type = "sshd-failed"; user = Cap(msg, @"Invalid user (?<u>\S+)"); }
        }
        else if (proc.StartsWith("sudo")) { type = "sudo"; user = Cap(msg, @"^\s*(?<u>\S+)\s*:"); }
        else if (proc.StartsWith("su")) { type = "su"; user = Cap(msg, @"user (?<u>\S+)"); }
        else if (proc.StartsWith("useradd")) { type = "useradd"; user = Cap(msg, @"name=(?<u>\S+?),"); }
        else if (proc.StartsWith("usermod")) type = "usermod";
        else if (proc.StartsWith("groupadd")) type = "groupadd";
        if (msg.Contains("authorized_keys") || msg.Contains("Found matching")) type ??= "new-ssh-key";

        return type is null ? null : new AuthEvent { Time = time, Type = type, User = user, SourceIp = ip, Raw = line.Trim() };
    }

    private static string? Cap(string s, string pattern) =>
        Regex.Match(s, pattern) is { Success: true } m ? m.Groups["u"].Value : null;

    // Parse "MMM d HH:mm:ss" (no year). Attach the most plausible year: this year, or last year if that would put
    // the date in the future (logs near a year boundary). Approximate, used only for ordering.
    private static DateTime? ParseSyslogTime(string ts)
    {
        ts = Regex.Replace(ts.Trim(), @"\s+", " ");
        foreach (var y in new[] { DateTime.UtcNow.Year, DateTime.UtcNow.Year - 1 })
            if (DateTime.TryParseExact($"{ts} {y}", "MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt) && dt <= DateTime.UtcNow.AddDays(1))
                return dt;
        return null;
    }
    #endregion
}
