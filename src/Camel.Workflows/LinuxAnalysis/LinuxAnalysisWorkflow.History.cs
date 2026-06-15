namespace Camel.Workflows;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

public partial class LinuxAnalysisWorkflow
{
    /// <summary>
    /// Reviews every user's shell history (bash/zsh/python) on a mounted root and flags commands matching the
    /// attacker tradecraft categories — reconnaissance, tool download, privilege escalation, persistence,
    /// lateral movement / C2, and anti-forensic cleanup. Returns the flagged commands (with the categories they
    /// matched and a timestamp when the history carried one) plus totals.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c>.</param>
    public async Task<WorkflowResult<ShellHistoryReport>> AnalyzeShellHistoryAsync(string rootDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing Linux shell history under {0}", rootDir);

        var entries = await LinuxAnalysis.ShellHistoryAsync(rootDir);
        if (entries is null)
            return WorkflowResult<ShellHistoryReport>.Failure(
                $"No readable shell history under '{rootDir}' (looked under home/ and root/).");

        var suspicious = new List<SuspiciousCommand>();
        foreach (var e in entries)
        {
            var cats = HistorySignatures.Where(s => s.Re.IsMatch(e.Command)).Select(s => s.Category).Distinct().ToArray();
            if (cats.Length > 0)
                suspicious.Add(new SuspiciousCommand
                {
                    User = e.User, Command = e.Command, Categories = cats, Timestamp = e.Timestamp, HistoryFile = e.HistoryFile,
                });
        }

        op.Complete();
        var report = new ShellHistoryReport
        {
            TotalLines = entries.Length,
            UsersWithHistory = entries.Select(e => e.User).Distinct().Count(),
            Suspicious = suspicious
                .OrderByDescending(c => c.Categories.Length)
                .ThenByDescending(c => c.Timestamp ?? DateTime.MinValue)
                .ToArray(),
        };
        return WorkflowResult<ShellHistoryReport>.Success(report,
            $"{entries.Length} history line(s) across {report.UsersWithHistory} user(s); flagged {suspicious.Count} command(s)." +
            (suspicious.Count == 0 ? "" : " e.g. " + string.Join("; ", report.Suspicious.Take(3).Select(c => $"{c.User}: {Truncate(c.Command, 60)} [{string.Join(",", c.Categories)}]"))));
    }

    // (category, regex). Compact, high-signal attacker patterns matched against each history command.
    private static readonly (string Category, Regex Re)[] HistorySignatures =
    [
        ("recon", new Regex(@"\b(uname|whoami|\bid\b|hostname|ifconfig|ip a|netstat|\bss\b|lsb_release|sudo -l|crontab -l)\b", RegexOptions.Compiled)),
        ("recon", new Regex(@"cat\s+/etc/(passwd|shadow|os-release)|find\s+/.*-perm", RegexOptions.Compiled)),
        ("download", new Regex(@"\b(wget|curl|scp|tftp|ftpget|git clone)\b", RegexOptions.Compiled)),
        ("privesc", new Regex(@"\b(sudo|su|pkexec)\b|chmod\s+[+]?s|chmod\s+[0-7]*4[0-7]{3}|setcap", RegexOptions.Compiled)),
        ("persistence", new Regex(@"crontab|systemctl\s+enable|authorized_keys|>>?\s*~?/?\.(bashrc|profile)|/etc/rc\.local|useradd|adduser", RegexOptions.Compiled)),
        ("lateral-c2", new Regex(@"\bn(c|cat)\b|/dev/tcp/|socat|bash\s+-i|msfvenom|meterpreter|reverse|/dev/udp/", RegexOptions.Compiled)),
        ("cleanup", new Regex(@"history\s+-c|>\s*~?/?\.bash_history|unset\s+HISTFILE|shred|rm\s+-rf\s+/|truncate", RegexOptions.Compiled)),
        ("credaccess", new Regex(@"cat\s+.*\.ssh/|cat\s+.*id_rsa|mysql\s+.*-p|mimipenguin|/etc/shadow", RegexOptions.Compiled)),
    ];
}
