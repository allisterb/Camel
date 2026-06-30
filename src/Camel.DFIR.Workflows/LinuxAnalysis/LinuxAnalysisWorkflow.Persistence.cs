namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

public partial class LinuxAnalysisWorkflow
{
    private const int PersistenceSuspiciousThreshold = 3;

    /// <summary>
    /// Hunts Linux persistence mechanisms across a mounted root and scores each by suspicion. Sources covered:
    /// cron (system, per-user, and the <c>cron.{hourly,daily,…}</c> script dirs), admin-added systemd units and
    /// timers (<c>etc/systemd/system</c> and per-user units), <c>rc.local</c>, <c>etc/init.d</c>, shell rc files
    /// (<c>.bashrc</c>/<c>.profile</c>/…), <c>ld.so.preload</c> (LD_PRELOAD rootkit), SSH <c>authorized_keys</c>,
    /// udev <c>RUN+=</c> rules, and the <c>update-motd.d</c> login scripts. Content is scored for the usual
    /// implant tells (execution from <c>/tmp</c>/<c>/dev/shm</c>, base64, download-pipe-to-shell, reverse-shell /
    /// netcat, inline interpreters). Returns every item plus the <see cref="LinuxPersistenceReport.Suspicious"/>
    /// subset.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c>.</param>
    public async Task<WorkflowResult<LinuxPersistenceReport>> HuntPersistenceAsync(string rootDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Hunting Linux persistence under {0}", rootDir);

        var items = new List<PersistenceItem>();

        // 1) cron (the toolkit already collects every cron location).
        var cron = (await LinuxAnalysis.CronEntriesAsync(rootDir)).Result ?? [];
        foreach (var c in cron)
        {
            var (bonus, reasons) = ScoreContent(c.Command);
            int baseScore = c.IsReboot ? 2 : (c.Source.Contains("cron.") ? 1 : 1);
            var rs = reasons.ToList();
            if (c.IsReboot) rs.Insert(0, "@reboot trigger");
            items.Add(new PersistenceItem
            {
                Mechanism = c.IsReboot ? "cron-reboot" : (c.Command == c.Source ? "cron-script" : "cron"),
                Source = c.Source, Detail = c.Raw, Score = baseScore + bonus, Reasons = rs.ToArray(),
            });
        }

        // 2) systemd units/timers added under /etc (admin/attacker), plus per-user units. /lib & /usr/lib units
        //    are distro-shipped and excluded to avoid drowning the signal.
        var unitFiles = await LinuxAnalysis.ReadFilesAsync(
        [
            $"{Combine(rootDir, "etc/systemd/system")}/*.service", $"{Combine(rootDir, "etc/systemd/system")}/*.timer",
            $"{Combine(rootDir, "etc/systemd/system")}/*/*.service",
            $"{Combine(rootDir, "root/.config/systemd/user")}/*.service", $"{Combine(rootDir, "home")}/*/.config/systemd/user/*.service",
        ]);
        foreach (var (path, content) in unitFiles)
        {
            var exec = Regex.Match(content, @"^\s*ExecStart\s*=\s*(.+)$", RegexOptions.Multiline);
            var detail = exec.Success ? exec.Groups[1].Value.Trim() : "(no ExecStart)";
            var (bonus, reasons) = ScoreContent(detail);
            items.Add(new PersistenceItem
            {
                Mechanism = path.EndsWith(".timer") ? "systemd-timer" : "systemd-unit",
                Source = path, Detail = detail, Score = 1 + bonus, Reasons = reasons,
            });
        }

        // 3) rc.local & init scripts.
        var rc = await LinuxAnalysis.ReadFilesAsync([Combine(rootDir, "etc/rc.local")]);
        foreach (var (path, content) in rc)
            foreach (var line in ContentLines(content))
            {
                var (bonus, reasons) = ScoreContent(line);
                items.Add(new PersistenceItem { Mechanism = "rc-local", Source = path, Detail = line, Score = 2 + bonus, Reasons = reasons });
            }

        // 4) shell rc / profile — only surface lines that actually score (these files are otherwise benign/noisy).
        var shellRc = await LinuxAnalysis.ReadFilesAsync(
            ShellRcNames.Select(n => $"{Combine(rootDir, "root")}/{n}")
                        .Concat(ShellRcNames.Select(n => $"{Combine(rootDir, "home")}/*/{n}")));
        foreach (var (path, content) in shellRc)
            foreach (var line in ContentLines(content))
            {
                var (bonus, reasons) = ScoreContent(line);
                if (bonus > 0) items.Add(new PersistenceItem { Mechanism = "shell-rc", Source = path, Detail = line, Score = bonus, Reasons = reasons });
            }

        // 5) ld.so.preload — any entry is a strong LD_PRELOAD-rootkit indicator.
        var preload = await LinuxAnalysis.ReadFilesAsync([Combine(rootDir, "etc/ld.so.preload")]);
        foreach (var (path, content) in preload)
            foreach (var line in ContentLines(content))
                items.Add(new PersistenceItem { Mechanism = "ld-preload", Source = path, Detail = line, Score = 4, Reasons = ["global LD_PRELOAD library (rootkit vector)"] });

        // 6) SSH authorized_keys — each trusted key is a potential backdoor.
        var keys = await LinuxAnalysis.ReadFilesAsync(
        [
            $"{Combine(rootDir, "root/.ssh")}/authorized_keys", $"{Combine(rootDir, "root/.ssh")}/authorized_keys2",
            $"{Combine(rootDir, "home")}/*/.ssh/authorized_keys", $"{Combine(rootDir, "home")}/*/.ssh/authorized_keys2",
        ]);
        foreach (var (path, content) in keys)
            foreach (var line in ContentLines(content))
            {
                var reasons = new List<string> { "authorized SSH key" };
                int score = 2;
                if (line.Contains("command=")) { reasons.Add("forced-command key"); score++; }
                items.Add(new PersistenceItem { Mechanism = "authorized-key", Source = path, Detail = Truncate(line, 100), Score = score, Reasons = reasons.ToArray() });
            }

        // 7) udev rules that run a program, and update-motd.d login scripts.
        var udev = await LinuxAnalysis.ReadFilesAsync([$"{Combine(rootDir, "etc/udev/rules.d")}/*"]);
        foreach (var (path, content) in udev)
            foreach (var line in ContentLines(content).Where(l => l.Contains("RUN")))
            {
                var (bonus, reasons) = ScoreContent(line);
                items.Add(new PersistenceItem { Mechanism = "udev", Source = path, Detail = line, Score = 3 + bonus, Reasons = reasons.Prepend("udev RUN+= rule").ToArray() });
            }
        var motd = await LinuxAnalysis.ReadFilesAsync([$"{Combine(rootDir, "etc/update-motd.d")}/*"]);
        foreach (var (path, content) in motd)
        {
            var (bonus, reasons) = ScoreContent(content);
            items.Add(new PersistenceItem { Mechanism = "motd", Source = path, Detail = "(login-time script)", Score = 1 + bonus, Reasons = reasons });
        }

        var suspicious = items.Where(i => i.Score >= PersistenceSuspiciousThreshold)
            .OrderByDescending(i => i.Score).ToArray();

        op.Complete();
        var report = new LinuxPersistenceReport { Items = items.ToArray(), Suspicious = suspicious, TotalItems = items.Count };
        return WorkflowResult<LinuxPersistenceReport>.Success(report,
            $"Collected {items.Count} persistence point(s); {suspicious.Length} scored suspicious. " +
            (suspicious.Length == 0 ? "Nothing stood out." : "Top: " +
                string.Join("; ", suspicious.Take(4).Select(s => $"{s.Mechanism} @ {s.Source} ({string.Join(",", s.Reasons)})")) + "."));
    }

    #region Scoring
    private static readonly string[] ShellRcNames = [".bashrc", ".bash_profile", ".profile", ".bash_login", ".zshrc", ".zprofile"];

    // (regex, points, reason) — content tells of an implant/backdoor, applied to any persistence command/line.
    private static readonly (Regex Re, int Points, string Reason)[] ContentSignatures =
    [
        (new Regex(@"/tmp/|/dev/shm/|/var/tmp/", RegexOptions.Compiled), 2, "runs from a world-writable dir"),
        (new Regex(@"\bbase64\b", RegexOptions.Compiled), 2, "base64-encoded payload"),
        (new Regex(@"(curl|wget)\b[^|]*\|\s*(ba)?sh", RegexOptions.Compiled | RegexOptions.IgnoreCase), 3, "download piped to a shell"),
        (new Regex(@"\bn(c|cat)\b|/dev/tcp/|/dev/udp/", RegexOptions.Compiled), 3, "reverse shell / netcat"),
        (new Regex(@"(python[0-9.]*|perl|ruby|php)\s+-(c|e)\b", RegexOptions.Compiled), 2, "inline interpreter one-liner"),
        (new Regex(@"\beval\b|\bexec\b", RegexOptions.Compiled), 1, "eval/exec"),
        (new Regex(@"chmod\s+[0-7]*[+]?x|chmod\s+777", RegexOptions.Compiled), 1, "makes a file executable"),
        (new Regex(@"\b(0\.0\.0\.0|\d{1,3}(\.\d{1,3}){3}:\d+)\b", RegexOptions.Compiled), 1, "hard-coded network endpoint"),
    ];

    private static (int Bonus, string[] Reasons) ScoreContent(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return (0, []);
        int bonus = 0;
        var reasons = new List<string>();
        foreach (var (re, pts, reason) in ContentSignatures)
            if (re.IsMatch(text)) { bonus += pts; reasons.Add(reason); }
        return (bonus, reasons.ToArray());
    }

    // Non-empty, non-comment lines of a config/script file.
    private static IEnumerable<string> ContentLines(string content) =>
        content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
               .Where(l => l.Length > 0 && !l.StartsWith('#'));
    #endregion
}
