namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

/// <summary>
/// Workflows for triaging a <em>mounted Linux root filesystem</em> (a forensic image mounted read-only, or a
/// live root) for compromise. They codify the postmortem Linux DFIR methodology from Bruce Nikkel's
/// <em>Practical Linux Forensics</em> over <see cref="LinuxAnalysisToolkit"/>'s typed extractors, adding the
/// correlation/scoring layer: which account is anomalous, which login is a brute-force, which cron job is
/// persistence. GUI-only and live-acquisition material from the source texts is intentionally excluded.
/// <list type="bullet">
/// <item><see cref="AnalyzeUserAccountsAsync"/> — passwd/shadow/sudoers risk review.</item>
/// <item><see cref="AnalyzeLoginActivityAsync"/> / <see cref="AnalyzeAuthLogAsync"/> — login records + auth log.</item>
/// <item><see cref="HuntPersistenceAsync"/> — cron / systemd / rc / shell-rc / ld.so.preload / SSH keys.</item>
/// <item><see cref="AnalyzeShellHistoryAsync"/> — attacker-pattern commands in shell history.</item>
/// <item><see cref="AnalyzeInstalledPackagesAsync"/> — package inventory + install timeline.</item>
/// <item><see cref="HuntAnomalousFilesAsync"/> / <see cref="ScanForMalwareAsync"/> — SUID/world-writable/temp + ClamAV/YARA.</item>
/// <item><see cref="AnalyzeJournalAsync"/> — systemd journal triage.</item>
/// <item><see cref="TriageHostAsync"/> — runs the key hunts in parallel and rolls up the top findings.</item>
/// </list>
/// </summary>
public partial class LinuxAnalysisWorkflow : Workflow
{
    public LinuxAnalysisWorkflow(CamelToolkitsApi api) : base(api) { }

    #region Orchestrator
    /// <summary>
    /// Triages a whole mounted Linux host in one call: runs the account, login, auth-log, persistence,
    /// shell-history and file-anomaly hunts in parallel over <paramref name="rootDir"/> and rolls up the
    /// highest-signal observations into <see cref="LinuxHostTriageReport.TopFindings"/>. Each sub-report is
    /// included (null when that step could not run), so the agent can drill into any area. The journal and
    /// malware scans are <em>not</em> included here (they are heavier / situational) — call
    /// <see cref="AnalyzeJournalAsync"/> and <see cref="ScanForMalwareAsync"/> directly when wanted.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c> (or <c>/</c> for the live host).</param>
    public async Task<WorkflowResult<LinuxHostTriageReport>> TriageHostAsync(string rootDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Triaging Linux host at {0}", rootDir);

        var system = await LinuxAnalysis.SystemInfoAsync(rootDir);
        // Run the independent hunts concurrently — the environment fans these out fine (see the parallelism memo).
        var accountsT = AnalyzeUserAccountsAsync(rootDir);
        var loginsT = AnalyzeLoginActivityAsync(rootDir);
        var authT = AnalyzeAuthLogAsync(rootDir);
        var persistenceT = HuntPersistenceAsync(rootDir);
        var historyT = AnalyzeShellHistoryAsync(rootDir);
        var filesT = HuntAnomalousFilesAsync(rootDir);
        await Task.WhenAll(accountsT, loginsT, authT, persistenceT, historyT, filesT);

        var accounts = accountsT.Result.Result;
        var logins = loginsT.Result.Result;
        var auth = authT.Result.Result;
        var persistence = persistenceT.Result.Result;
        var history = historyT.Result.Result;
        var files = filesT.Result.Result;

        // Roll up the top findings across every sub-report into a flat, citable list.
        var top = new List<string>();
        if (accounts is not null)
            top.AddRange(accounts.Findings.Select(f => $"[account] {f.Username}: {f.Issue}{(f.Detail is null ? "" : $" — {f.Detail}")}"));
        if (logins is not null)
            top.AddRange(logins.Findings.Select(f => $"[login] {f.Category}: {f.Detail}"));
        if (auth is not null)
            top.AddRange(auth.Findings.Take(10).Select(e => $"[auth] {e.Type}: {(e.User is null ? "" : e.User + " ")}{e.SourceIp}".TrimEnd()));
        if (persistence is not null)
            top.AddRange(persistence.Suspicious.Take(15).Select(p => $"[persistence/{p.Mechanism}] {p.Source}: {Truncate(p.Detail, 120)} ({string.Join(",", p.Reasons)})"));
        if (history is not null)
            top.AddRange(history.Suspicious.Take(15).Select(c => $"[history] {c.User}: {Truncate(c.Command, 120)} ({string.Join(",", c.Categories)})"));
        if (files is not null)
        {
            top.AddRange(files.SuspiciousSetuid.Take(10).Select(f => $"[file/setuid] {f.Path} (mode {f.Mode}, {f.Owner})"));
            top.AddRange(files.ExecutablesInTempDirs.Take(10).Select(f => $"[file/temp-exec] {f.Path}"));
        }

        op.Complete();
        var report = new LinuxHostTriageReport
        {
            System = system,
            Accounts = accounts,
            Logins = logins,
            Auth = auth,
            Persistence = persistence,
            ShellHistory = history,
            Files = files,
            TopFindings = top.ToArray(),
        };
        var host = system?.Hostname ?? rootDir;
        return WorkflowResult<LinuxHostTriageReport>.Success(report,
            $"Triaged Linux host '{host}'" + (system?.PrettyName is { } p ? $" ({p})" : "") +
            $": {top.Count} notable finding(s) across accounts, logins, persistence, history and files. " +
            (top.Count == 0 ? "No obvious compromise indicators surfaced." : "Review TopFindings and the per-area reports."));
    }
    #endregion

    #region Shared helpers
    // Join a mounted-root path with a relative artifact path (mirrors LinuxAnalysisToolkit.Combine).
    private protected static string Combine(string root, string rel) => root.TrimEnd('/') + "/" + rel.TrimStart('/');

    private protected static string Truncate(string? s, int max) =>
        s is null ? "" : s.Length <= max ? s : s[..max] + "…";

    // The standard SUID/SGID binaries shipped by the distro — a SUID file NOT on this baseline is what's worth a
    // look. Matched by basename, case-sensitively. (Intentionally conservative; the goal is to cut the ~30 stock
    // entries, not to be exhaustive across every distro.)
    private protected static readonly HashSet<string> SetuidBaseline = new(StringComparer.Ordinal)
    {
        "sudo", "su", "mount", "umount", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "pkexec", "fusermount",
        "fusermount3", "ping", "ping6", "ssh-agent", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
        "unix_chkpwd", "chage", "expiry", "ntfs-3g", "mount.nfs", "umount.nfs", "sg", "write", "wall", "bwrap",
        "snap-confine", "vmware-user-suid-wrapper",
    };
    #endregion
}
