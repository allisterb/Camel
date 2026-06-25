namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

public partial class LinuxAnalysisWorkflow
{
    #region Anomalous files
    /// <summary>
    /// Hunts anomalous files on a mounted root: SUID/SGID binaries not on the standard-distro baseline (privilege
    /// escalation), world-writable files in system locations (tampering vector), and executable files staged in
    /// the world-writable scratch dirs <c>/tmp</c>, <c>/dev/shm</c> and <c>/var/tmp</c> (malware staging). Returns
    /// the flagged sets plus the total SUID count for context.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c>.</param>
    public async Task<WorkflowResult<FileAnomalyReport>> HuntAnomalousFilesAsync(string rootDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Hunting anomalous files under {0}", rootDir);

        var setuid = await LinuxAnalysis.SetuidFilesAsync(rootDir);
        if (setuid is null)
            return WorkflowResult<FileAnomalyReport>.Failure(
                $"Could not enumerate SUID files under '{rootDir}'; the path may be wrong or the volume not mounted.");

        // A SUID/SGID file whose basename isn't a known stock setuid binary is the interesting one.
        var suspiciousSetuid = setuid
            .Where(f => !SetuidBaseline.Contains(Basename(f.Path)))
            .OrderByDescending(f => f.Modified ?? DateTime.MinValue).ToArray();

        var worldWritable = (await LinuxAnalysis.WorldWritableFilesAsync(rootDir) ?? [])
            .Where(f => !IsExpectedWorldWritable(f.Path))
            .Take(200).ToArray();

        var tempDirs = new[] { "tmp", "var/tmp", "dev/shm" }.Select(d => Combine(rootDir, d));
        var tempExec = (await LinuxAnalysis.FilesInDirsAsync(tempDirs) ?? [])
            .Where(f => f.IsExecutable)
            .OrderByDescending(f => f.Modified ?? DateTime.MinValue).Take(200).ToArray();

        op.Complete();
        var report = new FileAnomalyReport
        {
            SuspiciousSetuid = suspiciousSetuid,
            TotalSetuid = setuid.Length,
            WorldWritable = worldWritable,
            ExecutablesInTempDirs = tempExec,
        };
        return WorkflowResult<FileAnomalyReport>.Success(report,
            $"{setuid.Length} SUID/SGID file(s) ({suspiciousSetuid.Length} off-baseline), " +
            $"{worldWritable.Length} world-writable system file(s), {tempExec.Length} executable(s) in temp dirs. " +
            (suspiciousSetuid.Length + tempExec.Length == 0 ? "Nothing obviously anomalous." :
                "Notable: " + string.Join("; ", suspiciousSetuid.Concat(tempExec).Take(5).Select(f => f.Path)) + "."));
    }

    private static string Basename(string path) => path.TrimEnd('/').Split('/').LastOrDefault() ?? path;

    // World-writable files are expected (and uninteresting) in scratch/runtime trees — only flag them elsewhere.
    private static bool IsExpectedWorldWritable(string path) =>
        path.Contains("/tmp/") || path.Contains("/var/tmp/") || path.Contains("/dev/shm/") ||
        path.Contains("/run/") || path.Contains("/proc/") || path.Contains("/sys/") || path.Contains("/var/lib/lxcfs/");
    #endregion

    #region Malware scan
    /// <summary>
    /// Scans a target (a mounted root, a user home, a web root, …) for malware with ClamAV and YARA. ClamAV runs
    /// recursively; YARA applies the bundled rules pack (default: the master <c>index.yar</c>). When ClamAV
    /// reports nothing, a note advises confirming the signature database is current (<c>freshclam</c>), since a
    /// SIFT image may ship with an empty DB. Returns the combined matches.
    /// </summary>
    /// <param name="target">Directory (or file) on the mounted volume to scan.</param>
    /// <param name="yaraRulesFile">YARA rules file; defaults to the bundled master index.</param>
    public async Task<WorkflowResult<LinuxMalwareReport>> ScanForMalwareAsync(string target, string? yaraRulesFile = null)
    {
        yaraRulesFile ??= YaraToolkit.RulesRepoPath + "/index.yar";
        using var _audit = AuditScope();
        using var op = Begin("Scanning {0} for Linux malware (ClamAV + YARA)", target);

        // Run the two scanners concurrently.
        var clamT = LinuxAnalysis.ClamScanAsync(target);
        var yaraT = Yara.ScanAsync(yaraRulesFile, target, new YaraOptions { Recurse = true, Timeout = 120, NoFollowSymlinks = true });
        await Task.WhenAll(clamT, yaraT);
        var clam = clamT.Result;
        var yara = yaraT.Result;

        if (clam is null && yara is null)
            return WorkflowResult<LinuxMalwareReport>.Failure(
                $"Both ClamAV and YARA scans of '{target}' failed; check the path exists and the rules file '{yaraRulesFile}'.");

        op.Complete();
        var report = new LinuxMalwareReport
        {
            Target = target,
            ClamMatches = clam ?? [],
            YaraMatches = yara ?? [],
            Note = (clam ?? []).Length == 0 ? "ClamAV reported no detections — confirm the signature DB is current (freshclam)." : null,
        };
        int total = report.ClamMatches.Length + report.YaraMatches.Length;
        return WorkflowResult<LinuxMalwareReport>.Success(report,
            total == 0
                ? $"No ClamAV/YARA detections under '{target}'."
                : $"{report.ClamMatches.Length} ClamAV + {report.YaraMatches.Length} YARA detection(s) under '{target}': " +
                  string.Join("; ", report.ClamMatches.Select(m => $"{m.Path} ({m.Signature})")
                      .Concat(report.YaraMatches.Select(m => $"{m.Target} ({m.Rule})")).Take(5)) + ".");
    }
    #endregion
}
