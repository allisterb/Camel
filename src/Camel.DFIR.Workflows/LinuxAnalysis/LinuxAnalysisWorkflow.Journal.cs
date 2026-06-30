namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

public partial class LinuxAnalysisWorkflow
{
    /// <summary>
    /// Triages the systemd journal on a mounted root (<c>var/log/journal</c>) for security-relevant activity:
    /// <c>sudo</c> usage, SSH daemon events, service starts, and crash/authentication-failure markers. Counts the
    /// categories and returns a capped sample of the notable entries. <paramref name="maxEntries"/> bounds how
    /// many (most-recent) journal records are pulled back for analysis.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c>.</param>
    /// <param name="maxEntries">Cap on journal records to read (most recent). Defaults to 20000.</param>
    public async Task<WorkflowResult<JournalReport>> AnalyzeJournalAsync(string rootDir, int maxEntries = 20000)
    {
        using var _audit = AuditScope();
        var journalDir = Combine(rootDir, "var/log/journal");
        using var op = Begin("Analyzing systemd journal at {0}", journalDir);

        var entries = (await LinuxAnalysis.JournalAsync(journalDir, maxEntries: maxEntries)).Value;
        if (entries is null)
            return WorkflowResult<JournalReport>.Failure(
                $"Could not read the systemd journal at '{journalDir}'; the path may be wrong or the host used syslog only.");

        bool Is(JournalEntry e, string id) => string.Equals(e.Identifier, id, StringComparison.OrdinalIgnoreCase) ||
                                              (e.Unit?.StartsWith(id, StringComparison.OrdinalIgnoreCase) ?? false);

        int sudo = entries.Count(e => Is(e, "sudo"));
        int ssh = entries.Count(e => Is(e, "sshd") || Is(e, "ssh"));
        int starts = entries.Count(e => e.Message.StartsWith("Started ", StringComparison.Ordinal));

        var notable = entries.Where(e =>
                Is(e, "sudo") || Is(e, "sshd") ||
                e.Message.Contains("segfault", StringComparison.OrdinalIgnoreCase) ||
                e.Message.Contains("authentication failure", StringComparison.OrdinalIgnoreCase) ||
                e.Message.Contains("Failed password", StringComparison.OrdinalIgnoreCase) ||
                (e.Priority is <= 3))   // err and above
            .OrderByDescending(e => e.Timestamp ?? DateTime.MinValue)
            .Take(200).ToArray();

        op.Complete();
        var report = new JournalReport
        {
            JournalDir = journalDir,
            TotalEntries = entries.Length,
            SudoEvents = sudo,
            SshEvents = ssh,
            ServiceStarts = starts,
            Notable = notable,
        };
        return WorkflowResult<JournalReport>.Success(report,
            $"Read {entries.Length} journal entry/entries: {sudo} sudo, {ssh} SSH, {starts} service start(s); " +
            $"{notable.Length} notable entry/entries surfaced.");
    }
}
