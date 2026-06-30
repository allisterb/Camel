namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;
using Camel.Inference;

/// <summary>
/// Anti-forensics detection over NTFS filesystem metadata (FOR508.5), complementing the event-log/registry
/// detectors. Two techniques, both grounded in the idea that anti-forensics hides activity but cannot erase all
/// traces:
/// <list type="bullet">
/// <item><see cref="DetectTimestompingAsync"/> — flags files whose $STANDARD_INFORMATION timestamps were backdated
/// ($SI&lt;$FN / zeroed sub-seconds, via MFTECmd) and corroborates each against the creation times of its
/// MFT-adjacent records (a backdating-resistant reference).</item>
/// <item><see cref="AnalyzeUsnJournalAsync"/> — triages the USN change journal for bursts of file activity (mass
/// delete = wiping, mass create = staging) and rare file types, reusing the (event_id, Δt) anomaly ensemble.</item>
/// </list>
/// </summary>
public class AntiForensicsAnalysisWorkflow : Workflow
{
    public AntiForensicsAnalysisWorkflow(CamelToolkitsApi api) : base(api) { }

    #region Workflow methods
    /// <summary>
    /// Scans <paramref name="mftFile"/> (an extracted <c>$MFT</c>) for timestomping. MFTECmd flags each record's
    /// $SI-vs-$FN ordering and zeroed sub-seconds; this then corroborates every flagged file against the median
    /// creation time of the in-use files in its <paramref name="neighborWindow"/> adjacent MFT records — because
    /// files created together get sequential MFT slots, a backdated $SI stands out as far from its neighbours'
    /// (harder-to-forge) allocation cluster. Findings are ranked by that deviation.
    /// </summary>
    public async Task<WorkflowResult<TimestompReport>> DetectTimestompingAsync(string mftFile, int neighborWindow = 8)
    {
        using var _audit = AuditScope();
        using var op = Begin("Detecting timestomping in {0}", mftFile);

        var entries = (await WindowsAnalysis.MFTECmdAsync(mftFile)).Result;
        if (entries is null)
            return WorkflowResult<TimestompReport>.Failure($"MFTECmd failed to parse the MFT '{mftFile}'.");

        var findings = BuildTimestompFindings(entries, neighborWindow);
        op.Complete();

        var report = new TimestompReport { MftFile = mftFile, Findings = findings, EntriesScanned = entries.Length };
        return WorkflowResult<TimestompReport>.Success(report,
            findings.Length == 0
                ? $"No timestomping indicators among {entries.Length} MFT entries."
                : $"Flagged {findings.Length} possibly-timestomped file(s) of {entries.Length} entries. Top: " +
                  string.Join("; ", findings.Take(3).Select(f =>
                      f.Path + (f.DeviationHours is { } d ? $" (Δ{d:F0}h vs MFT-neighbours)" : ""))) + ".");
    }

    /// <summary>
    /// Triages the USN change journal <paramref name="usnFile"/> (<c>$UsnJrnl:$J</c>) for anomalous file activity:
    /// the create/delete/rename records are canonicalized as file-system events and run through the anomaly
    /// ensemble, so a volume burst (mass delete = wiping, mass create = staging/exfil) or a rare file type surfaces
    /// as a ranked pivot. Examine a pivot's time in the raw records for the specific update reasons.
    /// </summary>
    public async Task<WorkflowResult<UsnAnomalyReport>> AnalyzeUsnJournalAsync(string usnFile, int budget = 200)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing USN journal {0} for anomalous file activity (budget {1})", usnFile, budget);

        var records = (await WindowsAnalysis.MFTECmdUsnAsync(usnFile)).Result;
        if (records is null)
            return WorkflowResult<UsnAnomalyReport>.Failure($"MFTECmd failed to parse the USN journal '{usnFile}'.");

        var canonical = UsnToCanonical(records);
        if (canonical.Length == 0)
            return WorkflowResult<UsnAnomalyReport>.Failure($"No timestamped USN records to analyze in '{usnFile}'.");

        var triage = new AnomalyDetectionToolkit().Triage(canonical, budget);
        var pivots = triage.Shortlist.Select(i => new TimelineTriagePivot
        {
            Time = i.Time,
            EventType = i.Token,
            Bits = i.TotalBits,
            EventCount = i.Count,
            Reasons = i.Findings.Select(f => f.Reason).ToArray(),
        }).ToArray();

        op.Complete();
        var report = new UsnAnomalyReport { UsnFile = usnFile, Pivots = pivots, RecordsScanned = canonical.Length, Candidates = triage.Candidates };
        return WorkflowResult<UsnAnomalyReport>.Success(report,
            pivots.Length == 0
                ? $"Scanned {canonical.Length} USN record(s); no anomalous file-activity bursts surfaced."
                : $"Scanned {canonical.Length} USN record(s) → {pivots.Length} pivot(s) ({report.CompressionRatio:P2}). Top: " +
                  string.Join("; ", pivots.Take(3).Select(p => $"{p.Time:u} {p.EventType} ({p.EventCount} ev)")) + ".");
    }
    #endregion

    #region Pure logic (unit-tested without a workstation)
    /// <summary>Flags MFT entries with a timestomping indicator and corroborates each against its MFT-neighbour
    /// creation cluster; ordered by descending deviation.</summary>
    internal static TimestompFinding[] BuildTimestompFindings(MFTEntry[] entries, int neighborWindow)
    {
        // Creation time of every in-use, non-directory file, keyed by MFT entry number (the backdating-resistant
        // reference cluster). Last write wins on the rare reused-slot collision.
        var created = new Dictionary<int, DateTime>();
        foreach (var e in entries)
            if (e.InUse && !e.IsDirectory && e.Created0x10 is { } c) created[e.EntryNumber] = c;

        return entries
            .Where(e => !e.IsDirectory && (e.Timestomped || e.uSecZeros))
            .Select(e =>
            {
                var neighbor = NeighborMedianCreated(created, e.EntryNumber, neighborWindow);
                double? dev = e.Created0x10 is { } si && neighbor is { } nb ? Math.Abs((si - nb).TotalHours) : null;
                return new TimestompFinding
                {
                    Path = string.IsNullOrEmpty(e.ParentPath) ? e.FileName : $"{e.ParentPath}/{e.FileName}",
                    SiCreated = e.Created0x10,
                    SiBeforeFn = e.Timestomped,
                    ZeroSubseconds = e.uSecZeros,
                    NeighborCreated = neighbor,
                    DeviationHours = dev,
                };
            })
            .OrderByDescending(f => f.DeviationHours ?? 0)
            .ToArray();
    }

    /// <summary>Converts USN update records into canonical file-system events (Source=FileSystem, "file:ext"
    /// token) so the anomaly detectors can run; the update reason is carried as a label (context, not a feature).
    /// Records without a timestamp are dropped.</summary>
    internal static CanonicalEvent[] UsnToCanonical(IEnumerable<UsnJournalEntry> records) =>
        EventCanonicalizer.Order(records
            .Where(r => r.UpdateTimestamp is not null)
            .Select(r => new CanonicalEvent
            {
                Ts = ToMicros(r.UpdateTimestamp!.Value),
                DataType = "fs:usn",
                Source = SourceClass.FileSystem,
                Ext = NormalizeExt(r.Extension),
                HourOfDay = r.UpdateTimestamp!.Value.ToUniversalTime().Hour,
                Labels = r.UpdateReasons is { Length: > 0 } reason ? [reason] : [],
            }));

    // Median creation time of the in-use files in the ±window MFT records around entryNumber (excluding itself).
    private static DateTime? NeighborMedianCreated(IReadOnlyDictionary<int, DateTime> created, int entryNumber, int window)
    {
        var times = new List<DateTime>();
        for (int n = entryNumber - window; n <= entryNumber + window; n++)
            if (n != entryNumber && created.TryGetValue(n, out var t)) times.Add(t);
        if (times.Count == 0) return null;
        times.Sort();
        return times[times.Count / 2];
    }

    private static long ToMicros(DateTime dt) => (dt.ToUniversalTime().Ticks - DateTime.UnixEpoch.Ticks) / 10;

    private static string? NormalizeExt(string? ext)
    {
        if (string.IsNullOrEmpty(ext)) return null;
        var e = ext.TrimStart('.').ToLowerInvariant();
        return e.Length is > 0 and <= 5 && e.All(char.IsLetterOrDigit) ? e : null;
    }
    #endregion
}
