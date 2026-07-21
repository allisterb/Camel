namespace Camel.Reporting.Model;

/// <summary>
/// Everything the deterministic report generator reads from a baked case directory. The agent produces the narrative
/// (<c>report.md</c>) and the machine data (the CLEF trail, <c>engagement.json</c>, <c>iocs.csv</c>); this loads them
/// so the CLI can render the PDF without any agent involvement — the integrity boundary the design rests on (the
/// compliance content is machine-built, only the narrative is agent-authored).
/// </summary>
public sealed class CaseArtifacts
{
    /// <summary>The case id (the case directory's name).</summary>
    public required string CaseId { get; init; }

    /// <summary>The case root directory.</summary>
    public required string CaseDir { get; init; }

    /// <summary>The parsed engagement authorization block, or null for a DFIR case (no engagement) — the same gate
    /// the viewer uses to decide DFIR vs pen-test rendering.</summary>
    public EngagementView? Engagement { get; init; }

    /// <summary>The full CLEF audit trail as event views (empty if the log is absent).</summary>
    public IReadOnlyList<AuditEvent> Events { get; init; } = [];

    /// <summary>The agent-authored narrative report (<c>reports/report.md</c>), or null if not written yet.</summary>
    public string? ReportMarkdown { get; init; }

    /// <summary>The agent-authored self-assessment (<c>reports/accuracy.md</c>), or null.</summary>
    public string? AccuracyMarkdown { get; init; }

    /// <summary>The machine-readable indicators (<c>reports/iocs.csv</c>) raw text, or null.</summary>
    public string? IocsCsv { get; init; }

    /// <summary>True when an engagement is present — the case is a pen-test, rendered with the STAR / Authorization
    /// &amp; Scope layout; false for DFIR.</summary>
    public bool IsPenTest => Engagement is not null;

    /// <summary>Load every artifact from <paramref name="caseDir"/>. Best-effort: a missing file leaves its property
    /// null/empty rather than throwing, so a partially-written case still bakes a partial report.</summary>
    public static CaseArtifacts Load(string caseDir)
    {
        var full = Path.GetFullPath(caseDir);
        var reports = Path.Combine(full, "reports");
        var logs = Path.Combine(full, "logs");

        // Resolve the CLEF the same way the CLI's ResolveCaseId does: prefer the single audit-*.clef present in
        // logs/ (its filename carries the authoritative case id), falling back to the case directory's name. This
        // keeps the PDF pointed at the right trail even when the directory name and the case id differ.
        var (caseId, clef) = ResolveClef(logs, new DirectoryInfo(full).Name);
        var engagementJson = ReadIfExists(Path.Combine(reports, "authorization", "engagement.json"));

        return new CaseArtifacts
        {
            CaseId = caseId,
            CaseDir = full,
            Engagement = EngagementView.Parse(engagementJson),
            Events = ClefReader.Read(clef),
            ReportMarkdown = ReadIfExists(Path.Combine(reports, "report.md")),
            AccuracyMarkdown = ReadIfExists(Path.Combine(reports, "accuracy.md")),
            IocsCsv = ReadIfExists(Path.Combine(reports, "iocs.csv")),
        };
    }

    // (caseId, clefPath). If exactly one audit-*.clef exists, its filename gives the case id; otherwise the case
    // directory name is the id and the clef is the conventional audit-<id>.clef (which may not exist yet).
    private static (string CaseId, string Clef) ResolveClef(string logsDir, string dirName)
    {
        if (Directory.Exists(logsDir))
        {
            try
            {
                var clefs = Directory.EnumerateFiles(logsDir, "audit-*.clef").ToList();
                if (clefs.Count == 1)
                    return (Path.GetFileNameWithoutExtension(clefs[0])["audit-".Length..], clefs[0]);
            }
            catch { /* fall through to the conventional name */ }
        }
        return (dirName, Path.Combine(logsDir, $"audit-{dirName}.clef"));
    }

    private static string? ReadIfExists(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path) : null; }
        catch { return null; }
    }
}
