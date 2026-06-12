namespace Camel.Training;

/// <summary>
/// Event-keep predicates for <see cref="EventCanonicalizer.Canonicalize(System.Collections.Generic.IEnumerable{Camel.Toolkits.Models.TimelineEvent}, System.Func{CanonicalEvent, bool})"/>.
/// A Plaso super timeline is dominated by filesystem-metadata events (<c>filestat</c> / <c>$UsnJrnl</c>) — on the
/// Studiawan per-action dataset ~80% of every window is this churn (OneDrive sync, temp/log writes), and it is
/// largely the <em>same</em> across actions, so it dilutes any per-window representation. Filtering it out leaves
/// the discriminative "evidence of activity" so the embedder sees what the user actually did.
/// </summary>
public static class NoiseFilters
{
    /// <summary>
    /// Keeps the high-signal "evidence of user activity" source classes — event-log records, registry artifacts,
    /// web history, shortcuts (LNK), and program-execution (prefetch) — and drops the filesystem-metadata firehose
    /// (<see cref="SourceClass.FileSystem"/>) plus generic logs/other. Mirrors how a DFIR analyst filters the
    /// <c>filestat</c> noise out of a super timeline.
    /// </summary>
    public static bool KeepHighSignal(CanonicalEvent e) =>
        e.Source is SourceClass.EventLog or SourceClass.Registry or SourceClass.WebHistory
                 or SourceClass.Lnk or SourceClass.Prefetch;

    /// <summary>Drops only the raw filesystem-metadata stream (filestat/$UsnJrnl), keeping everything else.</summary>
    public static bool DropFilesystemChurn(CanonicalEvent e) => e.Source != SourceClass.FileSystem;
}
