namespace Camel.Workflows.Models;

using System;

/// <summary>
/// The result of scanning a <c>$MFT</c> for timestomping (FOR508.5 anti-forensics). Each <see cref="TimestompFinding"/>
/// is a file MFTECmd flagged via its $SI-vs-$FN comparison or zeroed sub-seconds, corroborated against the
/// creation times of its MFT-adjacent neighbours (records allocated in quick succession cluster in time, giving a
/// backdating-resistant reference the manipulated $SI can be measured against).
/// </summary>
public record TimestompReport
{
    /// <summary>The $MFT file that was parsed.</summary>
    public required string MftFile { get; init; }

    /// <summary>The flagged files, ordered by descending deviation from their MFT-neighbour creation cluster.</summary>
    public TimestompFinding[] Findings { get; init; } = [];

    /// <summary>Total MFT entries scanned.</summary>
    public int EntriesScanned { get; init; }
}

/// <summary>One file showing a timestomping indicator, with its backdating-resistant corroboration.</summary>
public record TimestompFinding
{
    /// <summary>The file's path (parent path + name).</summary>
    public required string Path { get; init; }

    /// <summary>The $STANDARD_INFORMATION (0x10) creation time — the timestamp an attacker backdates.</summary>
    public DateTime? SiCreated { get; init; }

    /// <summary>MFTECmd's "SI&lt;FN" flag: the $SI creation predates the $FILE_NAME (0x30) creation — a classic
    /// backdating tell, since $FN is harder to alter.</summary>
    public bool SiBeforeFn { get; init; }

    /// <summary>MFTECmd's "uSecZeros" flag: the timestamp's sub-second precision is zeroed (many timestomp tools
    /// write whole-second times).</summary>
    public bool ZeroSubseconds { get; init; }

    /// <summary>Median $SI creation time of the in-use files in MFT-adjacent records (the cluster the file's own
    /// creation should sit near if it weren't backdated), or null when no neighbours had timestamps.</summary>
    public DateTime? NeighborCreated { get; init; }

    /// <summary>|<see cref="SiCreated"/> − <see cref="NeighborCreated"/>| in hours — large values corroborate
    /// backdating (the claimed creation time is far from when its MFT slot was actually allocated).</summary>
    public double? DeviationHours { get; init; }
}

/// <summary>
/// The result of triaging a USN change journal (<c>$UsnJrnl:$J</c>) for anomalous file activity (FOR508.5
/// file-wiping / staging anti-forensics). The journal's create/delete/rename records are canonicalized as
/// file-system events and run through the (event_id, Δt) detectors: <see cref="Pivots"/> surfaces volume bursts
/// (mass delete = wiping, mass create = staging/exfil) and rare file types (e.g. archive extensions of staged
/// exfil). Each pivot's time can be examined in the raw records for the specific update reasons.
/// </summary>
public record UsnAnomalyReport
{
    /// <summary>The USN journal ($J) file that was analyzed.</summary>
    public required string UsnFile { get; init; }

    /// <summary>The ranked anomalous-file-activity pivots (most surprising first), capped at the review budget.</summary>
    public TimelineTriagePivot[] Pivots { get; init; } = [];

    /// <summary>USN records canonicalized and scored.</summary>
    public int RecordsScanned { get; init; }

    /// <summary>Distinct anomalous episodes any detector flagged.</summary>
    public int Candidates { get; init; }

    /// <summary>Shortlist size as a fraction of the records scored.</summary>
    public double CompressionRatio => RecordsScanned > 0 ? (double)Pivots.Length / RecordsScanned : 0;
}
