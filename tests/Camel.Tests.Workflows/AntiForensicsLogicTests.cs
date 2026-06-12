using System;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Workflows;
using Camel.Inference;

namespace Camel.Tests.Workflows;

/// <summary>Offline unit tests for the pure anti-forensics logic (no workstation): the timestomp flagging +
/// MFT-neighbour corroboration, and the USN-journal → canonical-event conversion feeding the anomaly detectors.</summary>
public class AntiForensicsLogicTests
{
    // --- #3 timestomping ---

    [Fact]
    public void BuildTimestompFindingsFlagsBackdatedAndZeroSubsecondFiles()
    {
        var cluster = new DateTime(2023, 6, 1, 10, 0, 0, DateTimeKind.Utc);
        var entries =
            // A run of normal, in-use files in adjacent MFT records, all created ~together (the neighbour cluster).
            Enumerable.Range(100, 12).Select(n => Mft(n, created: cluster.AddSeconds(n - 100)))
            .Append(Mft(106, created: new DateTime(2010, 1, 1, 0, 0, 0, DateTimeKind.Utc), timestomped: true))  // backdated $SI
            .Append(Mft(500, created: cluster, uSecZeros: true))                                                 // zeroed sub-seconds, isolated
            .Append(Mft(700, created: cluster, timestomped: true, isDir: true))                                  // a directory — excluded
            .ToArray();

        var findings = AntiForensicsAnalysisWorkflow.BuildTimestompFindings(entries, neighborWindow: 8);

        Assert.DoesNotContain(findings, f => f.Path.Contains("700"));               // directory excluded
        var backdated = Assert.Single(findings, f => f.SiBeforeFn && f.SiCreated?.Year == 2010);
        Assert.True(backdated.DeviationHours > 24 * 365, $"backdated file should deviate from its 2023 neighbours: {backdated.DeviationHours}");
        Assert.Equal(2023, backdated.NeighborCreated?.Year);                        // corroborated against the neighbour cluster
        Assert.Contains(findings, f => f.ZeroSubseconds && f.NeighborCreated is null);  // isolated uSecZeros file flagged, no neighbours
        // Ranked by descending deviation — the backdated file is first.
        Assert.Equal(backdated, findings[0]);
    }

    // --- #4 USN journal → anomaly triage ---

    [Fact]
    public void UsnToCanonicalMapsFileEventsAndBurstSurfacesInTriage()
    {
        var t0 = new DateTime(2023, 6, 1, 9, 0, 0, DateTimeKind.Utc);
        // Benign trickle: one varied-extension file op per minute for 20 minutes.
        var benign = Enumerable.Range(0, 20).Select(i =>
            Usn(name: $"doc{i}", ext: new[] { "txt", "log", "dat" }[i % 3], when: t0.AddMinutes(i), reason: "FileCreate|Close"));
        // A wiping burst: 50 .tmp deletes inside ~5 seconds, 10 minutes in.
        var burst = Enumerable.Range(0, 50).Select(i =>
            Usn(name: $"w{i}", ext: "tmp", when: t0.AddMinutes(10).AddMilliseconds(i * 100), reason: "FileDelete|Close"));
        var records = benign.Concat(burst).ToArray();

        var canonical = AntiForensicsAnalysisWorkflow.UsnToCanonical(records);
        Assert.Equal(records.Length, canonical.Length);
        Assert.All(canonical, e => Assert.Equal(SourceClass.FileSystem, e.Source));
        Assert.Contains(canonical, e => EventType.TokenOf(e) == "file:tmp");        // extension → token

        var report = new AnomalyDetectionToolkit().Triage(canonical, budget: 20);
        Assert.NotEmpty(report.Shortlist);
        var top = report.Shortlist[0];
        Assert.Equal("file:tmp", top.Token);                                        // the delete burst is the top pivot
        Assert.Contains(top.Findings, f => f.Detector == "timing-burst");
    }

    private static MFTEntry Mft(int entry, DateTime created, bool timestomped = false, bool uSecZeros = false, bool isDir = false) =>
        new()
        {
            EntryNumber = entry,
            InUse = true,
            IsDirectory = isDir,
            ParentPath = ".",
            FileName = $"file{entry}.dat",
            Created0x10 = created,
            Timestomped = timestomped,
            uSecZeros = uSecZeros,
        };

    private static UsnJournalEntry Usn(string name, string ext, DateTime when, string reason) =>
        new() { Name = $"{name}.{ext}", Extension = ext, UpdateTimestamp = when, UpdateReasons = reason };
}
