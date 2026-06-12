using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Training;
using Camel.Inference;

namespace Camel.Tests.Training;

public class AnomalyToolkitTests
{
    [Fact]
    public void TriageRecoversAndRanksThePlantedEvent()
    {
        var events = Enumerable.Range(0, 80).Select(i => Evtx(i, 4624))
            .Append(Evtx(80, 1102))                                  // a never-seen log-clear
            .ToArray();

        var report = new AnomalyDetectionToolkit().Triage(events, budget: 10);

        Assert.Equal(81, report.TotalEvents);
        Assert.True(report.Shortlist.Length <= 10);
        Assert.Contains(report.Shortlist, s => s.MemberIndices.Contains(80));   // the 1102 surfaced
    }

    [Fact]
    public void TriageTimelineCanonicalizesRawPlasoEventsThenTriages()
    {
        // Raw Plaso-style events: a wall of routine logons + one log-clear; the façade canonicalizes then triages.
        var raw = new List<TimelineEvent>();
        for (int i = 1; i <= 200; i++) raw.Add(Raw(i, "[4624 / 0x1210] An account was logged on"));
        raw.Add(Raw(201, "[1102 / 0x044e] The audit log was cleared"));

        var report = new AnomalyDetectionToolkit().TriageTimeline(raw, budget: 10);

        Assert.True(report.TotalEvents == 201);
        Assert.NotEmpty(report.Shortlist);
        Assert.Contains(report.Shortlist, s => s.Token == "evtx:1102");
    }

    [Fact]
    public void SummarizeRendersCompressionDetectorsAndTopItems()
    {
        var events = Enumerable.Range(0, 80).Select(i => Evtx(i, 4624)).Append(Evtx(80, 1102)).ToArray();
        var report = new AnomalyDetectionToolkit().Triage(events, budget: 10);

        var text = new AnomalyDetectionToolkit().Summarize(report, topN: 5);

        Assert.Contains("worth review", text);
        Assert.Contains("Detectors firing:", text);
        Assert.Contains("rare-type", text);          // the 1102 is flagged by the rare-type detector
    }

    private static CanonicalEvent Evtx(long ts, int id) =>
        new() { Ts = ts, DataType = "windows:evtx:record", Source = SourceClass.EventLog, EventId = id };
    private static TimelineEvent Raw(long ts, string message) =>
        new() { Timestamp = ts, DataType = "windows:evtx:record", TimestampDesc = "Creation Time", Message = message };
}
