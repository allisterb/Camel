using System;
using System.Linq;
using System.Text;

using Camel.Environments;
using Camel.Workflows;
using Camel.DFIR.Workflows;

namespace Camel.Tests.Workflows;

public class TimelineWorkflowTests : TestsRuntime
{
    public TimelineWorkflowTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelToolkitsApi(sshenv, sshconfig);
        workflow = new TimelineAnalysisWorkflow(api);

        // A one-entry mactime bodyfile (all four MACB times = 2010-01-01 00:00:00 UTC). Used as a tiny, fast,
        // deterministic source for the orchestration tests and as the $MFT-append fixture for the triage test —
        // it parses to exactly four events, so psort export and SSH transfer stay near-instant.
        WriteRemoteFile(Bodyfile,
            "0|/camel/probe.txt|99001|r/rrwxrwxrwx|0|0|10|1262304000|1262304000|1262304000|1262304000\n");

        // Two small shared storage files built once and reused by the analysis-layer tests (existence-guarded so
        // the parse cost is paid only on the first test). RegPlaso: the SYSTEM hive via winreg (tags/searches/
        // slices against real registry events). BodyPlaso: the synthetic bodyfile (a deterministic pivot target).
        if (!sshenv.ExecuteCommand("test", $"-f {RegPlaso}", out _, false))
            api.Timeline.Log2TimelineAsync(SystemHive, RegPlaso, parsers: "winreg").GetAwaiter().GetResult();
        if (!sshenv.ExecuteCommand("test", $"-f {BodyPlaso}", out _, false))
            api.Timeline.Log2TimelineAsync(Bodyfile, BodyPlaso, parsers: "mactime").GetAwaiter().GetResult();
    }

    [Fact]
    public async Task CanCreateSuperTimeline()
    {
        const string plaso = "/tmp/camel_wf_super.plaso";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        // Drives the full log2timeline → pinfo → psort orchestration over a tiny source.
        var r = await workflow.CreateSuperTimelineAsync(Bodyfile, plaso, parsers: "mactime");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Equal(plaso, r.Result.StorageFile);
        Assert.NotEmpty(r.Result.Events);
        Assert.True(r.Result.TotalEventsInStorage > 0);
        Assert.Equal(r.Result.Events.Length, r.Result.EventCount);
        // pinfo's artifact mix is surfaced; the bodyfile parser is the only source here.
        Assert.Contains("bodyfile", r.Result.ParserCounts.Keys);
        Assert.Null(r.Result.Filter);                 // no date window requested
        Assert.NotNull(r.Result.Start);
        Assert.True(r.Result.End >= r.Result.Start);  // Start/End bracket the exported events
    }

    [Fact]
    public async Task SuperTimelineDateFilterNarrowsExportedWindow()
    {
        const string plaso = "/tmp/camel_wf_window.plaso";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        // A window far in the future: the storage file still holds every parsed event (pinfo), but psort exports
        // none — proving the date filter is applied to the exported timeline only, not the collection.
        var r = await workflow.CreateSuperTimelineAsync(Bodyfile, plaso, parsers: "mactime", from: "2099-01-01 00:00:00");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.TotalEventsInStorage > 0);   // collection is intact
        Assert.Empty(r.Result.Events);                    // nothing in the requested window
        Assert.NotNull(r.Result.Filter);
        Assert.Contains("2099-01-01", r.Result.Filter);
    }

    [Fact]
    public async Task CreateSuperTimelineFailsForMissingSource()
    {
        const string plaso = "/tmp/camel_wf_missing.plaso";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        var r = await workflow.CreateSuperTimelineAsync("/mnt/dlpc/does_not_exist", plaso, parsers: "winreg");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task CanCreateTriageTimeline()
    {
        const string plaso = "/tmp/camel_wf_triage.plaso";
        const string filter = "/tmp/camel_wf_filter.yaml";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        // A minimal file-filter targeting just the SYSTEM hive still exercises the real file-filter scan over the
        // mounted volume (the SANS filter_windows.yaml is the production default). The 2010 window bounds the psort
        // export to the appended bodyfile entries so the test stays fast, while pinfo still reports the full mix.
        WriteRemoteFile(filter,
            "---\ndescription: Camel test triage filter.\ntype: include\npath_separator: '\\'\npaths:\n- '\\\\Windows\\\\System32\\\\config\\\\SYSTEM'\n");

        var r = await workflow.CreateTriageTimelineAsync(VolumeRoot, plaso, filterFile: filter, mftBodyfile: Bodyfile,
            from: "2009-12-31 00:00:00", to: "2010-01-02 00:00:00");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.Events);                 // the appended bodyfile entries fall in the window
        Assert.True(r.Result.TotalEventsInStorage > 0);
        // Both source classes were collected: the filtered registry hive and the appended bodyfile (MFT) entries.
        Assert.Contains(r.Result.ParserCounts.Keys, k => k.Contains("winreg"));
        Assert.Contains("bodyfile", r.Result.ParserCounts.Keys);
        Assert.True(r.Result.TopParsers.Length > 1);
    }

    [Fact]
    public async Task CanPivotAround()
    {
        // The bodyfile events sit at 2010-01-01 00:00:00 UTC; a ±5-min slice around that pivot returns them.
        var r = await workflow.PivotAroundAsync(BodyPlaso, new DateTimeOffset(2010, 1, 1, 0, 0, 0, TimeSpan.Zero), 5);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.Events);
        Assert.NotNull(r.Result.Filter);
        Assert.Contains("slice", r.Result.Filter);
        // Every returned event is inside the slice window.
        var lo = new DateTimeOffset(2009, 12, 31, 23, 55, 0, TimeSpan.Zero);
        var hi = new DateTimeOffset(2010, 1, 1, 0, 5, 0, TimeSpan.Zero);
        Assert.All(r.Result.Events, e => Assert.InRange(e.Time, lo, hi));
    }

    [Fact]
    public async Task PivotAroundEmptyWindowFarFromAnyEvent()
    {
        // A pivot decades away from any event yields an empty (but successful) slice.
        var r = await workflow.PivotAroundAsync(BodyPlaso, new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero), 5);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result.Events);
    }

    [Fact]
    public async Task CanCategorizeTimeline()
    {
        // The SYSTEM hive's AppCompatCache (shimcache) entries tag as "application_execution" under tag_windows.txt.
        var r = await workflow.CategorizeTimelineAsync(RegPlaso);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.Categories);
        Assert.True(r.Result.TotalTaggedEvents > 0);
        Assert.Contains("application_execution", r.Result.PopulatedCategories);
        // Every event in a category actually carries that category label, and categories are non-empty.
        Assert.All(r.Result.Categories, c =>
        {
            Assert.NotEmpty(c.Events);
            Assert.All(c.Events, e => Assert.Contains(c.Name, e.Labels));
        });
    }

    [Fact]
    public async Task CanSearchTimeline()
    {
        // "appcompatcache" appears in the data_type and rendered message of the shimcache events.
        var r = await workflow.SearchTimelineAsync(RegPlaso, ["appcompatcache"]);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.Matches);
        Assert.Contains("appcompatcache", r.Result.MatchedKeywords);
        // The union is time-ordered.
        var times = r.Result.Matches.Select(e => e.Time).ToArray();
        Assert.True(times.SequenceEqual(times.OrderBy(t => t)));
    }

    [Fact]
    public async Task SearchTimelineNoHitsForAbsentKeyword()
    {
        var r = await workflow.SearchTimelineAsync(RegPlaso, ["zzz_camel_no_such_token_zzz"]);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result.Matches);
        Assert.Empty(r.Result.Hits);
    }

    [Fact]
    public async Task CanDetectTimelinePivots()
    {
        // Security.evtx on the dlpc image yields a handful of Sigma alerts at "low"+. Each becomes a pivot whose
        // slice is carved from the registry super timeline (the alerts' times are parsed and de-duplicated).
        var r = await workflow.DetectTimelinePivotsAsync(RegPlaso, SecurityEvtx, minLevel: "low", maxPivots: 3);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.AlertsConsidered > 0);
        Assert.NotEmpty(r.Result.Pivots);
        Assert.True(r.Result.Pivots.Length <= 3);                 // capped
        Assert.All(r.Result.Pivots, p =>
        {
            Assert.False(string.IsNullOrEmpty(p.Alert.RuleTitle));
            Assert.NotEqual(default, p.PivotTime);                // the alert time parsed
        });
        // Pivots are time-ordered.
        var times = r.Result.Pivots.Select(p => p.PivotTime).ToArray();
        Assert.True(times.SequenceEqual(times.OrderBy(t => t)));
    }

    [Fact]
    public async Task CanTriageTimelineForAnomalousPivots()
    {
        // Auto-discover pivots in the SYSTEM-hive timeline via the (event_id, Δt) detectors — end to end through the
        // real psort → canonicalize → ensemble path (registry events: tokens like reg:run / reg:shimcache).
        var r = await workflow.TriageTimelineAsync(RegPlaso, budget: 50);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Equal(RegPlaso, r.Result.StorageFile);
        Assert.True(r.Result.TotalEvents > 0, "no canonical events scored");
        Assert.True(r.Result.Pivots.Length <= 50);                          // capped at the budget
        // The shortlist is ranked most-surprising-first and each pivot carries a reason an analyst can act on.
        var bits = r.Result.Pivots.Select(p => p.Bits).ToArray();
        Assert.True(bits.SequenceEqual(bits.OrderByDescending(b => b)));
        Assert.All(r.Result.Pivots, p =>
        {
            Assert.False(string.IsNullOrEmpty(p.EventType));
            Assert.NotEmpty(p.Reasons);
        });
    }

    // NOTE: impractical through PsortAsync at this scale — it exports all ~145k events to json_line (~540MB) and
    // cats the whole file back into one CLR string, which is extremely slow / memory-heavy (the same transfer wall
    // that motivated the slim-CSV staging in the anomaly eval). TriageTimelineAsync is fine for moderate timelines;
    // scaling to a full super timeline needs a streaming/sampled export or psort-side reduction (future work).
    [Fact]
    public async Task CanTriageProgramExecutionTimeline()
    {
        // Scope the SYSTEM-hive timeline to the "Evidence of Execution" artifacts (Shimcache is present here) and
        // triage that subset — validates the execution-scoped recipe end to end.
        var r = await workflow.ProgramExecutionTimelineAsync(RegPlaso, budget: 50);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.TotalEvents > 0, "execution scope matched no events (expected Shimcache from the SYSTEM hive)");
        var bits = r.Result.Pivots.Select(p => p.Bits).ToArray();
        Assert.True(bits.SequenceEqual(bits.OrderByDescending(b => b)));   // ranked (vacuously true if none surfaced)
    }

    // Validated 2026-06-12 against the SRL 3-log evtx plaso (lateral-movement scope = event logs + prefetch + lnk):
    // surfaces the attacker's auth/service bursts and rare EID transitions. [Skip] (slow ~2m: reduced export of
    // 145k evtx events; depends on the ad-hoc plaso) — same path as the suite-tested TriageTimelineAsync.
    [Fact(Skip = "one-off real-data validation (~2m, needs /tmp/camel_srl_3logs.plaso); run manually")]
    public async Task HuntsLateralMovementInSrlTimeline()
    {
        var r = await workflow.HuntLateralMovementTimelineAsync("/tmp/camel_srl_3logs.plaso", budget: 200);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.TotalEvents > 0);
        Assert.NotEmpty(r.Result.Pivots);
        System.IO.File.WriteAllText(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "camel_wf_latmov_srl.txt"),
            $"{r.Message}\n" + string.Join("\n", r.Result.Pivots.Take(20).Select(p => $"  [{p.Bits,7:F1}] {p.Time:u} {p.EventType} ×{p.EventCount} — {string.Join("; ", p.Reasons)}")));
    }

    // Validated 2026-06-12 (~2m15s): triage(RegPlaso) → 5 pivots expanded, each ranked + with reasons + a non-empty
    // slice. [Skip] in the suite because each psort --slice re-scans the whole storage (~20s × topPivots); the
    // chaining is thin glue over the (suite-tested) TriageTimelineAsync + (tested) PivotAround/--slice export.
    [Fact(Skip = "slow: psort --slice re-scans storage per pivot (×topPivots); validated one-off, run manually")]
    public async Task CanAutoPivotExpandFromAnomalies()
    {
        // Triage the SYSTEM-hive timeline for anomalies, then expand the top pivots into their ±N-min slices.
        var r = await workflow.AutoPivotExpansionAsync(RegPlaso, budget: 50, topPivots: 5, sliceSizeMinutes: 5);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Equal(RegPlaso, r.Result.StorageFile);
        Assert.True(r.Result.TotalEvents > 0);
        Assert.True(r.Result.Pivots.Length <= 5);                          // capped at topPivots
        Assert.Equal(5, r.Result.SliceSizeMinutes);
        // Expanded pivots stay ranked by anomaly score, each carries its triggering anomaly, and the slice around a
        // real pivot contains at least the pivot event itself.
        var bits = r.Result.Pivots.Select(p => p.Pivot.Bits).ToArray();
        Assert.True(bits.SequenceEqual(bits.OrderByDescending(b => b)));
        Assert.All(r.Result.Pivots, e => Assert.NotEmpty(e.Pivot.Reasons));
        Assert.Contains(r.Result.Pivots, e => e.SurroundingCount > 0);
    }

    // Validated 2026-06-12 (~2m2s): 145,756 events → 147 pivots (0.10%); top = the attacker's PowerShell 4103
    // bursts (one flagged "2 suspicious keyword(s)" = the squirreldirectory C2) + 4907/4945 audit bursts, with the
    // 1102/104 log-clears surfaced. Works now via PsortReducedAsync (server-side reduce → SCP download → stream
    // parse); ~110s of that is psort's own export. [Skip] in the suite (slow + depends on the ad-hoc 3-log plaso).
    [Fact(Skip = "one-off real-data validation (~2m, needs the staged /tmp/camel_srl_3logs.plaso); run manually")]
    public async Task TriagesRealSrlTimelineEndToEnd()
    {
        // Full workflow over the real compromised host (Security+System+PowerShell, ~145k events): should surface
        // the anti-forensics log-clears (1102/104) and the squirreldirectory C2 PowerShell among the top pivots.
        var r = await workflow.TriageTimelineAsync("/tmp/camel_srl_3logs.plaso", budget: 200);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        System.IO.File.WriteAllText(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "camel_wf_triage_srl.txt"),
            $"{r.Message}\nTotalEvents={r.Result.TotalEvents} Candidates={r.Result.Candidates} Pivots={r.Result.Pivots.Length} Compression={r.Result.CompressionRatio:P2}\n" +
            string.Join("\n", r.Result.Pivots.Take(20).Select(p => $"  [{p.Bits,7:F1}] {p.Time:u} {p.EventType} ×{p.EventCount} — {string.Join("; ", p.Reasons)}")));
        Assert.Contains(r.Result.Pivots, p => p.EventType is "evtx:1102" or "evtx:104");   // log-clears surfaced
    }

    // Writes UTF-8 text to a file on the SIFT box via base64 (avoids shell-escaping the YAML backslashes).
    private void WriteRemoteFile(string path, string content)
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(content));
        Assert.True(sshenv.ExecuteCommand("bash", $"-c \"echo {b64} | base64 -d > {path}\"", out _, false),
            $"failed to write remote fixture {path}");
    }

    // CFREDS Data Leakage PC image, mounted read-only at /mnt/dlpc (a full Windows volume).
    const string VolumeRoot = "/mnt/dlpc";
    const string SystemHive = "/mnt/dlpc/Windows/System32/config/SYSTEM";
    const string SecurityEvtx = "/mnt/dlpc/Windows/System32/winevt/Logs/Security.evtx";
    const string Bodyfile = "/tmp/camel_wf_mft.body";
    const string RegPlaso = "/tmp/camel_wf_reg.plaso";
    const string BodyPlaso = "/tmp/camel_wf_bodyp.plaso";

    AuditEnvironment sshenv;
    CamelToolkitsApi api;
    TimelineAnalysisWorkflow workflow;
}
