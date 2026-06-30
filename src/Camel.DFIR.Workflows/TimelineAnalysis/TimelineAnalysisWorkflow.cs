namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

using SerilogTimings;

using Camel.Toolkits;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;
using Camel.Inference;

/// <summary>
/// Timeline-creation workflows built on the Plaso toolkit (log2timeline → pinfo → psort), codifying the FOR508
/// "Timeline Analysis Process". Two creation strategies are offered, trading speed against coverage:
/// <list type="bullet">
/// <item><see cref="CreateSuperTimelineAsync"/> — the general orchestrator: parse a source into a .plaso (full
/// "kitchen sink", or scoped by parsers / file-filter / partitions / VSS), validate it with pinfo, then export a
/// sorted, optionally date-windowed timeline with psort.</item>
/// <item><see cref="CreateTriageTimelineAsync"/> — the fast, opinionated triage recipe: drive log2timeline with
/// the SANS Windows file-filter (parse only the key forensic files), optionally appending a full <c>$MFT</c>
/// bodyfile via the <c>mactime</c> parser so the timeline carries every filesystem entry while the rest of the
/// run stays narrow — the FOR508 web-server case-study technique.</item>
/// </list>
/// Both return a <see cref="SuperTimeline"/> whose persistent <see cref="SuperTimeline.StorageFile"/> can be
/// re-filtered cheaply afterwards (psort is near-instant) to carve further mini-timelines around pivot points.
/// </summary>
public class TimelineAnalysisWorkflow : Workflow
{
    public TimelineAnalysisWorkflow(CamelToolkitsApi api) : base(api) { }

    /// <summary>The SANS triage file-filter shipped with Plaso on the SIFT workstation (key Windows forensic files).</summary>
    public const string DefaultWindowsFilterFile = "/usr/share/plaso/filter_windows.yaml";

    /// <summary>The Plaso-shipped Windows tagging-rules file mapping events to the "Evidence of…" categories.</summary>
    public const string DefaultWindowsTagFile = "/usr/share/plaso/tag_windows.txt";

    #region Workflow methods
    /// <summary>
    /// Builds a Plaso super timeline from <paramref name="source"/> (a disk image, mounted volume, directory, or
    /// triage collection) into <paramref name="storageFile"/>, then exports a sorted timeline. The run is scoped
    /// by whichever of the optional parameters are supplied — leaving them all null produces the full
    /// "kitchen sink" timeline:
    /// <list type="bullet">
    /// <item><paramref name="parsers"/> — a Plaso parser preset or list (e.g. "windows", "winreg,winevtx").</item>
    /// <item><paramref name="filterFile"/> — a Plaso file-filter restricting parsing to listed files.</item>
    /// <item><paramref name="partitions"/> / <paramref name="vssStores"/> — limit partitions / include Volume
    /// Shadow Copies of a full image (psort de-duplicates the VSS overlap).</item>
    /// </list>
    /// <paramref name="from"/> / <paramref name="to"/> (UTC "yyyy-MM-dd HH:mm:ss") apply a psort date-range filter
    /// to the <em>exported</em> events only; the storage file always retains everything (re-filter it later for
    /// other windows). pinfo validates the parse and supplies the artifact-mix counts.
    /// </summary>
    public async Task<WorkflowResult<SuperTimeline>> CreateSuperTimelineAsync(
        string source, string storageFile,
        string? parsers = null, string? filterFile = null, string? partitions = null, string? vssStores = null,
        string? from = null, string? to = null, bool hash = false, string timezone = "UTC")
    {
        using var _audit = AuditScope();
        using var op = Begin("Creating super timeline from {0} into {1}", source, storageFile);

        if (!await Timeline.Log2TimelineAsync(source, storageFile, parsers, hash, filterFile, partitions, vssStores, timezone))
            return WorkflowResult<SuperTimeline>.Failure(
                $"log2timeline failed to parse '{source}' into '{storageFile}'. Check the source exists and the " +
                "parser/filter scope is valid.");

        return await FinalizeAsync(op, storageFile, from, to);
    }

    /// <summary>
    /// Fast triage-timeline recipe: drives log2timeline against <paramref name="source"/> with a file-filter
    /// (<paramref name="filterFile"/>, defaulting to the SANS <see cref="DefaultWindowsFilterFile"/>) so only the
    /// key forensic files are parsed — minutes instead of the hours a full image takes. When
    /// <paramref name="mftBodyfile"/> is supplied (a mactime bodyfile produced by
    /// <see cref="Camel.DFIR.Toolkits.WindowsAnalysisToolkit.MFTECmdBodyfileAsync"/> or fls), it is appended into the
    /// same storage file via the Plaso <c>mactime</c> parser — the FOR508 web-server case-study trick that folds a
    /// complete <c>$MFT</c> filesystem timeline into an otherwise targeted run. <paramref name="from"/> /
    /// <paramref name="to"/> apply a psort date-range filter to the exported events.
    /// </summary>
    public async Task<WorkflowResult<SuperTimeline>> CreateTriageTimelineAsync(
        string source, string storageFile,
        string? filterFile = DefaultWindowsFilterFile, string? mftBodyfile = null,
        string? from = null, string? to = null, string timezone = "UTC")
    {
        using var _audit = AuditScope();
        using var op = Begin("Creating triage timeline from {0} into {1}", source, storageFile);

        // Parse the triage files (default parsers, narrowed to the file-filter set).
        if (!await Timeline.Log2TimelineAsync(source, storageFile, filterFile: filterFile, timezone: timezone))
            return WorkflowResult<SuperTimeline>.Failure(
                $"log2timeline failed to parse triage files from '{source}' into '{storageFile}'. " +
                $"Check the source exists and the filter file '{filterFile}' is present.");

        // Optionally fold a full $MFT filesystem timeline into the same storage file (mactime parser appends).
        if (mftBodyfile is not null &&
            !await Timeline.Log2TimelineAsync(mftBodyfile, storageFile, parsers: "mactime", timezone: timezone))
            return WorkflowResult<SuperTimeline>.Failure(
                $"log2timeline failed to append the MFT bodyfile '{mftBodyfile}' (mactime parser) to '{storageFile}'.");

        return await FinalizeAsync(op, storageFile, from, to);
    }

    /// <summary>
    /// Slices a "pivot point" mini-timeline out of <paramref name="storageFile"/>: every event within
    /// <paramref name="sliceSizeMinutes"/> minutes either side of <paramref name="pivot"/> (psort <c>--slice</c>).
    /// This is the core FOR508 analysis move — once a suspicious moment is identified (a created executable, a
    /// logon, a high-fidelity alert), examine its temporal proximity to reconstruct what happened before and
    /// after. The persistent storage file is untouched, so you can pivot repeatedly at near-zero cost.
    /// </summary>
    /// <param name="storageFile">The .plaso to slice (e.g. one built by <see cref="CreateSuperTimelineAsync"/>).</param>
    /// <param name="pivot">The moment to centre the slice on (converted to UTC ISO-8601 for psort).</param>
    /// <param name="sliceSizeMinutes">Minutes either side of the pivot to include (default 5).</param>
    public async Task<WorkflowResult<SuperTimeline>> PivotAroundAsync(string storageFile, DateTimeOffset pivot, int sliceSizeMinutes = 5)
    {
        using var _audit = AuditScope();
        using var op = Begin("Slicing timeline around {0} (±{1} min) in {2}", pivot, sliceSizeMinutes, storageFile);

        var iso = Iso(pivot);
        var events = (await Timeline.PsortAsync(storageFile, slice: iso, sliceSize: sliceSizeMinutes)).Value;
        if (events is null)
            return WorkflowResult<SuperTimeline>.Failure($"psort failed to slice '{storageFile}' around {iso}.");

        var info = (await Timeline.PinfoAsync(storageFile)).Value;
        op.Complete();
        var result = new SuperTimeline
        {
            StorageFile = storageFile,
            Events = events,
            TotalEventsInStorage = info?.TotalEvents ?? 0,
            ParserCounts = info?.ParserCounts ?? new Dictionary<string, long>(),
            Filter = $"slice ±{sliceSizeMinutes}min around {iso}",
        };
        return WorkflowResult<SuperTimeline>.Success(result,
            $"Sliced {events.Length} event(s) within ±{sliceSizeMinutes} min of {iso}" +
            (result.Start is { } s && result.End is { } e ? $" ({s:u} … {e:u})." : "."));
    }

    /// <summary>
    /// Tags <paramref name="storageFile"/> with the Plaso <c>tagging</c> plugin (<paramref name="taggingFile"/>,
    /// defaulting to the shipped <see cref="DefaultWindowsTagFile"/>) and buckets the tagged events into the
    /// methodology's "Evidence of…" categories — the code-mode equivalent of Timeline Explorer's colour-coding.
    /// Tagging is persisted into the storage file, then a single psort pass pulls back every tagged event with its
    /// category labels inline. An event can fall in several categories. Returns the populated
    /// <see cref="CategorizedTimeline"/> (empty categories omitted).
    /// </summary>
    /// <param name="storageFile">The .plaso to tag and categorise.</param>
    /// <param name="taggingFile">The Plaso tagging-rules file (defaults to the Windows tag file).</param>
    /// <param name="categories">Category names to bucket into (defaults to the Windows tag file's full set).</param>
    public async Task<WorkflowResult<CategorizedTimeline>> CategorizeTimelineAsync(
        string storageFile, string taggingFile = DefaultWindowsTagFile, string[]? categories = null)
    {
        categories ??= WindowsTagCategories;

        using var _audit = AuditScope();
        using var op = Begin("Categorizing timeline {0} with {1}", storageFile, taggingFile);

        if (!await Timeline.PsortTagAsync(storageFile, taggingFile))
            return WorkflowResult<CategorizedTimeline>.Failure(
                $"psort tagging failed for '{storageFile}' with tag file '{taggingFile}'.");

        // One pass: pull every event carrying any of the categories — each comes back with its labels inline.
        var filter = string.Join(" OR ", categories.Select(c => $"tag contains '{c}'"));
        var events = (await Timeline.PsortAsync(storageFile, filter)).Value;
        if (events is null)
            return WorkflowResult<CategorizedTimeline>.Failure($"psort failed to export tagged events from '{storageFile}'.");

        var buckets = categories
            .Select(c => new TimelineCategory
            {
                Name = c,
                Events = events.Where(e => e.Labels.Contains(c, StringComparer.OrdinalIgnoreCase)).ToArray(),
            })
            .Where(b => b.Count > 0)
            .OrderByDescending(b => b.Count)
            .ToArray();

        op.Complete();
        var result = new CategorizedTimeline { StorageFile = storageFile, Categories = buckets, TotalTaggedEvents = events.Length };
        return WorkflowResult<CategorizedTimeline>.Success(result,
            buckets.Length == 0
                ? "No events matched any tagging category (no 'Evidence of…' artifacts in this timeline)."
                : $"Tagged {events.Length} event(s) across {buckets.Length} categor(ies): " +
                  string.Join(", ", buckets.Select(b => $"{b.Name}={b.Count}")) + ".");
    }

    /// <summary>
    /// Auto-detects pivot points in a timeline by running hayabusa's Sigma detections over the Windows event logs
    /// at <paramref name="evtxPath"/> and slicing the super timeline in <paramref name="storageFile"/> around each
    /// high-fidelity alert (within <paramref name="sliceSizeMinutes"/> minutes). This automates the
    /// "high-fidelity alert → pivot → examine temporal proximity" loop: every Sigma hit at or above
    /// <paramref name="minLevel"/> becomes a <see cref="TimelinePivot"/> with its surrounding mini-timeline.
    /// Alerts are de-duplicated to one pivot per minute and capped at <paramref name="maxPivots"/>; the slices are
    /// fetched in parallel.
    /// </summary>
    /// <param name="storageFile">The super timeline .plaso to slice (built from the same host's artifacts).</param>
    /// <param name="evtxPath">A single .evtx file, or a directory when <paramref name="evtxDirectory"/> is true.</param>
    /// <param name="evtxDirectory">True when <paramref name="evtxPath"/> is a directory of logs.</param>
    /// <param name="minLevel">Minimum Sigma severity to treat as a pivot (informational/low/medium/high/critical).</param>
    /// <param name="sliceSizeMinutes">Minutes either side of each alert to slice (default 5).</param>
    /// <param name="maxPivots">Cap on the number of distinct pivots to slice (default 20).</param>
    public async Task<WorkflowResult<TimelinePivotReport>> DetectTimelinePivotsAsync(
        string storageFile, string evtxPath, bool evtxDirectory = false, string minLevel = "high",
        int sliceSizeMinutes = 5, int maxPivots = 20)
    {
        using var _audit = AuditScope();
        using var op = Begin("Detecting timeline pivots in {0} from hayabusa alerts on {1}", storageFile, evtxPath);

        var alerts = (await Timeline.HayabusaJsonTimelineAsync(evtxPath, evtxDirectory, minLevel)).Value;
        if (alerts is null)
            return WorkflowResult<TimelinePivotReport>.Failure(
                $"hayabusa failed to scan '{evtxPath}'; check the path and that it points to Windows event log(s).");

        // One pivot per distinct minute (the loudest alert of that minute), earliest first, capped.
        var distinct = alerts
            .Select(a => (Alert: a, Time: ParseTime(a.Timestamp)))
            .Where(x => x.Time is not null)
            .GroupBy(x => new DateTimeOffset(x.Time!.Value.UtcDateTime.AddTicks(-(x.Time.Value.UtcDateTime.Ticks % TimeSpan.TicksPerMinute)), TimeSpan.Zero))
            .Select(g => g.First())
            .OrderBy(x => x.Time)
            .Take(maxPivots)
            .ToArray();

        // Slice the super timeline around each pivot in parallel (independent psort calls).
        var pivots = await Task.WhenAll(distinct.Select(async x =>
        {
            var surrounding = (await Timeline.PsortAsync(storageFile, slice: Iso(x.Time!.Value), sliceSize: sliceSizeMinutes)).Value ?? [];
            return new TimelinePivot { Alert = x.Alert, PivotTime = x.Time!.Value, Surrounding = surrounding };
        }));

        op.Complete();
        var report = new TimelinePivotReport
        {
            StorageFile = storageFile,
            Pivots = pivots.OrderBy(p => p.PivotTime).ToArray(),
            AlertsConsidered = alerts.Length,
            SliceSizeMinutes = sliceSizeMinutes,
        };
        return WorkflowResult<TimelinePivotReport>.Success(report,
            pivots.Length == 0
                ? $"No hayabusa alerts at or above '{minLevel}' on '{evtxPath}' — no pivots detected."
                : $"Detected {pivots.Length} pivot(s) from {alerts.Length} '{minLevel}'+ alert(s): " +
                  string.Join("; ", report.Pivots.Take(5).Select(p => $"{p.PivotTime:u} '{p.Alert.RuleTitle}' ({p.SurroundingCount} ev)")) + ".");
    }

    /// <summary>
    /// Auto-discovers pivot points by triaging the timeline with the label-free (event_id, Δt) anomaly detectors
    /// (Camel.Inference): exports the events from <paramref name="storageFile"/>, canonicalizes them, runs the
    /// <see cref="AnomalyDetectionToolkit"/> ensemble (rare type / rare transition / volume burst / periodic beacon
    /// / suspicious content), and returns the most-surprising episodes as a ranked review shortlist. This answers
    /// the FOR508 "where do I begin to look?" problem when there is no known signature (<see cref="DetectTimelinePivotsAsync"/>)
    /// or keyword (<see cref="SearchTimelineAsync"/>) to start from — the detectors generate the starting points
    /// statistically. Self-baselining: the host's own stream defines "normal".
    /// <para><paramref name="highSignalOnly"/> (default true) drops the filesystem-metadata firehose first (see
    /// <see cref="NoiseFilters.KeepHighSignal"/>), focusing on event-log / registry / web / prefetch / LNK artifacts;
    /// set false to also include filesystem events (e.g. to surface a burst of newly created executables).
    /// <paramref name="filter"/> optionally pre-narrows the psort export (e.g. a date window).</para>
    /// </summary>
    /// <param name="storageFile">The .plaso to triage (e.g. one built by <see cref="CreateTriageTimelineAsync"/>).</param>
    /// <param name="budget">Maximum pivots to return — the analyst's review budget (default 200).</param>
    /// <param name="highSignalOnly">Drop raw filesystem-metadata churn before triaging (default true).</param>
    /// <param name="filter">Optional psort filter applied to the export (e.g. a "date &gt; …" window).</param>
    public async Task<WorkflowResult<TimelineTriageReport>> TriageTimelineAsync(
        string storageFile, int budget = 200, bool highSignalOnly = true, string? filter = null)
    {
        using var _audit = AuditScope();
        using var op = Begin("Triaging timeline {0} for anomalous pivots (budget {1})", storageFile, budget);

        // Reduced export: only the canonical-relevant fields (with truncated messages) cross the wire, so this
        // scales to large super timelines that would overrun PsortAsync's whole-file transfer.
        var events = (await Timeline.PsortReducedAsync(storageFile, filter)).Value;
        if (events is null)
            return WorkflowResult<TimelineTriageReport>.Failure($"psort export/reduction failed for '{storageFile}'.");

        var canonical = EventCanonicalizer.Canonicalize(events, highSignalOnly ? NoiseFilters.KeepHighSignal : null);
        if (canonical.Length == 0)
            return WorkflowResult<TimelineTriageReport>.Failure(
                $"No events to triage from '{storageFile}'" + (highSignalOnly ? " after high-signal filtering (try highSignalOnly: false)." : "."));

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
        var report = new TimelineTriageReport
        {
            StorageFile = storageFile,
            Pivots = pivots,
            TotalEvents = canonical.Length,
            Candidates = triage.Candidates,
        };
        return WorkflowResult<TimelineTriageReport>.Success(report,
            pivots.Length == 0
                ? $"Triaged {canonical.Length} event(s); nothing surfaced above the detectors' thresholds."
                : $"Triaged {canonical.Length} event(s) → {pivots.Length} pivot(s) worth review " +
                  $"({report.CompressionRatio:P2}, {triage.Candidates} candidates). Top: " +
                  string.Join("; ", pivots.Take(3).Select(p => $"{p.Time:u} {p.EventType} [{p.Bits:F0} bits]")) + ".");
    }

    /// <summary>
    /// The full FOR508 analysis loop, automated: <see cref="TriageTimelineAsync"/> surfaces the anomalous pivots,
    /// then the top <paramref name="topPivots"/> are each expanded into their <em>temporal proximity</em> — the
    /// events within <paramref name="sliceSizeMinutes"/> minutes either side (psort <c>--slice</c>, full detail
    /// including the filesystem churn triage filtered out). This turns "where do I begin to look?" (the detectors)
    /// straight into "what happened before and after?" (the slices), so an analyst gets ranked anomalies already
    /// in context. Slices are cheap (a few minutes of events each) and fetched in parallel.
    /// </summary>
    /// <param name="storageFile">The .plaso to triage and slice.</param>
    /// <param name="budget">Triage review budget (anomaly shortlist size) before taking the top pivots.</param>
    /// <param name="topPivots">How many of the top-ranked pivots to expand (default 10).</param>
    /// <param name="sliceSizeMinutes">Minutes either side of each pivot to slice (default 5).</param>
    /// <param name="highSignalOnly">Drop raw filesystem-metadata churn before triaging (default true).</param>
    public async Task<WorkflowResult<AutoPivotReport>> AutoPivotExpansionAsync(
        string storageFile, int budget = 200, int topPivots = 10, int sliceSizeMinutes = 5, bool highSignalOnly = true)
    {
        using var _audit = AuditScope();
        using var op = Begin("Auto-pivot expansion on {0} (top {1} of budget {2}, ±{3} min)", storageFile, topPivots, budget, sliceSizeMinutes);

        var triage = await TriageTimelineAsync(storageFile, budget, highSignalOnly);
        if (!triage.IsSuccess || triage.Result is null)
            return WorkflowResult<AutoPivotReport>.Failure(triage.Message ?? $"Triage failed for '{storageFile}'.");

        var top = triage.Result.Pivots.Take(topPivots).ToArray();

        // Slice the timeline around each pivot in parallel (psort --slice is near-instant; the env throttles concurrency).
        var expanded = await Task.WhenAll(top.Select(async p =>
        {
            var slice = (await Timeline.PsortAsync(storageFile, slice: Iso(p.Time), sliceSize: sliceSizeMinutes)).Value ?? [];
            return new ExpandedPivot { Pivot = p, Surrounding = slice };
        }));

        op.Complete();
        var report = new AutoPivotReport
        {
            StorageFile = storageFile,
            Pivots = expanded.OrderByDescending(e => e.Pivot.Bits).ToArray(),
            TotalEvents = triage.Result.TotalEvents,
            Candidates = triage.Result.Candidates,
            SliceSizeMinutes = sliceSizeMinutes,
        };
        return WorkflowResult<AutoPivotReport>.Success(report,
            expanded.Length == 0
                ? $"Triaged {report.TotalEvents} event(s); no pivots to expand."
                : $"Expanded {expanded.Length} pivot(s) from {report.Candidates} candidates (±{sliceSizeMinutes} min): " +
                  string.Join("; ", report.Pivots.Take(3).Select(e => $"{e.Pivot.Time:u} {e.Pivot.EventType} ({e.SurroundingCount} ev)")) + ".");
    }

    /// <summary>
    /// Triages the <em>lateral-movement</em> view of a timeline: scopes the export to the artifact classes that
    /// carry the FOR508 "Event Logs + File Copy + Execution" signal — Windows event logs (network/RDP/explicit-
    /// credential logons, admin-share access, service installs), prefetch (tool execution), and LNK (file copy) —
    /// then runs the anomaly ensemble over that merged per-host stream. The <see cref="RareTransitionDetector"/> is
    /// what earns its keep here: lateral movement is a <em>sequence</em> of individually-common events (a network
    /// logon, then a service install, then an execution) in an order the host rarely produces, which a per-event
    /// rarity check misses. Reuses <see cref="TriageTimelineAsync"/> over the scoped subset (no re-parse).
    /// </summary>
    public Task<WorkflowResult<TimelineTriageReport>> HuntLateralMovementTimelineAsync(string storageFile, int budget = 200) =>
        TriageTimelineAsync(storageFile, budget, highSignalOnly: true, filter: LateralMovementScope);

    /// <summary>
    /// Triages the <em>program-execution</em> view of a timeline: scopes the export to the "Evidence of Execution"
    /// artifacts — prefetch, Shimcache (AppCompatCache), Amcache, BAM, and UserAssist — then runs the anomaly
    /// ensemble. Here <see cref="RareTypeDetector"/> surfaces never-before-run binaries and
    /// <see cref="TimingBurstDetector"/>/<see cref="TimingBeaconDetector"/> catch off-hours or scripted/periodic
    /// execution. Reuses <see cref="TriageTimelineAsync"/> over the scoped subset (no re-parse).
    /// </summary>
    public Task<WorkflowResult<TimelineTriageReport>> ProgramExecutionTimelineAsync(string storageFile, int budget = 200) =>
        TriageTimelineAsync(storageFile, budget, highSignalOnly: true, filter: ExecutionScope);

    /// <summary>
    /// Keyword/IOC-searches the timeline in <paramref name="storageFile"/> for any of <paramref name="keywords"/>
    /// — the "use keywords to identify pivot points" step. Each keyword is matched (case-insensitively, as a
    /// literal) against the rendered event text including the human-readable message (see
    /// <see cref="Camel.DFIR.Toolkits.TimelineToolkit.PsortSearchAsync"/>), so it finds hits a psort attribute filter
    /// would miss. Results are grouped per keyword and also returned as a de-duplicated, time-ordered union — the
    /// pivot-point shortlist. <paramref name="from"/> / <paramref name="to"/> pre-narrow the search to a window.
    /// </summary>
    /// <param name="storageFile">The .plaso to search.</param>
    /// <param name="keywords">Literal keywords / IOCs to hunt (filenames, IPs, tool names, hashes, …).</param>
    /// <param name="from">Optional UTC lower bound "yyyy-MM-dd HH:mm:ss".</param>
    /// <param name="to">Optional UTC upper bound "yyyy-MM-dd HH:mm:ss".</param>
    public async Task<WorkflowResult<TimelineSearchReport>> SearchTimelineAsync(
        string storageFile, string[] keywords, string? from = null, string? to = null)
    {
        if (keywords is null || keywords.Length == 0)
            return WorkflowResult<TimelineSearchReport>.Failure("No keywords provided to search for.");

        using var _audit = AuditScope();
        using var op = Begin("Searching timeline {0} for {1} keyword(s)", storageFile, keywords.Length);

        var pattern = string.Join("|", keywords.Where(k => !string.IsNullOrEmpty(k)).Select(EscapeEre));
        var filter = BuildDateFilter(from, to);
        var matches = (await Timeline.PsortSearchAsync(storageFile, pattern, filter)).Value;
        if (matches is null)
            return WorkflowResult<TimelineSearchReport>.Failure($"psort keyword search failed for '{storageFile}'.");

        var hits = keywords.Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(k => new TimelineKeywordHits { Keyword = k, Events = matches.Where(e => EventMatchesKeyword(e, k)).ToArray() })
            .Where(h => h.Count > 0)
            .OrderByDescending(h => h.Count)
            .ToArray();

        op.Complete();
        var report = new TimelineSearchReport
        {
            StorageFile = storageFile,
            Hits = hits,
            Matches = matches.OrderBy(e => e.Time).ToArray(),
        };
        return WorkflowResult<TimelineSearchReport>.Success(report,
            matches.Length == 0
                ? $"No timeline events matched any of: {string.Join(", ", keywords)}."
                : $"Found {matches.Length} matching event(s) across {hits.Length} keyword(s): " +
                  string.Join(", ", hits.Select(h => $"{h.Keyword}={h.Count}")) + ".");
    }
    #endregion

    // psort data_type scopes for the investigation-specific triage recipes (data_type is a stored attribute, so it
    // filters reliably — unlike the formatter-derived message). Lateral movement = event logs + execution + file
    // copy; program execution = the "Evidence of Execution" artifact set.
    private const string LateralMovementScope =
        "data_type contains 'evtx' OR data_type contains 'prefetch' OR data_type contains 'lnk'";
    private const string ExecutionScope =
        "data_type contains 'prefetch' OR data_type contains 'appcompatcache' OR data_type contains 'amcache' " +
        "OR data_type contains 'bam' OR data_type contains 'userassist'";

    // The "Evidence of…" categories defined by the Plaso Windows tagging file (tag_windows.txt).
    private static readonly string[] WindowsTagCategories =
    [
        "application_execution", "application_install", "application_update", "application_removal",
        "autorun", "document_open", "document_print", "file_download", "login_attempt", "login_failed",
        "logoff", "session_disconnection", "session_reconnection", "shell_start", "registry_modified",
        "service_new", "task_schedule", "eventlog_cleared", "firewall_change", "name_resolution_timeout",
        "system_start", "system_shutdown", "shutdown", "system_sleep", "system_wake", "time_change",
        "action_success", "job_success",
    ];

    // Formats a moment as the UTC ISO-8601 string psort's --slice expects (e.g. 2012-04-03T22:59:00+00:00).
    private static string Iso(DateTimeOffset t) => t.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture);

    // Tolerantly parses a timestamp string (e.g. a hayabusa alert time) to a UTC-anchored DateTimeOffset.
    private static DateTimeOffset? ParseTime(string? s) =>
        !string.IsNullOrWhiteSpace(s) &&
        DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t)
            ? t : null;

    // True when any rendered field of the event contains the keyword (case-insensitive substring).
    private static bool EventMatchesKeyword(TimelineEvent e, string keyword) =>
        new[] { e.Message, e.Filename, e.DisplayName, e.DataType, e.Parser }
            .Any(s => s is not null && s.Contains(keyword, StringComparison.OrdinalIgnoreCase));

    // Escapes POSIX-ERE metacharacters so a literal keyword is matched verbatim by grep -E.
    private static string EscapeEre(string keyword)
    {
        var sb = new System.Text.StringBuilder(keyword.Length + 8);
        foreach (var c in keyword)
        {
            if (c is '.' or '^' or '$' or '*' or '+' or '?' or '(' or ')' or '[' or ']' or '{' or '}' or '|' or '\\') sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }

    // Shared tail for both creation methods: pinfo-validate the storage file, then psort-export a sorted,
    // optionally date-windowed timeline, and assemble the SuperTimeline result.
    private async Task<WorkflowResult<SuperTimeline>> FinalizeAsync(
        Operation op, string storageFile, string? from, string? to)
    {
        var info = (await Timeline.PinfoAsync(storageFile)).Value;
        if (info is null || info.TotalEvents == 0)
            return WorkflowResult<SuperTimeline>.Failure(
                $"The timeline '{storageFile}' contains no events — the source had no parsable artifacts in scope " +
                "(check the parser/filter selection and that the source is the expected data).");

        var filter = BuildDateFilter(from, to);
        var events = (await Timeline.PsortAsync(storageFile, filter)).Value;
        if (events is null)
            return WorkflowResult<SuperTimeline>.Failure($"psort failed to export events from '{storageFile}'.");

        op.Complete();
        var result = new SuperTimeline
        {
            StorageFile = storageFile,
            Events = events,
            TotalEventsInStorage = info.TotalEvents,
            ParserCounts = info.ParserCounts,
            Filter = filter,
        };
        var top = result.TopParsers.Take(5).Select(kv => $"{kv.Key}={kv.Value}");
        return WorkflowResult<SuperTimeline>.Success(result,
            $"Built timeline '{storageFile}': {info.TotalEvents} event(s) collected" +
            (filter is null ? "" : $", {events.Length} in the requested window") +
            $". Top sources: {string.Join(", ", top)}.");
    }

    // Builds a psort date-range filter from optional UTC bounds, or null when neither is given.
    // psort expects "date > 'YYYY-MM-DD HH:MM:SS' AND date < 'YYYY-MM-DD HH:MM:SS'".
    private static string? BuildDateFilter(string? from, string? to)
    {
        var clauses = new List<string>(2);
        if (!string.IsNullOrWhiteSpace(from)) clauses.Add($"date > '{from}'");
        if (!string.IsNullOrWhiteSpace(to)) clauses.Add($"date < '{to}'");
        return clauses.Count == 0 ? null : string.Join(" AND ", clauses);
    }
}
