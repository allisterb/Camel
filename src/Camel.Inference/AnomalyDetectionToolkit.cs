namespace Camel.Inference;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;

/// <summary>
/// The agent-facing façade over the (event_id, Δt) anomaly detectors — the toolkit's product surface. It turns a
/// timeline into a ranked, <em>explained</em> triage shortlist in one call: "given these events and a review budget,
/// which are worth a human's attention, and why." Unlike the SIFT toolkits this is pure computation (no
/// <c>AuditEnvironment</c>): the agent acquires a timeline with the Timeline toolkit, then hands the events here.
///
/// <para>It is label-free and <em>self-baselining</em> by default — the host's own stream defines "normal", so no
/// clean reference is needed — and validated as triage on real intrusion data (SRL-2018: 145,756 events → a
/// ~150-event shortlist recovering 100% of the anti-forensics log-clears and the C2 PowerShell). See
/// <see cref="DetectorEnsemble"/> for the underlying detectors.</para>
/// </summary>
public sealed class AnomalyDetectionToolkit
{
    private readonly DetectorEnsemble ensemble;

    /// <param name="ensemble">The detector suite to run; defaults to <see cref="DetectorEnsemble.Default"/>
    /// (rare type + rare transition + timing burst + timing beacon + suspicious content).</param>
    public AnomalyDetectionToolkit(DetectorEnsemble? ensemble = null) => this.ensemble = ensemble ?? DetectorEnsemble.Default();

    // NOTE (possible future): a threshold cutoff mode as an alternative to the fixed review budget — keep every
    // episode whose total bits exceed t = μ + c·σ of the candidate bits (Studiawan 2020, Ch. 7, which thresholds
    // reconstruction error this way). Caveat: a *global* μ/σ over summed bits is dominated by TimingBurst's huge
    // magnitudes (the same cross-detector incommensurability the per-detector quota in DetectorEnsemble already
    // solves), so it would need to be applied per detector, not globally. The budget cutoff is the validated path.

    /// <summary>Triage a canonical stream against itself (self-baseline) — the single-host "what's worth examining?" case.</summary>
    public TriageReport Triage(CanonicalEvent[] events, int budget = 200) => ensemble.Triage(events, events, budget);

    /// <summary>Triage <paramref name="target"/> against a separate benign <paramref name="baseline"/> stream.</summary>
    public TriageReport Triage(CanonicalEvent[] baseline, CanonicalEvent[] target, int budget = 200) =>
        ensemble.Triage(baseline, target, budget);

    /// <summary>
    /// Canonicalize raw Plaso events (e.g. from <c>Timeline.PsortAsync</c>) and triage them (self-baseline). Pass
    /// <paramref name="highSignalOnly"/> to drop the filesystem-metadata firehose first (see
    /// <see cref="NoiseFilters.KeepHighSignal"/>).
    /// </summary>
    public TriageReport TriageTimeline(IEnumerable<TimelineEvent> rawEvents, int budget = 200, bool highSignalOnly = false) =>
        Triage(EventCanonicalizer.Canonicalize(rawEvents, highSignalOnly ? NoiseFilters.KeepHighSignal : null), budget);

    /// <summary>
    /// A compact, agent/LLM-readable rendering of a triage result: the headline compression, which detectors fired,
    /// and the top <paramref name="topN"/> shortlist entries with their reasons.
    /// </summary>
    public string Summarize(TriageReport report, int topN = 25)
    {
        var byDetector = report.Shortlist
            .SelectMany(i => i.Findings.Select(f => f.Detector))
            .GroupBy(d => d)
            .OrderByDescending(g => g.Count())
            .Select(g => $"{g.Key}×{g.Count()}");

        var lines = new List<string>
        {
            $"Triaged {report.TotalEvents} events → {report.Shortlist.Length} worth review " +
            $"({report.CompressionRatio:P2}; {report.Candidates} candidates flagged).",
            $"Detectors firing: {string.Join(", ", byDetector)}.",
            $"Top {Math.Min(topN, report.Shortlist.Length)}:",
        };
        lines.AddRange(report.Shortlist.Take(topN).Select((s, i) => $"{i + 1,3}. {s}"));
        return string.Join("\n", lines);
    }
}
