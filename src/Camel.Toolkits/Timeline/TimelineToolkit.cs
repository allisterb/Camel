namespace Camel.Toolkits;

using System;
using System.Collections.Generic;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class TimelineToolkit : Toolkit
{
    public TimelineToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("Timeline", auditEnvironment, config) { }

    /// <summary>
    /// Installs hayabusa (the Sigma-based EVTX threat-hunting tool) when the latest SIFT image omits it:
    /// the release zip (binary + bundled <c>rules/</c> and <c>config/</c>) is extracted to
    /// <c>/opt/hayabusa</c> and the versioned binary is symlinked to <c>/usr/local/bin/hayabusa</c> so it
    /// resolves its sibling rules directory. No-op when already present. (Plaso ships with SIFT.)
    /// </summary>
    protected override void InstallMissingTools() =>
        InstallZipRelease("hayabusa",
            "https://github.com/Yamato-Security/hayabusa/releases/download/v3.9.0/hayabusa-3.9.0-lin-x64-gnu.zip",
            "/opt/hayabusa", "hayabusa-3.9.0-lin-x64-gnu", "/usr/local/bin/hayabusa");

    /// <summary>
    /// Parses <paramref name="source"/> (a disk image, mounted path, directory, or file) into the Plaso
    /// storage file <paramref name="storageFile"/>. Optionally restrict to a <paramref name="parsers"/>
    /// preset or comma-separated list (e.g. "win7", "winreg,winevtx"). When <paramref name="hash"/> is true,
    /// passes <c>--hashers md5,sha256</c> so MD5 and SHA-256 of each processed source file are computed and
    /// stored on the resulting events (NB: this hashes the parsed input files, not the .plaso output).
    /// Returns true on success.
    /// </summary>
    public bool Log2Timeline(string source, string storageFile, string? parsers = null, bool hash = false, string timezone = "UTC") =>
        ExecuteToolText("Log2Timeline",
            $"-q --status-view none --storage-file {Q(storageFile)}" +
            (parsers is not null ? $" --parsers {parsers}" : "") +
            (hash ? " --hashers md5,sha256" : "") +
            $" --timezone {timezone} {Q(source)}") is not null;

    /// <summary>
    /// Sorts/exports the events in <paramref name="storageFile"/> (one or more .plaso files) as a timeline.
    /// An optional Plaso <paramref name="filter"/> expression narrows the output
    /// (e.g. "date &gt; '2004-01-01 00:00:00' AND message contains 'cmd.exe'").
    /// </summary>
    public TimelineEvent[]? Psort(string storageFile, string? filter = null) =>
        ExecuteToolJsonLinesFile<TimelineEvent>("Psort",
            f => $"-o json_line -w {Q(f)} {Q(storageFile)}" + (filter is not null ? $" {Qd(filter)}" : ""));

    /// <summary>Inspects a .plaso storage file and returns parser hit statistics and the total event count.</summary>
    public PlasoInfo? Pinfo(string storageFile) =>
        ExecuteToolText("Pinfo", $"--output-format json {Q(storageFile)}") is { } o ? PlasoInfo.Parse(o) : null;

    /// <summary>
    /// One-step ingest and export: parses <paramref name="source"/> and returns the timeline events without
    /// a persistent .plaso file. Optionally restrict to a <paramref name="parsers"/> preset/list.
    /// </summary>
    public TimelineEvent[]? Psteal(string source, string? parsers = null, string timezone = "UTC") =>
        ExecuteToolJsonLinesFile<TimelineEvent>("Psteal",
            f => $"--source {Q(source)} -o json_line -w {Q(f)} --status-view none --timezone {timezone}" +
                 (parsers is not null ? $" --parsers {parsers}" : ""));

    /// <summary>
    /// Extracts files from the storage-media image <paramref name="source"/> into <paramref name="outputDir"/>.
    /// Filter by <paramref name="names"/> (glob patterns, comma-separated) and/or <paramref name="extensions"/>
    /// (comma-separated, no dots). Returns true on success.
    /// </summary>
    public bool ImageExport(string source, string outputDir, string? names = null, string? extensions = null) =>
        ExecuteToolText("ImageExport",
            $"-q --write {Q(outputDir)}" +
            (names is not null ? $" --name {Qd(names)}" : "") +
            (extensions is not null ? $" --extension {Qd(extensions)}" : "") +
            $" {Q(source)}") is not null;

    /// <summary>
    /// Runs hayabusa's Sigma-based detection timeline over Windows event logs and returns the alerts.
    /// <paramref name="evtxPath"/> is a single .evtx file, or a directory when <paramref name="directory"/>
    /// is true. <paramref name="minLevel"/> filters by minimum severity (informational, low, medium, high,
    /// critical). Output is always UTC.
    /// </summary>
    public HayabusaAlert[]? HayabusaJsonTimeline(string evtxPath, bool directory = false, string? minLevel = null) =>
        ExecuteToolJsonLinesFile<HayabusaAlert>("Hayabusa",
            f => $"json-timeline {(directory ? "-d" : "-f")} {Q(evtxPath)} -L -o {Q(f)} -w -q -Q -U" +
                 (minLevel is not null ? $" -m {minLevel}" : ""));

    /// <summary>hayabusa computer-metrics: total events per computer name.</summary>
    public ComputerMetric[]? HayabusaComputerMetrics(string evtxPath, bool directory = false) =>
        ExecuteToolCsvFile<ComputerMetric>("Hayabusa",
            f => $"computer-metrics {Src(evtxPath, directory)} -o {Q(f)} -q -Q", ComputerMetric.FromRow);

    /// <summary>hayabusa eid-metrics: event-ID frequency across the logs.</summary>
    public EidMetric[]? HayabusaEidMetrics(string evtxPath, bool directory = false) =>
        ExecuteToolCsvFile<EidMetric>("Hayabusa",
            f => $"eid-metrics {Src(evtxPath, directory)} -o {Q(f)} -q -Q -U", EidMetric.FromRow);

    /// <summary>hayabusa log-metrics: per-evtx-file metadata (events, timestamps, channels, providers).</summary>
    public LogMetric[]? HayabusaLogMetrics(string evtxPath, bool directory = false) =>
        ExecuteToolCsvFile<LogMetric>("Hayabusa",
            f => $"log-metrics {Src(evtxPath, directory)} -o {Q(f)} -q -Q -U", LogMetric.FromRow);

    /// <summary>
    /// hayabusa logon-summary: successful and failed logon records. (hayabusa writes two CSV files from
    /// an output prefix; both are read and combined, each row flagged via <see cref="LogonSummaryEntry.Successful"/>.)
    /// </summary>
    public LogonSummaryEntry[]? HayabusaLogonSummary(string evtxPath, bool directory = false)
    {
        string prefix = "/tmp/camel_ls_" + Guid.NewGuid().ToString("N");
        try
        {
            if (ExecuteToolText("Hayabusa", $"logon-summary {Src(evtxPath, directory)} -o {Q(prefix)} -q -Q -U") is null) return null;
            var list = new List<LogonSummaryEntry>();
            if (ReadCsvFile($"{prefix}-successful.csv", r => LogonSummaryEntry.FromRow(r, true)) is { } s) list.AddRange(s);
            if (ReadCsvFile($"{prefix}-failed.csv", r => LogonSummaryEntry.FromRow(r, false)) is { } f) list.AddRange(f);
            return list.ToArray();
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-f {prefix}-successful.csv {prefix}-failed.csv", out _, false); }
    }

    public override string[] ToolList { get; } =
    [
        "Log2Timeline", "Psort", "Pinfo", "Psteal", "ImageExport", "Hayabusa"
    ];

    // Single-quote a path so spaces survive the shell.
    private static string Q(string path) => $"'{path}'";
    // hayabusa source selector: -f for a single .evtx file, -d for a directory.
    private static string Src(string path, bool directory) => $"{(directory ? "-d" : "-f")} {Q(path)}";
    // Double-quote a value that may itself need single quotes (e.g. psort filter expressions).
    private static string Qd(string value) => $"\"{value}\"";
}
