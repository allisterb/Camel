namespace Camel.DFIR.Toolkits;
using Camel.Toolkits;

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;

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
    /// storage file <paramref name="storageFile"/>. When <paramref name="storageFile"/> already exists, plaso
    /// <em>appends</em> to it — this is how a triage timeline is grown one source at a time (e.g. parse the
    /// event logs, then append a full <c>$MFT</c> bodyfile via <paramref name="parsers"/> = "mactime").
    /// <para>Scope the run for speed (targeted vs. "kitchen sink" timelines):</para>
    /// <list type="bullet">
    /// <item><paramref name="parsers"/> — restrict to a preset or comma-separated list (e.g. "windows",
    /// "winreg,winevtx", "mactime"); a leading "-" negates one (e.g. "win7,-filestat").</item>
    /// <item><paramref name="filterFile"/> — a plaso file-filter (<c>-f</c>): only the listed triage files are
    /// parsed, skipping the rest of the filesystem (the SIFT box ships <c>/usr/share/plaso/filter_windows.yaml</c>).</item>
    /// <item><paramref name="partitions"/> — limit to specific partitions of a multi-volume image
    /// (<c>--partitions</c>, e.g. "1,2" or "all").</item>
    /// <item><paramref name="vssStores"/> — include Volume Shadow Copies (<c>--vss-stores</c>, e.g. "all" or
    /// "1,2"); psort later de-duplicates the overlap. Null leaves plaso's default VSS handling untouched.</item>
    /// </list>
    /// When <paramref name="hash"/> is true, passes <c>--hashers md5,sha256</c> so MD5 and SHA-256 of each
    /// processed source file are computed and stored on the resulting events (NB: this hashes the parsed input
    /// files, not the .plaso output). Returns true on success.
    /// </summary>
    public async Task<bool> Log2TimelineAsync(string source, string storageFile, string? parsers = null, bool hash = false,
        string? filterFile = null, string? partitions = null, string? vssStores = null, string timezone = "UTC")
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(storageFile);   // never write/append the .plaso over evidence
        return await ExecuteToolTextAsync("Log2Timeline",
            $"-q --status-view none --storage-file {Q(storageFile)}" +
            (parsers is not null ? $" --parsers {parsers}" : "") +
            (filterFile is not null ? $" -f {Q(filterFile)}" : "") +
            (partitions is not null ? $" --partitions {partitions}" : "") +
            (vssStores is not null ? $" --vss-stores {vssStores}" : "") +
            (hash ? " --hashers md5,sha256" : "") +
            $" --timezone {timezone} {Q(source)}") is not null;
    }

    /// <summary>
    /// Sorts/exports the events in <paramref name="storageFile"/> (one or more .plaso files) as a timeline.
    /// An optional Plaso <paramref name="filter"/> expression narrows the output by event attributes
    /// (e.g. "date &gt; '2004-01-01 00:00:00'", "data_type contains 'appcompatcache'", "tag contains
    /// 'application_execution'"). NB: <c>message</c> is a formatter-derived field and is <em>not</em> reliably
    /// filterable — use <see cref="PsortSearchAsync"/> to keyword-search the rendered message text.
    /// <para>When <paramref name="slice"/> is set (an ISO-8601 timestamp, e.g. "2012-04-03T22:59:00+00:00"),
    /// psort returns only the events within <paramref name="sliceSize"/> minutes (default 5) either side — a
    /// "pivot point" mini-timeline. Slice and filter can be combined.</para>
    /// </summary>
    public async Task<ToolResult<TimelineEvent[]>> PsortAsync(string storageFile, string? filter = null, string? slice = null, int? sliceSize = null) =>
        Wrap("Psort", "psort", await ExecuteToolJsonLinesFileAsync<TimelineEvent>("Psort",
            f => $"-o json_line -w {Q(f)}" +
                 (slice is not null ? $" --slice {Qd(slice)}" : "") +
                 (sliceSize is not null ? $" --slice_size {sliceSize}" : "") +
                 $" {Q(storageFile)}" + (filter is not null ? $" {Qd(filter)}" : "")));

    /// <summary>
    /// Runs psort's <c>tagging</c> analysis plugin over <paramref name="storageFile"/>, labelling events that
    /// match the rules in <paramref name="taggingFile"/> (the Plaso-shipped <c>tag_windows.txt</c> /
    /// <c>tag_linux.txt</c> / <c>tag_macos.txt</c>). The tags are <em>persisted back into the storage file</em>
    /// (written with <c>-o null</c>, no timeline emitted), so a subsequent <see cref="PsortAsync"/> can filter
    /// on them (<c>"tag contains 'application_execution'"</c>) and each returned event carries its
    /// <see cref="TimelineEvent.Labels"/>. Idempotent in effect — re-tagging re-applies the same labels.
    /// Returns true on success.
    /// </summary>
    public async Task<bool> PsortTagAsync(string storageFile, string taggingFile)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(storageFile);   // tagging rewrites the storage file in place
        return await ExecuteToolTextAsync("Psort",
            $"-q --analysis tagging --tagging-file {Q(taggingFile)} -o null {Q(storageFile)}") is not null;
    }

    /// <summary>
    /// Keyword-searches the <em>rendered</em> timeline of <paramref name="storageFile"/>: psort writes the full
    /// json-line export to a temp file on the workstation, which is then <c>grep -i -E</c>'d for
    /// <paramref name="grepPattern"/> (an extended-regex; case-insensitive) so that only matching events cross
    /// the wire. Unlike a psort attribute filter this searches the whole serialized event including the
    /// human-readable <c>message</c>, making it the right tool for free-text / IOC keyword hunting. An optional
    /// psort <paramref name="filter"/> (e.g. a date range) pre-narrows the export. Returns the matching events,
    /// or null if psort failed.
    /// </summary>
    public async Task<ToolResult<TimelineEvent[]>> PsortSearchAsync(string storageFile, string grepPattern, string? filter = null)
    {
        string file = "/tmp/camel_ts_" + Guid.NewGuid().ToString("N") + ".jsonl";
        try
        {
            if (await ExecuteToolTextAsync("Psort",
                    $"-q -o json_line -w {Q(file)} {Q(storageFile)}" + (filter is not null ? $" {Qd(filter)}" : "")) is null)
                return ToolResult<TimelineEvent[]>.Fail(IsToolAvailable("Psort")
                    ? $"psort command failed on platform '{platform}' (see server log)."
                    : $"psort is not available on platform '{platform}'.");
            // grep server-side so only matching lines transfer. grep exits 1 on no match (empty output) — that
            // is an empty result, not a failure, so we just parse whatever it returned.
            var r = await auditEnvironment.ExecuteCommandAsync("grep", $"-i -E {Qd(grepPattern)} {Q(file)}", false);
            return ParseJsonLines<TimelineEvent>(r.Output);
        }
        finally { try { auditEnvironment.ExecuteCommand("rm", $"-f {file}", out _, false); } catch { } }
    }

    /// <summary>
    /// Like <see cref="PsortAsync"/> but server-side <em>reduced</em> for scale: psort exports json_line on the
    /// workstation, then a small Python pass strips the bulky <c>strings</c>/<c>xml_string</c> payloads and
    /// truncates each rendered <c>message</c> to <paramref name="maxMessageChars"/> before only the slim file
    /// crosses the wire. A full super timeline's json_line export is dominated by the per-event message (rendered
    /// Strings arrays — often well over 0.5&#160;KB/event), so reduction shrinks the transfer roughly 10x while
    /// keeping every field the canonicalization / anomaly pipeline needs: <c>timestamp</c>, <c>timestamp_desc</c>,
    /// <c>data_type</c>, the path (<c>display_name</c>/<c>filename</c>), and enough of the message for the Event-ID
    /// prefix and content keywords. This is what makes triaging a large timeline feasible where
    /// <see cref="PsortAsync"/>'s whole-file transfer would overrun memory. NB: message length is capped at
    /// <paramref name="maxMessageChars"/>, so the content detector's length-outlier signal saturates there (the
    /// keyword signal is unaffected). Requires <c>python3</c> on the workstation (ships with Plaso).
    /// </summary>
    public async Task<ToolResult<TimelineEvent[]>> PsortReducedAsync(string storageFile, string? filter = null, int maxMessageChars = 1024)
    {
        var id = Guid.NewGuid().ToString("N");
        string big = $"/tmp/camel_ts_{id}.jsonl", slim = $"/tmp/camel_ts_{id}.slim.jsonl", script = $"/tmp/camel_reduce_{id}.py";
        string localSlim = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"camel_ts_{id}.slim.jsonl");
        try
        {
            if (await ExecuteToolTextAsync("Psort",
                    $"-q -o json_line -w {Q(big)} {Q(storageFile)}" + (filter is not null ? $" {Qd(filter)}" : "")) is null)
                return ToolResult<TimelineEvent[]>.Fail(IsToolAvailable("Psort")
                    ? $"psort command failed on platform '{platform}' (see server log)."
                    : $"psort is not available on platform '{platform}'.");

            if (!await WriteRemoteTextAsync(script, ReduceScript))
                return ToolResult<TimelineEvent[]>.Fail("Could not stage the server-side timeline reducer script on the workstation.");

            // Reduce server-side: only the slim json (truncated messages, no Strings/xml payloads) is produced.
            var reduced = await auditEnvironment.ExecuteCommandAsync("python3", $"{Q(script)} {Q(big)} {Q(slim)} {maxMessageChars}", false);
            if (!reduced.IsCompleted)
            {
                Error($"Server-side timeline reduction failed for '{storageFile}': {reduced.Output}");
                return ToolResult<TimelineEvent[]>.Fail($"Server-side timeline reduction failed (needs python3 on the workstation).");
            }

            // SCP the slim file down (a binary stream — far faster than capturing a huge file through stdout) and
            // stream-parse it from disk, so neither the wire nor memory holds the whole export at once.
            if (auditEnvironment.GetFileAsLocal(slim, localSlim) is null)
            {
                Error($"Failed to download the reduced timeline '{slim}' from the workstation.");
                return ToolResult<TimelineEvent[]>.Fail($"Failed to download the reduced timeline from the workstation.");
            }
            return ParseJsonLinesFile<TimelineEvent>(localSlim);
        }
        finally
        {
            try { auditEnvironment.ExecuteCommand("rm", $"-f {big} {slim} {script}", out _, false); } catch { }
            try { System.IO.File.Delete(localSlim); } catch { }
        }
    }

    /// <summary>Inspects a .plaso storage file and returns parser hit statistics and the total event count.</summary>
    public async Task<ToolResult<PlasoInfo>> PinfoAsync(string storageFile)
    {
        var o = await ExecuteToolTextAsync("Pinfo", $"--output-format json {Q(storageFile)}");
        if (o is null) return ToolResult<PlasoInfo>.Fail(IsToolAvailable("Pinfo")
            ? $"pinfo command failed on platform '{platform}' (see server log)."
            : $"pinfo is not available on platform '{platform}'.");
        return PlasoInfo.Parse(o);
    }

    /// <summary>
    /// One-step ingest and export: parses <paramref name="source"/> and returns the timeline events without
    /// a persistent .plaso file. Optionally restrict to a <paramref name="parsers"/> preset/list.
    /// </summary>
    public async Task<ToolResult<TimelineEvent[]>> PstealAsync(string source, string? parsers = null, string timezone = "UTC") =>
        Wrap("Psteal", "psteal", await ExecuteToolJsonLinesFileAsync<TimelineEvent>("Psteal",
            f => $"--source {Q(source)} -o json_line -w {Q(f)} --status-view none --timezone {timezone}" +
                 (parsers is not null ? $" --parsers {parsers}" : "")));

    /// <summary>
    /// Extracts files from the storage-media image <paramref name="source"/> into <paramref name="outputDir"/>.
    /// Filter by <paramref name="names"/> (glob patterns, comma-separated) and/or <paramref name="extensions"/>
    /// (comma-separated, no dots). Returns true on success.
    /// </summary>
    public async Task<bool> ImageExportAsync(string source, string outputDir, string? names = null, string? extensions = null)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);   // never extract files onto evidence
        return await ExecuteToolTextAsync("ImageExport",
            $"-q --write {Q(outputDir)}" +
            (names is not null ? $" --name {Qd(names)}" : "") +
            (extensions is not null ? $" --extension {Qd(extensions)}" : "") +
            $" {Q(source)}") is not null;
    }

    /// <summary>
    /// Runs hayabusa's Sigma-based detection timeline over Windows event logs and returns the alerts.
    /// <paramref name="evtxPath"/> is a single .evtx file, or a directory when <paramref name="directory"/>
    /// is true. <paramref name="minLevel"/> filters by minimum severity (informational, low, medium, high,
    /// critical). Output is always UTC.
    /// </summary>
    public async Task<ToolResult<HayabusaAlert[]>> HayabusaJsonTimelineAsync(string evtxPath, bool directory = false, string? minLevel = null) =>
        Wrap("Hayabusa", "hayabusa", await ExecuteToolJsonLinesFileAsync<HayabusaAlert>("Hayabusa",
            f => $"json-timeline {(directory ? "-d" : "-f")} {Q(evtxPath)} -L -o {Q(f)} -w -q -Q -U" +
                 (minLevel is not null ? $" -m {minLevel}" : "")));

    /// <summary>hayabusa computer-metrics: total events per computer name.</summary>
    public async Task<ToolResult<ComputerMetric[]>> HayabusaComputerMetricsAsync(string evtxPath, bool directory = false) =>
        Wrap("Hayabusa", "hayabusa", await ExecuteToolCsvFileAsync<ComputerMetric>("Hayabusa",
            f => $"computer-metrics {Src(evtxPath, directory)} -o {Q(f)} -q -Q", ComputerMetric.FromRow));

    /// <summary>hayabusa eid-metrics: event-ID frequency across the logs.</summary>
    public async Task<ToolResult<EidMetric[]>> HayabusaEidMetricsAsync(string evtxPath, bool directory = false) =>
        Wrap("Hayabusa", "hayabusa", await ExecuteToolCsvFileAsync<EidMetric>("Hayabusa",
            f => $"eid-metrics {Src(evtxPath, directory)} -o {Q(f)} -q -Q -U", EidMetric.FromRow));

    /// <summary>hayabusa log-metrics: per-evtx-file metadata (events, timestamps, channels, providers).</summary>
    public async Task<ToolResult<LogMetric[]>> HayabusaLogMetricsAsync(string evtxPath, bool directory = false) =>
        Wrap("Hayabusa", "hayabusa", await ExecuteToolCsvFileAsync<LogMetric>("Hayabusa",
            f => $"log-metrics {Src(evtxPath, directory)} -o {Q(f)} -q -Q -U", LogMetric.FromRow));

    /// <summary>
    /// hayabusa logon-summary: successful and failed logon records. (hayabusa writes two CSV files from
    /// an output prefix; both are read and combined, each row flagged via <see cref="LogonSummaryEntry.Successful"/>.)
    /// </summary>
    public async Task<ToolResult<LogonSummaryEntry[]>> HayabusaLogonSummaryAsync(string evtxPath, bool directory = false)
    {
        string prefix = "/tmp/camel_ls_" + Guid.NewGuid().ToString("N");
        try
        {
            if (await ExecuteToolTextAsync("Hayabusa", $"logon-summary {Src(evtxPath, directory)} -o {Q(prefix)} -q -Q -U") is null)
                return ToolResult<LogonSummaryEntry[]>.Fail(IsToolAvailable("Hayabusa")
                    ? $"hayabusa command failed on platform '{platform}' (see server log)."
                    : $"hayabusa is not available on platform '{platform}'.");
            var list = new List<LogonSummaryEntry>();
            if (await ReadCsvFileAsync($"{prefix}-successful.csv", r => LogonSummaryEntry.FromRow(r, true)) is { } s) list.AddRange(s);
            if (await ReadCsvFileAsync($"{prefix}-failed.csv", r => LogonSummaryEntry.FromRow(r, false)) is { } f) list.AddRange(f);
            return list.ToArray();
        }
        // Sync cleanup so it runs even if the operation was cancelled.
        finally { auditEnvironment.ExecuteCommand("rm", $"-f {prefix}-successful.csv {prefix}-failed.csv", out _, false); }
    }

    public override string[] ToolList { get; } =
    [
        "Log2Timeline", "Psort", "Pinfo", "Psteal", "ImageExport", "Hayabusa"
    ];

    // Single-quote a path so spaces survive the shell.
    // Writes UTF-8 text to a workstation file via base64 (the payload is alphanumeric, so it survives the shell
    // unescaped — used to drop the reducer script on the box without quoting a multi-line Python source).
    private async Task<bool> WriteRemoteTextAsync(string path, string content)
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(content));
        return (await auditEnvironment.ExecuteCommandAsync("bash", $"-c {Qd($"echo {b64} | base64 -d > {path}")}", false)).IsCompleted;
    }

    // Server-side json_line reducer (args: in, out, max-message-chars). Keeps only the fields the canonical/anomaly
    // pipeline reads and truncates the rendered message, so the slim output is a fraction of the full export.
    private const string ReduceScript =
        """
        import sys, json
        inf, outf, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
        with open(inf) as f, open(outf, 'w') as o:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                m = e.get('message') or ''
                o.write(json.dumps({
                    'timestamp': e.get('timestamp'),
                    'timestamp_desc': e.get('timestamp_desc'),
                    'data_type': e.get('data_type'),
                    'display_name': e.get('display_name'),
                    'filename': e.get('filename'),
                    'message': m[:n],
                }) + '\n')
        """;

    // Wraps a base-helper result (null = the tool was unavailable on the platform OR its command failed) as a
    // ToolResult, naming the tool in the failure reason. The base ExecuteTool* helpers already short-circuit to
    // null without running when the tool is unavailable, so checking availability after the fact picks the message.
    private ToolResult<T[]> Wrap<T>(string toolKey, string label, T[]? r) =>
        r is not null ? r
        : ToolResult<T[]>.Fail(IsToolAvailable(toolKey)
            ? $"{label} command failed on platform '{platform}' (see server log)."
            : $"{label} is not available on platform '{platform}'.");

    private static string Q(string path) => $"'{path}'";
    // hayabusa source selector: -f for a single .evtx file, -d for a directory.
    private static string Src(string path, bool directory) => $"{(directory ? "-d" : "-f")} {Q(path)}";
    // Double-quote a value that may itself need single quotes (e.g. psort filter expressions).
    private static string Qd(string value) => $"\"{value}\"";
}
