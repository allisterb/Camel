namespace Camel.DFIR.Toolkits;
using Camel.Toolkits;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;

/// <summary>
/// Typed wrappers for the SIFT network/packet-analysis CLI tools, operating on a capture file (pcap/pcapng).
/// Delivers Wireshark's analytic power head-less via <c>tshark</c> (protocol hierarchy, conversations/endpoints,
/// <c>-T fields</c> extraction, follow-stream, object export), plus <c>capinfos</c>, <c>tcptrace</c>,
/// <c>tcpflow</c>, <c>ngrep</c>, <c>p0f</c>, <c>nfdump</c>, and the <c>suricata</c> signature IDS. The toolkit is
/// the "what's in the capture" layer; hunting/scoring lives in <see cref="Camel.Workflows.PacketAnalysisWorkflow"/>.
/// <para>
/// Provisioning (missing-tool assessment): the base SIFT image ships the Wireshark GUI but not its CLI twin
/// <c>tshark</c>, and no IDS engine. <see cref="InstallMissingTools"/> apt-installs <c>tshark</c> (the workhorse
/// most methods here rely on) and <c>suricata</c> (the maintained successor to the book's Snort) and fetches the
/// Emerging Threats open ruleset. Zeek is deliberately not auto-provisioned (no apt package; an OBS-repo/source
/// build is too heavy) — a future conn/dns/http.log extension.
/// </para>
/// Each data method returns a <see cref="ToolResult{T}"/>: check <c>.Ok</c>, read the payload from <c>.Value</c>,
/// or read why it produced nothing from <c>.FailureReason</c> (tool not installed vs. command failed) — the
/// distinction a bare <c>null</c> used to hide. Grounded in SANS FOR501.2 <em>Packet Analysis</em>.
/// </summary>
public class PacketAnalysisToolkit : Toolkit
{
    public PacketAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null)
        : base("PacketAnalysis", auditEnvironment, config) { }

    public override string[] ToolList { get; } =
        ["Tcpdump", "Tshark", "Capinfos", "Editcap", "Mergecap", "Tcpflow", "Tcptrace", "Ngrep", "Nfdump", "P0f", "Suricata"];

    /// <summary>
    /// Provisions the two tools the SIFT base image lacks: <c>tshark</c> and <c>suricata</c> (+ ET open rules).
    /// Pre-seeds the wireshark-common debconf answer so the tshark install never blocks on the setuid prompt.
    /// Best-effort: a failure here just means those methods return a failed result until the tool is present.
    /// </summary>
    protected override void InstallMissingTools()
    {
        // Avoid the interactive "should non-superusers capture packets?" debconf prompt during tshark install.
        auditEnvironment.ExecuteCommand("bash",
            "-c \"echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections\"", out _, true);
        InstallAptPackage("tshark", "/usr/bin/tshark");
        if (InstallAptPackage("suricata", "/usr/bin/suricata") &&
            !auditEnvironment.ExecuteCommand("test", "-s /var/lib/suricata/rules/suricata.rules", out _, false))
        {
            Info("Fetching Suricata Emerging Threats open ruleset (one-time) ...");
            auditEnvironment.ExecuteCommand("suricata-update", "", out _, true);   // best-effort; runs with default rules otherwise
        }
    }

    #region Capture metadata
    /// <summary>Capture-file metadata via <c>capinfos -M</c> (packets, bytes, duration, time span, hashes).</summary>
    public async Task<ToolResult<PcapInfo>> CapInfoAsync(string pcap, bool sudo = false)
    {
        var res = await RunAsync("Capinfos", $"-M {Q(pcap)}", sudo);
        if (!res.IsSuccess) return ToolResult<PcapInfo>.Fail(res.Message!);
        var o = res.Result!;
        var kv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in Lines(o))
        {
            var i = line.IndexOf(':');
            if (i <= 0) continue;
            var key = line[..i].Trim();
            if (!kv.ContainsKey(key)) kv[key] = line[(i + 1)..].Trim();
        }
        string? g(string k) => kv.TryGetValue(k, out var v) ? v : null;
        return new PcapInfo
        {
            FileName = g("File name"),
            FileType = g("File type"),
            Encapsulation = g("File encapsulation"),
            PacketCount = Num(g("Number of packets")),
            FileSize = Num(g("File size")),
            DataSize = Num(g("Data size")),
            DurationSeconds = Dbl(g("Capture duration")),
            FirstPacketTime = ParseCapTime(g("First packet time")),
            LastPacketTime = ParseCapTime(g("Last packet time")),
            DataByteRate = Dbl(g("Data byte rate")),
            AveragePacketSize = Dbl(g("Average packet size")),
            Sha256 = g("SHA256"),
            Sha1 = g("SHA1"),
        };
    }
    #endregion

    #region tshark statistics
    /// <summary>Protocol-hierarchy tree via <c>tshark -z io,phs</c> (each protocol's frame/byte totals and nesting depth).</summary>
    public async Task<ToolResult<ProtocolLayer[]>> ProtocolHierarchyAsync(string pcap, bool sudo = false)
    {
        var res = await RunAsync("Tshark", $"-n -q -r {Q(pcap)} -z io,phs", sudo);
        if (!res.IsSuccess) return ToolResult<ProtocolLayer[]>.Fail(res.Message!);
        var o = res.Result!;
        var layers = new List<ProtocolLayer>();
        foreach (var line in o.Split('\n'))
        {
            var m = Regex.Match(line.TrimEnd(), @"^(?<indent>\s*)(?<proto>\S+)\s+frames:(?<f>\d+)\s+bytes:(?<b>\d+)$");
            if (!m.Success) continue;
            layers.Add(new ProtocolLayer
            {
                Protocol = m.Groups["proto"].Value,
                Depth = m.Groups["indent"].Value.Length / 2,
                Frames = long.Parse(m.Groups["f"].Value),
                Bytes = long.Parse(m.Groups["b"].Value),
            });
        }
        return layers.ToArray();
    }

    /// <summary>Conversations (flows) via <c>tshark -z conv,&lt;proto&gt;</c> (default tcp). Directional + total
    /// frame/byte counts and duration per endpoint pair. <paramref name="proto"/> is tcp/udp/ip/eth/…</summary>
    public async Task<ToolResult<Conversation[]>> ConversationsAsync(string pcap, string proto = "tcp", bool sudo = false)
    {
        var res = await RunAsync("Tshark", $"-n -q -r {Q(pcap)} -z conv,{proto}", sudo);
        if (!res.IsSuccess) return ToolResult<Conversation[]>.Fail(res.Message!);
        var o = res.Result!;
        var convs = new List<Conversation>();
        foreach (var line in o.Split('\n'))
        {
            if (!line.Contains("<->")) continue;
            // "<epA>  <->  <epB>  <-Frames <-Bytes[unit]  ->Frames ->Bytes[unit]  TotFrames TotBytes[unit]  RelStart  Dur"
            var m = Regex.Match(line.Trim(),
                @"^(?<a>\S+)\s+<->\s+(?<b>\S+)\s+(?<fba>\d+)\s+(?<bba>[\d.]+)\s*(?<uba>bytes|kB|MB|GB)?\s+(?<fab>\d+)\s+(?<bab>[\d.]+)\s*(?<uab>bytes|kB|MB|GB)?\s+(?<ft>\d+)\s+(?<bt>[\d.]+)\s*(?<ut>bytes|kB|MB|GB)?\s+(?<start>[\d.]+)\s+(?<dur>[\d.]+)$");
            if (!m.Success) continue;
            convs.Add(new Conversation
            {
                EndpointA = m.Groups["a"].Value,
                EndpointB = m.Groups["b"].Value,
                FramesBToA = long.Parse(m.Groups["fba"].Value),
                BytesBToA = Si(m.Groups["bba"].Value, m.Groups["uba"].Value),
                FramesAToB = long.Parse(m.Groups["fab"].Value),
                BytesAToB = Si(m.Groups["bab"].Value, m.Groups["uab"].Value),
                TotalFrames = long.Parse(m.Groups["ft"].Value),
                TotalBytes = Si(m.Groups["bt"].Value, m.Groups["ut"].Value),
                RelativeStart = Dbl(m.Groups["start"].Value),
                Duration = Dbl(m.Groups["dur"].Value),
            });
        }
        return convs.ToArray();
    }

    /// <summary>Endpoints (hosts) via <c>tshark -z endpoints,&lt;proto&gt;</c> (default ip) with exact packet/byte
    /// and tx/rx splits.</summary>
    public async Task<ToolResult<Endpoint[]>> EndpointsAsync(string pcap, string proto = "ip", bool sudo = false)
    {
        var res = await RunAsync("Tshark", $"-n -q -r {Q(pcap)} -z endpoints,{proto}", sudo);
        if (!res.IsSuccess) return ToolResult<Endpoint[]>.Fail(res.Message!);
        var o = res.Result!;
        var eps = new List<Endpoint>();
        foreach (var line in o.Split('\n'))
        {
            // "<addr>  Packets Bytes TxPackets TxBytes RxPackets RxBytes" — all plain integers.
            var m = Regex.Match(line.Trim(), @"^(?<addr>\S+)\s+(?<p>\d+)\s+(?<b>\d+)\s+(?<tp>\d+)\s+(?<tb>\d+)\s+(?<rp>\d+)\s+(?<rb>\d+)$");
            if (!m.Success) continue;
            eps.Add(new Endpoint
            {
                Address = m.Groups["addr"].Value,
                Packets = long.Parse(m.Groups["p"].Value), Bytes = long.Parse(m.Groups["b"].Value),
                TxPackets = long.Parse(m.Groups["tp"].Value), TxBytes = long.Parse(m.Groups["tb"].Value),
                RxPackets = long.Parse(m.Groups["rp"].Value), RxBytes = long.Parse(m.Groups["rb"].Value),
            });
        }
        return eps.ToArray();
    }
    #endregion

    #region Packets & fields
    /// <summary>
    /// Per-packet summary rows (the Wireshark column view) via <c>tshark -T fields</c>. Optional
    /// <paramref name="displayFilter"/> is a Wireshark display filter (e.g. <c>"http.request"</c>);
    /// <paramref name="count"/> caps packets read.
    /// </summary>
    public async Task<ToolResult<PacketSummary[]>> ReadPacketsAsync(string pcap, string? displayFilter = null, int? count = null, bool sudo = false)
    {
        var args = $"-n -r {Q(pcap)}" + (count is int c and > 0 ? $" -c {c}" : "") +
                   (displayFilter is not null ? $" -Y {Q(displayFilter)}" : "") +
                   " -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e _ws.col.Info";
        var res = await RunAsync("Tshark", args, sudo);
        if (!res.IsSuccess) return ToolResult<PacketSummary[]>.Fail(res.Message!);
        var o = res.Result!;
        var rows = new List<PacketSummary>();
        foreach (var line in Lines(o))
        {
            var f = line.Split('\t');
            if (f.Length < 6) continue;
            int.TryParse(f[0], out var no);
            int.TryParse(f.Length > 5 ? f[5] : "0", out var len);
            rows.Add(new PacketSummary
            {
                Number = no, Time = Dbl(f[1]),
                Source = NullIfEmpty(f[2]), Destination = NullIfEmpty(f[3]),
                Protocol = NullIfEmpty(f[4]), Length = len,
                Info = f.Length > 6 ? f[6] : null,
            });
        }
        return rows.ToArray();
    }

    /// <summary>
    /// Generic field extractor: runs <c>tshark -T fields</c> with the given Wireshark <paramref name="fields"/>
    /// (e.g. <c>["dns.qry.name","dns.qry.type"]</c>) over packets matching <paramref name="displayFilter"/>, and
    /// returns one <c>string[]</c> per packet (one element per requested field, empty string when absent). This
    /// is the primitive the workflows build their DNS/HTTP/credential hunts on.
    /// </summary>
    public async Task<ToolResult<string[][]>> FieldsAsync(string pcap, string displayFilter, string[] fields, bool sudo = false)
    {
        if (fields.Length == 0) return ToolResult<string[][]>.Pass([]);
        var fieldArgs = string.Join(" ", fields.Select(f => $"-e {f}"));
        var args = $"-n -r {Q(pcap)}" + (string.IsNullOrEmpty(displayFilter) ? "" : $" -Y {Q(displayFilter)}") +
                   $" -T fields {fieldArgs}";
        var res = await RunAsync("Tshark", args, sudo);
        if (!res.IsSuccess) return ToolResult<string[][]>.Fail(res.Message!);
        var o = res.Result!;
        return Lines(o).Select(l =>
        {
            var parts = l.Split('\t');
            // Pad/truncate to the requested field count so callers can index positionally.
            var row = new string[fields.Length];
            for (int i = 0; i < fields.Length; i++) row[i] = i < parts.Length ? parts[i] : "";
            return row;
        }).ToArray();
    }
    #endregion

    #region Streams & objects
    /// <summary>
    /// Reassembles and returns the content of one stream via <c>tshark -z follow,&lt;proto&gt;,ascii,&lt;index&gt;</c>
    /// (proto = tcp/udp/http). <paramref name="index"/> is the stream number (e.g. <c>tcp.stream</c>). The header
    /// banner is stripped; the reassembled payload text is returned.
    /// </summary>
    public async Task<ToolResult<string>> FollowStreamAsync(string pcap, string proto, int index, bool sudo = false)
    {
        var res = await RunAsync("Tshark", $"-n -q -r {Q(pcap)} -z follow,{proto},ascii,{index}", sudo);
        if (!res.IsSuccess) return ToolResult<string>.Fail(res.Message!);
        var o = res.Result!;
        // Drop the banner (up to and including the "Node 1:" line) and the trailing "===" rule.
        var lines = o.Split('\n').ToList();
        int start = lines.FindIndex(l => l.StartsWith("Node 1:", StringComparison.Ordinal));
        var body = (start >= 0 ? lines.Skip(start + 1) : lines)
            .Where(l => !l.StartsWith("===", StringComparison.Ordinal));
        return string.Join("\n", body).Trim();
    }

    /// <summary>
    /// Carves transferred objects of <paramref name="kind"/> (http/smb/tftp/imf/dicom) into
    /// <paramref name="outDir"/> on the workstation via <c>tshark --export-objects</c>, and returns the full paths
    /// of the carved files. The directory is created if missing.
    /// </summary>
    public Task<ToolResult<string[]>> ExportObjectsAsync(string pcap, string kind, string outDir, bool sudo = false) =>
        RunToDirAsync(outDir, sudo, () => RunAsync("Tshark", $"-n -q -r {Q(pcap)} --export-objects {kind},{Q(outDir)}", sudo));

    /// <summary>Reassembles every TCP flow into files under <paramref name="outDir"/> via <c>tcpflow -r -o</c>;
    /// returns the carved flow-file paths.</summary>
    public Task<ToolResult<string[]>> TcpFlowAsync(string pcap, string outDir, bool sudo = false) =>
        RunToDirAsync(outDir, sudo, () => RunAsync("Tcpflow", $"-r {Q(pcap)} -o {Q(outDir)}", sudo));
    #endregion

    #region Other analysers
    /// <summary>Per-connection TCP summary via <c>tcptrace -n</c> (host pairs, packet counts each way, completeness).</summary>
    public async Task<ToolResult<TcpTraceConn[]>> TcpTraceAsync(string pcap, bool sudo = false)
    {
        var res = await RunAsync("Tcptrace", $"-n {Q(pcap)}", sudo);
        if (!res.IsSuccess) return ToolResult<TcpTraceConn[]>.Fail(res.Message!);
        var o = res.Result!;
        var conns = new List<TcpTraceConn>();
        foreach (var line in o.Split('\n'))
        {
            var m = Regex.Match(line,
                @"^\s*\d+:\s+(?<ha>\S+):(?<pa>\d+)\s+-\s+(?<hb>\S+):(?<pb>\d+)\s+\((?<label>\w+)\)\s+(?<ab>\d+)>\s+(?<ba>\d+)<\s*(?<complete>\(complete\))?");
            if (!m.Success) continue;
            conns.Add(new TcpTraceConn
            {
                HostA = m.Groups["ha"].Value, PortA = int.Parse(m.Groups["pa"].Value),
                HostB = m.Groups["hb"].Value, PortB = int.Parse(m.Groups["pb"].Value),
                Label = m.Groups["label"].Value,
                PacketsAToB = int.Parse(m.Groups["ab"].Value), PacketsBToA = int.Parse(m.Groups["ba"].Value),
                Complete = m.Groups["complete"].Success,
            });
        }
        return conns.ToArray();
    }

    /// <summary>
    /// Searches packet payloads with <c>ngrep</c> for the (extended-regex) <paramref name="pattern"/>, optionally
    /// constrained by a BPF <paramref name="bpf"/> filter (e.g. <c>"tcp port 80"</c>). Returns the matching
    /// packets (endpoints + single-line payload).
    /// </summary>
    public async Task<ToolResult<NgrepMatch[]>> NgrepAsync(string pcap, string pattern, string? bpf = null, bool sudo = false)
    {
        var res = await RunAsync("Ngrep", $"-I {Q(pcap)} -q -W single {Q(pattern)}" + (bpf is not null ? $" {Q(bpf)}" : ""), sudo);
        if (!res.IsSuccess) return ToolResult<NgrepMatch[]>.Fail(res.Message!);
        var o = res.Result!;
        var matches = new List<NgrepMatch>();
        NgrepMatch? cur = null; var payload = new StringBuilder();
        void Flush() { if (cur is not null) { matches.Add(cur with { Payload = payload.ToString().Trim() }); cur = null; payload.Clear(); } }
        foreach (var raw in o.Split('\n'))
        {
            var line = raw.TrimEnd();
            var m = Regex.Match(line, @"^(?<proto>[TUI])\s+(?<src>\S+)\s+->\s+(?<dst>\S+)\s+\[(?<flags>[^\]]*)\]\s?(?<payload>.*)$");
            if (m.Success)
            {
                Flush();
                cur = new NgrepMatch { Protocol = m.Groups["proto"].Value, Source = m.Groups["src"].Value, Destination = m.Groups["dst"].Value, Flags = m.Groups["flags"].Value };
                payload.Append(m.Groups["payload"].Value);
            }
            else if (cur is not null && line.Length > 0 && !line.StartsWith("input:") && !line.StartsWith("filter:") && !line.StartsWith("match"))
                payload.Append(line);
            else if (line.Length == 0) Flush();
        }
        Flush();
        return matches.ToArray();
    }

    /// <summary>Passive OS/device fingerprints from <c>p0f -r</c>. Distinct (host, OS) observations.</summary>
    public async Task<ToolResult<P0fRecord[]>> P0fAsync(string pcap, bool sudo = false)
    {
        var res = await RunAsync("P0f", $"-r {Q(pcap)}", sudo);
        if (!res.IsSuccess) return ToolResult<P0fRecord[]>.Fail(res.Message!);
        var o = res.Result!;
        var records = new List<P0fRecord>();
        string? subject = null, address = null;
        foreach (var raw in o.Split('\n'))
        {
            var m = Regex.Match(raw, @"^\|\s*(?<key>\w+)\s*=\s*(?<val>.+?)\s*$");
            if (!m.Success) continue;
            var key = m.Groups["key"].Value; var val = m.Groups["val"].Value;
            if (key is "client" or "server") { subject = key; address = val.Split('/')[0]; }
            else if (key == "os" && address is not null && val != "???")
                records.Add(new P0fRecord { Subject = subject ?? "", Address = address, Os = val });
        }
        return records.DistinctBy(r => (r.Address, r.Os)).ToArray();
    }

    /// <summary>
    /// Reads NetFlow records from an nfcapd flow file (or directory with <c>-R</c>) via <c>nfdump -o csv</c>,
    /// optionally filtered by an nfdump <paramref name="filter"/>. Note: operates on collected NetFlow, not pcap.
    /// </summary>
    public async Task<ToolResult<NetflowRecord[]>> NfdumpAsync(string flowSource, string? filter = null, bool sudo = false)
    {
        var src = flowSource.Contains('*') || !flowSource.Contains('.') ? $"-R {Q(flowSource)}" : $"-r {Q(flowSource)}";
        var res = await RunAsync("Nfdump", $"{src} -o csv -q" + (filter is not null ? $" {Q(filter)}" : ""), sudo);
        if (!res.IsSuccess) return ToolResult<NetflowRecord[]>.Fail(res.Message!);
        var o = res.Result!;
        var records = new List<NetflowRecord>();
        foreach (var line in Lines(o))
        {
            var f = line.Split(',');
            if (f.Length < 12 || f[0] == "ts") continue;   // header / short lines
            records.Add(new NetflowRecord
            {
                Start = DateTime.TryParse(f[0], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null,
                Duration = Dbl(f[2]), Proto = f[3], SrcIp = f[4], SrcPort = (int)Num(f[5]),
                DstIp = f[6], DstPort = (int)Num(f[7]), Packets = Num(f[9]), Bytes = Num(f[10]), Flags = f.Length > 8 ? f[8] : null,
            });
        }
        return records.ToArray();
    }
    #endregion

    #region Suricata IDS
    /// <summary>
    /// Runs the Suricata signature IDS over <paramref name="pcap"/>, writing its logs to <paramref name="outDir"/>
    /// (created if missing), and returns the parsed alert events from <c>eve.json</c>. Alert lines are filtered
    /// server-side before transfer. A failed result only if Suricata could not run; an empty array means "ran
    /// clean, no alerts" (or no ruleset loaded — provision with <c>suricata-update</c>).
    /// </summary>
    public async Task<ToolResult<SuricataAlert[]>> SuricataAsync(string pcap, string outDir, bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outDir);
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(outDir)}", false);
        var res = await RunAsync("Suricata", $"-r {Q(pcap)} -l {Q(outDir)}", sudo || Tools["Suricata"].Sudo);
        if (!res.IsSuccess) return ToolResult<SuricataAlert[]>.Fail(res.Message!);
        if (Tools["Suricata"].Sudo || sudo)
            await auditEnvironment.ExecuteCommandAsync("chown", $"-R $(id -un):$(id -gn) {Q(outDir)}", true);

        // Pull only the alert lines out of (a potentially large) eve.json.
        var eve = $"{outDir.TrimEnd('/')}/eve.json";
        var r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"grep '\\\"event_type\\\":\\\"alert\\\"' {Q(eve)} 2>/dev/null\"", false);
        if (!r.IsCompleted) return ToolResult<SuricataAlert[]>.Pass([]);
        var alerts = new List<SuricataAlert>();
        foreach (var line in Lines(r.Output))
        {
            if (TryParseAlert(line) is { } a) alerts.Add(a);
        }
        return alerts.ToArray();
    }

    private static SuricataAlert? TryParseAlert(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("alert", out var alert)) return null;
            string? s(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            int i(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
            JsonElement? http = root.TryGetProperty("http", out var h) ? h : null;
            return new SuricataAlert
            {
                Timestamp = DateTime.TryParse(s(root, "timestamp"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var t) ? t : null,
                SrcIp = s(root, "src_ip"), SrcPort = i(root, "src_port"),
                DestIp = s(root, "dest_ip"), DestPort = i(root, "dest_port"),
                Proto = s(root, "proto"), AppProto = s(root, "app_proto"),
                SignatureId = i(alert, "signature_id"), Signature = s(alert, "signature") ?? "",
                Category = s(alert, "category"), Severity = i(alert, "severity"),
                HttpHost = http is { } hh ? s(hh, "hostname") : null,
                HttpUrl = http is { } hu ? s(hu, "url") : null,
            };
        }
        catch (JsonException) { return null; }
    }
    #endregion

    #region Utility (slice / merge)
    /// <summary>Writes a subset of <paramref name="pcap"/> to <paramref name="outFile"/> via <c>editcap</c> — a
    /// packet range (<paramref name="firstPacket"/>..<paramref name="lastPacket"/>) and/or a time window
    /// (<paramref name="startEpoch"/>/<paramref name="endEpoch"/>). Returns true on success.</summary>
    public async Task<bool> EditcapSliceAsync(string pcap, string outFile,
        int? firstPacket = null, int? lastPacket = null, double? startEpoch = null, double? endEpoch = null, bool sudo = false)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outFile);
        var args = new StringBuilder();
        if (startEpoch is not null) args.Append($"-A {EpochArg(startEpoch.Value)} ");
        if (endEpoch is not null) args.Append($"-B {EpochArg(endEpoch.Value)} ");
        args.Append($"{Q(pcap)} {Q(outFile)}");
        if (firstPacket is not null && lastPacket is not null) args.Append($" {firstPacket}-{lastPacket}");
        return (await RunAsync("Editcap", args.ToString().Trim(), sudo)).IsSuccess;
    }

    /// <summary>Merges multiple captures into <paramref name="outFile"/> via <c>mergecap -w</c>. Returns true on success.</summary>
    public async Task<bool> MergeAsync(string[] pcaps, string outFile, bool sudo = false)
    {
        if (pcaps.Length == 0) return false;
        auditEnvironment.FailIfEvidenceSpoliationRisk(outFile);
        return (await RunAsync("Mergecap", $"-w {Q(outFile)} {string.Join(" ", pcaps.Select(Q))}", sudo)).IsSuccess;
    }
    #endregion

    #region Helpers
    // Runs a tool that writes files into outDir; creates the dir (as login user), runs, hands files back, lists them.
    private async Task<ToolResult<string[]>> RunToDirAsync(string outDir, bool sudo, Func<Task<ToolResult<string>>> run)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outDir);
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {Q(outDir)}", false);
        var res = await run();
        if (!res.IsSuccess) return ToolResult<string[]>.Fail(res.Message!);
        if (sudo) await auditEnvironment.ExecuteCommandAsync("chown", $"-R $(id -un):$(id -gn) {Q(outDir)}", true);
        var find = await auditEnvironment.ExecuteCommandAsync("find", $"{Q(outDir)} -maxdepth 1 -type f -printf '%p\\n'", false);
        return find.IsCompleted
            ? find.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToArray()
            : System.Array.Empty<string>();
    }

    // Runs a tool and returns its stdout as a ToolResult: a failed result names the tool when it is unavailable on
    // the platform, or carries the command's error output when it ran but failed — the distinction a bare null hid.
    private async Task<ToolResult<string>> RunAsync(string name, string args, bool sudo)
    {
        if (!Tools[name].Available)
            return ToolResult<string>.Fail($"{name} is not available on platform '{platform}'.");
        var r = await auditEnvironment.ExecuteCommandAsync(Tools[name].Command, args, Tools[name].Sudo || sudo);
        if (r.IsCompleted) return r.Output ?? "";
        Error($"Failed to execute tool command {Tools[name].Command} {args}: {r.Output}.");
        return ToolResult<string>.Fail($"{name} command failed: {Short(r.Output)}");
    }

    // Condenses tool error output into a single-line reason for a failed ToolResult (avoids dumping huge stderr).
    private static string Short(string? s) =>
        string.IsNullOrWhiteSpace(s) ? "(no output)" : (s.Length > 200 ? s[..200] + "…" : s).Replace("\r", " ").Replace("\n", " ").Trim();

    // tshark/conv byte values use decimal SI units (kB=1000). Returns bytes as a long.
    private static long Si(string num, string unit)
    {
        if (!double.TryParse(num, NumberStyles.Float, CultureInfo.InvariantCulture, out var n)) return 0;
        return (long)(n * unit switch { "kB" => 1_000, "MB" => 1_000_000, "GB" => 1_000_000_000, _ => 1 });
    }

    // capinfos time: "2007-12-17 03:32:16.111289".
    private static DateTime? ParseCapTime(string? s) =>
        s is not null && DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null;

    // editcap -A/-B accept "YYYY-MM-DD HH:MM:SS" or an epoch with a leading marker; epoch form is simplest.
    private static string EpochArg(double epoch) => $"'{epoch.ToString("0", CultureInfo.InvariantCulture)}'";

    private static readonly Regex FirstNumber = new(@"-?\d[\d,]*\.?\d*", RegexOptions.Compiled);
    private static long Num(string? s) => s is not null && FirstNumber.Match(s) is { Success: true } m && long.TryParse(m.Value.Replace(",", ""), out var n) ? n : 0;
    private static double Dbl(string? s) => s is not null && FirstNumber.Match(s) is { Success: true } m && double.TryParse(m.Value.Replace(",", ""), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0;
    private static string? NullIfEmpty(string s) => string.IsNullOrEmpty(s) ? null : s;

    private static string Q(string s) => $"'{s.Replace("'", "'\\''")}'";
    private static IEnumerable<string> Lines(string? text) =>
        text is null ? [] : text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    #endregion
}
