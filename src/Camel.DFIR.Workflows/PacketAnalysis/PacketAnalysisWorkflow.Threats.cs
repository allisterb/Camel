namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

public partial class PacketAnalysisWorkflow
{
    #region Credentials
    /// <summary>
    /// Harvests cleartext credentials from a capture: HTTP Basic auth (decoded), FTP <c>USER</c>/<c>PASS</c>
    /// pairs, and form/login parameters found in payloads (via ngrep). These cleartext-protocol creds are a
    /// primary FOR501.2 finding. Returns each recovered credential with its protocol and endpoints.
    /// </summary>
    /// <param name="pcap">Path to the capture file.</param>
    public async Task<WorkflowResult<PcapCredentialReport>> ExtractCredentialsAsync(string pcap)
    {
        using var _audit = AuditScope();
        using var op = Begin("Extracting cleartext credentials from {0}", pcap);

        var basicT = PacketAnalysis.FieldsAsync(pcap, "http.authorization", ["ip.src", "ip.dst", "http.authorization"]);
        var ftpT = PacketAnalysis.FieldsAsync(pcap, "ftp.request.command==\"USER\" || ftp.request.command==\"PASS\"",
            ["ip.src", "ip.dst", "ftp.request.command", "ftp.request.arg"]);
        var formT = PacketAnalysis.NgrepAsync(pcap, "(pass(word)?|pwd|login|user)=", "tcp");
        await Task.WhenAll(basicT, ftpT, formT);

        if (basicT.Result is null && ftpT.Result is null && formT.Result is null)
            return WorkflowResult<PcapCredentialReport>.Failure(
                $"Could not read '{pcap}' for credential extraction; check the path and that the file is a capture.");

        var findings = new List<CredentialFinding>();

        // HTTP Basic: "Basic <base64(user:pass)>".
        foreach (var r in basicT.Result ?? [])
        {
            var hdr = r.Length > 2 ? r[2] : "";
            var m = Regex.Match(hdr, @"Basic\s+(?<b64>[A-Za-z0-9+/=]+)");
            if (!m.Success) continue;
            var dec = TryB64(m.Groups["b64"].Value);
            var parts = dec?.Split(':', 2);
            findings.Add(new CredentialFinding
            {
                Protocol = "http-basic", Source = Nz(r, 0), Destination = Nz(r, 1),
                Username = parts?.ElementAtOrDefault(0), Password = parts?.ElementAtOrDefault(1),
                Detail = dec is null ? hdr : null,
            });
        }

        // FTP: pair each USER with the following PASS on the same (src,dst).
        var pendingUser = new Dictionary<string, string>();
        foreach (var r in ftpT.Result ?? [])
        {
            string key = $"{Nz(r, 0)}->{Nz(r, 1)}", cmd = (r.Length > 2 ? r[2] : "").ToUpperInvariant(), arg = r.Length > 3 ? r[3] : "";
            if (cmd == "USER") pendingUser[key] = arg;
            else if (cmd == "PASS")
                findings.Add(new CredentialFinding
                {
                    Protocol = "ftp", Source = Nz(r, 0), Destination = Nz(r, 1),
                    Username = pendingUser.GetValueOrDefault(key), Password = arg,
                });
        }

        // Form/login params seen in payloads.
        foreach (var ng in formT.Result ?? [])
        {
            var user = Regex.Match(ng.Payload, @"(?i)(user(name)?|login)=([^&\s]+)");
            var pass = Regex.Match(ng.Payload, @"(?i)(pass(word)?|pwd)=([^&\s]+)");
            if (!pass.Success && !user.Success) continue;
            findings.Add(new CredentialFinding
            {
                Protocol = "http-form", Source = ng.Source, Destination = ng.Destination,
                Username = user.Success ? user.Groups[3].Value : null,
                Password = pass.Success ? pass.Groups[3].Value : null,
                Detail = Truncate(ng.Payload, 160),
            });
        }

        op.Complete();
        var report = new PcapCredentialReport { Findings = findings.ToArray() };
        return WorkflowResult<PcapCredentialReport>.Success(report,
            findings.Count == 0
                ? $"No cleartext credentials recovered from '{pcap}'."
                : $"Recovered {findings.Count} credential artifact(s): " +
                  string.Join("; ", findings.Take(5).Select(f => $"{f.Protocol} {f.Username}@{f.Destination}")) + ".");
    }
    #endregion

    #region Beaconing
    private const int BeaconMinConnections = 4;
    private const double BeaconMaxJitter = 0.25;   // stddev/mean below this = a regular beacon

    /// <summary>
    /// Detects C2 beaconing by timing: groups new TCP connections (SYN) by (source → destination:port) and flags
    /// channels whose repeated connections arrive on a regular cadence (low jitter) — the hallmark of malware
    /// calling home on an interval. Returns each candidate beacon with its mean interval and jitter.
    /// </summary>
    /// <param name="pcap">Path to the capture file.</param>
    public async Task<WorkflowResult<BeaconReport>> DetectBeaconingAsync(string pcap)
    {
        using var _audit = AuditScope();
        using var op = Begin("Detecting C2 beaconing in {0}", pcap);

        var rows = await PacketAnalysis.FieldsAsync(pcap, "tcp.flags.syn==1 && tcp.flags.ack==0",
            ["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport"]);
        if (rows is null)
            return WorkflowResult<BeaconReport>.Failure(
                $"Could not read connection starts from '{pcap}'; check the path and that the file is a capture.");

        var beacons = new List<BeaconFinding>();
        foreach (var g in rows.Where(r => r.Length >= 4 && r[1].Length > 0).GroupBy(r => (Src: r[1], Dst: r[2], Port: r[3])))
        {
            var times = g.Select(r => double.TryParse(r[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var t) ? t : 0)
                         .Where(t => t > 0).OrderBy(t => t).ToArray();
            if (times.Length < BeaconMinConnections) continue;
            var intervals = times.Zip(times.Skip(1), (a, b) => b - a).ToArray();
            double mean = intervals.Average();
            if (mean <= 0) continue;
            double std = Math.Sqrt(intervals.Select(i => (i - mean) * (i - mean)).Average());
            double jitter = std / mean;
            if (jitter > BeaconMaxJitter) continue;

            int.TryParse(g.Key.Port, out var port);
            beacons.Add(new BeaconFinding
            {
                Source = g.Key.Src, Destination = g.Key.Dst, DestinationPort = port,
                ConnectionCount = times.Length, MeanIntervalSeconds = Math.Round(mean, 2),
                JitterRatio = Math.Round(jitter, 3),
                Score = (times.Length >= 10 ? 2 : 1) + (jitter < 0.1 ? 2 : 1),
            });
        }
        beacons = beacons.OrderByDescending(b => b.Score).ThenByDescending(b => b.ConnectionCount).ToList();

        op.Complete();
        var report = new BeaconReport { Beacons = beacons.ToArray() };
        return WorkflowResult<BeaconReport>.Success(report,
            beacons.Count == 0
                ? $"No regular-cadence beacons detected in '{pcap}'."
                : $"{beacons.Count} candidate beacon(s): " +
                  string.Join("; ", beacons.Take(4).Select(b => $"{b.Source}→{b.Destination}:{b.DestinationPort} every ~{b.MeanIntervalSeconds}s ×{b.ConnectionCount} (jitter {b.JitterRatio})")) + ".");
    }
    #endregion

    #region Host fingerprints
    /// <summary>
    /// Passively fingerprints the OS/device of each host in a capture using <c>p0f</c>. Returns each host with the
    /// distinct OS guess(es) p0f attributed to it — useful for inventorying who was on the wire and spotting
    /// unexpected systems.
    /// </summary>
    /// <param name="pcap">Path to the capture file.</param>
    public async Task<WorkflowResult<HostFingerprintReport>> FingerprintHostsAsync(string pcap)
    {
        using var _audit = AuditScope();
        using var op = Begin("Passively fingerprinting hosts in {0}", pcap);

        var fps = await PacketAnalysis.P0fAsync(pcap);
        if (fps is null)
            return WorkflowResult<HostFingerprintReport>.Failure(
                $"p0f could not read '{pcap}'; check the path and that the file is a capture.");

        var hosts = fps.GroupBy(f => f.Address)
            .Select(g => new HostFingerprint
            {
                Address = g.Key,
                Role = g.GroupBy(x => x.Subject).OrderByDescending(x => x.Count()).First().Key,
                OsGuesses = g.Select(x => x.Os).Where(o => o is not null).Select(o => o!).Distinct().ToArray(),
            })
            .OrderBy(h => h.Address).ToArray();

        op.Complete();
        var report = new HostFingerprintReport { Hosts = hosts };
        return WorkflowResult<HostFingerprintReport>.Success(report,
            $"Fingerprinted {hosts.Length} host(s): " +
            string.Join("; ", hosts.Take(6).Select(h => $"{h.Address} ({string.Join("/", h.OsGuesses)})")) + ".");
    }
    #endregion

    #region IDS
    /// <summary>
    /// Runs the Suricata signature IDS over a capture (the maintained successor to the book's Snort) and returns
    /// the alerts, grouped by signature and severity with the top alerting source IPs. <paramref name="outDir"/>
    /// receives Suricata's logs (eve.json/fast.log); a temp dir is used when omitted.
    /// </summary>
    /// <param name="pcap">Path to the capture file.</param>
    /// <param name="outDir">Directory for Suricata's output (defaults to a temp dir under /tmp).</param>
    public async Task<WorkflowResult<IdsReport>> RunIdsAsync(string pcap, string? outDir = null)
    {
        outDir ??= "/tmp/camel_suricata_" + Guid.NewGuid().ToString("N");
        using var _audit = AuditScope();
        using var op = Begin("Running Suricata IDS over {0}", pcap);

        var alerts = await PacketAnalysis.SuricataAsync(pcap, outDir);
        if (alerts is null)
            return WorkflowResult<IdsReport>.Failure(
                $"Suricata could not analyse '{pcap}'; check the path and that suricata is installed/provisioned.");

        NameCount[] count<T>(IEnumerable<T> src, Func<T, string> key) =>
            src.GroupBy(key).Select(g => new NameCount { Name = g.Key, Count = g.Count() })
               .OrderByDescending(n => n.Count).Take(25).ToArray();

        op.Complete();
        var report = new IdsReport
        {
            AlertCount = alerts.Length,
            BySignature = count(alerts, a => a.Signature),
            BySeverity = count(alerts, a => $"sev{a.Severity}"),
            TopSourceIps = count(alerts.Where(a => a.SrcIp is not null), a => a.SrcIp!),
            Alerts = alerts.OrderBy(a => a.Severity).ThenBy(a => a.SignatureId).Take(200).ToArray(),
        };
        return WorkflowResult<IdsReport>.Success(report,
            alerts.Length == 0
                ? $"Suricata raised no alerts on '{pcap}' (confirm the ruleset is provisioned via suricata-update)."
                : $"Suricata raised {alerts.Length} alert(s) across {report.BySignature.Length} signature(s). Top: " +
                  string.Join("; ", report.BySignature.Take(3).Select(s => $"{s.Name} ×{s.Count}")) + ".");
    }
    #endregion

    #region Helpers
    private static string? Nz(string[] r, int i) => i < r.Length && r[i].Length > 0 ? r[i] : null;
    private static string? TryB64(string s)
    {
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(s)); } catch { return null; }
    }
    #endregion
}
