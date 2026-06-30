namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

public partial class LinuxAnalysisWorkflow
{
    /// <summary>
    /// Inventories installed packages (from <c>var/lib/dpkg/status</c>) and builds the install/upgrade/remove
    /// timeline (from <c>dpkg.log</c> + <c>apt/history.log</c>). Surfaces the most recent package events and
    /// flags installs of dual-use / offensive tooling (nmap, netcat, masscan, hydra, john, hashcat, socat,
    /// metasploit, …) — a common attacker move on a freshly compromised host. Debian/Ubuntu (dpkg) only.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c>.</param>
    public async Task<WorkflowResult<PackageReport>> AnalyzeInstalledPackagesAsync(string rootDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing installed packages under {0}", rootDir);

        var installed = (await LinuxAnalysis.InstalledPackagesAsync(rootDir)).Value;
        if (installed is null)
            return WorkflowResult<PackageReport>.Failure(
                $"Could not read '{Combine(rootDir, "var/lib/dpkg/status")}' (not a dpkg-based image, or wrong path).");
        var events = (await LinuxAnalysis.PackageLogAsync(rootDir)).Value ?? [];

        var recent = events.OrderByDescending(e => e.Timestamp ?? DateTime.MinValue).Take(50).ToArray();
        var findings = events
            .Where(e => e.Action == "install" && HackToolPackages.Contains(e.Package))
            .OrderByDescending(e => e.Timestamp ?? DateTime.MinValue)
            .ToArray();

        op.Complete();
        var report = new PackageReport
        {
            InstalledCount = installed.Count(p => p.Installed),
            RecentEvents = recent,
            Findings = findings,
        };
        return WorkflowResult<PackageReport>.Success(report,
            $"{report.InstalledCount} package(s) installed; {events.Length} log event(s). " +
            (findings.Length == 0
                ? "No dual-use/offensive tooling installs flagged."
                : $"Flagged install(s) of: {string.Join(", ", findings.Select(f => f.Package).Distinct().Take(8))}."));
    }

    // Dual-use / offensive packages whose installation on a host under investigation is worth a second look.
    private static readonly HashSet<string> HackToolPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "nmap", "netcat", "netcat-traditional", "netcat-openbsd", "ncat", "masscan", "hydra", "john", "hashcat",
        "socat", "tcpdump", "nikto", "sqlmap", "metasploit-framework", "responder", "proxychains", "proxychains-ng",
        "aircrack-ng", "ettercap-text-only", "dsniff", "chisel", "tor", "openvpn", "tshark", "wireshark",
    };
}
