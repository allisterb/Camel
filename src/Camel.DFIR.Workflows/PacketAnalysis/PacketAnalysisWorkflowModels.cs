namespace Camel.Workflows.Models;

using System;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;

// =====================================================================================================
// Report models for PacketAnalysisWorkflow. Each report carries the parsed network artifacts plus the items
// the workflow flagged (with the reason). Grounded in SANS FOR501.2 "Packet Analysis".
// =====================================================================================================

#region Triage
/// <summary>Overview of a capture: file metadata, protocol mix, top talkers, and the busiest DNS/HTTP hosts.</summary>
public record PcapTriageReport
{
    public PcapInfo? Info { get; init; }
    public ProtocolLayer[] ProtocolHierarchy { get; init; } = [];
    public Conversation[] TopConversations { get; init; } = [];
    public Endpoint[] TopEndpoints { get; init; } = [];
    public NameCount[] TopDnsQueries { get; init; } = [];
    public NameCount[] TopHttpHosts { get; init; } = [];
}
#endregion

#region Streams
/// <summary>One reassembled stream's content, with any credential/keyword lines highlighted.</summary>
public record StreamReport
{
    public string Protocol { get; init; } = "";
    public int Index { get; init; }
    public string Content { get; init; } = "";
    public string[] Highlights { get; init; } = [];
}
#endregion

#region DNS tunneling
/// <summary>Result of hunting DNS tunneling / DNS-tunnelled C2 (the book's DNS-backdoor lab).</summary>
public record DnsTunnelingReport
{
    public int TotalQueries { get; init; }
    public int UniqueDomains { get; init; }
    public DnsDomainFinding[] SuspiciousDomains { get; init; } = [];
}

/// <summary>One parent domain scored for tunneling indicators.</summary>
public record DnsDomainFinding
{
    public required string Domain { get; init; }
    public int QueryCount { get; init; }
    public int UniqueSubdomains { get; init; }
    public int MaxLabelLength { get; init; }
    public double AvgEntropy { get; init; }
    /// <summary>Uncommon record types seen for this domain (TXT/NULL/CNAME-heavy = tunneling tell).</summary>
    public string[] RareTypes { get; init; } = [];
    public int Score { get; init; }
    public string[] Reasons { get; init; } = [];
}
#endregion

#region HTTP objects
/// <summary>Result of carving HTTP objects from a capture plus the request transactions seen.</summary>
public record HttpObjectReport
{
    public string OutDir { get; init; } = "";
    public string[] CarvedFiles { get; init; } = [];
    public HttpTransaction[] Transactions { get; init; } = [];
}

/// <summary>One HTTP request observed in the capture.</summary>
public record HttpTransaction
{
    public string? Method { get; init; }
    public string? Host { get; init; }
    public string? Uri { get; init; }
    public string? UserAgent { get; init; }
}
#endregion

#region Credentials
/// <summary>Result of harvesting cleartext credentials from a capture.</summary>
public record PcapCredentialReport
{
    public CredentialFinding[] Findings { get; init; } = [];
}

/// <summary>One recovered credential / authentication artifact.</summary>
public record CredentialFinding
{
    /// <summary>http-basic / ftp / http-form / telnet / smtp-auth / pop / imap.</summary>
    public required string Protocol { get; init; }
    public string? Source { get; init; }
    public string? Destination { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
    public string? Detail { get; init; }
}
#endregion

#region Beaconing
/// <summary>Result of timing-based C2-beacon detection over a capture.</summary>
public record BeaconReport
{
    public BeaconFinding[] Beacons { get; init; } = [];
}

/// <summary>A (src→dst:port) channel whose repeated connections arrive on a regular cadence (low jitter).</summary>
public record BeaconFinding
{
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public int DestinationPort { get; init; }
    public int ConnectionCount { get; init; }
    public double MeanIntervalSeconds { get; init; }
    /// <summary>Jitter = stddev/mean of the inter-connection intervals; near 0 = a metronomic beacon.</summary>
    public double JitterRatio { get; init; }
    public int Score { get; init; }
}
#endregion

#region Host fingerprints
/// <summary>Result of passive host fingerprinting (p0f) over a capture.</summary>
public record HostFingerprintReport
{
    public HostFingerprint[] Hosts { get; init; } = [];
}

/// <summary>A host with the OS guess(es) p0f attributed to it.</summary>
public record HostFingerprint
{
    public required string Address { get; init; }
    public string? Role { get; init; }
    public string[] OsGuesses { get; init; } = [];
}
#endregion

#region IDS
/// <summary>Result of running the Suricata signature IDS over a capture.</summary>
public record IdsReport
{
    public int AlertCount { get; init; }
    public NameCount[] BySignature { get; init; } = [];
    public NameCount[] BySeverity { get; init; } = [];
    public NameCount[] TopSourceIps { get; init; } = [];
    /// <summary>A capped sample of alerts, most-severe first.</summary>
    public SuricataAlert[] Alerts { get; init; } = [];
}
#endregion
