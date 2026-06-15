namespace Camel.Toolkits.Models;

using System;

// =====================================================================================================
// Packet-analysis models produced by PacketAnalysisToolkit. Hand-parsed from the text output of the SIFT
// network tools (tshark statistics / -T fields, capinfos -M, tcptrace, ngrep, p0f) or, for Suricata,
// JSON-lines (eve.json). Grounded in SANS FOR501.2 "Packet Analysis".
// =====================================================================================================

/// <summary>Capture-file metadata from <c>capinfos -M</c> (machine-readable, raw values — no SI suffixes).</summary>
public record PcapInfo
{
    public string? FileName { get; init; }
    public string? FileType { get; init; }
    public string? Encapsulation { get; init; }
    public long PacketCount { get; init; }
    public long FileSize { get; init; }
    public long DataSize { get; init; }
    public double DurationSeconds { get; init; }
    public DateTime? FirstPacketTime { get; init; }
    public DateTime? LastPacketTime { get; init; }
    public double DataByteRate { get; init; }
    public double AveragePacketSize { get; init; }
    public string? Sha256 { get; init; }
    public string? Sha1 { get; init; }
}

/// <summary>One packet's summary row (Wireshark column view) from <c>tshark -T fields</c>.</summary>
public record PacketSummary
{
    public int Number { get; init; }
    /// <summary>Epoch seconds (frame.time_epoch).</summary>
    public double Time { get; init; }
    public string? Source { get; init; }
    public string? Destination { get; init; }
    public string? Protocol { get; init; }
    public int Length { get; init; }
    public string? Info { get; init; }
}

/// <summary>One node of the protocol-hierarchy tree from <c>tshark -z io,phs</c>. <see cref="Depth"/> is the
/// nesting level (0 = link layer); a child protocol is carried inside its parent.</summary>
public record ProtocolLayer
{
    public string Protocol { get; init; } = "";
    public int Depth { get; init; }
    public long Frames { get; init; }
    public long Bytes { get; init; }
}

/// <summary>A conversation (flow) between two endpoints from <c>tshark -z conv,&lt;proto&gt;</c>. Directional
/// counts are relative to A: <c>AToB</c> is the <c>-&gt;</c> column, <c>BToA</c> the <c>&lt;-</c> column.</summary>
public record Conversation
{
    public string EndpointA { get; init; } = "";
    public string EndpointB { get; init; } = "";
    public long FramesAToB { get; init; }
    public long BytesAToB { get; init; }
    public long FramesBToA { get; init; }
    public long BytesBToA { get; init; }
    public long TotalFrames { get; init; }
    public long TotalBytes { get; init; }
    /// <summary>Relative start time (seconds from capture start).</summary>
    public double RelativeStart { get; init; }
    public double Duration { get; init; }
}

/// <summary>A traffic endpoint (host) from <c>tshark -z endpoints,&lt;proto&gt;</c> with exact byte/packet counts.</summary>
public record Endpoint
{
    public string Address { get; init; } = "";
    public long Packets { get; init; }
    public long Bytes { get; init; }
    public long TxPackets { get; init; }
    public long TxBytes { get; init; }
    public long RxPackets { get; init; }
    public long RxBytes { get; init; }
}

/// <summary>A TCP connection summary from <c>tcptrace</c>: the two hosts and the packet counts each way.</summary>
public record TcpTraceConn
{
    public string HostA { get; init; } = "";
    public int PortA { get; init; }
    public string HostB { get; init; } = "";
    public int PortB { get; init; }
    /// <summary>tcptrace's per-connection label (e.g. "a2b").</summary>
    public string? Label { get; init; }
    public int PacketsAToB { get; init; }
    public int PacketsBToA { get; init; }
    public bool Complete { get; init; }
}

/// <summary>One payload match from <c>ngrep</c>: the matched packet's endpoints and (single-line) payload.</summary>
public record NgrepMatch
{
    /// <summary>"T" for TCP, "U" for UDP (ngrep's leading protocol marker).</summary>
    public string Protocol { get; init; } = "";
    public string? Source { get; init; }
    public string? Destination { get; init; }
    /// <summary>TCP flags ngrep prints in brackets, e.g. "AP".</summary>
    public string? Flags { get; init; }
    public string Payload { get; init; } = "";
}

/// <summary>A passive OS/device fingerprint from <c>p0f -r</c>.</summary>
public record P0fRecord
{
    /// <summary>"client" or "server" (the role p0f attributed).</summary>
    public string Subject { get; init; } = "";
    public string Address { get; init; } = "";
    public string? Os { get; init; }
    /// <summary>Any extra detail p0f reported (link, raw_mtu, distance, …) joined for context.</summary>
    public string? Detail { get; init; }
}

/// <summary>A NetFlow record from <c>nfdump -o csv</c> (operates on nfcapd flow files, not pcap).</summary>
public record NetflowRecord
{
    public DateTime? Start { get; init; }
    public double Duration { get; init; }
    public string? Proto { get; init; }
    public string? SrcIp { get; init; }
    public int SrcPort { get; init; }
    public string? DstIp { get; init; }
    public int DstPort { get; init; }
    public long Packets { get; init; }
    public long Bytes { get; init; }
    public string? Flags { get; init; }
}

/// <summary>One Suricata IDS alert parsed from <c>eve.json</c> (<c>event_type=alert</c>).</summary>
public record SuricataAlert
{
    public DateTime? Timestamp { get; init; }
    public string? SrcIp { get; init; }
    public int SrcPort { get; init; }
    public string? DestIp { get; init; }
    public int DestPort { get; init; }
    public string? Proto { get; init; }
    public string? AppProto { get; init; }
    public long SignatureId { get; init; }
    public string Signature { get; init; } = "";
    public string? Category { get; init; }
    /// <summary>Suricata severity: 1 = most severe … 3 = informational.</summary>
    public int Severity { get; init; }
    /// <summary>HTTP host/url when the alert carried an http object, for quick context.</summary>
    public string? HttpHost { get; init; }
    public string? HttpUrl { get; init; }
}
