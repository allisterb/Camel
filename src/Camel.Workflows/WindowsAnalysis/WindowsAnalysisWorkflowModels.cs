namespace Camel.Workflows.Models;

using System;
using System.Linq;

using Camel.Toolkits.Models;

/// <summary>
/// One of the forensic registry artifacts from the Windows-artifacts methodology: a human-readable
/// <see cref="Name"/> and the <see cref="RegistryEntry"/> rows the RECmd batch produced whose key path
/// matched it. <see cref="Entries"/> is empty when the parsed hives contained no such artifact (e.g. an
/// NTUSER-only artifact when only SYSTEM/SOFTWARE hives were parsed).
/// </summary>
public record KeyArtifact
{
    public string Name { get; }
    public RegistryEntry[] Entries { get; }
    public KeyArtifact(string name, RegistryEntry[] entries)
    {
        this.Name = name;
        this.Entries = entries;
    }
}

/// <summary>
/// The result of batch-parsing a directory of registry hives with RECmd's DFIR batch file and bucketing the
/// output into the key forensic artifacts. <see cref="Artifacts"/> holds one <see cref="KeyArtifact"/> per
/// artifact category (Run keys, UserAssist, USBSTOR, Shimcache, …); <see cref="AllEntries"/> is the complete
/// RECmd output for anything not covered by a named bucket.
/// </summary>
public record KeyArtifactsReport
{
    public KeyArtifact[] Artifacts { get; }
    public RegistryEntry[] AllEntries { get; }
    public KeyArtifactsReport(KeyArtifact[] artifacts, RegistryEntry[] allEntries)
    {
        this.Artifacts = artifacts;
        this.AllEntries = allEntries;
    }
}

/// <summary>
/// A single persistence entry recovered from a registry hive by RegRipper and classified into one of the
/// malware-persistence mechanism categories (Run keys, Services, Scheduled Tasks, AppInit DLLs, shell open
/// commands). <see cref="Command"/> is the autostart value / service image path / command line driving the
/// persistence (null when the source doesn't record one, e.g. a TaskCache entry without its action). When
/// <see cref="Suspicious"/> is true, <see cref="Reasons"/> explains why (suspicious location, LOLBin/scripting
/// host, encoded command, hijacked handler, …) — these are leads to triage, not verdicts.
/// </summary>
public record PersistenceEntry
{
    public string Category { get; init; } = "";
    public string Hive { get; init; } = "";
    public string Plugin { get; init; } = "";
    public string? KeyPath { get; init; }
    public string Name { get; init; } = "";
    public string? Command { get; init; }
    public string? LastWrite { get; init; }
    public bool Suspicious { get; init; }
    public string[] Reasons { get; init; } = [];
}

/// <summary>One malware-persistence mechanism category and the <see cref="PersistenceEntry"/> entries found in it.</summary>
public record PersistenceMechanism
{
    public string Category { get; }
    public PersistenceEntry[] Entries { get; }
    public PersistenceMechanism(string category, PersistenceEntry[] entries)
    {
        this.Category = category;
        this.Entries = entries;
    }
}

/// <summary>
/// The result of hunting a Windows system's registry hives for malware-persistence mechanisms.
/// <see cref="Mechanisms"/> holds one bucket per persistence category (always present, even when empty);
/// <see cref="AllEntries"/> is every entry found across all categories; <see cref="SuspiciousEntries"/> is the
/// actionable subset that scored at least one suspicion reason.
/// </summary>
public record PersistenceReport
{
    public PersistenceMechanism[] Mechanisms { get; }
    public PersistenceEntry[] AllEntries { get; }
    public PersistenceEntry[] SuspiciousEntries { get; }
    public PersistenceReport(PersistenceMechanism[] mechanisms)
    {
        this.Mechanisms = mechanisms;
        this.AllEntries = mechanisms.SelectMany(m => m.Entries).ToArray();
        this.SuspiciousEntries = this.AllEntries.Where(e => e.Suspicious).ToArray();
    }
}

/// <summary>
/// A WMI event consumer flagged as a persistence lead: its <see cref="Type"/> and <see cref="Name"/>, the
/// recovered action <see cref="Command"/> (and its <see cref="DecodedCommand"/> when the action was an encoded
/// PowerShell payload — revealing the real intent, e.g. a download cradle), the bound event filter
/// (<see cref="FilterName"/>, the trigger), and the <see cref="Reasons"/> it was flagged.
/// </summary>
public record WmiPersistenceEntry
{
    public string Type { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Command { get; init; }
    public string? DecodedCommand { get; init; }
    public string? FilterName { get; init; }
    public string[] Reasons { get; init; } = [];
}

/// <summary>
/// The result of hunting WMI event-consumer persistence in a repository's OBJECTS.DATA.
/// <see cref="SuspiciousConsumers"/> is the flagged subset; <see cref="Consumers"/> is every attacker-favored
/// (CommandLine/ActiveScript) consumer considered; <see cref="Bindings"/> and <see cref="Filters"/> are the
/// full recovered subscription context.
/// </summary>
public record WmiPersistenceReport
{
    public WmiPersistenceEntry[] SuspiciousConsumers { get; init; } = [];
    public WmiConsumer[] Consumers { get; init; } = [];
    public WmiBinding[] Bindings { get; init; } = [];
    public string[] Filters { get; init; } = [];
}

/// <summary>
/// A potential DLL-hijacking persistence artifact found on a mounted volume. <see cref="Kind"/> distinguishes a
/// search-order shadow (a <c>\Windows</c>-root DLL impersonating a System32 DLL — for the latter,
/// <see cref="ShadowedSystemDll"/> is the genuine file it differs from) from a DLL dropped in a transient/
/// world-writable location where DLLs do not normally reside. These are filesystem leads to triage.
/// </summary>
public record DllHijackFinding
{
    public string Path { get; init; } = "";
    public string Name { get; init; } = "";
    public long Size { get; init; }
    public string Kind { get; init; } = "";
    public string? ShadowedSystemDll { get; init; }
    public string[] Reasons { get; init; } = [];
}

/// <summary>
/// The result of hunting DLL-hijacking persistence on a mounted Windows volume: the <see cref="Findings"/> and
/// the number of candidate DLLs examined (<see cref="DllsScanned"/>).
/// </summary>
public record DllHijackReport
{
    public DllHijackFinding[] Findings { get; init; } = [];
    public int DllsScanned { get; init; }
}

/// <summary>
/// A credential-dumping artifact found on a mounted volume. <see cref="Kind"/> distinguishes an exfiltrated AD
/// database (<c>ntds.dit</c> outside <c>\Windows\NTDS</c>), a registry hive copied out of <c>\System32\config</c>
/// for offline extraction (SAM/SECURITY/SYSTEM), an LSASS memory dump (<c>lsass*.dmp</c>), or an exported
/// Kerberos ticket (<c>.kirbi</c>). Filesystem leads to triage.
/// </summary>
public record CredentialDumpFinding
{
    public string Path { get; init; } = "";
    public string Name { get; init; } = "";
    public long Size { get; init; }
    public string Kind { get; init; } = "";
    public string[] Reasons { get; init; } = [];
}

/// <summary>
/// The result of hunting credential-dumping artifacts on a mounted Windows volume: the <see cref="Findings"/>
/// and the number of candidate files examined (<see cref="FilesScanned"/>).
/// </summary>
public record CredentialDumpReport
{
    public CredentialDumpFinding[] Findings { get; init; } = [];
    public int FilesScanned { get; init; }
}

/// <summary>
/// One parsed Windows logon/logoff/privilege Security event. <see cref="LogonType"/> (and its
/// <see cref="LogonTypeName"/>) classify how the authentication happened — the key discriminator for hunting:
/// 3 = Network (share/PtH), 10 = RemoteInteractive (RDP), 9 = NewCredentials (runas /netonly, overpass-the-hash),
/// 2 = Interactive. <see cref="TargetUser"/> is the account that logged on, <see cref="SubjectUser"/> the account
/// that initiated it, and <see cref="SourceIp"/>/<see cref="Workstation"/> the origin (for remote logons).
/// </summary>
public record LogonEvent
{
    public DateTime? Time { get; init; }
    public int EventId { get; init; }
    public bool Success { get; init; }
    public int? LogonType { get; init; }
    public string? LogonTypeName { get; init; }
    public string? TargetUser { get; init; }
    public string? TargetDomain { get; init; }
    public string? SubjectUser { get; init; }
    public string? SourceIp { get; init; }
    public string? Workstation { get; init; }
    public string? AuthPackage { get; init; }
    public string? LogonProcess { get; init; }
    public string? Computer { get; init; }
}

/// <summary>A logon-type bucket and how many logons fell into it.</summary>
public record LogonTypeCount
{
    public int LogonType { get; init; }
    public string Name { get; init; } = "";
    public int Count { get; init; }
}

/// <summary>
/// The result of analysing a Security event log's authentication events. <see cref="Logons"/> holds every parsed
/// event; the computed views surface the triage/lateral-movement subsets the methodology calls out —
/// failed logons (password guessing), RemoteInteractive (RDP), Network (share/PtH), explicit-credential use
/// (runas), and NewCredentials (overpass-the-hash) — plus a per-logon-type breakdown.
/// </summary>
public record LogonReport
{
    public LogonEvent[] Logons { get; init; } = [];

    public LogonTypeCount[] ByLogonType => Logons.Where(l => l.LogonType is not null)
        .GroupBy(l => (l.LogonType!.Value, l.LogonTypeName ?? ""))
        .Select(g => new LogonTypeCount { LogonType = g.Key.Item1, Name = g.Key.Item2, Count = g.Count() })
        .OrderByDescending(c => c.Count).ToArray();

    public LogonEvent[] FailedLogons => Logons.Where(l => l.EventId == 4625).ToArray();
    public LogonEvent[] RemoteDesktopLogons => Logons.Where(l => l.LogonType == 10).ToArray();
    public LogonEvent[] NetworkLogons => Logons.Where(l => l.LogonType == 3).ToArray();
    public LogonEvent[] ExplicitCredentialLogons => Logons.Where(l => l.EventId == 4648).ToArray();
    public LogonEvent[] NewCredentialLogons => Logons.Where(l => l.LogonType == 9).ToArray();
    public LogonEvent[] PrivilegedLogons => Logons.Where(l => l.EventId == 4672).ToArray();
}

/// <summary>One network-share access event (Security 5140): the <see cref="ShareName"/> accessed, by which
/// <see cref="Account"/>, from which <see cref="SourceIp"/> — the admin-share (C$/ADMIN$) channel used for
/// remote file copy and PsExec.</summary>
public record ShareAccess
{
    public DateTime? Time { get; init; }
    public string? ShareName { get; init; }
    public string? SharePath { get; init; }
    public string? SourceIp { get; init; }
    public string? Account { get; init; }
}

/// <summary>
/// One service-install event (Security 4697 / System 7045): the <see cref="ServiceName"/>, its
/// <see cref="ImagePath"/>, and start/account context. A service install is always IR-relevant (it's how PsExec,
/// Cobalt Strike, and many implants execute remotely); <see cref="Suspicious"/> marks the ones matching a
/// concrete remote-exec pattern (tool name, transient image location, or launching a command interpreter).
/// </summary>
public record ServiceInstall
{
    public DateTime? Time { get; init; }
    public int EventId { get; init; }
    public string? ServiceName { get; init; }
    public string? ImagePath { get; init; }
    public string? ServiceType { get; init; }
    public string? StartType { get; init; }
    public string? Account { get; init; }
    public bool Suspicious { get; init; }
    public string[] Reasons { get; init; } = [];
}

/// <summary>
/// The result of hunting lateral movement across a host's event logs. <see cref="RemoteLogons"/> are inbound
/// Network/RDP logons from real remote sources (who authenticated from where); <see cref="ExplicitCredentialLogons"/>
/// are 4648 runas/alternate-credential events (pass-the-hash); <see cref="AdminShareAccess"/> is C$/ADMIN$ usage;
/// <see cref="ServiceInstalls"/> is every installed service (PsExec/implants), with <see cref="SuspiciousServiceInstalls"/>
/// the auto-flagged subset.
/// </summary>
public record LateralMovementReport
{
    public LogonEvent[] RemoteLogons { get; init; } = [];
    public LogonEvent[] ExplicitCredentialLogons { get; init; } = [];
    public ShareAccess[] AdminShareAccess { get; init; } = [];
    public ServiceInstall[] ServiceInstalls { get; init; } = [];

    public ServiceInstall[] SuspiciousServiceInstalls => ServiceInstalls.Where(s => s.Suspicious).ToArray();
}

/// <summary>One event-log-clearing event: which log was wiped (<see cref="ClearedLog"/>), by whom
/// (<see cref="User"/>), and when — a high-signal anti-forensics indicator (Security 1102 / System 104).</summary>
public record LogClearedEvent
{
    public DateTime? Time { get; init; }
    public int EventId { get; init; }
    public string? ClearedLog { get; init; }
    public string? User { get; init; }
    public string? Computer { get; init; }
}

/// <summary>The result of hunting event-log clearing. <see cref="Detected"/> is true when any clear occurred.</summary>
public record LogClearingReport
{
    public LogClearedEvent[] Events { get; init; } = [];
    public bool Detected => Events.Length > 0;
}

/// <summary>
/// One PowerShell script block recorded by script-block logging (event 4104) — the deobfuscated script text
/// PowerShell actually executed. <see cref="ScriptText"/> is the logged script; <see cref="DecodedText"/> is the
/// decoded payload when the block carried an encoded command. <see cref="Suspicious"/> marks blocks matching
/// download-cradle / obfuscation indicators (DownloadString, FromBase64, IEX, <c>-enc</c>, remote URLs).
/// </summary>
public record PowerShellScriptBlock
{
    public DateTime? Time { get; init; }
    public string? ScriptText { get; init; }
    public string? Path { get; init; }
    public string? ScriptBlockId { get; init; }
    public string? DecodedText { get; init; }
    public bool Suspicious { get; init; }
    public string[] Reasons { get; init; } = [];
}

/// <summary>
/// The result of analysing a PowerShell Operational log's script-block events. <see cref="ScriptBlocks"/> holds
/// every parsed block; <see cref="SuspiciousScriptBlocks"/> is the auto-flagged subset (download cradles,
/// base64/encoded payloads, dynamic execution).
/// </summary>
public record PowerShellReport
{
    public PowerShellScriptBlock[] ScriptBlocks { get; init; } = [];
    public PowerShellScriptBlock[] SuspiciousScriptBlocks => ScriptBlocks.Where(s => s.Suspicious).ToArray();
}

/// <summary>
/// One executable's evidence of execution, merged across the offline execution-evidence sources: Shimcache
/// (it existed on disk — <see cref="ShimcacheLastModified"/>) and Amcache (it was present/ran, with its
/// <see cref="Sha1"/> for threat-intel pivoting, <see cref="AmcacheTimestamp"/>, and PE <see cref="CompileTime"/>).
/// <see cref="Sources"/> lists which caches it appeared in. When <see cref="Suspicious"/>, <see cref="Reasons"/>
/// explains why (suspicious execution location, a notable hacking/anti-forensic tool, or a LOLBin masquerade).
/// </summary>
public record ExecutionArtifact
{
    public string Path { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Sha1 { get; init; }
    public DateTime? ShimcacheLastModified { get; init; }
    public DateTime? AmcacheTimestamp { get; init; }
    public DateTime? CompileTime { get; init; }
    public string[] Sources { get; init; } = [];
    public bool Suspicious { get; init; }
    public string[] Reasons { get; init; } = [];
}

/// <summary>
/// A unified, scored inventory of evidence of execution for a host, correlated from Shimcache and Amcache.
/// <see cref="Executables"/> is every executable seen; <see cref="SuspiciousExecutables"/> is the auto-flagged
/// subset. SHA-1s (from Amcache) are carried for VirusTotal / threat-intel pivoting.
/// </summary>
public record ExecutionReport
{
    public ExecutionArtifact[] Executables { get; init; } = [];
    public ExecutionArtifact[] SuspiciousExecutables => Executables.Where(e => e.Suspicious).ToArray();
}

/// <summary>
/// One remote network share a user connected to (a mapped drive or browsed UNC path), recovered from the
/// registry. <see cref="Unc"/> is the full <c>\\server\share</c>, split into <see cref="Server"/> and
/// <see cref="Share"/>; <see cref="Source"/> names the artifact it came from (MountPoints2, Map Network Drive
/// MRU). These are the file-copy / exfiltration channels in insider and lateral-movement cases.
/// </summary>
public record ExternalConnection
{
    public string Unc { get; init; } = "";
    public string? Server { get; init; }
    public string? Share { get; init; }
    public string Source { get; init; } = "";
    public DateTime? LastWrite { get; init; }
}

/// <summary>
/// The remote network shares a user connected to, reconstructed from a user's registry hives. NOTE: the
/// relevant keys frequently live in unreplayed transaction logs of a dirty hive (especially after anti-forensic
/// MRU cleaning), so this is sourced via RECmd, which replays the logs — RegRipper would miss them.
/// </summary>
public record ExternalConnectionReport
{
    public ExternalConnection[] RemoteShares { get; init; } = [];
}
