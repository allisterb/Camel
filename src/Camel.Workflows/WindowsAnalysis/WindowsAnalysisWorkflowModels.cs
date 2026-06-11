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
public record KeyRegistryArtifact
{
    public string Name { get; }
    public RegistryEntry[] Entries { get; }
    public KeyRegistryArtifact(string name, RegistryEntry[] entries)
    {
        this.Name = name;
        this.Entries = entries;
    }
}

/// <summary>
/// The result of batch-parsing a directory of registry hives with RECmd's DFIR batch file and bucketing the
/// output into the key forensic artifacts. <see cref="Artifacts"/> holds one <see cref="KeyRegistryArtifact"/> per
/// artifact category (Run keys, UserAssist, USBSTOR, Shimcache, …); <see cref="AllEntries"/> is the complete
/// RECmd output for anything not covered by a named bucket.
/// </summary>
public record KeyRegistryArtifactsReport
{
    public KeyRegistryArtifact[] Artifacts { get; }
    public RegistryEntry[] AllEntries { get; }
    public KeyRegistryArtifactsReport(KeyRegistryArtifact[] artifacts, RegistryEntry[] allEntries)
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
public record RegistryPersistenceMechanism
{
    public string Category { get; }
    public PersistenceEntry[] Entries { get; }
    public RegistryPersistenceMechanism(string category, PersistenceEntry[] entries)
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
public record RegistryPersistenceReport
{
    public RegistryPersistenceMechanism[] Mechanisms { get; }
    public PersistenceEntry[] AllEntries { get; }
    public PersistenceEntry[] SuspiciousEntries { get; }
    public RegistryPersistenceReport(RegistryPersistenceMechanism[] mechanisms)
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
/// One Kerberos authentication event parsed from a Domain Controller's Security log: a TGT request (4768),
/// a service-ticket request (4769), or a pre-auth failure (4771). <see cref="TicketEncryptionType"/> is the raw
/// hex encryption-type code from the event (<c>0x17</c> = RC4-HMAC, <c>0x12</c> = AES256, …) and
/// <see cref="TicketEncryptionName"/> its human-readable name — the key Kerberoasting/AS-REP-roasting discriminator
/// (an attacker requests RC4 so the response can be cracked offline). <see cref="Status"/> is the raw Kerberos
/// status (<c>0x0</c> = success, <c>0x18</c> = bad password / pre-auth fail, …); <see cref="PreAuthType"/> on a 4768
/// is <c>"0"</c> only when pre-authentication was not required — the AS-REP-roasting precondition. When
/// <see cref="Suspicious"/> is true, <see cref="Reasons"/> explains why (Kerberoasting / AS-REP roasting).
/// </summary>
public record KerberosEvent
{
    public DateTime? Time { get; init; }
    public int EventId { get; init; }
    public string? TargetUser { get; init; }
    public string? TargetDomain { get; init; }
    public string? ServiceName { get; init; }
    public string? ClientIp { get; init; }
    public string? TicketEncryptionType { get; init; }
    public string? TicketEncryptionName { get; init; }
    public string? Status { get; init; }
    public string? StatusName { get; init; }
    public string? PreAuthType { get; init; }
    public string? Computer { get; init; }
    public bool Suspicious { get; init; }
    public string[] Reasons { get; init; } = [];
}

/// <summary>
/// A burst of Kerberos pre-authentication failures (4771) from a single <see cref="SourceIp"/>: how many failures
/// (<see cref="FailureCount"/>), against which accounts (<see cref="AffectedAccounts"/>), and the time window
/// (<see cref="FirstSeen"/> … <see cref="LastSeen"/>). A burst targeting many accounts is a password spray; one
/// targeting a single account is a brute-force attempt.
/// </summary>
public record KerberosPreAuthBurst
{
    public string SourceIp { get; init; } = "";
    public int FailureCount { get; init; }
    public string[] AffectedAccounts { get; init; } = [];
    public DateTime? FirstSeen { get; init; }
    public DateTime? LastSeen { get; init; }
}

/// <summary>
/// The result of hunting Kerberos attacks in a Security event log. <see cref="Events"/> holds every parsed
/// Kerberos event; the computed views surface the high-precision attacks the methodology calls out —
/// <see cref="KerberoastingAttempts"/> (4769 RC4 service-ticket requests, the offline-cracking precondition),
/// <see cref="AsRepRoastingAttempts"/> (4768 successes against accounts where pre-auth is disabled), and
/// <see cref="PreAuthFailureBursts"/> (4771 brute-force / password-spray sources).
/// </summary>
public record KerberosReport
{
    public KerberosEvent[] Events { get; init; } = [];
    public KerberosPreAuthBurst[] PreAuthFailureBursts { get; init; } = [];

    public KerberosEvent[] KerberoastingAttempts => Events.Where(e => e.EventId == 4769 && e.Suspicious).ToArray();
    public KerberosEvent[] AsRepRoastingAttempts => Events.Where(e => e.EventId == 4768 && e.Suspicious).ToArray();
    public KerberosEvent[] SuspiciousEvents => Events.Where(e => e.Suspicious).ToArray();
}

/// <summary>
/// An executable surfaced by the "adversary hiding in plain sight" file-system triage. <see cref="Kind"/>
/// distinguishes a <em>system-process masquerade</em> — a file named like a core Windows process (svchost.exe,
/// lsass.exe, services.exe, …; <see cref="Impersonates"/> names it) found outside that process's canonical
/// directory — from a <em>transient-location executable</em> — an <c>.exe/.scr/.com/.pif</c> dropped in a
/// Temp / PerfLogs location where executables do not normally reside. Component-store copies (<c>\WinSxS</c>,
/// <c>\servicing</c>, <c>\DriverStore</c>, <c>\Windows.old</c>) are excluded from the masquerade check. Leads to triage.
/// </summary>
public record SuspiciousExecutable
{
    public string Path { get; init; } = "";
    public string Name { get; init; } = "";
    public long Size { get; init; }
    public string Kind { get; init; } = "";
    public string? Impersonates { get; init; }
    public string[] Reasons { get; init; } = [];
}

/// <summary>
/// The result of triaging a mounted Windows volume for executables hiding in plain sight: the
/// <see cref="Findings"/> and the number of candidate files examined (<see cref="FilesScanned"/>).
/// </summary>
public record SuspiciousExecutableReport
{
    public SuspiciousExecutable[] Findings { get; init; } = [];
    public int FilesScanned { get; init; }
}

/// <summary>
/// One remote network share a user connected to (a mapped drive or browsed UNC path), recovered from the
/// registry. <see cref="Unc"/> is the full <c>\\server\share</c>, split into <see cref="Server"/> and
/// <see cref="Share"/>; <see cref="Source"/> names the artifact it came from (MountPoints2, Map Network Drive
/// MRU). These are the file-copy / exfiltration channels in insider and lateral-movement cases.
/// </summary>
public record ExternalShareConnection
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
public record ExternalShareConnectionsReport
{
    public ExternalShareConnection[] RemoteShares { get; init; } = [];
}
