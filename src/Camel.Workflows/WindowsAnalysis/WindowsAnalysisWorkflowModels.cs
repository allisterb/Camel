namespace Camel.Workflows.Models;

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
