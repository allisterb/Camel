namespace Camel.Workflows.Models;

using System.Linq;

using Camel.Toolkits.Models;

/// <summary>
/// The result of comparing a pool-tag process scan (<c>windows.psscan</c>) against the active-process
/// linked-list walk (<c>windows.pslist</c>). Both collections hold EPROCESS structures the scan found but
/// the list walk missed (present in psscan, absent from pslist by PID), split by whether the process had
/// exited at capture time:
/// <list type="bullet">
/// <item><see cref="HiddenProcesses"/> — no exit time yet missing from the active list: a still-running
/// process unlinked from the EPROCESS list, the classic DKOM-rootkit indicator. High signal.</item>
/// <item><see cref="ExitedProcesses"/> — have an exit time: processes that terminated before capture and
/// are only recoverable by pool scanning. Usually routine, but worth correlating with the timeline.</item>
/// </list>
/// <see cref="PsListCount"/> / <see cref="PsScanCount"/> give the raw enumeration sizes for context.
/// </summary>
public record HiddenProcessReport
{
    public WindowsPsScan[] HiddenProcesses { get; }
    public WindowsPsScan[] ExitedProcesses { get; }
    public int PsListCount { get; }
    public int PsScanCount { get; }
    public HiddenProcessReport(WindowsPsScan[] hiddenProcesses, WindowsPsScan[] exitedProcesses, int psListCount, int psScanCount)
    {
        this.HiddenProcesses = hiddenProcesses;
        this.ExitedProcesses = exitedProcesses;
        this.PsListCount = psListCount;
        this.PsScanCount = psScanCount;
    }
}

/// <summary>
/// The result of scanning a Windows memory image for services with suspicious binary paths. A pool-tag
/// service scan (<c>windows.svcscan</c>) surfaces every service — including hidden, deleted, and not-yet-
/// loaded ones that the live SCM view can miss — and <see cref="SuspiciousServices"/> are those whose backing
/// binary or hosting DLL lives in a directory legitimate Windows services do not use (e.g. <c>%TEMP%</c>,
/// <c>%APPDATA%</c>, a user profile), a common malware-persistence indicator. <see cref="TotalServices"/> is
/// the full count scanned, for context.
/// </summary>
public record SuspiciousServiceReport
{
    public WindowsSvcScan[] SuspiciousServices { get; }
    public int TotalServices { get; }
    public SuspiciousServiceReport(WindowsSvcScan[] suspiciousServices, int totalServices)
    {
        this.SuspiciousServices = suspiciousServices;
        this.TotalServices = totalServices;
    }
}

/// <summary>
/// The result of scanning a Windows memory image for code-injection and process-hollowing indicators with
/// <c>windows.malfind</c>. Every malfind hit (<see cref="SuspectRegions"/>) is already a private, executable
/// memory region with no file backing — anomalous by itself. Two stronger indicators are surfaced from it:
/// <list type="bullet">
/// <item><see cref="MzHeaderRegions"/> — regions that begin with an <c>MZ</c>/PE header: an executable image
/// mapped into memory that no file on disk backs, the classic process-hollowing / PE-injection indicator.</item>
/// <item><see cref="RwxRegions"/> — regions with read-write-execute protection (<c>PAGE_EXECUTE_READWRITE</c>):
/// a writable code region, the classic shellcode-injection indicator.</item>
/// </list>
/// A region may appear in both lists. malfind is prone to false positives (JIT, .NET CLR), so triage hits.
/// When dumping is requested, <see cref="DumpedExecutables"/> / <see cref="DumpedProcessMemory"/> carry the
/// workstation paths of the extracted artifacts for downstream triage (strings, YARA, etc.).
/// </summary>
public record AnomalousMemoryReport
{
    public WindowsMalFind[] MzHeaderRegions { get; }
    public WindowsMalFind[] RwxRegions { get; }
    public WindowsMalFind[] SuspectRegions { get; }

    /// <summary>Paths of dumped process executables (PE images), when a dump directory was requested.</summary>
    public string[] DumpedExecutables { get; init; } = [];
    /// <summary>Paths of dumped process memory images, when a dump directory was requested.</summary>
    public string[] DumpedProcessMemory { get; init; } = [];
    /// <summary>
    /// Paths of the per-process ASCII and Unicode strings files extracted from the dumped memory, when both a
    /// memory dump and a strings directory were requested.
    /// </summary>
    public string[] ExtractedStrings { get; init; } = [];

    public AnomalousMemoryReport(WindowsMalFind[] mzHeaderRegions, WindowsMalFind[] rwxRegions, WindowsMalFind[] suspectRegions)
    {
        this.MzHeaderRegions = mzHeaderRegions;
        this.RwxRegions = rwxRegions;
        this.SuspectRegions = suspectRegions;
    }
}

/// <summary>
/// The result of collecting the unique remote IP addresses a memory image's network connections reference,
/// for IOC pivoting. Derived from <c>windows.netscan</c> (a pool-tag scan, so historical/closed connections
/// are recovered alongside active ones). <see cref="RemoteIPs"/> is the de-duplicated, sorted list of foreign
/// addresses with loopback, unspecified, and wildcard endpoints (127.0.0.1, ::1, 0.0.0.0, ::, *) excluded;
/// <see cref="Connections"/> is the full netscan output for correlating each IP to its port, state, and owner.
/// </summary>
public record RemoteIpReport
{
    public string[] RemoteIPs { get; }
    public WindowsNetScan[] Connections { get; }
    public RemoteIpReport(string[] remoteIPs, WindowsNetScan[] connections)
    {
        this.RemoteIPs = remoteIPs;
        this.Connections = connections;
    }
}

/// <summary>
/// The result of generating a memory-artifact timeline: the path to the sorted timeline file written on the
/// workstation, and the intermediate mactime bodyfile (<c>volatility.body</c>) it was rendered from — kept so
/// the timeline can be re-rendered with filters (date ranges, etc.) without re-running timeliner.
/// </summary>
public record MemoryTimeline
{
    public string TimelinePath { get; }
    public string BodyfilePath { get; }
    public MemoryTimeline(string timelinePath, string bodyfilePath)
    {
        this.TimelinePath = timelinePath;
        this.BodyfilePath = bodyfilePath;
    }
}

/// <summary>
/// One LSA secret recovered from memory: its <see cref="Key"/>, the raw <see cref="Hex"/> bytes, and —
/// when the bytes decode to printable text (UTF-16) — the <see cref="DecodedText"/>. Many LSA secrets are
/// plaintext (service-account passwords, the DefaultPassword auto-logon value); binary key material decodes
/// to null.
/// </summary>
public record LsaSecret
{
    public string Key { get; init; } = "";
    public string? Hex { get; init; }
    public string? DecodedText { get; init; }
}

/// <summary>
/// The credential material recovered from a Windows memory image: local account NTLM hashes from the SAM
/// (<see cref="LocalHashes"/>), <see cref="LsaSecrets"/>, and cached domain credentials
/// (<see cref="CachedCredentials"/>, mscash/mscash2). This scopes what an attacker who accessed this host could
/// have harvested — pivot the hashes for pass-the-hash exposure and crack the cached creds / read plaintext secrets.
/// </summary>
public record CredentialReport
{
    public WindowsHashdump[] LocalHashes { get; init; } = [];
    public LsaSecret[] LsaSecrets { get; init; } = [];
    public WindowsCachedump[] CachedCredentials { get; init; } = [];

    /// <summary>LSA secrets whose bytes decoded to printable plaintext (the high-value subset).</summary>
    public LsaSecret[] PlaintextSecrets => LsaSecrets.Where(s => !string.IsNullOrEmpty(s.DecodedText)).ToArray();
}
