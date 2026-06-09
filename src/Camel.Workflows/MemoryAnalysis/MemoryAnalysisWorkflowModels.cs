namespace Camel.Workflows.Models;

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

    public AnomalousMemoryReport(WindowsMalFind[] mzHeaderRegions, WindowsMalFind[] rwxRegions, WindowsMalFind[] suspectRegions)
    {
        this.MzHeaderRegions = mzHeaderRegions;
        this.RwxRegions = rwxRegions;
        this.SuspectRegions = suspectRegions;
    }
}
