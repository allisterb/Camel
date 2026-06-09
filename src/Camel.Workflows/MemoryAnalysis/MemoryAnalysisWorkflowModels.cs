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
