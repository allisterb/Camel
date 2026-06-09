namespace Camel.Workflows;

using System.Linq;

using Camel.Workflows.Models;

public class MemoryAnalysisWorkflow : Workflow
{
    public MemoryAnalysisWorkflow(CamelApi api) : base(api) {}

    /// <summary>
    /// Detects hidden processes in a Windows memory image by cross-referencing two enumeration techniques —
    /// the canonical first step of the memory-forensics methodology. <c>windows.pslist</c> walks the active
    /// EPROCESS linked list (fast, but a rootkit can unlink an entry to hide it); <c>windows.psscan</c> scans
    /// the pool for <c>Proc</c> tags and so also finds processes that are unlinked, hidden, or already exited.
    /// Processes present in psscan but absent from pslist (matched by PID) are split by exit state: those with
    /// no exit time are reported as <see cref="HiddenProcessReport.HiddenProcesses"/> (still running yet
    /// unlinked — the DKOM-rootkit indicator), while those that had exited are reported separately as
    /// <see cref="HiddenProcessReport.ExitedProcesses"/> (routine, but worth correlating with the timeline).
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    public async Task<WorkflowResult<HiddenProcessReport>> FindHiddenProcessAsync(string imageFile)
    {
        using var op = Begin("Finding hidden processes in {0}", imageFile);

        // Active-process linked-list walk: fast, but misses unlinked (hidden) and exited processes.
        var psList = await MemoryAnalysis.WindowsPsListAsync(imageFile);
        if (psList is null)
            return WorkflowResult<HiddenProcessReport>.Failure(
                $"windows.pslist failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        // Pool-tag scan: finds EPROCESS structures the list walk can't, including hidden/exited processes.
        var psScan = await MemoryAnalysis.WindowsPsScanAsync(imageFile);
        if (psScan is null)
            return WorkflowResult<HiddenProcessReport>.Failure(
                $"windows.psscan failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        // Processes the pool scan found but the linked-list walk missed (matched on PID), then split by exit
        // state: no ExitTime => still running yet unlinked (genuinely hidden); ExitTime set => already exited.
        var listedPids = psList.Select(p => p.PID).ToHashSet();
        var notListed = psScan.Where(p => !listedPids.Contains(p.PID)).ToArray();
        var hidden = notListed.Where(p => p.ExitTime is null).ToArray();
        var exited = notListed.Where(p => p.ExitTime is not null).ToArray();

        op.Complete();
        return WorkflowResult<HiddenProcessReport>.Success(
            new HiddenProcessReport(hidden, exited, psList.Length, psScan.Length),
            hidden.Length == 0
                ? $"No hidden processes ({exited.Length} exited process(es) recovered only by psscan)."
                : $"Found {hidden.Length} hidden process(es) — in psscan, unlinked from pslist, still running: " +
                  string.Join(", ", hidden.Select(h => $"{h.ImageFileName} (PID {h.PID})")) +
                  $". Plus {exited.Length} exited process(es) recovered only by psscan.");
    }

    /// <summary>
    /// Scans a Windows memory image for services with suspicious binary paths. <c>windows.svcscan</c> pool-
    /// scans for service records — surfacing hidden, deleted, and not-yet-loaded services the live SCM view
    /// can miss — and this flags any whose backing binary or hosting DLL resides in a location legitimate
    /// services do not use, per the services-triage step of the methodology. Defaults to the standard unusual-
    /// location set (<c>\temp\</c>, <c>\appdata\</c>, <c>\users\</c>); pass <paramref name="suspiciousPathFragments"/>
    /// to override.
    /// </summary>
    /// <param name="imageFile">Path to the Windows memory image to analyse.</param>
    /// <param name="suspiciousPathFragments">Path substrings (case-insensitive) that mark a service binary as
    /// suspicious. Defaults to <c>\temp\</c>, <c>\appdata\</c>, <c>\users\</c> when none are supplied.</param>
    public async Task<WorkflowResult<SuspiciousServiceReport>> FindHiddenServicesAsync(
        string imageFile, params string[] suspiciousPathFragments)
    {
        if (suspiciousPathFragments.Length == 0)
            suspiciousPathFragments = [@"\temp\", @"\appdata\", @"\users\"];

        using var op = Begin("Finding services with suspicious binary paths in {0}", imageFile);

        // Pool-tag service scan: surfaces every service, including hidden/deleted/not-yet-loaded ones.
        var services = await MemoryAnalysis.WindowsSvcScanAsync(imageFile);
        if (services is null)
            return WorkflowResult<SuspiciousServiceReport>.Failure(
                $"windows.svcscan failed for '{imageFile}'; the image may be unreadable or its symbols unavailable.");

        // A service is suspicious when its binary (ImagePath, from memory or the registry) or hosting DLL lives
        // in a directory legitimate Windows services do not use.
        bool Suspicious(string? path) =>
            path is not null && suspiciousPathFragments.Any(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));
        var suspicious = services
            .Where(s => Suspicious(s.Binary) || Suspicious(s.BinaryRegistry) || Suspicious(s.Dll))
            .ToArray();

        op.Complete();
        return WorkflowResult<SuspiciousServiceReport>.Success(
            new SuspiciousServiceReport(suspicious, services.Length),
            suspicious.Length == 0
                ? $"No services with suspicious binary paths among {services.Length} scanned."
                : $"Found {suspicious.Length} service(s) with suspicious binary paths: " +
                  string.Join(", ", suspicious.Select(s => $"{s.Name} ({s.Binary ?? s.BinaryRegistry ?? s.Dll})")) + ".");
    }
}
