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

/// <summary>
/// The result of hunting code injection across a Windows memory image. Three orthogonal sources are merged:
/// <list type="bullet">
/// <item><see cref="UnlinkedDlls"/> — DLLs visible in the VAD tree but missing from one or more PEB lists
/// (the <c>ldrmodules</c> signal). Includes DLLs with no <c>MappedPath</c> (loaded outside the Windows API,
/// i.e. reflective DLL injection).</item>
/// <item><see cref="HollowedProcesses"/> — processes whose PEB image base disagrees with the in-memory VAD
/// or on-disk image (the <c>hollowprocesses</c> signal).</item>
/// <item><see cref="AnomalousRegions"/> — the underlying <c>malfind</c> report (MZ-headed and RWX regions).</item>
/// </list>
/// <see cref="SuspectPids"/> aggregates the distinct PIDs flagged by any source, ranked by total signals.
/// </summary>
public record CodeInjectionReport
{
    public WindowsLdrModules[] UnlinkedDlls { get; init; } = [];
    public WindowsHollowProcesses[] HollowedProcesses { get; init; } = [];
    public AnomalousMemoryReport AnomalousRegions { get; init; } = new([], [], []);

    /// <summary>Distinct PIDs flagged by any source, with the per-PID signal count, ordered by count desc.</summary>
    public (int Pid, string Process, int SignalCount)[] SuspectPids
    {
        get
        {
            var rows = UnlinkedDlls.Select(u => (u.PID, u.Process))
                .Concat(HollowedProcesses.Select(h => (h.PID, h.Process)))
                .Concat(AnomalousRegions.SuspectRegions.Select(r => (r.PID, r.Process)));
            return rows
                .GroupBy(r => r.PID)
                .Select(g => (Pid: g.Key, Process: g.First().Process, SignalCount: g.Count()))
                .OrderByDescending(g => g.SignalCount)
                .ThenBy(g => g.Pid)
                .ToArray();
        }
    }
}

/// <summary>
/// The result of hunting kernel rootkit hooks across a Windows memory image. Each row identifies a hook in
/// one of the three kernel hooking surfaces (<see cref="HookSurface"/>): <c>SSDT</c>, <c>Callback</c>, or
/// <c>IRP</c>. Legitimate entries owned by the canonical Microsoft kernel modules (<c>ntoskrnl</c>,
/// <c>win32k</c>, <c>hal</c>) are filtered out; what's left is rootkit, EDR, or third-party AV hooking — leads
/// to triage, not verdicts.
/// </summary>
public record KernelRootkitReport
{
    public KernelHook[] Hooks { get; init; } = [];
    public int SsdtScanned { get; init; }
    public int CallbacksScanned { get; init; }
    public int DriverIrpScanned { get; init; }

    /// <summary>Distinct foreign modules registering hooks, ordered by hook count.</summary>
    public (string Module, int HookCount)[] ForeignModules =>
        Hooks
            .GroupBy(h => h.Module ?? "?", StringComparer.OrdinalIgnoreCase)
            .Select(g => (Module: g.Key, HookCount: g.Count()))
            .OrderByDescending(g => g.HookCount)
            .ThenBy(g => g.Module, StringComparer.OrdinalIgnoreCase)
            .ToArray();
}

/// <summary>
/// One kernel hook found by <see cref="KernelRootkitReport"/>: the source <see cref="HookSurface"/> that
/// reported it, the hooked <see cref="Target"/> (SSDT symbol, callback type, or IRP major function), and the
/// foreign <see cref="Module"/> that owns the implementation.
/// </summary>
public record KernelHook
{
    public string HookSurface { get; init; } = "";
    public string Target { get; init; } = "";
    public string? Module { get; init; }
    public string? Symbol { get; init; }
    public long Address { get; init; }
}

/// <summary>
/// The result of a cross-view hidden-process scan via <c>windows.psxview</c>. Each row of the report names a
/// process and which of four enumeration sources (<see cref="HiddenProcessSighting.PsList"/>,
/// <see cref="HiddenProcessSighting.PsScan"/>, <see cref="HiddenProcessSighting.ThrdScan"/>,
/// <see cref="HiddenProcessSighting.Csrss"/>) saw it. <see cref="HiddenSightings"/> is the subset that exhibits
/// a visibility gap beyond the legitimate "exited but not yet freed" case (any process missing from
/// <c>psscan</c>, or missing from <c>pslist</c> while still running).
/// </summary>
public record CrossViewHiddenProcessReport
{
    public HiddenProcessSighting[] AllSightings { get; init; } = [];
    public HiddenProcessSighting[] HiddenSightings { get; init; } = [];
}

/// <summary>One row of a cross-view hidden-process report (see <see cref="CrossViewHiddenProcessReport"/>).</summary>
public record HiddenProcessSighting
{
    public int Pid { get; init; }
    public string Name { get; init; } = "";
    public string? ExitTime { get; init; }
    public bool PsList { get; init; }
    public bool PsScan { get; init; }
    public bool ThrdScan { get; init; }
    public bool Csrss { get; init; }

    public bool HasExited => !string.IsNullOrWhiteSpace(ExitTime);
    /// <summary>Sources that saw this process (the "True" columns).</summary>
    public string[] SeenBy =>
        new[] { PsList ? "pslist" : null, PsScan ? "psscan" : null, ThrdScan ? "thrdscan" : null, Csrss ? "csrss" : null }
            .Where(s => s is not null).ToArray()!;
    /// <summary>Sources that did NOT see this process (the "False" columns).</summary>
    public string[] MissedBy =>
        new[] { PsList ? null : "pslist", PsScan ? null : "psscan", ThrdScan ? null : "thrdscan", Csrss ? null : "csrss" }
            .Where(s => s is not null).ToArray()!;
}

/// <summary>
/// The result of reconstructing interactive-attacker console activity from a Windows memory image via
/// <c>windows.cmdscan</c> (typed commands) and <c>windows.consoles</c> (typed + program output). The
/// <see cref="ConsoleSessions"/> aggregate every recovered buffer per (PID, console process); the
/// <see cref="TypedCommands"/> flatten just the command history for quick triage.
/// </summary>
public record ConsoleHistoryReport
{
    public ConsoleSession[] ConsoleSessions { get; init; } = [];
    public TypedCommand[] TypedCommands { get; init; } = [];
}

/// <summary>One console buffer recovered from memory: which process hosted it, the typed command lines, and
/// (when <c>consoles</c> recovered it) the screen-buffer output.</summary>
public record ConsoleSession
{
    public int Pid { get; init; }
    public string Process { get; init; } = "";
    public string? Application { get; init; }
    public string[] TypedCommands { get; init; } = [];
    public string? ScreenOutput { get; init; }
}

/// <summary>One command typed in a console — its hosting PID and process, and the command line itself.</summary>
public record TypedCommand
{
    public int Pid { get; init; }
    public string Process { get; init; } = "";
    public string Command { get; init; } = "";
}

/// <summary>
/// The result of scanning every process's VAD regions for YARA-rule matches via <c>windows.vadyarascan</c>.
/// <see cref="Matches"/> is the raw match rows; <see cref="MatchesByRule"/> / <see cref="MatchesByProcess"/>
/// pivot for triage. Bring your own rules file — anything compatible with <c>yara</c>.
/// </summary>
public record MemoryYaraReport
{
    public WindowsVadYaraScan[] Matches { get; init; } = [];
    public string RulesFile { get; init; } = "";

    public (string Rule, int Count)[] MatchesByRule =>
        Matches.GroupBy(m => m.Rule).Select(g => (Rule: g.Key, Count: g.Count()))
            .OrderByDescending(g => g.Count).ThenBy(g => g.Rule).ToArray();
    public (int Pid, string Process, int Count)[] MatchesByProcess =>
        Matches.Where(m => m.PID is not null)
            .GroupBy(m => m.PID!.Value)
            .Select(g => (Pid: g.Key, Process: g.First().Process ?? "?", Count: g.Count()))
            .OrderByDescending(g => g.Count).ThenBy(g => g.Pid).ToArray();
}

/// <summary>
/// The result of a Skeleton Key check against an LSASS-bearing DC memory image
/// (<c>windows.skeleton_key_check</c>). On a clean DC the <see cref="Findings"/> are empty and
/// <see cref="IsCompromised"/> is false; a finding indicates a patched <c>CDLocateCSystem</c>, the canonical
/// implant signature.
/// </summary>
public record SkeletonKeyReport
{
    public WindowsSkeletonKeyCheck[] Findings { get; init; } = [];
    public bool IsCompromised => Findings.Any(f => f.SkeletonKeyFound == true);
}
