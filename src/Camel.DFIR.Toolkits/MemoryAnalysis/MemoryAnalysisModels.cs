namespace Camel.DFIR.Toolkits.Models;

using System;
using System.Text.Json.Serialization;


public class WindowsInfo
{
    public string Value { get; set; } = "";
    public string Variable { get; set; } = "";
    public object[] __children { get; set; } = [];
}

/// <summary>windows.hashdump: a local account's NTLM hashes recovered from the SAM in a memory image.</summary>
public class WindowsHashdump
{
    public string User { get; set; } = "";
    [JsonPropertyName("rid")] public int Rid { get; set; }
    [JsonPropertyName("lmhash")] public string? LmHash { get; set; }
    [JsonPropertyName("nthash")] public string? NtHash { get; set; }
}

/// <summary>
/// windows.lsadump: one LSA secret (service-account passwords, DPAPI master keys, DefaultPassword auto-logon,
/// machine account secret, …). <see cref="Secret"/>/<see cref="Hex"/> are space-separated hex bytes; many
/// secrets are UTF-16 plaintext once decoded.
/// </summary>
public class WindowsLsadump
{
    public string Key { get; set; } = "";
    public string? Secret { get; set; }
    public string? Hex { get; set; }
}

/// <summary>
/// windows.cachedump: a cached domain credential (mscash/mscash2 — crackable offline). NOTE: the field mapping
/// is schema-derived from the plugin's columns; the validation image held no cached creds to verify against.
/// </summary>
public class WindowsCachedump
{
    public string? Username { get; set; }
    public string? Domain { get; set; }
    [JsonPropertyName("Domain name")] public string? DomainName { get; set; }
    public string? Hash { get; set; }
}

/// <summary>
/// A single row from a Volatility dump plugin (e.g. <c>windows.pslist --dump</c>, <c>windows.memmap --dump</c>):
/// captures only the <c>File output</c> column, which names the file the plugin wrote to the output directory
/// (or an error/"Disabled" marker when nothing was dumped).
/// </summary>
public class WindowsDump
{
    [JsonPropertyName("File output")]
    public string? FileOutput { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsPsList
{
    public DateTime? CreateTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public string Fileoutput { get; set; } = "";
    public object? Handles { get; set; } = null;
    public string ImageFileName { get; set; } = "";
    public long OffsetV { get; set; }
    public int PID { get; set; }
    public int PPID { get; set; }
    public int? SessionId { get; set; }
    public int Threads { get; set; }
    public bool Wow64 { get; set; }
    public WindowsPsTree[] __children { get; set; } = [];
}

public class WindowsPsScan
{
    public DateTime? CreateTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public string Fileoutput { get; set; } = "";
    public object? Handles { get; set; }
    public string ImageFileName { get; set; } = "";
    public long OffsetV { get; set; }
    public int PID { get; set; }
    public int PPID { get; set; }
    public int? SessionId { get; set; }
    public int Threads { get; set; }
    public bool Wow64 { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsSvcScan
{
    public string? Binary { get; set; }
    [JsonPropertyName("Binary (Registry)")]
    public string? BinaryRegistry { get; set; }
    public string Display { get; set; } = "";
    public string? Dll { get; set; }
    public string Name { get; set; } = "";
    public long Offset { get; set; }
    public int Order { get; set; }
    public int? PID { get; set; }
    public string Start { get; set; } = "";
    public string State { get; set; } = "";
    public string Type { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsCmdLine
{
    public string? Args { get; set; }
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsEnvVars
{
    public string Block { get; set; } = "";
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public string Value { get; set; } = "";
    public string Variable { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsGetSids
{
    public string Name { get; set; } = "";
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public string SID { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsPrivs
{
    public string Attributes { get; set; } = "";
    public string Description { get; set; } = "";
    public int PID { get; set; }
    public string Privilege { get; set; } = "";
    public string Process { get; set; } = "";
    public int Value { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsHandles
{
    public long GrantedAccess { get; set; }
    public long HandleValue { get; set; }
    public string? Name { get; set; }
    public long Offset { get; set; }
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public string Type { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsMalFind
{
    public long CommitCharge { get; set; }
    public string Disasm { get; set; } = "";
    [JsonPropertyName("End VPN")]
    public long EndVPN { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public string Hexdump { get; set; } = "";
    public string? Notes { get; set; }
    public int PID { get; set; }
    public long PrivateMemory { get; set; }
    public string Process { get; set; } = "";
    public string Protection { get; set; } = "";
    [JsonPropertyName("Start VPN")]
    public long StartVPN { get; set; }
    public string Tag { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsNetStat
{
    public long Offset { get; set; }
    public string Proto { get; set; } = "";
    public string LocalAddr { get; set; } = "";
    public int LocalPort { get; set; }
    public string ForeignAddr { get; set; } = "";
    public int ForeignPort { get; set; }
    public string State { get; set; } = "";
    public int? PID { get; set; }
    public string Owner { get; set; } = "";
    public DateTime? Created { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsNetScan
{
    public long Offset { get; set; }
    public string Proto { get; set; } = "";
    public string LocalAddr { get; set; } = "";
    public int LocalPort { get; set; }
    public string ForeignAddr { get; set; } = "";
    public int ForeignPort { get; set; }
    public string State { get; set; } = "";
    public int? PID { get; set; }
    public string Owner { get; set; } = "";
    public DateTime? Created { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsDllList
{
    public long Base { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public int LoadCount { get; set; }
    public DateTime? LoadTime { get; set; }
    public string? Name { get; set; }
    public int PID { get; set; }
    public string? Path { get; set; }
    public string Process { get; set; } = "";
    public long Size { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsGetServiceSids
{
    public string SID { get; set; } = "";
    public string Service { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsModules
{
    public long Base { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public string Name { get; set; } = "";
    public long Offset { get; set; }
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsModScan
{
    public long Base { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public string Name { get; set; } = "";
    public long Offset { get; set; }
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsFileScan
{
    public string Name { get; set; } = "";
    public long Offset { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsVadInfo
{
    public long CommitCharge { get; set; }
    [JsonPropertyName("End VPN")]
    public long EndVPN { get; set; }
    public string? File { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public long Offset { get; set; }
    public int PID { get; set; }
    public long Parent { get; set; }
    public long PrivateMemory { get; set; }
    public string Process { get; set; } = "";
    public string Protection { get; set; } = "";
    [JsonPropertyName("Start VPN")]
    public long StartVPN { get; set; }
    public string Tag { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsRegistryHiveList
{
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public string FileFullPath { get; set; } = "";
    public long Offset { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsRegistryPrintKey
{
    public string Data { get; set; } = "";
    [JsonPropertyName("Hive Offset")]
    public long HiveOffset { get; set; }
    public string Key { get; set; } = "";
    [JsonPropertyName("Last Write Time")]
    public DateTime? LastWriteTime { get; set; }
    public string? Name { get; set; }
    public string Type { get; set; } = "";
    public bool? Volatile { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsRegistryUserAssist
{
    public int? Count { get; set; }
    [JsonPropertyName("Focus Count")]
    public int? FocusCount { get; set; }
    [JsonPropertyName("Hive Name")]
    public string HiveName { get; set; } = "";
    [JsonPropertyName("Hive Offset")]
    public long HiveOffset { get; set; }
    public int? ID { get; set; }
    [JsonPropertyName("Last Updated")]
    public DateTime? LastUpdated { get; set; }
    [JsonPropertyName("Last Write Time")]
    public DateTime? LastWriteTime { get; set; }
    public string? Name { get; set; }
    public string Path { get; set; } = "";
    [JsonPropertyName("Raw Data")]
    public string RawData { get; set; } = "";
    [JsonPropertyName("Time Focused")]
    public string? TimeFocused { get; set; }
    public string Type { get; set; } = "";
    public WindowsRegistryUserAssist[] __children { get; set; } = [];
}


public class WindowsPsTree
{
    public string Audit { get; set; } = "";
    public string Cmd { get; set; } = "";
    public DateTime? CreateTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public object? Handles { get; set; }
    public string ImageFileName { get; set; } = "";
    public long OffsetV { get; set; }
    public int PID { get; set; }
    public int PPID { get; set; }
    public string Path { get; set; } = "";
    public int? SessionId { get; set; }
    public int Threads { get; set; }
    public bool Wow64 { get; set; }
    public WindowsPsTree[] __children { get; set; } = [];
}

/// <summary>
/// windows.ldrmodules: one DLL/module mapping in a process, with the three PEB doubly-linked-list flags
/// (<see cref="InLoad"/>, <see cref="InInit"/>, <see cref="InMem"/>) and the VAD-tree-derived
/// <see cref="MappedPath"/>. Stealthy injection unlinks the DLL from one or more lists (an entry present in
/// VAD but missing in the PEB lists, or with no MappedPath, is the injection indicator).
/// </summary>
public class WindowsLdrModules
{
    public long Base { get; set; }
    public bool InInit { get; set; }
    public bool InLoad { get; set; }
    public bool InMem { get; set; }
    public string? MappedPath { get; set; }
    [JsonPropertyName("Pid")] public int PID { get; set; }
    public string Process { get; set; } = "";
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.hollowprocesses: a process flagged for hollowing — the PEB's image base doesn't match the in-memory
/// VAD or the on-disk image. <see cref="Notes"/> describes which check failed.
/// </summary>
public class WindowsHollowProcesses
{
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public string? Notes { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.threads: one thread in a process. <see cref="StartAddress"/> / <see cref="StartPath"/> identify
/// the kernel start; <see cref="Win32StartAddress"/> / <see cref="Win32StartPath"/> the user-mode start
/// (where an injected thread typically diverges from a host-process baseline).
/// </summary>
public class WindowsThreads
{
    public DateTime? CreateTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public long Offset { get; set; }
    public int PID { get; set; }
    public long StartAddress { get; set; }
    public string? StartPath { get; set; }
    public int TID { get; set; }
    public long Win32StartAddress { get; set; }
    public string? Win32StartPath { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.ssdt: one System Service Descriptor Table entry. Entries legitimately point into
/// <c>ntoskrnl</c> / <c>win32k</c>; any other <see cref="Module"/> is a kernel SSDT hook (rootkit indicator).
/// </summary>
public class WindowsSsdt
{
    public long Address { get; set; }
    public int Index { get; set; }
    public string Module { get; set; } = "";
    public string? Symbol { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.callbacks: one registered kernel callback (image/thread/process/registry notify routines, Bug-check
/// callbacks, …). <see cref="Module"/> identifies who registered it; foreign (non-MS) modules registering
/// callbacks are common rootkit / EDR indicators.
/// </summary>
public class WindowsCallbacks
{
    public long Callback { get; set; }
    public string? Detail { get; set; }
    public string? Module { get; set; }
    public string? Symbol { get; set; }
    public string Type { get; set; } = "";
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.driverirp: one Major Function entry in a driver's IRP_MJ table. Entries legitimately resolve to
/// the owning driver or <c>ntoskrnl</c>; any other <see cref="Module"/> is an IRP-table hook.
/// </summary>
public class WindowsDriverIrp
{
    public long Address { get; set; }
    [JsonPropertyName("Driver Name")] public string DriverName { get; set; } = "";
    public string IRP { get; set; } = "";
    public string Module { get; set; } = "";
    public long Offset { get; set; }
    public string? Symbol { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.psxview: a process viewed by four enumeration sources (<see cref="PsList"/>, <see cref="PsScan"/>,
/// <see cref="ThrdScan"/>, <see cref="Csrss"/>). A process visible in some sources but not others — beyond the
/// legitimate "exited but not yet freed" case — is the cross-view hidden-process indicator.
/// </summary>
public class WindowsPsxView
{
    [JsonPropertyName("Exit Time")] public string? ExitTime { get; set; }
    public string Name { get; set; } = "";
    [JsonPropertyName("Offset(Virtual)")] public long OffsetVirtual { get; set; }
    public int PID { get; set; }
    [JsonPropertyName("csrss")] public bool Csrss { get; set; }
    [JsonPropertyName("pslist")] public bool PsList { get; set; }
    [JsonPropertyName("psscan")] public bool PsScan { get; set; }
    [JsonPropertyName("thrdscan")] public bool ThrdScan { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.mutantscan: one mutant (mutex) object found by pool-tag scanning. Named mutexes are the
/// canonical malware-family IOC (single-instance markers; e.g. <c>Global\ZeusMutex</c>).
/// </summary>
public class WindowsMutantScan
{
    public string? Name { get; set; }
    public long Offset { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.cmdscan: one COMMAND_HISTORY buffer recovered from a console host (cmd.exe / conhost.exe), with
/// the typed command lines.
/// </summary>
public class WindowsCmdScan
{
    [JsonPropertyName("CommandHistory")] public long CommandHistory { get; set; }
    [JsonPropertyName("CommandCountMax")] public int? CommandCountMax { get; set; }
    [JsonPropertyName("LastAdded")] public int? LastAdded { get; set; }
    [JsonPropertyName("LastDisplayed")] public int? LastDisplayed { get; set; }
    [JsonPropertyName("ProcessHandle")] public long? ProcessHandle { get; set; }
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public string? Application { get; set; }
    [JsonPropertyName("Cmd")] public string? Cmd { get; set; }
    [JsonPropertyName("Data")] public string? Data { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.consoles: one CONSOLE_INFORMATION buffer — what was displayed in the console (typed commands plus
/// the output written back). More comprehensive than cmdscan: includes program output.
/// </summary>
public class WindowsConsoles
{
    public int PID { get; set; }
    public string Process { get; set; } = "";
    [JsonPropertyName("ConsoleProcess")] public string? ConsoleProcess { get; set; }
    public int? ConsolePid { get; set; }
    [JsonPropertyName("ScreenBuffer")] public long? ScreenBuffer { get; set; }
    [JsonPropertyName("Data")] public string? Data { get; set; }
    [JsonPropertyName("Cmd")] public string? Cmd { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.shimcachemem: one Application Compatibility Cache entry recovered from kernel memory (i.e. before
/// it would be flushed to the SYSTEM hive at shutdown). <see cref="FilePath"/> + <see cref="LastModified"/>
/// are the canonical execution-evidence pair.
/// </summary>
public class WindowsShimcacheMem
{
    [JsonPropertyName("Exec Flag")] public string? ExecFlag { get; set; }
    [JsonPropertyName("File Path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("File Size")] public long? FileSize { get; set; }
    [JsonPropertyName("Last Modified")] public DateTime? LastModified { get; set; }
    [JsonPropertyName("Last Update")] public DateTime? LastUpdate { get; set; }
    public int Order { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.skeleton_key_check: an LSASS-resident Skeleton Key implant indicator on a Domain Controller —
/// when a patched <c>CDLocateCSystem</c> is detected the row carries the implant details. Empty result = clean.
/// </summary>
public class WindowsSkeletonKeyCheck
{
    public int? PID { get; set; }
    public string? Process { get; set; }
    [JsonPropertyName("Skeleton Key Found")] public bool? SkeletonKeyFound { get; set; }
    [JsonPropertyName("rc4HmacInitialize")] public long? Rc4HmacInitialize { get; set; }
    [JsonPropertyName("rc4HmacDecrypt")] public long? Rc4HmacDecrypt { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.processghosting: a process whose backing file was deleted before <c>NtCreateProcessEx</c> — the
/// Process Ghosting evasion. Empty result = clean.
/// </summary>
public class WindowsProcessGhosting
{
    public int PID { get; set; }
    public string Process { get; set; } = "";
    [JsonPropertyName("DeletePending")] public int? DeletePending { get; set; }
    [JsonPropertyName("FILE_OBJECT")] public long? FileObject { get; set; }
    public string? Path { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.verinfo: PE version-info for a loaded module/EXE/DLL. <see cref="Product"/> typically carries the
/// company/product strings; signed Microsoft binaries report consistent values, masquerades often don't.
/// </summary>
public class WindowsVerInfo
{
    public long Base { get; set; }
    public int? Build { get; set; }
    public int? Major { get; set; }
    public int? Minor { get; set; }
    public string Name { get; set; } = "";
    public int? PID { get; set; }
    public string? Process { get; set; }
    public string? Product { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>
/// windows.vadyarascan: one YARA rule match found inside a process's VAD region. <see cref="Rule"/> is the
/// matching rule's name; <see cref="Offset"/> is where in the region the match starts.
/// </summary>
public class WindowsVadYaraScan
{
    public long Offset { get; set; }
    public string Rule { get; set; } = "";
    public string Component { get; set; } = "";
    public string? Value { get; set; }
    public int? PID { get; set; }
    public string? Process { get; set; }
    public object[] __children { get; set; } = [];
}

// =====================================================================================================
// Linux memory models (Volatility 3 linux.* plugins).
//
// Column names below are taken verbatim from the installed plugin sources' TreeGrid definitions, so the
// JsonPropertyName attributes match the keys Volatility's JSON renderer emits (which preserves spaces and
// parentheses, e.g. "OFFSET (V)", "Process Name"). Volatility renders format_hints.Hex columns (offsets,
// kernel addresses) as "0x…" strings, so those fields are typed string?; datetimes render as ISO-8601.
//
// NOTE: like the Windows credential models, these schemas are derived from the plugin columns and could not be
// validated against a live Linux memory image with matching ISF symbols on the workstation. Linux plugins
// require an ISF symbol table for the captured kernel banner (auto-fetched from the public symbol server for
// known kernels, otherwise generated with dwarf2json); when none is available the method returns null.
// =====================================================================================================

/// <summary>linux.pslist: one task from the kernel task list (the live, allocated process view).</summary>
public class LinuxPsList
{
    [JsonPropertyName("OFFSET (V)")] public string? Offset { get; set; }
    public int PID { get; set; }
    public int TID { get; set; }
    public int PPID { get; set; }
    public string COMM { get; set; } = "";
    public int? UID { get; set; }
    public int? GID { get; set; }
    public int? EUID { get; set; }
    public int? EGID { get; set; }
    [JsonPropertyName("CREATION TIME")] public DateTime? CreationTime { get; set; }
    [JsonPropertyName("File output")] public string? FileOutput { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.psscan: a task recovered by scanning memory for task_struct pool allocations — surfaces
/// processes unlinked from the task list (a hidden/rootkit process is in psscan but not pslist).</summary>
public class LinuxPsScan
{
    [JsonPropertyName("OFFSET (P)")] public string? Offset { get; set; }
    public int PID { get; set; }
    public int TID { get; set; }
    public int PPID { get; set; }
    public string COMM { get; set; } = "";
    public string? EXIT_STATE { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.pstree: the process tree (parent/child nesting in <see cref="__children"/>).</summary>
public class LinuxPsTree
{
    [JsonPropertyName("OFFSET (V)")] public string? Offset { get; set; }
    public int PID { get; set; }
    public int TID { get; set; }
    public int PPID { get; set; }
    public string COMM { get; set; } = "";
    public LinuxPsTree[] __children { get; set; } = [];
}

/// <summary>linux.psaux: each process with its full argument vector (<see cref="ARGS"/>) — the Linux
/// equivalent of windows.cmdline, for spotting masqueraded or suspicious command lines.</summary>
public class LinuxPsAux
{
    public int PID { get; set; }
    public int PPID { get; set; }
    public string COMM { get; set; } = "";
    public string? ARGS { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.bash: a bash command recovered from a process's in-memory history buffer, with the time it
/// was run — typed commands that may never have been flushed to ~/.bash_history.</summary>
public class LinuxBash
{
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public DateTime? CommandTime { get; set; }
    public string Command { get; set; } = "";
    public object[] __children { get; set; } = [];
}

/// <summary>linux.lsof: one open file descriptor of a process (sockets, pipes, regular files).</summary>
public class LinuxLsof
{
    public int PID { get; set; }
    public int TID { get; set; }
    public string Process { get; set; } = "";
    public int FD { get; set; }
    public string? Path { get; set; }
    public string? Device { get; set; }
    public long? Inode { get; set; }
    public string? Type { get; set; }
    public string? Mode { get; set; }
    public DateTime? Changed { get; set; }
    public DateTime? Modified { get; set; }
    public DateTime? Accessed { get; set; }
    public long? Size { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.sockstat: one network/Unix socket with its owning process and connection endpoints.</summary>
public class LinuxSockstat
{
    public int NetNS { get; set; }
    [JsonPropertyName("Process Name")] public string? ProcessName { get; set; }
    public int PID { get; set; }
    public int TID { get; set; }
    public int FD { get; set; }
    [JsonPropertyName("Sock Offset")] public string? SockOffset { get; set; }
    public string? Family { get; set; }
    public string? Type { get; set; }
    public string? Proto { get; set; }
    [JsonPropertyName("Source Addr")] public string? SourceAddr { get; set; }
    [JsonPropertyName("Source Port")] public string? SourcePort { get; set; }
    [JsonPropertyName("Destination Addr")] public string? DestinationAddr { get; set; }
    [JsonPropertyName("Destination Port")] public string? DestinationPort { get; set; }
    public string? State { get; set; }
    public string? Filter { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.lsmod / linux.malware.check_modules / linux.malware.hidden_modules: one kernel module. The
/// same column set is shared by all three plugins. check_modules/hidden_modules surface modules present in
/// memory but missing from the kernel's module list (a hidden/rootkit module).</summary>
public class LinuxModule
{
    [JsonPropertyName("Offset")] public string? Offset { get; set; }
    [JsonPropertyName("Module Name")] public string ModuleName { get; set; } = "";
    [JsonPropertyName("Code Size")] public string? CodeSize { get; set; }
    public string? Taints { get; set; }
    [JsonPropertyName("Load Arguments")] public string? LoadArguments { get; set; }
    [JsonPropertyName("File Output")] public string? FileOutput { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.malware.malfind: a process memory region with execute+write permissions and no backing file
/// (classic injected-code / shellcode indicator). <see cref="Protection"/> is the VMA's protection flags.</summary>
public class LinuxMalfind
{
    public int PID { get; set; }
    public string Process { get; set; } = "";
    [JsonPropertyName("Start")] public string? Start { get; set; }
    [JsonPropertyName("End")] public string? End { get; set; }
    public string? Path { get; set; }
    public string? Protection { get; set; }
    public string? Hexdump { get; set; }
    public string? Disasm { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.malware.tty_check: a TTY whose receive handler points at code outside the kernel/known
/// modules — a keystroke-logging rootkit hook.</summary>
public class LinuxTtyCheck
{
    public string Name { get; set; } = "";
    [JsonPropertyName("Address")] public string? Address { get; set; }
    public string? Module { get; set; }
    public string? Symbol { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.malware.check_syscall: one system-call table entry whose handler does not resolve to a known
/// kernel symbol — a hooked syscall (rootkit). <see cref="HandlerSymbol"/> is "UNKNOWN" when hooked.</summary>
public class LinuxCheckSyscall
{
    [JsonPropertyName("Table Address")] public string? TableAddress { get; set; }
    [JsonPropertyName("Table Name")] public string? TableName { get; set; }
    public int Index { get; set; }
    [JsonPropertyName("Handler Address")] public string? HandlerAddress { get; set; }
    [JsonPropertyName("Handler Symbol")] public string? HandlerSymbol { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.malware.check_afinfo: a network protocol-handler (seq_ops) function pointer that has been
/// overwritten to point outside the kernel — a network-hiding rootkit hook.</summary>
public class LinuxCheckAfinfo
{
    [JsonPropertyName("Symbol Name")] public string? SymbolName { get; set; }
    public string? Member { get; set; }
    [JsonPropertyName("Handler Address")] public string? HandlerAddress { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.malware.netfilter: a registered netfilter hook. A hook whose handler is outside a known
/// module (<see cref="IsHooked"/>) can hide traffic or implement a backdoor knock.</summary>
public class LinuxNetfilter
{
    [JsonPropertyName("Net NS")] public int NetNS { get; set; }
    public string? Proto { get; set; }
    public string? Hook { get; set; }
    public int Priority { get; set; }
    [JsonPropertyName("Handler")] public string? Handler { get; set; }
    public string? Module { get; set; }
    public string? Symbol { get; set; }
    [JsonPropertyName("Is Hooked")] public string? IsHooked { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.malware.check_creds: a set of processes that share one in-kernel cred structure — normally
/// impossible, and a hallmark of a credential-stealing rootkit. <see cref="PIDs"/> is the sharing process list.</summary>
public class LinuxCheckCreds
{
    [JsonPropertyName("CredVAddr")] public string? CredVAddr { get; set; }
    public string? PIDs { get; set; }
    public object[] __children { get; set; } = [];
}

/// <summary>linux.kmsg: one kernel log-buffer (dmesg) line recovered from memory.</summary>
public class LinuxKmsg
{
    public string? Facility { get; set; }
    public string? Level { get; set; }
    public string? Timestamp { get; set; }
    public string? Caller { get; set; }
    public string? Line { get; set; }
    public object[] __children { get; set; } = [];
}
