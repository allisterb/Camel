namespace Camel.DFIR.Toolkits;
using Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class MemoryAnalysisToolkit : Toolkit
{
    public MemoryAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("MemoryAnalysis", auditEnvironment, config) {}

    public Task<WindowsInfo[]?> WindowsInfoAsync(string filename) => ExecuteToolAsync<WindowsInfo[]>("Volatility3", $"-f {filename} -r json windows.info");

    public Task<WindowsPsList[]?> WindowsPsListAsync(string filename) => ExecuteToolAsync<WindowsPsList[]>("Volatility3", $"-f {filename} -r json windows.pslist");

    public Task<WindowsPsScan[]?> WindowsPsScanAsync(string filename) => ExecuteToolAsync<WindowsPsScan[]>("Volatility3", $"-f {filename} -r json windows.psscan");

    public Task<WindowsPsTree[]?> WindowsPsTreeAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsPsTree[]>("Volatility3", $"-f {filename} -r json windows.pstree" +
            (pid is not null ? $" --pid {pid}" : ""));

    public Task<WindowsSvcScan[]?> WindowsSvcScanAsync(string filename) => ExecuteToolAsync<WindowsSvcScan[]>("Volatility3", $"-f {filename} -r json windows.svcscan");

    public Task<WindowsCmdLine[]?> WindowsCmdLineAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsCmdLine[]>("Volatility3", $"-f {filename} -r json windows.cmdline" + (pid is not null ? $" --pid {pid}" : ""));

    public Task<WindowsEnvVars[]?> WindowsEnvVarsAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsEnvVars[]>("Volatility3", $"-f {filename} -r json windows.envars" + (pid is not null ? $" --pid {pid}" : ""));

    public Task<WindowsGetSids[]?> WindowsGetSidsAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsGetSids[]>("Volatility3", $"-f {filename} -r json windows.getsids" + (pid is not null ? $" --pid {pid}" : ""));

    public Task<WindowsPrivs[]?> WindowsPrivsAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsPrivs[]>("Volatility3", $"-f {filename} -r json windows.privileges.Privs" + (pid is not null ? $" --pid {pid}" : ""));

    public Task<WindowsMalFind[]?> WindowsMalFindAsync(string filename) => ExecuteToolAsync<WindowsMalFind[]>("Volatility3", $"-f {filename} -r json windows.malfind");

    public async Task<WindowsHandles[]?> WindowsHandlesAsync(string filename, int? pid = null, string? objectType = null) =>
        (await ExecuteToolAsync<WindowsHandles[]>("Volatility3", $"-f {filename} -r json windows.handles" +
            (pid is not null ? $" --pid {pid}" : "")))
            ?.Where(h => objectType is null || string.Equals(h.Type, objectType, StringComparison.OrdinalIgnoreCase))
            .ToArray();

    public Task<WindowsNetStat[]?> WindowsNetStatAsync(string filename) => ExecuteToolAsync<WindowsNetStat[]>("Volatility3", $"-f {filename} -r json windows.netstat");

    public Task<WindowsNetScan[]?> WindowsNetScanAsync(string filename) => ExecuteToolAsync<WindowsNetScan[]>("Volatility3", $"-f {filename} -r json windows.netscan");

    public Task<WindowsDllList[]?> WindowsDllListAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsDllList[]>("Volatility3", $"-f {filename} -r json windows.dlllist" + (pid is not null ? $" --pid {pid}" : ""));

    public Task<WindowsGetServiceSids[]?> WindowsGetServiceSidsAsync(string filename) => ExecuteToolAsync<WindowsGetServiceSids[]>("Volatility3", $"-f {filename} -r json windows.getservicesids");

    public Task<WindowsModules[]?> WindowsModulesAsync(string filename) => ExecuteToolAsync<WindowsModules[]>("Volatility3", $"-f {filename} -r json windows.modules");

    public Task<WindowsModScan[]?> WindowsModScanAsync(string filename) => ExecuteToolAsync<WindowsModScan[]>("Volatility3", $"-f {filename} -r json windows.modscan");

    public Task<WindowsFileScan[]?> WindowsFileScanAsync(string filename) => ExecuteToolAsync<WindowsFileScan[]>("Volatility3", $"-f {filename} -r json windows.filescan");

    public Task<WindowsVadInfo[]?> WindowsVadInfoAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsVadInfo[]>("Volatility3", $"-f {filename} -r json windows.vadinfo" + (pid is not null ? $" --pid {pid}" : ""));

    public Task<WindowsRegistryHiveList[]?> WindowsRegistryHiveListAsync(string filename) => ExecuteToolAsync<WindowsRegistryHiveList[]>("Volatility3", $"-f {filename} -r json windows.registry.hivelist");

    public Task<WindowsRegistryPrintKey[]?> WindowsRegistryPrintKeyAsync(string filename, string key) => ExecuteToolAsync<WindowsRegistryPrintKey[]>("Volatility3", $"-f {filename} -r json windows.registry.printkey --key '{key}'");

    public Task<WindowsRegistryUserAssist[]?> WindowsRegistryUserAssistAsync(string filename) => ExecuteToolAsync<WindowsRegistryUserAssist[]>("Volatility3", $"-f {filename} -r json windows.registry.userassist");

    /// <summary>Dumps local account NTLM hashes from the SAM in <paramref name="filename"/> (<c>windows.hashdump</c>).</summary>
    public Task<WindowsHashdump[]?> WindowsHashdumpAsync(string filename) => ExecuteToolAsync<WindowsHashdump[]>("Volatility3", $"-f {filename} -r json windows.hashdump");

    /// <summary>Dumps LSA secrets (service-account passwords, DPAPI keys, DefaultPassword, …) from <paramref name="filename"/> (<c>windows.lsadump</c>).</summary>
    public Task<WindowsLsadump[]?> WindowsLsadumpAsync(string filename) => ExecuteToolAsync<WindowsLsadump[]>("Volatility3", $"-f {filename} -r json windows.lsadump");

    /// <summary>Dumps cached domain credentials (mscash/mscash2) from <paramref name="filename"/> (<c>windows.cachedump</c>).</summary>
    public Task<WindowsCachedump[]?> WindowsCachedumpAsync(string filename) => ExecuteToolAsync<WindowsCachedump[]>("Volatility3", $"-f {filename} -r json windows.cachedump");

    /// <summary>
    /// Lists each process's loaded DLLs from <paramref name="filename"/> (<c>windows.ldrmodules</c>), reporting
    /// for each entry whether it appears in the three PEB doubly-linked lists (InLoad/InInit/InMem) and the
    /// VAD-tree MappedPath. A DLL present in VAD but missing from one or more PEB lists, or with no
    /// MappedPath, indicates injection / unlinking.
    /// </summary>
    public Task<WindowsLdrModules[]?> WindowsLdrModulesAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsLdrModules[]>("Volatility3", $"-f {filename} -r json windows.ldrmodules" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>
    /// Detects process-hollowing victims in <paramref name="filename"/> (<c>windows.hollowprocesses</c>): a
    /// process whose PEB image base disagrees with the in-memory VAD or the on-disk image.
    /// </summary>
    public Task<WindowsHollowProcesses[]?> WindowsHollowProcessesAsync(string filename) =>
        ExecuteToolAsync<WindowsHollowProcesses[]>("Volatility3", $"-f {filename} -r json windows.hollowprocesses");

    /// <summary>
    /// Lists every thread in every process from <paramref name="filename"/> (<c>windows.threads</c>) with its
    /// kernel and Win32 start addresses — the data the thread-based hollowing / injection detector consumes.
    /// </summary>
    public Task<WindowsThreads[]?> WindowsThreadsAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsThreads[]>("Volatility3", $"-f {filename} -r json windows.threads" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>
    /// Lists every System Service Descriptor Table entry from <paramref name="filename"/> (<c>windows.ssdt</c>).
    /// Entries owned by anything other than <c>ntoskrnl</c> / <c>win32k</c> are kernel SSDT hooks.
    /// </summary>
    public Task<WindowsSsdt[]?> WindowsSsdtAsync(string filename) => ExecuteToolAsync<WindowsSsdt[]>("Volatility3", $"-f {filename} -r json windows.ssdt");

    /// <summary>
    /// Lists registered kernel callbacks from <paramref name="filename"/> (<c>windows.callbacks</c>) — image-,
    /// thread-, process-, and registry-notify routines, plus Bug-check callbacks. Foreign-module entries are
    /// rootkit / EDR indicators.
    /// </summary>
    public Task<WindowsCallbacks[]?> WindowsCallbacksAsync(string filename) => ExecuteToolAsync<WindowsCallbacks[]>("Volatility3", $"-f {filename} -r json windows.callbacks");

    /// <summary>
    /// Lists every Major Function entry in every driver's IRP_MJ table from <paramref name="filename"/>
    /// (<c>windows.driverirp</c>). Entries pointing into a module other than the owning driver or
    /// <c>ntoskrnl</c> are IRP-table hooks.
    /// </summary>
    public Task<WindowsDriverIrp[]?> WindowsDriverIrpAsync(string filename) => ExecuteToolAsync<WindowsDriverIrp[]>("Volatility3", $"-f {filename} -r json windows.driverirp");

    /// <summary>
    /// Cross-view process enumeration from <paramref name="filename"/> (<c>windows.psxview</c>): each process
    /// reported with which of four sources (pslist / psscan / thrdscan / csrss) saw it. Visibility gaps are
    /// the cross-view hidden-process indicator.
    /// </summary>
    public Task<WindowsPsxView[]?> WindowsPsxViewAsync(string filename) => ExecuteToolAsync<WindowsPsxView[]>("Volatility3", $"-f {filename} -r json windows.psxview");

    /// <summary>
    /// Pool-tag scan for mutant (mutex) objects from <paramref name="filename"/> (<c>windows.mutantscan</c>).
    /// Named mutexes are canonical malware-family IOCs (single-instance markers).
    /// </summary>
    public Task<WindowsMutantScan[]?> WindowsMutantScanAsync(string filename) => ExecuteToolAsync<WindowsMutantScan[]>("Volatility3", $"-f {filename} -r json windows.mutantscan");

    /// <summary>
    /// Recovers <c>COMMAND_HISTORY</c> buffers (typed command lines) from console hosts in
    /// <paramref name="filename"/> (<c>windows.cmdscan</c>).
    /// </summary>
    public Task<WindowsCmdScan[]?> WindowsCmdScanAsync(string filename) => ExecuteToolAsync<WindowsCmdScan[]>("Volatility3", $"-f {filename} -r json windows.cmdscan");

    /// <summary>
    /// Recovers <c>CONSOLE_INFORMATION</c> buffers (typed commands plus the output written back) from
    /// <paramref name="filename"/> (<c>windows.consoles</c>).
    /// </summary>
    public Task<WindowsConsoles[]?> WindowsConsolesAsync(string filename) => ExecuteToolAsync<WindowsConsoles[]>("Volatility3", $"-f {filename} -r json windows.consoles");

    /// <summary>
    /// Extracts Application Compatibility Cache entries from kernel memory in <paramref name="filename"/>
    /// (<c>windows.shimcachemem</c>) — including entries not yet flushed to the SYSTEM hive at shutdown.
    /// </summary>
    public Task<WindowsShimcacheMem[]?> WindowsShimcacheMemAsync(string filename) => ExecuteToolAsync<WindowsShimcacheMem[]>("Volatility3", $"-f {filename} -r json windows.shimcachemem");

    /// <summary>
    /// DC-only: scans LSASS for a Skeleton Key implant in <paramref name="filename"/>
    /// (<c>windows.skeleton_key_check</c>). Empty result = clean.
    /// </summary>
    public Task<WindowsSkeletonKeyCheck[]?> WindowsSkeletonKeyCheckAsync(string filename) =>
        ExecuteToolAsync<WindowsSkeletonKeyCheck[]>("Volatility3", $"-f {filename} -r json windows.skeleton_key_check");

    /// <summary>
    /// Detects Process Ghosting evasion in <paramref name="filename"/> (<c>windows.processghosting</c>) — a
    /// process whose backing file was deleted before <c>NtCreateProcessEx</c>. Empty result = clean.
    /// </summary>
    public Task<WindowsProcessGhosting[]?> WindowsProcessGhostingAsync(string filename) =>
        ExecuteToolAsync<WindowsProcessGhosting[]>("Volatility3", $"-f {filename} -r json windows.processghosting");

    /// <summary>
    /// Extracts PE version-info (company / product / version strings) for loaded modules in
    /// <paramref name="filename"/> (<c>windows.verinfo</c>). Signed Microsoft binaries report consistent
    /// values; masquerades and packed binaries frequently don't.
    /// </summary>
    public Task<WindowsVerInfo[]?> WindowsVerInfoAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<WindowsVerInfo[]>("Volatility3", $"-f {filename} -r json windows.verinfo" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>
    /// YARA-scans every process's VAD regions in <paramref name="filename"/> (<c>windows.vadyarascan</c>)
    /// against the rules in <paramref name="yaraRulesFile"/> (passed via <c>--yara-file</c>). Returns a row
    /// per match. When <paramref name="pid"/> is set, only that process is scanned. <paramref name="wide"/>
    /// matches UTF-16 strings (mirroring YARA's <c>wide</c> modifier).
    /// </summary>
    public Task<WindowsVadYaraScan[]?> WindowsVadYaraScanAsync(string filename, string yaraRulesFile, int? pid = null, bool wide = false) =>
        ExecuteToolAsync<WindowsVadYaraScan[]>("Volatility3",
            $"-f {filename} -r json windows.vadyarascan --yara-file {Q(yaraRulesFile)}" +
            (pid is not null ? $" --pid {pid}" : "") + (wide ? " --wide" : ""));

    /// <summary>
    /// Extracts cached file contents from <paramref name="filename"/> to <paramref name="outputDir"/> on the
    /// workstation (<c>windows.dumpfiles</c>). Pass <paramref name="virtualAddress"/> / <paramref name="physicalAddress"/>
    /// (from a <c>filescan</c> result) to extract a single FILE_OBJECT, or <paramref name="pid"/> to extract
    /// every cached file backing that process, or <paramref name="filterRegex"/> to extract every cached file
    /// whose name matches the regex. The directory is created if missing. Returns the full path(s) of the
    /// dumped file(s), or null if the plugin failed.
    /// </summary>
    public Task<string[]?> DumpFilesAsync(string filename, string outputDir,
        long? virtualAddress = null, long? physicalAddress = null, int? pid = null, string? filterRegex = null) =>
        DumpAsync($"-o {outputDir} -f {filename} -r json windows.dumpfiles" +
            (virtualAddress is not null ? $" --virtaddr {virtualAddress}" : "") +
            (physicalAddress is not null ? $" --physaddr {physicalAddress}" : "") +
            (pid is not null ? $" --pid {pid}" : "") +
            (filterRegex is not null ? $" --filter {Q(filterRegex)}" : ""), outputDir);

    static string Q(string s) => $"'{s.Replace("'", "'\\''")}'";

    /// <summary>
    /// Dumps the executable image (PE) of the process <paramref name="pid"/> from <paramref name="filename"/>
    /// to <paramref name="outputDir"/> on the workstation, via <c>windows.pslist --pid &lt;pid&gt; --dump</c>.
    /// The directory is created if missing. Returns the full path(s) of the dumped file(s) (empty if the
    /// process was found but no image could be written), or null if the plugin failed.
    /// </summary>
    public Task<string[]?> DumpProcessExecutableAsync(string filename, int pid, string outputDir) =>
        DumpAsync($"-o {outputDir} -f {filename} -r json windows.pslist --pid {pid} --dump", outputDir);

    /// <summary>
    /// Dumps all mapped memory pages of the process <paramref name="pid"/> from <paramref name="filename"/>
    /// to <paramref name="outputDir"/> on the workstation (a single <c>pid.&lt;pid&gt;.dmp</c>), via
    /// <c>windows.memmap --pid &lt;pid&gt; --dump</c>. The directory is created if missing. Returns the full
    /// path(s) of the dumped file(s), or null if the plugin failed.
    /// </summary>
    public Task<string[]?> DumpProcessMemoryAsync(string filename, int pid, string outputDir) =>
        DumpAsync($"-o {outputDir} -f {filename} -r json windows.memmap --pid {pid} --dump", outputDir);

    /// <summary>
    /// Extracts printable strings from <paramref name="inputFile"/> on the workstation into
    /// <paramref name="outputFile"/> via <c>strings</c>, keeping only those at least <paramref name="minLength"/>
    /// characters long (default 8, to reduce noise). When <paramref name="unicode"/> is true, 16-bit little-
    /// endian (UTF-16/Unicode) strings are extracted (<c>-el</c>); otherwise 7-bit ASCII. The output directory
    /// is created if missing. Returns true on success.
    /// </summary>
    public async Task<bool> ExtractStringsAsync(string inputFile, string outputFile, bool unicode = false, int minLength = 8)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputFile);   // never redirect extracted strings over evidence
        // Ensure the destination directory exists (created as the login user so strings can write into it).
        int slash = outputFile.LastIndexOf('/');
        if (slash > 0)
            await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p '{outputFile[..slash]}'", false);

        var r = await auditEnvironment.ExecuteCommandAsync("strings",
            $"-a {(unicode ? "-el " : "")}-n {minLength} '{inputFile}' > '{outputFile}'", false);
        return r.IsCompleted;
    }

    /// <summary>
    /// Generates a mactime <em>bodyfile</em> of every timestamped artifact in <paramref name="image"/>
    /// (processes, threads, handles, sockets, registry keys, …) via <c>timeliner --create-bodyfile</c>, which
    /// writes <c>volatility.body</c> into <paramref name="outputDir"/> (the global <c>-o</c> directory;
    /// <c>-r none</c> suppresses the large, unneeded stdout table). The directory is created if missing. Feed
    /// the result to <c>mactime</c> to render a timeline. Returns the bodyfile path, or null on failure.
    /// </summary>
    public async Task<string?> TimelinerBodyfileAsync(string image, string outputDir)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);   // never write the bodyfile (and chown) onto evidence
        // Created as the login user so the (sudo'd) plugin can write into it.
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {outputDir}", false);

        if (await ExecuteToolTextAsync("Volatility3", $"-o {outputDir} -f {image} -r none timeliner --create-bodyfile") is null)
            return null;

        // The plugin runs under sudo, so the bodyfile lands root-owned; hand it back so a non-sudo mactime can read it.
        if (Tools["Volatility3"].Sudo)
            await auditEnvironment.ExecuteCommandAsync("chown", $"-R $(id -un):$(id -gn) {outputDir}", true);

        var bodyfile = $"{outputDir.TrimEnd('/')}/volatility.body";
        var test = await auditEnvironment.ExecuteCommandAsync("test", $"-s '{bodyfile}'", false);
        return test.IsCompleted ? bodyfile : null;
    }

    /// <summary>
    /// Runs a Volatility dump plugin (output directory <paramref name="outputDir"/> supplied via the global
    /// <c>-o</c> option in <paramref name="args"/>), creating the directory first, and returns the full paths
    /// of the distinct, non-empty files the plugin reported writing (0-byte dumps — produced when a PE image
    /// or region was paged out of RAM — are dropped as useless for triage). When the plugin runs under sudo
    /// the dumped files land root-owned, so they are handed back to the login user. Null if the plugin failed.
    /// </summary>
    private async Task<string[]?> DumpAsync(string args, string outputDir)
    {
        // Single chokepoint for all dump plugins (DumpFiles/DumpProcessExecutable/DumpProcessMemory): never let
        // a memory dump land on registered evidence.
        auditEnvironment.FailIfEvidenceSpoliationRisk(outputDir);
        // Created as the login user so the (sudo'd) plugin can still write its dump files into it.
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {outputDir}", false);

        var rows = await ExecuteToolAsync<WindowsDump[]>("Volatility3", args);
        if (rows is null) return null;

        // The plugin writes each dump under the bare name in its "File output" column; keep the distinct real
        // filenames (dropping error / "Disabled" markers).
        var names = rows
            .Select(r => r.FileOutput)
            .Where(f => !string.IsNullOrEmpty(f) && !f.Contains("Error", StringComparison.OrdinalIgnoreCase) && f != "Disabled")
            .Distinct()
            .ToArray();
        if (names.Length == 0) return [];

        // The plugin runs under sudo, so the dumped files land root-owned; hand them back to the login user.
        if (Tools["Volatility3"].Sudo)
            await auditEnvironment.ExecuteCommandAsync("chown", $"-R $(id -un):$(id -gn) {outputDir}", true);

        // Drop 0-byte dumps: vol still writes a file when a PE image / region was paged out of RAM, but it
        // has no content. Ask the workstation which dumped files are non-empty (single call, by basename).
        var find = await auditEnvironment.ExecuteCommandAsync("find", $"'{outputDir}' -maxdepth 1 -type f -size +0c -printf '%f\\n'", false);
        var nonEmpty = find.IsCompleted
            ? find.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet()
            : names.ToHashSet(); // if the size check itself failed, don't silently drop everything

        return names.Where(nonEmpty.Contains).Select(f => $"{outputDir.TrimEnd('/')}/{f}").ToArray();
    }

    #region Linux plugins
    // Volatility 3 Linux memory plugins. These mirror the Windows plugin methods above but target a Linux memory
    // image. IMPORTANT: every Linux plugin needs an ISF symbol table matching the captured kernel's banner — none
    // ship with Volatility. For a known kernel `vol` auto-downloads the symbols from the public symbol server on
    // first use; otherwise generate them from the kernel's debug info with dwarf2json and drop the .json(.xz) into
    // the symbols/linux directory. Without symbols the plugin fails and the method returns null (not an empty
    // result), which a caller should treat as "symbols unavailable", distinct from "ran clean, nothing found".

    /// <summary>Lists processes from the kernel task list (linux.pslist) — the live, allocated process view.</summary>
    public Task<LinuxPsList[]?> LinuxPsListAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<LinuxPsList[]>("Volatility3", $"-f {filename} -r json linux.pslist" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>Scans memory for task_struct allocations (linux.psscan); a process present here but absent from
    /// <see cref="LinuxPsListAsync"/> has been unlinked from the task list (hidden / rootkit process).</summary>
    public Task<LinuxPsScan[]?> LinuxPsScanAsync(string filename) =>
        ExecuteToolAsync<LinuxPsScan[]>("Volatility3", $"-f {filename} -r json linux.psscan");

    /// <summary>Process tree with parent/child nesting in <c>__children</c> (linux.pstree).</summary>
    public Task<LinuxPsTree[]?> LinuxPsTreeAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<LinuxPsTree[]>("Volatility3", $"-f {filename} -r json linux.pstree" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>Each process with its full argument vector (linux.psaux) — Linux equivalent of windows.cmdline.</summary>
    public Task<LinuxPsAux[]?> LinuxPsAuxAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<LinuxPsAux[]>("Volatility3", $"-f {filename} -r json linux.psaux" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>Recovers bash command history (with timestamps) from process memory (linux.bash) — typed commands
    /// that may never have reached <c>~/.bash_history</c>.</summary>
    public Task<LinuxBash[]?> LinuxBashAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<LinuxBash[]>("Volatility3", $"-f {filename} -r json linux.bash" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>Open file descriptors per process — sockets, pipes, files (linux.lsof).</summary>
    public Task<LinuxLsof[]?> LinuxLsofAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<LinuxLsof[]>("Volatility3", $"-f {filename} -r json linux.lsof" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>Network and Unix sockets with owning process and endpoints (linux.sockstat) — the netstat view.</summary>
    public Task<LinuxSockstat[]?> LinuxSockstatAsync(string filename) =>
        ExecuteToolAsync<LinuxSockstat[]>("Volatility3", $"-f {filename} -r json linux.sockstat");

    /// <summary>Loaded kernel modules from the module list (linux.lsmod).</summary>
    public Task<LinuxModule[]?> LinuxLsmodAsync(string filename) =>
        ExecuteToolAsync<LinuxModule[]>("Volatility3", $"-f {filename} -r json linux.lsmod");

    /// <summary>Cross-checks the module list against module-allocation memory (linux.malware.check_modules);
    /// rows are modules in memory but missing from the list — a hidden/rootkit module.</summary>
    public Task<LinuxModule[]?> LinuxCheckModulesAsync(string filename) =>
        ExecuteToolAsync<LinuxModule[]>("Volatility3", $"-f {filename} -r json linux.malware.check_modules");

    /// <summary>Carves module structures directly from kernel memory to find modules hidden from every standard
    /// list (linux.malware.hidden_modules). Empty result = none hidden.</summary>
    public Task<LinuxModule[]?> LinuxHiddenModulesAsync(string filename) =>
        ExecuteToolAsync<LinuxModule[]>("Volatility3", $"-f {filename} -r json linux.malware.hidden_modules");

    /// <summary>System-call table entries whose handler doesn't resolve to a known symbol (linux.malware.check_syscall)
    /// — hooked syscalls. Empty result = clean.</summary>
    public Task<LinuxCheckSyscall[]?> LinuxCheckSyscallAsync(string filename) =>
        ExecuteToolAsync<LinuxCheckSyscall[]>("Volatility3", $"-f {filename} -r json linux.malware.check_syscall");

    /// <summary>Protocol-handler (seq_ops) function pointers overwritten to point outside the kernel
    /// (linux.malware.check_afinfo) — a network-hiding rootkit hook. Empty result = clean.</summary>
    public Task<LinuxCheckAfinfo[]?> LinuxCheckAfinfoAsync(string filename) =>
        ExecuteToolAsync<LinuxCheckAfinfo[]>("Volatility3", $"-f {filename} -r json linux.malware.check_afinfo");

    /// <summary>Processes sharing a single in-kernel cred structure (linux.malware.check_creds) — a hallmark of a
    /// credential-stealing rootkit. Empty result = clean.</summary>
    public Task<LinuxCheckCreds[]?> LinuxCheckCredsAsync(string filename) =>
        ExecuteToolAsync<LinuxCheckCreds[]>("Volatility3", $"-f {filename} -r json linux.malware.check_creds");

    /// <summary>TTYs whose receive handler points outside the kernel/known modules (linux.malware.tty_check) — a
    /// keystroke-logging rootkit hook. Empty result = clean.</summary>
    public Task<LinuxTtyCheck[]?> LinuxTtyCheckAsync(string filename) =>
        ExecuteToolAsync<LinuxTtyCheck[]>("Volatility3", $"-f {filename} -r json linux.malware.tty_check");

    /// <summary>Process memory regions that are writable+executable with no file backing (linux.malware.malfind)
    /// — injected code / shellcode. Empty result = clean.</summary>
    public Task<LinuxMalfind[]?> LinuxMalfindAsync(string filename, int? pid = null) =>
        ExecuteToolAsync<LinuxMalfind[]>("Volatility3", $"-f {filename} -r json linux.malware.malfind" + (pid is not null ? $" --pid {pid}" : ""));

    /// <summary>Registered netfilter hooks (linux.malware.netfilter); a hook handled outside a known module can
    /// hide traffic or implement a backdoor.</summary>
    public Task<LinuxNetfilter[]?> LinuxNetfilterAsync(string filename) =>
        ExecuteToolAsync<LinuxNetfilter[]>("Volatility3", $"-f {filename} -r json linux.malware.netfilter");

    /// <summary>Kernel log buffer (dmesg) recovered from memory (linux.kmsg).</summary>
    public Task<LinuxKmsg[]?> LinuxKmsgAsync(string filename) =>
        ExecuteToolAsync<LinuxKmsg[]>("Volatility3", $"-f {filename} -r json linux.kmsg");
    #endregion

    public override string[] ToolList { get; } = ["Volatility3"];
}
