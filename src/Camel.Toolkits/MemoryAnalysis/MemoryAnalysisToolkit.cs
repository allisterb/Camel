namespace Camel.Toolkits;

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

    public override string[] ToolList { get; } = ["Volatility3"];
}
