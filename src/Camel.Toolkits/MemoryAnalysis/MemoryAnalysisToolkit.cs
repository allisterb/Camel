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

    public override string[] ToolList { get; } = ["Volatility3"];
}
