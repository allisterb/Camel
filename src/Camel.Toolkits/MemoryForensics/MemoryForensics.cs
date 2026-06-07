namespace Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class MemoryForensicsToolkit : Toolkit
{
    public MemoryForensicsToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("MemoryForensics", auditEnvironment, config) {}

    public WindowsInfo[]? WindowsInfo(string filename) => ExecuteTool<WindowsInfo[]>("Volatility3", $"-f {filename} -r json windows.info");

    public WindowsPsList[]? WindowsPsList(string filename) => ExecuteTool<WindowsPsList[]>("Volatility3", $"-f {filename} -r json windows.pslist");

    public WindowsPsScan[]? WindowsPsScan(string filename) => ExecuteTool<WindowsPsScan[]>("Volatility3", $"-f {filename} -r json windows.psscan");

    public WindowsPsTree[]? WindowsPsTree(string filename) => ExecuteTool<WindowsPsTree[]>("Volatility3", $"-f {filename} -r json windows.pstree");

    public WindowsSvcScan[]? WindowsSvcScan(string filename) => ExecuteTool<WindowsSvcScan[]>("Volatility3", $"-f {filename} -r json windows.svcscan");

    public WindowsCmdLine[]? WindowsCmdLine(string filename) => ExecuteTool<WindowsCmdLine[]>("Volatility3", $"-f {filename} -r json windows.cmdline");

    public WindowsEnvVars[]? WindowsEnvVars(string filename) => ExecuteTool<WindowsEnvVars[]>("Volatility3", $"-f {filename} -r json windows.envars");

    public WindowsGetSids[]? WindowsGetSids(string filename) => ExecuteTool<WindowsGetSids[]>("Volatility3", $"-f {filename} -r json windows.getsids");

    public WindowsPrivs[]? WindowsPrivs(string filename) => ExecuteTool<WindowsPrivs[]>("Volatility3", $"-f {filename} -r json windows.privileges.Privs");

    public WindowsMalFind[]? WindowsMalFind(string filename) => ExecuteTool<WindowsMalFind[]>("Volatility3", $"-f {filename} -r json windows.malfind");

    public WindowsHandles[]? WindowsHandles(string filename, int? pid = null, string? objectType = null) =>
        ExecuteTool<WindowsHandles[]>("Volatility3", $"-f {filename} -r json windows.handles" +
            (pid is not null ? $" --pid {pid}" : ""))
            ?.Where(h => objectType is null || string.Equals(h.Type, objectType, StringComparison.OrdinalIgnoreCase))
            .ToArray();

    public override string[] ToolList { get; } = ["Volatility3"];
}
