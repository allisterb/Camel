using Camel.Environments;
using Camel.Toolkits;
using Camel.DFIR.Toolkits;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;

namespace Camel.Tests.Toolkits;

public class MemoryAnalysisTests : TestsRuntime
{
    public MemoryAnalysisTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new MemoryAnalysisToolkit(sshenv, sshconfig);
    }

    const string Image = "/mnt/artifacts/pat-2009-11-19.mddramimage";

    [Fact]
    public async Task CanRunWindowsPsList()
    {
        var r = (await toolkit.WindowsPsListAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsPsScan()
    {
        var r = (await toolkit.WindowsPsScanAsync(Image)).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        // psscan returns EPROCESS structures with valid PIDs; SessionId/CreateTime can be null on some
        // (exited/partial) entries — deserialization must tolerate that.
        Assert.All(r, p => Assert.True(p.PID >= 0));
    }

    [Fact]
    public async Task CanRunWindowsPsTree()
    {
        var r = (await toolkit.WindowsPsTreeAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsPsTreeForPid()
    {
        // Filtering to a PID narrows the forest to the single ancestry branch containing that PID (rooted at
        // the top-most ancestor, with the target nested among __children).
        var r = (await toolkit.WindowsPsTreeAsync(Image, 988)).Result;
        Assert.NotNull(r);
        Assert.Single(r);
        Assert.Contains(Flatten(r), p => p.PID == 988);
    }

    // Depth-first flatten of a pstree forest (each node plus its nested __children).
    static IEnumerable<WindowsPsTree> Flatten(IEnumerable<WindowsPsTree> nodes) =>
        nodes.SelectMany(n => new[] { n }.Concat(Flatten(n.__children)));

    [Fact]
    public async Task CanRunWindowsSvcScan()
    {
        var r = (await toolkit.WindowsSvcScanAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsCmdLine()
    {
        var r = (await toolkit.WindowsCmdLineAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsEnvVars()
    {
        var r = (await toolkit.WindowsEnvVarsAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsGetSids()
    {
        var r = (await toolkit.WindowsGetSidsAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsPrivs()
    {
        var r = (await toolkit.WindowsPrivsAsync(Image)).Result;
        Assert.NotNull(r);
    }

    // Filtering each per-process plugin to a PID restricts its output to that process (988 is valid in the
    // test image). An empty result is still valid for some plugins, so only assert PID scoping when present.
    [Fact]
    public async Task CanRunWindowsCmdLineForPid()
    {
        var r = (await toolkit.WindowsCmdLineAsync(Image, 988)).Result;
        Assert.NotNull(r);
        Assert.All(r, e => Assert.Equal(988, e.PID));
    }

    [Fact]
    public async Task CanRunWindowsEnvVarsForPid()
    {
        var r = (await toolkit.WindowsEnvVarsAsync(Image, 988)).Result;
        Assert.NotNull(r);
        Assert.All(r, e => Assert.Equal(988, e.PID));
    }

    [Fact]
    public async Task CanRunWindowsGetSidsForPid()
    {
        var r = (await toolkit.WindowsGetSidsAsync(Image, 988)).Result;
        Assert.NotNull(r);
        Assert.All(r, e => Assert.Equal(988, e.PID));
    }

    [Fact]
    public async Task CanRunWindowsPrivsForPid()
    {
        var r = (await toolkit.WindowsPrivsAsync(Image, 988)).Result;
        Assert.NotNull(r);
        Assert.All(r, e => Assert.Equal(988, e.PID));
    }

    [Fact]
    public async Task CanRunWindowsHandles()
    {
        var r = (await toolkit.WindowsHandlesAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsHandlesFiltered()
    {
        var r = (await toolkit.WindowsHandlesAsync(Image, 988, "Key")).Result;
        Assert.NotNull(r);
        Assert.All(r, h => Assert.Equal(988, h.PID));
        Assert.All(r, h => Assert.Equal("Key", h.Type));
    }

    [Fact]
    public async Task CanRunWindowsMalFind()
    {
        var r = (await toolkit.WindowsMalFindAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsDllList()
    {
        var r = (await toolkit.WindowsDllListAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsGetServiceSids()
    {
        var r = (await toolkit.WindowsGetServiceSidsAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsModules()
    {
        var r = (await toolkit.WindowsModulesAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsModScan()
    {
        var r = (await toolkit.WindowsModScanAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsFileScan()
    {
        var r = (await toolkit.WindowsFileScanAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsVadInfo()
    {
        var r = (await toolkit.WindowsVadInfoAsync(Image, 988)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsRegistryHiveList()
    {
        var r = (await toolkit.WindowsRegistryHiveListAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsRegistryPrintKey()
    {
        var r = (await toolkit.WindowsRegistryPrintKeyAsync(Image, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsRegistryUserAssist()
    {
        var r = (await toolkit.WindowsRegistryUserAssistAsync(Image)).Result;
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanDumpProcessExecutable()
    {
        const string dir = "/tmp/camel_dump_exe";
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, true); // clean slate

        var files = (await toolkit.DumpProcessExecutableAsync(Image, 988, dir)).Result; // services.exe
        Assert.NotNull(files);
        Assert.NotEmpty(files);
        Assert.All(files, f => Assert.StartsWith(dir, f));
        // Each reported path is a non-empty file that really exists on disk.
        Assert.All(files, f => Assert.True(sshenv.ExecuteCommand("test", $"-s {f}", out _, true)));

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, true);
    }

    [Fact]
    public async Task CanDumpProcessMemory()
    {
        const string dir = "/tmp/camel_dump_mem";
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, true);

        var files = (await toolkit.DumpProcessMemoryAsync(Image, 988, dir)).Result;
        Assert.NotNull(files);
        Assert.NotEmpty(files);
        // memmap writes a single pid.<PID>.dmp for the process.
        Assert.Contains(files, f => f.EndsWith("pid.988.dmp"));
        Assert.All(files, f => Assert.True(sshenv.ExecuteCommand("test", $"-s {f}", out _, true)));

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, true);
    }

    [Fact]
    public async Task CanExtractStrings()
    {
        const string dir = "/tmp/camel_strings";
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, true);

        // Dump a process's memory, then extract ASCII and Unicode strings (min 8 chars) from it.
        var dumps = (await toolkit.DumpProcessMemoryAsync(Image, 988, dir)).Result;
        Assert.NotNull(dumps);
        var dmp = Assert.Single(dumps);

        string ascii = $"{dir}/strings_ascii.txt";
        string unicode = $"{dir}/strings_unicode.txt";
        Assert.True(await toolkit.ExtractStringsAsync(dmp, ascii, unicode: false));
        Assert.True(await toolkit.ExtractStringsAsync(dmp, unicode, unicode: true));

        // Both string files were written with content.
        Assert.True(sshenv.ExecuteCommand("test", $"-s {ascii}", out _, true));
        Assert.True(sshenv.ExecuteCommand("test", $"-s {unicode}", out _, true));

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, true);
    }

    // windows.netstat / windows.netscan do not support the Windows XP (5.1) test image
    // (Volatility3 raises NotImplementedError), so verify against the Windows 10 image.
    [Fact]
    public async Task CanRunWindowsNetStat()
    {
        var r = (await toolkit.WindowsNetStatAsync("/mnt/artifacts/Rocba-Memory.raw")).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, c => Assert.NotEmpty(c.Proto));
    }

    [Fact]
    public async Task CanRunWindowsNetScan()
    {
        var r = (await toolkit.WindowsNetScanAsync("/mnt/artifacts/Rocba-Memory.raw")).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, c => Assert.NotEmpty(c.Proto));
    }

    [Fact]
    public async Task CanRunWindowsHashdump()
    {
        var r = (await toolkit.WindowsHashdumpAsync(Image)).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, h => h.Rid == 500 && !string.IsNullOrEmpty(h.NtHash)); // built-in Administrator
    }

    [Fact]
    public async Task CanRunWindowsLsadump()
    {
        var r = (await toolkit.WindowsLsadumpAsync(Image)).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, s => !string.IsNullOrEmpty(s.Key));
    }

    [Fact]
    public async Task CanRunWindowsCachedump()
    {
        // This standalone image has no cached domain creds; verify the call path returns a (possibly empty) set.
        var r = (await toolkit.WindowsCachedumpAsync(Image)).Result;
        Assert.NotNull(r);
    }

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    MemoryAnalysisToolkit toolkit;
}
