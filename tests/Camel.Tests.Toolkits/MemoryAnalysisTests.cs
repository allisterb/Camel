using Camel.Environments;
using Camel.Toolkits;

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
        var r = await toolkit.WindowsPsListAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsPsTree()
    {
        var r = await toolkit.WindowsPsTreeAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsSvcScan()
    {
        var r = await toolkit.WindowsSvcScanAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsCmdLine()
    {
        var r = await toolkit.WindowsCmdLineAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsEnvVars()
    {
        var r = await toolkit.WindowsEnvVarsAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsGetSids()
    {
        var r = await toolkit.WindowsGetSidsAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsPrivs()
    {
        var r = await toolkit.WindowsPrivsAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsHandles()
    {
        var r = await toolkit.WindowsHandlesAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsHandlesFiltered()
    {
        var r = await toolkit.WindowsHandlesAsync(Image, 988, "Key");
        Assert.NotNull(r);
        Assert.All(r, h => Assert.Equal(988, h.PID));
        Assert.All(r, h => Assert.Equal("Key", h.Type));
    }

    [Fact]
    public async Task CanRunWindowsMalFind()
    {
        var r = await toolkit.WindowsMalFindAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsDllList()
    {
        var r = await toolkit.WindowsDllListAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsGetServiceSids()
    {
        var r = await toolkit.WindowsGetServiceSidsAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsModules()
    {
        var r = await toolkit.WindowsModulesAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsModScan()
    {
        var r = await toolkit.WindowsModScanAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsFileScan()
    {
        var r = await toolkit.WindowsFileScanAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsVadInfo()
    {
        var r = await toolkit.WindowsVadInfoAsync(Image, 988);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsRegistryHiveList()
    {
        var r = await toolkit.WindowsRegistryHiveListAsync(Image);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsRegistryPrintKey()
    {
        var r = await toolkit.WindowsRegistryPrintKeyAsync(Image, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunWindowsRegistryUserAssist()
    {
        var r = await toolkit.WindowsRegistryUserAssistAsync(Image);
        Assert.NotNull(r);
    }

    // windows.netstat / windows.netscan do not support the Windows XP (5.1) test image
    // (Volatility3 raises NotImplementedError), so verify against the Windows 10 image.
    [Fact]
    public async Task CanRunWindowsNetStat()
    {
        var r = await toolkit.WindowsNetStatAsync("/mnt/artifacts/Rocba-Memory.raw");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, c => Assert.NotEmpty(c.Proto));
    }

    [Fact]
    public async Task CanRunWindowsNetScan()
    {
        var r = await toolkit.WindowsNetScanAsync("/mnt/artifacts/Rocba-Memory.raw");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, c => Assert.NotEmpty(c.Proto));
    }

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    MemoryAnalysisToolkit toolkit;
}
