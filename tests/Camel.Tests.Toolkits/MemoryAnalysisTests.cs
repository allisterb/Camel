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

    [Fact]
    public void CanRunWindowsPsList()
    {
        var r = toolkit.WindowsPsList("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsPsTree()
    {
        var r = toolkit.WindowsPsTree("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }
    [Fact]
    public void CanRunWindowsSvcScan()
    {
        var r = toolkit.WindowsSvcScan("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }
    [Fact]
    public void CanRunWindowsCmdLine()
    {
        var r = toolkit.WindowsCmdLine("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsEnvVars()
    {
        var r = toolkit.WindowsEnvVars("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsGetSids()
    {
        var r = toolkit.WindowsGetSids("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsPrivs()
    {
        var r = toolkit.WindowsPrivs("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsHandles()
    {
        var r = toolkit.WindowsHandles("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsHandlesFiltered()
    {
        var r = toolkit.WindowsHandles("/mnt/memory-images/pat-2009-11-19.mddramimage", 988, "Key");
        Assert.NotNull(r);
        Assert.All(r, h => Assert.Equal(988, h.PID));
        Assert.All(r, h => Assert.Equal("Key", h.Type));
    }
    [Fact]
    public void CanRunWindowsMalFind()
    {
        var r = toolkit.WindowsMalFind("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }
    [Fact]
    public void CanRunWindowsDllList()
    {
        var r = toolkit.WindowsDllList("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsGetServiceSids()
    {
        var r = toolkit.WindowsGetServiceSids("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsModules()
    {
        var r = toolkit.WindowsModules("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsModScan()
    {
        var r = toolkit.WindowsModScan("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsFileScan()
    {
        var r = toolkit.WindowsFileScan("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsVadInfo()
    {
        var r = toolkit.WindowsVadInfo("/mnt/memory-images/pat-2009-11-19.mddramimage", 988);
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsRegistryHiveList()
    {
        var r = toolkit.WindowsRegistryHiveList("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsRegistryPrintKey()
    {
        var r = toolkit.WindowsRegistryPrintKey("/mnt/memory-images/pat-2009-11-19.mddramimage", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsRegistryUserAssist()
    {
        var r = toolkit.WindowsRegistryUserAssist("/mnt/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    // windows.netstat / windows.netscan do not support the Windows XP (5.1) test image
    // (Volatility3 raises NotImplementedError), so verify against the Windows 10 image.
    [Fact]
    public void CanRunWindowsNetStat()
    {
        var r = toolkit.WindowsNetStat("/mnt/memory-images/Rocba-Memory.raw");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, c => Assert.NotEmpty(c.Proto));
    }

    [Fact]
    public void CanRunWindowsNetScan()
    {
        var r = toolkit.WindowsNetScan("/mnt/memory-images/Rocba-Memory.raw");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, c => Assert.NotEmpty(c.Proto));
    }
    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    MemoryAnalysisToolkit toolkit;
}
