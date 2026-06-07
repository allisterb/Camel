using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

public class MemoryForensicsTests : TestsRuntime
{
    public MemoryForensicsTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new MemoryForensicsToolkit(sshenv, sshconfig);    
    }

    [Fact]
    public void CanRunWindowsPsList()
    {
        //var toolkit = new MemoryForensicsToolkit(sshenv);
        var r = toolkit.WindowsPsList("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsPsTree()
    {
        var r = toolkit.WindowsPsTree("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }
    [Fact]
    public void CanRunWindowsSvcScan()
    {
        var r = toolkit.WindowsSvcScan("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }
    [Fact]
    public void CanRunWindowsCmdLine()
    {
        var r = toolkit.WindowsCmdLine("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsEnvVars()
    {
        var r = toolkit.WindowsEnvVars("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsGetSids()
    {
        var r = toolkit.WindowsGetSids("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsPrivs()
    {
        var r = toolkit.WindowsPrivs("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsHandles()
    {
        var r = toolkit.WindowsHandles("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunWindowsHandlesFiltered()
    {
        var r = toolkit.WindowsHandles("~/memory-images/pat-2009-11-19.mddramimage", 988, "Key");
        Assert.NotNull(r);
        Assert.All(r, h => Assert.Equal(988, h.PID));
        Assert.All(r, h => Assert.Equal("Key", h.Type));
    }
    [Fact]
    public void CanRunWindowsMalFind()
    {
        var r = toolkit.WindowsMalFind("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }
    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    MemoryForensicsToolkit toolkit;
}
