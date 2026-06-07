using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

public class WindowsAnalysisTests : TestsRuntime
{
    public WindowsAnalysisTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new WindowsAnalysisToolkit(sshenv, sshconfig);
    }

    [Fact]
    public void CanLoadAllToolsFromConfig()
    {
        // Constructing the toolkit loads every ToolList entry from config; verify all resolved.
        Assert.Equal(toolkit.ToolList.Length, toolkit.Tools.Count);
        Assert.All(toolkit.ToolList, name =>
        {
            Assert.True(toolkit.Tools.ContainsKey(name));
            Assert.StartsWith("dotnet /opt/zimmermantools/", toolkit.Tools[name].Command);
            Assert.NotEmpty(toolkit.Tools[name].Descriptioon);
        });
    }

    [Fact]
    public void CanRunMFTECmd()
    {
        var r = toolkit.MFTECmd($"{Mount}/$MFT");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.FileName == "boot.ini");
    }

    [Fact]
    public void CanRunLECmd()
    {
        var r = toolkit.LECmd($"{Mount}/Documents and Settings/All Users/Start Menu/Programs/Accessories/Calculator.lnk");
        Assert.NotNull(r);
        var lnk = Assert.Single(r);
        Assert.NotEmpty(lnk.SourceFile);
        Assert.Contains("calc.exe", lnk.RelativePath ?? "");
    }

    [Fact]
    public void CanRunSBECmd()
    {
        // This XP image records no shellbags, so just verify the call path returns a (possibly empty) set.
        var r = toolkit.SBECmd($"{Mount}/Documents and Settings/Mr. Evil");
        Assert.NotNull(r);
    }

    [Fact]
    public void CanRunAppCompatCacheParser()
    {
        var r = toolkit.AppCompatCacheParser($"{Mount}/WINDOWS/system32/config/system");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.Path.Contains("services.exe"));
    }

    [Fact]
    public void CanRunRBCmd()
    {
        var r = toolkit.RBCmd($"{Mount}/RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003/INFO2");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.FileName.Contains("lalsetup250.exe"));
    }

    [Fact]
    public void CanRunBstrings()
    {
        var r = toolkit.Bstrings($"{Mount}/boot.ini", minLength: 5);
        Assert.NotNull(r);
        Assert.Contains(r, s => s.Contains("boot loader"));
    }

    const string Mount = "/mnt/ewf_mount";

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    WindowsAnalysisToolkit toolkit;
}
