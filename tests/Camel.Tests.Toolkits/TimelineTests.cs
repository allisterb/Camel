using System.Linq;

using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

public class TimelineTests : TestsRuntime
{
    public TimelineTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new TimelineToolkit(sshenv, sshconfig);

        // Build a small shared .plaso once (winreg over the SYSTEM hive) for the pinfo/psort tests.
        if (!sshenv.ExecuteCommand("test", $"-f {Plaso}", out _, false))
            toolkit.Log2Timeline(SystemHive, Plaso, parsers: "winreg");
    }

    [Fact]
    public void CanLoadAllToolsFromConfig()
    {
        Assert.Equal(toolkit.ToolList.Length, toolkit.Tools.Count);
        Assert.All(toolkit.ToolList, name =>
        {
            Assert.True(toolkit.Tools.ContainsKey(name));
            Assert.Contains("bin/", toolkit.Tools[name].Command);
            Assert.NotEmpty(toolkit.Tools[name].Descriptioon);
        });
    }

    [Fact]
    public void CanRunLog2Timeline()
    {
        const string plaso = "/tmp/camel_l2t.plaso";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        Assert.True(toolkit.Log2Timeline(SystemHive, plaso, parsers: "winreg"));
        Assert.True(sshenv.ExecuteCommand("test", $"-s {plaso}", out _, false)); // file exists & non-empty
    }

    [Fact]
    public void Log2TimelineHashPopulatesMd5OnEvents()
    {
        const string plaso = "/tmp/camel_l2t_hash.plaso";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        // --hashers md5,sha256 hashes the processed source files; md5_hash then appears on events.
        Assert.True(toolkit.Log2Timeline(SystemHive, plaso, parsers: "winreg", hash: true));

        var r = toolkit.Psort(plaso);
        Assert.NotNull(r);
        Assert.Contains(r, e => !string.IsNullOrEmpty(e.Md5Hash));
    }

    [Fact]
    public void CanRunPinfo()
    {
        var r = toolkit.Pinfo(Plaso);
        Assert.NotNull(r);
        Assert.True(r.TotalEvents > 0);
        Assert.NotEmpty(r.ParserCounts);
        Assert.Contains(r.ParserCounts.Keys, k => k.Contains("winreg") || k.Contains("windows"));
    }

    [Fact]
    public void CanRunPsort()
    {
        var r = toolkit.Psort(Plaso);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => (e.Parser ?? "").StartsWith("winreg"));
    }

    [Fact]
    public void CanRunPsortWithFilter()
    {
        // Narrow to just the AppCompatCache (shimcache) registry events; proves the filter is applied.
        var r = toolkit.Psort(Plaso, "data_type contains 'appcompatcache'");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, e => Assert.Contains("appcompatcache", e.DataType ?? ""));
    }

    [Fact]
    public void CanRunPsteal()
    {
        var r = toolkit.Psteal(SystemHive, parsers: "winreg");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => (e.Parser ?? "").StartsWith("winreg"));
    }

    [Fact]
    public void CanRunImageExport()
    {
        const string outDir = "/tmp/camel_ie";
        sshenv.ExecuteCommand("rm", $"-rf {outDir}", out _, false);

        Assert.True(toolkit.ImageExport(E01, outDir, names: "boot.ini"));
        Assert.True(sshenv.ExecuteCommand("test", $"-f {outDir}/boot.ini", out _, false));
    }

    [Fact]
    public void CanRunHayabusaJsonTimeline()
    {
        // System.evtx yields a small set of medium+ Sigma detections on this image (fast, bounded).
        var r = toolkit.HayabusaJsonTimeline($"{EvtxLogs}/System.evtx", minLevel: "medium");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, a => Assert.False(string.IsNullOrEmpty(a.RuleTitle)));
        Assert.Contains(r, a => a.EventID > 0 && !string.IsNullOrEmpty(a.RuleID));
    }

    [Fact]
    public void CanRunHayabusaComputerMetrics()
    {
        var r = toolkit.HayabusaComputerMetrics($"{EvtxLogs}/System.evtx");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, c => c.Computer == "SRL-FORGE" && c.Events > 0);
    }

    [Fact]
    public void CanRunHayabusaEidMetrics()
    {
        var r = toolkit.HayabusaEidMetrics($"{EvtxLogs}/System.evtx");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.EventId > 0 && e.Total > 0);
    }

    [Fact]
    public void CanRunHayabusaLogMetrics()
    {
        var r = toolkit.HayabusaLogMetrics($"{EvtxLogs}/System.evtx");
        Assert.NotNull(r);
        var m = Assert.Single(r);
        Assert.Equal("System.evtx", m.Filename);
        Assert.True(m.Events > 0);
    }

    [Fact]
    public void CanRunHayabusaLogonSummary()
    {
        var r = toolkit.HayabusaLogonSummary($"{EvtxLogs}/Security.evtx");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => !e.Successful && e.Count > 0); // brute-force failures present
        Assert.Contains(r, e => e.Successful);
    }

    const string Plaso = "/tmp/camel_timeline.plaso";
    const string EvtxLogs = "/mnt/ewf/Windows/System32/winevt/Logs";
    const string SystemHive = "/mnt/windows_mount2/WINDOWS/system32/config/system";
    const string E01 = "/mnt/artifacts/4Dell Latitude CPi.E01";

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    TimelineToolkit toolkit;
}
