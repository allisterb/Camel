using System.Linq;

using Camel.Environments;
using Camel.Toolkits;
using Camel.DFIR.Toolkits;

namespace Camel.Tests.Toolkits;

public class TimelineTests : TestsRuntime
{
    public TimelineTests()
    {
        var sshconfig = EnsureSIFT(LoadConfigFile("sshtestappsettings.json"));
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new TimelineToolkit(sshenv, sshconfig);
        EvidenceMounts.EnsureAll(sshenv);   // ensure /mnt/windows_mount2 etc. before the shared .plaso build reads the hive

        // Build a small shared .plaso once (winreg over the SYSTEM hive) for the pinfo/psort tests.
        // Sync-over-async is fine here: test host has no SynchronizationContext, and this is one-time setup.
        if (!sshenv.ExecuteCommand("test", $"-f {Plaso}", out _, false))
            toolkit.Log2TimelineAsync(SystemHive, Plaso, parsers: "winreg").GetAwaiter().GetResult();
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
    public async Task CanRunLog2Timeline()
    {
        const string plaso = "/tmp/camel_l2t.plaso";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        Assert.True(await toolkit.Log2TimelineAsync(SystemHive, plaso, parsers: "winreg"));
        Assert.True(sshenv.ExecuteCommand("test", $"-s {plaso}", out _, false)); // file exists & non-empty
    }

    [Fact]
    public async Task Log2TimelineFilterFileNarrowsToTriageFiles()
    {
        const string plaso = "/tmp/camel_l2t_ff.plaso";
        const string filter = "/tmp/camel_l2t_filter.yaml";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        // A file-filter (same YAML format as the SANS filter_windows.yaml that ships with plaso) restricts parsing
        // to the listed files. Pointed at a full Windows volume, only the filtered SYSTEM hive is walked — the rest
        // of the filesystem is skipped — proving -f is applied and the run still yields events.
        var b64 = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
            "---\ndescription: Camel filter-file test.\ntype: include\npath_separator: '\\'\npaths:\n- '\\\\Windows\\\\System32\\\\config\\\\SYSTEM'\n"));
        sshenv.ExecuteCommand("bash", $"-c \"echo {b64} | base64 -d > {filter}\"", out _, false);

        Assert.True(await toolkit.Log2TimelineAsync(WindowsMount, plaso, parsers: "winreg", filterFile: filter));

        var info = (await toolkit.PinfoAsync(plaso)).Result;
        Assert.NotNull(info);
        Assert.True(info.TotalEvents > 0);
    }

    [Fact]
    public async Task Log2TimelineHashPopulatesMd5OnEvents()
    {
        const string plaso = "/tmp/camel_l2t_hash.plaso";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);

        // --hashers md5,sha256 hashes the processed source files; md5_hash then appears on events.
        Assert.True(await toolkit.Log2TimelineAsync(SystemHive, plaso, parsers: "winreg", hash: true));

        var r = (await toolkit.PsortAsync(plaso)).Result;
        Assert.NotNull(r);
        Assert.Contains(r, e => !string.IsNullOrEmpty(e.Md5Hash));
    }

    [Fact]
    public async Task CanTagSliceAndSearchWithPsort()
    {
        const string plaso = "/tmp/camel_tk_probe.plaso";
        sshenv.ExecuteCommand("rm", $"-f {plaso}", out _, false);
        Assert.True(await toolkit.Log2TimelineAsync(DlpcSystemHive, plaso, parsers: "winreg"));

        // Tagging persists labels into the storage file; a tag filter then returns events carrying them inline.
        Assert.True(await toolkit.PsortTagAsync(plaso, "/usr/share/plaso/tag_windows.txt"));
        var tagged = (await toolkit.PsortAsync(plaso, "tag contains 'application_execution'")).Result;
        Assert.NotNull(tagged);
        Assert.NotEmpty(tagged);
        Assert.All(tagged, e => Assert.Contains("application_execution", e.Labels));

        // A slice around one tagged event's time returns events within the window.
        var pivot = tagged[0].Time.ToString("yyyy-MM-ddTHH:mm:sszzz");
        var slice = (await toolkit.PsortAsync(plaso, slice: pivot, sliceSize: 60)).Result;
        Assert.NotNull(slice);
        Assert.NotEmpty(slice);

        // Grep-search the rendered timeline for a token present in the message text.
        var found = (await toolkit.PsortSearchAsync(plaso, "appcompatcache")).Result;
        Assert.NotNull(found);
        Assert.NotEmpty(found);
    }

    [Fact]
    public async Task CanRunPinfo()
    {
        var r = (await toolkit.PinfoAsync(Plaso)).Result;
        Assert.NotNull(r);
        Assert.True(r.TotalEvents > 0);
        Assert.NotEmpty(r.ParserCounts);
        Assert.Contains(r.ParserCounts.Keys, k => k.Contains("winreg") || k.Contains("windows"));
    }

    [Fact]
    public async Task CanRunPsort()
    {
        var r = (await toolkit.PsortAsync(Plaso)).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => (e.Parser ?? "").StartsWith("winreg"));
    }

    [Fact]
    public async Task CanRunPsortWithFilter()
    {
        // Narrow to just the AppCompatCache (shimcache) registry events; proves the filter is applied.
        var r = (await toolkit.PsortAsync(Plaso, "data_type contains 'appcompatcache'")).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, e => Assert.Contains("appcompatcache", e.DataType ?? ""));
    }

    [Fact]
    public async Task CanRunPsteal()
    {
        var r = (await toolkit.PstealAsync(SystemHive, parsers: "winreg")).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => (e.Parser ?? "").StartsWith("winreg"));
    }

    [Fact]
    public async Task CanRunImageExport()
    {
        const string outDir = "/tmp/camel_ie";
        sshenv.ExecuteCommand("rm", $"-rf {outDir}", out _, false);

        Assert.True(await toolkit.ImageExportAsync(E01, outDir, names: "boot.ini"));
        Assert.True(sshenv.ExecuteCommand("test", $"-f {outDir}/boot.ini", out _, false));
    }

    [Fact]
    public async Task CanRunHayabusaJsonTimeline()
    {
        // System.evtx yields a small set of medium+ Sigma detections on this image (fast, bounded).
        var r = (await toolkit.HayabusaJsonTimelineAsync($"{EvtxLogs}/System.evtx", minLevel: "medium")).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, a => Assert.False(string.IsNullOrEmpty(a.RuleTitle)));
        Assert.Contains(r, a => a.EventID > 0 && !string.IsNullOrEmpty(a.RuleID));
    }

    [Fact]
    public async Task CanRunHayabusaComputerMetrics()
    {
        var r = (await toolkit.HayabusaComputerMetricsAsync($"{EvtxLogs}/System.evtx")).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, c => c.Computer == "SRL-FORGE" && c.Events > 0);
    }

    [Fact]
    public async Task CanRunHayabusaEidMetrics()
    {
        var r = (await toolkit.HayabusaEidMetricsAsync($"{EvtxLogs}/System.evtx")).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.EventId > 0 && e.Total > 0);
    }

    [Fact]
    public async Task CanRunHayabusaLogMetrics()
    {
        var r = (await toolkit.HayabusaLogMetricsAsync($"{EvtxLogs}/System.evtx")).Result;
        Assert.NotNull(r);
        var m = Assert.Single(r);
        Assert.Equal("System.evtx", m.Filename);
        Assert.True(m.Events > 0);
    }

    [Fact]
    public async Task CanRunHayabusaLogonSummary()
    {
        var r = (await toolkit.HayabusaLogonSummaryAsync($"{EvtxLogs}/Security.evtx")).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => !e.Successful && e.Count > 0); // brute-force failures present
        Assert.Contains(r, e => e.Successful);
    }

    const string Plaso = "/tmp/camel_timeline.plaso";
    const string EvtxLogs = "/mnt/ewf/Windows/System32/winevt/Logs";
    const string SystemHive = "/mnt/windows_mount2/WINDOWS/system32/config/system";
    const string WindowsMount = "/mnt/dlpc";
    const string DlpcSystemHive = "/mnt/dlpc/Windows/System32/config/SYSTEM";
    const string E01 = "/mnt/artifacts/4Dell Latitude CPi.E01";

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    TimelineToolkit toolkit;
}
