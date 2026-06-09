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
    public async Task CanRunMFTECmd()
    {
        // The modern $MFT is ~560MB; parsing all of it would round-trip a ~560MB JSON. Parse a bounded
        // extract of the mount's real $MFT (single quotes keep $MFT literal; redirect runs in the shell).
        const string mft = "/tmp/camel_mft_head";
        sshenv.ExecuteCommand("head", $"-c 16000000 '{Modern}/$MFT' > {mft}", out _, false);

        var r = await toolkit.MFTECmdAsync(mft);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.FileName == "$MFT"); // entry 0 is always $MFT
    }

    [Fact]
    public async Task CanRunLECmd()
    {
        var r = await toolkit.LECmdAsync($"{Modern}/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/10l_brianlaiphotography-northcotepoint.lnk");
        Assert.NotNull(r);
        var lnk = Assert.Single(r);
        Assert.NotEmpty(lnk.SourceFile);
        Assert.Contains(".jpg", lnk.LocalPath ?? "");
    }

    [Fact]
    public async Task CanRunSBECmd()
    {
        // This image records no parseable shellbags, so just verify the call path returns a (possibly empty) set.
        var r = await toolkit.SBECmdAsync($"{Modern}/Users/fredr");
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunAppCompatCacheParser()
    {
        var r = await toolkit.AppCompatCacheParserAsync($"{Modern}/Windows/System32/config/SYSTEM");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.Path.Contains(".exe"));
    }

    [Fact]
    public async Task CanRunRBCmd()
    {
        var r = await toolkit.RBCmdAsync($"{Modern}/$Recycle.Bin/S-1-5-21-528816539-567677750-276746561-1002/$I0JIS5M.lnk");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => !string.IsNullOrEmpty(e.FileName));
    }

    [Fact]
    public async Task CanRunBstrings()
    {
        var r = await toolkit.BstringsAsync($"{Modern}/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/10l_brianlaiphotography-northcotepoint.lnk", minLength: 5);
        Assert.NotNull(r);
        Assert.Contains(r, s => s.Contains(".jpg"));
    }

    [Fact]
    public async Task CanRunAmcacheParser()
    {
        var r = await toolkit.AmcacheParserAsync($"{Modern}/Windows/appcompat/Programs/Amcache.hve");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => !string.IsNullOrEmpty(e.SHA1) && !string.IsNullOrEmpty(e.FullPath));
    }

    [Fact]
    public async Task CanRunEvtxECmd()
    {
        var r = await toolkit.EvtxECmdAsync($"{Modern}/Windows/System32/winevt/Logs/Setup.evtx");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, e => Assert.Equal("Setup", e.Channel));
        Assert.Contains(r, e => e.EventId > 0);
    }

    [Fact]
    public async Task CanRunJLECmd()
    {
        var r = await toolkit.JLECmdAsync($"{Modern}/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => !string.IsNullOrEmpty(e.Path));
    }

    [Fact]
    public async Task CanRunWxTCmd()
    {
        // This image's ActivitiesCache.db files contain no activities; verify the call path returns non-null.
        var r = await toolkit.WxTCmdAsync($"{Modern}/Users/fredr/AppData/Local/ConnectedDevicesPlatform/e431499dada298ba/ActivitiesCache.db");
        Assert.NotNull(r);
    }

    [Fact]
    public async Task CanRunRECmd()
    {
        // Batch-parse the mount's registry hives with the bundled DFIR batch file (--bn).
        var r = await toolkit.RECmdAsync($"{Modern}/Windows/System32/config", DfirBatch);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => !string.IsNullOrEmpty(e.KeyPath) && !string.IsNullOrEmpty(e.HivePath));
    }

    [Fact]
    public async Task CanRunSQLECmd()
    {
        // SQLECmd's --json aggregate is empty for these Chrome DBs (maps emit per-artifact files), and a full
        // profile scan is slow (~50s). Run against a single small DB copied out of the mount to keep it fast.
        const string dir = "/tmp/camel_sqle";
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
        sshenv.ExecuteCommand("mkdir", $"-p {dir}", out _, false);
        sshenv.ExecuteCommand("cp", $"'{Modern}/Users/fredr/AppData/Local/Google/Chrome/User Data/Default/History' {dir}/", out _, false);

        var r = await toolkit.SQLECmdAsync(dir);
        Assert.NotNull(r);
    }

    const string Modern = "/mnt/ewf";
    const string DfirBatch = "/opt/zimmermantools/RECmd/DFIRBatch.reb";

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    WindowsAnalysisToolkit toolkit;
}
