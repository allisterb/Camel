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
            var cmd = toolkit.Tools[name].Command;
            // EZ Tools run via dotnet from /opt/zimmermantools; RegRipper is the on-PATH rip.pl Perl script; the
            // FOR500.3+4 email/ESE/USB/browser tools are native binaries under /usr/bin or /usr/local/bin.
            Assert.True(cmd.StartsWith("dotnet /opt/zimmermantools/") || cmd == "rip.pl"
                        || cmd.StartsWith("/usr/bin/") || cmd.StartsWith("/usr/local/bin/"),
                $"unexpected command for {name}: {cmd}");
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
    public async Task CanRunMFTECmdCsv()
    {
        const string mft = "/tmp/camel_mft_csv_in";
        const string dir = "/tmp/camel_mft_csv";
        sshenv.ExecuteCommand("head", $"-c 16000000 '{Modern}/$MFT' > {mft}", out _, false); // record-aligned extract
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);

        var r = await toolkit.MFTECmdCsvAsync(mft, outputDir: dir, outputFile: "mft.csv", allTimestamps: true);

        Assert.NotNull(r);
        Assert.True(r.FileRecords > 0);
        Assert.Equal($"{dir}/mft.csv", r.OutputFile);
        Assert.True(sshenv.ExecuteCommand("test", $"-s {dir}/mft.csv", out _, false)); // CSV written with content

        sshenv.ExecuteCommand("rm", $"-rf {dir} {mft}", out _, false);
    }

    [Fact]
    public async Task CanRunMFTECmdBodyfile()
    {
        const string mft = "/tmp/camel_mft_body_in";
        const string dir = "/tmp/camel_mft_body";
        sshenv.ExecuteCommand("head", $"-c 16000000 '{Modern}/$MFT' > {mft}", out _, false);
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);

        var r = await toolkit.MFTECmdBodyfileAsync(mft, outputDir: dir, outputFile: "mft.body", driveLetter: "C");

        Assert.NotNull(r);
        Assert.True(r.FileRecords > 0);
        Assert.Equal($"{dir}/mft.body", r.OutputFile);
        Assert.True(sshenv.ExecuteCommand("test", $"-s {dir}/mft.body", out _, false));
        // The bodyfile paths carry the drive letter from --bdl C (e.g. "c:/$MFT").
        Assert.True(sshenv.ExecuteCommand("grep", $"-q 'c:/' {dir}/mft.body", out _, false));

        sshenv.ExecuteCommand("rm", $"-rf {dir} {mft}", out _, false);
    }

    [Fact]
    public async Task MFTECmdCsvRequiresOutputFileOrDir()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => toolkit.MFTECmdCsvAsync("/tmp/x"));
    }

    [Fact]
    public async Task MFTECmdBodyfileRequiresOutputFileOrDir()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => toolkit.MFTECmdBodyfileAsync("/tmp/x"));
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
    public async Task CanRunSBECmdCsv()
    {
        const string dir = "/tmp/camel_sbe_csv";
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false); // clean slate

        // The Greg Schardt image's "Mr. Evil" profile NTUSER.DAT has parseable shellbags.
        var r = await toolkit.SBECmdCsvAsync($"{GregSchardt}/Documents and Settings/Mr. Evil", dir);

        Assert.NotNull(r);
        Assert.True(r.TotalShellBags > 0);
        Assert.Equal(dir, r.OutputDirectory);
        Assert.NotEmpty(r.CsvFiles); // a per-hive CSV (e.g. NTUSER.csv) was written
        Assert.All(r.CsvFiles, f => Assert.True(sshenv.ExecuteCommand("test", $"-s {f}", out _, false)));

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
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
    public async Task CanRunEvtxECmdWithIncludeFilter()
    {
        string log = $"{Modern}/Windows/System32/winevt/Logs/Setup.evtx";
        var all = await toolkit.EvtxECmdAsync(file: log);
        Assert.NotNull(all);
        Assert.NotEmpty(all);

        // Filtering to a single known-present Event ID (--inc) returns only that ID.
        int id = all[0].EventId;
        var filtered = await toolkit.EvtxECmdAsync(file: log, includeIds: id.ToString());
        Assert.NotNull(filtered);
        Assert.NotEmpty(filtered);
        Assert.All(filtered, e => Assert.Equal(id, e.EventId));
        Assert.True(filtered.Length <= all.Length);
    }

    [Fact]
    public async Task EvtxECmdRequiresFileOrDirectory()
    {
        // With neither -f nor -d there is nothing to parse — fail fast rather than invoking the tool.
        await Assert.ThrowsAsync<ArgumentException>(() => toolkit.EvtxECmdAsync());
    }

    [Fact]
    public async Task CanRunEvtxECmdCsv()
    {
        const string dir = "/tmp/camel_evtx_csv";
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false); // clean slate

        var r = await toolkit.EvtxECmdCsvAsync(
            file: $"{Modern}/Windows/System32/winevt/Logs/Setup.evtx",
            outputDir: dir, outputFile: "setup.csv");

        Assert.NotNull(r);
        Assert.True(r.RecordsIncluded > 0);
        Assert.Equal($"{dir}/setup.csv", r.OutputFile);
        Assert.Equal(dir, r.OutputDirectory);
        // The CSV file was really written with content.
        Assert.True(sshenv.ExecuteCommand("test", $"-s {dir}/setup.csv", out _, false));

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
    }

    [Fact]
    public async Task EvtxECmdCsvRequiresFileOrDirectory()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => toolkit.EvtxECmdCsvAsync(outputDir: "/tmp/x"));
    }

    [Fact]
    public async Task EvtxECmdCsvRequiresOutputFileOrDir()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => toolkit.EvtxECmdCsvAsync(file: "/x.evtx"));
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

    [Fact]
    public async Task CanRunRegRipper()
    {
        // The 'run' plugin lists the autostart Run/RunOnce keys from the SOFTWARE hive.
        var r = await toolkit.RegRipperAsync($"{Modern}/Windows/System32/config/SOFTWARE", "run");
        Assert.NotNull(r);
        Assert.Equal("run", r.Plugin);
        Assert.NotEmpty(r.Lines);
        Assert.NotNull(r.Version);
        Assert.Contains(@"CurrentVersion\Run", r.Output); // the Run key path appears in the plugin output
    }

    [Fact]
    public async Task CanParseScheduledTasks()
    {
        // Parse the on-disk Task Scheduler XML tree (UTF-16 files) into typed entries with recovered actions.
        var r = await toolkit.ScheduledTasksAsync($"{Modern}/Windows/System32/Tasks");
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, t => Assert.NotEmpty(t.TaskFile));
        // Most tasks expose a <URI>, and third-party tasks (Adobe/Google/Office) carry an Exec command line.
        Assert.Contains(r, t => !string.IsNullOrEmpty(t.Uri));
        Assert.Contains(r, t => !string.IsNullOrEmpty(t.Command));
    }

    [Fact]
    public async Task CanLoadLolbas()
    {
        // The toolkit constructor installs lolbas.json; load it into the queryable index.
        var lolbas = await toolkit.LoadLolbasAsync();
        Assert.NotNull(lolbas);
        Assert.True(lolbas.Count > 100, $"expected the full LOLBAS list, got {lolbas.Count}");
        Assert.True(lolbas.IsLolbin("rundll32.exe"));
        Assert.False(lolbas.IsLolbin("definitely_not_a_lolbin.exe"));
        // Canonical install location is recognized; the same binary in a temp dir is not (masquerading).
        Assert.True(lolbas.IsCanonicalPath("rundll32.exe", @"C:\Windows\System32\rundll32.exe"));
        Assert.True(lolbas.IsCanonicalPath("rundll32.exe", @"%SystemRoot%\System32\rundll32.exe")); // env-var prefix
        Assert.False(lolbas.IsCanonicalPath("rundll32.exe", @"C:\ProgramData\rundll32.exe"));
    }

    [Fact]
    public async Task CanParseWmiSubscriptions()
    {
        // Synthetic OBJECTS.DATA with a WMI subscription's strings in repository order; strings extraction +
        // parsing must recover the consumer, its action, and the bound filter (the proximity-association path).
        const string dir = "/tmp/camel_wmi_tk";
        const string content =
            "PerformanceMonitor\n" +
            "powershell -W Hidden -nop -noni -ec SQBFAFgA\n" +
            "SystemPerformanceMonitor\n" +
            "CommandLineEventConsumer.Name=\"SystemPerformanceMonitor\"\n" +
            "__EventFilter.Name=\"PerformanceMonitor\"\n";
        var b64 = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(content));
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
        sshenv.ExecuteCommand("mkdir", $"-p {dir}", out _, false);
        sshenv.ExecuteCommand("echo", $"{b64} | base64 -d > {dir}/OBJECTS.DATA", out _, false);

        var r = await toolkit.WmiSubscriptionsAsync($"{dir}/OBJECTS.DATA");

        Assert.NotNull(r);
        var c = Assert.Single(r.Consumers);
        Assert.Equal("CommandLineEventConsumer", c.Type);
        Assert.Equal("SystemPerformanceMonitor", c.Name);
        Assert.Contains("powershell", c.Command ?? "");            // action recovered by proximity
        Assert.Contains("PerformanceMonitor", r.Filters);
        Assert.Contains(r.Bindings, b => b.ConsumerName == "SystemPerformanceMonitor" && b.FilterName == "PerformanceMonitor");

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
    }

    // ── FOR500.3+4 wrappers (email / ESE / USB / browser SQLite), against the CFREDS Data-Leakage mount ──────────

    [Fact]
    public async Task CanGetPstStoreInfo()
    {
        var r = await toolkit.PffInfoAsync(DlpcOst);
        Assert.NotNull(r);
        Assert.Contains("OST", r!.ContentType ?? "");            // iaman.informant@nist.gov.ost is an Exchange OST
        Assert.True(r.FileSize > 0);
    }

    [Fact]
    public async Task CanReadPstMessages()
    {
        var r = await toolkit.ReadPstAsync(DlpcOst);
        Assert.NotNull(r);
        Assert.NotEmpty(r!.Messages);
        // The Data-Leakage scenario seeds a conversation with spy.conspirator@nist.gov.
        Assert.Contains(r.Messages, m => (m.From ?? "").Contains("nist.gov", StringComparison.OrdinalIgnoreCase)
                                      || (m.To ?? "").Contains("nist.gov", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CanListEseTablesAndParseWebCacheHistory()
    {
        var info = await toolkit.EsedbInfoAsync(DlpcWebCache);
        Assert.NotNull(info);
        Assert.Contains("Containers", info!.Tables);

        var entries = await toolkit.WebCacheHistoryAsync(DlpcWebCache);
        Assert.NotNull(entries);
        Assert.NotEmpty(entries!);
        // Every recovered record is a real URL (http/https/file/…), not a content header or "Host:" marker.
        Assert.All(entries!, e => Assert.Contains("://", e.Url));
    }

    [Fact]
    public async Task CanProfileUsbDevices()
    {
        var r = await toolkit.UsbDeviceForensicsAsync(DlpcSystem, DlpcSoftware);
        Assert.NotNull(r);
        Assert.NotEmpty(r!);
        // The case features a SanDisk Cruzer Fit thumb drive used to exfiltrate data.
        Assert.Contains(r!, d => (d.Product ?? "").Contains("Cruzer", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CanQueryBrowserSqlite()
    {
        var rows = await toolkit.SqliteQueryAsync(DlpcChromeHistory,
            "SELECT url,title,visit_count,last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10");
        Assert.NotNull(rows);
        Assert.NotEmpty(rows!);
        Assert.Contains(rows!, r => r.ContainsKey("url"));
    }

    [Fact]
    public async Task CanParseLnkDirectory()
    {
        var r = await toolkit.LECmdDirectoryAsync($"{DlpcUser}/AppData/Roaming/Microsoft/Windows/Recent");
        Assert.NotNull(r);   // an empty Recent folder yields [] (not null); a parse failure yields null
    }

    const string Modern = "/mnt/ewf";
    const string GregSchardt = "/mnt/windows_mount2"; // 'Greg Schardt' XP image (4Dell Latitude CPi.E01)
    const string DfirBatch = "/opt/zimmermantools/RECmd/DFIRBatch.reb";

    // CFREDS "Data Leakage" PC image, mounted at /mnt/dlpc (registry hives, an Outlook OST, WebCache, Chrome).
    const string Dlpc = "/mnt/dlpc";
    const string DlpcUser = "/mnt/dlpc/Users/informant";
    const string DlpcSystem = "/mnt/dlpc/Windows/System32/config/SYSTEM";
    const string DlpcSoftware = "/mnt/dlpc/Windows/System32/config/SOFTWARE";
    const string DlpcOst = "/mnt/dlpc/Users/informant/AppData/Local/Microsoft/Outlook/iaman.informant@nist.gov.ost";
    const string DlpcWebCache = "/mnt/dlpc/Users/admin11/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat";
    const string DlpcChromeHistory = "/mnt/dlpc/Users/admin11/AppData/Local/Google/Chrome/User Data/Default/History";

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    WindowsAnalysisToolkit toolkit;
}
