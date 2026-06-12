using System.Linq;

using Camel.Environments;
using Camel.Toolkits.Models;
using Camel.Training;

namespace Camel.Tests.Training;

public class CanonicalizerTests : TestsRuntime
{
    public CanonicalizerTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelApi(sshenv, sshconfig);
    }

    // --- pure logic tests (no workstation) ---

    [Fact]
    public void OrdersByTimeAndComputesLogDelta()
    {
        long b = 1_600_000_000_000_000;                 // base epoch microseconds; gaps are 60 s (60_000_000 µs)
        var evs = new[]
        {
            Ev(b + 120_000_000, "windows:registry:key_value"),   // latest  (+120s) — supplied out of order
            Ev(b,               "windows:registry:key_value"),   // earliest
            Ev(b + 60_000_000,  "windows:registry:key_value"),   // middle  (+60s)
        };

        var c = EventCanonicalizer.Canonicalize(evs);

        Assert.Equal(3, c.Length);
        Assert.True(c[0].Ts < c[1].Ts && c[1].Ts < c[2].Ts);        // sorted ascending
        Assert.Equal(0f, c[0].DtPrev);                              // first has no predecessor
        Assert.InRange(c[1].DtPrev, 4.0f, 4.2f);                    // ln(1+60) ≈ 4.11
        Assert.InRange(c[2].DtPrev, 4.0f, 4.2f);                    // ln(1+60) ≈ 4.11
    }

    [Theory]
    [InlineData("windows:registry:appcompatcache", SourceClass.Registry)]
    [InlineData("windows:evtx:record", SourceClass.EventLog)]
    [InlineData("fs:stat", SourceClass.FileSystem)]
    [InlineData("windows:lnk:link", SourceClass.Lnk)]
    [InlineData("windows:prefetch:execution", SourceClass.Prefetch)]
    [InlineData("msiecf:url", SourceClass.WebHistory)]
    [InlineData("syslog:line", SourceClass.Log)]
    [InlineData("something:exotic", SourceClass.Other)]
    public void ClassifiesSource(string dataType, SourceClass expected) =>
        Assert.Equal(expected, EventCanonicalizer.ClassifySource(dataType));

    [Theory]
    [InlineData("windows:registry:appcompatcache", RegClass.Shimcache)]
    [InlineData("windows:registry:userassist", RegClass.UserAssist)]
    [InlineData("windows:registry:windows_run", RegClass.Run)]
    [InlineData("windows:registry:bagmru", RegClass.Bagmru)]          // not swallowed by the "mru" rule
    [InlineData("windows:registry:key_value", RegClass.Other)]
    [InlineData("windows:evtx:record", RegClass.None)]               // non-registry
    public void ClassifiesRegistryArtifact(string dataType, RegClass expected) =>
        Assert.Equal(expected, EventCanonicalizer.ClassifyReg(dataType));

    [Theory]
    [InlineData(@"C:\Windows\System32\svchost.exe", LocBucket.System32)]
    [InlineData(@"C:\Windows\SysWOW64\x.dll", LocBucket.SysWow64)]
    [InlineData(@"C:\Windows\Temp\a.exe", LocBucket.Temp)]
    [InlineData(@"C:\Users\bob\AppData\Local\Temp\x.tmp", LocBucket.AppData)]   // appdata wins over temp
    [InlineData(@"C:\Users\bob\Documents\report.docx", LocBucket.UsersProfile)]
    [InlineData(@"C:\Program Files\app\app.exe", LocBucket.ProgramFiles)]
    [InlineData(@"C:\$Recycle.Bin\S-1-5-21\$IABC.exe", LocBucket.Recycle)]
    [InlineData(@"\\server\share\file.dat", LocBucket.Network)]
    [InlineData("OS:/mnt/dlpc/Windows/System32/config/SYSTEM", LocBucket.System32)]  // scheme prefix stripped
    [InlineData("", LocBucket.Unknown)]
    public void ClassifiesLocation(string path, LocBucket expected) =>
        Assert.Equal(expected, EventCanonicalizer.ClassifyLocation(path));

    [Theory]
    [InlineData("Creation Time", Macb.Birth)]
    [InlineData("Content Modification Time", Macb.Modified)]
    [InlineData("Last Written Time", Macb.Modified)]
    [InlineData("Last Access Time", Macb.Accessed)]
    [InlineData("Metadata Modification Time", Macb.Changed)]          // C, not M+C
    public void ClassifiesMacb(string desc, Macb expected) =>
        Assert.Equal(expected, EventCanonicalizer.ClassifyMacb(desc));

    [Fact]
    public void ExtractsEventIdAndExtension()
    {
        Assert.Equal(4624, EventCanonicalizer.ExtractEventId("[4624 / 0x1210] Record Number: 5 ..."));
        Assert.Null(EventCanonicalizer.ExtractEventId("no event id here"));
        Assert.Equal("ps1", EventCanonicalizer.ExtractExt(@"C:\x\evil.PS1"));
        Assert.Equal("gz", EventCanonicalizer.ExtractExt("archive.tar.gz"));
        Assert.Null(EventCanonicalizer.ExtractExt(@"C:\folder\noext"));
    }

    [Fact]
    public void RendersStableTokenSentence()
    {
        var e = new CanonicalEvent
        {
            Ts = 1_600_000_000_000_000, DataType = "windows:evtx:record", Source = SourceClass.EventLog,
            Macb = Macb.Birth, Location = LocBucket.System32, EventId = 4624, DtPrev = 0f, HourOfDay = 14,
        };
        var text = TextRenderer.Render(e);
        Assert.Contains("eventlog", text);
        Assert.Contains("evtx record", text);
        Assert.Contains("eid: 4624", text);            // field name separated from value for clean tokenization
        Assert.Contains("loc: system32", text);
        Assert.Contains("macb: ...b", text);
        Assert.Contains("h: 14", text);
    }

    // --- integration: canonicalize a real timeline off the SIFT box ---

    [Fact]
    public async Task CanonicalizesRealDlpcTimeline()
    {
        // Build (once) a registry timeline from the dlpc SYSTEM hive and canonicalize the real events. The export
        // is narrowed to the AppCompatCache (shimcache) subset — real Plaso events, but a few hundred rather than
        // the ~35k winreg_default emits, so the SSH transfer stays fast.
        if (!sshenv.ExecuteCommand("test", $"-f {RegPlaso}", out _, false))
            Assert.True(await api.Timeline.Log2TimelineAsync(SystemHive, RegPlaso, parsers: "winreg"));
        var events = await api.Timeline.PsortAsync(RegPlaso, "data_type contains 'appcompatcache'");
        Assert.NotNull(events);
        Assert.NotEmpty(events);

        var canon = EventCanonicalizer.Canonicalize(events);

        Assert.NotEmpty(canon);
        for (int i = 1; i < canon.Length; i++) Assert.True(canon[i].Ts >= canon[i - 1].Ts);   // ascending
        Assert.Equal(0f, canon[0].DtPrev);
        Assert.All(canon, c => Assert.InRange(c.HourOfDay, 0, 23));
        // A SYSTEM hive is registry-dominated and carries AppCompatCache (shimcache) entries.
        Assert.Contains(canon, c => c.Source == SourceClass.Registry);
        Assert.Contains(canon, c => c.Reg == RegClass.Shimcache);
        // Every canonical event renders to a non-empty token sentence (the MiniLM embedding input).
        Assert.All(canon, c => Assert.False(string.IsNullOrWhiteSpace(TextRenderer.Render(c))));
    }

    private static TimelineEvent Ev(long ts, string dataType) => new() { Timestamp = ts, DataType = dataType };

    const string SystemHive = "/mnt/dlpc/Windows/System32/config/SYSTEM";
    const string RegPlaso = "/tmp/camel_train_reg.plaso";

    AuditEnvironment sshenv;
    CamelApi api;
}
