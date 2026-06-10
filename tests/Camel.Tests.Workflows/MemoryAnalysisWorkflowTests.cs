using System.Linq;

using Camel.Environments;
using Camel.Workflows;

namespace Camel.Tests.Workflows;

public class MemoryAnalysisWorkflowTests : TestsRuntime
{
    public MemoryAnalysisWorkflowTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelApi(sshenv, sshconfig);
        workflow = new MemoryAnalysisWorkflow(api);
    }

    [Fact]
    public async Task CanFindHiddenProcesses()
    {
        var r = await workflow.FindHiddenProcessAsync(Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        // Both enumerations returned processes (sanity: the image parsed and symbols resolved).
        Assert.True(r.Result.PsListCount > 0);
        Assert.True(r.Result.PsScanCount > 0);

        // Neither bucket may contain a PID that the pslist walk reports as active.
        var pslist = await api.MemoryAnalysis.WindowsPsListAsync(Image);
        Assert.NotNull(pslist);
        var listedPids = pslist!.Select(p => p.PID).ToHashSet();
        Assert.All(r.Result.HiddenProcesses, h => Assert.DoesNotContain(h.PID, listedPids));
        Assert.All(r.Result.ExitedProcesses, h => Assert.DoesNotContain(h.PID, listedPids));

        // The split is by exit state: hidden = still running (no ExitTime); exited = have an ExitTime.
        Assert.All(r.Result.HiddenProcesses, h => Assert.Null(h.ExitTime));
        Assert.All(r.Result.ExitedProcesses, h => Assert.NotNull(h.ExitTime));
    }

    [Fact]
    public async Task FindHiddenProcessFailsForMissingImage()
    {
        var r = await workflow.FindHiddenProcessAsync("/mnt/artifacts/does_not_exist.raw");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task CanFindHiddenServices()
    {
        var r = await workflow.FindHiddenServicesAsync(Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.TotalServices > 0); // the scan enumerated services

        // A clean image may legitimately flag none; any that ARE flagged must match a default fragment.
        string[] fragments = [@"\temp\", @"\appdata\", @"\users\"];
        Assert.All(r.Result.SuspiciousServices, s =>
            Assert.Contains(fragments, f => HasFragment(s.Binary, f) || HasFragment(s.BinaryRegistry, f) || HasFragment(s.Dll, f)));
    }

    [Fact]
    public async Task FindHiddenServicesFlagsByCustomFragment()
    {
        // "system32" is present in most legitimate service binaries, so a custom fragment proves the path
        // matching works (and every flagged service genuinely contains the fragment).
        const string fragment = "system32";
        var r = await workflow.FindHiddenServicesAsync(Image, fragment);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.SuspiciousServices);
        Assert.True(r.Result.SuspiciousServices.Length <= r.Result.TotalServices);
        Assert.All(r.Result.SuspiciousServices, s =>
            Assert.True(HasFragment(s.Binary, fragment) || HasFragment(s.BinaryRegistry, fragment) || HasFragment(s.Dll, fragment)));
    }

    [Fact]
    public async Task FindHiddenServicesFailsForMissingImage()
    {
        var r = await workflow.FindHiddenServicesAsync("/mnt/artifacts/does_not_exist.raw");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    static bool HasFragment(string? path, string fragment) =>
        path is not null && path.Contains(fragment, StringComparison.OrdinalIgnoreCase);

    [Fact]
    public async Task CanFindHollowingIndicators()
    {
        var r = await workflow.FindAnomalousMemoryIndicatorsAsync(Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.SuspectRegions); // malfind found anomalous executable regions

        // The two indicator buckets are subsets of all malfind hits.
        Assert.True(r.Result.RwxRegions.Length <= r.Result.SuspectRegions.Length);
        Assert.True(r.Result.MzHeaderRegions.Length <= r.Result.SuspectRegions.Length);

        // Every RWX region is genuinely writable+executable; every MZ region genuinely starts with an MZ header.
        Assert.All(r.Result.RwxRegions, h =>
        {
            Assert.Contains("EXECUTE", h.Protection);
            Assert.Contains("WRITE", h.Protection);
        });
        Assert.All(r.Result.MzHeaderRegions, h =>
            Assert.True((h.Notes?.Contains("MZ", StringComparison.OrdinalIgnoreCase) ?? false)
                || h.Hexdump.TrimStart().StartsWith("4d 5a", StringComparison.OrdinalIgnoreCase)));

        // This image contains at least one RWX (PAGE_EXECUTE_READWRITE) region, so the RWX detector flags it.
        Assert.NotEmpty(r.Result.RwxRegions);
    }

    [Fact]
    public async Task FindHollowingIndicatorsFailsForMissingImage()
    {
        var r = await workflow.FindAnomalousMemoryIndicatorsAsync("/mnt/artifacts/does_not_exist.raw");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task FindAnomalousMemoryDumpsAnomalousProcesses()
    {
        const string exeDir = "/tmp/camel_wf_anom_exe";
        sshenv.ExecuteCommand("rm", $"-rf {exeDir}", out _, true); // clean slate

        // Request executable dumps (light, ~100KB each). The memory-dump path uses the same per-PID helper and
        // is covered by the toolkit-level CanDumpProcessMemory test, so we don't dump ~100MB × every PID here.
        var r = await workflow.FindAnomalousMemoryIndicatorsAsync(Image, dumpProcessDir: exeDir);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.DumpedExecutables);              // each flagged process's image was dumped
        Assert.Empty(r.Result.DumpedProcessMemory);               // memory dir not requested
        Assert.All(r.Result.DumpedExecutables, f => Assert.StartsWith(exeDir, f));
        // 0-byte dumps (PE image paged out of RAM) are filtered, so every returned path is a non-empty file.
        Assert.All(r.Result.DumpedExecutables, f => Assert.True(sshenv.ExecuteCommand("test", $"-s {f}", out _, true)));

        sshenv.ExecuteCommand("rm", $"-rf {exeDir}", out _, true);
    }

    [Fact]
    public async Task FindAnomalousMemoryDoesNotDumpByDefault()
    {
        var r = await workflow.FindAnomalousMemoryIndicatorsAsync(Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result.DumpedExecutables);
        Assert.Empty(r.Result.DumpedProcessMemory);
        Assert.Empty(r.Result.ExtractedStrings);
    }

    [Fact]
    public async Task FindAnomalousMemoryStringsRequireMemoryDump()
    {
        // A strings dir without a memory dir has nothing to read from: no strings extracted, no memory dumped.
        var r = await workflow.FindAnomalousMemoryIndicatorsAsync(Image, dumpStringsDir: "/tmp/camel_wf_strings_nomem");

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result.ExtractedStrings);
        Assert.Empty(r.Result.DumpedProcessMemory);
    }

    [Fact]
    public async Task CanFindAllUniqueRemoteIPs()
    {
        // netscan is unsupported on the Windows XP image, so use the Windows 10 image (which has live connections).
        var r = await workflow.FindAllUniqueRemoteIPsAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.Connections);
        Assert.NotEmpty(r.Result.RemoteIPs); // this capture has connections to real remote hosts

        // The list is de-duplicated and excludes loopback/unspecified/wildcard noise.
        Assert.Equal(r.Result.RemoteIPs.Length, r.Result.RemoteIPs.Distinct().Count());
        string[] noise = ["", "0.0.0.0", "127.0.0.1", "::", "::1", "*"];
        Assert.All(r.Result.RemoteIPs, ip => Assert.DoesNotContain(ip, noise));

        // Every reported IP really is a foreign address from the netscan results.
        var foreign = r.Result.Connections.Select(c => c.ForeignAddr).ToHashSet();
        Assert.All(r.Result.RemoteIPs, ip => Assert.Contains(ip, foreign));
    }

    [Fact]
    public async Task FindAllUniqueRemoteIPsFailsForMissingImage()
    {
        var r = await workflow.FindAllUniqueRemoteIPsAsync("/mnt/artifacts/does_not_exist.raw");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task CanGenerateTimeline()
    {
        const string dir = "/tmp/camel_wf_timeline";
        const string outPath = dir + "/mem_timeline.txt";
        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, true); // clean slate

        var r = await workflow.GenerateTimelineAsync(Image, outPath);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Equal(outPath, r.Result.TimelinePath);
        Assert.EndsWith("volatility.body", r.Result.BodyfilePath);
        // Both the timeline and the intermediate bodyfile were written with content.
        Assert.True(sshenv.ExecuteCommand("test", $"-s {r.Result.TimelinePath}", out _, true));
        Assert.True(sshenv.ExecuteCommand("test", $"-s {r.Result.BodyfilePath}", out _, true));

        sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, true);
    }

    [Fact]
    public async Task GenerateTimelineFailsForMissingImage()
    {
        var r = await workflow.GenerateTimelineAsync("/mnt/artifacts/does_not_exist.raw", "/tmp/camel_wf_timeline_bad/mem_timeline.txt");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    const string Image = "/mnt/artifacts/pat-2009-11-19.mddramimage";
    const string Win10Image = "/mnt/artifacts/Rocba-Memory.raw";

    AuditEnvironment sshenv;
    CamelApi api;
    MemoryAnalysisWorkflow workflow;
}
