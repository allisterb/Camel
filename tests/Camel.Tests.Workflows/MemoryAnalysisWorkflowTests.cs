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

    const string Image = "/mnt/artifacts/pat-2009-11-19.mddramimage";

    AuditEnvironment sshenv;
    CamelApi api;
    MemoryAnalysisWorkflow workflow;
}
