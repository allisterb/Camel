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

    const string Modern = "/mnt/ewf";

    AuditEnvironment sshenv;
    CamelApi api;
    WindowsAnalysisWorkflow workflow;
}
