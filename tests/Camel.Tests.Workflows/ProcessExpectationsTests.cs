using System.Linq;

using Camel.Environments;
using Camel.Toolkits;
using Camel.DFIR.Toolkits;
using Camel.Toolkits.Models;
using Camel.Workflows;
using Camel.DFIR.Workflows;
using Camel.Workflows.Models;

namespace Camel.Tests.Workflows;

/// <summary>
/// Offline unit tests for the process-expectation dataset (parsing the bundled <c>process_expectations.yaml</c>)
/// and the process-tree validation logic — no SIFT workstation required.
/// </summary>
public class ProcessExpectationsTests
{
    // ValidateProcessTreeAsync / GetProcessExpectations touch no environment, so a local-env workflow suffices.
    private static readonly WindowsAnalysisWorkflow workflow =
        new(new CamelToolkitsApi(new LocalEnvironment()));

    // --- parsing ---

    [Fact]
    public void ParsesEveryProcessKeyedByLowercaseName()
    {
        var db = ProcessExpectations.Load();

        Assert.Equal(57, db.Count);                              // 57 process_name entries in the dataset
        Assert.True(db.ContainsKey("svchost.exe"));
        Assert.True(db.ContainsKey("system"));                   // kernel processes have no .exe suffix
        Assert.All(db.Keys, k => Assert.Equal(k.ToLowerInvariant(), k));
        Assert.All(db, kv => Assert.Equal(kv.Key, kv.Value.ProcessName));
    }

    [Fact]
    public void CapturesWhitelistBlacklistNeverSpawnsAndScalars()
    {
        var db = ProcessExpectations.Load();

        // Whitelist + required args + instance band for svchost.
        var svchost = db["svchost.exe"];
        Assert.Equal(["services.exe"], svchost.ValidParents!);
        Assert.Equal("-k", svchost.RequiredArgs);
        Assert.Equal(5, svchost.MinInstances);
        Assert.Null(svchost.MaxInstances);
        Assert.Contains(@"\windows\system32\svchost.exe", svchost.ValidPaths!);

        // Never-spawns-children injection target.
        Assert.True(db["lsass.exe"].NeverSpawnsChildren);
        Assert.Equal(1, db["lsass.exe"].MaxInstances);

        // "system" has an explicit empty valid_parents ([]), distinct from cmd.exe's null (any parent OK).
        Assert.Empty(db["system"].ValidParents!);
        Assert.Null(db["cmd.exe"].ValidParents);
    }

    [Fact]
    public void ResolvesYamlAnchorsForSharedSuspiciousParentLists()
    {
        var db = ProcessExpectations.Load();

        // cmd/powershell/pwsh share the big blacklist; the &recon alias is reused across recon binaries.
        foreach (var shell in new[] { "cmd.exe", "powershell.exe", "pwsh.exe" })
        {
            Assert.NotNull(db[shell].SuspiciousParents);
            Assert.Contains("winword.exe", db[shell].SuspiciousParents!);
            Assert.Contains("lsass.exe", db[shell].SuspiciousParents!);
        }
    }

    // --- validation ---

    [Fact]
    public async Task FlagsInjectionWhenNeverSpawnsParentHasAChild()
    {
        // lsass.exe must never spawn a child; a cmd.exe under it is a critical injection lead.
        var r = await workflow.ValidateProcessTreeAsync(
        [
            new ProcessNode { Name = "cmd.exe", ParentName = "lsass.exe", Pid = 4321, Ppid = 700 },
        ]);

        Assert.True(r.IsSuccess, r.Message);
        var check = Assert.Single(r.Result!.Processes);
        Assert.Contains(check.Findings, f => f.Type == WindowsAnalysisWorkflow.FindingInjection
                                          && f.Severity == WindowsAnalysisWorkflow.SevCritical);
        Assert.Single(r.Result.SuspiciousProcesses);
    }

    [Fact]
    public async Task FlagsSuspiciousParentForOfficeSpawningShell()
    {
        var r = await workflow.ValidateProcessTreeAsync(
        [
            new ProcessNode { Name = "powershell.exe", ParentName = "winword.exe" },
        ]);

        var check = Assert.Single(r.Result!.Processes);
        Assert.True(check.InExpectationsDb);
        Assert.Contains(check.Findings, f => f.Type == WindowsAnalysisWorkflow.FindingSuspiciousParent);
    }

    [Fact]
    public async Task FlagsUnexpectedParentPathAndUserButNotTheCleanProcess()
    {
        var r = await workflow.ValidateProcessTreeAsync(
        [
            // Clean: svchost under services.exe, canonical path, SYSTEM (svchost's user_type is EITHER).
            new ProcessNode { Name = "svchost.exe", ParentName = "services.exe",
                              Path = @"C:\Windows\System32\svchost.exe", User = @"NT AUTHORITY\SYSTEM" },
            // Wrong parent (whitelist is services.exe only) + wrong path.
            new ProcessNode { Name = "svchost.exe", ParentName = "explorer.exe", Path = @"C:\Temp\svchost.exe" },
            // lsass is user_type SYSTEM — a non-SYSTEM account is an unexpected-user lead (parent/path are clean).
            new ProcessNode { Name = "lsass.exe", ParentName = "wininit.exe",
                              Path = @"C:\Windows\System32\lsass.exe", User = "Alice" },
        ]);

        var clean = r.Result!.Processes[0];
        Assert.True(clean.InExpectationsDb);
        Assert.Empty(clean.Findings);

        var bad = r.Result.Processes[1];
        Assert.Contains(bad.Findings, f => f.Type == WindowsAnalysisWorkflow.FindingUnexpectedParent);
        Assert.Contains(bad.Findings, f => f.Type == WindowsAnalysisWorkflow.FindingUnexpectedPath);

        var lsass = r.Result.Processes[2];
        Assert.Contains(lsass.Findings, f => f.Type == WindowsAnalysisWorkflow.FindingUnexpectedUser
                                          && f.Severity == WindowsAnalysisWorkflow.SevMedium);
    }

    [Fact]
    public async Task NormalizesEnvVarPathSoUnexpandedPlaceholderMatches()
    {
        var r = await workflow.ValidateProcessTreeAsync(
        [
            new ProcessNode { Name = "svchost.exe", ParentName = "services.exe", Path = @"%SystemRoot%\System32\svchost.exe" },
        ]);

        Assert.Empty(Assert.Single(r.Result!.Processes).Findings);   // %SystemRoot% -> \windows matches the rule
    }

    [Fact]
    public async Task UnknownProcessIsReportedButNotValidated()
    {
        var r = await workflow.ValidateProcessTreeAsync(
        [
            new ProcessNode { Name = "totally_custom_app.exe", ParentName = "explorer.exe" },
        ]);

        var check = Assert.Single(r.Result!.Processes);
        Assert.False(check.InExpectationsDb);
        Assert.Empty(check.Findings);
    }

    [Fact]
    public async Task InstanceCountsFlagTooManyOnlyWhenRequested()
    {
        ProcessNode[] two =
        [
            new ProcessNode { Name = "lsass.exe", ParentName = "wininit.exe", Pid = 700 },
            new ProcessNode { Name = "lsass.exe", ParentName = "wininit.exe", Pid = 701 },   // a 2nd lsass (max is 1)
        ];

        var off = await workflow.ValidateProcessTreeAsync(two);                       // default: no cardinality check
        Assert.Empty(off.Result!.InstanceFindings);

        var on = await workflow.ValidateProcessTreeAsync(two, checkInstanceCounts: true);
        Assert.Contains(on.Result!.InstanceFindings, f => f.Type == WindowsAnalysisWorkflow.FindingTooMany);
    }

    [Fact]
    public async Task ResolvesParentNamesFromPsListOverload()
    {
        WindowsPsList[] psList =
        [
            new WindowsPsList { PID = 700, PPID = 600, ImageFileName = "lsass.exe" },
            new WindowsPsList { PID = 600, PPID = 588, ImageFileName = "wininit.exe" },
            new WindowsPsList { PID = 4321, PPID = 700, ImageFileName = "cmd.exe" },   // child of lsass -> injection
        ];

        var r = await workflow.ValidateProcessTreeAsync(psList);

        var cmd = Assert.Single(r.Result!.Processes, c => c.Name == "cmd.exe");
        Assert.Equal("lsass.exe", cmd.ParentName);                                    // resolved by PPID
        Assert.Contains(cmd.Findings, f => f.Type == WindowsAnalysisWorkflow.FindingInjection);
    }
}
