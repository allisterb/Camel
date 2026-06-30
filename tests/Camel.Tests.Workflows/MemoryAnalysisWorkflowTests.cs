using System.Linq;

using Camel.Environments;
using Camel.Workflows;
using Camel.DFIR.Workflows;

namespace Camel.Tests.Workflows;

public class MemoryAnalysisWorkflowTests : TestsRuntime
{
    public MemoryAnalysisWorkflowTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelToolkitsApi(sshenv, sshconfig);
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
        var pslist = (await api.MemoryAnalysis.WindowsPsListAsync(Image)).Value;
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

    [Fact]
    public async Task CanExtractCredentialMaterial()
    {
        var r = await workflow.ExtractCredentialMaterialAsync(Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.LocalHashes);
        Assert.Contains(r.Result.LocalHashes, h => h.Rid == 500);             // built-in Administrator
        Assert.All(r.Result.LocalHashes, h => Assert.NotEmpty(h.User));
        Assert.NotEmpty(r.Result.LsaSecrets);
        // At least one LSA secret decodes to printable plaintext (this image has UTF-16 plaintext secrets).
        Assert.NotEmpty(r.Result.PlaintextSecrets);
    }

    [Fact]
    public async Task ExtractCredentialMaterialRunsOnWin10Image()
    {
        // vol3's credential plugins run cleanly on this Win10 image but recover nothing (Win10 SAM encryption,
        // no cached/LSA creds here), so the workflow must succeed gracefully with a well-formed empty report
        // rather than fail — distinguishing "ran, found nothing" from "could not run".
        var r = await workflow.ExtractCredentialMaterialAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotNull(r.Result.LocalHashes);
        Assert.NotNull(r.Result.LsaSecrets);
        Assert.NotNull(r.Result.CachedCredentials);
    }

    [Fact]
    public async Task ExtractCredentialMaterialFailsForMissingImage()
    {
        var r = await workflow.ExtractCredentialMaterialAsync("/mnt/artifacts/does_not_exist.raw");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task CanFindCodeInjection()
    {
        // Win10 image: clean baseline. The workflow should run all three sources end-to-end (ldrmodules,
        // hollowprocesses, malfind) and produce a well-formed report. Clean image => no hollowed processes;
        // ldrmodules legitimately surfaces orphan entries (mui/locale resources). The SuspectPids aggregation
        // must be internally consistent.
        var r = await workflow.FindCodeInjectionAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotNull(r.Result.UnlinkedDlls);
        Assert.NotNull(r.Result.HollowedProcesses);
        Assert.NotNull(r.Result.AnomalousRegions);
        Assert.All(r.Result.SuspectPids, p => Assert.True(p.SignalCount > 0));
        // Every suspect PID must be sourced from at least one of the three signals.
        var sources = r.Result.UnlinkedDlls.Select(u => u.PID)
            .Concat(r.Result.HollowedProcesses.Select(h => h.PID))
            .Concat(r.Result.AnomalousRegions.SuspectRegions.Select(rg => rg.PID))
            .ToHashSet();
        Assert.All(r.Result.SuspectPids, p => Assert.Contains(p.Pid, sources));
    }

    [Fact]
    public async Task FindCodeInjectionFailsForMissingImage()
    {
        var r = await workflow.FindCodeInjectionAsync("/mnt/artifacts/does_not_exist.raw");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task CanDetectKernelRootkit()
    {
        // Win10 image: clean baseline. All three hook surfaces must enumerate (the scanned counts go up);
        // foreign-module hooks may exist legitimately (Windows Defender's WdFilter installs callbacks), so we
        // assert structure rather than zero hooks, and that every reported hook is genuinely non-canonical.
        var r = await workflow.DetectKernelRootkitAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.SsdtScanned > 0);
        Assert.True(r.Result.CallbacksScanned > 0);
        Assert.True(r.Result.DriverIrpScanned > 0);
        string[] canonical = ["ntoskrnl", "win32k", "hal"];
        Assert.All(r.Result.Hooks, h =>
            Assert.DoesNotContain(canonical, c => string.Equals(c, h.Module, StringComparison.OrdinalIgnoreCase)));
        Assert.All(r.Result.Hooks, h => Assert.Contains(h.HookSurface, new[] { "SSDT", "Callback", "IRP" }));
    }

    [Fact]
    public async Task CanCrossViewHiddenProcess()
    {
        // psxview enumerates every process across four sources. The hidden set is a subset; structurally,
        // every "hidden" sighting must actually be missing from psscan, OR (still running AND missing from
        // pslist). All sightings must carry a PID and a non-empty name.
        var r = await workflow.CrossViewHiddenProcessAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.AllSightings);
        Assert.All(r.Result.AllSightings, s => Assert.NotEmpty(s.Name));
        Assert.All(r.Result.HiddenSightings, s =>
            Assert.True(!s.PsScan || (!s.HasExited && !s.PsList)));
    }

    [Fact]
    public async Task CanReconstructConsoleHistory()
    {
        // The plugins return empty on most images (no live console host at capture). The workflow must still
        // succeed gracefully — empty session list and empty typed-command list, both non-null.
        var r = await workflow.ReconstructConsoleHistoryAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotNull(r.Result.ConsoleSessions);
        Assert.NotNull(r.Result.TypedCommands);
        // Every typed command must trace back to a real session.
        var sessionPids = r.Result.ConsoleSessions.Select(s => s.Pid).ToHashSet();
        Assert.All(r.Result.TypedCommands, c => Assert.Contains(c.Pid, sessionPids));
    }

    [Fact]
    public async Task CanDetectSkeletonKey()
    {
        // Non-DC image: skeleton_key_check should find nothing. The workflow must succeed with IsCompromised
        // false and an empty findings list.
        var r = await workflow.DetectSkeletonKeyAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.False(r.Result.IsCompromised);
        Assert.Empty(r.Result.Findings);
    }

    [Fact]
    public async Task CanScanMemoryWithYara()
    {
        // Bring our own minimal rules file (one rule matching a common Windows-API string), upload it to the
        // workstation, then scan. The workflow must run vadyarascan, parse the matches, and pivot per-rule.
        const string rulesPath = "/tmp/camel_yara_test.yar";
        const string rule = "rule kernel32_marker { strings: $a = \"kernel32.dll\" condition: $a }";
        // Bypass nested-quote hell by base64-piping the rule body to the SIFT box.
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(rule));
        await sshenv.ExecuteCommandAsync("bash", $"-c \"echo {b64} | base64 -d > {rulesPath}\"", false);

        var r = await workflow.ScanMemoryWithYaraAsync(Win10Image, rulesPath);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Equal(rulesPath, r.Result.RulesFile);
        // kernel32.dll string is ubiquitous in a Windows memory image, so we expect at least one match.
        Assert.NotEmpty(r.Result.Matches);
        // vol3 namespaces rule names ("default.kernel32_marker"); just assert the rule body is the source.
        Assert.All(r.Result.Matches, m => Assert.EndsWith("kernel32_marker", m.Rule));
        Assert.NotEmpty(r.Result.MatchesByRule);
    }

    [Fact]
    public async Task CanFindMalwareEndToEnd()
    {
        // The full six-step methodology against the clean Win10 baseline. This orchestrates psxview + netscan +
        // ldrmodules + hollowprocesses + malfind + ssdt + callbacks + driverirp + cmdline + getsids, so it runs
        // long. We assert the orchestration is structurally sound rather than expecting specific positives:
        //  - all four sub-reports populated;
        //  - every suspect carries at least one signal and is sourced from a real methodology category;
        //  - high-confidence = ≥2 categories, and that subset is consistent;
        //  - no dump/YARA requested, so those stay empty/null.
        var r = await workflow.FindMalwareAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotNull(r.Result.RogueProcesses);
        Assert.NotNull(r.Result.ProcessTriage);
        Assert.NotNull(r.Result.NetworkArtifacts);
        Assert.NotNull(r.Result.CodeInjection);
        Assert.NotNull(r.Result.KernelRootkit);

        string[] validCategories = ["rogue-process", "process-anomaly", "code-injection", "network", "yara-detection"];
        Assert.All(r.Result.Suspects, s =>
        {
            Assert.NotEmpty(s.Signals);
            Assert.Equal(s.Signals.Length, s.SignalCount);
            Assert.NotEmpty(s.Categories);
            Assert.All(s.Categories, c => Assert.Contains(c, validCategories));
            Assert.Equal(s.Categories.Length >= 2, s.IsHighConfidence);
        });

        // Suspects are ranked: category count is non-increasing down the list.
        for (int i = 1; i < r.Result.Suspects.Length; i++)
            Assert.True(r.Result.Suspects[i - 1].Categories.Length >= r.Result.Suspects[i].Categories.Length);

        // The high-confidence subset is exactly the ≥2-category suspects.
        Assert.Equal(r.Result.Suspects.Count(s => s.IsHighConfidence), r.Result.HighConfidenceSuspects.Length);
        Assert.All(r.Result.HighConfidenceSuspects, s => Assert.True(s.Categories.Length >= 2));

        // A network signal only ever appears alongside another category (network never nominates alone).
        Assert.All(r.Result.Suspects, s =>
        {
            if (s.Categories.Contains("network"))
                Assert.True(s.Categories.Length >= 2, $"PID {s.Pid} flagged by network only");
        });

        // Wiring: every process-triage finding is folded in as a suspect carrying the process-anomaly category.
        var anomalyPids = r.Result.Suspects.Where(s => s.Categories.Contains("process-anomaly")).Select(s => s.Pid).ToHashSet();
        Assert.All(r.Result.ProcessTriage.FlaggedProcesses, p => Assert.Contains(p.Pid, anomalyPids));

        // No Step-6 work requested.
        Assert.Empty(r.Result.DumpedArtifacts);
        Assert.Empty(r.Result.DumpYaraMatches);
        Assert.Null(r.Result.YaraScan);
    }

    [Fact]
    public async Task FindMalwareScansDumpedExecutablesWithClassicYara()
    {
        // Step 6 with dumping: extracts suspect executables and always scans them with the bundled malware pack
        // via the classic yara file scanner (vol3's YARA-X can't load that pack). On the clean image we expect
        // no malware hits, but the path must run end-to-end and the wiring invariants must hold.
        var dumpDir = $"/tmp/camel_fm_dump_{System.Guid.NewGuid():N}";
        try
        {
            var r = await workflow.FindMalwareAsync(Win10Image, dumpDir: dumpDir);

            Assert.True(r.IsSuccess, r.Message);
            Assert.NotNull(r.Result);
            Assert.NotNull(r.Result.DumpYaraMatches);

            // Every classic-YARA hit targets one of the dumped files, and traces to a suspect carrying the
            // yara-detection category.
            var dumpedNames = r.Result.DumpedArtifacts.Select(System.IO.Path.GetFileName).ToHashSet();
            Assert.All(r.Result.DumpYaraMatches, m =>
                Assert.Contains(System.IO.Path.GetFileName(m.Target), dumpedNames));
            Assert.All(r.Result.Suspects.Where(s => s.YaraMatches.Length > 0), s =>
            {
                Assert.Contains("yara-detection", s.Categories);
                Assert.All(s.YaraMatches, m => Assert.Contains(m, r.Result.DumpYaraMatches));
            });
            // Conversely, any suspect tagged yara-detection actually carries matches.
            Assert.All(r.Result.Suspects.Where(s => s.Categories.Contains("yara-detection")),
                s => Assert.NotEmpty(s.YaraMatches));
        }
        finally
        {
            sshenv.ExecuteCommand("rm", $"-rf {dumpDir}", out _, false);
        }
    }

    [Fact]
    public async Task CanTriageProcessAncestry()
    {
        // Clean Win10 baseline: the whole tree parses and every flagged process is structurally well-formed.
        // A correct ruleset produces zero false positives here (the canonical system processes all pass), which
        // is the key low-FP property — the boot-time PID-reuse trap (csrss/winlogon PPID recycled by a later
        // svchost) must NOT flag.
        var r = await workflow.TriageProcessAncestryAsync(Win10Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.TotalProcesses > 0);

        string[] validCategories = ["system-process-integrity", "ancestry-anomaly"];
        Assert.All(r.Result.FlaggedProcesses, p =>
        {
            Assert.NotEmpty(p.Reasons);
            Assert.NotEmpty(p.Categories);
            Assert.All(p.Categories, c => Assert.Contains(c, validCategories));
        });
        // Category views partition the flagged set by their tag.
        Assert.All(r.Result.IntegrityFailures, p => Assert.Contains("system-process-integrity", p.Categories));
        Assert.All(r.Result.AncestryAnomalies, p => Assert.Contains("ancestry-anomaly", p.Categories));

        // The canonical system processes on a clean image must not be flagged for integrity — this is the
        // PID-reuse-trap regression guard.
        Assert.DoesNotContain(r.Result.IntegrityFailures, p =>
            p.Name.Equals("csrss.exe", StringComparison.OrdinalIgnoreCase) ||
            p.Name.Equals("winlogon.exe", StringComparison.OrdinalIgnoreCase) ||
            p.Name.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase) ||
            p.Name.Equals("services.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task TriageProcessAncestryRunsOnXp()
    {
        // Windows XP (5.1) regression: it has no wininit.exe — services.exe/lsass.exe are children of
        // winlogon.exe. The parentage rules accept both wininit and winlogon, so these must NOT be flagged as
        // integrity failures (the pre-Vista false-positive guard).
        var r = await workflow.TriageProcessAncestryAsync(Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.TotalProcesses > 0);
        Assert.DoesNotContain(r.Result.IntegrityFailures, p =>
            p.Name.Equals("services.exe", StringComparison.OrdinalIgnoreCase) ||
            p.Name.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task FindMalwareDegradesGracefullyOnXp()
    {
        // Windows XP (5.1): vol3's windows.netscan is unimplemented for this OS. Because network is
        // corroboration-only, FindMalware must still SUCCEED — degrading to empty network artifacts rather than
        // aborting — and the rest of the six-step analysis runs (all other XP plugins are supported).
        var r = await workflow.FindMalwareAsync(Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Empty(r.Result.NetworkArtifacts.RemoteIPs);
        // No suspect can carry a network category when netscan was unavailable.
        Assert.DoesNotContain(r.Result.Suspects, s => s.Categories.Contains("network"));
    }

    [Fact]
    public void ProcessTriageDetectionLogicIsCorrect()
    {
        // Deterministic, offline validation of the novel detection primitives — the real malware-positive
        // coverage the clean image cannot provide (no infected memory fixture parses under vol3 here).

        // Damerau-Levenshtein: substitution and adjacent transposition each count as one edit.
        Assert.Equal(0, MemoryAnalysisWorkflow.DamerauLevenshtein("svchost", "svchost"));
        Assert.Equal(1, MemoryAnalysisWorkflow.DamerauLevenshtein("svchost", "svch0st")); // o -> 0 (substitution)
        Assert.Equal(1, MemoryAnalysisWorkflow.DamerauLevenshtein("svchost", "scvhost")); // v<->c (transposition)
        Assert.True(MemoryAnalysisWorkflow.DamerauLevenshtein("svchost", "explorer") > 2);

        // Masquerade detection: one edit from a system name flags; the exact name and unrelated names do not.
        Assert.Equal("svchost", MemoryAnalysisWorkflow.NearestSystemProcessName("scvhost"));
        Assert.Equal("svchost", MemoryAnalysisWorkflow.NearestSystemProcessName("svch0st"));
        Assert.Equal("lsass", MemoryAnalysisWorkflow.NearestSystemProcessName("lsasss"));
        Assert.Null(MemoryAnalysisWorkflow.NearestSystemProcessName("svchost"));  // it IS the real one
        Assert.Null(MemoryAnalysisWorkflow.NearestSystemProcessName("chrome"));   // unrelated
        Assert.Null(MemoryAnalysisWorkflow.NearestSystemProcessName("lsm"));      // too short to compare

        // Path-location check (case- and slash-insensitive; matches dir immediately before the exe).
        Assert.True(MemoryAnalysisWorkflow.PathInExpectedDir(
            @"\Device\HarddiskVolume3\Windows\System32\svchost.exe", "svchost", ["system32", "syswow64"]));
        Assert.False(MemoryAnalysisWorkflow.PathInExpectedDir(
            @"\Device\HarddiskVolume3\Users\evil\AppData\Local\Temp\svchost.exe", "svchost", ["system32", "syswow64"]));

        Assert.Equal("svchost", MemoryAnalysisWorkflow.ProcBaseName("SvcHost.exe"));
    }

    [Fact]
    public async Task TriageProcessAncestryFailsForMissingImage()
    {
        var r = await workflow.TriageProcessAncestryAsync("/mnt/artifacts/does_not_exist.raw");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task FindMalwareFailsForMissingImage()
    {
        var r = await workflow.FindMalwareAsync("/mnt/artifacts/does_not_exist.raw");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task FindMalwareLegacyModeReducesCrossViewNoiseOnServer2008()
    {
        // Server 2008 (the Ali Hadi web-server case image): psxview's pslist/csrss cross-view is unreliable on
        // pre-Win10 builds and flags nearly every process as "missed by pslist/csrss", inflating the
        // rogue-process nominations. Legacy mode demotes those pslist/csrss-only discrepancies to
        // corroboration-only (only a genuine psscan miss still nominates), so it must yield no MORE suspects —
        // and in particular no more rogue-process-only suspects — than the default, while both still succeed.
        var normal = await workflow.FindMalwareAsync(Server2008Image);
        var legacy = await workflow.FindMalwareAsync(Server2008Image, legacyMode: true);

        Assert.True(normal.IsSuccess, normal.Message);
        Assert.True(legacy.IsSuccess, legacy.Message);

        // Demoting the noisy cross-view discrepancies can only shrink the suspect set.
        Assert.True(legacy.Result!.Suspects.Length <= normal.Result!.Suspects.Length,
            $"legacy {legacy.Result.Suspects.Length} > normal {normal.Result.Suspects.Length}");

        // The pure-rogue (psxview-only) suspects are exactly what legacy mode suppresses.
        static int OnlyRogue(Camel.Workflows.Models.FindMalwareReport r) =>
            r.Suspects.Count(s => s.Categories is ["rogue-process"]);
        Assert.True(OnlyRogue(legacy.Result!) <= OnlyRogue(normal.Result!));

        // Every rogue-process suspect that survives legacy mode either is a genuine psscan miss or is corroborated
        // by another category — none is a pslist/csrss-only nomination standing alone is acceptable (psscan miss),
        // so we assert the count is bounded, not zero.
        Assert.True(legacy.Result!.HighConfidenceSuspects.Length <= normal.Result!.HighConfidenceSuspects.Length);
    }

    const string Image = "/mnt/artifacts/pat-2009-11-19.mddramimage";
    const string Win10Image = "/mnt/artifacts/Rocba-Memory.raw";
    const string Server2008Image = "/mnt/artifacts/memdump.mem";

    AuditEnvironment sshenv;
    CamelToolkitsApi api;
    MemoryAnalysisWorkflow workflow;
}
