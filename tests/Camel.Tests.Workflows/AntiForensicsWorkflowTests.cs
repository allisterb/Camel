using System;
using System.Linq;
using System.Threading.Tasks;

using Camel.Environments;
using Camel.Workflows;
using Camel.DFIR.Workflows;

namespace Camel.Tests.Workflows;

public class AntiForensicsWorkflowTests : TestsRuntime
{
    public AntiForensicsWorkflowTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelToolkitsApi(sshenv, sshconfig);
        workflow = new AntiForensicsAnalysisWorkflow(api);
        EvidenceMounts.EnsureAll(sshenv);   // self-heal the /mnt/dlpc evidence mount on a reset SIFT VM
    }

    [Fact]
    public async Task CanDetectTimestompingInMft()
    {
        const string mft = "/tmp/camel_af_mft";
        // The head of the volume's $MFT (a full parse is slow; 16 MB is plenty of records for a smoke test). The
        // path is single-quoted so the shell doesn't treat $MFT as a variable.
        sshenv.ExecuteCommand("head", $"-c 16000000 '{VolumeRoot}/$MFT' > {mft}", out _, false);
        try
        {
            var r = await workflow.DetectTimestompingAsync(mft);

            Assert.True(r.IsSuccess, r.Message);
            Assert.NotNull(r.Result);
            Assert.Equal(mft, r.Result.MftFile);
            Assert.True(r.Result.EntriesScanned > 0, "no MFT entries parsed");
            // Whatever is flagged carries a path and at least one indicator (this image may be clean → zero findings).
            Assert.All(r.Result.Findings, f =>
            {
                Assert.False(string.IsNullOrEmpty(f.Path));
                Assert.True(f.SiBeforeFn || f.ZeroSubseconds);
            });
        }
        finally { sshenv.ExecuteCommand("rm", $"-f {mft}", out _, false); }
    }

    // Validated 2026-06-12 against the real SRL $J (~13s): 384,493 USN records → 109 pivots (0.03%); top = mass
    // file-activity bursts (file:png ×13241/60s, file:dll, file:json) via TimingBurst. The $UsnJrnl:$J stream is
    // only exposed when the volume is mounted with streams_interface=windows — DiskAnalysisToolkit.EwfMountLoopbackAsync
    // now passes that option (it had a typo: "streams_interace"). [Skip] (depends on such a mount at /mnt/srl_str).
    // NB MFTECmdUsnAsync cats the CSV to a string (64MB here = fine); a much larger $J would want the reduced/SCP path.
    [Fact(Skip = "one-off: needs a streams_interface=windows mount exposing $UsnJrnl:$J (see EwfMountLoopbackAsync); run manually")]
    public async Task CanAnalyzeUsnJournal()
    {
        var r = await workflow.AnalyzeUsnJournalAsync("/mnt/srl_str/$Extend/$UsnJrnl:$J");
        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.RecordsScanned > 0);
        System.IO.File.WriteAllText(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "camel_af_usn_srl.txt"),
            $"{r.Message}\n" + string.Join("\n", r.Result.Pivots.Take(20).Select(p => $"  [{p.Bits,7:F1}] {p.Time:u} {p.EventType} ×{p.EventCount} — {string.Join("; ", p.Reasons)}")));
    }

    // CFREDS Data Leakage PC image, mounted read-only at /mnt/dlpc (a full Windows volume).
    const string VolumeRoot = "/mnt/dlpc";

    AuditEnvironment sshenv;
    CamelToolkitsApi api;
    AntiForensicsAnalysisWorkflow workflow;
}
