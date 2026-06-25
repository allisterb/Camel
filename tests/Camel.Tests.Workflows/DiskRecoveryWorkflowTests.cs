using System;
using System.Linq;
using System.Text;

using Camel.Environments;
using Camel.Workflows;
using Camel.DFIR.Workflows;

namespace Camel.Tests.Workflows;

/// <summary>Builds a small ext4 image with deleted files + forensic features, shared across the recovery workflow tests.</summary>
public class RecoveryImageFixture : TestsRuntime, IDisposable
{
    public string ImagePath { get; }
    public AuditEnvironment Env { get; }

    public RecoveryImageFixture()
    {
        var cfg = LoadConfigFile("sshtestappsettings.json");
        Env = AuditEnvironment.CreateFromConfig(cfg);
        var id = Guid.NewGuid().ToString("N");
        ImagePath = $"/tmp/camel_recov_{id}.img";
        var mnt = $"/tmp/camel_rm_{id}";
        var script = $$"""
            set -e
            F={{ImagePath}}; M={{mnt}}
            JPG=$(find /usr/share -name '*.jpg' -size +5k 2>/dev/null | head -1)
            PNG=$(find /usr/share -name '*.png' -size +5k 2>/dev/null | head -1)
            sudo rm -f "$F"; rm -rf "$M"
            dd if=/dev/zero of="$F" bs=1M count=20 status=none; mkfs.ext4 -q -F "$F"
            mkdir -p "$M"; sudo mount -o loop "$F" "$M"
            sudo cp "$JPG" "$M"/photo.jpg; sudo cp "$PNG" "$M"/icon.png
            yes 'contact bob@example.com http://evil.example.com/c2 card 4111111111111111' | head -50 | sudo tee "$M"/notes.txt >/dev/null
            sudo sync; sudo rm -f "$M"/photo.jpg "$M"/icon.png "$M"/notes.txt; sudo sync
            sudo umount "$M"; sudo chown $(id -un) "$F"; rm -rf "$M"
            """;
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(script.Replace("\r\n", "\n")));
        Env.ExecuteCommand("bash", $"-c \"echo {b64} | base64 -d | bash\"", out _, false);
    }

    public void Dispose() => Env.ExecuteCommand("rm", $"-f {ImagePath}", out _, false);
}

public class DiskRecoveryWorkflowTests : TestsRuntime, IClassFixture<RecoveryImageFixture>
{
    public DiskRecoveryWorkflowTests(RecoveryImageFixture fx)
    {
        var cfg = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(cfg);
        api = new CamelToolkitsApi(sshenv, cfg);
        workflow = new DiskAnalysisWorkflow(api);
        this.fx = fx;
    }

    [Fact]
    public async Task CarvesUnallocatedSpace()
    {
        var dir = $"/tmp/camel_cu_{Guid.NewGuid():N}";
        try
        {
            var r = await workflow.CarveUnallocatedSpaceAsync(fx.ImagePath, dir);
            Assert.True(r.IsSuccess, r.Message);
            Assert.NotEmpty(r.Result!.CarvedFiles);
            Assert.Contains(r.Result.ByType, t => t.Name is "jpg" or "png");
        }
        finally { sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false); }
    }

    [Fact]
    public async Task ExtractsForensicFeatures()
    {
        var dir = $"/tmp/camel_ff_{Guid.NewGuid():N}";
        try
        {
            var r = await workflow.ExtractForensicFeaturesAsync(fx.ImagePath, dir);
            Assert.True(r.IsSuccess, r.Message);
            var email = r.Result!.Features.FirstOrDefault(f => f.Category == "email");
            Assert.NotNull(email);
            Assert.True(email!.Count > 0);
            Assert.Contains(email.TopValues, v => v.Contains("bob@example.com"));
        }
        finally { sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false); }
    }

    [Fact]
    public async Task ListsDeletedFiles()
    {
        var r = await workflow.ListDeletedFilesAsync(fx.ImagePath);
        Assert.True(r.IsSuccess, r.Message);
        // The three deleted files surface as orphaned inodes on ext4.
        Assert.True(r.Result!.Count >= 1);
        Assert.All(r.Result.DeletedFiles, d => Assert.False(string.IsNullOrWhiteSpace(d.Inode)));
    }

    AuditEnvironment sshenv;
    CamelToolkitsApi api;
    DiskAnalysisWorkflow workflow;
    RecoveryImageFixture fx;
}
