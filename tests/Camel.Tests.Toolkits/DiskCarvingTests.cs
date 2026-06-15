using System;
using System.Linq;
using System.Text;

using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

/// <summary>
/// Builds a small ext4 image on the SIFT workstation with a deleted JPEG, PNG and a feature-rich text file (an
/// email/URL/credit-card), shared across the carving tests. Bounds runtime by using a 20 MB image.
/// </summary>
public class CarveImageFixture : TestsRuntime, IDisposable
{
    public string ImagePath { get; }
    public AuditEnvironment Env { get; }

    public CarveImageFixture()
    {
        var cfg = LoadConfigFile("sshtestappsettings.json");
        Env = AuditEnvironment.CreateFromConfig(cfg);
        var id = Guid.NewGuid().ToString("N");
        ImagePath = $"/tmp/camel_carve_{id}.img";
        var mnt = $"/tmp/camel_cm_{id}";
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

public class DiskCarvingTests : TestsRuntime, IClassFixture<CarveImageFixture>
{
    public DiskCarvingTests(CarveImageFixture fx)
    {
        var cfg = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(cfg);
        toolkit = new DiskAnalysisToolkit(sshenv, cfg);
        this.fx = fx;
    }

    [Fact]
    public async Task CanExtractUnallocatedWithBlkls()
    {
        var outFile = $"/tmp/camel_unalloc_{Guid.NewGuid():N}.blk";
        try
        {
            var bytes = await toolkit.BlklsAsync(fx.ImagePath, outFile);
            Assert.NotNull(bytes);
            Assert.True(bytes > 0);
        }
        finally { sshenv.ExecuteCommand("rm", $"-f {outFile}", out _, false); }
    }

    [Fact]
    public async Task CanCarveWithForemost()
    {
        var dir = $"/tmp/camel_fm_{Guid.NewGuid():N}";
        try
        {
            var carved = await toolkit.ForemostAsync(fx.ImagePath, dir, "jpeg,png");
            Assert.NotNull(carved);
            Assert.Contains(carved, c => c.Type == "jpg" && c.Size > 0);
            Assert.Contains(carved, c => c.Type == "png");
        }
        finally { sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false); }
    }

    [Fact]
    public async Task CanExtractFeaturesWithBulkExtractor()
    {
        var dir = $"/tmp/camel_be_{Guid.NewGuid():N}";
        try
        {
            var feats = await toolkit.BulkExtractorAsync(fx.ImagePath, dir);
            Assert.NotNull(feats);
            var email = feats.FirstOrDefault(f => f.Category == "email");
            Assert.NotNull(email);
            Assert.True(email!.Count > 0);
            Assert.Contains(email.TopValues, v => v.Contains("bob@example.com"));
        }
        finally { sshenv.ExecuteCommand("rm", $"-rf {dir}", out _, false); }
    }

    AuditEnvironment sshenv;
    DiskAnalysisToolkit toolkit;
    CarveImageFixture fx;
}
