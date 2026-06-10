using System;
using System.Text;

using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

public class DiskAnalysisTests : TestsRuntime
{
    public DiskAnalysisTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new DiskAnalysisToolkit(sshenv, sshconfig);
    }

    [Fact]
    public void CanLoadAllToolsFromConfig()
    {
        // Constructing the toolkit loads every ToolList entry from config; verify all resolved.
        Assert.Equal(toolkit.ToolList.Length, toolkit.Tools.Count);
        Assert.All(toolkit.ToolList, name =>
        {
            Assert.True(toolkit.Tools.ContainsKey(name));
            Assert.Contains("bin/", toolkit.Tools[name].Command);
            Assert.NotEmpty(toolkit.Tools[name].Descriptioon);
        });
    }

    [Fact]
    public async Task CanRunEwfInfo()
    {
        var r = await toolkit.EwfInfoAsync(Image);
        Assert.NotNull(r);
        Assert.Equal("aee4fcd9301c03b3b054623ca261959a", r.MD5);
        Assert.Equal("Greg Schardt", r.CaseNumber);
        Assert.Equal(512, r.BytesPerSector);
        Assert.Equal(9514260, r.NumberOfSectors);
    }

    [Fact]
    public async Task CanRunEwfVerify()
    {
        var r = await toolkit.EwfVerifyAsync(Image);
        Assert.NotNull(r);
        Assert.True(r.Success);
        Assert.Equal(r.StoredMD5, r.CalculatedMD5);
        Assert.Equal("aee4fcd9301c03b3b054623ca261959a", r.CalculatedMD5);
    }

    [Fact]
    public async Task CanRunImgStat()
    {
        var r = await toolkit.ImgStatAsync(Image);
        Assert.NotNull(r);
        Assert.Equal("ewf", r.ImageType);
        Assert.Equal(4871301120, r.SizeOfData);
        Assert.Equal(512, r.SectorSize);
    }

    [Fact]
    public async Task CanRunMmls()
    {
        var r = await toolkit.MmlsAsync(Image);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        var ntfs = Assert.Single(r, e => e.Description.Contains("NTFS"));
        Assert.Equal(63, ntfs.Start);
    }

    [Fact]
    public async Task CanRunFsStat()
    {
        var r = await toolkit.FsStatAsync(Image, NtfsOffset);
        Assert.NotNull(r);
        Assert.Equal("NTFS", r.FileSystemType);
        Assert.Equal(5, r.RootDirectory);
        Assert.Equal(512, r.SectorSize);
    }

    [Fact]
    public async Task CanRunFls()
    {
        var r = await toolkit.FlsAsync(Image, NtfsOffset);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.Name == "boot.ini");
        Assert.Contains(r, e => e.Deleted); // image has deleted entries at root
    }

    [Fact]
    public async Task CanRunIstat()
    {
        var r = await toolkit.IstatAsync(Image, 3664, NtfsOffset); // boot.ini
        Assert.NotNull(r);
        Assert.Equal(3664, r.Entry);
        Assert.True(r.Allocated);
        Assert.NotNull(r.Created);
    }

    [Fact]
    public async Task CanRunFfind()
    {
        var r = await toolkit.FfindAsync(Image, 3664, NtfsOffset);
        Assert.NotNull(r);
        Assert.Contains("boot.ini", r);
    }

    [Fact]
    public async Task CanRunIls()
    {
        var r = await toolkit.IlsAsync(Image, NtfsOffset);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, e => Assert.True(e.StIno >= 0));
    }

    [Fact]
    public async Task CanRunEwfMountRaw()
    {
        const string mountDir = "/tmp/camel_ewf";
        sshenv.ExecuteCommand("umount", mountDir, out _, true); // ensure not already mounted
        sshenv.ExecuteCommand("mkdir", $"-p {mountDir}", out _, false);

        var ok = await toolkit.EwfMountRawAsync(Image, mountDir);
        Assert.True(ok);

        // The raw device ewf1 should be exposed (FUSE mount is root-only, so check via sudo).
        sshenv.ExecuteCommand("ls", mountDir, out var contents, true);
        Assert.Contains("ewf1", contents);

        sshenv.ExecuteCommand("umount", mountDir, out _, true);
    }

    [Fact]
    public async Task CanRunDDMount()
    {
        EnsureDdImages();
        const string mnt = "/tmp/camel_ddmnt";
        sshenv.ExecuteCommand("umount", mnt, out _, true);
        sshenv.ExecuteCommand("mkdir", $"-p {mnt}", out _, false);

        Assert.True(await toolkit.DDMountAsync("/tmp/camel_whole.dd", mnt));
        sshenv.ExecuteCommand("ls", mnt, out var contents, true);
        Assert.Contains("lost+found", contents); // ext4 filesystem mounted

        sshenv.ExecuteCommand("umount", mnt, out _, true);
    }

    [Fact]
    public async Task CanRunDDMountWithOffset()
    {
        EnsureDdImages();
        const string mnt = "/tmp/camel_ddmnt_off";
        sshenv.ExecuteCommand("umount", mnt, out _, true);
        sshenv.ExecuteCommand("mkdir", $"-p {mnt}", out _, false);

        // The partition starts at sector 2048 (per ListPartitions / fdisk).
        Assert.True(await toolkit.DDMountAsync("/tmp/camel_part.dd", mnt, offset: 2048));
        sshenv.ExecuteCommand("ls", mnt, out var contents, true);
        Assert.Contains("lost+found", contents);

        sshenv.ExecuteCommand("umount", mnt, out _, true);
    }

    [Fact]
    public async Task CanRunMakeMountDir()
    {
        const string name = "camel_mp_test";
        sshenv.ExecuteCommand("rmdir", $"/mnt/{name}", out _, true); // clean up any prior run

        var path = await toolkit.MakeMountDirAsync(name);
        Assert.Equal($"/mnt/{name}", path);
        Assert.True(sshenv.ExecuteCommand("test", $"-d /mnt/{name}", out _, false)); // dir exists

        sshenv.ExecuteCommand("rmdir", $"/mnt/{name}", out _, true);
    }

    [Fact]
    public async Task CanRunListPartitions()
    {
        // ListPartitions reads a raw disk device; expose the E01 as ewf1 first.
        const string raw = "/tmp/camel_ewfraw_lp";
        sshenv.ExecuteCommand("umount", raw, out _, true);
        sshenv.ExecuteCommand("mkdir", $"-p {raw}", out _, false);
        Assert.True(await toolkit.EwfMountRawAsync(Image, raw));

        var parts = await toolkit.ListPartitionsAsync($"{raw}/ewf1");
        Assert.NotNull(parts);
        Assert.NotEmpty(parts);

        // The NTFS partition's Start sector is the offset used by the loopback/ntfs mount tests.
        var ntfs = Assert.Single(parts, p => p.Type.Contains("NTFS"));
        Assert.Equal(NtfsOffset, ntfs.Start);
        Assert.True(ntfs.Sectors > 0 && ntfs.End > ntfs.Start);

        sshenv.ExecuteCommand("umount", raw, out _, true);
    }

    [Fact]
    public async Task CanRunEwfMountLoopback()
    {
        const string raw = "/tmp/camel_ewfraw_lb";
        const string mnt = "/tmp/camel_ntfs_lb";
        sshenv.ExecuteCommand("umount", mnt, out _, true);
        sshenv.ExecuteCommand("umount", raw, out _, true);
        sshenv.ExecuteCommand("mkdir", $"-p {raw} {mnt}", out _, false);
        Assert.True(await toolkit.EwfMountRawAsync(Image, raw));

        var ok = await toolkit.EwfMountLoopbackAsync($"{raw}/ewf1", mnt, offset: NtfsOffset);
        Assert.True(ok);

        // The NTFS partition should now be mounted (check via sudo; mount is root-owned).
        sshenv.ExecuteCommand("ls", mnt, out var contents, true);
        Assert.Contains("WINDOWS", contents);

        sshenv.ExecuteCommand("umount", mnt, out _, true);
        sshenv.ExecuteCommand("umount", raw, out _, true);
    }

    [Fact]
    public async Task CanRunEwfMountNtfs()
    {
        const string raw = "/tmp/camel_ewfraw_ntfs";
        const string mnt = "/tmp/camel_ntfs_ntfs";
        sshenv.ExecuteCommand("umount", mnt, out _, true);
        sshenv.ExecuteCommand("umount", raw, out _, true);
        sshenv.ExecuteCommand("mkdir", $"-p {raw} {mnt}", out _, false);
        Assert.True(await toolkit.EwfMountRawAsync(Image, raw));

        var ok = await toolkit.EwfMountNtfsAsync($"{raw}/ewf1", mnt, offset: NtfsOffset);
        Assert.True(ok);

        sshenv.ExecuteCommand("ls", mnt, out var contents, true);
        Assert.Contains("WINDOWS", contents);

        sshenv.ExecuteCommand("umount", mnt, out _, true);
        sshenv.ExecuteCommand("umount", raw, out _, true);
    }

    [Fact]
    public async Task CanRunIcat()
    {
        const string outFile = "/tmp/camel_boot.ini";
        sshenv.ExecuteCommand("rm", $"-f {outFile}", out _, false);

        var ok = await toolkit.IcatAsync(Image, 3664, outFile, NtfsOffset); // boot.ini
        Assert.True(ok);

        // Confirm the extracted bytes landed in the output file.
        sshenv.ExecuteCommand("cat", outFile, out var content, false);
        Assert.Contains("boot loader", content);
    }

    [Fact]
    public async Task CanRunTskRecover()
    {
        const string outDir = "/tmp/camel_recover";
        sshenv.ExecuteCommand("rm", $"-rf {outDir}", out _, true);

        var n = await toolkit.TskRecoverAsync(Image, outDir, all: false, offset: NtfsOffset);
        Assert.NotNull(n);
        Assert.True(n > 0);

        // The recovered tree should be owned by the login user, not root.
        sshenv.ExecuteCommand("stat", $"-c %U {outDir}", out var owner, false);
        Assert.NotEqual("root", owner.Trim());
    }

    [Fact]
    public async Task CanRunTskRecoverDirInode()
    {
        const string outDir = "/tmp/camel_recover_dir";
        sshenv.ExecuteCommand("rm", $"-rf {outDir}", out _, true);

        // Recover only the WINDOWS directory subtree (inode 458).
        var n = await toolkit.TskRecoverAsync(Image, outDir, all: false, dirInode: 458, offset: NtfsOffset);
        Assert.NotNull(n);
        Assert.True(n > 0);
    }

    [Fact]
    public async Task CanRunMactime()
    {
        // mactime consumes a bodyfile; generate one on the workstation first (fls -m).
        const string bodyfile = "/tmp/camel_mactime_bf.txt";
        sshenv.ExecuteCommand("bash",
            $"-c \"fls -o {NtfsOffset} -m / '{Image}' 5 > {bodyfile}\"", out _, false);

        var r = await toolkit.MactimeAsync(bodyfile);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, e => Assert.NotEmpty(e.Date));
        Assert.Contains(r, e => e.FileName.Contains("boot.ini"));
    }

    // Creates two small ext4 .dd images on the workstation (idempotent): a whole-filesystem image and a
    // partitioned image with one partition at sector 2048. Delivered via base64 to avoid shell quoting.
    void EnsureDdImages()
    {
        const string script =
            "[ -f /tmp/camel_whole.dd ] || { dd if=/dev/zero of=/tmp/camel_whole.dd bs=1M count=16 status=none; mkfs.ext4 -q -F /tmp/camel_whole.dd; }\n" +
            "[ -f /tmp/camel_part.dd ] || { dd if=/dev/zero of=/tmp/camel_part.dd bs=1M count=32 status=none; printf 'label: dos\\nstart=2048, type=83\\n' | sfdisk /tmp/camel_part.dd >/dev/null 2>&1; L=$(losetup -fP --show /tmp/camel_part.dd); mkfs.ext4 -q -F ${L}p1; losetup -d $L; }\n";
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
        sshenv.ExecuteCommand("bash", $"-c \"echo {b64} | base64 -d > /tmp/camel_ddsetup.sh\"", out _, false);
        sshenv.ExecuteCommand("bash", "/tmp/camel_ddsetup.sh", out _, true); // sudo: sfdisk/losetup/mkfs
    }

    [Fact]
    public async Task CanFindFilesAndHash()
    {
        const string d = "/tmp/camel_findfiles";
        sshenv.ExecuteCommand("rm", $"-rf {d}", out _, false);
        sshenv.ExecuteCommand("mkdir", $"-p {d}/sub", out _, false);
        sshenv.ExecuteCommand("bash", $"-c \"printf 'hello' > '{d}/a.dll'; printf 'x' > '{d}/b.txt'; printf 'y' > '{d}/sub/c.dll'\"", out _, false);

        // Glob + recursion finds both .dll files (path/name/size), excluding the .txt.
        var all = await toolkit.FindFilesAsync(d, "*.dll");
        Assert.Equal(2, all.Length);
        Assert.Contains(all, f => f.Name == "a.dll" && f.Size == 5);
        Assert.DoesNotContain(all, f => f.Name == "b.txt");

        // maxDepth 1 excludes the nested file.
        var shallow = await toolkit.FindFilesAsync(d, "*.dll", maxDepth: 1);
        Assert.Equal("a.dll", Assert.Single(shallow).Name);

        // Multi-pattern overload: both globs matched in one traversal (a.dll, sub/c.dll, b.txt).
        var multi = await toolkit.FindFilesAsync(d, ["*.dll", "*.txt"]);
        Assert.Equal(3, multi.Length);

        // A missing directory yields an empty list rather than an error.
        Assert.Empty(await toolkit.FindFilesAsync($"{d}/nope", "*.dll"));

        // SHA-256 of known content ("hello").
        Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", await toolkit.Sha256Async($"{d}/a.dll"));

        sshenv.ExecuteCommand("rm", $"-rf {d}", out _, false);
    }

    const string Image = "/mnt/artifacts/4Dell Latitude CPi.E01";
    const int NtfsOffset = 63;

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    DiskAnalysisToolkit toolkit;
}
