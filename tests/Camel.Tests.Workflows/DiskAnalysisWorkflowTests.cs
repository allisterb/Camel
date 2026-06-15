using Camel.Environments;
using Camel.Workflows;

namespace Camel.Tests.Workflows;

public class DiskAnalysisWorkflowTests : TestsRuntime
{
    public DiskAnalysisWorkflowTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelToolkitsApi(sshenv, sshconfig);
        workflow = new DiskAnalysisWorkflow(api);
    }

    [Fact]
    public async Task CanMountEwfImage()
    {
        const string mountDir = "/tmp/camel_wf_ewf";
        sshenv.ExecuteCommand("umount", mountDir, out _, true); // ensure not already mounted from a prior run

        var r = await workflow.MountEwfImageAsync(Image, mountDir);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);

        // The workflow validated and surfaced the embedded image metadata.
        Assert.Equal("aee4fcd9301c03b3b054623ca261959a", r.Result.Info.MD5);
        Assert.Equal("Greg Schardt", r.Result.Info.CaseNumber);

        // The raw device is exposed at <mountDir>/ewf1, and the FUSE mount really exists on the box.
        Assert.Equal($"{mountDir}/ewf1", r.Result.RawDevice);
        Assert.Equal(mountDir, r.Result.MountDir);
        sshenv.ExecuteCommand("ls", mountDir, out var contents, true); // FUSE mount is root-only
        Assert.Contains("ewf1", contents);

        // mmls found the partition table, including the NTFS volume at sector 63.
        Assert.NotEmpty(r.Result.PartitionTable);
        var ntfs = Assert.Single(r.Result.PartitionTable, e => e.Description.Contains("NTFS"));
        Assert.Equal(NtfsOffset, ntfs.Start);

        sshenv.ExecuteCommand("umount", mountDir, out _, true);
    }

    [Fact]
    public async Task MountEwfImageCreatesMissingMountDir()
    {
        // A mount point that does not yet exist must be created by the workflow (sudo mkdir -p).
        const string mountDir = "/tmp/camel_wf_ewf_new";
        sshenv.ExecuteCommand("umount", mountDir, out _, true);
        sshenv.ExecuteCommand("rmdir", mountDir, out _, true); // remove so the workflow has to create it

        var r = await workflow.MountEwfImageAsync(Image, mountDir);

        Assert.True(r.IsSuccess, r.Message);
        // The mountpoint exists; after ewfmount it is a root-only FUSE filesystem, so check via sudo.
        Assert.True(sshenv.ExecuteCommand("test", $"-d {mountDir}", out _, true));

        sshenv.ExecuteCommand("umount", mountDir, out _, true);
        sshenv.ExecuteCommand("rmdir", mountDir, out _, true);
    }

    [Fact]
    public async Task MountEwfImageFailsForMissingImage()
    {
        // ewfinfo cannot read a nonexistent file, so the workflow fails fast before attempting a mount.
        var r = await workflow.MountEwfImageAsync("/mnt/artifacts/does_not_exist.E01", "/tmp/camel_wf_missing");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
        Assert.Contains("EWF metadata", r.Message);
    }

    [Fact]
    public async Task CanMountFileSystem()
    {
        const string rawDir = "/tmp/camel_wf_fs_raw";
        const string fsDir = "/tmp/camel_wf_fs_ntfs";
        sshenv.ExecuteCommand("umount", fsDir, out _, true);  // tear down any leftover mounts from a prior run
        sshenv.ExecuteCommand("umount", rawDir, out _, true);

        var raw = await workflow.MountEwfImageAsync(Image, rawDir);
        Assert.True(raw.IsSuccess, raw.Message);

        var r = await workflow.MountFileSystemAsync(raw.Result!, NtfsOffset, fsDir);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.Equal("NTFS", r.Result.Info.FileSystemType);
        Assert.Equal(NtfsOffset, r.Result.Offset);
        Assert.Equal(fsDir, r.Result.MountDir);

        // The NTFS filesystem is really mounted (check via sudo; the mount is root-owned).
        sshenv.ExecuteCommand("ls", fsDir, out var contents, true);
        Assert.Contains("WINDOWS", contents);

        sshenv.ExecuteCommand("umount", fsDir, out _, true);
        sshenv.ExecuteCommand("umount", rawDir, out _, true);
    }

    [Fact]
    public async Task MountFileSystemDerivesMountDirFromOffset()
    {
        // When no mount dir is given, the workflow mounts at a sibling derived from the raw mount + offset.
        const string rawDir = "/tmp/camel_wf_fs_derive";
        string derived = $"{rawDir}_fs_{NtfsOffset}";
        sshenv.ExecuteCommand("umount", derived, out _, true);
        sshenv.ExecuteCommand("umount", rawDir, out _, true);

        var raw = await workflow.MountEwfImageAsync(Image, rawDir);
        Assert.True(raw.IsSuccess, raw.Message);

        var r = await workflow.MountFileSystemAsync(raw.Result!, NtfsOffset);

        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal(derived, r.Result!.MountDir);
        sshenv.ExecuteCommand("ls", derived, out var contents, true);
        Assert.Contains("WINDOWS", contents);

        sshenv.ExecuteCommand("umount", derived, out _, true);
        sshenv.ExecuteCommand("umount", rawDir, out _, true);
    }

    [Fact]
    public async Task MountFileSystemFailsForInvalidOffset()
    {
        const string rawDir = "/tmp/camel_wf_fs_bad";
        sshenv.ExecuteCommand("umount", rawDir, out _, true);

        var raw = await workflow.MountEwfImageAsync(Image, rawDir);
        Assert.True(raw.IsSuccess, raw.Message);

        // Sector 30 sits before the NTFS partition (starts at 63), so fsstat finds no filesystem there and
        // the workflow refuses to mount rather than mounting garbage.
        var r = await workflow.MountFileSystemAsync(raw.Result!, 30, "/tmp/camel_wf_fs_bad_mnt");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
        Assert.Contains("No valid filesystem", r.Message);

        sshenv.ExecuteCommand("umount", rawDir, out _, true);
    }

    [Fact]
    public async Task CanVerifyImage()
    {
        var r = await workflow.VerifyImageAsync(Image);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.IntegrityVerified); // stored hash == recalculated hash
        Assert.Equal("aee4fcd9301c03b3b054623ca261959a", r.Result.Info.MD5);
        Assert.Equal(r.Result.Verification.StoredMD5, r.Result.Verification.CalculatedMD5);
    }

    [Fact]
    public async Task VerifyImageFailsForMissingImage()
    {
        var r = await workflow.VerifyImageAsync("/mnt/artifacts/does_not_exist.E01");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task CanGenerateFilesystemTimeline()
    {
        var r = await workflow.GenerateFilesystemTimelineAsync(Image, NtfsOffset);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.Entries);
        Assert.All(r.Result.Entries, e => Assert.NotEmpty(e.Date));
        Assert.Contains(r.Result.Entries, e => e.FileName.Contains("boot.ini"));
        Assert.False(string.IsNullOrEmpty(r.Result.BodyfilePath));
    }

    [Fact]
    public async Task GenerateFilesystemTimelineFailsForInvalidOffset()
    {
        // Sector 30 is before the NTFS partition (starts at 63): fsstat finds no filesystem there.
        var r = await workflow.GenerateFilesystemTimelineAsync(Image, 30);

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.Contains("No valid filesystem", r.Message);
    }

    [Fact]
    public async Task CanRecoverFiles()
    {
        const string outDir = "/tmp/camel_wf_recover";
        sshenv.ExecuteCommand("rm", $"-rf {outDir}", out _, true);

        var r = await workflow.RecoverFilesAsync(Image, outDir, NtfsOffset, includeDeleted: false);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.FilesRecovered > 0);
        Assert.Equal(outDir, r.Result.OutputDir);

        // tsk_recover ran under sudo; the workflow hands the tree back to the login user.
        sshenv.ExecuteCommand("stat", $"-c %U {outDir}", out var owner, false);
        Assert.NotEqual("root", owner.Trim());
    }

    [Fact]
    public async Task RecoverFilesFailsForInvalidOffset()
    {
        var r = await workflow.RecoverFilesAsync(Image, "/tmp/camel_wf_recover_bad", 30);

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.Contains("No valid filesystem", r.Message);
    }

    [Fact]
    public async Task CanUnmountImage()
    {
        const string rawDir = "/tmp/camel_wf_unmount_raw";
        const string fsDir = "/tmp/camel_wf_unmount_fs";
        sshenv.ExecuteCommand("umount", fsDir, out _, true); // clean slate
        sshenv.ExecuteCommand("umount", rawDir, out _, true);

        var raw = await workflow.MountEwfImageAsync(Image, rawDir);
        Assert.True(raw.IsSuccess, raw.Message);
        var fs = await workflow.MountFileSystemAsync(raw.Result!, NtfsOffset, fsDir);
        Assert.True(fs.IsSuccess, fs.Message);

        var r = await workflow.UnmountImageAsync(raw.Result!, fs.Result!);

        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal(2, r.Result!.Length); // filesystem mount + raw device

        // Neither path should still be a mountpoint (mountpoint -q exits non-zero when not mounted).
        Assert.False(sshenv.ExecuteCommand("mountpoint", $"-q {fsDir}", out _, true));
        Assert.False(sshenv.ExecuteCommand("mountpoint", $"-q {rawDir}", out _, true));
    }

    [Fact]
    public async Task InspectBitLockerVolumeFailsForUnencryptedVolume()
    {
        // The NIST image's NTFS partition is not BitLocker-encrypted, so the workflow must fail cleanly (not throw)
        // and say so - exercising the full mount -> bdeinfo path against a real (non-BDE) volume.
        const string rawDir = "/tmp/camel_wf_bde_raw";
        sshenv.ExecuteCommand("umount", rawDir, out _, true);

        var raw = await workflow.MountEwfImageAsync(Image, rawDir);
        Assert.True(raw.IsSuccess, raw.Message);

        var r = await workflow.InspectBitLockerVolumeAsync(raw.Result!, NtfsOffset);
        Assert.False(r.IsSuccess);
        Assert.Contains("No BitLocker volume", r.Message);

        await workflow.UnmountImageAsync(raw.Result!);
    }

    [Fact]
    public async Task UnlockBitLockerVolumeFailsWithoutCredential()
    {
        // Calling unlock with no credential is a usage error caught before any tool runs.
        const string rawDir = "/tmp/camel_wf_bde_nocred";
        sshenv.ExecuteCommand("umount", rawDir, out _, true);

        var raw = await workflow.MountEwfImageAsync(Image, rawDir);
        Assert.True(raw.IsSuccess, raw.Message);

        var r = await workflow.UnlockBitLockerVolumeAsync(raw.Result!, NtfsOffset);
        Assert.False(r.IsSuccess);
        Assert.Contains("No BitLocker credential", r.Message);

        await workflow.UnmountImageAsync(raw.Result!);
    }

    [Fact]
    public async Task CanSearchBitLockerRecoveryKeysWorkflow()
    {
        const string f = "/tmp/camel_wf_bde_rk.txt";
        const string key = "111111-222222-333333-444444-555555-666666-777777-888888";
        sshenv.ExecuteCommand("bash", $"-c \"printf 'recovery key\\n{key}\\n' > {f}\"", out _, false);

        var r = await workflow.SearchBitLockerRecoveryKeysAsync(f);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Contains(key, r.Result!);

        sshenv.ExecuteCommand("rm", $"-f {f}", out _, false);
    }

    const string Image = "/mnt/artifacts/4Dell Latitude CPi.E01";
    const int NtfsOffset = 63;

    AuditEnvironment sshenv;
    CamelToolkitsApi api;
    DiskAnalysisWorkflow workflow;
}
