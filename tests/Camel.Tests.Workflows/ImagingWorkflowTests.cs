using Camel.Environments;
using Camel.Workflows;

namespace Camel.Tests.Workflows;

public class ImagingWorkflowTests : TestsRuntime
{
    public ImagingWorkflowTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelApi(sshenv, sshconfig);
        workflow = new ImagingWorkflow(api);
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

    const string Image = "/mnt/artifacts/4Dell Latitude CPi.E01";
    const int NtfsOffset = 63;

    AuditEnvironment sshenv;
    CamelApi api;
    ImagingWorkflow workflow;
}
