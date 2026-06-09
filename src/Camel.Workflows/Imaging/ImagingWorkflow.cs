using System;

using Camel.Toolkits.Models;

namespace Camel.Workflows;

public class ImagingWorkflow : Workflow
{
    public ImagingWorkflow(CamelApi api) : base(api) {}

    /// <summary>
    /// Mounts an EWF/E01 evidence image read-only on the workstation, following standard forensic practice:
    /// read and validate the image metadata, create the mount point, expose the raw disk via <c>ewfmount</c>
    /// (as <c>&lt;mountDir&gt;/ewf1</c>), then read its partition table with <c>mmls</c>. The image is never
    /// written to. The returned <see cref="EwfImageMount"/> gives callers the raw device path and partition
    /// table needed to mount/analyse an individual filesystem partition (e.g. via the disk-analysis toolkit's
    /// loopback/ntfs mount methods using a partition's start sector as the offset). Multi-segment images
    /// (E01, E02, …) are joined automatically — pass the first segment. Unmount with <c>umount mountDir</c>.
    /// </summary>
    /// <param name="imageFile">Absolute path to the .E01 image (first segment for multi-segment sets).</param>
    /// <param name="mountDir">Directory to mount the raw device under (created if missing, e.g. /mnt/ewf).</param>
    public async Task<WorkflowResult<EwfImageMount>> MountEwfImageAsync(string imageFile, string mountDir)
    {
        using var op = Begin("Mounting EWF image {0} at {1}", imageFile, mountDir);

        // 1. Read and validate the image metadata. This also confirms the file exists and is a readable
        //    EWF/E01 image before we attempt to mount it (records the embedded MD5/SHA1 for case notes).
        var info = await api.DiskAnalysis.EwfInfoAsync(imageFile);
        if (info is null)
            return WorkflowResult<EwfImageMount>.Failure(
                $"Could not read EWF metadata for '{imageFile}'; the file may be missing or not a valid E01/EWF image.");

        // 2. Ensure the mount point exists (sudo mkdir -p; harmless if it already does).
        if (!await api.DiskAnalysis.MakeDirAsync(mountDir))
            return WorkflowResult<EwfImageMount>.Failure($"Failed to create mount directory '{mountDir}'.");

        // 3. Mount the EWF image read-only, exposing the raw disk as <mountDir>/ewf1.
        if (!await api.DiskAnalysis.EwfMountRawAsync(imageFile, mountDir))
            return WorkflowResult<EwfImageMount>.Failure(
                $"ewfmount failed for '{imageFile}' at '{mountDir}'. The image may already be mounted there — " +
                $"unmount with 'umount {mountDir}' and retry.");

        // 4. Inspect the partition table of the raw device so callers can locate the target volume.
        string rawDevice = $"{mountDir.TrimEnd('/')}/ewf1";
        var partitionTable = await api.DiskAnalysis.MmlsAsync(rawDevice);
        if (partitionTable is null)
        {
            // mmls failing isn't fatal: a single-volume image (a partition image rather than a whole disk)
            // has no partition map. Surface an empty table rather than aborting the otherwise-successful mount.
            Warn("mmls produced no partition table for {0}; the image may be a single volume with no partition map.", rawDevice);
            partitionTable = [];
        }

        op.Complete();
        return WorkflowResult<EwfImageMount>.Success(
            new EwfImageMount(mountDir, info, partitionTable),
            $"Mounted '{imageFile}' read-only at '{rawDevice}' ({partitionTable.Length} partition(s) detected).");
    }

    /// <summary>
    /// Mounts a single filesystem (partition) from a previously-mounted raw disk device read-only. The
    /// partition is identified by its start sector <paramref name="offset"/> (e.g. an <see cref="MmlsEntry.Start"/>
    /// from <see cref="EwfImageMount.PartitionTable"/>). Before mounting, <c>fsstat</c> is run at the offset to
    /// confirm a valid filesystem actually exists there — guarding against a wrong/garbage offset that would
    /// otherwise fail or, worse, silently mount nothing. NTFS volumes use the Windows-aware kernel driver with
    /// an ntfs-3g <c>force</c> fallback for dirty/hibernated volumes; other filesystems use a plain read-only
    /// loopback mount. Unmount with <c>umount mountDir</c>.
    /// </summary>
    /// <param name="imageMount">A raw image mount from <see cref="MountEwfImageAsync"/>.</param>
    /// <param name="offset">Partition start sector (e.g. from the mount's partition table).</param>
    /// <param name="mountDir">Directory to mount the filesystem under. Defaults to a sibling of the raw mount
    /// dir derived from the offset (created if missing).</param>
    public async Task<WorkflowResult<FileSystemMount>> MountFileSystemAsync(EwfImageMount imageMount, int offset, string? mountDir = null)
    {
        mountDir ??= $"{imageMount.MountDir.TrimEnd('/')}_fs_{offset}";
        using var op = Begin("Mounting filesystem at sector {0} of {1} at {2}", offset, imageMount.RawDevice, mountDir);

        // 1. Verify a filesystem actually lives at this offset before attempting to mount. fsstat reads the
        //    volume boot record / superblock at the offset; it reports a File System Type only when one is
        //    recognised (it otherwise prints "Cannot determine file system type", leaving the type unset).
        var fs = await api.DiskAnalysis.FsStatAsync(imageMount.RawDevice, offset);
        if (fs is null || string.IsNullOrWhiteSpace(fs.FileSystemType))
            return WorkflowResult<FileSystemMount>.Failure(
                $"No valid filesystem found at sector offset {offset} of '{imageMount.RawDevice}'. " +
                $"Check the partition table (mmls) for a correct partition start sector.");

        // 2. Ensure the mount point exists (sudo mkdir -p; harmless if it already does).
        if (!await api.DiskAnalysis.MakeDirAsync(mountDir))
            return WorkflowResult<FileSystemMount>.Failure($"Failed to create mount directory '{mountDir}'.");

        // 3. Mount read-only. NTFS gets the Windows-aware kernel driver, falling back to ntfs-3g 'force' for
        //    dirty/hibernated volumes the kernel driver refuses; everything else uses a plain ro,loop mount.
        bool isNtfs = fs.FileSystemType!.Contains("NTFS", StringComparison.OrdinalIgnoreCase);
        bool mounted = isNtfs
            ? await api.DiskAnalysis.EwfMountLoopbackAsync(imageMount.RawDevice, mountDir, offset)
              || await api.DiskAnalysis.EwfMountNtfsAsync(imageMount.RawDevice, mountDir, offset)
            : await api.DiskAnalysis.DDMountAsync(imageMount.RawDevice, mountDir, offset);

        if (!mounted)
            return WorkflowResult<FileSystemMount>.Failure(
                $"Failed to mount the {fs.FileSystemType} filesystem at offset {offset} of '{imageMount.RawDevice}' at '{mountDir}'.");

        op.Complete();
        return WorkflowResult<FileSystemMount>.Success(
            new FileSystemMount(mountDir, imageMount.RawDevice, offset, fs),
            $"Mounted {fs.FileSystemType} filesystem (offset {offset}) read-only at '{mountDir}'.");
    }
}
