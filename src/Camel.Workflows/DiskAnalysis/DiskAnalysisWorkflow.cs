namespace Camel.Workflows;

using System;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

public class DiskAnalysisWorkflow : Workflow
{
    public DiskAnalysisWorkflow(CamelApi api) : base(api) {}

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
        var info = await DiskAnalysis.EwfInfoAsync(imageFile);
        if (info is null)
            return WorkflowResult<EwfImageMount>.Failure(
                $"Could not read EWF metadata for '{imageFile}'; the file may be missing or not a valid E01/EWF image.");

        // 2. Ensure the mount point exists (sudo mkdir -p; harmless if it already does).
        if (!await DiskAnalysis.MakeDirAsync(mountDir))
            return WorkflowResult<EwfImageMount>.Failure($"Failed to create mount directory '{mountDir}'.");

        // 3. Mount the EWF image read-only, exposing the raw disk as <mountDir>/ewf1.
        if (!await DiskAnalysis.EwfMountRawAsync(imageFile, mountDir))
            return WorkflowResult<EwfImageMount>.Failure(
                $"ewfmount failed for '{imageFile}' at '{mountDir}'. The image may already be mounted there — " +
                $"unmount with 'umount {mountDir}' and retry.");

        // 4. Inspect the partition table of the raw device so callers can locate the target volume.
        string rawDevice = $"{mountDir.TrimEnd('/')}/ewf1";
        var partitionTable = await DiskAnalysis.MmlsAsync(rawDevice);
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
        var fs = await DiskAnalysis.FsStatAsync(imageMount.RawDevice, offset);
        if (fs is null || string.IsNullOrWhiteSpace(fs.FileSystemType))
            return WorkflowResult<FileSystemMount>.Failure(
                $"No valid filesystem found at sector offset {offset} of '{imageMount.RawDevice}'. " +
                $"Check the partition table (mmls) for a correct partition start sector.");

        // 2. Ensure the mount point exists (sudo mkdir -p; harmless if it already does).
        if (!await DiskAnalysis.MakeDirAsync(mountDir))
            return WorkflowResult<FileSystemMount>.Failure($"Failed to create mount directory '{mountDir}'.");

        // 3. Mount read-only. NTFS gets the Windows-aware kernel driver, falling back to ntfs-3g 'force' for
        //    dirty/hibernated volumes the kernel driver refuses; everything else uses a plain ro,loop mount.
        bool isNtfs = fs.FileSystemType!.Contains("NTFS", StringComparison.OrdinalIgnoreCase);
        bool mounted = isNtfs
            ? await DiskAnalysis.EwfMountLoopbackAsync(imageMount.RawDevice, mountDir, offset)
              || await DiskAnalysis.EwfMountNtfsAsync(imageMount.RawDevice, mountDir, offset)
            : await DiskAnalysis.DDMountAsync(imageMount.RawDevice, mountDir, offset);

        if (!mounted)
            return WorkflowResult<FileSystemMount>.Failure(
                $"Failed to mount the {fs.FileSystemType} filesystem at offset {offset} of '{imageMount.RawDevice}' at '{mountDir}'.");

        op.Complete();
        return WorkflowResult<FileSystemMount>.Success(
            new FileSystemMount(mountDir, imageMount.RawDevice, offset, fs),
            $"Mounted {fs.FileSystemType} filesystem (offset {offset}) read-only at '{mountDir}'.");
    }

    /// <summary>
    /// Verifies an EWF/E01 image before analysis: reads its embedded metadata (<c>ewfinfo</c>) and recomputes
    /// the image hash, comparing it to the hash stored at acquisition (<c>ewfverify</c>). The returned
    /// <see cref="ImageVerification"/> always carries the metadata and verification detail when both tools
    /// ran; inspect <see cref="ImageVerification.IntegrityVerified"/> for the verdict. Standard practice is to
    /// confirm integrity here before any further processing — a mismatch indicates a corrupt or altered image.
    /// </summary>
    /// <param name="imageFile">Absolute path to the .E01 image (first segment for multi-segment sets).</param>
    public async Task<WorkflowResult<ImageVerification>> VerifyImageAsync(string imageFile)
    {
        using var op = Begin("Verifying EWF image {0}", imageFile);

        var info = await DiskAnalysis.EwfInfoAsync(imageFile);
        if (info is null)
            return WorkflowResult<ImageVerification>.Failure(
                $"Could not read EWF metadata for '{imageFile}'; the file may be missing or not a valid E01/EWF image.");

        var verify = await DiskAnalysis.EwfVerifyAsync(imageFile);
        if (verify is null)
            return WorkflowResult<ImageVerification>.Failure($"ewfverify did not complete for '{imageFile}'.");

        op.Complete();
        // Both tools ran, so the workflow succeeded regardless of the verdict — the integrity result is
        // carried in IntegrityVerified so a caller can decide whether to proceed.
        return WorkflowResult<ImageVerification>.Success(
            new ImageVerification(info, verify),
            verify.Success
                ? $"Integrity verified: calculated hash matches the acquisition hash (MD5 {verify.CalculatedMD5})."
                : $"INTEGRITY CHECK FAILED: stored MD5 {verify.StoredMD5} != calculated {verify.CalculatedMD5}. Do not rely on this image.");
    }

    /// <summary>
    /// Builds a filesystem timeline for a partition of <paramref name="imageFile"/> directly (no mount needed):
    /// confirms a filesystem exists at <paramref name="offset"/> with <c>fsstat</c>, walks it into a mactime
    /// bodyfile with <c>fls -r -m</c>, then renders a sorted timeline with <c>mactime</c>. Offsets come from a
    /// partition table (<see cref="EwfImageMount.PartitionTable"/> / mmls); omit for a single-volume image.
    /// </summary>
    /// <param name="imageFile">Path to the image (or raw device) to walk.</param>
    /// <param name="offset">Partition start sector, or null for a single-volume image.</param>
    /// <param name="timezone">Timezone for the rendered timestamps (default UTC).</param>
    /// <param name="bodyfilePath">Where to write the intermediate bodyfile (defaults to a temp path).</param>
    public async Task<WorkflowResult<FilesystemTimeline>> GenerateFilesystemTimelineAsync(
        string imageFile, int? offset = null, string timezone = "UTC", string? bodyfilePath = null)
    {
        bodyfilePath ??= $"/tmp/camel_bodyfile_{offset ?? 0}.txt";
        using var op = Begin("Generating filesystem timeline for {0} (offset {1})", imageFile, offset?.ToString() ?? "none");

        // Confirm a filesystem actually lives at the offset before walking it (avoids an empty/garbage timeline).
        var fs = await DiskAnalysis.FsStatAsync(imageFile, offset);
        if (fs is null || string.IsNullOrWhiteSpace(fs.FileSystemType))
            return WorkflowResult<FilesystemTimeline>.Failure(
                $"No valid filesystem found at sector offset {offset} of '{imageFile}'. " +
                $"Check the partition table (mmls) for a correct partition start sector.");

        // Walk the filesystem into a mactime bodyfile, then sort it into a timeline.
        if (!await DiskAnalysis.FlsBodyfileAsync(imageFile, bodyfilePath, offset))
            return WorkflowResult<FilesystemTimeline>.Failure(
                $"Failed to generate the fls bodyfile for '{imageFile}' (offset {offset}).");

        var entries = await DiskAnalysis.MactimeAsync(bodyfilePath, timezone);
        if (entries is null)
            return WorkflowResult<FilesystemTimeline>.Failure($"mactime failed to process bodyfile '{bodyfilePath}'.");

        op.Complete();
        return WorkflowResult<FilesystemTimeline>.Success(
            new FilesystemTimeline(bodyfilePath, entries),
            $"Generated {entries.Length} timeline entries for the {fs.FileSystemType} filesystem (offset {offset}).");
    }

    /// <summary>
    /// Bulk-recovers files from a partition of <paramref name="imageFile"/> into <paramref name="outputDir"/>
    /// directly (no mount needed): confirms a filesystem exists at <paramref name="offset"/> with <c>fsstat</c>,
    /// then runs <c>tsk_recover</c>. When <paramref name="includeDeleted"/> is true (the default) unallocated /
    /// deleted files are recovered as well as allocated ones (<c>-e</c>); otherwise only allocated files. The
    /// recovered tree is handed back to the login user (tsk_recover under sudo would otherwise leave it root-owned).
    /// </summary>
    /// <param name="imageFile">Path to the image (or raw device) to recover from.</param>
    /// <param name="outputDir">Workstation directory to write the recovered tree to.</param>
    /// <param name="offset">Partition start sector, or null for a single-volume image.</param>
    /// <param name="includeDeleted">Include unallocated/deleted files as well as allocated (default true).</param>
    public async Task<WorkflowResult<FileRecovery>> RecoverFilesAsync(
        string imageFile, string outputDir, int? offset = null, bool includeDeleted = true)
    {
        using var op = Begin("Recovering files from {0} (offset {1}) to {2}", imageFile, offset?.ToString() ?? "none", outputDir);

        var fs = await DiskAnalysis.FsStatAsync(imageFile, offset);
        if (fs is null || string.IsNullOrWhiteSpace(fs.FileSystemType))
            return WorkflowResult<FileRecovery>.Failure(
                $"No valid filesystem found at sector offset {offset} of '{imageFile}'. " +
                $"Check the partition table (mmls) for a correct partition start sector.");

        var count = await DiskAnalysis.TskRecoverAsync(imageFile, outputDir, all: includeDeleted, offset: offset);
        if (count is null)
            return WorkflowResult<FileRecovery>.Failure($"tsk_recover failed for '{imageFile}' (offset {offset}).");

        op.Complete();
        return WorkflowResult<FileRecovery>.Success(
            new FileRecovery(outputDir, count.Value, includeDeleted),
            $"Recovered {count} file(s){(includeDeleted ? " (including deleted/unallocated)" : "")} " +
            $"from the {fs.FileSystemType} filesystem to '{outputDir}'.");
    }

    /// <summary>
    /// Tears down an image mount in the correct order: unmounts any filesystem mounts taken from the image
    /// first, then the underlying raw EWF device — a FUSE <c>ewfmount</c> cannot be released while a loopback
    /// filesystem mount still sits on top of it. Attempts every unmount and reports any that failed.
    /// </summary>
    /// <param name="imageMount">The raw image mount from <see cref="MountEwfImageAsync"/>.</param>
    /// <param name="filesystemMounts">Filesystem mounts taken from it via <see cref="MountFileSystemAsync"/>.</param>
    public async Task<WorkflowResult<string[]>> UnmountImageAsync(EwfImageMount imageMount, params FileSystemMount[] filesystemMounts)
    {
        using var op = Begin("Unmounting image {0}", imageMount.MountDir);

        var failed = new List<string>();
        // Filesystem mounts sit on top of the raw device, so release them first (reverse of mount order).
        foreach (var fsMount in filesystemMounts)
            if (!await DiskAnalysis.UnmountAsync(fsMount.MountDir)) failed.Add(fsMount.MountDir);
        if (!await DiskAnalysis.UnmountAsync(imageMount.MountDir)) failed.Add(imageMount.MountDir);

        if (failed.Count > 0)
            return WorkflowResult<string[]>.Failure($"Failed to unmount: {string.Join(", ", failed)}.");

        op.Complete();
        var unmounted = filesystemMounts.Select(f => f.MountDir).Append(imageMount.MountDir).ToArray();
        return WorkflowResult<string[]>.Success(unmounted, $"Unmounted {unmounted.Length} mount(s).");
    }
}
