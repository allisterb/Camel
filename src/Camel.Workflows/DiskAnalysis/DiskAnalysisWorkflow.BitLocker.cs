namespace Camel.Workflows;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

public partial class DiskAnalysisWorkflow
{
    #region BitLocker (BDE)
    /// <summary>
    /// Identifies a BitLocker (BDE) volume on a previously-mounted raw disk device and reports how it is protected,
    /// without unlocking it (no credential needed). Runs <c>bdeinfo</c> at the partition start sector
    /// <paramref name="offset"/> of <paramref name="imageMount"/>'s raw device and returns the encryption method,
    /// volume identifier, creation time, and the list of key protectors (TPM / recovery password / password /
    /// startup key) - which tells you which credential class you need to decrypt it. A BitLocker volume still
    /// appears as "NTFS" in the partition table (mmls), so use this to confirm whether a partition is actually
    /// encrypted before trying to mount it.
    /// </summary>
    /// <param name="imageMount">A raw image mount from <see cref="MountEwfImageAsync"/>.</param>
    /// <param name="offset">Partition start sector (e.g. an <see cref="Camel.Toolkits.Models.MmlsEntry.Start"/>).</param>
    public async Task<WorkflowResult<BitLockerInfo>> InspectBitLockerVolumeAsync(EwfImageMount imageMount, int offset)
    {
        using var _audit = AuditScope();
        using var op = Begin("Inspecting BitLocker volume at sector {0} of {1}", offset, imageMount.RawDevice);

        var info = await DiskAnalysis.BdeInfoAsync(imageMount.RawDevice, offset);
        if (info is null || !info.IsBitLockerVolume)
            return WorkflowResult<BitLockerInfo>.Failure(
                $"No BitLocker volume found at sector offset {offset} of '{imageMount.RawDevice}'. " +
                $"Check the partition table (mmls) for a correct partition start sector - the volume may be unencrypted.");

        op.Complete();
        var protectors = info.KeyProtectors.Length > 0
            ? info.KeyProtectors.Length + " key protector(s): " + string.Join(", ", info.KeyProtectors.Select(p => p.Type))
            : "no key protectors reported";
        return WorkflowResult<BitLockerInfo>.Success(info,
            $"BitLocker volume ({info.EncryptionMethod ?? "unknown method"}) at offset {offset} with {protectors}.");
    }

    /// <summary>
    /// Unlocks and mounts a BitLocker (BDE) partition from a previously-mounted raw disk device read-only,
    /// following standard practice: confirm a BDE volume exists at <paramref name="offset"/> (<c>bdeinfo</c>),
    /// then decrypt it with <c>bdemount</c> - which exposes the cleartext volume as a raw <c>bde1</c> device - and
    /// (unless <paramref name="mountFilesystem"/> is false) loop-mount that decrypted device so its files are
    /// directly browsable. Supply exactly one credential: a 48-digit <paramref name="recoveryPassword"/>, a
    /// <paramref name="password"/>, a startup-key <paramref name="bekFile"/> (.BEK), or the raw
    /// <paramref name="fullKey"/> (FVEK:TWEAK base16). The returned <see cref="BitLockerVolumeMount"/> gives the
    /// decrypted raw device for the Sleuth Kit tools (run them with no offset) and, when mounted, the browsable
    /// filesystem directory. Tear down with <see cref="UnmountBitLockerVolumeAsync"/>.
    /// </summary>
    /// <param name="imageMount">A raw image mount from <see cref="MountEwfImageAsync"/>.</param>
    /// <param name="offset">BitLocker partition start sector (from the mount's partition table / mmls).</param>
    /// <param name="recoveryPassword">A 48-digit recovery password (<c>NNNNNN-NNNNNN-...</c>).</param>
    /// <param name="password">The user password/passphrase protecting the volume.</param>
    /// <param name="bekFile">Path to a startup-key (.BEK) file on the workstation.</param>
    /// <param name="fullKey">The raw full volume encryption key and tweak key (<c>FVEK:TWEAK</c>, base16).</param>
    /// <param name="bdeMountDir">FUSE mount dir for the decrypted device (defaults to a sibling of the raw mount dir).</param>
    /// <param name="fsMountDir">Where to loop-mount the decrypted filesystem (defaults to a sibling of the bde dir).</param>
    /// <param name="mountFilesystem">Also loop-mount the decrypted volume for file browsing (default true).</param>
    public async Task<WorkflowResult<BitLockerVolumeMount>> UnlockBitLockerVolumeAsync(
        EwfImageMount imageMount, int offset,
        string? recoveryPassword = null, string? password = null, string? bekFile = null, string? fullKey = null,
        string? bdeMountDir = null, string? fsMountDir = null, bool mountFilesystem = true)
    {
        bdeMountDir ??= $"{imageMount.MountDir.TrimEnd('/')}_bde_{offset}";
        using var _audit = AuditScope();
        using var op = Begin("Unlocking BitLocker volume at sector {0} of {1}", offset, imageMount.RawDevice);

        if (string.IsNullOrWhiteSpace(recoveryPassword) && string.IsNullOrWhiteSpace(password)
            && string.IsNullOrWhiteSpace(bekFile) && string.IsNullOrWhiteSpace(fullKey))
            return WorkflowResult<BitLockerVolumeMount>.Failure(
                "No BitLocker credential supplied. Provide one of: a recovery password, a password, a startup-key " +
                "(.BEK) file, or the full volume key (FVEK:TWEAK).");

        // 1. Confirm a BitLocker volume actually lives at this offset (and capture its protectors for the report).
        var info = await DiskAnalysis.BdeInfoAsync(imageMount.RawDevice, offset);
        if (info is null || !info.IsBitLockerVolume)
            return WorkflowResult<BitLockerVolumeMount>.Failure(
                $"No BitLocker volume found at sector offset {offset} of '{imageMount.RawDevice}'. " +
                $"Check the partition table (mmls) - the volume may be unencrypted.");

        // 2. Create the FUSE mount point for the decrypted device.
        if (!await DiskAnalysis.MakeDirAsync(bdeMountDir))
            return WorkflowResult<BitLockerVolumeMount>.Failure($"Failed to create BitLocker mount directory '{bdeMountDir}'.");

        // 3. Unlock and mount - bdemount exposes the cleartext volume as <bdeMountDir>/bde1.
        if (!await DiskAnalysis.BdeMountAsync(imageMount.RawDevice, bdeMountDir, recoveryPassword, password, bekFile, fullKey, offset))
            return WorkflowResult<BitLockerVolumeMount>.Failure(
                $"bdemount failed to unlock the BitLocker volume at offset {offset} of '{imageMount.RawDevice}'. " +
                $"The supplied credential may be wrong, or a volume may already be mounted at '{bdeMountDir}' " +
                $"(unmount with 'umount {bdeMountDir}' and retry).");

        string decrypted = $"{bdeMountDir.TrimEnd('/')}/bde1";

        // 4. Optionally loop-mount the decrypted volume so its files are directly browsable. The decrypted device is
        //    a single volume at offset 0; verify a filesystem then mount NTFS-aware (with the ntfs-3g fallback).
        string? mountedFsDir = null;
        FsStat? fsInfo = null;
        if (mountFilesystem)
        {
            fsMountDir ??= $"{bdeMountDir.TrimEnd('/')}_fs";
            fsInfo = await DiskAnalysis.FsStatAsync(decrypted);
            if (fsInfo is not null && !string.IsNullOrWhiteSpace(fsInfo.FileSystemType)
                && await DiskAnalysis.MakeDirAsync(fsMountDir)
                && (await DiskAnalysis.EwfMountLoopbackAsync(decrypted, fsMountDir)
                    || await DiskAnalysis.EwfMountNtfsAsync(decrypted, fsMountDir)))
                mountedFsDir = fsMountDir;
            else
                Warn("Unlocked the volume (decrypted device {0}) but could not mount its filesystem; " +
                     "use the device directly with the Sleuth Kit tools.", decrypted);
        }

        op.Complete();
        var mount = new BitLockerVolumeMount(bdeMountDir, info, mountedFsDir, fsInfo);
        return WorkflowResult<BitLockerVolumeMount>.Success(mount,
            $"Unlocked the BitLocker volume ({info.EncryptionMethod ?? "unknown method"}) at offset {offset}. " +
            $"Decrypted device: '{decrypted}'" +
            (mountedFsDir is not null
                ? $", mounted read-only at '{mountedFsDir}'."
                : " (filesystem not mounted; run the Sleuth Kit tools against the device with no offset)."));
    }

    /// <summary>
    /// Tears down a BitLocker volume mount in the correct order: unmounts the decrypted filesystem (if one was
    /// loop-mounted) first, then the underlying <c>bdemount</c> FUSE device - the FUSE mount cannot be released
    /// while a loopback filesystem mount still sits on top of it. The underlying EWF image mount is left in place;
    /// release it afterwards with <see cref="UnmountImageAsync"/>. Attempts every unmount and reports any failures.
    /// </summary>
    /// <param name="mount">The BitLocker volume mount from <see cref="UnlockBitLockerVolumeAsync"/>.</param>
    public async Task<WorkflowResult<string[]>> UnmountBitLockerVolumeAsync(BitLockerVolumeMount mount)
    {
        using var _audit = AuditScope();
        using var op = Begin("Unmounting BitLocker volume {0}", mount.BdeMountDir);

        var failed = new List<string>();
        // The decrypted filesystem mount sits on top of the bde1 device, so release it first (reverse of mount order).
        if (mount.FilesystemMountDir is not null && !await DiskAnalysis.UnmountAsync(mount.FilesystemMountDir))
            failed.Add(mount.FilesystemMountDir);
        if (!await DiskAnalysis.UnmountAsync(mount.BdeMountDir)) failed.Add(mount.BdeMountDir);

        if (failed.Count > 0)
            return WorkflowResult<string[]>.Failure($"Failed to unmount: {string.Join(", ", failed)}.");

        op.Complete();
        var unmounted = mount.FilesystemMountDir is not null
            ? new[] { mount.FilesystemMountDir, mount.BdeMountDir }
            : new[] { mount.BdeMountDir };
        return WorkflowResult<string[]>.Success(unmounted, $"Unmounted {unmounted.Length} BitLocker mount(s).");
    }

    /// <summary>
    /// Searches <paramref name="input"/> (a raw image/device, an unallocated-space extract, a memory dump, or any
    /// blob) for BitLocker 48-digit recovery keys by string search - the FOR508 data-recovery technique for when
    /// no key is supplied. Returns the distinct candidate keys found (try each with
    /// <see cref="UnlockBitLockerVolumeAsync"/>'s <c>recoveryPassword</c>); only the key whose identifier matches
    /// the volume will actually unlock it.
    /// </summary>
    /// <param name="input">Path to the image/device/extract/dump to scan.</param>
    /// <param name="maxMatches">Cap on candidate keys returned. Default 50.</param>
    public async Task<WorkflowResult<string[]>> SearchBitLockerRecoveryKeysAsync(string input, int maxMatches = 50)
    {
        using var _audit = AuditScope();
        using var op = Begin("Searching {0} for BitLocker recovery keys", input);

        var keys = await DiskAnalysis.SearchBitLockerRecoveryKeysAsync(input, maxMatches);
        if (keys is null)
            return WorkflowResult<string[]>.Failure($"Could not read '{input}' for the recovery-key search.");

        op.Complete();
        return WorkflowResult<string[]>.Success(keys,
            keys.Length == 0
                ? $"No BitLocker recovery keys found in '{input}'."
                : $"Found {keys.Length} candidate BitLocker recovery key(s) in '{input}': {string.Join(", ", keys.Take(5))}" +
                  (keys.Length > 5 ? ", ..." : "") + ".");
    }
    #endregion
}
