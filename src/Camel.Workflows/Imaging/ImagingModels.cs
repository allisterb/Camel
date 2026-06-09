using Camel.Toolkits.Models;

namespace Camel.Workflows;

/// <summary>
/// The result of mounting an EWF/E01 image: the directory it was mounted under, the raw disk device
/// FUSE-exposed inside it (<see cref="RawDevice"/>, i.e. <c>&lt;MountDir&gt;/ewf1</c>) that subsequent
/// Sleuth Kit tools operate on, the image's embedded metadata, and its partition table.
/// </summary>
public record EwfImageMount
{
    public string MountDir { get; }
    public string RawDevice { get; }
    public EwfInfo Info { get; }
    public MmlsEntry[] PartitionTable { get; }
    public EwfImageMount(string mountDir, EwfInfo info, MmlsEntry[] partitionTable)
    {
        this.MountDir = mountDir;
        this.RawDevice = $"{mountDir.TrimEnd('/')}/ewf1";
        this.Info = info;
        this.PartitionTable = partitionTable;
    }
}

/// <summary>
/// The result of verifying an EWF/E01 image: its embedded metadata and the integrity-check outcome.
/// <see cref="IntegrityVerified"/> is true only when the hash calculated over the data matches the hash
/// stored at acquisition time — i.e. the evidence is intact and safe to analyse.
/// </summary>
public record ImageVerification
{
    public EwfInfo Info { get; }
    public EwfVerify Verification { get; }
    public bool IntegrityVerified => Verification.Success;
    public ImageVerification(EwfInfo info, EwfVerify verification)
    {
        this.Info = info;
        this.Verification = verification;
    }
}

/// <summary>
/// A filesystem timeline: the sorted <c>mactime</c> rows and the path to the bodyfile on the workstation
/// they were generated from (kept so it can be fed to other tools, e.g. log2timeline, or re-rendered).
/// </summary>
public record FilesystemTimeline
{
    public string BodyfilePath { get; }
    public MactimeEntry[] Entries { get; }
    public FilesystemTimeline(string bodyfilePath, MactimeEntry[] entries)
    {
        this.BodyfilePath = bodyfilePath;
        this.Entries = entries;
    }
}

/// <summary>
/// The result of a bulk file-recovery run: the directory the recovered tree was written to, the number of
/// files recovered, and whether deleted/unallocated content was included as well as allocated files.
/// </summary>
public record FileRecovery
{
    public string OutputDir { get; }
    public int FilesRecovered { get; }
    public bool IncludedDeleted { get; }
    public FileRecovery(string outputDir, int filesRecovered, bool includedDeleted)
    {
        this.OutputDir = outputDir;
        this.FilesRecovered = filesRecovered;
        this.IncludedDeleted = includedDeleted;
    }
}

/// <summary>
/// The result of mounting a single filesystem (a partition) from a raw disk device: the directory it was
/// mounted under, the raw device and partition start sector (<see cref="Offset"/>) it was mounted from, and
/// the <c>fsstat</c> metadata that was used to verify a valid filesystem exists at that offset.
/// </summary>
public record FileSystemMount
{
    public string MountDir { get; }
    public string RawDevice { get; }
    public int Offset { get; }
    public FsStat Info { get; }
    public FileSystemMount(string mountDir, string rawDevice, int offset, FsStat info)
    {
        this.MountDir = mountDir;
        this.RawDevice = rawDevice;
        this.Offset = offset;
        this.Info = info;
    }
}
