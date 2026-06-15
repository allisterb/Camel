namespace Camel.Workflows.Models;

using System;

using Camel.Toolkits.Models;

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

/// <summary>
/// The result of unlocking and mounting a BitLocker (BDE) volume: the FUSE mount directory holding the decrypted
/// raw device (<see cref="DecryptedDevice"/>, i.e. <c>&lt;BdeMountDir&gt;/bde1</c>) that the Sleuth Kit tools and
/// a loopback mount operate on just like an <see cref="EwfImageMount.RawDevice"/>, the volume's BitLocker metadata
/// (<see cref="Info"/>), and - when the decrypted filesystem was also loop-mounted for browsing - that mount
/// directory (<see cref="FilesystemMountDir"/>) and its <c>fsstat</c> detail (<see cref="FilesystemInfo"/>).
/// </summary>
public record BitLockerVolumeMount
{
    /// <summary>The bdemount FUSE directory containing the decrypted <c>bde1</c> device.</summary>
    public string BdeMountDir { get; }
    /// <summary>The decrypted raw volume device (<c>&lt;BdeMountDir&gt;/bde1</c>); pass it to the TSK tools with no offset.</summary>
    public string DecryptedDevice { get; }
    /// <summary>Where the decrypted volume was loop-mounted read-only for direct file browsing, or null if not mounted.</summary>
    public string? FilesystemMountDir { get; }
    /// <summary>The BitLocker volume metadata and key protectors (from bdeinfo).</summary>
    public BitLockerInfo Info { get; }
    /// <summary>The decrypted filesystem's fsstat detail, when the filesystem was mounted; otherwise null.</summary>
    public FsStat? FilesystemInfo { get; }
    public BitLockerVolumeMount(string bdeMountDir, BitLockerInfo info, string? filesystemMountDir, FsStat? filesystemInfo)
    {
        this.BdeMountDir = bdeMountDir;
        this.DecryptedDevice = $"{bdeMountDir.TrimEnd('/')}/bde1";
        this.Info = info;
        this.FilesystemMountDir = filesystemMountDir;
        this.FilesystemInfo = filesystemInfo;
    }
}

/// <summary>The result of a signature-carving run: the recovered files (with type/size/offset), grouped by type.</summary>
public record CarveReport
{
    public string OutputDir { get; init; } = "";
    /// <summary>The carver used: "foremost", "scalpel", or "photorec".</summary>
    public string Carver { get; init; } = "";
    public CarvedFile[] CarvedFiles { get; init; } = [];
    /// <summary>Carved-file counts per type (jpg/png/pdf/…), most common first.</summary>
    public NameCount[] ByType { get; init; } = [];
    public int TotalFiles { get; init; }
}

/// <summary>The result of a bulk_extractor feature-extraction run: the feature categories found, with counts and top values.</summary>
public record FeatureExtractionReport
{
    public string OutputDir { get; init; } = "";
    public FeatureCategory[] Features { get; init; } = [];
}

/// <summary>One bulk_extractor feature category (email/url/domain/ccn/telephone/ip/…) with its hit count and most-frequent values.</summary>
public record FeatureCategory
{
    public required string Category { get; init; }
    public long Count { get; init; }
    /// <summary>The most frequent values for this feature (from the category histogram), most-frequent first.</summary>
    public string[] TopValues { get; init; } = [];
}

/// <summary>The result of enumerating deleted files on a filesystem image.</summary>
public record DeletedFilesReport
{
    public DeletedFileEntry[] DeletedFiles { get; init; } = [];
    public int Count { get; init; }
}

/// <summary>One deleted file recovered from the filesystem metadata: its path, inode, size, and recoverability.</summary>
public record DeletedFileEntry
{
    public string Path { get; init; } = "";
    /// <summary>The TSK inode address (pass to <c>RecoverDeletedFileAsync</c> / <c>icat</c> to extract its content).</summary>
    public string Inode { get; init; } = "";
    public long Size { get; init; }
    /// <summary>The inode's change time (updated at deletion), the best available "deleted ~when" signal.</summary>
    public DateTime? DeletedTime { get; init; }
    /// <summary>False when the inode has been reallocated to a new file (content likely overwritten).</summary>
    public bool Recoverable { get; init; }
}
