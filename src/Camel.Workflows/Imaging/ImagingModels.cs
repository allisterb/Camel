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
