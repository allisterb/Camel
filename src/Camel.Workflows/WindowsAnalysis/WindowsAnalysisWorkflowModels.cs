namespace Camel.Workflows.Models;

using Camel.Toolkits.Models;

/// <summary>
/// One of the forensic registry artifacts from the Windows-artifacts methodology: a human-readable
/// <see cref="Name"/> and the <see cref="RegistryEntry"/> rows the RECmd batch produced whose key path
/// matched it. <see cref="Entries"/> is empty when the parsed hives contained no such artifact (e.g. an
/// NTUSER-only artifact when only SYSTEM/SOFTWARE hives were parsed).
/// </summary>
public record KeyArtifact
{
    public string Name { get; }
    public RegistryEntry[] Entries { get; }
    public KeyArtifact(string name, RegistryEntry[] entries)
    {
        this.Name = name;
        this.Entries = entries;
    }
}

/// <summary>
/// The result of batch-parsing a directory of registry hives with RECmd's DFIR batch file and bucketing the
/// output into the key forensic artifacts. <see cref="Artifacts"/> holds one <see cref="KeyArtifact"/> per
/// artifact category (Run keys, UserAssist, USBSTOR, Shimcache, …); <see cref="AllEntries"/> is the complete
/// RECmd output for anything not covered by a named bucket.
/// </summary>
public record KeyArtifactsReport
{
    public KeyArtifact[] Artifacts { get; }
    public RegistryEntry[] AllEntries { get; }
    public KeyArtifactsReport(KeyArtifact[] artifacts, RegistryEntry[] allEntries)
    {
        this.Artifacts = artifacts;
        this.AllEntries = allEntries;
    }
}
