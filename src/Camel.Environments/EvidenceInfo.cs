namespace Camel.Environments;

using System;

/// <summary>The cryptographic hash algorithm used to fingerprint a piece of evidence.</summary>
public enum HashType
{
    MD5,
    SHA1,
    SHA256
}

/// <summary>
/// Identifies a piece of original evidence (e.g. a disk image, memory capture, or mounted artifact) by its
/// path on an <see cref="AuditEnvironment"/> together with a verified cryptographic hash. Toolkits/workflows
/// consult the environment's registered evidence to guarantee they never write over original data — the
/// architectural enforcement of zero evidence-spoliation risk.
/// </summary>
/// <param name="FilePath">The path to the evidence on the environment where it resides.</param>
/// <param name="HashType">The algorithm used to compute <paramref name="HashValue"/>.</param>
/// <param name="HashValue">The known-good hash of the evidence, used to verify integrity.</param>
public record EvidenceInfo(string FilePath, HashType HashType, string HashValue);

/// <summary>
/// Thrown when an operation targets a path that would modify, overwrite, or otherwise disturb registered
/// original evidence — the architectural stop that enforces zero evidence-spoliation risk.
/// </summary>
public class EvidenceSpoliationRiskException : Exception
{
    public EvidenceSpoliationRiskException(EvidenceInfo evidence, string targetPath)
        : base($"The operation targeting '{targetPath}' is at risk of spoliating the original evidence file " +
               $"'{evidence.FilePath}' ({evidence.HashType} {evidence.HashValue}) and was refused.")
    {
        this.Evidence = evidence;
        this.TargetPath = targetPath;
    }

    /// <summary>The registered evidence that the refused operation would have put at risk.</summary>
    public EvidenceInfo Evidence { get; }

    /// <summary>The path the refused operation was targeting.</summary>
    public string TargetPath { get; }
}
