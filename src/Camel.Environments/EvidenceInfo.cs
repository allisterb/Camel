namespace Camel.Environments;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

/// <summary>The cryptographic hash algorithm used to fingerprint a piece of evidence. <see cref="None"/> is used
/// when the case description supplied no hash for the artifact.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum HashType
{
    None,
    MD5,
    SHA1,
    SHA256
}

/// <summary>
/// Identifies a piece of original evidence (e.g. a disk image, memory capture, or mounted artifact) by its
/// path on an <see cref="AuditEnvironment"/>, optionally with a verified cryptographic hash. Toolkits/workflows
/// consult the environment's registered evidence to guarantee they never write over original data — the
/// architectural enforcement of zero evidence-spoliation risk. The hash is optional because a case description
/// does not always provide one; spoliation protection is path-based and does not depend on it.
/// </summary>
/// <param name="FilePath">The path to the evidence on the environment where it resides.</param>
/// <param name="HashType">The algorithm used to compute <paramref name="HashValue"/>; <see cref="HashType.None"/>
/// when no hash is known (the default).</param>
/// <param name="HashValue">The known-good hash of the evidence, used to verify integrity; empty when unknown.</param>
public record EvidenceInfo(string FilePath, HashType HashType = HashType.None, string HashValue = "");

/// <summary>The presence/size preflight result for a single evidence file (see
/// <see cref="AuditEnvironment.GetEvidenceSummary"/>).</summary>
/// <param name="FilePath">The evidence path that was checked.</param>
/// <param name="Exists">True if the path exists on the environment (as a file or directory).</param>
/// <param name="SizeBytes">The file size in bytes, or <c>-1</c> when the path is missing or cannot be sized
/// (e.g. it is a directory/mount).</param>
public record EvidenceFileSummary(string FilePath, bool Exists, long SizeBytes);

/// <summary>
/// The preflight summary produced before registering evidence (see <see cref="AuditEnvironment.GetEvidenceSummary"/>):
/// whether every supplied evidence path is present on the environment, with each file's existence and size. The
/// <c>SetEvidence</c> tool uses it to refuse registration when any evidence file is missing.
/// </summary>
/// <param name="AllPresent">True when every supplied evidence path exists.</param>
/// <param name="Files">One <see cref="EvidenceFileSummary"/> per supplied evidence item, in order.</param>
public record CaseEvidenceSummary(bool AllPresent, EvidenceFileSummary[] Files)
{
    /// <summary>The paths of evidence files that do not exist on the environment (empty when all are present).</summary>
    public IEnumerable<string> MissingFiles => Files.Where(f => !f.Exists).Select(f => f.FilePath);
}

/// <summary>The re-hash result for a single registered evidence item (see
/// <see cref="AuditEnvironment.VerifyCaseEvidenceAsync"/>).</summary>
/// <param name="Evidence">The registered evidence entry that was checked.</param>
/// <param name="CurrentHash">The hash actually computed from the file on disk now. When the entry supplied a
/// hash, it is computed with that same algorithm so it can be compared; when the entry supplied no hash, this is
/// the file's SHA-1, recorded as a chain-of-custody baseline.</param>
/// <param name="Matched">True if the entry supplied a hash and the current value equals it; true also when the
/// entry supplied no hash (there is nothing to contradict); false on a mismatch or if the file could not be hashed.</param>
public record EvidenceHashCheck(EvidenceInfo Evidence, string CurrentHash, bool Matched);

/// <summary>
/// The outcome of re-hashing every registered evidence file and comparing it against the supplied hash (see
/// <see cref="AuditEnvironment.VerifyCaseEvidenceAsync"/>). <see cref="Success"/> is false when any item that
/// supplied a hash failed to match (or could not be hashed); items with no supplied hash never fail it — their
/// current SHA-1 is simply recorded.
/// </summary>
/// <param name="Success">True when every hash-bearing evidence item matched its supplied hash.</param>
/// <param name="Results">One <see cref="EvidenceHashCheck"/> per registered evidence item, in order.</param>
public record CaseEvidenceVerification(bool Success, EvidenceHashCheck[] Results);

/// <summary>
/// Thrown when an operation targets a path that would modify, overwrite, or otherwise disturb registered
/// original evidence — the architectural stop that enforces zero evidence-spoliation risk.
/// </summary>
public class EvidenceSpoliationRiskException : Exception
{
    public EvidenceSpoliationRiskException(EvidenceInfo evidence, string targetPath)
        : base($"The operation targeting '{targetPath}' is at risk of spoliating the original evidence file " +
               $"'{evidence.FilePath}'{FormatHash(evidence)} and was refused.")
    {
        this.Evidence = evidence;
        this.TargetPath = targetPath;
    }

    // Appends the hash only when one is known, so a hashless evidence entry doesn't render "(None )".
    private static string FormatHash(EvidenceInfo e) =>
        e.HashType == HashType.None || string.IsNullOrEmpty(e.HashValue) ? "" : $" ({e.HashType} {e.HashValue})";

    /// <summary>The registered evidence that the refused operation would have put at risk.</summary>
    public EvidenceInfo Evidence { get; }

    /// <summary>The path the refused operation was targeting.</summary>
    public string TargetPath { get; }
}
