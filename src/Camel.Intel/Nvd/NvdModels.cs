namespace Camel.Intel;

using System;

/// <summary>
/// One CVE from the NIST NVD CVE API 2.0. The CVSS base score/vector are the best available across the v3.1/v3.0/v2
/// metric blocks (null when NVD published none). Summary is the English description.
/// </summary>
/// <param name="Id">The CVE id (e.g. "CVE-2020-15778").</param>
/// <param name="Cvss">CVSS base score (0-10), or null when no metric was published.</param>
/// <param name="CvssVector">CVSS vector string, or "" when none.</param>
/// <param name="Summary">English description of the vulnerability.</param>
/// <param name="Published">NVD publication time (UTC), or null.</param>
/// <param name="LastModified">NVD last-modified time (UTC), or null.</param>
/// <param name="References">Reference URLs NVD lists for the CVE.</param>
public record CveRecord(
    string Id,
    double? Cvss,
    string CvssVector,
    string Summary,
    DateTime? Published,
    DateTime? LastModified,
    string[] References);
