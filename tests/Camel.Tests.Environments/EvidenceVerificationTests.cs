namespace Camel.Tests.Environments;

using Camel.Environments;

/// <summary>
/// Unit tests for <see cref="AuditEnvironment.ParseEwfDigest"/> - the parser that pulls a media-content digest out
/// of <c>ewfverify</c> output so an <c>.E01</c> image can be verified against its acquisition hash (the digest of
/// the imaged media, not of the container file). The sample text is the verbatim output captured from
/// <c>ewfverify -d sha1 -q</c> on a real FOR508 SRL E01 (xp-tdungan-c-drive.E01); the asserted hashes are that
/// image's acquisition MD5/SHA1 from its FTK Imager sidecar.
/// </summary>
public class EvidenceVerificationTests
{
    // Verbatim ewfverify -d sha1 -q output (tabs preserved). Note both a "stored in file" and a "calculated over
    // data" line per algorithm - the parser must pick the calculated one.
    private const string EwfVerifyOutput =
        "ewfverify 20140816\n" +
        "\n\n" +
        "MD5 hash stored in file:\t\t60b778a12a4b7ad5ed5b28eb6e869b3f\n" +
        "MD5 hash calculated over data:\t\t60b778a12a4b7ad5ed5b28eb6e869b3f\n" +
        "SHA1 hash stored in file:\t\t5ee219f99e69db4739631da89c0dd5a8164477e2\n" +
        "SHA1 hash calculated over data:\t\t5ee219f99e69db4739631da89c0dd5a8164477e2\n" +
        "\n" +
        "ewfverify: SUCCESS\n";

    [Fact]
    public void ParsesCalculatedMd5_NotTheStoredLine()
    {
        Assert.Equal("60b778a12a4b7ad5ed5b28eb6e869b3f", AuditEnvironment.ParseEwfDigest(EwfVerifyOutput, "md5"));
    }

    [Fact]
    public void ParsesCalculatedSha1_NotMd5OrStoredLine()
    {
        // Must pick the SHA1 *calculated* line, not the 32-char MD5 and not the SHA1 "stored in file" line.
        Assert.Equal("5ee219f99e69db4739631da89c0dd5a8164477e2", AuditEnvironment.ParseEwfDigest(EwfVerifyOutput, "sha1"));
    }

    [Fact]
    public void Md5OnlyOutput_ParsesMd5()
    {
        // ewfverify without -d prints only MD5 lines; the parser still finds the calculated MD5.
        const string md5Only =
            "ewfverify 20140816\n\n" +
            "MD5 hash stored in file:\t\t60b778a12a4b7ad5ed5b28eb6e869b3f\n" +
            "MD5 hash calculated over data:\t\t60b778a12a4b7ad5ed5b28eb6e869b3f\n\n" +
            "ewfverify: SUCCESS\n";
        Assert.Equal("60b778a12a4b7ad5ed5b28eb6e869b3f", AuditEnvironment.ParseEwfDigest(md5Only, "md5"));
    }

    [Fact]
    public void Sha256_IsNotConfusedWithSha1()
    {
        const string withSha256 =
            "MD5 hash calculated over data:\t\t60b778a12a4b7ad5ed5b28eb6e869b3f\n" +
            "SHA256 hash calculated over data:\t\t" +
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n";
        Assert.Equal("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            AuditEnvironment.ParseEwfDigest(withSha256, "sha256"));
        // sha1 was not calculated here -> nothing to return.
        Assert.Equal("", AuditEnvironment.ParseEwfDigest(withSha256, "sha1"));
    }

    [Fact]
    public void EmptyOrUnrelatedOutput_ReturnsEmpty()
    {
        Assert.Equal("", AuditEnvironment.ParseEwfDigest("", "md5"));
        Assert.Equal("", AuditEnvironment.ParseEwfDigest("ewfverify: FAILURE\n", "md5"));
    }
}
