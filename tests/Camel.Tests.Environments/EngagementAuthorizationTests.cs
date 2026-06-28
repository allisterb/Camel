namespace Camel.Tests.Environments;

using System;
using System.Linq;
using System.Net;

using Camel.Environments;

/// <summary>
/// Unit tests for the engagement authorization tiering (docs/PenTestBookGapAnalysis.md C.2): address-class
/// classification, the (posture x tier) -> proof-requirement matrix, and the per-entry evaluation that the
/// public-IP hard gate rests on. Pure/deterministic — uses IP literals and CIDRs so no DNS resolution is needed.
/// </summary>
public class EngagementAuthorizationTests
{
    static EngagementInfo Eng(EngagementPosture posture, EngagementDocument[]? docs, string waiver,
        params ScopeTarget[] scope) =>
        new("eng", "Acme", "A", "RoE-1", DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(1),
            scope, AllowExternalTargetDisclosure: false, Documents: docs, Posture: posture,
            InternalAuthorizationWaiver: waiver);

    static EngagementDocument Roe => new(EngagementDocumentKind.RulesOfEngagement, "roe.pdf");
    static EngagementDocument Nda => new(EngagementDocumentKind.Nda, "nda.pdf");

    static AddressTier Tier(string ip) => EngagementAuthorization.ClassifyIp(IPAddress.Parse(ip));

    // ---- Address-class classification ----

    [Theory]
    [InlineData("127.0.0.1", AddressTier.SelfOwned)]
    [InlineData("::1", AddressTier.SelfOwned)]
    [InlineData("169.254.10.5", AddressTier.SelfOwned)]   // IPv4 link-local
    [InlineData("10.0.0.5", AddressTier.Private)]
    [InlineData("172.16.4.2", AddressTier.Private)]
    [InlineData("172.31.255.1", AddressTier.Private)]
    [InlineData("192.168.1.1", AddressTier.Private)]
    [InlineData("100.64.0.1", AddressTier.Private)]       // CGNAT
    [InlineData("fd00::1", AddressTier.Private)]          // IPv6 ULA
    [InlineData("8.8.8.8", AddressTier.Public)]
    [InlineData("172.32.0.1", AddressTier.Public)]        // just outside 172.16/12
    [InlineData("203.0.113.7", AddressTier.Public)]
    public void ClassifyIp_TiersByOwnership(string ip, AddressTier expected) => Assert.Equal(expected, Tier(ip));

    // ---- The (posture x tier) proof matrix ----

    [Theory]
    // Self-owned: always self-attested.
    [InlineData(EngagementPosture.Lab, AddressTier.SelfOwned, ProofRequirement.SelfAttested)]
    [InlineData(EngagementPosture.Client, AddressTier.SelfOwned, ProofRequirement.SelfAttested)]
    // Public: always a document, regardless of posture (the hard gate).
    [InlineData(EngagementPosture.Lab, AddressTier.Public, ProofRequirement.DocumentRequired)]
    [InlineData(EngagementPosture.Internal, AddressTier.Public, ProofRequirement.DocumentRequired)]
    [InlineData(EngagementPosture.Client, AddressTier.Public, ProofRequirement.DocumentRequired)]
    // Private: posture decides.
    [InlineData(EngagementPosture.Lab, AddressTier.Private, ProofRequirement.SelfAttested)]
    [InlineData(EngagementPosture.Internal, AddressTier.Private, ProofRequirement.DocumentOrWaiver)]
    [InlineData(EngagementPosture.Client, AddressTier.Private, ProofRequirement.DocumentRequired)]
    public void RequiredProof_Matrix(EngagementPosture posture, AddressTier tier, ProofRequirement expected) =>
        Assert.Equal(expected, EngagementAuthorization.RequiredProof(posture, tier));

    // ---- End-to-end per-entry evaluation (the gate) ----

    static EngagementAuthorizationResult Eval(EngagementInfo e) =>
        new LocalEnvironment().EvaluateEngagementAuthorization(e);

    [Fact]
    public void Public_NoDocument_Refused()
    {
        var r = Eval(Eng(EngagementPosture.Internal, null, "", new ScopeTarget(ScopeKind.Host, "8.8.8.8")));
        Assert.False(r.Valid);
        Assert.Contains("authorizing document", string.Join(" ", r.Problems));
    }

    [Fact]
    public void Public_WithAuthorizingDocument_Allowed()
    {
        var r = Eval(Eng(EngagementPosture.Internal, [Roe], "", new ScopeTarget(ScopeKind.Host, "8.8.8.8")));
        Assert.True(r.Valid);
        Assert.Equal("document", r.Decisions.Single().Basis);
    }

    [Fact]
    public void Public_NdaOnly_Refused()
    {
        // An NDA is not an authorizing document — it must not satisfy a public target.
        var r = Eval(Eng(EngagementPosture.Internal, [Nda], "", new ScopeTarget(ScopeKind.Host, "8.8.8.8")));
        Assert.False(r.Valid);
    }

    [Fact]
    public void PublicCidr_Refused()
    {
        var r = Eval(Eng(EngagementPosture.Internal, null, "", new ScopeTarget(ScopeKind.Cidr, "203.0.113.0/24")));
        Assert.False(r.Valid);
    }

    [Fact]
    public void PrivateInternal_NoProof_Refused()
    {
        var r = Eval(Eng(EngagementPosture.Internal, null, "", new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24")));
        Assert.False(r.Valid);
        Assert.Contains("internalAuthorizationWaiver", string.Join(" ", r.Problems));
    }

    [Fact]
    public void PrivateInternal_Waiver_AllowedAndFlagged()
    {
        var r = Eval(Eng(EngagementPosture.Internal, null, "internal lab over VPN",
            new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24")));
        Assert.True(r.Valid);
        Assert.Equal("waiver", r.Decisions.Single().Basis);
        Assert.Single(r.Waived);   // surfaced as residual risk
    }

    [Fact]
    public void PrivateInternal_Document_Allowed()
    {
        var r = Eval(Eng(EngagementPosture.Internal, [Roe], "", new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24")));
        Assert.True(r.Valid);
        Assert.Equal("document", r.Decisions.Single().Basis);
    }

    [Fact]
    public void PrivateLab_SelfAttested()
    {
        var r = Eval(Eng(EngagementPosture.Lab, null, "", new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24")));
        Assert.True(r.Valid);
        Assert.Equal("self", r.Decisions.Single().Basis);
    }

    [Fact]
    public void PrivateClient_WaiverDoesNotSatisfy_DocumentRequired()
    {
        // Client posture is strict: a waiver does NOT substitute for a document on a private target.
        var r = Eval(Eng(EngagementPosture.Client, null, "trust me", new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24")));
        Assert.False(r.Valid);
    }

    [Fact]
    public void Loopback_SelfAttested_EvenInternal()
    {
        var r = Eval(Eng(EngagementPosture.Internal, null, "", new ScopeTarget(ScopeKind.Host, "127.0.0.1")));
        Assert.True(r.Valid);
        Assert.Equal("self", r.Decisions.Single().Basis);
    }

    [Fact]
    public void ExcludedEntries_AreNotGated()
    {
        // Only in-scope (included) entries are gated; an excluded public carve-out must not force a document.
        var r = Eval(Eng(EngagementPosture.Lab, null, "",
            new ScopeTarget(ScopeKind.Cidr, "10.0.0.0/8"),
            new ScopeTarget(ScopeKind.Host, "8.8.8.8", Excluded: true)));
        Assert.True(r.Valid);
        Assert.Single(r.Decisions);   // the excluded public host is not evaluated
    }
}
