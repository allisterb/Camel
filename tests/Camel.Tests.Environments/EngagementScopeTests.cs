namespace Camel.Tests.Environments;

using System;

using Camel.Environments;

/// <summary>
/// Unit tests for the red-team engagement scope gate on <see cref="AuditEnvironment"/> (the offensive
/// counterpart of the evidence-spoliation guard): scope matching (host/CIDR/domain/URL), exclusion precedence,
/// the validity window, fail-closed behaviour when no engagement is registered, write-once registration, and
/// the pre-registration <see cref="AuditEnvironment.ValidateEngagement"/> preflight. Runs offline against a
/// <see cref="LocalEnvironment"/>; no host needed.
/// </summary>
public class EngagementScopeTests
{
    // An engagement valid right now (window: an hour either side), with the supplied scope.
    static EngagementInfo Eng(params ScopeTarget[] scope) =>
        new("eng-1", "Acme", "J. Authorizer", "RoE-2026-001",
            DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(1), scope);

    static AuditEnvironment Armed(params ScopeTarget[] scope)
    {
        var env = new LocalEnvironment();
        Assert.True(env.TrySetEngagement(Eng(scope)));
        return env;
    }

    [Fact]
    public void FailClosed_NoEngagement_Throws()
    {
        var env = new LocalEnvironment();
        Assert.False(env.EngagementRegistered);
        Assert.Throws<EngagementRequiredException>(() => env.FailIfOutOfScope("10.0.0.1"));
    }

    [Fact]
    public void HostScope_MatchesExact_RefusesOther()
    {
        var env = Armed(new ScopeTarget(ScopeKind.Host, "10.0.0.5"));
        env.FailIfOutOfScope("10.0.0.5");                                       // in scope: no throw
        Assert.Throws<OutOfScopeException>(() => env.FailIfOutOfScope("10.0.0.6"));
    }

    [Fact]
    public void CidrScope_ContainsAddress()
    {
        var env = Armed(new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24"));
        Assert.True(env.EvaluateScope("10.0.5.21").InScope);
        Assert.False(env.EvaluateScope("10.0.6.1").InScope);
    }

    [Fact]
    public void DomainScope_MatchesSubdomain_NotSuffixCollision()
    {
        var env = Armed(new ScopeTarget(ScopeKind.Domain, "lab.local"));
        Assert.True(env.EvaluateScope("web01.lab.local").InScope);
        Assert.True(env.EvaluateScope("lab.local").InScope);
        Assert.False(env.EvaluateScope("evillab.local").InScope);   // must anchor on a dot boundary
        Assert.False(env.EvaluateScope("lab.local.evil.com").InScope);
    }

    [Fact]
    public void UrlScope_MatchesByHost()
    {
        var env = Armed(new ScopeTarget(ScopeKind.Url, "https://app.lab.local/login"));
        Assert.True(env.EvaluateScope("http://app.lab.local/admin").InScope);   // same host, different path/scheme
        Assert.False(env.EvaluateScope("http://other.lab.local/").InScope);
    }

    [Fact]
    public void Exclusion_WinsOverInclusion()
    {
        var env = Armed(
            new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24"),
            new ScopeTarget(ScopeKind.Host, "10.0.5.99", Excluded: true));   // carve-out inside the range
        Assert.True(env.EvaluateScope("10.0.5.21").InScope);
        Assert.False(env.EvaluateScope("10.0.5.99").InScope);
        Assert.Throws<OutOfScopeException>(() => env.FailIfOutOfScope("10.0.5.99"));
    }

    [Fact]
    public void OutsideWindow_RefusesInScopeTarget()
    {
        var env = new LocalEnvironment();
        // Window already closed: even an authorized target is refused.
        env.TrySetEngagement(new EngagementInfo("eng-x", "Acme", "A", "RoE",
            DateTime.UtcNow.AddHours(-3), DateTime.UtcNow.AddHours(-1),
            [new ScopeTarget(ScopeKind.Host, "10.0.0.5")]));
        Assert.False(env.EvaluateScope("10.0.0.5").InScope);
        Assert.Throws<OutOfScopeException>(() => env.FailIfOutOfScope("10.0.0.5"));
    }

    [Fact]
    public void Engagement_IsWriteOnce()
    {
        var env = Armed(new ScopeTarget(ScopeKind.Host, "10.0.0.5"));
        Assert.False(env.TrySetEngagement(Eng(new ScopeTarget(ScopeKind.Cidr, "0.0.0.0/0"))));   // refused
        Assert.Throws<OutOfScopeException>(() => env.FailIfOutOfScope("8.8.8.8"));                 // scope unchanged
    }

    [Fact]
    public void Validate_RejectsBadEngagements()
    {
        var env = new LocalEnvironment();
        // Empty scope -> nothing authorized.
        Assert.False(env.ValidateEngagement(Eng()).Valid);
        // Inverted window.
        Assert.False(env.ValidateEngagement(new EngagementInfo("e", "c", "a", "r",
            DateTime.UtcNow.AddHours(1), DateTime.UtcNow.AddHours(-1),
            [new ScopeTarget(ScopeKind.Host, "h")])).Valid);
        // Unparseable CIDR.
        Assert.False(env.ValidateEngagement(Eng(new ScopeTarget(ScopeKind.Cidr, "10.0.0.0/99"))).Valid);
        // A well-formed engagement passes.
        Assert.True(env.ValidateEngagement(Eng(new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24"))).Valid);
    }
}
