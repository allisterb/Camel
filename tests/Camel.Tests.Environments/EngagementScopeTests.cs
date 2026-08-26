namespace Camel.Tests.Environments;

using System;
using System.IO;

using Camel;
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

    /// <summary>
    /// Every refusal must leave a `scope-violation` record, not just refuse. Found by an E2E agent run (B-0): the gate
    /// blocked two out-of-scope calls and wrote zero events, so the one question a scope gate's trail exists to
    /// answer — did this engagement ever reach outside scope? — could only be answered with silence.
    /// </summary>
    [Theory]
    [InlineData(false)]   // armed engagement, out-of-scope target
    [InlineData(true)]    // fail-closed: nothing registered at all
    public void RefusedTarget_IsRecordedAsScopeViolation(bool failClosed)
    {
        var dir = Path.Combine(Path.GetTempPath(), "camel_audit_" + Guid.NewGuid().ToString("N"));
        Runtime.WithAuditLog(dir);
        try
        {
            using (Runtime.PushAuditProperty("CaseId", "scope-audit"))
            {
                var env = failClosed ? new LocalEnvironment() : Armed(new ScopeTarget(ScopeKind.Host, "10.0.0.5"));
                Assert.ThrowsAny<Exception>(() => env.FailIfOutOfScope("203.0.113.10"));
                Assert.ThrowsAny<Exception>(() => env.FailIfRangeOutOfScope("203.0.113.0/24"));
            }
            Runtime.CloseAndFlushAuditLog();

            var content = File.ReadAllText(Path.Combine(dir, "audit-scope-audit.clef"));
            Assert.Equal(2, content.Split("scope-violation").Length - 1);   // both refusals recorded
            Assert.Contains("203.0.113.10", content);                       // the target reached for
            Assert.Contains("203.0.113.0/24", content);
            Assert.Contains(failClosed ? "fail-closed" : "No authorized scope entry", content);   // and why
        }
        finally
        {
            Runtime.CloseAndFlushAuditLog();
            try { Directory.Delete(dir, true); } catch { }
        }
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

    // ---- Range (CIDR-sweep) scope, for host discovery ----

    [Fact]
    public void RangeScope_SubnetInsideAuthorizedRange_InScope()
    {
        var env = Armed(new ScopeTarget(ScopeKind.Cidr, "10.0.0.0/16"));
        Assert.True(env.EvaluateRangeScope("10.0.5.0/24").InScope);   // /24 fully within the /16
        Assert.True(env.EvaluateRangeScope("10.0.0.0/16").InScope);   // equal range is contained
    }

    [Fact]
    public void RangeScope_BroaderOrUnrelatedRange_OutOfScope()
    {
        var env = Armed(new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24"));
        Assert.False(env.EvaluateRangeScope("10.0.0.0/16").InScope);    // a /16 is NOT inside a /24
        Assert.False(env.EvaluateRangeScope("192.168.1.0/24").InScope); // unrelated range
        Assert.Throws<OutOfScopeException>(() => env.FailIfRangeOutOfScope("10.0.0.0/16"));
    }

    [Fact]
    public void RangeScope_WhollyExcludedRange_Refused()
    {
        var env = Armed(
            new ScopeTarget(ScopeKind.Cidr, "10.0.0.0/16"),
            new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24", Excluded: true));
        Assert.False(env.EvaluateRangeScope("10.0.5.0/24").InScope);    // the whole sub-range is excluded
        Assert.True(env.EvaluateRangeScope("10.0.6.0/24").InScope);     // a sibling range is still fine
    }

    [Fact]
    public void RangeScope_PartialExclusion_SweepAllowed_HostDropped()
    {
        // A single excluded host inside the range does NOT block the sweep; the per-host check drops it instead.
        var env = Armed(
            new ScopeTarget(ScopeKind.Cidr, "10.0.0.0/16"),
            new ScopeTarget(ScopeKind.Host, "10.0.5.99", Excluded: true));
        Assert.True(env.EvaluateRangeScope("10.0.5.0/24").InScope);     // sweep authorized
        Assert.False(env.EvaluateScope("10.0.5.99").InScope);          // ...but the carve-out host is out
        Assert.True(env.EvaluateScope("10.0.5.21").InScope);
    }

    [Fact]
    public void RangeScope_FailClosed_NoEngagement()
    {
        Assert.Throws<EngagementRequiredException>(() => new LocalEnvironment().FailIfRangeOutOfScope("10.0.5.0/24"));
    }

    // ---- External-disclosure gate (target-keyed KB queries, e.g. Shodan) ----

    [Fact]
    public void Disclosure_Forbidden_ByDefault()
    {
        var env = Armed(new ScopeTarget(ScopeKind.Host, "10.0.0.5"));   // default engagement: disclosure NOT allowed
        Assert.False(env.ExternalDisclosureAllowed);
        Assert.Throws<ExternalDisclosureForbiddenException>(() => env.FailIfExternalDisclosureForbidden());
    }

    [Fact]
    public void Disclosure_Allowed_WhenEngagementOptsIn()
    {
        var env = new LocalEnvironment();
        env.TrySetEngagement(new EngagementInfo("eng-d", "Acme", "A", "RoE",
            DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(1),
            [new ScopeTarget(ScopeKind.Host, "10.0.0.5")], AllowExternalTargetDisclosure: true));
        Assert.True(env.ExternalDisclosureAllowed);
        env.FailIfExternalDisclosureForbidden();   // no throw
    }

    [Fact]
    public void Disclosure_FailClosed_NoEngagement()
    {
        Assert.Throws<EngagementRequiredException>(() => new LocalEnvironment().FailIfExternalDisclosureForbidden());
    }

    /// <summary>
    /// A refused DISCLOSURE is recorded too, and names the asset that was withheld: refusing to hand a client target
    /// to a third party is exactly the kind of restraint the engagement's attestation should be able to evidence.
    /// Recorded as `scope-violation` (the same tally the report's compliance attestation counts), with a reason that
    /// says it was a disclosure refusal so a reader never mistakes it for an out-of-scope target.
    /// </summary>
    [Fact]
    public void RefusedDisclosure_IsRecordedAsScopeViolation_NamingTheWithheldAsset()
    {
        var dir = Path.Combine(Path.GetTempPath(), "camel_audit_" + Guid.NewGuid().ToString("N"));
        Runtime.WithAuditLog(dir);
        try
        {
            using (Runtime.PushAuditProperty("CaseId", "disclosure-audit"))
            {
                var armed = Armed(new ScopeTarget(ScopeKind.Host, "10.0.0.5"));      // in scope, disclosure NOT opted in
                Assert.Throws<ExternalDisclosureForbiddenException>(() => armed.FailIfExternalDisclosureForbidden("10.0.0.5"));
                Assert.Throws<EngagementRequiredException>(() => new LocalEnvironment().FailIfExternalDisclosureForbidden("acme.example"));
            }
            Runtime.CloseAndFlushAuditLog();

            var content = File.ReadAllText(Path.Combine(dir, "audit-disclosure-audit.clef"));
            Assert.Equal(2, content.Split("scope-violation").Length - 1);
            Assert.Contains("10.0.0.5", content);              // the asset that would have gone to the third party
            Assert.Contains("acme.example", content);
            Assert.Contains("External disclosure refused", content);   // and that it was a disclosure, not an out-of-scope target
        }
        finally
        {
            Runtime.CloseAndFlushAuditLog();
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Fact]
    public void GateRefusal_ToString_IsTheReasonOnly_NotAStackTrace()
    {
        // An E2E agent run flagged that a DESIGNED refusal surfaced a full .NET stack trace with absolute source
        // paths (…OffensiveToolkit.cs:line 86) to the operator — noise on an expected outcome, plus path disclosure.
        // The gate exceptions' string form (what String(e) and the Execute error path surface) must be just the
        // reason: legible, no "   at …" frames, no source path.
        Exception[] refusals =
        [
            new EngagementRequiredException(),
            new ActivityNotAuthorizedException(ActivityClass.Exploit),
            new ExternalDisclosureForbiddenException(),
        ];
        foreach (var ex in refusals)
        {
            var s = ex.ToString();
            Assert.Equal(ex.Message, s);                     // string form == the reason, nothing appended
            Assert.DoesNotContain("   at ", s);              // no stack frames
            Assert.DoesNotContain(".cs:line", s);            // no source path / line disclosure
            Assert.IsAssignableFrom<GateRefusalException>(ex);
        }
    }
}
