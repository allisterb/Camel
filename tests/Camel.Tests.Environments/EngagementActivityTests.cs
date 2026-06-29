namespace Camel.Tests.Environments;

using System;

using Camel.Environments;

/// <summary>
/// Unit tests for the engagement activity gate (docs/PenTestBookGapAnalysis.md #5): the (posture-independent)
/// allow-list of offensive <see cref="ActivityClass"/>es. Recon/Scan/Enumerate/VulnScan are an always-permitted
/// baseline; intrusive classes need explicit opt-in; DoS and social engineering are only ever permitted when
/// listed. Scope answers "where", this answers "what". Offline against a <see cref="LocalEnvironment"/>.
/// </summary>
public class EngagementActivityTests
{
    static EngagementInfo Eng(params ActivityClass[] allowed) =>
        new("eng-a", "Acme", "A", "RoE-1", DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(1),
            [new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24")],
            AllowedActivities: allowed.Length == 0 ? null : allowed);

    static AuditEnvironment Armed(params ActivityClass[] allowed)
    {
        var env = new LocalEnvironment();
        Assert.True(env.TrySetEngagement(Eng(allowed)));
        return env;
    }

    [Theory]
    [InlineData(ActivityClass.Recon)]
    [InlineData(ActivityClass.Scan)]
    [InlineData(ActivityClass.Enumerate)]
    [InlineData(ActivityClass.VulnScan)]
    public void Baseline_AlwaysAllowed_NoOptIn(ActivityClass a)
    {
        var env = Armed();                       // no AllowedActivities supplied
        Assert.True(env.IsActivityAllowed(a));
        env.FailIfActivityNotAuthorized(a);      // no throw
    }

    [Theory]
    [InlineData(ActivityClass.Exploit)]
    [InlineData(ActivityClass.CredentialAttack)]
    [InlineData(ActivityClass.PostExploit)]
    [InlineData(ActivityClass.Exfiltration)]
    [InlineData(ActivityClass.SocialEngineering)]
    [InlineData(ActivityClass.DenialOfService)]
    public void Intrusive_DeniedByDefault(ActivityClass a)
    {
        var env = Armed();
        Assert.False(env.IsActivityAllowed(a));
        Assert.Throws<ActivityNotAuthorizedException>(() => env.FailIfActivityNotAuthorized(a));
    }

    [Fact]
    public void OptIn_AuthorizesListedIntrusiveClasses_OnlyThose()
    {
        var env = Armed(ActivityClass.Exploit, ActivityClass.CredentialAttack);
        env.FailIfActivityNotAuthorized(ActivityClass.Exploit);          // listed -> ok
        env.FailIfActivityNotAuthorized(ActivityClass.CredentialAttack); // listed -> ok
        env.FailIfActivityNotAuthorized(ActivityClass.Scan);             // baseline still ok
        Assert.Throws<ActivityNotAuthorizedException>(                   // not listed -> denied
            () => env.FailIfActivityNotAuthorized(ActivityClass.PostExploit));
    }

    [Fact]
    public void DosAndSocialEngineering_RequireExplicitListing()
    {
        var dos = Armed(ActivityClass.DenialOfService);
        dos.FailIfActivityNotAuthorized(ActivityClass.DenialOfService);  // explicitly listed -> ok
        Assert.Throws<ActivityNotAuthorizedException>(                   // SE not listed -> still denied
            () => dos.FailIfActivityNotAuthorized(ActivityClass.SocialEngineering));
    }

    [Fact]
    public void FailClosed_NoEngagement_Throws()
    {
        var env = new LocalEnvironment();
        Assert.False(env.IsActivityAllowed(ActivityClass.Scan));
        Assert.Throws<EngagementRequiredException>(() => env.FailIfActivityNotAuthorized(ActivityClass.Scan));
    }

    [Fact]
    public void EffectiveActivities_IsBaselinePlusAdditions()
    {
        var e = Eng(ActivityClass.Exploit);
        Assert.Contains(ActivityClass.Scan, e.EffectiveActivities);       // baseline
        Assert.Contains(ActivityClass.Exploit, e.EffectiveActivities);    // added
        Assert.DoesNotContain(ActivityClass.DenialOfService, e.EffectiveActivities);
    }
}
