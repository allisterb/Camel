namespace Camel.Tests.Environments;

using System;

using Camel.Environments;

/// <summary>
/// Unit tests for the fail-safe intensity throttle (docs/PenTestBookGapAnalysis.md #6): an engagement's optional
/// caps override the server-configured defaults, and an unspecified cap falls back to the default (never uncapped),
/// with the source recorded so the report can state it. Offline against a <see cref="LocalEnvironment"/>.
/// </summary>
public class EngagementThrottleTests
{
    static EngagementInfo Eng(int? rate = null, int? conc = null) =>
        new("eng-t", "Acme", "A", "RoE-1", DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(1),
            [new ScopeTarget(ScopeKind.Cidr, "10.0.5.0/24")],
            MaxPacketRate: rate, MaxConcurrentTargets: conc);

    static AuditEnvironment Env(int defaultRate, int defaultConc, EngagementInfo e)
    {
        var env = new LocalEnvironment { DefaultMaxPacketRate = defaultRate, DefaultMaxConcurrentTargets = defaultConc };
        Assert.True(env.TrySetEngagement(e));
        return env;
    }

    [Fact]
    public void UnspecifiedCaps_FallBackToServerDefault_NotUncapped()
    {
        var t = Env(2000, 8, Eng()).EffectiveThrottle();
        Assert.Equal(2000, t.MaxPacketRate);
        Assert.Equal(8, t.MaxConcurrentTargets);
        Assert.False(t.RateFromEngagement);
        Assert.False(t.ConcurrencyFromEngagement);
        Assert.Equal("default (appsettings)", t.RateSource);
    }

    [Fact]
    public void EngagementCaps_OverrideDefaults_AndAreMarkedAsSuch()
    {
        var t = Env(2000, 8, Eng(rate: 500, conc: 4)).EffectiveThrottle();
        Assert.Equal(500, t.MaxPacketRate);
        Assert.Equal(4, t.MaxConcurrentTargets);
        Assert.True(t.RateFromEngagement);
        Assert.True(t.ConcurrencyFromEngagement);
        Assert.Equal("engagement", t.RateSource);
    }

    [Fact]
    public void MixedCaps_EachResolvedIndependently()
    {
        // Rate from the engagement, concurrency from the default.
        var t = Env(2000, 8, Eng(rate: 750)).EffectiveThrottle();
        Assert.Equal(750, t.MaxPacketRate);
        Assert.True(t.RateFromEngagement);
        Assert.Equal(8, t.MaxConcurrentTargets);
        Assert.False(t.ConcurrencyFromEngagement);
    }

    [Fact]
    public void Defaults_FallBackToBuiltInConstants_WhenUnconfigured()
    {
        // A bare LocalEnvironment (not built via CreateFromConfig) carries the built-in safe fallbacks.
        var env = new LocalEnvironment();
        Assert.Equal(EngagementThrottle.FallbackMaxPacketRate, env.DefaultMaxPacketRate);
        Assert.Equal(EngagementThrottle.FallbackMaxConcurrentTargets, env.DefaultMaxConcurrentTargets);
    }
}
