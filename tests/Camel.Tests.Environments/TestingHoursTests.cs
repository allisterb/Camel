namespace Camel.Tests.Environments;

using System;
using System.Linq;

using Camel.Environments;

/// <summary>
/// Unit tests for the recurring testing-hours window (docs/PenTestBookGapAnalysis.md #7, lean): the timezone-aware,
/// weekday-masked, midnight-wrap-aware <see cref="TestingHours.Contains"/> check and its registration-time
/// <see cref="TestingHours.Problems"/> validation. Enforcement is advisory (status + warning), but the time logic
/// is exact. Deterministic — fixed UTC instants; the one timezone-conversion case uses a January (no-DST) instant.
/// </summary>
public class TestingHoursTests
{
    // Thursday 2026-01-15 (2026-01-01 is a Thursday; +14 days = Thursday); Monday 2026-01-19.
    static DateTime Utc(int day, int hour, int min = 0) => new(2026, 1, day, hour, min, 0, DateTimeKind.Utc);

    [Fact]
    public void NullWindow_AlwaysWithin()
    {
        var e = new EngagementInfo("e", "c", "a", "r", DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(1),
            [new ScopeTarget(ScopeKind.Cidr, "10.0.0.0/24")]);   // no TestingHours
        Assert.True(e.IsWithinTestingHours(Utc(15, 3)));
    }

    [Fact]
    public void TimeOfDay_Utc_InsideAndOutside()
    {
        var th = new TestingHours("09:00", "17:00");   // empty TimeZone = UTC, any day
        Assert.True(th.Contains(Utc(15, 12)));         // 12:00 UTC -> inside
        Assert.False(th.Contains(Utc(15, 20)));        // 20:00 UTC -> outside
        Assert.False(th.Contains(Utc(15, 8, 59)));     // just before open
    }

    [Fact]
    public void WeekdayMask_OnlyListedDays()
    {
        var th = new TestingHours(Days: ["Mon"]);      // any time, Mondays only
        Assert.False(th.Contains(Utc(15, 12)));        // Thursday
        Assert.True(th.Contains(Utc(19, 12)));         // Monday
    }

    [Fact]
    public void OvernightWindow_WrapsMidnight()
    {
        var th = new TestingHours("22:00", "06:00");   // wraps midnight
        Assert.True(th.Contains(Utc(15, 23)));         // 23:00 -> inside
        Assert.True(th.Contains(Utc(15, 3)));          // 03:00 -> inside
        Assert.False(th.Contains(Utc(15, 12)));        // 12:00 -> outside
    }

    [Fact]
    public void TimeZone_IsApplied_NotJustUtc()
    {
        // 09:00-17:00 America/New_York; in January NY = EST (UTC-5), so the window is 14:00-22:00 UTC.
        var th = new TestingHours("09:00", "17:00", null, "America/New_York");
        Assert.True(th.Contains(Utc(15, 21)));   // 21:00 UTC = 16:00 EST -> inside  (would be OUTSIDE if read as UTC)
        Assert.False(th.Contains(Utc(15, 13)));  // 13:00 UTC = 08:00 EST -> outside (would be INSIDE if read as UTC)
    }

    [Fact]
    public void Problems_FlagsMalformedWindow()
    {
        Assert.Contains(new TestingHours(TimeZone: "Not/AZone").Problems(), p => p.Contains("time zone"));
        Assert.Contains(new TestingHours("9 oclock", "17:00").Problems(), p => p.Contains("startLocal"));
        Assert.Contains(new TestingHours(Days: ["Funday"]).Problems(), p => p.Contains("days"));
        Assert.Empty(new TestingHours("09:00", "17:00", ["Mon", "Fri"], "America/New_York").Problems());
    }
}
