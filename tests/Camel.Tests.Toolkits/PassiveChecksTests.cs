using System.Collections.Generic;
using System.Linq;

using Camel.PenTest.Browser;

namespace Camel.Tests.Toolkits;

/// <summary>
/// Offline unit tests for <see cref="PassiveChecks"/>. Pure and target-free, which is the point: passive checks earn
/// their keep by being quiet, so most of these assert what is deliberately <b>NOT</b> flagged. A noisy passive layer
/// is worse than none — it buries the findings that matter.
/// </summary>
public class PassiveChecksTests
{
    const string Http = "http://app.test/page";
    const string Https = "https://app.test/page";

    static Dictionary<string, string> Hardened() => new()
    {
        ["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'",
        ["x-frame-options"] = "DENY",
        ["x-content-type-options"] = "nosniff",
        ["strict-transport-security"] = "max-age=31536000",
        ["referrer-policy"] = "no-referrer",
    };

    static ObservedCookie[] SafeCookie() =>
        [new ObservedCookie("sid", HttpOnly: true, Secure: true, SameSite: "Strict", SameSiteDeclared: "Strict")];

    static string[] Checks(PassiveFinding[] f) => [.. f.Select(x => x.Check)];

    #region Scheme awareness (the main anti-noise rule)
    [Fact]
    public void PlainHttp_ReportsTransportOnce_AndSkipsHstsAndSecureCookie()
    {
        // Over HTTP, HSTS and the cookie Secure attribute are meaningless. Flagging them would add two findings to
        // EVERY http target for no signal. The transport itself is reported instead — that is the real issue.
        var f = PassiveChecks.Analyze(Http, Hardened(),
            [new ObservedCookie("sid", HttpOnly: true, Secure: false, SameSite: "Strict")]);

        Assert.Contains("plaintext-http", Checks(f));
        Assert.DoesNotContain("missing-hsts", Checks(f));
        Assert.DoesNotContain("cookie-missing-secure", Checks(f));
    }

    [Fact]
    public void Https_DoesNotReportPlaintext_AndDoesCheckHsts()
    {
        var headers = Hardened();
        headers.Remove("strict-transport-security");
        var f = PassiveChecks.Analyze(Https, headers, SafeCookie());

        Assert.DoesNotContain("plaintext-http", Checks(f));
        Assert.Contains("missing-hsts", Checks(f));
    }
    #endregion

    #region Quiet on a well-configured response
    [Fact]
    public void HardenedHttpsResponse_ProducesNoFindings()
    {
        // The baseline that keeps the layer honest: a properly configured response must be silent.
        var f = PassiveChecks.Analyze(Https, Hardened(), SafeCookie());
        Assert.Empty(f);
    }

    [Fact]
    public void CspFrameAncestors_SatisfiesClickjacking_WithoutXFrameOptions()
    {
        // frame-ancestors is the modern equivalent of X-Frame-Options; demanding both would be a false positive.
        var headers = Hardened();
        headers.Remove("x-frame-options");
        var f = PassiveChecks.Analyze(Https, headers, SafeCookie());

        Assert.DoesNotContain("missing-clickjacking-protection", Checks(f));
    }
    #endregion

    #region Header findings
    [Fact]
    public void MissingSecurityHeaders_AreEachReported()
    {
        var f = PassiveChecks.Analyze(Https, new Dictionary<string, string>(), SafeCookie());
        var checks = Checks(f);

        Assert.Contains("missing-csp", checks);
        Assert.Contains("missing-clickjacking-protection", checks);
        Assert.Contains("missing-nosniff", checks);
        Assert.Contains("missing-hsts", checks);
        Assert.Contains("missing-referrer-policy", checks);
    }

    [Fact]
    public void HeaderLookupIsCaseInsensitive()
    {
        // HTTP header names are case-insensitive and different stacks emit different casing; missing that would
        // produce findings against servers that set the header correctly.
        var f = PassiveChecks.Analyze(Https, new Dictionary<string, string>
        {
            ["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'",
            ["X-Content-Type-Options"] = "nosniff",
            ["Strict-Transport-Security"] = "max-age=1",
            ["Referrer-Policy"] = "no-referrer",
        }, SafeCookie());

        Assert.Empty(f);
    }
    #endregion

    #region Disclosure
    [Theory]
    [InlineData("Apache/2.2.8 (Ubuntu)", true)]     // a version maps straight to CVE lookups
    [InlineData("nginx", false)]                    // a bare product name tells an attacker little — flagging it is noise
    public void ServerHeader_FlaggedOnlyWhenItDisclosesAVersion(string server, bool expected)
    {
        var headers = Hardened();
        headers["server"] = server;
        var f = PassiveChecks.Analyze(Https, headers, SafeCookie());

        Assert.Equal(expected, Checks(f).Contains("server-version-disclosure"));
        if (expected) Assert.Equal(server, f.Single(x => x.Check == "server-version-disclosure").Evidence);
    }

    [Fact]
    public void XPoweredBy_IsReportedWithItsValue()
    {
        var headers = Hardened();
        headers["x-powered-by"] = "PHP/5.3.10";
        var f = PassiveChecks.Analyze(Https, headers, SafeCookie());

        Assert.Equal("PHP/5.3.10", f.Single(x => x.Check == "tech-disclosure").Evidence);
    }
    #endregion

    #region Cookies
    [Fact]
    public void CookieWithoutHttpOnly_IsReportedWithItsName()
    {
        var f = PassiveChecks.Analyze(Https, Hardened(),
            [new ObservedCookie("PHPSESSID", HttpOnly: false, Secure: true, SameSite: "Strict")]);

        var finding = f.Single(x => x.Check == "cookie-missing-httponly");
        Assert.Equal("PHPSESSID", finding.Evidence);
        Assert.Equal("medium", finding.Severity);
    }

    [Theory]
    [InlineData("Strict", false)]
    [InlineData("Lax", false)]
    [InlineData("None", true)]
    [InlineData("", true)]      // the server sent no SameSite attribute at all
    public void SameSite_JudgedOnWhatTheServerDeclared(string declared, bool expected)
    {
        var f = PassiveChecks.Analyze(Https, Hardened(),
            [new ObservedCookie("sid", HttpOnly: true, Secure: true, SameSite: "Lax", SameSiteDeclared: declared)]);

        Assert.Equal(expected, Checks(f).Contains("cookie-weak-samesite"));
    }

    [Fact]
    public void SameSite_BrowserNormalisedLax_StillFlaggedWhenTheServerDeclaredNothing()
    {
        // REGRESSION GUARD for a real bug: Chromium normalises a cookie with no SameSite attribute to Lax, so the
        // browser's effective value is 'Lax' even when the server sent nothing. Judging on the effective value made
        // this check silently unfireable — every genuinely-unset cookie looked protected.
        var f = PassiveChecks.Analyze(Https, Hardened(),
            [new ObservedCookie("PHPSESSID", HttpOnly: true, Secure: true,
                SameSite: "Lax",              // what the browser reports
                SameSiteDeclared: "")]);      // what the server actually sent: nothing

        Assert.Contains("cookie-weak-samesite", Checks(f));
        Assert.Contains("absent", f.Single(x => x.Check == "cookie-weak-samesite").Detail);
    }

    [Fact]
    public void SameSite_NotFlaggedWhenNoSetCookieWasObserved()
    {
        // null declaration = we never saw a Set-Cookie for it, so the attribute is UNKNOWN. Reporting that as
        // "unset" would be a guess dressed as a finding; silence is the honest answer.
        var f = PassiveChecks.Analyze(Https, Hardened(),
            [new ObservedCookie("sid", HttpOnly: true, Secure: true, SameSite: "Lax", SameSiteDeclared: null)]);

        Assert.DoesNotContain("cookie-weak-samesite", Checks(f));
    }

    [Fact]
    public void EveryCookieIsChecked_NotJustTheFirst()
    {
        var f = PassiveChecks.Analyze(Https, Hardened(), [
            new ObservedCookie("a", HttpOnly: false, Secure: true, SameSite: "Strict"),
            new ObservedCookie("b", HttpOnly: false, Secure: true, SameSite: "Strict"),
        ]);

        Assert.Equal(2, f.Count(x => x.Check == "cookie-missing-httponly"));
    }

    [Fact]
    public void NoCookies_ProducesNoCookieFindings()
    {
        var f = PassiveChecks.Analyze(Https, Hardened(), []);
        Assert.Empty(f);
    }

    #region Web Storage (WSTG-CLNT-12)
    static PassiveFinding[] Storage(params StorageEntry[] entries) =>
        PassiveChecks.Analyze(Https, Hardened(), SafeCookie(), entries);

    [Fact]
    public void Jwt_InLocalStorage_IsDetectedByShape_EvenWithAnInnocuousKey()
    {
        // Shape detection matters because the key name is often meaningless ('u', 'data', 'ls.0').
        var f = Storage(new StorageEntry("localStorage", "u",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123signature"));

        var finding = Assert.Single(f);
        Assert.Equal("storage-sensitive-value", finding.Check);
        Assert.Contains("JWT", finding.Detail);
    }

    [Fact]
    public void SensitiveKeyName_IsDetected_EvenWhenTheValueLooksOrdinary()
    {
        var f = Storage(new StorageEntry("sessionStorage", "access_token", "abc123"));
        Assert.Contains("storage-sensitive-value", Checks(f));
    }

    [Theory]
    [InlineData("theme", "dark")]
    [InlineData("locale", "en-GB")]
    [InlineData("sidebar_collapsed", "true")]
    [InlineData("cart_count", "3")]
    public void OrdinaryStorage_IsNotFlagged(string key, string value)
    {
        // The anti-noise case: SPAs keep a lot of harmless state here. Flagging it all would drown the real finding.
        Assert.Empty(Storage(new StorageEntry("localStorage", key, value)));
    }

    [Fact]
    public void EmptyValue_IsNotFlagged_EvenUnderASensitiveKey()
    {
        Assert.Empty(Storage(new StorageEntry("localStorage", "auth_token", "")));
    }

    [Fact]
    public void StorageFinding_NeverContainsTheValue_OnlyTheKeyAndLength()
    {
        // The value IS the credential. A finding that quotes it puts a live token in the report and the audit log.
        const string secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.s3cr3t-signature-material";
        var finding = Assert.Single(Storage(new StorageEntry("localStorage", "id_token", secret)));

        Assert.DoesNotContain(secret, finding.Evidence);
        Assert.DoesNotContain(secret, finding.Detail);
        Assert.Contains("id_token", finding.Evidence);
        Assert.Contains(secret.Length.ToString(), finding.Evidence);
    }

    [Fact]
    public void NoStorage_ProducesNoStorageFindings() => Assert.Empty(Storage());
    #endregion

    [Fact]
    public void NothingIsRatedHigh_NoneOfItIsProvenExploitable()
    {
        // Severity discipline: a missing header is a configuration observation, not a demonstrated compromise. If
        // passive findings could be 'high' they would outrank confirmed, executed XSS in any triage.
        var f = PassiveChecks.Analyze(Http, new Dictionary<string, string> { ["server"] = "Apache/2.2.8" },
            [new ObservedCookie("sid", HttpOnly: false, Secure: false, SameSite: "")]);

        Assert.NotEmpty(f);
        Assert.DoesNotContain("high", f.Select(x => x.Severity));
    }
    #endregion
}
