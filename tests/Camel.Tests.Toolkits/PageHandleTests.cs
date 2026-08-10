using System.Linq;
using System.Text.Json;

using Camel.PenTest.Toolkits;
using Camel.PenTest.Toolkits.Models;

namespace Camel.Tests.Toolkits;

/// <summary>
/// Offline unit tests for the pure mappers behind the browser DOM API (<see cref="PageHandle"/>): the
/// JsonElement→model shaping and the storage secret-redaction. The live browser methods (Open/Query/… against a real
/// page) are exercised by the host-gated live tests; this covers the shaping/masking logic that would otherwise only
/// be reachable through a browser. See docs/BrowserDomApiDesign.md.
/// </summary>
public class PageHandleTests
{
    static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;

    #region Libraries
    [Fact]
    public void MapLibraries_ShapesNameVersionGlobal_AndNullVersion()
    {
        var libs = PageHandle.MapLibraries(J(
            """[{"name":"jQuery","version":"1.12.4","global":"$"},{"name":"Next.js","version":null,"global":"__NEXT_DATA__"}]"""));

        Assert.Equal(2, libs.Length);
        Assert.Equal(new LibraryInfo("jQuery", "1.12.4", "$"), libs[0]);
        Assert.Equal("Next.js", libs[1].Name);
        Assert.Null(libs[1].Version);          // present global, no readable version
    }

    [Fact]
    public void MapLibraries_NonArray_IsEmpty() => Assert.Empty(PageHandle.MapLibraries(J("{}")));
    #endregion

    #region Forms
    [Fact]
    public void MapForms_ShapesFieldsAndCsrfFlag()
    {
        var forms = PageHandle.MapForms(J(
            """
            [{"action":"https://app.test/login","method":"POST","hasCsrfToken":true,
              "fields":[{"name":"user","type":"text","required":true,"pattern":"[a-z]+"},
                        {"name":"csrf","type":"hidden","required":false,"pattern":null}]}]
            """));

        var f = Assert.Single(forms);
        Assert.Equal("POST", f.Method);
        Assert.True(f.HasCsrfToken);
        Assert.Equal(2, f.Fields.Length);
        Assert.True(f.Fields[0].Required);
        Assert.Equal("[a-z]+", f.Fields[0].Pattern);
        Assert.False(f.Fields[1].Required);
        Assert.Null(f.Fields[1].Pattern);
    }

    [Fact]
    public void MapForms_MissingFields_YieldEmptyArray()
    {
        var f = Assert.Single(PageHandle.MapForms(J("""[{"action":"/x","method":"GET"}]""")));
        Assert.Empty(f.Fields);
        Assert.False(f.HasCsrfToken);
    }
    #endregion

    #region Elements
    [Fact]
    public void MapElements_ShapesTagAttributesText_AndAttributeLookup()
    {
        var els = PageHandle.MapElements(J(
            """[{"tag":"a","text":"Home","attributes":[{"name":"href","value":"/home"},{"name":"class","value":"nav"}]}]"""));

        var el = Assert.Single(els);
        Assert.Equal("a", el.Tag);
        Assert.Equal("Home", el.Text);
        Assert.Equal("/home", el.Attribute("HREF"));   // case-insensitive convenience lookup
        Assert.Null(el.Attribute("id"));
    }
    #endregion

    #region Storage redaction
    [Theory]
    [InlineData("authToken", true)]
    [InlineData("jwt", true)]
    [InlineData("api_key", true)]
    [InlineData("SESSIONID", true)]
    [InlineData("csrf-token", true)]
    [InlineData("theme", false)]
    [InlineData("locale", false)]
    public void LooksSecret_FlagsSensitiveKeys(string key, bool secret) =>
        Assert.Equal(secret, PageHandle.LooksSecret(key, "somevalue"));

    [Fact]
    public void LooksSecret_EmptyValue_IsNotSecret() => Assert.False(PageHandle.LooksSecret("token", ""));

    [Fact]
    public void MapStorage_RedactsSecretValues_ByLength_KeepsOrdinaryOnes()
    {
        var dump = PageHandle.MapStorage(J(
            """
            {"local":[{"key":"authToken","value":"eyJhbGciOi.secret.value"},{"key":"theme","value":"dark"}],
             "session":[{"key":"cartId","value":"42"}]}
            """));

        var token = dump.Local.Single(i => i.Key == "authToken");
        Assert.True(token.Redacted);
        Assert.DoesNotContain("secret", token.Value);            // the value is not surfaced
        Assert.Contains("len=", token.Value);                    // reported as present-with-length

        var theme = dump.Local.Single(i => i.Key == "theme");
        Assert.False(theme.Redacted);
        Assert.Equal("dark", theme.Value);

        Assert.Equal("42", dump.Session.Single().Value);
    }
    #endregion

    #region Listeners + endpoint dedup
    [Fact]
    public void MapListeners_ExtractsDistinctTypes()
    {
        var types = PageHandle.MapListeners(J(
            """{"listeners":[{"type":"click"},{"type":"message"},{"type":"click"}]}"""));
        Assert.Equal(["click", "message"], types);               // deduped, order preserved
    }

    [Fact]
    public void MapListeners_NoListeners_IsEmpty() => Assert.Empty(PageHandle.MapListeners(J("{}")));

    [Fact]
    public void Dedup_Endpoints_ByMethodAndUrl_PreservingOrder()
    {
        var deduped = PageHandle.Dedup(
        [
            new ObservedEndpoint("GET", "https://app.test/api/a", "fetch"),
            new ObservedEndpoint("POST", "https://app.test/api/b", "xhr"),
            new ObservedEndpoint("GET", "https://app.test/api/a", "fetch"),   // dup
        ]);

        Assert.Equal(2, deduped.Length);
        Assert.Equal("https://app.test/api/a", deduped[0].Url);
        Assert.Equal("https://app.test/api/b", deduped[1].Url);
    }
    #endregion
}
