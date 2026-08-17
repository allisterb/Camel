namespace Camel.Tests.Server;

using Jint;
using Jint.Native;

using Camel.PenTest.Toolkits.Models;

/// <summary>
/// The <c>table(...)</c> output helper's argument shaping (agent finding B-2). The helper used to be a typed CLR
/// delegate, so Jint's argument conversion rejected the natural call — "print this array of records" — with a host
/// error, and for an SDK model array that error escaped <c>try/catch</c> and aborted the whole <c>Execute</c>. These
/// pin the three shapes an agent writes and, above all, that a malformed call DIAGNOSES rather than throws.
/// </summary>
public class TableRenderingTests
{
    // Evaluate an expression and hand the resulting JsValue(s) to the helper exactly as the bound function would.
    private static string Render(string expression, object? clrValue = null)
    {
        var engine = new Engine();
        if (clrValue is not null) engine.SetValue("clr", clrValue);
        var value = engine.Evaluate(expression);
        return CamelMCPTools.RenderTable(value.IsArray() && expression.StartsWith("[[")
            ? [value.AsArray().Get(0), value.AsArray().Get(1)]
            : [value]);
    }

    [Fact]
    public void ArrayOfRecords_DerivesColumnsFromTheKeys()
    {
        var table = Render("[{Name:'svchost.exe', Pid:880}, {Name:'evil', Pid:1337}]");

        Assert.Contains("| Name", table);
        Assert.Contains("| Pid", table);
        Assert.Contains("| svchost.exe | 880", table);
        Assert.Contains("| evil        | 1337", table);
        Assert.Equal(2, table.Split('\n').Count(l => l.StartsWith("| ") && !l.Contains("Name")));
    }

    [Fact]
    public void ArrayOfScalars_IsOneRowEach()
    {
        // The old behaviour rendered these as ONE row of two columns.
        var table = Render("['one','two']");

        Assert.Contains("| value", table);
        Assert.Contains("| one", table);
        Assert.Contains("| two", table);
        Assert.Equal(2, table.Split('\n').Count(l => l.StartsWith("| ") && !l.Contains("value")));
    }

    [Fact]
    public void SdkModelArray_RendersItsProperties()
    {
        // The uncatchable case: a wrapped CLR array ("Object must implement IConvertible") that killed the script.
        WebTechnology[] technologies = [new("Apache", "2.2.8"), new("PHP", "5.2.4"), new("jQuery")];

        var table = Render("clr", technologies);

        Assert.Contains("| Name", table);
        Assert.Contains("| Version", table);
        Assert.Contains("| Apache | 2.2.8", table);
        Assert.Contains("| jQuery |", table);          // a null property renders empty, not "null"
    }

    [Fact]
    public void ExplicitHeaders_StillWork_AndProjectRecords()
    {
        Assert.Contains("| svchost.exe | 880", Render("[['Process','PID'], [['svchost.exe', 880]]]"));
        // Records projected by the named columns (case-insensitively), in the caller's column order.
        var projected = Render("[['PID','Process'], [{Process:'evil', PID:1337}]]");
        Assert.Contains("| PID  | Process", projected);
        Assert.Contains("| 1337 | evil", projected);
    }

    [Fact]
    public void MalformedInput_Diagnoses_AndNeverThrows()
    {
        Assert.Contains("expected an array of rows", Render("'not a table'"));
        Assert.Contains("expected an array of rows", Render("42"));
        Assert.Equal("(empty table)", Render("[]"));
        Assert.Equal("(empty table)", Render("null"));
    }
}
