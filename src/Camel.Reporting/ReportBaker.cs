namespace Camel.Reporting;

using Camel.Reporting.Model;
using Camel.Reporting.Reports;
using MigraDoc.Rendering;
using PdfSharp.Fonts;

/// <summary>
/// The entry point the CLI bake pipeline calls: given a baked case directory, load its artifacts, pick the DFIR vs
/// pen-test layout by the same gate the interactive viewer uses (presence of an engagement), render the MigraDoc
/// document, and write <c>reports/report.pdf</c>. Fully deterministic and agent-independent — the agent produced the
/// narrative and the machine data; this compiles them into the final PDF.
/// </summary>
public static class ReportBaker
{
    // The PDFsharp-MigraDoc metapackage is the cross-platform Core build (no built-in font resolution). On Windows,
    // point it at the system font store so the report's Arial / Courier New resolve. On Linux (e.g. a SIFT host) this
    // property is a no-op and a custom IFontResolver with an embedded font would be needed — a known deployment
    // caveat for baking the PDF off-Windows.
    static ReportBaker()
    {
        if (OperatingSystem.IsWindows())
            GlobalFontSettings.UseWindowsFontsUnderWindows = true;
    }

    /// <summary>Bake <paramref name="caseDir"/>'s PDF report to <c>reports/report.pdf</c> (created if missing).
    /// Returns the path written, or null when there is nothing to render (no narrative and no engagement — an
    /// un-started case).</summary>
    public static string? Bake(string caseDir)
    {
        var artifacts = CaseArtifacts.Load(caseDir);
        if (!artifacts.IsPenTest && string.IsNullOrWhiteSpace(artifacts.ReportMarkdown))
            return null;   // DFIR case with no narrative yet — nothing to compile.

        var outPath = Path.Combine(artifacts.CaseDir, "reports", "report.pdf");
        return BakeTo(artifacts, outPath);
    }

    /// <summary>Render <paramref name="artifacts"/> to a PDF at <paramref name="outPath"/> and return the path.</summary>
    public static string BakeTo(CaseArtifacts artifacts, string outPath)
    {
        var document = artifacts.IsPenTest
            ? PenTestReportGenerator.Build(artifacts)
            : DfirReportGenerator.Build(artifacts);

        var renderer = new PdfDocumentRenderer { Document = document };
        renderer.RenderDocument();
        Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
        renderer.PdfDocument.Save(outPath);
        return outPath;
    }
}
