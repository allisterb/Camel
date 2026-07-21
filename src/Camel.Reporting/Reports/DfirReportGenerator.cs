namespace Camel.Reporting.Reports;

using Camel.Reporting.Markdown;
using Camel.Reporting.Model;
using Camel.Reporting.Pdf;
using MigraDoc.DocumentObjectModel;

/// <summary>
/// Builds the DFIR incident-report PDF from a baked case. A DFIR case has no engagement, so there is no
/// Authorization &amp; Scope section; the document is the agent-authored <c>report.md</c> (the incident report with
/// its evidence table, timeline, and findings) rendered under a title/confidentiality cover, with
/// <c>accuracy.md</c> as an appendix. The machine-built compliance layer is what distinguishes the pen-test STAR;
/// here the narrative is the report.
/// </summary>
public static class DfirReportGenerator
{
    public static Document Build(CaseArtifacts artifacts)
    {
        var document = PdfReportBuilder.NewDocument($"DFIR Incident Report — {artifacts.CaseId}", "Camel");
        var section = PdfReportBuilder.AddSection(document, $"Camel · {artifacts.CaseId} · CONFIDENTIAL");

        PdfReportBuilder.AddSectionLabel(section, "Confidential — Incident Response");
        PdfReportBuilder.AddTitleBlock(section, "DFIR Incident Report", $"Case {artifacts.CaseId}");
        PdfReportBuilder.AddKeyValueGrid(section,
        [
            ("Case id", artifacts.CaseId),
            ("Report generated", DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'")),
            ("Audit events", artifacts.Events.Count.ToString()),
        ]);

        var conf = section.AddParagraph("Confidentiality statement");
        conf.Style = StyleNames.Heading3;
        PdfReportBuilder.AddBodyParagraph(section,
            "This document contains confidential incident-response findings and is distributed on a need-to-know " +
            "basis. It must not be disclosed or reproduced, in whole or in part, without authorization. All evidence " +
            "was handled read-only under chain of custody as recorded in the case audit trail.");

        if (!string.IsNullOrWhiteSpace(artifacts.ReportMarkdown))
        {
            section.AddPageBreak();
            var renderer = new MarkdownToMigraDoc(url => ResolveImage(artifacts.CaseDir, url));
            renderer.Render(artifacts.ReportMarkdown!, section);
        }

        if (!string.IsNullOrWhiteSpace(artifacts.AccuracyMarkdown))
        {
            section.AddPageBreak();
            var h = section.AddParagraph("Appendix: Accuracy Self-Assessment");
            h.Style = StyleNames.Heading1;
            var renderer = new MarkdownToMigraDoc(url => ResolveImage(artifacts.CaseDir, url));
            renderer.Render(artifacts.AccuracyMarkdown!, section);
        }

        return document;
    }

    private static string? ResolveImage(string caseDir, string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (url.StartsWith("http://") || url.StartsWith("https://") || url.StartsWith("data:")) return null;
        try
        {
            if (Path.IsPathRooted(url)) return url;
            var fromReports = Path.Combine(caseDir, "reports", url);
            return File.Exists(fromReports) ? fromReports : Path.Combine(caseDir, url);
        }
        catch { return null; }
    }
}
