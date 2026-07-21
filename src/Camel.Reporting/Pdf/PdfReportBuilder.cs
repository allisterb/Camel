namespace Camel.Reporting.Pdf;

using Camel.Reporting.Markdown;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;

/// <summary>
/// Generic MigraDoc building blocks shared by the DFIR and pen-test report generators — document setup, the cover
/// block, key/value grids, bordered data tables, and page furniture. Domain-specific sections (the STAR attestation,
/// the severity report card) live in the generators; these are the primitives both compose.
/// </summary>
public static class PdfReportBuilder
{
    /// <summary>Create a styled, page-sized document with the report's fonts/styles configured and metadata set.</summary>
    public static Document NewDocument(string title, string author = "Camel")
    {
        var document = new Document();
        document.Info.Title = title;
        document.Info.Author = author;
        document.Info.Subject = title;
        ReportStyles.Configure(document);
        return document;
    }

    /// <summary>Add a section (with its own A4 page setup — MigraDoc freezes <c>DefaultPageSetup</c>) that carries a
    /// "Camel · &lt;caseId&gt;" running footer with a page-of-total field.</summary>
    public static Section AddSection(Document document, string footerLabel)
    {
        var section = document.AddSection();
        var ps = document.DefaultPageSetup.Clone();
        ps.PageFormat = PageFormat.A4;
        ps.TopMargin = Unit.FromCentimeter(ReportPage.MarginCm);
        ps.BottomMargin = Unit.FromCentimeter(2.0);
        ps.LeftMargin = Unit.FromCentimeter(ReportPage.MarginCm);
        ps.RightMargin = Unit.FromCentimeter(ReportPage.MarginCm);
        section.PageSetup = ps;
        var footer = section.Footers.Primary.AddParagraph();
        footer.Format.Font.Size = 8;
        footer.Format.Font.Color = ReportColors.Muted;
        footer.Format.Borders.Top = new Border { Width = Unit.FromPoint(0.5), Color = ReportColors.Rule };
        footer.Format.SpaceBefore = Unit.FromPoint(2);
        footer.AddText(footerLabel + "    ");
        footer.AddTab();
        footer.AddText("Page ");
        footer.AddPageField();
        footer.AddText(" of ");
        footer.AddNumPagesField();
        // Right-align the page-of-total via a right tab at the usable width.
        footer.Format.TabStops.ClearAll();
        footer.Format.AddTabStop(Unit.FromPoint(ReportPage.UsablePoints), TabAlignment.Right);
        return section;
    }

    /// <summary>The report title block: big title, muted subtitle line(s).</summary>
    public static void AddTitleBlock(Section section, string title, params string[] subtitles)
    {
        var t = section.AddParagraph(title);
        t.Style = ReportStyles.Title;
        foreach (var sub in subtitles)
        {
            if (string.IsNullOrWhiteSpace(sub)) continue;
            var p = section.AddParagraph(sub);
            p.Style = ReportStyles.Subtitle;
        }
    }

    /// <summary>A small uppercase section label (e.g. "AUTHORIZATION &amp; SCOPE"), for the machine-built sections.</summary>
    public static void AddSectionLabel(Section section, string text)
    {
        var p = section.AddParagraph(text.ToUpperInvariant());
        p.Style = ReportStyles.SectionLabel;
    }

    /// <summary>A borderless two-column key/value grid (definition-list style) — the layout the Authorization section
    /// uses for engagement/window/intensity facts. Blank-valued pairs are skipped.</summary>
    public static void AddKeyValueGrid(Section section, IEnumerable<(string Key, string? Value)> pairs)
    {
        var visible = pairs.Where(p => !string.IsNullOrWhiteSpace(p.Value)).ToList();
        if (visible.Count == 0) return;

        var table = section.AddTable();
        table.Borders.Visible = false;
        table.Format.SpaceAfter = Unit.FromPoint(6);
        var usable = Usable(section.Document!);
        table.AddColumn(Unit.FromCentimeter(4.4));
        table.AddColumn(Unit.FromPoint(usable - Unit.FromCentimeter(4.4).Point));

        foreach (var (key, value) in visible)
        {
            var row = table.AddRow();
            var k = row.Cells[0].AddParagraph(key);
            k.Format.Font.Bold = true;
            k.Format.Font.Color = ReportColors.Muted;
            k.Format.Font.Size = 9.5;
            var v = row.Cells[1].AddParagraph(value ?? "");
            v.Format.Font.Size = 9.5;
        }
    }

    /// <summary>A bordered data table with a shaded header row. Each row is padded/truncated to the header width.</summary>
    public static Table AddDataTable(Section section, string[] headers, IEnumerable<string[]> rows)
    {
        var table = section.AddTable();
        table.Borders.Width = Unit.FromPoint(0.5);
        table.Borders.Color = ReportColors.Rule;
        table.Format.SpaceBefore = Unit.FromPoint(4);
        table.Format.SpaceAfter = Unit.FromPoint(8);

        var usable = Usable(section.Document!);
        for (int c = 0; c < headers.Length; c++) table.AddColumn(Unit.FromPoint(usable / headers.Length));

        var head = table.AddRow();
        head.Shading.Color = ReportColors.TableHeader;
        for (int c = 0; c < headers.Length; c++)
        {
            var p = head.Cells[c].AddParagraph(headers[c]);
            p.Format.Font.Bold = true;
            p.Format.Font.Size = 9;
        }

        foreach (var r in rows)
        {
            var row = table.AddRow();
            for (int c = 0; c < headers.Length; c++)
            {
                var text = c < r.Length ? r[c] ?? "" : "";
                var p = row.Cells[c].AddParagraph(text);
                p.Format.Font.Size = 9;
            }
        }
        return table;
    }

    /// <summary>A single body paragraph (report boilerplate: confidentiality, disclaimer).</summary>
    public static Paragraph AddBodyParagraph(Section section, string text)
    {
        var p = section.AddParagraph(text);
        p.Style = StyleNames.Normal;
        return p;
    }

    /// <summary>The usable content width of the report page in points (page width minus left/right margins).</summary>
    public static double Usable(Document document) => ReportPage.UsablePoints;
}
