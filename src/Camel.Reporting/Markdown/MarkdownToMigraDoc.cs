namespace Camel.Reporting.Markdown;

using global::Markdig;
using global::Markdig.Extensions.Tables;
using global::Markdig.Syntax;
using global::Markdig.Syntax.Inlines;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Shapes;
using MigraDoc.DocumentObjectModel.Tables;
using MdTable = global::Markdig.Extensions.Tables.Table;

/// <summary>
/// Renders an agent-authored Markdown document (<c>report.md</c>) into a MigraDoc section, preserving structure and
/// content restyled into the report's design. We use Markdig only as the <em>parser</em> (robust CommonMark + GFM via
/// the advanced-extensions pipeline) and own the <em>renderer</em>: walking Markdig's typed AST and mapping each node
/// to a styled MigraDoc element. This is the right path because MigraDoc has no HTML importer — Markdig's HTML export
/// would only help an HTML-to-PDF engine, which is the native-binary dependency we deliberately avoided.
/// </summary>
public sealed class MarkdownToMigraDoc
{
    private readonly Func<string, string?> _resolveImage;

    /// <param name="resolveImage">Maps a Markdown image URL (usually case-relative) to an absolute local file path,
    /// or returns null if it cannot be resolved (the image is then rendered as a placeholder, never silently dropped).</param>
    public MarkdownToMigraDoc(Func<string, string?>? resolveImage = null) =>
        _resolveImage = resolveImage ?? (_ => null);

    private static readonly MarkdownPipeline Pipeline =
        new MarkdownPipelineBuilder().UseAdvancedExtensions().Build();

    /// <summary>Parse <paramref name="markdown"/> and render its blocks into <paramref name="section"/> in order.</summary>
    public void Render(string markdown, Section section)
    {
        var doc = global::Markdig.Markdown.Parse(markdown ?? "", Pipeline);
        foreach (var block in doc) RenderBlock(block, section, indent: 0);
    }

    #region Blocks

    private void RenderBlock(Block block, Section section, int indent)
    {
        switch (block)
        {
            case HeadingBlock h: RenderHeading(h, section); break;
            case ParagraphBlock p: RenderParagraph(p, section, indent); break;
            case ListBlock l: RenderList(l, section, indent); break;
            case QuoteBlock q: RenderQuote(q, section, indent); break;
            case MdTable t: RenderTable(t, section); break;
            case ThematicBreakBlock: RenderRule(section); break;
            case CodeBlock c: RenderCodeBlock(c, section); break;   // FencedCodeBlock derives from CodeBlock
            case HtmlBlock html: RenderHtmlBlock(html, section); break;
            case ContainerBlock container: foreach (var child in container) RenderBlock(child, section, indent); break;
            // LinkReferenceDefinitionGroup and other non-rendering blocks: nothing to emit.
        }
    }

    private void RenderHeading(HeadingBlock h, Section section)
    {
        var style = h.Level switch
        {
            1 => StyleNames.Heading1, 2 => StyleNames.Heading2, 3 => StyleNames.Heading3,
            4 => StyleNames.Heading4, 5 => StyleNames.Heading5, _ => StyleNames.Heading6,
        };
        var p = section.AddParagraph();
        p.Style = style;
        if (h.Inline is not null) RenderInlines(h.Inline, p, new RunFormat());
    }

    private void RenderParagraph(ParagraphBlock p, Section section, int indent)
    {
        var para = section.AddParagraph();
        para.Style = StyleNames.Normal;
        if (indent > 0) para.Format.LeftIndent = Unit.FromCentimeter(0.6 * indent);
        if (p.Inline is not null) RenderInlines(p.Inline, para, new RunFormat());
    }

    private void RenderList(ListBlock list, Section section, int indent)
    {
        int number = list.IsOrdered && int.TryParse(list.OrderedStart, out var start) ? start : 1;
        foreach (var item in list)
        {
            if (item is not ListItemBlock li) continue;
            var marker = list.IsOrdered ? $"{number}. " : "•  ";
            RenderListItem(li, section, indent, marker);
            number++;
        }
    }

    // A list item: render its first paragraph inline with the bullet/number marker, then any nested blocks
    // (sub-lists, extra paragraphs) at a deeper indent. Keeps the marker attached to the item's text.
    private void RenderListItem(ListItemBlock item, Section section, int indent, string marker)
    {
        bool first = true;
        foreach (var child in item)
        {
            if (first && child is ParagraphBlock p)
            {
                var para = section.AddParagraph();
                para.Style = StyleNames.Normal;
                para.Format.LeftIndent = Unit.FromCentimeter(0.6 * (indent + 1));
                para.Format.FirstLineIndent = Unit.FromCentimeter(-0.6);
                para.AddFormattedText(marker, TextFormat.Bold);
                if (p.Inline is not null) RenderInlines(p.Inline, para, new RunFormat());
                first = false;
            }
            else
            {
                RenderBlock(child, section, indent + 1);
                first = false;
            }
        }
    }

    private void RenderQuote(QuoteBlock quote, Section section, int indent)
    {
        foreach (var child in quote)
        {
            // Render the quote's content, then style the emitted paragraphs as a ruled, indented block.
            int before = section.Elements.Count;
            RenderBlock(child, section, indent);
            for (int i = before; i < section.Elements.Count; i++)
            {
                if (section.Elements[i] is not Paragraph para) continue;
                para.Format.LeftIndent = Unit.FromCentimeter(0.6 * (indent + 1));
                para.Format.Borders.Left = new Border { Width = Unit.FromPoint(2.5), Color = ReportColors.Rule };
                para.Format.Borders.DistanceFromLeft = Unit.FromPoint(6);
                para.Format.Font.Color = ReportColors.Muted;
                para.Format.Font.Italic = true;
            }
        }
    }

    private static void RenderCodeBlock(CodeBlock code, Section section)
    {
        var para = section.AddParagraph();
        para.Style = ReportStyles.CodeBlock;
        var lines = code.Lines.Lines;
        for (int i = 0; i < code.Lines.Count; i++)
        {
            if (i > 0) para.AddLineBreak();
            para.AddText(lines[i].Slice.ToString());
        }
    }

    // Raw HTML the agent should not emit; if present, show its literal text as monospace rather than dropping it,
    // so nothing silently vanishes and the raw HTML is never interpreted.
    private static void RenderHtmlBlock(HtmlBlock html, Section section)
    {
        var para = section.AddParagraph();
        para.Style = ReportStyles.CodeBlock;
        var lines = html.Lines.Lines;
        for (int i = 0; i < html.Lines.Count; i++)
        {
            if (i > 0) para.AddLineBreak();
            para.AddText(lines[i].Slice.ToString());
        }
    }

    private static void RenderRule(Section section)
    {
        var para = section.AddParagraph();
        para.Format.SpaceBefore = Unit.FromPoint(4);
        para.Format.SpaceAfter = Unit.FromPoint(4);
        para.Format.Borders.Bottom = new Border { Width = Unit.FromPoint(0.75), Color = ReportColors.Rule };
    }

    private void RenderTable(MdTable mdTable, Section section)
    {
        var rows = mdTable.OfType<TableRow>().ToList();
        if (rows.Count == 0) return;
        int cols = rows.Max(r => r.Count);
        if (cols == 0) return;

        var table = section.AddTable();
        table.Style = StyleNames.Normal;
        table.Borders.Width = Unit.FromPoint(0.5);
        table.Borders.Color = ReportColors.Rule;
        table.Format.SpaceBefore = Unit.FromPoint(4);
        table.Format.SpaceAfter = Unit.FromPoint(8);

        // Distribute the usable page width evenly across columns; MigraDoc needs explicit column widths.
        var usable = ReportPage.UsablePoints;
        for (int c = 0; c < cols; c++) table.AddColumn(Unit.FromPoint(usable / cols));

        foreach (var mdRow in rows)
        {
            var row = table.AddRow();
            for (int c = 0; c < cols; c++)
            {
                var cell = row.Cells[c];
                var para = cell.AddParagraph();
                para.Format.Font.Size = 9;
                if (mdRow.IsHeader)
                {
                    para.Format.Font.Bold = true;
                    cell.Shading.Color = ReportColors.TableHeader;
                }
                if (c < mdRow.Count && mdRow[c] is TableCell tc)
                {
                    // A table cell holds blocks (usually one paragraph); render its inline content.
                    var block = tc.OfType<ParagraphBlock>().FirstOrDefault();
                    if (block?.Inline is not null) RenderInlines(block.Inline, para, new RunFormat());
                }
            }
        }
    }

    #endregion

    #region Inlines

    // Formatting state carried down the inline tree (emphasis nests: **_x_** is bold+italic).
    private readonly record struct RunFormat(bool Bold = false, bool Italic = false, bool Code = false)
    {
        public RunFormat With(bool? bold = null, bool? italic = null, bool? code = null) =>
            new(bold ?? Bold, italic ?? Italic, code ?? Code);
    }

    private void RenderInlines(ContainerInline container, Paragraph para, RunFormat fmt)
    {
        foreach (var inline in container) RenderInline(inline, para, fmt);
    }

    private void RenderInline(Inline inline, Paragraph para, RunFormat fmt)
    {
        switch (inline)
        {
            case LiteralInline lit: AddRun(para, lit.Content.ToString(), fmt); break;
            case EmphasisInline em: RenderInlines(em, para, EmphasisFormat(em, fmt)); break;
            case CodeInline code: AddRun(para, code.Content, fmt.With(code: true)); break;
            case LineBreakInline: para.AddLineBreak(); break;
            case LinkInline link when link.IsImage: RenderImage(link, para); break;
            case LinkInline link: RenderLink(link, para, fmt); break;
            case AutolinkInline auto: RenderAutolink(auto, para); break;
            case HtmlInline: break;   // inline raw HTML (e.g. <br>): ignore the tag rather than print it literally
            case ContainerInline c: RenderInlines(c, para, fmt); break;
            default: AddRun(para, inline.ToString() ?? "", fmt); break;
        }
    }

    private static RunFormat EmphasisFormat(EmphasisInline em, RunFormat fmt) => em.DelimiterChar switch
    {
        '~' => fmt,                                      // strikethrough: MigraDoc has no run-level strike; keep text
        _ => em.DelimiterCount >= 2 ? fmt.With(bold: true) : fmt.With(italic: true),
    };

    private static void AddRun(Paragraph para, string text, RunFormat fmt)
    {
        if (string.IsNullOrEmpty(text)) return;
        var ft = para.AddFormattedText(text);
        if (fmt.Bold) ft.Bold = true;
        if (fmt.Italic) ft.Italic = true;
        if (fmt.Code)
        {
            ft.Font.Name = ReportFonts.Mono;
            ft.Font.Size = 9;
        }
    }

    private void RenderLink(LinkInline link, Paragraph para, RunFormat fmt)
    {
        var label = InlineText(link);
        var url = link.Url ?? "";
        if (string.IsNullOrEmpty(url)) { AddRun(para, label, fmt); return; }
        var hyperlink = para.AddHyperlink(url, HyperlinkType.Web);
        var ft = hyperlink.AddFormattedText(string.IsNullOrEmpty(label) ? url : label);
        ft.Font.Color = ReportColors.Link;
        ft.Font.Underline = Underline.Single;
        if (fmt.Bold) ft.Bold = true;
        if (fmt.Italic) ft.Italic = true;
    }

    private static void RenderAutolink(AutolinkInline auto, Paragraph para)
    {
        var url = auto.Url ?? "";
        var hyperlink = para.AddHyperlink(url, HyperlinkType.Web);
        var ft = hyperlink.AddFormattedText(url);
        ft.Font.Color = ReportColors.Link;
        ft.Font.Underline = Underline.Single;
    }

    // An image resolves to a local file (relative to the case dir) and is embedded; if it cannot be resolved, a
    // labelled placeholder is emitted so a reader sees a reference existed rather than a blank.
    private void RenderImage(LinkInline link, Paragraph para)
    {
        var url = link.Url ?? "";
        var path = _resolveImage(url);
        if (path is not null && File.Exists(path))
        {
            try { para.AddImage(path); return; }
            catch { /* fall through to placeholder */ }
        }
        var alt = InlineText(link);
        AddRun(para, $"[image: {(string.IsNullOrEmpty(alt) ? url : alt)}]", new RunFormat(Italic: true));
    }

    // Flatten an inline subtree to its plain text (link/image labels, table-cell text for measuring).
    private static string InlineText(ContainerInline container)
    {
        var sb = new System.Text.StringBuilder();
        Walk(container);
        return sb.ToString();

        void Walk(Inline node)
        {
            switch (node)
            {
                case LiteralInline lit: sb.Append(lit.Content.ToString()); break;
                case CodeInline code: sb.Append(code.Content); break;
                case ContainerInline c: foreach (var child in c) Walk(child); break;
            }
        }
    }

    #endregion
}
