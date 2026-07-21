namespace Camel.Reporting.Markdown;

using MigraDoc.DocumentObjectModel;

// Placed in the Camel.Reporting.Markdown namespace so the renderer above can reference these unqualified; the PDF
// generators use them via `using Camel.Reporting.Markdown`. Kept together because they are the shared visual
// vocabulary of the whole report (Markdown body + machine-built compliance sections).

/// <summary>Page geometry shared by the document factory, the per-section page setup, and any code that needs the
/// usable content width (MigraDoc requires explicit column widths on tables). A4 portrait with even margins.</summary>
public static class ReportPage
{
    public const double WidthCm = 21.0;    // A4 portrait width
    public const double MarginCm = 2.2;

    /// <summary>Usable content width in points (page width minus left+right margins).</summary>
    public static double UsablePoints => Unit.FromCentimeter(WidthCm - 2 * MarginCm).Point;
}

/// <summary>Font families the report uses. Chosen for ubiquity on the Windows build; on Linux the PDFsharp GDI build
/// needs a font resolver or these families installed (a known deployment caveat — see the reporting notes).</summary>
public static class ReportFonts
{
    public const string Body = "Arial";
    public const string Mono = "Courier New";
}

/// <summary>The report palette (print-tuned versions of the viewer's severity/accent colors).</summary>
public static class ReportColors
{
    public static readonly Color Ink = new(0x1a, 0x1a, 0x1a);
    public static readonly Color Muted = new(0x66, 0x66, 0x66);
    public static readonly Color Rule = new(0xcc, 0xcc, 0xcc);
    public static readonly Color Link = new(0x14, 0x5a, 0xb0);
    public static readonly Color Accent = new(0x0d, 0x47, 0x7a);
    public static readonly Color TableHeader = new(0xf0, 0xf2, 0xf4);

    public static readonly Color Critical = new(0xa0, 0x10, 0x30);
    public static readonly Color High = new(0xd1, 0x4b, 0x16);
    public static readonly Color Medium = new(0xb8, 0x86, 0x00);
    public static readonly Color Low = new(0x1f, 0x6f, 0x8b);
    public static readonly Color Info = new(0x6b, 0x72, 0x80);

    /// <summary>The print color for a normalized severity band (critical/high/medium/low/info/unknown).</summary>
    public static Color ForSeverity(string band) => band.ToLowerInvariant() switch
    {
        "critical" => Critical,
        "high" => High,
        "medium" => Medium,
        "low" => Low,
        _ => Info,
    };
}

/// <summary>Custom MigraDoc style names + one-time document style configuration for the report.</summary>
public static class ReportStyles
{
    public const string CodeBlock = "CamelCodeBlock";
    public const string Title = "CamelTitle";
    public const string Subtitle = "CamelSubtitle";
    public const string SectionLabel = "CamelSectionLabel";

    /// <summary>Configure the document's built-in and custom styles. Called once per <see cref="Document"/> before any
    /// content is added, so headings/body/code/table text all share the report's visual system.</summary>
    public static void Configure(Document document)
    {
        var normal = document.Styles[StyleNames.Normal]!;
        normal.Font.Name = ReportFonts.Body;
        normal.Font.Size = 10.5;
        normal.Font.Color = ReportColors.Ink;
        normal.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);
        normal.ParagraphFormat.LineSpacingRule = LineSpacingRule.Multiple;
        normal.ParagraphFormat.LineSpacing = 1.15;

        void Heading(string name, double size, Color color, double before, double after, bool bold = true)
        {
            var s = document.Styles[name]!;
            s.Font.Name = ReportFonts.Body;
            s.Font.Size = size;
            s.Font.Bold = bold;
            s.Font.Color = color;
            s.ParagraphFormat.SpaceBefore = Unit.FromPoint(before);
            s.ParagraphFormat.SpaceAfter = Unit.FromPoint(after);
            s.ParagraphFormat.KeepWithNext = true;
        }

        Heading(StyleNames.Heading1, 18, ReportColors.Accent, 16, 8);
        Heading(StyleNames.Heading2, 14, ReportColors.Accent, 12, 6);
        Heading(StyleNames.Heading3, 12, ReportColors.Ink, 10, 4);
        Heading(StyleNames.Heading4, 11, ReportColors.Ink, 8, 4);
        Heading(StyleNames.Heading5, 10.5, ReportColors.Muted, 6, 3);
        Heading(StyleNames.Heading6, 10, ReportColors.Muted, 6, 3);

        var title = document.Styles.AddStyle(Title, StyleNames.Normal);
        title.Font.Size = 26;
        title.Font.Bold = true;
        title.Font.Color = ReportColors.Accent;
        title.ParagraphFormat.SpaceAfter = Unit.FromPoint(4);

        var subtitle = document.Styles.AddStyle(Subtitle, StyleNames.Normal);
        subtitle.Font.Size = 13;
        subtitle.Font.Color = ReportColors.Muted;
        subtitle.ParagraphFormat.SpaceAfter = Unit.FromPoint(2);

        var label = document.Styles.AddStyle(SectionLabel, StyleNames.Normal);
        label.Font.Size = 8;
        label.Font.Bold = true;
        label.Font.Color = ReportColors.Muted;
        label.ParagraphFormat.SpaceBefore = Unit.FromPoint(2);

        var code = document.Styles.AddStyle(CodeBlock, StyleNames.Normal);
        code.Font.Name = ReportFonts.Mono;
        code.Font.Size = 9;
        code.ParagraphFormat.LeftIndent = Unit.FromPoint(8);
        code.ParagraphFormat.SpaceBefore = Unit.FromPoint(4);
        code.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);
        code.ParagraphFormat.Shading.Color = new Color(0xf6, 0xf8, 0xfa);
        code.ParagraphFormat.LineSpacing = 1.0;
        code.ParagraphFormat.LineSpacingRule = LineSpacingRule.Single;
    }
}
