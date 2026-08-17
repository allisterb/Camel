namespace Camel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>
/// One addressable subject area of the JavaScript SDK reference — the unit the per-area doc resources serve.
/// An area is named after the JS global it documents (<c>ScanningToolkit</c>, <c>WindowsAnalysisWorkflow</c>, …)
/// because that is what an agent has in hand when it needs the reference; a few small, cohesive globals share a
/// single area (the knowledge bases), which is what <see cref="SharedGlobals"/> records. See
/// <c>docs/SearchToolDesign.md</c> (Layer 1).
/// </summary>
/// <param name="Name">The area name — the last segment of its resource URI, and by default the markdown heading
/// text to slice on.</param>
/// <param name="SharedGlobals">The JS globals documented in this area, when it groups more than the one it is
/// named after; null for the usual one-global-per-area case.</param>
/// <param name="Heading">The heading text to slice on when it differs from the area name (used by the extra,
/// non-global sections — "SetEngagement inputs …", "Example").</param>
public sealed record SdkArea(string Name, string[]? SharedGlobals = null, string? Heading = null)
{
    /// <summary>The JS globals this area documents — the area itself unless it groups several.</summary>
    public string[] Globals => SharedGlobals ?? [Name];

    /// <summary>The heading text this area is sliced on.</summary>
    public string HeadingText => Heading ?? Name;
}

/// <summary>
/// The two reference documents of one investigation's SDK (core = methods, schema = returned models), the areas they
/// are sliced into, and the sections that belong in the index rather than in an area. One instance per investigation
/// (see <c>CamelResources</c>), which is what makes the resource surface investigation-aware without duplicating the
/// slicing logic.
/// </summary>
/// <param name="Label">Investigation label used in the index title.</param>
/// <param name="Core">Reader for the core (method reference) document.</param>
/// <param name="Schema">Reader for the schema (returned models) document.</param>
/// <param name="Areas">The subject areas — one per bound JS global (asserted by the guardrail test).</param>
/// <param name="Extras">Addressable sections that are not a JS global (examples, MCP tool inputs): served like an
/// area, listed in the index, but exempt from the bound-global check.</param>
/// <param name="CorePreamble">Heading prefixes of the core sections copied verbatim into the index — the protocol an
/// agent must have before its first call (execution model, authorization, audit, globals).</param>
/// <param name="SchemaPreamble">Heading prefixes of the schema sections copied verbatim into the index — the result
/// envelopes every area's models sit inside.</param>
public sealed record SdkDocSet(
    string Label,
    Func<string> Core,
    Func<string> Schema,
    SdkArea[] Areas,
    SdkArea[] Extras,
    string[] CorePreamble,
    string[] SchemaPreamble)
{
    /// <summary>The areas plus the extras — everything addressable as <c>camel://sdk/{core|schema}/{area}</c>.</summary>
    public IEnumerable<SdkArea> Addressable => Areas.Concat(Extras);
}

/// <summary>
/// The subject-area map of the SDK reference docs: the slicer that cuts an area out of one of them, and the index
/// generator that replaces "read both documents whole" with "read the map, then the areas your task touches".
/// <para>
/// The docs are authored as ONE markdown file per kind and sliced at runtime, so maintainers keep a single place to
/// edit and the slices cannot drift from the document. Areas are the BOUND GLOBALS rather than a heading level,
/// because the level that names a toolkit/workflow is not consistent — the PenTest core doc has toolkits at
/// <c>###</c> but workflows at <c>####</c> under one <c>### Workflows</c>, both schema docs use <c>##</c>, and
/// <c>Camel.schema.md</c> has duplicate (<c>MemoryAnalysisToolkit</c> twice) and merged (<c>DiskAnalysisToolkit /
/// DiskAnalysisWorkflow (carving &amp; recovery)</c>) headings. So a slice is located by heading TEXT at any level,
/// and duplicates are concatenated.
/// </para>
/// </summary>
public static class SdkDocs
{
    #region Properties

    /// <summary>The DFIR (blue) areas — the SIFT toolkits, the anomaly engine, and the analysis workflows. Must
    /// match the globals <c>DFIRMCPTools</c> binds (asserted by the guardrail test).</summary>
    public static SdkArea[] DfirAreas { get; } =
    [
        new("MemoryAnalysisToolkit"),
        new("DiskAnalysisToolkit"),
        new("WindowsAnalysisToolkit"),
        new("TimelineAnalysisToolkit"),
        new("YaraToolkit"),
        new("UnixToolsToolkit"),
        new("LinuxAnalysisToolkit"),
        new("PacketAnalysisToolkit"),
        new("AnomalyDetectionToolkit"),
        new("MemoryAnalysisWorkflow"),
        new("DiskAnalysisWorkflow"),
        new("WindowsAnalysisWorkflow"),
        new("TimelineAnalysisWorkflow"),
        new("AntiForensicsAnalysisWorkflow"),
        new("WebServerAnalysisWorkflow"),
        new("LinuxAnalysisWorkflow"),
        new("PacketAnalysisWorkflow"),
    ];

    /// <summary>The PenTest (red) areas — the offensive toolkits, the offensive workflows, and the external
    /// knowledge bases (grouped: each facade is a handful of methods over one cohesive section). Must match the
    /// globals <c>PenTestMCPTools</c> binds (asserted by the guardrail test).</summary>
    public static SdkArea[] PenTestAreas { get; } =
    [
        new("ReconToolkit"),
        new("ScanningToolkit"),
        new("VulnScanToolkit"),
        new("WebAppToolkit"),
        new("BrowserToolkit"),
        new("PasswordsToolkit"),
        new("MetasploitToolkit"),
        new("ReconWorkflow"),
        new("NetworkDiscoveryWorkflow"),
        new("VulnAnalysisWorkflow"),
        new("WebAppWorkflow"),
        new("WebExploitationWorkflow"),
        new("ExploitationWorkflow"),
        new("PostExploitWorkflow"),
        new("KnowledgeBases", ["Nvd", "Kev", "Epss", "ExploitDb", "Osv", "Shodan", "VulnCheck"]),
    ];

    #endregion

    #region Methods

    /// <summary>
    /// Cuts the section(s) documenting <paramref name="area"/> out of <paramref name="doc"/>: every heading whose
    /// text names the area (at any level, ignoring a parenthetical qualifier and slash-merged names) together with
    /// everything under it up to the next heading of the same or higher level. Multiple matches are concatenated in
    /// document order. Returns null when the area has no heading — the drift the guardrail test turns into a build
    /// failure.
    /// </summary>
    public static string? Slice(string doc, string area)
    {
        var headings = Headings(doc);
        var lines = doc.Split('\n');
        var slices = headings
            .Select((h, i) => (Heading: h, Next: headings.Skip(i + 1).FirstOrDefault(n => n.Level <= h.Level)))
            .Where(s => Names(s.Heading.Text, area))
            .Select(s => string.Join('\n', lines[s.Heading.Line..(s.Next.Line > 0 ? s.Next.Line : lines.Length)]).TrimEnd())
            .ToArray();
        return slices.Length == 0 ? null : string.Join("\n\n", slices);
    }

    /// <summary>
    /// The markdown headings of a doc as (0-based line index, level, text), skipping fenced code blocks so a
    /// shell comment inside an example is never mistaken for a heading.
    /// </summary>
    public static List<(int Line, int Level, string Text)> Headings(string doc)
    {
        var headings = new List<(int, int, string)>();
        var fenced = false;
        var lines = doc.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (line.StartsWith("```", StringComparison.Ordinal)) { fenced = !fenced; continue; }
            if (fenced || !line.StartsWith('#')) continue;
            var level = line.TakeWhile(c => c == '#').Count();
            if (level > 6 || level >= line.Length || line[level] != ' ') continue;
            headings.Add((i, level, line[(level + 1)..].Trim()));
        }
        return headings;
    }

    /// <summary>
    /// The map an agent reads instead of both whole documents: the doc intro and the mandatory protocol sections
    /// verbatim, then — per area — a one-line purpose and the COMPLETE inventory of its method and model names, with
    /// the URIs to read for detail. The inventory is generated from the docs themselves, so it cannot drift from
    /// them, and it is what makes selective reading safe: an agent can neither invent a method nor conclude a
    /// capability is absent without having seen every name.
    /// </summary>
    public static string BuildIndex(SdkDocSet set)
    {
        var core = set.Core();
        var schema = set.Schema();
        var index = new StringBuilder();

        index.AppendLine($"# Camel JavaScript SDK — reference map ({set.Label})");
        index.AppendLine();
        index.AppendLine("""
            **This map replaces reading the reference documents whole.** It carries the execution model and the
            protocol sections in full (they are short and mandatory), then the COMPLETE inventory of every callable
            method and every returned model type, grouped by area. The detail lives per area:

            - `camel://sdk/core/{Area}` — the methods of that area: parameters, semantics, gating, worked usage.
            - `camel://sdk/schema/{Area}` — the fields of every model those methods return.
            - `camel://sdk/core/all`, `camel://sdk/schema/all` — the whole documents, if you truly want everything.

            Read the areas your task touches, then write the script. The rules are unchanged: **call only methods
            listed in this inventory** (if a name is not here it does not exist — do not invent one), and **read only
            properties documented in that area's schema**. Equally: do not conclude a capability is missing because
            you have not read its area — the inventory below is complete, so check it first.
            """);
        index.AppendLine();

        foreach (var section in set.CorePreamble)
            Append(index, Slice(core, section));
        foreach (var section in set.SchemaPreamble)
            Append(index, Slice(schema, section));

        index.AppendLine();
        index.AppendLine("# Areas — the inventory");
        index.AppendLine();
        foreach (var area in set.Areas)
        {
            var coreSlice = Slice(core, area.HeadingText);
            var schemaSlice = Slice(schema, area.HeadingText);
            var methods = MethodNames(coreSlice ?? "", area.Name);
            var models = ModelNames(schemaSlice ?? "");
            index.AppendLine($"## {area.Name}");
            index.AppendLine();
            if (Purpose(coreSlice) is string purpose) index.AppendLine(purpose);
            if (area.SharedGlobals is not null)
                index.AppendLine($"Globals: `{string.Join("`, `", area.Globals)}`");
            index.AppendLine();
            index.AppendLine($"- Methods ({methods.Count}) — detail in `camel://sdk/core/{area.Name}`:");
            index.AppendLine($"  {string.Join(", ", methods)}");
            index.AppendLine($"- Models ({models.Count}) — fields in `camel://sdk/schema/{area.Name}`:");
            index.AppendLine($"  {(models.Count > 0 ? string.Join(", ", models) : "none (this area returns models documented in another area)")}");
            index.AppendLine();
        }

        if (set.Extras.Length > 0)
        {
            index.AppendLine("## Other sections");
            index.AppendLine();
            foreach (var extra in set.Extras)
            {
                var kind = Slice(core, extra.HeadingText) is not null ? "core" : "schema";
                index.AppendLine($"- **{extra.HeadingText}** → `camel://sdk/{kind}/{extra.Name}`");
            }
            index.AppendLine();
        }
        return index.ToString();
    }

    /// <summary>
    /// The short body served at the legacy whole-schema URI (<c>camel://sdk/schema</c>): the schemas are now per
    /// area, so an agent following the old "read the schema doc" instruction gets a signpost instead of 95–120 KB.
    /// </summary>
    public static string BuildSchemaSignpost(SdkDocSet set)
    {
        var areas = string.Join(", ", set.Areas.Select(a => a.Name));
        return $$"""
            # Camel JavaScript SDK — schemas ({{set.Label}})

            The model schemas are served **per subject area**, not as one document:

            - `camel://sdk/schema/{Area}` — the exact fields of every model that area's methods return.
            - `camel://sdk/index` — the map: it names **every model type** and which area owns it, plus the method
              inventory and the execution model. **Read the map first** — it is the one place that tells you which
              area to open for a type like `HostScan` or `TriageReport`.
            - `camel://sdk/schema/all` — the whole schema document, if you need every area at once.

            Areas: {{areas}}.

            """;
    }

    /// <summary>
    /// The method names documented in a core-doc slice, in document order. Every method is documented as a bullet
    /// whose first token is its backticked signature (<c>- `ScanningToolkit.ScanHostAsync(target, ports?)` → …</c>),
    /// so the inventory is derived from the doc rather than from a second hand-maintained list. The receiver is kept
    /// unless it is the area itself — so an area that groups several globals stays unambiguous
    /// (<c>Nvd.CveAsync</c> vs <c>VulnCheck.CveAsync</c>), as does a method on a returned handle
    /// (<c>page.Forms</c>).
    /// </summary>
    public static List<string> MethodNames(string slice, string? area = null)
    {
        var names = new List<string>();
        foreach (var bullet in Bullets(slice))
        {
            foreach (var (receiver, name) in Signatures(bullet))
            {
                var qualified = receiver.Length == 0 || receiver == area ? name : $"{receiver}.{name}";
                if (!names.Contains(qualified, StringComparer.Ordinal)) names.Add(qualified);
            }
        }
        return names;
    }

    /// <summary>
    /// The bullets of a slice, each joined with its wrapped continuation lines — a long signature list runs across
    /// lines (<c>`Md5SumAsync(…)` / `Sha1SumAsync(…)` /</c> … <c>`Sha256SumAsync(…)` → `string`</c>), so a
    /// line-at-a-time reader loses the ones after the wrap.
    /// </summary>
    private static IEnumerable<string> Bullets(string slice)
    {
        var bullet = new StringBuilder();
        var fenced = false;
        foreach (var raw in slice.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("```", StringComparison.Ordinal)) { fenced = !fenced; continue; }
            var starts = !fenced && trimmed.StartsWith("- ", StringComparison.Ordinal);
            var continues = bullet.Length > 0 && !fenced && line.StartsWith(' ') && trimmed.Length > 0
                            && !trimmed.StartsWith("- ", StringComparison.Ordinal);
            if (starts || !continues)
            {
                if (bullet.Length > 0) { yield return bullet.ToString(); bullet.Clear(); }
                if (starts) bullet.Append(trimmed);
            }
            else bullet.Append(' ').Append(trimmed);
        }
        if (bullet.Length > 0) yield return bullet.ToString();
    }

    /// <summary>
    /// The signatures a bullet DECLARES, as (receiver, name). A bullet opens with a signature region — one or more
    /// backticked calls separated by <c>/</c>, <c>·</c> or <c>,</c>, each optionally followed by <c>→ `ReturnType`</c>
    /// — and then turns to prose. Reading only the region is what distinguishes a declared method from one merely
    /// named in the prose, while still catching the second and third on a shared bullet: <c>CookiesForAsync</c> was
    /// documented that way and went missing from the map (agent finding B-4).
    /// </summary>
    private static IEnumerable<(string Receiver, string Name)> Signatures(string bullet)
    {
        var rest = bullet.StartsWith("- ", StringComparison.Ordinal) ? bullet[2..] : bullet;
        while (true)
        {
            var signature = SignatureToken.Match(rest);
            if (!signature.Success) yield break;
            yield return (signature.Groups[1].Value, signature.Groups[2].Value);
            rest = rest[signature.Length..];
            rest = ReturnTypeToken.Match(rest) is { Success: true } ret ? rest[ret.Length..] : rest;
            if (SeparatorToken.Match(rest) is not { Success: true } sep) yield break;
            rest = rest[sep.Length..];
        }
    }

    /// <summary>
    /// The model type names documented in a schema-doc slice, in document order — every schema is a
    /// "<c>### CorsResult Schema</c>" heading, optionally with a parenthetical note about what returns it.
    /// </summary>
    public static List<string> ModelNames(string slice) =>
        Headings(slice)
            .Select(h => SchemaHeading.Match(h.Text))
            .Where(m => m.Success)
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    // The three tokens of a bullet's signature region, all anchored so they consume it left to right.
    private static readonly Regex SignatureToken =
        new(@"^`(?:([A-Za-z_][A-Za-z0-9_]*)\.)?([A-Za-z_][A-Za-z0-9_]*)\([^`]*\)`", RegexOptions.Compiled);
    private static readonly Regex ReturnTypeToken =
        new(@"^\s*(?:→|->)\s*`[^`]*`", RegexOptions.Compiled);
    private static readonly Regex SeparatorToken =
        new(@"^\s*[/·,]\s*", RegexOptions.Compiled);

    // A schema heading: "CorsResult Schema", "ProcessNode Schema (input to ValidateProcessTreeAsync)".
    private static readonly Regex SchemaHeading =
        new(@"^`?([A-Za-z_][A-Za-z0-9_]*)`?(?:&lt;\w+&gt;)?\s+Schema\b", RegexOptions.Compiled);

    /// <summary>The area's own one-line description: its first prose sentence, capped so the map stays a map.</summary>
    private static string? Purpose(string? slice)
    {
        // The opening paragraph, unwrapped (the docs hard-wrap at ~110 columns, so the first sentence usually spans
        // two or three lines), then cut at its first sentence so the map stays a map.
        var lines = (slice ?? "").Split('\n').Skip(1).Select(l => l.Trim())
            .SkipWhile(l => l.Length == 0)
            .TakeWhile(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith('-') && !l.StartsWith("```"))
            .ToArray();
        if (lines.Length == 0) return null;
        var prose = string.Join(' ', lines);
        var stop = prose.IndexOf(". ", StringComparison.Ordinal);
        var sentence = stop > 0 ? prose[..(stop + 1)] : prose;
        return sentence.Length <= 240 ? sentence : sentence[..237].TrimEnd() + "…";
    }

    private static void Append(StringBuilder index, string? section)
    {
        if (section is null) return;
        index.AppendLine(section);
        index.AppendLine();
    }

    /// <summary>
    /// Whether a heading text names an area: compare on letters and digits only (so "Knowledge bases" resolves
    /// <c>KnowledgeBases</c>), after dropping a generic parameter ("WorkflowResult&lt;T&gt;"), any parenthetical
    /// qualifier ("MemoryAnalysisToolkit (Linux plugins)", "Execution model (read this first)") and any em-dash
    /// aside, and considering each side of a slash-merged heading ("DiskAnalysisToolkit / DiskAnalysisWorkflow (…)").
    /// </summary>
    private static bool Names(string heading, string area)
    {
        var text = GenericParameter.Replace(heading.Replace("`", ""), "");
        foreach (var aside in new[] { "(", "—" })
        {
            var at = text.IndexOf(aside, StringComparison.Ordinal);
            if (at >= 0) text = text[..at];
        }
        var target = Alphanumeric(area);
        return text.Split('/').Any(segment => Alphanumeric(segment) == target);
    }

    // "WorkflowResult&lt;T&gt;" / "ToolResult<T>" — the type parameter is not part of the area name.
    private static readonly Regex GenericParameter = new(@"(&lt;|<)\w+(&gt;|>)", RegexOptions.Compiled);

    private static string Alphanumeric(string s) =>
        string.Concat(s.Where(char.IsLetterOrDigit)).ToLowerInvariant();

    #endregion
}
