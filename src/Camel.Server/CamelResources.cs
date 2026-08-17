namespace Camel;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

using ModelContextProtocol.Server;

/// <summary>
/// Base for the MCP resource classes that expose the Camel JavaScript SDK reference to the agent. The markdown
/// docs are embedded in this assembly (see Camel.Server.csproj) and served SLICED BY SUBJECT AREA, so an agent
/// reads the map plus the two or three areas its task touches instead of ~226 KB of reference before its first
/// call (see <c>docs/SearchToolDesign.md</c>, Layer 1, and <see cref="SdkDocs"/> for the slicing rules).
/// The investigation-specific subclasses (<see cref="DFIRResources"/> / <see cref="PenTestResources"/>) declare
/// the <c>[McpServerResource]</c> methods under the SAME <c>camel://sdk/*</c> URIs but point them at the blue or
/// red doc set; the host registers exactly one per server (see <c>CamelMCPServer</c>), so the agent on a given
/// server always reads the reference for the toolkits that server actually binds.
/// NOTE: these are served as <c>text/plain</c>, not <c>text/markdown</c>, on purpose — a client that renders a
/// markdown resource collapses single-newline line breaks (markdown only breaks on blank lines / hard breaks),
/// flattening the reference into one long line for the model. Plain text is surfaced to the model verbatim.
/// </summary>
public abstract class CamelResources
{
    #region Properties

    /// <summary>The DFIR (blue) doc set: the SIFT toolkits/workflows + anomaly engine reference and its schemas.</summary>
    public static SdkDocSet Dfir { get; } = new(
        Label: "DFIR",
        Core: () => ReadEmbedded("Camel.core.md"),
        Schema: () => ReadEmbedded("Camel.schema.md"),
        Areas: SdkDocs.DfirAreas,
        Extras: [new("Patterns", Heading: "End-to-end patterns")],
        CorePreamble: ["Execution model", "Audit trail", "Global Functions", "Session storage", "WorkflowResult"],
        SchemaPreamble: ["WorkflowResult", "ToolResult"]);

    /// <summary>The PenTest (red) doc set: the offensive toolkits/workflows reference and its schemas.</summary>
    public static SdkDocSet PenTest { get; } = new(
        Label: "PenTest",
        Core: () => ReadEmbedded("Camel.pentest.core.md"),
        Schema: () => ReadEmbedded("Camel.pentest.schema.md"),
        Areas: SdkDocs.PenTestAreas,
        Extras: [new("Examples", Heading: "Example"), new("SetEngagement", Heading: "SetEngagement inputs")],
        CorePreamble: ["Execution model", "Authorization", "Session storage"],
        SchemaPreamble: ["ToolResult"]);

    #endregion

    #region Methods

    protected static string ReadEmbedded(string name)
    {
        using var stream = typeof(CamelResources).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded SDK doc '{name}' was not found in the assembly.");
        using var reader = new System.IO.StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>The generated map of a doc set (memoized — the docs are immutable for the process's lifetime).</summary>
    public static string Index(SdkDocSet set) => Memo($"{set.Label}/index", () => SdkDocs.BuildIndex(set));

    /// <summary>The signpost served at the legacy whole-schema URI: where the per-area schemas now live.</summary>
    public static string SchemaSignpost(SdkDocSet set) => Memo($"{set.Label}/schema-signpost", () => SdkDocs.BuildSchemaSignpost(set));

    /// <summary>
    /// The per-area doc resources of a doc set — <c>camel://sdk/core/{Area}</c> and <c>camel://sdk/schema/{Area}</c>
    /// for every area and extra section, registered as CONCRETE resources rather than one URI template so that every
    /// client lists them (a template is only discoverable through <c>resources/templates/list</c>). An area with no
    /// section in one of the documents is not registered on that side — the guardrail test
    /// (<c>SdkDocAreaTests</c>) keeps that from happening silently to a real area.
    /// </summary>
    public static IEnumerable<McpServerResource> AreaResources(SdkDocSet set)
    {
        // Read each document once for the whole registration pass (they are embedded and immutable).
        var documents = new[] { ("core", set.Core()), ("schema", set.Schema()) };
        foreach (var area in set.Addressable)
        {
            foreach (var (kind, doc) in documents)
            {
                if (SdkDocs.Slice(doc, area.HeadingText) is null) continue;
                var (uri, name) = ($"camel://sdk/{kind}/{area.Name}", $"camel-sdk-{kind}-{area.Name.ToLowerInvariant()}");
                var description = kind == "core"
                    ? $"{area.Name} — method reference: every method's parameters, semantics and gating, with worked " +
                      $"usage. The models it returns are documented in {area.Name}'s schema resource."
                    : $"{area.Name} — JSON schemas: the exact fields of every model {area.Name}'s methods return. " +
                      $"Read this before reading properties off a result.";
                yield return McpServerResource.Create(
                    () => Memo($"{set.Label}/{kind}/{area.Name}", () => SdkDocs.Slice(doc, area.HeadingText)!),
                    new McpServerResourceCreateOptions
                    {
                        UriTemplate = uri,
                        Name = name,
                        Title = $"Camel JS SDK — {area.Name} ({kind})",
                        Description = description,
                        MimeType = "text/plain",
                    });
            }
        }
    }

    private static readonly ConcurrentDictionary<string, string> memo = new();
    private static string Memo(string key, Func<string> build) => memo.GetOrAdd(key, _ => build());

    #endregion
}

/// <summary>The DFIR (blue-team) SDK reference resources — the SIFT toolkits/workflows + anomaly engine API and
/// the forensic discipline. Registered by the DFIR server.</summary>
public class DFIRResources : CamelResources
{
    [McpServerResource(UriTemplate = "camel://sdk/index", Name = "camel-sdk-index",
        Title = "Camel JS SDK reference — map (read this first)", MimeType = "text/plain")]
    [Description("START HERE for the Camel JavaScript SDK used by the Execute tool. The map: the execution model " +
        "(await semantics, return-value shapes, PascalCase naming, positional optional params), the audit/case " +
        "attribution protocol, the result envelopes, and the COMPLETE inventory of every toolkit/workflow object, " +
        "every method name and every returned model type — grouped by subject area, each with the URI to read for " +
        "detail (camel://sdk/core/{Area} for methods, camel://sdk/schema/{Area} for their fields). Read this, then " +
        "read only the areas your task touches.")]
    public static string SdkIndex() => Index(Dfir);

    [McpServerResource(UriTemplate = "camel://sdk/core", Name = "camel-sdk-core",
        Title = "Camel JS SDK reference — core (serves the map)", MimeType = "text/plain")]
    [Description("The SDK map — IDENTICAL to 'camel-sdk-index' (camel://sdk/index), kept at this URI for the " +
        "instruction 'read camel://sdk/core first'. Read either one, not both. The per-area method reference lives " +
        "at camel://sdk/core/{Area}; camel://sdk/core/all still serves the whole core document.")]
    public static string SdkCore() => Index(Dfir);

    [McpServerResource(UriTemplate = "camel://sdk/core/all", Name = "camel-sdk-core-all",
        Title = "Camel JS SDK reference — core (whole document)", MimeType = "text/plain")]
    [Description("The ENTIRE core method reference in one read (~67 KB). Prefer the map (camel://sdk/index) plus " +
        "the per-area resources; use this only when you genuinely need every area at once.")]
    public static string SdkCoreAll() => Dfir.Core();

    [McpServerResource(UriTemplate = "camel://sdk/schema", Name = "camel-sdk-schema",
        Title = "Camel JS SDK reference — schemas (index)", MimeType = "text/plain")]
    [Description("Where the model schemas live now: they are served per subject area at camel://sdk/schema/{Area}. " +
        "This resource lists the areas; the map (camel://sdk/index) additionally names every model type per area, " +
        "so read that to find which area owns a type. camel://sdk/schema/all still serves the whole document.")]
    public static string SdkSchema() => SchemaSignpost(Dfir);

    [McpServerResource(UriTemplate = "camel://sdk/schema/all", Name = "camel-sdk-schema-all",
        Title = "Camel JS SDK reference — schemas (whole document)", MimeType = "text/plain")]
    [Description("The ENTIRE schema reference in one read (~95 KB) — every parameter and return model of the SDK. " +
        "Prefer the per-area schema resources named in the map (camel://sdk/index).")]
    public static string SdkSchemaAll() => Dfir.Schema();

    [McpServerResource(UriTemplate = "camel://sdk/discipline", Name = "camel-sdk-discipline",
        Title = "Camel JS SDK reference — forensic discipline", MimeType = "text/plain")]
    [Description("The forensic investigative discipline for the Execute tool: how to reason over what the SDK " +
        "returns — core principles (evidence is sovereign, absence ≠ absence, correlation ≠ causation, benign " +
        "until proven malicious), the analyze/collect/corroborate/record loop, the self-checks and golden rules " +
        "for grounding a finding in cited execution ids, and the high-consequence decisions to flag for human " +
        "judgement (via auditReviewRec) while still running autonomously. Read this alongside the SDK map.")]
    public static string SdkDiscipline() => ReadEmbedded("Camel.discipline.md");
}

/// <summary>The PenTest (red-team) SDK reference resources — the offensive toolkits API, their model schemas, and
/// the engagement/authorization discipline. Registered by the PenTest server under the same camel://sdk/* URIs as
/// the DFIR set, so an agent reads whichever reference matches the server it is talking to.</summary>
public class PenTestResources : CamelResources
{
    [McpServerResource(UriTemplate = "camel://sdk/index", Name = "camel-sdk-index",
        Title = "Camel JS SDK reference — map (read this first, PenTest)", MimeType = "text/plain")]
    [Description("START HERE for the Camel JavaScript SDK on the PenTest (red-team) server. The map: the execution " +
        "model (await semantics, return-value shapes, PascalCase naming, positional optional params), the " +
        "fail-closed AUTHORIZATION protocol (offensive tools refuse to run until SetEngagement registers an " +
        "engagement), and the COMPLETE inventory of every offensive toolkit/workflow object, every method name and " +
        "every returned model type — grouped by subject area, each with the URI to read for detail " +
        "(camel://sdk/core/{Area}, camel://sdk/schema/{Area}). Read this, then only the areas your task touches.")]
    public static string SdkIndex() => Index(PenTest);

    [McpServerResource(UriTemplate = "camel://sdk/core", Name = "camel-sdk-core",
        Title = "Camel JS SDK reference — core (serves the map, PenTest)", MimeType = "text/plain")]
    [Description("The SDK map — IDENTICAL to 'camel-sdk-index' (camel://sdk/index), kept at this URI for the " +
        "instruction 'read camel://sdk/core first'. Read either one, not both. The per-area method reference lives " +
        "at camel://sdk/core/{Area}; camel://sdk/core/all still serves the whole core document.")]
    public static string SdkCore() => Index(PenTest);

    [McpServerResource(UriTemplate = "camel://sdk/core/all", Name = "camel-sdk-core-all",
        Title = "Camel JS SDK reference — core (whole document, PenTest)", MimeType = "text/plain")]
    [Description("The ENTIRE offensive core method reference in one read (~106 KB). Prefer the map " +
        "(camel://sdk/index) plus the per-area resources; use this only when you need every area at once.")]
    public static string SdkCoreAll() => PenTest.Core();

    [McpServerResource(UriTemplate = "camel://sdk/schema", Name = "camel-sdk-schema",
        Title = "Camel JS SDK reference — schemas (index, PenTest)", MimeType = "text/plain")]
    [Description("Where the model schemas live now: they are served per subject area at camel://sdk/schema/{Area}. " +
        "This resource lists the areas; the map (camel://sdk/index) additionally names every model type per area, " +
        "so read that to find which area owns a type. camel://sdk/schema/all still serves the whole document.")]
    public static string SdkSchema() => SchemaSignpost(PenTest);

    [McpServerResource(UriTemplate = "camel://sdk/schema/all", Name = "camel-sdk-schema-all",
        Title = "Camel JS SDK reference — schemas (whole document, PenTest)", MimeType = "text/plain")]
    [Description("The ENTIRE offensive schema reference in one read (~120 KB) — every parameter and return model " +
        "of the PenTest SDK, plus the SetEngagement inputs. Prefer the per-area schema resources named in the map.")]
    public static string SdkSchemaAll() => PenTest.Schema();

    [McpServerResource(UriTemplate = "camel://sdk/discipline", Name = "camel-sdk-discipline",
        Title = "Camel JS SDK reference — engagement discipline", MimeType = "text/plain")]
    [Description("The red-team engagement discipline for the Execute tool: how to operate within authorization — " +
        "authorization & scope are sovereign (only act on in-scope targets, in window), least-intrusive technique, " +
        "no collateral damage, ground every finding in returned values and cited execution ids, and the " +
        "high-consequence/edge-of-scope actions to flag for human judgement (via auditReviewRec) while still " +
        "running autonomously. Read this alongside the SDK map.")]
    public static string SdkDiscipline() => ReadEmbedded("Camel.pentest.discipline.md");
}
