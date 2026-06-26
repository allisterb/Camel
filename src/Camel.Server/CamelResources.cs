namespace Camel;

using System;
using System.ComponentModel;

using ModelContextProtocol.Server;

/// <summary>
/// MCP resources exposing the Camel JavaScript SDK reference to the agent. The markdown docs are embedded in
/// this assembly (see Camel.Server.csproj) and served verbatim, so an agent can read the SDK surface before
/// generating code for the <c>Execute</c> tool without the docs having to exist on disk at runtime.
/// NOTE: these are served as <c>text/plain</c>, not <c>text/markdown</c>, on purpose — a client that renders a
/// markdown resource collapses single-newline line breaks (markdown only breaks on blank lines / hard breaks),
/// flattening the reference into one long line for the model. Plain text is surfaced to the model verbatim.
/// </summary>
public class CamelResources
{
    [McpServerResource(UriTemplate = "camel://sdk/core", Name = "camel-sdk-core",
        Title = "Camel JS SDK reference — core", MimeType = "text/plain")]
    [Description("Core reference for the Camel JavaScript SDK used by the Execute tool: the execution " +
        "model (await semantics, return-value shapes, PascalCase naming, positional optional params) and the full " +
        "method signature index — every toolkit and workflow object, each method's parameters and return type. " +
        "Read this FIRST and keep it in context when generating JS. The method return types reference model types " +
        "whose JSON schemas live in the companion 'camel-sdk-schema' resource (camel://sdk/schema).")]
    public static string SdkCore() => ReadEmbedded("Camel.core.md");

    [McpServerResource(UriTemplate = "camel://sdk/schema", Name = "camel-sdk-schema",
        Title = "Camel JS SDK reference — schemas", MimeType = "text/plain")]
    [Description("JSON schemas for every parameter and return model type in the Camel JavaScript SDK — the " +
        "companion to 'camel-sdk-core'. Consult this when you need the exact fields of an object a toolkit or " +
        "workflow method returns (e.g. TimelineEvent, FindMalwareReport, TriageReport). Schemas are grouped by " +
        "the object that returns them.")]
    public static string SdkSchema() => ReadEmbedded("Camel.schema.md");

    [McpServerResource(UriTemplate = "camel://sdk/discipline", Name = "camel-sdk-discipline",
        Title = "Camel JS SDK reference — forensic discipline", MimeType = "text/plain")]
    [Description("The forensic investigative discipline for the Execute tool: how to reason over what the SDK " +
        "returns — core principles (evidence is sovereign, absence ≠ absence, correlation ≠ causation, benign " +
        "until proven malicious), the analyze/collect/corroborate/record loop, the self-checks and golden rules " +
        "for grounding a finding in cited execution ids, and the high-consequence decisions to flag for human " +
        "judgement (via auditReviewRec) while still running autonomously. Read this alongside 'camel-sdk-core'.")]
    public static string SdkDiscipline() => ReadEmbedded("Camel.discipline.md");

    static string ReadEmbedded(string name)
    {
        using var stream = typeof(CamelResources).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded SDK doc '{name}' was not found in the assembly.");
        using var reader = new System.IO.StreamReader(stream);
        return reader.ReadToEnd();
    }
}
