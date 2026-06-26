namespace Camel;

using System;
using System.ComponentModel;

using ModelContextProtocol.Server;

/// <summary>
/// Base for the MCP resource classes that expose the Camel JavaScript SDK reference to the agent. The markdown
/// docs are embedded in this assembly (see Camel.Server.csproj) and served verbatim, so an agent can read the SDK
/// surface before generating code for the <c>Execute</c> tool without the docs having to exist on disk at runtime.
/// The investigation-specific subclasses (<see cref="DFIRResources"/> / <see cref="PenTestResources"/>) declare
/// the <c>[McpServerResource]</c> methods under the SAME <c>camel://sdk/*</c> URIs but point them at the blue or
/// red docs; the host registers exactly one per server (see <c>CamelMCPServer</c>), so the agent on a given server
/// always reads the reference for the toolkits that server actually binds.
/// NOTE: these are served as <c>text/plain</c>, not <c>text/markdown</c>, on purpose — a client that renders a
/// markdown resource collapses single-newline line breaks (markdown only breaks on blank lines / hard breaks),
/// flattening the reference into one long line for the model. Plain text is surfaced to the model verbatim.
/// </summary>
public abstract class CamelResources
{
    protected static string ReadEmbedded(string name)
    {
        using var stream = typeof(CamelResources).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded SDK doc '{name}' was not found in the assembly.");
        using var reader = new System.IO.StreamReader(stream);
        return reader.ReadToEnd();
    }
}

/// <summary>The DFIR (blue-team) SDK reference resources — the SIFT toolkits/workflows + anomaly engine API and
/// the forensic discipline. Registered by the DFIR server.</summary>
public class DFIRResources : CamelResources
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
}

/// <summary>The PenTest (red-team) SDK reference resources — the offensive toolkits API, their model schemas, and
/// the engagement/authorization discipline. Registered by the PenTest server under the same camel://sdk/* URIs as
/// the DFIR set, so an agent reads whichever reference matches the server it is talking to.</summary>
public class PenTestResources : CamelResources
{
    [McpServerResource(UriTemplate = "camel://sdk/core", Name = "camel-sdk-core",
        Title = "Camel JS SDK reference — core (PenTest)", MimeType = "text/plain")]
    [Description("Core reference for the Camel JavaScript SDK on the PenTest (red-team) server used by the Execute " +
        "tool: the execution model (await semantics, return-value shapes, PascalCase naming, positional optional " +
        "params) and the method index for the OFFENSIVE toolkits (scanning, …) — each method's parameters and " +
        "return type. Read this FIRST. Offensive tools are fail-closed: register the engagement with SetEngagement " +
        "before calling them. Return-model schemas live in the companion 'camel-sdk-schema' resource.")]
    public static string SdkCore() => ReadEmbedded("Camel.pentest.core.md");

    [McpServerResource(UriTemplate = "camel://sdk/schema", Name = "camel-sdk-schema",
        Title = "Camel JS SDK reference — schemas (PenTest)", MimeType = "text/plain")]
    [Description("JSON schemas for every parameter and return model type of the Camel PenTest SDK — the companion " +
        "to 'camel-sdk-core'. Consult this for the exact fields of an object an offensive toolkit method returns " +
        "(e.g. HostScan, PortInfo). Schemas are grouped by the toolkit that owns them.")]
    public static string SdkSchema() => ReadEmbedded("Camel.pentest.schema.md");

    [McpServerResource(UriTemplate = "camel://sdk/discipline", Name = "camel-sdk-discipline",
        Title = "Camel JS SDK reference — engagement discipline", MimeType = "text/plain")]
    [Description("The red-team engagement discipline for the Execute tool: how to operate within authorization — " +
        "authorization & scope are sovereign (only act on in-scope targets, in window), least-intrusive technique, " +
        "no collateral damage, ground every finding in returned values and cited execution ids, and the " +
        "high-consequence/edge-of-scope actions to flag for human judgement (via auditReviewRec) while still " +
        "running autonomously. Read this alongside 'camel-sdk-core'.")]
    public static string SdkDiscipline() => ReadEmbedded("Camel.pentest.discipline.md");
}
