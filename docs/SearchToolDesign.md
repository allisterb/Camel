# Design: SDK doc `Search` tool (and the interim resource split)

## Problem

The code-mode servers ship the SDK reference as a small number of large MCP resources:

| Resource | PenTest | DFIR |
|----------|--------:|-----:|
| `camel://sdk/core`   | 91 KB | 67 KB |
| `camel://sdk/schema` | 110 KB | 95 KB |
| `camel://sdk/discipline` | ~10 KB | ~10 KB |

An agent reads `core` + `schema` whole before it can write a single `Execute` script. That already strains the
context budget, and it grows every time the API does — this session alone added ~10 web-exploitation methods and
their schemas. The `pentest-agent` E2E run flagged it as real (paraphrased): *the core/schema resources arrive as
one ~90–116 KB blob; an agent with only the MCP tools and no shell would be stuck paging it.*

Two independent needs fall out of this:

1. **Read less per task.** An agent doing web exploitation should not have to hold the Metasploit and Passwords
   sections in context to find `ConfirmCorsAsync`.
2. **Find by intent.** "I want to confirm a CORS misconfiguration" → the one method + its return schema, not a
   116 KB document to grep.

The mature answer, and what most code-mode MCP servers converge on, is a **two-tool surface**: `Execute` to run
code, `Search` to locate the API to run. This doc specs that, plus a low-risk interim that is also the substrate
Search builds on.

---

## Layer 1 (interim, ~1 hour): split the resources by subject area

Keep the mechanism (`ReadEmbedded` behind `camel://sdk/*` URIs); change the granularity. Instead of one
`camel://sdk/core`, register one resource per toolkit/workflow area, plus a small index:

```
camel://sdk/index                 # one-screen map: areas + one line each + "call Search to pinpoint"
camel://sdk/core/scanning         # ScanningToolkit methods
camel://sdk/core/recon
camel://sdk/core/vulnscan
camel://sdk/core/webapp
camel://sdk/core/browser          # BrowserToolkit + the WebExploitation confirmers
camel://sdk/core/passwords
camel://sdk/core/metasploit
camel://sdk/core/workflows
camel://sdk/schema/<area>         # the matching schema blocks per area
camel://sdk/discipline            # unchanged — meant to be read whole
```

**Why this helps on its own.** MCP `resources/list` returns metadata only (uri + name + description); the client
reads bodies selectively. A well-described per-area menu *is* a coarse search — the agent reads the two or three
areas its task touches, not all eight. The `### ToolkitName` / `### Workflows` boundaries already in the docs are
the split points, so this is mechanical: slice each doc, register a resource per slice, write the index.

**Costs and caveats.**
- More resources in the list. Fine as long as the client does not auto-read-all bodies — the harness has the agent
  choose, so this holds. Flag it if a future client bulk-loads.
- The maintenance rule "update core + schema + CaseTemplate per API change" becomes "update the *area* core + area
  schema + CaseTemplate." Net fewer lines touched per change (an API change is usually one area), more files total.
- Not a real search: the agent still picks an area by its description, then reads the whole area. Good enough to
  unblock the context-blob problem; it does not answer "which method does X" without reading a whole area.

This is worth doing regardless of Layer 2, because Layer 2 indexes exactly these per-area slices.

---

## Layer 2 (the real fix): a `Search` MCP tool

A second tool alongside `Execute`, on **both** servers (DFIR and PenTest — same design, different corpus).

### Tool contract

```
Search(query: string, kind?: "methods" | "schemas" | "all" = "all", topK?: number = 8, area?: string)
  → SearchHit[]

SearchHit {
  kind:      "method" | "schema"
  area:      "scanning" | "webexploitation" | ...      // the resource it lives in
  name:      "ConfirmCorsAsync" | "CorsResult"
  signature: "WebExploitationWorkflow.ConfirmCorsAsync(url, probeOrigin?) → WorkflowResult<CorsResult>"
  snippet:   the method's prose / the schema's field list (the chunk body, capped)
  resource:  "camel://sdk/core/browser"                 // where to read the full context
  score:     number
}
```

`area` optionally scopes the search. `kind` lets an agent ask for just the schema of a type it already knows.
Typical use: `Search("confirm CORS misconfiguration")` → `ConfirmCorsAsync` (method) + `CorsResult` (schema), each
with a snippet good enough to write the call without reading the whole resource.

### Chunking — the unit of retrieval

The corpus is already structured, so chunks fall out of the markdown with no re-authoring:

- **Method chunk** = one `- \`Toolkit.MethodAsync(params)\` → \`ReturnType\`` bullet plus its indented prose. The
  docs are formatted this way consistently (I maintain them), so a parser keyed on that bullet shape + the enclosing
  `### Area` header yields ~200–400 method chunks across both servers.
- **Schema chunk** = one `### XSchema` block (the fenced JSON). One chunk per returned type.

Each chunk carries `{area, name, signature, kind}` metadata for the hit. **The index is derived from the same
embedded docs the resources serve, at load time** — so it cannot drift from the docs, and there is no second source
of truth to maintain. Update a doc, rebuild, the index follows.

### Retrieval — start lexical, leave an embedding seam

The query is almost always a **method name**, a **type name**, or a **short task phrase**. Lexical retrieval
(TF-IDF / BM25 over the chunk text, with the method/type name up-weighted) nails the first two and does acceptably
on the third. It is deterministic, needs no model, and adds no heavy dependency.

**v1: `Build5Nines.SharpVector`** (the suggested in-memory .NET vector DB). Its `BasicMemoryVectorDatabase` uses a
built-in **TF-IDF** vectoriser — no external embedding model, no ONNX, no model download. Build the index once at
server start (or lazily on first `Search`): parse docs → chunks → `db.AddText(chunk, metadata)`. Sub-second for a
few hundred small chunks; the whole index is a few MB in memory.

Wrap it behind a tiny interface so the retriever is swappable:

```csharp
interface IDocIndex {
    void Add(DocChunk chunk);
    IReadOnlyList<(DocChunk chunk, double score)> Search(string query, int topK, string? area);
}
```

**v2 (only if recall demands it): embedding retrieval.** Task-phrase queries ("get a foothold" → `ExploitAsync`)
are where lexical is weakest. An ONNX sentence-embedder over the same chunks fixes that. **Constraint:** the current
architecture rule keeps `Camel.Search` (the ONNX/vector stack) out of the Server's dependency graph — it is a
`Camel.Training`-only reference. Honour that: do **not** pull `Camel.Search` into the Server for v2. Either (a) keep
the embedder in its own small package the Server may reference, or (b) revisit that rule deliberately. Do not
back-door it. v1's lexical path needs none of this, which is a reason to ship it first.

### Where it lives

`Camel.Server`, next to the `Execute` tool (`[McpServerTool]`), reading the same embedded doc files
`CamelResources` already serves. One `DocIndex` per investigation type, built from that server's own docs, so the
PenTest server searches only offensive methods and the DFIR server only blue-team ones — no cross-leak, mirroring
how the resources are already split per server.

### Dependency + guardrail note

`Build5Nines.SharpVector` is a NuGet package. Per the project guardrail, do not add it automatically — the
implementer prompts for the install. It is MIT-licensed and dependency-light.

---

## Recommendation

1. **Do Layer 1 now.** Low risk, ~1 hour, directly kills the "116 KB blob" the agent hit, and produces the per-area
   slices Layer 2 indexes. Nothing is wasted.
2. **Then Layer 2, lexical (SharpVector TF-IDF).** No model, no `Camel.Search` dependency, deterministic. This is
   the durable answer to "find the API by intent" and it scales with the API.
3. **Defer embeddings** until a real recall miss on task-phrase queries justifies the model dependency and the
   `Camel.Search`-rule conversation.

Keep the `discipline` resource whole throughout — it is narrative, meant to be read start to finish, and is small.

## Open questions

- **Index build cost at startup** vs lazy-on-first-`Search`. Lazy avoids paying it when a session never searches;
  startup avoids a first-call latency spike. Lean lazy — most of the build is cheap and many sessions are short.
- **Does any target client auto-read all resources?** If yes, Layer 1's resource proliferation needs rethinking
  (a single index resource + Search only). The harness has the agent choose, so this is not a blocker today.
- **Snippet length cap** — long enough to write the call (signature + the load-bearing sentence), short enough that
  `topK: 8` stays well under a screen. Start ~400 chars/chunk, tune against real agent runs.
- **Should `Search` also cover the `discipline` and `CaseTemplate` prose?** Probably not — those are read whole, not
  looked up by intent. Keep the index to methods + schemas.
