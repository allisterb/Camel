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

## Layer 1: split the resources by subject area — ✅ BUILT (2026-08-12)

**As-built**, with the deviations from the plan below recorded inline:

| | Planned | Built |
|---|---|---|
| Slicing | areas = bound globals, located by heading text at any level | as planned — `SdkDocs.Slice` (`src/Camel.Server/SdkDocs.cs`) |
| Area list | derived from `BindDomainGlobals` | `SdkDocs.DfirAreas` / `PenTestAreas`; both MCP tool classes now bind from a single declarative `domainGlobals` table exposing `DomainGlobalNames`, and a test asserts areas ≡ bound globals in both directions |
| Per-area URIs | one `{area}` UriTemplate parameter | **concrete resources** (`CamelResources.AreaResources`) — a template is only discoverable via `resources/templates/list`, so a client that ignores templates could never find them; ~40 small `resources/list` entries is the cheaper risk |
| Index size | < 15 KB | **PenTest 20.7 KB / DFIR 28.8 KB.** The 15 KB budget was self-inconsistent (the mandatory preamble alone is 10.4 KB red / 11.4 KB blue). Startup drops 226 KB → 20.7 KB (red) and 162 KB → 28.8 KB (blue); a task then pays 5–20 KB per area touched |
| Inventory | ~60 chars/method | names only (methods + model types), receivers kept where an area groups several globals (`Nvd.CveAsync` vs `VulnCheck.CveAsync`); purpose line is the area's own first sentence, so it cannot drift |
| Heading normalization | make every global resolvable | one edit was needed: `### External knowledge bases` → `### Knowledge bases (external intelligence)` (matching the schema doc). `WorkflowResult<T>`, `(Linux plugins)` and slash-merged headings are handled by the matcher instead of by editing docs |

Beyond the plan: `camel://sdk/schema` now serves a **signpost** (<1 KB) rather than 95–120 KB, and a coverage test
asserts every method bullet and every `### X Schema` in all four documents is reachable through the map — which is
what makes "the inventory is complete, so absence is real" a checked property rather than a hope. Guardrails live in
`tests/Camel.Tests.Server/SdkDocAreaTests.cs`.

Still open from this layer: re-run a `tests/pentest-agent*` harness so the acceptance test is the agent's own account
of the startup cost.

### Original plan

Worth doing **regardless of Layer 2**, because Layer 2 indexes exactly these slices. What follows is measured, not
estimated.

### What we are actually dealing with (measured 2026-08)

| Doc | Size | Top-level (`##`) sections | Largest |
|---|---|---|---|
| `Camel.pentest.core.md` | **106 KB** | **4** | `## Method signature index` — **94 KB** |
| `Camel.pentest.schema.md` | **120 KB** | 17 | `WebExploitationWorkflow` 23 KB |
| `Camel.core.md` | 67 KB | 23 | `MemoryAnalysisToolkit` 9 KB |
| `Camel.schema.md` | 95 KB | 21 | `WindowsAnalysisWorkflow` 18 KB |

An agent following the mandated "read both first" pays **226 KB (~57k tokens) on the PenTest server before its first
call** — and four consecutive E2E runs reported it, the last one blowing both the resource-read *and* file-read caps
and resorting to byte-offset shell slicing.

### ⚠️ The gotcha that invalidates "just split on a heading level"

The heading level that names a toolkit/workflow **is not consistent** — not between the two docs, and not even within
one doc:

- **`Camel.pentest.core.md`** — toolkits are `###`; workflows are `####` nested under a single `### Workflows`
  (`WebExploitationWorkflow` 16.6 KB, `VulnAnalysisWorkflow` 6.7 KB, …). Splitting at `##` yields one 94 KB blob;
  splitting at `###` merges all seven workflows into one 33 KB section.
- **`Camel.pentest.schema.md`** — everything is `##`.
- **`Camel.schema.md`** — `##`, but with **duplicate and merged** area names: `MemoryAnalysisToolkit` appears twice
  (the second is "(Linux plugins)"), and one section is `DiskAnalysisToolkit / DiskAnalysisWorkflow (carving &
  recovery)`.

A level-based slicer produces wrong or missing areas on three of the four documents.

### The design: areas are the **bound globals**, not the headings

The server already knows the authoritative area list — it is the set of globals `BindDomainGlobals` binds
(`ScanningToolkit`, `BrowserToolkit`, `VulnAnalysisWorkflow`, …). So:

- **An area = one bound JS global.** Slicing locates the heading whose text matches that name **at whatever level**,
  and takes everything until the next heading of the same-or-higher level. Duplicate/merged headings for one area are
  concatenated.
- **Slice at runtime, from the existing single markdown file.** Do **not** fragment the docs on disk: maintainers keep
  one file per doc (one place to edit, no cross-file drift), and the server derives the slices on load. This also
  keeps `git diff` on an API change readable.
- **This permanently kills the heading-drift bug class.** A startup/unit check asserts *every bound global resolves to
  a section in both core and schema*. That is exactly the D-3 defect an E2E agent hit — browser types sat under
  `## WebAppToolkit`, so it concluded `ScannerRunResult` "isn't in the schema doc" when it was — turned into a build
  failure instead of a silent wrong answer.

### Resource surface

```
camel://sdk/index            # NEW DEFAULT — the map (see contract below).  Target < 15 KB
camel://sdk/core/{area}      # per-area method reference        (MCP UriTemplate parameter)
camel://sdk/schema/{area}    # per-area schemas
camel://sdk/core             # UNCHANGED URI, NEW BODY: serves the index (the behaviour change that fixes the tax)
camel://sdk/core/all         # the whole document — back-compat / "give me everything"
camel://sdk/schema/all
camel://sdk/discipline       # unchanged — meant to be read whole
```

Using an MCP **UriTemplate parameter** (`{area}`) keeps `resources/list` to a handful of entries rather than ~40
concrete resources.

**Redirecting `camel://sdk/core` to the index is the load-bearing change.** If that URI keeps returning 106 KB while
the tool description says "read this first", nothing improves — the split would just add options nobody takes.

### The index contract (the part that must not be got wrong)

The hard rule is *"call only methods listed in core; read only properties listed in schema."* If an agent reads two
areas out of twenty, it must still be unable to (a) invent a method, or (b) conclude something is absent. So the index
carries the **complete inventory of names** — every object, every method name, one line of purpose, and the area to
read for detail — while the *detail* (parameters, return types, remarks) lives in the area slices.

That is what makes selective reading safe rather than merely cheaper. Rough budget: ~200 methods × ~60 chars ≈ 12 KB,
plus the execution model and authorization preamble (already 4.5 KB + 5.8 KB on the PenTest side, both mandatory
reading). Keep the whole index **under 15 KB**.

### Consumers that must change with it

The split is only half the work; three places currently mandate the old protocol:

1. **`CamelMCPTools`' `Execute` tool description** — today: *"you MUST read camel-sdk-core … and camel-sdk-schema"*.
   Becomes: read `camel://sdk/index`, then the `core/{area}` + `schema/{area}` for the areas you touch.
2. **`CaseTemplate/CLAUDE.md` and `CLAUDE.pentest.md`** — same instruction, repeated to the case agent.
3. **The `camel-sdk-discipline` resource** — references its companions by name.

### Sizing expectation

Index (~12 KB) + the two or three areas a task actually touches (5–20 KB each) ≈ **30–50 KB instead of 226 KB** —
roughly a 5× cut, and paid only for what is used. Two areas stay heavy and are candidates for a later sub-split if
measurement justifies it: `BrowserToolkit` (20 KB core + 15 KB schema) and `WebExploitationWorkflow` (17 KB + 23 KB).

### Order of work

1. **Heading normalization + the guardrail test** (small, do first): make every bound global resolvable in both docs;
   add the test that asserts it. Fixes the D-3 class immediately, even before any split ships.
2. **Slicer + area resolution** (pure, unit-testable against the four real docs — assert no area is empty and the
   slices reconstruct the whole document).
3. **Index generation.** Prefer *generated* over hand-written: derive the name inventory from the same slices, so it
   cannot drift from the docs. Hand-write only the per-area one-liners.
4. **Register the new resources; repoint `camel://sdk/core` at the index; keep `/all`.**
5. **Update the three consumers above**, then re-run a `tests/pentest-agent*` harness — the agent's own account of the
   startup cost is the acceptance test.

### Costs and caveats

- More resources in the list (mitigated by the UriTemplate parameter). Fine as long as a client does not bulk-read
  every body — the harness has the agent choose. Flag it if a future client auto-loads.
- Still not a real search: the agent picks an area from the index, then reads that whole area. Good enough to remove
  the startup tax; it does not answer "which method does X" without reading an area. That is Layer 2.
- The maintenance rule stays "update core + schema + CaseTemplate", since the files do not fragment — only the *serving*
  granularity changes.

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
