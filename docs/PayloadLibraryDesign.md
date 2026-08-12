# Design: a context-keyed payload library (observe → retrieve → fire)

## The gap this closes

Camel's payload sets are **fixed and small**. `BrowserToolkit.ConfirmDomXssAsync` ships 10 built-in vectors and the
`HuntWebVulnsAsync` sweep uses 4. They cover the textbook breakouts (raw element, attribute-value break, `img`/`svg`
handlers, a `javascript:` URL) and nothing else. Against an application with **any** input filtering — the normal
case on anything written this decade — they all fail, and the result reads as `NotReflected` / `Reflected`: a clean
verdict that means "our four payloads didn't work", not "this parameter is safe".

The missing piece is not a better *oracle* — the dialog/beacon execution oracle is already the strongest part of the
web capability. It is **payload selection**: choosing vectors that fit the filter *this page actually has*.

That is precisely the knowledge a published cheat sheet encodes, and precisely the observation the
[Browser DOM API](BrowserDomApiDesign.md) can now make. This design joins the two.

## Why this is a *query*, not a RAG

The tempting framing is "index a technique corpus and retrieve semantically". For this corpus that is the wrong
tool. `reference/articles/cheat-sheet.pdf` (PortSwigger Research, XSS cheat sheet) is not prose — it is a
**structured database** whose every entry is keyed by facets:

| Facet | Example values |
|---|---|
| tag | `svg`, `iframe`, `custom tags`, `a`, `object` |
| event handler | `onanimationcancel`, `onauxclick`, `onbeforeinput` |
| browser | Chrome / Firefox / Safari, with per-vector compatibility |
| framework + version | Angular, Vue **2**, jQuery — framework sandbox escapes and CSTI |
| interaction | fires automatically vs requires user interaction |
| length | vector length (the tie-breaker when a field has a size cap) |

Facets are what the agent already knows from observation. So retrieval is a **filter over structured rows**, and
choosing that over embeddings buys three things that matter here:

1. **Determinism.** The same page state yields the same vector set — a property a security finding needs and a
   nearest-neighbour search cannot give.
2. **Auditability.** A finding can cite *which* vector, from *which* source section. `"vector=onanimationcancel/custom-tag,
   source=portswigger-xss-cheatsheet"` is a provenance line; "the retriever ranked it 0.83" is not.
3. **No model, no embedding step.** It is a table lookup. (The same reason `SearchToolDesign.md` starts lexical.)

**Semantic retrieval is the right tool for the *other* corpus** — Camel's own API surface, where the query is a
developer's intent in prose. Keep the two apart (see *Relationship to the Search tool* below).

## The loop this unlocks

Every step already exists except retrieval:

```js
// 1. OBSERVE — what does this page actually do? (DOM API, Enumerate)
const page  = (await BrowserToolkit.OpenAsync(url)).Result;
const libs  = (await page.Libraries()).Result;         // e.g. [{Name:'Vue', Version:'2.6.14'}]
const probe = await page.Read("() => { /* reflect a benign marker, read back what survived */ }");

// 2. RETRIEVE — vectors that fit THIS filter and THIS stack
const vectors = Payloads.XssVectors({ framework: 'vue', frameworkVersion: '2', allowsTags: ['svg','x'],
                                      requiresInteraction: false, maxLength: 120 });

// 3. FIRE — through the EXISTING confirmer, so the verdict keeps its low false-positive rate
const r = await BrowserToolkit.ConfirmDomXssAsync(url, 'q', vectors.map(v => v.Vector));
```

Step 3 is the part worth emphasising: `ConfirmDomXssAsync` **already accepts a custom payload array** with `{0}`
marker substitution, and already proves execution with the dialog/beacon oracle. So an agent-selected vector inherits
the same `Executed` vs `Reflected` discipline as a built-in one. **No new confirmation machinery is needed** — which
is exactly the "ship the oracles as composable primitives so bespoke tests inherit low-FP verdicts" principle from
the DOM API design.

**This is the differentiator argument made concrete.** A rule engine cannot do steps 1–2, because the filter's
behaviour is a property of the specific page, discovered at run time. TechDispatch routes by what a target *is*; this
routes by what a page *does*.

## The model

```
PayloadVector {
  Id:                  "xss-onanimationcancel-customtag"   // stable, citable
  Vector:              "<style>@keyframes x{...}</style><xss id=x style=... onanimationcancel=\"{0}\"></xss>"
  Class:               xss | ssti | traversal | sqli       // extensible; XSS first
  Tag:                 "custom tags"                       // null when not tag-scoped
  Event:               "onanimationcancel"                 // null when not event-driven
  Frameworks:          [{ Name: "vue", VersionRange: "2" }] // null/empty = framework-agnostic
  Browsers:            ["chrome", "firefox"]               // where it is known to work
  RequiresInteraction: false                                // a vector needing a click is useless in a sweep
  Length:              132
  Source:              "portswigger-xss-cheatsheet"        // provenance, carried onto the finding
  Reference:           "…#onanimationcancel"
}
```

Two deliberate choices:

- **`{0}` marker substitution, not a hard-coded `alert(1)`.** Imported vectors have their payload body rewritten to
  the confirmer's marker convention, so the existing oracle attributes an execution to *our* run. A vector whose
  body cannot be substituted (it demonstrates a side effect other than script execution) is imported with
  `RequiresInteraction`/`Unsupported` set rather than silently mangled.
- **`RequiresInteraction` is first-class.** The cheat sheet's own top-level split is "event handlers that do not
  require user interaction" — and that is the difference between a vector usable in an automated sweep and one that
  needs a click. Until DOM API Phase 2 lands (`Click`), interaction-required vectors are retrievable but not
  auto-fired, and the count is reported (the same "make the zero legible" rule as form candidates).

## The query surface

Bound as a JS global (`Payloads`), **ungated** — it is a local reference lookup that touches no target, exactly like
the knowledge bases' keyless sources. Firing what it returns is what costs `Exploit`.

```
Payloads.XssVectors({ tag?, event?, framework?, frameworkVersion?, browser?,
                      allowsTags?: string[], requiresInteraction?, maxLength?, limit? })  -> PayloadVector[]
Payloads.Get(id)                                                                          -> PayloadVector
Payloads.Sources()                                                                        -> { Name, Count, Licence, Version }[]
```

`allowsTags` is the interesting one: it takes the tags the agent *observed* surviving the filter and returns only
vectors built from those. That is the whole point — retrieval keyed on evidence, not on a guess.

## Relationship to what already exists

Three neighbouring things; keeping the boundaries clean matters.

| | unit | who runs it | keyed on |
|---|---|---|---|
| **`PayloadCheckStore`** (TechDispatch) | a whole **check** (request + matcher) | the dispatcher, automatically | what the target **is** (tech tags + version) |
| **Payload library** (this doc) | a **payload fragment** | the agent, deliberately, via an existing confirmer | what the page **does** (filter/stack observed) |
| **Search tool** (`SearchToolDesign.md`) | a doc chunk | the agent, to find API | developer intent (prose) |

The payload library is **not** a second dispatcher and must not become one: it answers "what should I fire here",
never "fire this". The decision and the gate stay with the caller.

## Provenance and the audit trail

A bespoke finding costs more audit rigour than a predefined one (the DOM API design's standing rule). A vector
carries `Id` + `Source`, and both must reach the trail: the retrieval query and the selected vector id are recorded,
so a reviewer can reconstruct *why this payload was chosen for this page* — the evidence chain that makes an
agent-selected test defensible rather than a lucky guess. `auditVulnerability` on such a finding should cite the
vector id alongside the oracle signal and the execution ids.

## ⚠️ Licensing — decide per source *before* importing

This is the gate on what can be built, and it splits cleanly:

| Source | Nature | Redistribution |
|---|---|---|
| **Nuclei templates** | permissive OSS | already our `PayloadCheckStore` source; safe to ship derived data |
| **PortSwigger XSS cheat sheet** | PortSwigger Research content | **verify terms before bundling a derived index.** Local reference use ≠ shipping a derived database |
| **HackTricks** | CC BY-NC-SA | share-alike **and non-commercial** — a real constraint on anything shipped; attribution alone is not sufficient |

Design consequence: the library must support **out-of-tree corpora**. Ship the schema, the query engine and a
permissively-licensed default set; let a restricted corpus be provisioned locally (like the LOLBAS/rockyou pattern)
rather than committed. `Payloads.Sources()` reports what is actually loaded, with its licence, so a report can state
its provenance honestly.

## Safety

- **Retrieval is never authorization.** A returned vector is *data*. Firing it goes through the `Exploit` gate
  exactly as a hand-written payload does. Nothing in this layer weakens the engagement gate.
- **Corpus content is untrusted input.** Curated PortSwigger vectors are one thing; the moment a community corpus is
  ingested, its text is attacker-influenceable. Vectors are treated as opaque payload strings — never as
  instructions, and never executed anywhere but at an in-scope target through the gated primitives.
- **No silent caps.** A `limit` that truncates must be reported, or "12 vectors tried" reads as exhaustive.

## Phasing

1. **Schema + query engine + a small hand-curated XSS set** (permissively sourced or hand-written), wired into
   `ConfirmDomXssAsync`'s `payloads` parameter. Proves the observe → retrieve → fire loop end to end with no import
   pipeline and no licence question.
2. **An importer** for a facet-structured corpus into `PayloadVector` rows, with `{0}`-substitution rewriting and a
   provenance stamp — run against whichever corpus the licence review clears.
3. **Filter-probing helper**: a routine that reflects a benign marker and reports which tags/attributes/events
   survived, so `allowsTags` is derived from evidence automatically rather than by hand. This is the piece that makes
   the loop feel like one call instead of five, and it depends on nothing but the existing DOM API.
4. **Beyond XSS**: the same shape holds for SSTI (engine-keyed) and traversal (OS/encoding-keyed) — but only once
   the XSS slice has proven the model.

## Open questions

- **Where does the filter-probe live** — a DOM API method (`page.ProbeFilter(param)`), or a workflow step? It writes
  a benign marker, so it is arguably `Enumerate`; but it is a *test*, which argues for the workflow layer.
- **Vector rewriting fidelity.** Substituting `{0}` into a vector that carries its own quoting/encoding can break it.
  Import needs a validation pass that at minimum confirms the rewritten vector still parses as the intended markup.
- **Ranking within a facet match.** Length is the obvious tie-breaker (field size caps), but "most likely to work" is
  a judgement the corpus does not encode. Start with shortest-first + browser-match; do not invent a score.
- **Overlap with Phase 2 `RunPayload`.** Once the DOM API can fire payloads directly, the library should feed that
  path too — the retrieval surface is the same, only the execution primitive changes.
