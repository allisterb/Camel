# Design: technology-driven check dispatch (rule-runner agnostic)

## The gap this closes

`VulnAnalysisWorkflow.AnalyzeWebStackAsync` today: fingerprint the web target (whatweb) → look the product+version
up in NVD/KEV → emit **unconfirmed** `AttackPlan` leads. It has no step that says *"this stack runs Jenkins — go
confirm the exposed script console."* So it structurally misses the whole class of **default-config / anonymous
RCEs** whose exploitability is not a version→CVE match. The `pentest-agent` E2E run proved the cost: it never
surfaced Jenkins (8484) or GlassFish (8080), the box's two most iconic footholds, from `AnalyzeHostAsync` — they
had to be hand-fingerprinted afterward.

The missing piece is a **dispatch layer**: given what a target *is* (its fingerprint), decide which checks are
worth running, and run only those. This is the mechanism a scanner's "scenario" / "playbook" library rides on.
Borrowed from ZAP's scan engine, kept independent of any one rule format so BCheck, ZAP rules, and hand-written
checks can all feed it.

## What ZAP does (the pattern worth taking)

ZAP's `Plugin` model (`zaproxy` core, Apache-2.0) has two reusable ideas, and **only the ideas** — none of its Java
is copied:

1. **`targets(TechSet)`** — every scan rule declares the technologies it applies to. The engine runs a rule against
   a target only when the target's fingerprint intersects the rule's tech tags. A `Tech` tree
   (MySQL, PostgreSQL, Java, Spring, ASP, …) is the shared vocabulary both sides speak.
2. **Input vectors / `Variant`** — a rule does not hard-code *where* it injects; the engine enumerates insertion
   points (query, path, cookie, header, JSON body, …) and the rule is applied at each. *(Camel already adopted this
   half — `InsertionPoint` on the SSTI / path-traversal confirmers.)*

`AttackStrength` / `AlertThreshold` are the intensity/confidence dials that pair with dispatch — they map onto
Camel's engagement intensity caps if a runner ever needs a "how hard do I probe" knob.

## The design: a `TechTag` vocabulary + a dispatch predicate

Two small pieces, both rule-format-agnostic.

### 1. A normalized technology vocabulary

A `TechTag` is a stable identifier for a product / language / framework / server — `jenkins`, `glassfish`,
`elasticsearch`, `spring`, `apache-httpd`, `php`, `tomcat`, `mysql`. The fingerprinter's raw output
(whatweb plugin names, `Server` headers, favicon hashes, distinctive paths) maps into this vocabulary via a
**normalization table** — one place that knows "whatweb's `Jenkins` plugin ⇒ `jenkins`", "`X-Jenkins` header ⇒
`jenkins`", "`Server: GlassFish` ⇒ `glassfish`". The table is data, not code, so it grows without touching logic.

A target's fingerprint becomes a `TechSet` — the set of `TechTag`s detected, each with an optional version.

### 2. A dispatch predicate every check declares

A check (whatever its source format) carries a small manifest:

```
CheckManifest {
  id:            "jenkins-script-console-exposed"
  appliesTo:     TechTag[]        // e.g. [jenkins]   — empty = tech-agnostic, always eligible
  insertionPts:  InsertionPoint[] // where it injects, if applicable
  activity:      ActivityClass    // Enumerate / Exploit — feeds the engagement gate
  source:        "bcheck" | "zap" | "builtin"
}

bool Eligible(CheckManifest c, TechSet fingerprint) =>
    c.appliesTo.Length == 0 || c.appliesTo.Any(fingerprint.Contains);
```

Dispatch is then: fingerprint the target → filter the check corpus by `Eligible` → run only those, each already
carrying the `ActivityClass` the **engagement gate** checks. Nothing runs that the target can't be, and nothing
runs that the engagement didn't authorize.

**This is the whole idea.** It is deliberately not a rule engine — it is the routing layer that sits in front of
one. It answers "which checks are worth running here", and leaves "how a check is expressed and executed" to a
separate runner.

## Why keep it rule-runner-agnostic

Three check sources are on the table, and they should share one dispatch layer:

| Source | Format | Licence | Notes |
|--------|--------|---------|-------|
| **BChecks** | PortSwigger DSL (`given host` / `given response`) | LGPL-3.0 | ~237/264 implementable without Collaborator; heavily default-config + CVE checks |
| **ZAP rules** | Java scan rules (in `zap-extensions`, not the core repo) | Apache-2.0 | the actual attack logic; already carry `targets(TechSet)` tags to import |
| **Built-in** | hand-written C# (the existing confirmers) | — | SSTI, traversal, XSS, CORS, CSRF, IDOR, … |

If dispatch is defined over a neutral `CheckManifest`, a BCheck parser, a ZAP-rule adapter, and the built-in
confirmers all emit manifests into one corpus, and one dispatcher routes across all of them. The runner(s) that
*execute* a check stay separate and pluggable — the BCheck interpreter (see the deferred BCheck-runner idea), a
ZAP-rule shim, or a direct C# call. **Licence isolation falls out for free:** BChecks stay in their own
LGPL-marked assembly behind the manifest interface; Camel core depends on the interface, not the LGPL content.

## Where it plugs into Camel

- **`AnalyzeWebStackAsync`** already fingerprints. Add: fingerprint → `TechSet` (via the normalization table) →
  `Eligible` filter over the check corpus → run the eligible checks → fold confirmed results in alongside the
  existing version→CVE leads (kept separate: dispatched checks that *confirm* are findings; CVE lookups stay leads).
- **The engagement gate is unchanged and load-bearing.** Each manifest's `ActivityClass` flows through the existing
  `GuardActivity`, so a dispatched exploit check is refused exactly like a hand-called one unless `Exploit` is
  authorized. Dispatch decides *relevance*; the gate decides *permission*. Keep them separate.

## Phasing

1. **`TechTag` + normalization table + `TechSet` from the fingerprint.** Pure, testable, no runner needed. On its
   own this lets `AnalyzeWebStackAsync` report *"detected: jenkins, elasticsearch"* as structured tags instead of
   raw whatweb strings — already useful.
2. **`CheckManifest` + `Eligible` dispatch, over the built-in confirmers only.** Proves the routing end-to-end
   with zero new check formats: e.g. tag the CORS/CSRF confirmers tech-agnostic, and add a couple of built-in
   default-config checks (Jenkins script console, GlassFish admin) tagged `[jenkins]` / `[glassfish]` — which
   directly closes the E2E gap that motivated this.
3. **A BCheck parser emitting manifests** (the deferred runner idea), then a ZAP-rule adapter. Both land as new
   check sources behind the same dispatch, no core change.

Phase 2 is the one that pays back the `pentest-agent` finding; phases 1–2 need no external rule corpus at all.

## Open questions

- **Fingerprint richness.** whatweb is good but misses things a favicon-hash / distinctive-path probe would catch
  (Jenkins' `/login?from=`, GlassFish' `/common/index.jsf`). The normalization table can include path-probe rules,
  but that turns fingerprinting into its own active step — decide whether tech detection stays passive or gains an
  active confirm.
- **Version-scoped tags.** Some checks apply to a tech *at a version range* (Spring4Shell = specific Spring + JDK).
  `appliesTo` may need `(tag, versionRange)` rather than a bare tag. Start with bare tags; add ranges when a real
  check needs one.
- **Corpus provenance in findings.** A finding from a dispatched check should cite which check + which source, so a
  BCheck-derived result is distinguishable from a built-in one in the report.
