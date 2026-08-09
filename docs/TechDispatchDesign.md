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

## Validation against `zap-extensions` (2026, the actual rule repo)

Inspected the real active-scan rules (not the core framework), which confirms the design rather than just the idea:

- **`Eligible` is exactly ZAP's `targets(TechSet)`.** e.g. `SqlInjectionMySqlTimingScanRule.targets(t)` is literally
  `t.includes(Tech.MySQL)`. **26+ ascan rules** declare a tech target this way — the pattern is proven at scale, and
  those 26 are the concrete import corpus: `Log4ShellScanRule`, `Spring4ShellScanRule`, `SpringActuatorScanRule`,
  `React2ShellScanRule`, `Text4ShellScanRule`, `RemoteCodeExecutionCve20121823ScanRule`, the per-DB
  `SqlInjection{MySql,MsSql,Oracle,PostgreSql,SqLite,Hypersonic}TimingScanRule`, `LdapInjectionScanRule`,
  `MongoDbInjectionScanRule`, `CommandInjectionScanRule`. Every one is a `CheckManifest` with a populated
  `appliesTo`.
- **The per-DB SQLi split is the model for version/tech-scoped checks.** ZAP does not have one "SQLi" rule; it has a
  generic one plus a timing rule per database, each `targets()`-ing its DB. That is the answer to the open question
  below on granularity — split by the tech that changes the payload, tag each, let dispatch route.
- **Even "generic" rules are tech-aware.** `PathTraversalScanRule` carries `Tech.Linux` / `Tech.Windows` matchers to
  pick its file targets (`/etc/passwd` vs `Windows/system.ini`). So `appliesTo: []` (agnostic) is right for the
  *applicability* gate, but a check still wants **OS tags** to choose payloads — the manifest's `appliesTo` and a
  check's internal tech-branching are different uses of the same vocabulary.

### Separately — confirmer improvements found in passing (not TechDispatch, but worth logging)

ZAP's SSTI / traversal rules are more thorough than Camel's current confirmers in three concrete ways:

1. **Context-escape prefixes.** ZAP's SSTI tries `WAYS_TO_FIX_CODE_SYNTAX = {"\"", "'", "1", ""}` before the
   payload — to break *out* of a string/expression context the input sits in, so a sink where input lands inside an
   already-parsed expression is reached, not just statement-level input. **DONE for `ConfirmSstiAsync`** (2026):
   prefixes `["", "'", "\""]`, bare-first so the common case still costs one request per syntax and the breakouts
   only run as a fallback. **Not added to `ConfirmPathTraversalAsync`:** traversal's context-escape analogue is
   null-byte suffix truncation, which is dead on modern stacks (PHP ≥5.3.4), so it would be noise — the traversal
   confirmer's coverage lives in its encoding × depth-climb matrix instead.
2. **Error-polyglot (blind-SSTI lead). DONE (2026).** When the arithmetic oracle finds nothing, `ConfirmSstiAsync`
   sends a syntax-breaking polyglot; if it triggers a *template* error (not a generic 5xx) that a benign same-length
   control does not, it returns a new `ErrorSignal` verdict — explicitly a **lead, not a confirmation** — for the
   escaped-output case where the engine processes input but the product never reaches the body.
3. **Traversal encodings. DONE (2026).** Added the leading-`/` variant and `%c0%af` overlong-UTF-8 `../` to the
   payload set (deduped so Windows targets don't resend identical bytes).

Still out of scope: ZAP's **sink-point vs insertion-point** model — inject at A, detect render at B — which is how
it does *stored* SSTI/XSS. Our confirmers are same-response only (except the stored-XSS browser path). A real model
change, not a confirmer tweak; deferred until stored-injection confirmation beyond XSS is actually wanted.

## Where it plugs into Camel

- **`AnalyzeWebStackAsync`** already fingerprints. Add: fingerprint → `TechSet` (via the normalization table) →
  `Eligible` filter over the check corpus → run the eligible checks → fold confirmed results in alongside the
  existing version→CVE leads (kept separate: dispatched checks that *confirm* are findings; CVE lookups stay leads).
- **The engagement gate is unchanged and load-bearing.** Each manifest's `ActivityClass` flows through the existing
  `GuardActivity`, so a dispatched exploit check is refused exactly like a hand-called one unless `Exploit` is
  authorized. Dispatch decides *relevance*; the gate decides *permission*. Keep them separate.

## Phasing

1. **`TechTag` + normalization table + `TechSet` from the fingerprint. ✅ DONE (2026-08).** Pure, testable, no
   runner needed. On its own this lets `AnalyzeWebStackAsync` report *"detected: jenkins, tomcat"* as structured
   tags (`AttackPlan.TechStack`, a `DetectedTech[]`) instead of raw whatweb strings — already useful. Implemented in
   `src/Camel.PenTest.Workflows/TechDispatch/` (`TechTag.cs`, `TechCatalog.cs` — the normalization table is a
   data-driven ordered rule list, first-match-wins per token so `Apache-Coyote` ⇒ `tomcat`, not `apache-httpd`).
2. **`CheckManifest` + `Eligible` dispatch, over the built-in checks only. ✅ DONE (2026-08).** Proves the routing
   end-to-end with zero new check formats. `CheckManifest.cs` (the neutral manifest + `Eligible` = ZAP's
   `targets(TechSet)`), `CheckDispatcher.cs` (filter-by-eligible → gate-by-activity → run, with per-check failure
   isolation), and `DefaultConfigChecks.cs` — the phase-2 corpus: `git-directory-exposed` (agnostic),
   `jenkins-script-console-exposed` `[jenkins]`, `tomcat-manager-exposed` `[tomcat]`,
   `glassfish-admin-console-exposed` `[glassfish]`. Wired into `AnalyzeWebStackAsync` /
   `BuildWebStackAttackPlanAsync`; confirmed findings land in `AttackPlan.DispatchedFindings`, kept separate from
   the version→CVE `Entries`. Directly closes the E2E gap that motivated this. **Note on activity class:** the
   checks are `Exploit`-class (not `Enumerate`), because the only body-returning HTTP primitive
   (`WebApp.HttpRequestAsync`) is itself `Exploit`-gated — so declaring them `Exploit` keeps the manifest's activity
   aligned with the gate the primitive enforces, no drift. They self-skip in a baseline run (recorded) and fire when
   Exploit is authorized; the `TechStack` detection is baseline and always reported. Tests:
   `tests/Camel.Tests.Workflows/PenTestTechDispatchTests.cs`. *(Deferred within phase 2: routing the existing
   parameter-driven confirmers — SSTI/traversal/IDOR/CORS — through the same dispatcher; they need a discovered
   parameter surface `AnalyzeWebStackAsync` does not have. The dispatcher and manifest already model them; wiring
   waits until dispatch runs from a crawl that supplies insertion points.)*
3. **A BCheck parser emitting manifests** (the deferred runner idea), then a ZAP-rule adapter. Both land as new
   check sources behind the same dispatch, no core change. The `CheckSource` enum (`Builtin`/`BCheck`/`Zap`) and the
   rule-runner-agnostic `WebCheck(Manifest, Run)` pairing are already in place for this.

Phase 2 is the one that pays back the `pentest-agent` finding; phases 1–2 need no external rule corpus at all.

### The verbatim payload store (declarative checks) — ✅ DONE (2026-08)

Alongside the hand-written default-config checks, phase 2 gained a **declarative, data-driven check format** — the
"verbatim payload store" — for the class the store exists to cover: precise, long-tail, **version-pinned** tests
whose exact paths/signatures a model would misremember (an Apache 2.4.49 traversal, an exposed `.env`). Built in
`PayloadCheck.cs` (`PayloadCheck` + a compact matcher engine: `Matcher` word/regex/status × body/header/status,
`and`/`or` within a matcher and across matchers, `negative`) and `PayloadCheckStore.cs` (the curated seed +
`TechDispatchCorpus.Builtin` aggregator). A `PayloadCheck.ToWebCheck()` lowers an entry into the **same** `WebCheck`
the hand-written confirmers emit, so it routes through the existing dispatcher unchanged — *the store is data, the
runner is generic.* This is the phase-3 runner arriving early, hand-fed instead of bulk-imported.

**Version scoping landed with it** (the open question below, now answered): `CheckManifest.AppliesToVersion` +
`VersionRange` (a half-open `[Introduced, Fixed)` with a tolerant dotted-numeric compare). `Eligible` now gates on
tag **and** version — an unknown detected version does not suppress (the response matcher is the backstop), but a
detected patched version does. Seed: `CVE-2021-41773` (Apache 2.4.49/2.4.50 traversal, version-scoped),
`php-info-disclosure` (tech-scoped, `[php]`), `dotenv-exposed` (agnostic). Tests in `PenTestTechDispatchTests.cs`.

**Source-format analysis (which corpora are ingestible).** The declarative format deliberately mirrors the two
sources that *are* data:
- **Nuclei templates** — declarative YAML (`http:` path/method/headers/body + `matchers` word/regex/status with
  `condition`/`matchers-condition` + `info`/`classification` tags). A curated entry transcribes one directly; a bulk
  importer (phase 3) targets the `PayloadCheck` shape. **The primary source.**
- **Burp BChecks** — a declarative DSL (`given … send request … if {response.body} contains … then report issue`).
  Different syntax, same send+match+tag shape; absorbs into the same intermediate representation. LGPL-3.0 → keep
  license-isolated behind the manifest interface.
- **ZAP scan rules** — **not** a data format: imperative Java (`AbstractAppPlugin` + `targets(TechSet)`). The
  reusable part is the tech-targeting *metadata* (already captured by `CheckManifest`) and the *idea*, not a payload
  file. A **pattern reference**, not an ingest source — you'd extract constants or reimplement, not parse.

## Open questions

- **Fingerprint richness.** whatweb is good but misses things a favicon-hash / distinctive-path probe would catch
  (Jenkins' `/login?from=`, GlassFish' `/common/index.jsf`). The normalization table can include path-probe rules,
  but that turns fingerprinting into its own active step — decide whether tech detection stays passive or gains an
  active confirm.
- **Version-scoped tags. ✅ RESOLVED (2026-08).** The verbatim payload store needed it, so `CheckManifest` gained an
  optional `AppliesToVersion` (`VersionRange`, half-open `[Introduced, Fixed)`) and `Eligible` now gates on tag AND
  version (unknown version does not suppress; a detected patched version does). `appliesTo` stays a bare tag list;
  the version window is a separate optional field on the manifest, so a check that does not need it is unaffected.
- **Corpus provenance in findings.** A finding from a dispatched check should cite which check + which source, so a
  BCheck-derived result is distinguishable from a built-in one in the report.
