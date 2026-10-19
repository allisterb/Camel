# Knowledge corpora — bulk datasets acquired once, queried offline (design plan)

*Status: design, not built. Extends [KnowledgeBases.md](KnowledgeBases.md), which covers the live
query-an-API case. Consumed by [DfirReporting.md](DfirReporting.md) §3.4 (the ATT&CK catalog).*

---

## Thesis

`Camel.Intel` models an **external source you query one item at a time**: a CVE id in, a record out,
over HTTP or a CLI. It has no notion of a **dataset you acquire once and then query locally** — and we
already depend on two of those, provisioned ad hoc, outside every guarantee the KB layer provides.

The gap is exactly the one to close: **we can query a local file KB, but we cannot say "download this
whole corpus, and if it is available, query it."** Adding that serves both servers — ATT&CK, Sigma, and
YARA rules on the blue side; nuclei templates, wordlists, and GTFOBins on the red side — and it turns
provenance, licensing, and version-pinning from per-toolkit accidents into properties of the layer.

---

## 1. What exists today

**Two precedents, both ad hoc, both inside `Toolkit.InstallMissingTools()`:**

| Corpus | How | Where |
|---|---|---|
| Yara-Rules community pack | `InstallGithubRepoZip("yara-rules", <github zip>, "/opt/yara-rules", checkPath)` | `Toolkit.cs:212`, called from `YaraToolkit` |
| LOLBAS dataset | `InstallFile("lolbas.json", <lolbas-project api>, "/opt/zimmermantools/lolbas.json")` | `Toolkit.cs:166`, called from `WindowsAnalysisToolkit` |

Both helpers are synchronous, `wget`-based, return `bool`, and decide "is it installed?" with a bare
`test -e`. The querying half is equally ad hoc: `LoadLolbasAsync` is a `cat` plus a parse.

**What they do not have — all of which the KB layer already provides for HTTP sources:**

- **No version.** `test -e` cannot tell a two-year-old rules pack from today's.
- **No integrity check.** Whatever `wget` returned is what we scan evidence with.
- **No provenance or audit.** KB queries emit `kb-query` events with source, timing, and cache status.
  Corpus acquisitions emit nothing — the report cannot say where the YARA rules came from.
- **No licensing or attribution.** Recorded nowhere, so third-party notices are manual.
- **No refresh policy**, no staleness signal, no way to pin.
- **No offline story.** `wget` fails on an air-gapped workstation and the caller gets `false`.

**Two structural facts that constrain the design:**

1. **`InstallMissingTools()` is called from the `Toolkit` constructor** (`Toolkit.cs:86`). That is what
   caused the session-creation stall — the first `ExecuteJavaScript` blocked on synchronous downloads —
   fixed by making toolkit binding lazy and conditional. **Corpus acquisition must never be
   constructor-time.** It is an explicit, awaited, cancellable operation.
2. **`BindsKnowledgeBases` is `false` on the base `CamelMCPTools` and `true` only on `PenTestMCPTools`
   — knowledge bases are red-only today.** Corpora are needed by both, so they bind in the shared base.

`KbTransport.File` reads a local file the layer never acquired. Corpora are the missing other half.

---

## 2. What a corpus is (and is not)

A **corpus** is a bulk reference dataset: acquired as a whole, versioned, stored on the platform,
queried locally and repeatedly at no marginal cost, and identical for every client.

|  | Knowledge base (existing) | Corpus (new) |
|---|---|---|
| Unit of work | one query, one record | one acquisition, then unlimited local queries |
| Network at query time | yes | **no** |
| Keyed by client data? | often (Shodan, NVD-by-product) | **never** — the dataset is the same for everyone |
| Cost model | rate limits, API keys, quotas | one download, then free |
| Failure mode | API down, key missing, throttled | not acquired, or stale |
| Reproducibility | best-effort cache | **pinned version, hashed** |

**The disclosure distinction matters and is the crux of the safety model.** A Shodan query *sends a
client asset to a third party*, so it is scope-gated and requires the engagement to permit external
disclosure. Fetching ATT&CK or nuclei templates sends **nothing about the client** — it is a public
download that reveals only that someone runs the tool. So:

- Corpus acquisition is **not** a `kb-disclosure` event and must not be gated as one. Gating it that
  way would be security theatre and would block blue work that has no engagement at all.
- It **is** still outbound network traffic from the platform, which a covert engagement may not want.
  So acquisition honours an `AllowNetworkFetch` switch that defaults on, and defaults **off** when the
  engagement is marked unannounced/covert — with side-loading (§5) as the escape hatch.
- Acquisition is **always audited** (`corpus-acquire`), because "what data was this conclusion drawn
  against, and when was it fetched?" is a real evidentiary question.

---

## 3. The model

```csharp
public enum CorpusKind { SingleFile, GithubZip, TarGz, GitClone, Taxii }
public enum CorpusRefresh { Pinned, OnDemand, StaleAfterDays }

public record Corpus(
    string Name,                  // "attack-enterprise", "yara-rules", "lolbas", "nuclei-templates"
    string Url,                   // acquisition source
    CorpusKind Kind,
    string InstallPath,           // where it lands on the platform
    string CheckPath,             // the file whose presence means "acquired"
    string License,               // SPDX id or "MITRE ATT&CK Terms of Use"
    string Attribution,           // notice text reproduced verbatim in reports
    string? Version = null,       // pinned release tag / ATT&CK version, null = tracking a branch
    string? Sha256 = null,        // expected digest, when the source publishes one
    CorpusRefresh Refresh = CorpusRefresh.Pinned,
    int StaleAfterDays = 0,
    string? DistillCommand = null // optional post-acquire reduction (see 3.2)
);
```

Declared in configuration alongside `KnowledgeBases`, so adding a corpus is a config change, not a code
change — matching how tools and KBs are already declared.

### 3.1 The manifest is the point

Every acquisition writes `.camel-corpus.json` into the install directory:

```json
{ "name": "attack-enterprise", "url": "...", "version": "v15.1",
  "sha256": "...", "fetchedAt": "2026-08-26T14:02:11Z",
  "license": "MITRE ATT&CK Terms of Use",
  "attribution": "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." }
```

This is what makes the whole thing worth building. The manifest is read by:

- **`StatusAsync`** — acquired? which version? how old? integrity intact?
- **The report's forensic soundness statement** — [DfirReporting.md](DfirReporting.md) §4.3 item 2 wants
  exactly this: which reference data, which version, fetched when. Today it cannot be answered for the
  YARA rules a malware finding rests on.
- **Third-party notices** — `Attribution` renders automatically. ATT&CK *requires* its notice be
  reproduced; making that a data field rather than a habit is how it stays correct.

### 3.1a TAXII as an acquisition transport (`CorpusKind.Taxii`)

MITRE runs a public TAXII 2.1 server at `https://attack-taxii.mitre.org`, root `/api/v21/`, with three
collections (enterprise / ICS / mobile) and no authentication required. It is a **better way to acquire
the ATT&CK corpus than downloading and parsing the monolithic bundle** — but it is *not* a substitute
for holding the corpus locally, and the reason is in MITRE's own documentation.

**The rate limit decides it: 50 requests per 10 minutes per source IP**, and MITRE states plainly that
users needing more frequent access should download the STIX/JSON bundles instead. So:

- **As a live validation source — no.** One investigation's findings would exhaust the budget, and more
  decisively, per-query validation needs network *at query time*, which breaks §5a. A validation gate
  that requires the internet fails closed in exactly the air-gapped evaluation scenario we just
  committed to handling. Technique validation must be local.
- **As the acquisition transport — yes, and it is cleaner.** `match[type]=attack-pattern` against
  `GET /<api-root>/collections/<id>/objects/` returns just the techniques rather than the full 53.8 MB
  object graph, paginated via the `more` flag. That is a handful of requests, once, comfortably inside
  the limit — and it removes most of the distillation work in §3.2 rather than adding to it.

Two further benefits that fit the model directly:

- **Pinned API roots give us a real version string.** `/api/v21/attack-<x.y>` (e.g. `attack-19.1`)
  addresses a specific ATT&CK release, so `Corpus.Version` becomes an authoritative identifier rather
  than a branch name and a digest. This partly resolves the §9 open question about integrity when the
  source publishes no digest — a pinned root *is* the guarantee.
- **`added_after` is a one-request staleness check.** `StaleAfterDays` can ask "has anything changed
  since our manifest's `fetchedAt`?" for the cost of a single call, without re-acquiring. That makes
  the warn-don't-update policy in §3.3 cheap to honour.

Collection ids are stable and belong in configuration:

| Domain | Collection id |
|---|---|
| enterprise-attack | `x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019` |
| ICS | `x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09` |
| Mobile | `x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858` |

Requires an `Accept: application/taxii+json;version=2.1` header — worth noting because the existing
`KnowledgeBaseClient` HTTP path assumes JSON defaults, so `CorpusKind.Taxii` needs its own header and
pagination handling. Licensing is unchanged: same ATT&CK Terms of Use, same required attribution
notice, recorded in the manifest either way.

### 3.2 Distillation

Some corpora are unusable raw: ATT&CK enterprise STIX is 53.8 MB against the few hundred KB we need.
`DistillCommand` runs once after acquisition and reduces the corpus in place. The manifest records both
the source digest and the distilled digest, so the reduction is auditable rather than magic.

### 3.3 Pinning is a forensic requirement, not a preference

`CorpusRefresh.Pinned` is the default, deliberately. A report that cites "ATT&CK v15.1" or a YARA hit
against a dated rules pack must still mean the same thing when the case is reviewed a year later.
Silent auto-update would make findings irreproducible — the exact property a forensic report exists to
guarantee. `StaleAfterDays` *warns*; it never updates behind the analyst's back. Refresh is an explicit
operation that writes a new manifest and a `corpus-acquire` event.

---

## 4. The client

`CorpusClient` in `Camel.Intel`, mirroring `KnowledgeBaseClient`'s shape so the two read alike:

```csharp
Task<KbResult<CorpusStatus>> StatusAsync(string name);            // acquired? version? stale? intact?
Task<KbResult<CorpusStatus>> EnsureAsync(string name, bool force = false);
Task<KbResult<T>>            QueryAsync<T>(string name, Func<string, T?> map);   // whole-corpus read
Task<KbResult<T>>            QueryFileAsync<T>(string name, string relPath, Func<string, T?> map);
Task<KbResult<string[]>>     GrepAsync(string name, string pattern, int maxHits = 200);
IEnumerable<CorpusStatus>    DescribeCorpora();
```

Notes:

- **`KbResult<T>` throughout**, so corpora fail the way everything else does — never an exception, never
  a null-return. Mind the value-type `Result` trap: gate on `IsSuccess`.
- **`EnsureAsync` is explicit and awaited.** Nothing in a constructor. It is cancellable and reports
  progress, because a rules-pack download is exactly the kind of long operation that has bitten us
  before (the 10s Jint promise timeout, the client idle-timeout abort).
- **`GrepAsync` matters more than it looks.** Most corpus queries in practice are "does this indicator
  appear anywhere in the pack?" — and grepping on the platform keeps the data next to the evidence,
  which is the whole code-mode argument.
- **`DescribeCorpora` parallels `DescribeSources`**, so the server can report corpus status at startup
  the way it already reports KB status.

Audit events: `corpus-acquire` (name, url, version, digest, bytes, duration, distilled) and
`corpus-query` (name, kind of query, hit count). Same provenance pipeline as `kb-query`.

---

## 5. Offline and side-loading

SIFT deployments are often isolated, and a covert engagement may forbid outbound fetches. Both are the
same requirement: **a corpus must be installable without this machine reaching the internet.**

- `EnsureAsync` accepts a local archive or directory as the source instead of a URL.
- A `camel corpus` CLI verb (`status`, `fetch`, `import <path>`, `verify`) lets an operator stage
  corpora ahead of time — including onto an air-gapped workstation from removable media.
- `StatusAsync` reporting *not acquired* is a normal, well-typed answer. Callers degrade: the malware
  hunt says "no YARA corpus available" rather than failing, matching how `Tool.Available` already
  degrades gracefully.

---

## 5a. Never assume outbound network access

**Design assumption: there may be no internet, and that must be an ordinary outcome.** Three separate
scenarios produce it, and they are not exotic:

1. **Evaluation harnesses may deliberately air-gap.** LLM benchmark contamination is a real and
   commonly reported failure — an agent that can reach the internet can fetch the answers to a
   well-known public case rather than derive them. Camel's own writeup raised this: when running the
   public DFIR cases the agent would sometimes recognise the evidence set and name the case. An
   evaluator who takes that seriously has an obvious lever: cut egress. We should behave correctly when
   they pull it.
2. **Covert red engagements** may forbid outbound traffic from the testing host by rule of engagement.
3. **Isolated forensic workstations** are routine — an evidence-handling VM with no route out is good
   practice, not a misconfiguration.

**This is a credibility argument, not just a robustness one.** A system that degrades cleanly with no
egress is *easier to evaluate honestly*, because the evaluator can remove the contamination channel
without breaking the tool. Designing for it makes Camel more trustworthy under assessment, not less
capable.

**The rule: a failed or forbidden acquisition is never fatal, and never silent.** It is a typed,
reportable gap:

- `EnsureAsync` returns `KbResult` failure with a *distinguishable reason* — `NotAcquired`,
  `NetworkUnavailable`, `PolicyForbidden`, `IntegrityFailed`, `InsufficientSpace` — never an exception.
- Consumers degrade to reduced capability, not error. The existing shape is already close:
  `ScanForMalwareAsync` fails only when *both* ClamAV and YARA fail, and returns partial results
  otherwise.
- **The gap reaches the report.** A missing corpus should raise `auditMissingEvidence` and land in the
  report's Gaps and limitations section — "the YARA community pack was unavailable, so file-signature
  scanning was not performed" is an honest finding. Silently producing zero YARA hits is not.

**One weakness to fix while doing this.** Today, if the rules pack is absent, `YaraToolkit.ScanAsync`
still runs `yara /opt/yara-rules/index.yar <target>`, and the failure surfaces as a generic "scan
command failed". The caller cannot distinguish *yara is not installed* from *the rules corpus is
missing* from *the scan errored*. `ScanAsync` should consult corpus status first and return a specific
`corpus not acquired` failure. That is the difference between a report that says "no malware detected"
and one that says "we could not look".

---

## 5b. Should the corpus API be agent-facing?

**Yes — with the acquisition call closed-world.** Reversing the earlier lean, for the reason above: if
the agent cannot see corpus state, it cannot adapt to a missing one, and pre-provisioning by an operator
is precisely what fails in the fresh-VM and air-gapped scenarios. The agent already handles this shape
of degradation everywhere else — `Tool.Available`, `ToolResult.IsSuccess` — and corpus status is the
same idea.

Split by capability rather than by audience:

| Call | Agent-facing | Why |
|---|---|---|
| `corpus.Status(name)` / `corpus.Describe()` | **yes** | free, no side effects; lets the agent plan around what is present |
| `corpus.Query` / `QueryFile` / `Grep` | **yes** | local reads; the point of having the corpus |
| `corpus.Ensure(name)` | **yes, constrained** | see the four constraints below |

**The real downside is not cost or disk — it is egress surface.** An acquisition call that took a
**URL** would be a general-purpose outbound fetch primitive, and that directly undermines the
contamination argument above: an agent that can fetch an arbitrary URL can fetch the case answers. So:

1. **Closed-world.** `Ensure(name)` accepts only the *names of corpora declared in configuration* —
   never a URL, never a path outside the declared set. The egress allowlist is fixed at config time and
   auditable. This is the same closed-world gating already used for Metasploit module invocation.
2. **Budgeted.** Each corpus declares a maximum size and timeout. An acquisition that would exceed
   either fails typed rather than filling the evidence VM's disk or stalling an analysis. The long-call
   protections already exist — the Jint promise timeout and the client-idle heartbeat — and apply here.
3. **Policy-gated.** `AllowNetworkFetch` still governs. Under a covert engagement the agent receives a
   clean `PolicyForbidden` answer it can reason about, not a failure it might retry.
4. **Recorded.** A mid-case acquisition writes its manifest and a `corpus-acquire` event into the case
   trail, and the report states the corpus version *and* that it was acquired during the investigation.

That last point resolves the one genuine tension with §3.3. Fetching mid-case makes the corpus version
a function of when the agent ran — which is bad for reproducibility. But the fix is *recording*, not
*forbidding*: the manifest and the audit event make the version an explicit, citable property of the
case. Pinning survives; opacity does not.

---

## 6. Candidate corpora

**Blue:** ATT&CK enterprise (distilled — [DfirReporting.md](DfirReporting.md) §3.4); Yara-Rules pack
*(migrate the existing install)*; LOLBAS *(migrate)*; SigmaHQ rules; ATT&CK-to-800-53 mappings
(Apache 2.0).

**Red:** nuclei templates (MIT); SecLists / wordlists (MIT, large — a strong distillation candidate);
GTFOBins; PayloadsAllTheThings — ⚠️ **settle licensing first**, the same caution already standing over
the payload-library design.

**Already covered elsewhere, do not migrate:** ExploitDB is a CLI KB via `searchsploit`; hayabusa's
Sigma rules ship with hayabusa itself and are provisioned by SIFT.

`License` and `Attribution` are required fields precisely because half this list has real obligations.

---

## 7. Migration

1. Declare `yara-rules` and `lolbas` as corpora **at their existing paths** — `/opt/yara-rules`,
   `/opt/zimmermantools/lolbas.json` — so nothing that references them breaks.
2. Move acquisition out of `YaraToolkit.InstallMissingTools` / `WindowsAnalysisToolkit.InstallMissingTools`
   into explicit `EnsureAsync` calls on the paths that actually need them.
3. Backfill manifests for already-installed copies, marked `fetchedAt: unknown` — honest about what we
   cannot reconstruct rather than inventing a date.
4. Leave `InstallAptPackage` / `InstallZipRelease` alone. **Those install *tools*; this layer manages
   *data*.** Keeping the two separate is what stops this becoming a general package manager.

---

## 8. Build plan

**Increment 1 — model and manifest.** `Corpus`, `CorpusStatus`, manifest read/write, `StatusAsync`,
`DescribeCorpora`, config binding. No acquisition yet; it can already describe the two corpora on disk.

**Increment 2 — acquisition.** `EnsureAsync` for `SingleFile` and `GithubZip` (the two kinds we already
use), digest verification, `corpus-acquire` audit, `AllowNetworkFetch` honouring the covert flag.

**Increment 3 — query and graceful degradation.** `QueryAsync`, `QueryFileAsync`, `GrepAsync`,
`corpus-query` audit. Migrate `LoadLolbasAsync` as the first consumer and validate against the existing
masquerade detection. Fix `YaraToolkit.ScanAsync` to report *corpus not acquired* distinctly (§5a), and
wire "corpus unavailable" through to `auditMissingEvidence` so it reaches the report's Gaps section.

**Increment 4 — bind and surface.** Bind in the shared `CamelMCPTools` base so blue and red both get it;
`camel corpus` CLI verb; corpus status in the startup report; manifest into the report soundness
statement.

**Increment 5 — ATT&CK.** Declare it as a corpus with `DistillCommand`; unblocks
[DfirReporting.md](DfirReporting.md) Increment 3.

**Increment 6 — migrate YARA and side-loading.** Move the YARA pack over; add `import`/`verify`.

---

## 9. Open decisions

- ~~**Does the agent get a corpus API, or only workflows?**~~ **Resolved (§5b): yes, all three,
  with `Ensure` closed-world (declared names only, never a URL), budgeted, policy-gated, and recorded.**
  The agent needs to see corpus state to adapt to a missing one, and the egress-surface risk is removed
  by the closed world rather than by hiding the call.
- **Where do corpora live?** The existing installs are scattered (`/opt/yara-rules`,
  `/opt/zimmermantools/lolbas.json`). A single `/opt/camel/corpora/<name>/` is cleaner but breaks
  existing paths. *Leaning: new corpora go under the new root; the two existing ones stay put, declared
  where they are.*
- **Per-case pinning?** Should a case record the corpus versions it used, so re-running it later can
  reproduce the result? Attractive for forensic reproducibility, and the manifest makes it cheap — but
  it implies keeping multiple versions side by side. *Defer, but do not design it out.*
- **Integrity when the source publishes no digest** (a GitHub branch zip changes every push). Record
  the digest we actually got, so drift is at least *detectable* even when it cannot be *prevented*.
- **Distillation on the platform or on the server?** Distilling on the workstation keeps the data next
  to where it is used, but needs the tooling there. *Leaning platform-side with a managed fallback.*

---

## 10. Key file references

| What | Where |
|---|---|
| Ad-hoc corpus installers to replace | `src/Camel.Toolkits/Toolkit.cs:166` (`InstallFile`), `:212` (`InstallGithubRepoZip`) |
| Constructor-time install hook (the stall) | `src/Camel.Toolkits/Toolkit.cs:86` |
| Existing consumers | `src/Camel.DFIR.Toolkits/Yara/YaraToolkit.cs`, `.../WindowsAnalysis/WindowsAnalysisToolkit.cs` (`LoadLolbasAsync`) |
| Client to mirror | `src/Camel.Intel/KnowledgeBaseClient.cs` |
| Source model to extend | `src/Camel.Intel/KnowledgeBase.cs` |
| Agent-facing facade | `src/Camel.Intel/CamelKnowledgeApi.cs` |
| Red-only binding to fix | `src/Camel.Server/CamelMCPTools.cs:309` (`BindsKnowledgeBases`) |
| Design this serves | `docs/DfirReporting.md` §3.4 |
