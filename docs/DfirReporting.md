# DFIR reporting — finding schema v2 and a real report generator (design plan)

*Status: design, not built. Companion to [PenTestReporting.md](PenTestReporting.md), which solved the
same problem on the red side and supplies the blueprint.*

---

## Thesis

**Answering the case questions is necessary but not sufficient.** Camel's incident reports answer what
was asked, cite an execution id for every claim, and are honest about gaps. What they do not do is
*argue*. A reader finishes `report.md` knowing the answers without having acquired the investigator's
understanding of the incident — no spine, no phases, no sense of how the intrusion unfolded or why one
reading of the evidence beat the alternatives.

The Find Evil! result made the cost concrete. Mulder (1st) and TRUDI (2nd) both produced reports whose
narrative quality exceeded Camel's, and neither did so by finding more evidence. Camel's SRL-2018
findings are, per word, *denser* than Mulder's — F3 alone carries two SHA-256s, the `MSSE-<n>-server`
named-pipe token, the service-stub API sequence, and four execution ids. The deficit is structural.

**The structural diagnosis, precisely.** The red side records findings as structured events and
*builds* the document from them: `PenTestReportGenerator` is 350 lines that assemble a severity report
card, a ranked findings section, and a compliance attestation out of `vulnerability` events via
`ReportAggregates`. The blue side records four loose strings and asks the agent to hand-write prose:
`DfirReportGenerator` is 69 lines that render the agent's `report.md` under a cover page. Blue has the
weaker schema and the weaker generator, on the side of the product where narrative matters *more*.

**This design inverts that.** The finding becomes a structured record rich enough to render from; the
kill-chain phase becomes a first-class object so the narrative has a spine; the generator assembles the
report the way the red one already does. Reporting stops being the thing we do at the end with whatever
tokens remain.

> **Scoping note.** This is a schema-and-rendering change, not an investigation change. It does not
> require the multi-agent architecture the winners used — though §7 notes where an adversarial pass
> plugs in, because that pass is what *produces* the counter-analysis content §4.2 renders.

---

## 1. What we have today

| | DFIR (blue) | PenTest (red) |
|---|---|---|
| Per-finding record | `auditFinding(observation, interpretation, confidence, evidenceExecutionIds)` — 4 strings | `auditVulnerability(title, severity, cvss, affectedAsset, description, remediation, references, evidenceExecutionIds)` — 8 fields |
| Aggregation layer | none | `ReportAggregates` (`VulnerabilityView`, `SeverityCounts`, `Attestation`) |
| Generator | `DfirReportGenerator`, **69 lines** — cover + agent's `report.md` + accuracy appendix | `PenTestReportGenerator`, **350 lines** — builds sections from events |
| Narrative source | agent free-writes the whole `report.md` | generator assembles; agent supplies per-finding prose |
| Severity | **none** (confidence only) | normalized band + CVSS |
| ATT&CK | none | n/a (CVE / 800-53 references instead) |

The existing DFIR sections, per `CaseTemplate/CLAUDE.md`, are: Case evidence → Executive summary →
Answers to the case questions → Incident timeline → Findings → Gaps → `auditReviewRec` items. That
skeleton is sound. It is missing a phase narrative, severity, technique mapping, counter-analysis, and
remediation — and its findings are one dense paragraph each rather than a structured header plus
exposition.

Supporting events already exist and are **currently discarded at report time**: `auditFalsePositive`
(a lead checked and rejected), `auditMissingEvidence` (an absent or cleared log), `auditHallucination`
(a caught self-invention), `auditReviewRec` (a human-judgement call). These are exactly the raw
material for the counter-analysis and limitations sections that make a report read as rigorous. Today
they live only in the CLEF trail and the HTML viewer.

---

## 2. What to adopt from the winners (and what not to)

**Adopt — Mulder:**

- Structured finding header (severity, confidence, time range, sources, evidence refs, ATT&CK) as a
  table, **then** 150–600 words of exposition. The header is scannable; the prose is the argument.
- Named kill-chain phases with date ranges as the report's spine, each expanded per host.
- Server-side rejection of findings whose evidence refs do not match real tool invocations.
- Counter-analysis surfaced *inline* — dismissed detections, de-escalated hosts, corrected facts.

**Adopt — TRUDI:**

- Confidence as a *two-level model with a stated rule* (`confirmed` = two or more independent sources;
  `inference` = single source needing validation), not a free-text adjective.
- Structural gates enforced server-side rather than prompted, especially `negative_completeness`:
  **refuse an absence claim when the evidence it rests on was truncated.** Camel's tool wrappers have
  line caps and the roughly 25k output cap, so this failure mode is live for us.
- Findings tied to a hypothesis id, so the report can show what was considered and discarded.

**Do not adopt:**

- **Length as a proxy for quality.** Mulder's report is 25–30k words against our 2,257; a good deal of
  that is exposition our format deliberately compresses. Target is roughly 8–12k words for a case of
  SRL-2018's size — enough for per-finding argument, not padding.
- **Per-finding LLM narration as a separate pass.** The agent already holds the context when it records
  the finding; ask for the prose *there*.

---

## 3. Finding schema v2

### 3.1 Binding shape — object argument, raw `ClrFunction`

The current binding is `Action<string,string,string,string>`. Adding parameters would break every
existing script, and — per the `table()` incident (agent finding B-2) — **typed CLR delegates convert
arguments before the call, and those conversion failures are host errors a script cannot catch**, which
aborted an entire Execute past a `try`/`catch`. A positional twelve-argument delegate would be the same
trap, worse: arity errors currently name nothing.

So: keep the four-argument positional form working forever, and add an **object form** bound as a raw
`ClrFunction` that shapes and validates its own argument, exactly as `table()` now does.

```js
// v1 — still valid, unchanged semantics
auditFinding(observation, interpretation, confidence, evidenceExecutionIds);

// v2 — object form
auditFinding({
  id:             "F3",                        // stable, report-citable
  title:          "Cobalt-Strike-style SMB/named-pipe beacon on rd-01 and file server",
  severity:       "critical",                  // critical|high|medium|low|info
  confidence:     "confirmed",                 // confirmed|inference  (rule in 3.3)
  phase:          "P3",                        // links to a phase record (see 4.1)
  hosts:          ["base-rd-01", "base-file"],
  timeFrom:       "2018-08-31T22:16:12Z",
  timeTo:         "2018-08-31T22:52:08Z",
  sources:        ["yara.rules", "volatility.psscan", "evtx.powershell-operational"],
  attack:         ["T1059.001", "T1021.002"],  // validated against the local catalog
  observation:    "...",                       // what was seen — unchanged meaning
  interpretation: "...",                       // what it means — unchanged meaning
  narrative:      "...",                       // NEW: 150-600 words of argument
  remediation:    "...",                       // NEW: optional, defensive control
  supersedes:     "F12",                       // NEW: optional, corrects an earlier finding
  evidenceExecutionIds: "93f4b2fb,48d19cb2,421294a8"
});
```

Every field except `observation`, `interpretation`, `confidence`, and `evidenceExecutionIds` is
optional; a v2 call missing them degrades to exactly a v1 finding. **Unknown keys produce a diagnosable
line of output, never a thrown host error** — the `table()` lesson.

### 3.2 Why `narrative` belongs on the finding

The single biggest lever in this design. Today the agent writes roughly 80 telegraphic words per
finding inside a whole-report budget it is rationing. Asking for the argument *at the point of
recording* — while the evidence is in context — costs little and is where the insight actually is. The
generator then assembles; nobody has to hold the whole report in one head at the end.

### 3.3 Severity and confidence are orthogonal

We conflated them. They answer different questions and the report needs both:

- **Confidence** — *how sure are we this is true?* Two levels with a stated rule: `confirmed` (two or
  more independent artifact sources corroborate) and `inference` (single source, or reasoning across
  sources without direct corroboration). A recorded rule, not vibes.
- **Severity** — *how much does it matter to this incident?* `critical` (attacker capability or impact:
  implant, credential theft, exfiltration, DC compromise), `high` (a step in the chain: lateral
  movement, persistence, staging), `medium` (supporting context), `low` / `info` (scoping,
  chain of custody, negative results).

Severity is what makes an executive summary possible at all: "55 findings: 11 critical, 19 high" is
triage; "all findings HIGH confidence" is not. Reuse `ReportAggregates.SeverityBands` and `SevOrder`
verbatim so blue and red rank identically.

### 3.4 ATT&CK mapping with a local catalog

ATT&CK mapping is **standard practice on both sides of the product** — DFIR reports map findings to
techniques, pen-test reports map findings and attack-plan steps to them. It was long planned here and
never built. It is also the single most legible signal to a reader that a report is professional, which
is a large part of why both winners carry it.

**Licensing: settled, we can vendor.** MITRE grants "a non-exclusive, royalty-free license to use
ATT&CK® for research, development, and commercial purposes", conditioned on reproducing MITRE's
copyright designation and the license in any copy. The required notice is:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
> MITRE Corporation.

`ATT&CK®` is a registered trademark, so it is named as a mapping standard, never as branding. The
notice goes in the vendored catalog, the report's soundness statement, and the repo's third-party
notices. MITRE's own disclaimer — that ATT&CK does not enumerate all possible behaviours and coverage
of it does not imply defensive coverage — should be quoted in the report's limitations section, because
it is also *true of our coverage table* and pre-empts an over-reading of it.

**Distill, do not vendor raw.** Two acquisition routes, both ending in the same compact local catalog:
technique id, name, parent technique for sub-techniques, tactics (kill-chain phases), platforms,
canonical URL, deprecated/revoked flags, and the data-source components — roughly 650 enterprise
entries, landing in the low hundreds of KB.

- **Preferred: MITRE's public TAXII 2.1 server** (`https://attack-taxii.mitre.org`, no auth). Filtering
  `match[type]=attack-pattern` against a **pinned API root** (`/api/v21/attack-<x.y>`) returns just the
  techniques, so most of the distillation disappears and `Version` becomes an authoritative release
  identifier rather than a branch name. See [KnowledgeCorpora.md](KnowledgeCorpora.md) §3.1a.
- **Fallback: the `mitre-attack/attack-stix-data` bundles** (STIX 2.1, per-domain, versioned,
  `index.json` catalog). The current `enterprise-attack.json` is **53.8 MB** — fine as a one-time
  acquisition to distil, far too large to embed, and the right route when TAXII is unreachable.

**TAXII is an acquisition transport, not a validation service.** Its rate limit is 50 requests per
10 minutes per source IP, and MITRE's own guidance is to download bundles for heavier use. Validating
technique ids per finding over the network would exhaust that in one investigation *and* would break
the no-outbound-access requirement. Validation stays local, against the distilled catalog.

**Where it lives — not a `KnowledgeBase`.** The natural-looking home is wrong. `Camel.Intel`'s
`KnowledgeBase` models a *live external source*: HTTP/CLI/File transport, auth and `KeyRef`, rate
limits, response cache, and `DisclosesTarget` gating. ATT&CK is none of those — it is an **offline,
vendored, versioned reference table**. Worse, `BindsKnowledgeBases` is `false` on the base
`CamelMCPTools` and `true` only on `PenTestMCPTools`, so **knowledge bases are red-only today** and a
catalog placed there would be unreachable from the DFIR server.

Instead: ship the distilled catalog as an **embedded resource**, following the precedent already in
`Camel.Server.csproj`, which embeds the SDK docs that way. Validation then runs inside `AuditFinding`
in the **shared** `CamelMCPTools` base, so blue and red get it without touching `BindsKnowledgeBases`.
Whether to *also* expose a lookup to the agent (`attack.Technique("T1059.001")`) is a separate and
lower-priority decision — validation does not require it.

**Three jobs, in value order:**

1. **Validate at record time.** An unknown or revoked technique id is rejected with a diagnosable
   message. This is an anti-hallucination gate: inventing `T1234.567`, or citing a technique that was
   deprecated three versions ago, is exactly the sort of plausible-looking detail an LLM emits, and it
   is cheap to catch. Revoked-technique detection is a bonus the STIX data gives us free.
2. **Roll up.** Technique to tactic gives the report a coverage table, and per-finding links resolve to
   canonical URLs at render time rather than being pasted — and mistyped — by the agent.
3. **Drive a coverage audit.** ATT&CK's **data sources and data components** map each technique to the
   telemetry that evidences it. That is the missing half of Mulder's applicable-but-never-invoked check,
   and it is a better fit for Camel than for either winner: given a claimed technique, we can ask
   whether the artifact that would evidence it was actually parsed, and given the artifacts we *did*
   parse, which techniques we were positioned to detect and never looked for. This turns the coverage
   table from decoration into an actual gap-finder. Worth building as its own increment once (1) and
   (2) are in.

**Version it and disclose it.** TRUDI's stated limitation is that its local catalog constrains
technique validation scope. Record the ATT&CK version in the soundness statement so the constraint is
visible rather than hidden, and make the refresh a deliberate, reviewable step.

#### 3.4.1 What is already on the SIFT workstation (surveyed 2026-08-26)

There is **no ATT&CK catalog and no ATT&CK tooling** on SIFT — no `mitreattack-python`, no `attackcti`,
no STIX bundles, nothing under `/usr/share/mitre*` or `/opt/attack*`. (`/opt/stix-validator` exists, but
it validates STIX; it ships no data.) So the vendored catalog above is genuinely needed; there is
nothing to reuse.

**But Hayabusa already computes the mapping, and we are throwing it away.** SIFT ships hayabusa 3.9.0
with **4,947 Sigma rules carrying ATT&CK tags** — `332 distinct technique ids` plus tactic tags.
Hayabusa surfaces them through its output *profile*, and the profiles differ exactly here:

| Profile | MITRE fields |
|---|---|
| `minimal` | none |
| `standard` — **what `HayabusaJsonTimelineAsync` currently gets** | **none** |
| `verbose` | `MitreTactics`, `MitreTags`, `OtherTags` (+ `RuleFile`, `EvtxFile`) |

`HayabusaJsonTimelineAsync` passes no `-p`, so it takes the default `standard` profile, and
`HayabusaAlert` has no field to receive the tags anyway. Verified on a real run against a ROCBA
`Archive-Security` EVTX: **19,231 of 56,252 detections (34%) carry `MitreTags`**, as clean technique
ids —

```json
{ "RuleTitle": "Failed Logon From Public IP", "Level": "med",
  "MitreTactics": ["PrivEsc","InitAccess","Persis","Stealth"],
  "MitreTags": ["T1078","T1190","T1133"] }
```

**Why this matters more than the convenience.** A technique id that comes off the Sigma rule that fired
is **evidence-derived**; one the agent recalls is **asserted**. For every Hayabusa-derived finding we
can attribute the mapping to the detection rule and cite it, which is a stronger claim than the
validation gate can ever make — the gate only proves a technique *exists*, not that it *applies*. This
is close to free and independent of everything else in this document, so it goes first, as
**Increment 0**:

- add `MitreTactics` / `MitreTags` / `OtherTags` to `HayabusaAlert`;
- add a profile parameter to `HayabusaJsonTimelineAsync`, defaulting to `verbose`;
- partition `MitreTags` by prefix when consuming it — the profile documents it as carrying MITRE
  *techniques, software and groups*, so `S####` / `G####` ids can appear alongside `T####` and must not
  be fed to the technique validator (software/group ids are useful separately, as threat-actor context);
- map `MitreTactics` through a lookup — the values are Hayabusa's **abbreviations** (`PrivEsc`,
  `InitAccess`, `Persis`, `Stealth`), not canonical ATT&CK tactic names.

**The ruleset is not a substitute for the catalog.** 332 techniques against roughly 650 in enterprise
ATT&CK, with no technique names, no canonical URLs, no deprecation or revocation data, and only
whatever Sigma happens to have rules for. It maps *log-derived* findings only — nothing from memory,
disk, registry, or filesystem analysis. Increment 0 makes a third of Hayabusa's output self-mapping;
Increment 3 is still what covers the rest of the investigation.

**Red side, same catalog.** `auditVulnerability` should take `attack` on the same terms, and attack-plan
steps map to techniques naturally. Building the catalog in the shared base means red gets it for the
cost of one extra field. A follow-on worth scoping separately: the Center for Threat-Informed Defense
publishes ATT&CK-to-controls mappings under **Apache 2.0**, which would connect findings to the NIST
800-53 references the red report already cites — a real remediation bridge. Confirm the exact mapping
sets and file formats before committing to it.

### 3.5 Server-side gates (enforced, not prompted)

`AuditFinding` validates before it writes the event. Each rejection returns a diagnosable line and
records a `finding-rejected` event — a rejection is *positive evidence of rigour*, the same argument as
the red gate's `scope-violation` events.

| Gate | Rule | Steals from |
|---|---|---|
| `evidence_refs_resolve` | every id in `evidenceExecutionIds` matches a real `execution` event **in this case** | Mulder |
| `confirmed_requires_two_sources` | `confidence: "confirmed"` requires two or more distinct `sources` entries | TRUDI |
| `attack_ids_valid` | every `attack` id exists in the catalog | TRUDI |
| `negative_completeness` | a finding whose `interpretation` asserts absence is refused if any cited execution hit a line cap or the output cap | TRUDI |
| `phase_exists` | `phase` matches a declared phase id | — |
| `supersedes_exists` | `supersedes` matches a recorded finding id | — |

`evidence_refs_resolve` is the one to build first: **Camel already has the exec-id plumbing, and the
finding-to-execution link is currently a viewer convention rather than an enforced invariant.** Making
it an invariant is a small change with an outsized credibility return.

`negative_completeness` needs truncation to be *recorded* — the execution event must carry a
`truncated` flag when a wrapper hits its line cap or the output cap. That flag does not exist yet; it
is a prerequisite, and useful independently.

---

## 4. The narrative layer

### 4.1 Phases as first-class records

The spine. A new `auditPhase` call, recorded as a `phase` event:

```js
auditPhase({
  id: "P3", ordinal: 3,
  name: "Active Operations",
  timeFrom: "2018-08-27T00:00:00Z", timeTo: "2018-09-01T00:00:00Z",
  hosts: ["base-rd-01", "base-rd-02", "base-file"],
  summary: "..."   // the phase's own paragraph — how this stage unfolded
});
```

Findings reference a phase; the generator groups them under it. This is the whole difference between a
findings *list* and an attack *narrative*, and it costs one event type.

Recommended default phases, from the kill chain, with the agent free to rename, merge, or add:
initial access, persistence, privilege escalation, lateral movement, collection and staging, command
and control, exfiltration, anti-forensics. Phases are **not** required to be disjoint in time; real
intrusions overlap, and forcing a partition would misrepresent them.

### 4.2 Hypotheses and counter-analysis

TRUDI's genuine differentiator is that competing hypotheses *direct* collection rather than decorating
the write-up. A light version that fits code-mode:

```js
auditHypothesis({
  id: "H1", statement: "...",
  status: "supported" | "rejected" | "open",
  discriminator: "the tool call that would separate this from H2",
  rationale: "..."
});
```

Rejected hypotheses become report content. Combined with the already-recorded but currently discarded
`auditFalsePositive` / `auditMissingEvidence` / `auditHallucination` events, this fills a
**Counter-analysis and corrections** section for free — the section that reads as rigour precisely
because it shows what was considered and discarded.

### 4.3 The generator, section by section

`DfirReportGenerator` grows from a 69-line wrapper into the blue analogue of the 350-line red one:

1. **Cover and confidentiality** — keep as-is.
2. **Forensic soundness statement** — methodology, read-only handling, `VerifyEvidence` results per
   file, tool provenance and versions, ATT&CK catalog version. Machine-built from `evidence` and
   `execution` events; today F1-style chain-of-custody is a *finding*, which undersells it.
3. **Executive summary** — machine-built: scope (hosts, evidence sources, execution count, wall-clock
   from the CLEF span), severity counts, incident date range, the phase list with date ranges, and
   critical findings by title. Deterministic, so it cannot drift from the findings.
4. **Answers to the case questions** — kept, and kept early. Necessary but not sufficient; each answer
   now cross-links the finding ids that support it.
5. **Attack narrative** — phases in ordinal order; each renders its `summary`, then its findings
   grouped by host. **This is the new section and the point of the exercise.**
6. **Findings** — per-finding structured header table, then `narrative`, then observation,
   interpretation, evidence ids, and SDK methods. Ranked severity, then confidence, then time.
7. **ATT&CK coverage** — technique by tactic rollup with finding counts.
8. **Counter-analysis and corrections** — rejected hypotheses, false positives, superseded findings,
   caught hallucinations.
9. **Gaps and limitations** — from `auditMissingEvidence` plus the agent's Gaps prose; every
   `negative_completeness` rejection surfaces here too.
10. **Remediation** — per-finding `remediation`, grouped by control theme.
11. **Human-judgement items** — `auditReviewRec`, as today.
12. **Appendix: accuracy self-assessment** — keep as-is.

Sections 2, 3, 7, and 8 are **fully machine-built**. Sections 5, 6, and 10 interleave agent prose from
structured slots. The agent never again free-writes a whole document.

### 4.4 Aggregation

Add `DfirReportAggregates` beside `ReportAggregates`, same pattern: `FindingView.From(AuditEvent)`,
`PhaseView`, `HypothesisView`, `AttackRollup`, `SoundnessView`, plus ranking helpers reusing `SevOrder`.

`ReportAggregates`' own comment already flags the risk this must not repeat: the HTML viewer computes
the same aggregates in `report.js`, and the C# and JS can drift. **Take the follow-up it proposes now
rather than later** — the bake emits aggregates as a sidecar `.js` the viewer renders, making C# the
sole source. Cheaper to do while adding a second aggregate set than after.

---

## 5. The brief is half the fix

`CaseTemplate/CLAUDE.md` currently says: record findings as observation, interpretation, confidence,
and *"If any questions are asked in the case description then use your findings to answer them."* That
instruction produces exactly what we got — a correct checklist. The brief must ask for the argument:

- Declare phases as the investigation takes shape; assign every finding to one.
- Write the `narrative` on each finding, at record time, while the evidence is in context.
- Record hypotheses you rejected and why — a rejected lead is reportable work, not waste.
- State severity separately from confidence, using the stated rules.
- The report's job is to give a reader genuine insight into the incident. The case questions are a
  floor, not the deliverable.

Budget guidance belongs here too: per-finding narrative is *cheap* relative to investigation, and the
report is the only artifact most readers will ever see.

---

## 6. Backward compatibility and migration

- **v1 `auditFinding` keeps working**, indefinitely. Cases baked from old CLEF still render — findings
  without severity sort as `info`, without a phase group under "Unphased".
- **The existing eight cases re-bake without re-running.** They gain the machine-built soundness
  statement and executive summary (both derived from events already present) and lose nothing.
- **`bake-report` stays deterministic and non-agent-facing** — the generator is not exposed to the JS
  engine, matching the red side.
- **`report.md` remains the human-readable artifact**; the change is that the generator writes most of
  it rather than the agent.

---

## 7. Where an adversarial pass plugs in

Out of scope to build here, noted so the schema does not foreclose it. A second agent reading the
`finding`, `hypothesis`, and `execution` events — **not raw tool output** — could challenge conclusions,
propose counter-evidence, and flag applicable-but-never-invoked tools (Mulder's coverage audit). It
writes `auditHypothesis(status: "rejected")` and `supersedes` findings; §4.3 item 8 renders the result.
This composes with code-mode rather than replacing it: the adversary reasons over distilled findings,
which is precisely the context-cheap surface code-mode already produces.

---

## 8. Build plan

**Increment 0 — stop discarding Hayabusa's ATT&CK tags** (§3.4.1). `verbose` profile,
`MitreTactics`/`MitreTags`/`OtherTags` on `HayabusaAlert`, prefix partitioning, tactic-abbreviation
lookup. Independent of everything below and worth doing on its own merits.

**Increment 1 — schema and gates.** Object-form `auditFinding` as a raw `ClrFunction`; `severity`,
`title`, `id`, `hosts`, `sources`, `timeFrom` / `timeTo`, `narrative`, `remediation`, `supersedes`.
`evidence_refs_resolve` and `confirmed_requires_two_sources` gates, `finding-rejected` event.
Truncation flag on execution events. Unit tests per gate.

**Increment 2 — narrative records.** `auditPhase`, `auditHypothesis`; `phase_exists` and
`supersedes_exists` gates.

**Increment 3 — ATT&CK catalog.** Build-time distillation of the STIX bundle to a compact embedded
resource; `attack_ids_valid` gate (unknown *and* revoked ids) in the shared `CamelMCPTools` base so blue
and red share it; tactic rollup; version recorded in the soundness statement; MITRE notice in the
catalog, the report, and third-party notices. Add `attack` to `auditVulnerability` in the same pass.
**Increment 3b (separate)** — the data-component coverage audit from §3.4 item 3.

**Increment 4 — the generator.** `DfirReportAggregates`; `DfirReportGenerator` rebuilt to the §4.3
section list; aggregate sidecar so `report.js` stops recomputing.

**Increment 5 — the brief.** `CaseTemplate/CLAUDE.md` rewritten per §5. **Rebuild the CLI** — SDK docs
are embedded in `Camel.Server.dll`.

**Increment 6 — validate.** Re-bake all eight cases. Re-run SRL-2018 end-to-end and compare the new
report against Mulder's on narrative coherence, not length. Do `negative_completeness` last, since it
depends on the truncation flag being reliable across every wrapper.

---

## 9. Open decisions

- **`id` — agent-assigned or server-assigned?** Agent-assigned (`F3`) is citable mid-investigation and
  matches how the existing reports read; it needs a uniqueness gate. Server-assigned is collision-proof
  but the agent cannot reference a finding until after the call returns. *Leaning agent-assigned plus a
  uniqueness gate.*
- **Confidence: two levels or three?** TRUDI's two-level model is cleaner and harder to fudge, but our
  existing cases use HIGH / MEDIUM / LOW and would need mapping. *Leaning two levels, with HIGH to
  `confirmed` and MEDIUM / LOW to `inference` on legacy re-bake.*
- **Should `narrative` have a length floor?** A gate rejecting a two-sentence narrative on a `critical`
  finding would force the argument — or would produce padding. *Leaning guidance, not a gate.*
- **Phase overlap** — allowed (§4.1); revisit if the rendering gets confusing.
- **ATT&CK catalog source and licensing** — **settled** (§3.4): royalty-free for commercial use with
  the MITRE notice reproduced; distil the 53.8 MB STIX bundle to an embedded resource. Remaining sub-
  decisions: which domains to ship (enterprise only, or add ICS/mobile), whether to expose an
  agent-facing `attack.*` lookup at all, and the refresh cadence.
- **ATT&CK-to-800-53 control mappings** (Center for Threat-Informed Defense, Apache 2.0) — confirm the
  published mapping sets and formats before scoping the remediation bridge.

---

## 10. Key file references

| What | Where |
|---|---|
| Finding / vulnerability bindings and `AuditFinding` | `src/Camel.Server/CamelMCPTools.cs` (~L140, ~L338) |
| Raw `ClrFunction` precedent (`table`) | `src/Camel.Server/CamelMCPTools.cs` (~L168) |
| Red aggregates to mirror | `src/Camel.Reporting/Model/ReportAggregates.cs` |
| Red generator — the blueprint | `src/Camel.Reporting/Reports/PenTestReportGenerator.cs` (350 lines) |
| Blue generator — the 69-line wrapper to replace | `src/Camel.Reporting/Reports/DfirReportGenerator.cs` |
| Bake entry point | `src/Camel.Reporting/ReportBaker.cs` |
| Viewer (drift risk) | `src/Camel.CLI/CaseTemplate/report.js` |
| Analyst brief to rewrite | `src/Camel.CLI/CaseTemplate/CLAUDE.md` (Deliverables, ~L280) |
| Reference report to beat | `cases/SRL-2018/reports/report.md` (2,257 words) |
