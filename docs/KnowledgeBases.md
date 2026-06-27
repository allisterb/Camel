# External Knowledge Bases & Intelligence Sources (design draft)

*How Camel queries remote, API-based intelligence sources (Shodan, NVD/CVE, Vulners, Exploit-DB, CISA KEV, …)
from generated JS — with managed secrets, scope/disclosure controls, and provenance auditing strong enough to put
an external claim in a deliverable.*

> **Status:** design draft. Nothing here is built yet. Sequenced after the first offensive toolkits
> ([PenTestEnvironments.md](PenTestEnvironments.md), [RedTeamEngagementGate.md](RedTeamEngagementGate.md)); the
> client core is investigation-neutral so the DFIR side can use threat-intel KBs later.

> **Local-only during the hackathon freeze.** Like the rest of the red work, this lives on the `redserver` branch
> and is kept off GitHub until the Find Evil! hackathon is over (see the guards in
> [RedTeamEngagementGate.md](RedTeamEngagementGate.md#keeping-this-work-local)).

---

## Why this exists

A huge part of intelligence gathering — and of vulnerability analysis and exploitation planning — is **lookups
against web/cloud knowledge bases**: "what does Shodan know about this host", "what CVEs affect OpenSSH 8.2p1",
"is this CVE in CISA's known-exploited catalog", "what Metasploit modules target SMB". This is a potentially large
volume of queries, and the answers are critical to the engagement — but they come from *outside* the platform box,
so they bypass the toolkit/`AuditEnvironment` command path entirely and raise three problems the CLI toolkits never
had to solve:

1. **Secrets.** These APIs need keys. Keys must never land in the repo, the audit log, the JS sandbox, or a report.
2. **Provenance.** A pentest finding that says "host X is vulnerable to CVE-Y" must trace to "per NVD at time T,
   version Z matches CVE-Y" — external intelligence is fallible and stale, so the *source, time, and exact response*
   have to be on the record, the way a DFIR finding traces to an `[audit] execution=<id>`.
3. **Disclosure.** Asking Shodan about a client IP *sends that client asset to a third party* that caches and
   indexes it. That is an outbound disclosure the rules of engagement may forbid.

The design turns those three into architecture: secrets-as-references with a redaction guarantee, a provenance
envelope on every result, and a disclosure control wired into the engagement gate.

---

## The central distinction: two classes of query

These look alike but have opposite gate semantics, and the whole design hinges on separating them:

| | **Knowledge query** | **Target-keyed query** |
| --- | --- | --- |
| Example | "CVEs for `openssh 8.2p1`"; "MSF modules for SMB" | "Shodan, what's on `203.0.113.5`?" |
| Carries an engagement target? | **No** — a software/version/CVE id | **Yes** — a client host/domain |
| Scope-gated? | No (nothing to gate) | **Yes** — target must be in scope |
| Discloses client data to a 3rd party? | No | **Yes** — audited, and gated by RoE policy |
| Examples | NVD, Vulners, Exploit-DB, CISA KEV, MSF module search | Shodan, Censys, (VirusTotal/AbuseIPDB on the blue side) |

A KB declares which it is (`DisclosesTarget`), and the client forks on it: knowledge queries run freely (audited);
target-keyed queries pass `FailIfOutOfScope(target)` **and** an engagement disclosure check before a packet leaves.

---

## Design

Six parts. The core (1–3) is investigation-neutral; the gate fork (4) is red-specific.

### 1. Models

```csharp
namespace Camel.Intel;

/// <summary>How a knowledge base authenticates a request.</summary>
public enum KbAuth { None, Header, QueryParam }

/// <summary>
/// A configured external intelligence source. NOTE: <see cref="KeyRef"/> is the NAME of a secret to resolve at
/// call time (an env-var / secrets-file key), never the key itself — secrets never live in config or source.
/// </summary>
/// <param name="Name">Logical id used by the facade and in the audit trail (e.g. "nvd", "shodan").</param>
/// <param name="BaseUrl">API base URL the facade builds request paths under.</param>
/// <param name="Auth">How the key is presented (none / a header / a query param).</param>
/// <param name="AuthName">Header name (e.g. "apiKey") or query-param name (e.g. "key") when Auth != None.</param>
/// <param name="KeyRef">Name of the secret to resolve (e.g. "SHODAN_API_KEY"). Empty when the KB needs no key.</param>
/// <param name="RateLimitPerMinute">Client-side throttle; 0 = unlimited.</param>
/// <param name="CacheTtlMinutes">Response cache lifetime; 0 = no cache.</param>
/// <param name="DisclosesTarget">True for target-keyed KBs (Shodan/Censys): queries send a client asset to a third
/// party, so they are scope-gated AND require the engagement to permit external disclosure.</param>
public record KnowledgeBase(
    string Name, string BaseUrl,
    KbAuth Auth = KbAuth.None, string AuthName = "", string KeyRef = "",
    int RateLimitPerMinute = 0, int CacheTtlMinutes = 0, bool DisclosesTarget = false);

/// <summary>
/// The provenance envelope wrapping EVERY knowledge-base result. The payload alone is not enough for a deliverable —
/// a finding cites the source, the exact query, when it was retrieved, and a digest of the raw response, plus the
/// execution id that ties it into the per-case audit trail. The red-side analogue of an evidence hash.
/// </summary>
/// <param name="Source">The KB name the answer came from.</param>
/// <param name="Query">The exact query issued, with any secret redacted.</param>
/// <param name="RetrievedUtc">When the underlying response was fetched (the ORIGINAL fetch time on a cache hit).</param>
/// <param name="Result">The typed payload (T), or null on failure / empty result.</param>
/// <param name="ResponseDigest">SHA-256 of the raw response body — the authoritative reference to the retained copy.</param>
/// <param name="QueryId">Short id of this call's <c>kb-query</c> audit event (cite this in findings). The event is
/// also auto-attributed to the ambient case/execution, so it shows up under the Execute call that issued it.</param>
/// <param name="FromCache">True when served from the response cache rather than a fresh fetch.</param>
public record KbResult<T>(
    string Source, string Query, DateTime RetrievedUtc, T? Result,
    string ResponseDigest, string QueryId, bool FromCache = false)
{
    public bool Ok => Result is not null;
}
```

### 2. Secrets — references resolved server-side, never exposed

A small `ISecretsProvider` resolves a `KeyRef` to a secret at call time, checked in priority order so secrets stay
out of source control:

```csharp
public interface ISecretsProvider
{
    /// <summary>Resolve a secret by reference name, or null if unset. Resolution order: environment variable →
    /// a gitignored secrets file (path from config, default e.g. ~/.camel/secrets.json) → config (discouraged,
    /// dev-only). Never returns the value to the JS layer.</summary>
    string? Resolve(string keyRef);
}
```

Three guarantees the client enforces around it:

- **Never into JS.** The agent calls `Nvd.CvesForProductAsync(...)`; the *server* injects the key into the request.
  The key is never bound into the Jint engine, so a generated script can't read or exfiltrate it.
- **Never into the trail or a report.** Every resolved secret string is registered in a redaction set; all audit
  text (and the `KbResult.Query`) has it replaced with `<redacted>` before it is written. For `QueryParam` auth the
  key is stripped from the logged URL.
- **Degrade, don't crash.** A KB whose `KeyRef` won't resolve is **unavailable** (mirroring `Tool.Available`): its
  methods return a null `KbResult` and audit a `kb-unavailable` event with a directive message ("set
  SHODAN_API_KEY"), exactly like a missing platform tool.

### 3. The client core — generic plumbing + uniform provenance

One `KnowledgeBaseClient` does everything that is the same across KBs, so adding a KB is "config entry + a thin
typed facade", not new plumbing (the same lever as the toolkit `Name`/`Command` split):

- **Request build + auth injection** from the `KnowledgeBase` config (header or query-param key).
- **Rate limiting** (per-KB token bucket from `RateLimitPerMinute`) — matters for the high query volume.
- **Response caching** keyed by `(source, normalized-query)` with `CacheTtlMinutes`. A cache hit still produces a
  `KbResult`, but with the **original** `RetrievedUtc`/digest and `FromCache = true`, so the same CVE lookup across
  many hosts costs one call and the report rests on one retained artifact — without faking the provenance time.
- **Provenance + audit on every call** (see part 5): emit a `kb-query` audit event, compute the response digest,
  retain the raw body, and wrap the typed payload in `KbResult<T>`.

```csharp
// Core entry point the facades call. handler maps the raw response to T.
protected async Task<KbResult<T>> QueryAsync<T>(
    string source, string path, IReadOnlyDictionary<string,string> queryParams,
    Func<JsonElement, T?> map, string? disclosedTarget = null);
```

### 4. Typed facades + the engagement-gate fork

Each KB gets a thin facade mapping its endpoints to typed models; these are what `BindDomainGlobals` exposes to the
agent. A generic escape hatch (`KnowledgeBase.QueryAsync("name", params) → KbResult<JsonElement>`) covers any
configured KB without a facade yet.

| KB | Facade method (sketch) | Returns | Class |
| --- | --- | --- | --- |
| NVD / CVE | `Nvd.CvesForProductAsync(product, version)` / `Nvd.CveAsync(id)` | `CveRecord[]` | knowledge |
| Vulners | `Vulners.SoftwareVulnsAsync(name, version)` | `VulnRecord[]` | knowledge |
| Exploit-DB | `ExploitDb.SearchAsync(term)` | `ExploitEntry[]` | knowledge |
| CISA KEV | `Kev.IsKnownExploitedAsync(cveId)` | `KevEntry?` | knowledge |
| Metasploit | `Msf.ModulesForAsync(serviceOrCve)` | `MsfModule[]` | knowledge |
| Shodan | `Shodan.HostAsync(ip)` | `ShodanHost` | **target-keyed** |
| Censys | `Censys.HostAsync(ip)` | `CensysHost` | **target-keyed** |

A **target-keyed** facade does two extra things before the core call, using the session's `AuditEnvironment` (the
same object that holds the engagement, see [RedTeamEngagementGate.md](RedTeamEngagementGate.md)):

```csharp
public Task<KbResult<ShodanHost>> HostAsync(string ip)
{
    env.FailIfOutOfScope(ip);                 // the looked-up host must be authorized
    env.FailIfExternalDisclosureForbidden();  // ...and the RoE must permit sending it to a third party
    return client.QueryAsync("shodan", $"shodan/host/{ip}", …, MapHost, disclosedTarget: ip);
}
```

This needs one new field on the engagement and one guard:

- `EngagementInfo` gains **`AllowExternalTargetDisclosure`** (default **false**). Fail-closed: target-keyed KBs are
  inert until the RoE explicitly permits sending client assets to external services. Knowledge KBs ignore it.
- `AuditEnvironment.FailIfExternalDisclosureForbidden()` throws an `ExternalDisclosureForbiddenException` when no
  engagement is registered or the flag is false — mirroring `FailIfOutOfScope`.

Knowledge facades skip both gates (no target, no disclosure) — they just run and audit.

### 5. Provenance & audit — the centerpiece

Every KB call lands in the per-case CLEF audit log as a **`kb-query`** event, the remote-intelligence analogue of
the `command` event the `AuditEnvironment` emits for a tool execution:

```
kb-query  source=nvd  query="…?cpeName=cpe:2.3:a:openbsd:openssh:8.2p1…"  status=200
          digest=sha256:…  fromCache=false  durationMs=412  execution=<id>
```

- **Raw retention.** The full response body is written content-addressed to the case (`exports/kb/<source>-<sha256>.json`)
  so a reviewer can verify the claim byte-for-byte; the audit event and `KbResult.ResponseDigest` point to it. The
  CLEF carries the digest, not the (potentially large) body.
- **Disclosure ledger.** A target-keyed query additionally emits a **`kb-disclosure`** event recording exactly which
  client asset was sent to which third party and when — so the report can state precisely what data left the
  perimeter (and an attempt blocked by the flag is recorded too, like a `scope-violation`).
- **Report integration.** Because these ride the existing per-case audit trail, KB queries show up in the
  [report viewer](AuditTrail.md) and a finding's `evidenceExecutionIds` can cite a `kb-query` exactly as it cites a
  tool execution.

### 6. Binding & placement

- **Neutral core, per-server facades.** The `KnowledgeBaseClient` + `ISecretsProvider` + models live in a neutral
  assembly (a new `Camel.Intel`, the offense/defense-agnostic analogue of the base `Camel.Toolkits`), because the
  blue side will want threat-intel KBs (VirusTotal/AbuseIPDB hash/IP reputation) too. The **red server binds the
  offensive facades** (Nvd/Shodan/ExploitDb/…) in `PenTestMCPTools.BindDomainGlobals`; blue binds threat-intel
  facades later. Facades are constructed lazily and added to a `CamelKnowledgeApi` on the `SessionContext`,
  parallel to `CamelPenTestToolkitsApi`.
- **Capability surfacing.** The configured-and-resolvable KBs feed the launch capability report the same way
  toolkits do, so a red server prints which intelligence sources are live (and which are dark for want of a key).

---

## Configuration

KB config is a **top-level, investigation-neutral** section — these are remote services, not tools on the
Kali/SIFT box, so they do NOT sit under a `{platform}` profile. Keys are references; the literals live in env vars
or a gitignored secrets file.

```jsonc
{
  "KnowledgeBases": {
    "nvd": {
      "BaseUrl": "https://services.nvd.nist.gov/rest/json/",
      "Auth": "Header", "AuthName": "apiKey", "KeyRef": "NVD_API_KEY",   // optional: raises the rate limit
      "RateLimitPerMinute": 50, "CacheTtlMinutes": 1440, "DisclosesTarget": false
    },
    "cisa-kev": {
      "BaseUrl": "https://www.cisa.gov/sites/default/files/feeds/",
      "Auth": "None", "CacheTtlMinutes": 1440, "DisclosesTarget": false
    },
    "shodan": {
      "BaseUrl": "https://api.shodan.io/",
      "Auth": "QueryParam", "AuthName": "key", "KeyRef": "SHODAN_API_KEY",
      "RateLimitPerMinute": 60, "CacheTtlMinutes": 60, "DisclosesTarget": true   // target-keyed
    }
  },
  // Optional: where the secrets file lives (env vars are checked first regardless). Gitignored.
  "Secrets": { "File": "~/.camel/secrets.json" }
}
```

---

## JS API shape

```js
// Knowledge query: enrich a discovered banner with CVEs, keep only KEV-listed ones, find MSF modules — all
// inside the sandbox, returning a provenance-stamped shortlist instead of raw API JSON.
const scan = Session["scan_5_21"];                 // a HostScan from ScanningToolkit
const ssh = scan.OpenPorts.find(p => p.Service === "ssh");
if (ssh) {
  const cves = await Nvd.CvesForProductAsync("openssh", ssh.Version);   // KbResult<CveRecord[]>
  for (const c of cves.Result) {
    const kev = await Kev.IsKnownExploitedAsync(c.Id);
    if (kev.Result) {
      const mods = await Msf.ModulesForAsync(c.Id);
      auditFinding(
        `${scan.Address} openssh ${ssh.Version} -> ${c.Id} (CVSS ${c.Cvss}), KEV-listed, ${mods.Result.length} MSF module(s)`,
        "Known-exploited CVE on an exposed service - prioritise",
        "MEDIUM",                                  // a version-banner match is a LEAD, not confirmed exploitability
        `${cves.QueryId}, ${kev.QueryId}, ${mods.QueryId}`);   // cite the kb-query ids
    }
  }
}

// Target-keyed query: throws if 203.0.113.5 is out of scope OR the RoE forbids external disclosure.
const sh = await Shodan.HostAsync("203.0.113.5");
```

---

## Discipline (addition to `Camel.pentest.discipline.md`)

- **External intelligence is a lead, not proof.** A CVE matched by a version banner is a *hypothesis* — banners
  lie, vendors backport fixes without bumping the version. Cite the source and `RetrievedUtc`, cap confidence
  accordingly (`SPECULATIVE`/`LOW`/`MEDIUM`), and confirm exploitability by other means before a HIGH call.
- **Provenance always.** Every claim resting on a KB cites its `kb-query` execution id; the retained raw response
  is the authority. "NVD says" without the query, time, and digest is not citable.
- **Disclosure is a deliberate act.** A target-keyed lookup sends a client asset to a third party. Do it only when
  the RoE permits it, prefer knowledge queries (which disclose nothing) when they answer the question, and expect
  every disclosure to be on the record.

---

## Local CLI vs remote HTTP

Some "knowledge" lives in **local tools**, not HTTP APIs: `searchsploit` (offline Exploit-DB) and `msfconsole
search` run on the platform through the `AuditEnvironment`. Those stay in the `VulnScan`/`Exploitation` toolkits;
the KB subsystem is for genuine **remote** intelligence. The *capability* ("find exploits for X") may be served by
either, and the workflow layer can prefer whichever is available/configured — but the two paths keep their natural
homes (CLI → toolkit + `command` audit; HTTP → KB facade + `kb-query` audit).

---

## What this buys, in compliance terms

- **Secrets hygiene** — keys are references resolved server-side, redacted from the trail, and never reachable by
  generated code; nothing sensitive enters the repo or a deliverable.
- **Defensible findings** — every external claim carries source, query, time, and a digest of the retained raw
  response, traceable from the report straight into the per-case audit log.
- **Disclosure control** — sending a client asset to a third party is fail-closed (RoE opt-in), scope-checked, and
  recorded, so the engagement can prove exactly what client data left the perimeter and under what authorization.

---

## Open questions

- **Secrets backend.** Env-var + gitignored file is the baseline; is an OS credential store / vault integration
  worth it, or left to the operator to populate the env?
- **Cache scope & persistence.** Per-session (in-memory) vs per-engagement on disk (survives restarts, dedups across
  sessions). On-disk caching strengthens provenance (one retained artifact) but needs an invalidation story.
- **Quota exhaustion.** When a rate limit / monthly quota is hit, degrade to cache-only and audit a
  `kb-quota-exhausted` event, or surface a hard error? Probably degrade + audit, like a missing tool.
- **Result normalisation.** Whether to map disparate CVE sources (NVD/Vulners/OSV) into one `CveRecord` shape or
  keep them KB-specific. Lean KB-specific first; a normalised view is a later workflow concern.

---

## Lowest-risk first slice

Build the neutral core end-to-end against the **cleanest** KB first: **NVD** — keyless (a key only raises the rate
limit), a pure knowledge source (no scope/disclosure gate to exercise yet), and immediately useful (version →
CVEs). That proves the `KnowledgeBaseClient` + `ISecretsProvider` + `KbResult<T>` provenance envelope + `kb-query`
audit + caching/rate-limit, with `Nvd.CvesForProductAsync` and tests over a captured NVD response. **Shodan**
follows as the first *target-keyed* KB, adding `EngagementInfo.AllowExternalTargetDisclosure`,
`FailIfExternalDisclosureForbidden`, and the `kb-disclosure` event — the slice that exercises the gate fork.
