# Red-Team Engagement Gate (design draft)

*How a Camel "red" MCP server enforces authorization, scope, and a validity window in code —
the offensive-side counterpart to the [evidence-spoliation guard](AuditEnvironments.md) and the
[audit trail](AuditTrail.md).*

> **Status:** design draft. Nothing here is built yet. The intent is to make the red server's
> compliance posture an *architectural invariant* (fail-closed, enforced at the environment), not a
> documented convention an agent could ignore.

> **Local-only during the hackathon freeze.** This work lives on the `redserver` branch and is kept
> off GitHub until the Find Evil! hackathon is over. Two local guards (neither version-controlled, both
> easy to remove later) prevent an accidental push — see [Keeping this work local](#keeping-this-work-local).

---

## Why this exists

Camel's blue (DFIR) server already turns two compliance properties into code:

- **Zero spoliation** — `SetEvidence` arms a write-once, environment-level guard; any tool execution
  that would write over registered evidence is refused (`EvidenceSpoliationRiskException`).
- **Full attribution** — every command funnels through one chokepoint
  (`AuditEnvironment.ExecuteCommandAsync` → `AuditCommand`) and lands in a per-case CLEF audit log.

A red (pen-test) server raises a *different* primary risk: acting on a system you are not authorized
to touch. Anthropic's Usage Policy draws its line at **authorization, scope, and intent** — not at
"offense vs defense." So the red server needs the symmetric architectural stop: **no offensive tool
runs until an engagement (authorization + scope + validity window) is registered, and every action is
checked against that scope before it executes.**

The design deliberately mirrors the evidence guard so the two servers share one mental model:

| Blue (DFIR)                         | Red (pen-test)                                  |
| ----------------------------------- | ----------------------------------------------- |
| `EvidenceInfo[]`                    | `EngagementInfo` (authorization + scope)        |
| `SetEvidence` (write-once)          | `SetEngagement` (write-once)                     |
| `FailIfEvidenceSpoliationRisk(path)`| `FailIfOutOfScope(target)`                       |
| `EvidenceSpoliationRiskException`   | `OutOfScopeException` / `EngagementRequiredException` |
| guard is **opt-in** (no evidence → no protection needed) | gate is **fail-closed** (no engagement → offensive tools refuse to run) |
| audit tag `evidence-spoliation`     | audit tag `scope-violation`                      |

The one asymmetry is the most important: the evidence guard is permissive by default (it only blocks
when evidence is registered), whereas the engagement gate is **restrictive by default** — an offensive
toolkit with no registered engagement does nothing. Authorization is mandatory, not optional.

---

## 1. The model — `EngagementInfo.cs`

New file `src/Camel.Environments/EngagementInfo.cs`, structured exactly like `EvidenceInfo.cs`
(record + preflight/verification records + exception types).

```csharp
namespace Camel.Environments;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json.Serialization;

/// <summary>The kind of authorized in-scope target a <see cref="ScopeTarget"/> matches.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ScopeKind
{
    Host,       // a single IP or hostname, e.g. 10.0.5.21 or web01.lab.local
    Cidr,       // an IPv4/IPv6 range in CIDR notation, e.g. 10.0.5.0/24
    Domain,     // a DNS suffix, e.g. lab.local (matches host and any subdomain)
    Url         // a base URL the engagement authorizes (web-app tests)
}

/// <summary>
/// One authorized (or explicitly excluded) target in an engagement's rules of engagement. Exclusions
/// always win over inclusions, so a carve-out inside an authorized range can never be hit.
/// </summary>
/// <param name="Kind">How <paramref name="Value"/> is interpreted when matching a tool's target.</param>
/// <param name="Value">The host / CIDR / domain / URL this entry covers.</param>
/// <param name="Excluded">True for an out-of-scope carve-out (e.g. a production box inside an in-scope subnet).</param>
public record ScopeTarget(ScopeKind Kind, string Value, bool Excluded = false);

/// <summary>
/// Identifies the authorization under which a red-team engagement runs: who authorized it, the
/// rules-of-engagement reference, the validity window, and the in-/out-of-scope targets. Offensive
/// toolkits consult the environment's registered engagement — via <see cref="AuditEnvironment.FailIfOutOfScope"/>
/// — before acting on any target, the architectural enforcement of "authorized, scoped, in-window only."
/// Mirrors <see cref="EvidenceInfo"/> on the blue side.
/// </summary>
/// <param name="EngagementId">Short human-readable id for the engagement (audit-file name, like a case id).</param>
/// <param name="Client">The organization that owns the systems and granted permission.</param>
/// <param name="AuthorizedBy">The named authorizer on the client side (the signatory of the RoE).</param>
/// <param name="RulesOfEngagementRef">A pointer to the signed authorization (contract/ticket/RoE id) for the record.</param>
/// <param name="ValidFromUtc">Start of the authorized testing window (UTC).</param>
/// <param name="ValidUntilUtc">End of the authorized testing window (UTC); actions after this are refused.</param>
/// <param name="Scope">Authorized and excluded targets. Empty in-scope set ⇒ nothing is in scope (fail-closed).</param>
public record EngagementInfo(
    string EngagementId,
    string Client,
    string AuthorizedBy,
    string RulesOfEngagementRef,
    DateTime ValidFromUtc,
    DateTime ValidUntilUtc,
    ScopeTarget[] Scope)
{
    /// <summary>True if <paramref name="nowUtc"/> falls inside the authorized window.</summary>
    public bool IsWithinWindow(DateTime nowUtc) => nowUtc >= ValidFromUtc && nowUtc <= ValidUntilUtc;

    /// <summary>The authorized-target entries (exclusions removed).</summary>
    public IEnumerable<ScopeTarget> Included => Scope.Where(t => !t.Excluded);

    /// <summary>The explicit carve-outs that override any inclusion.</summary>
    public IEnumerable<ScopeTarget> Excluded => Scope.Where(t => t.Excluded);
}

/// <summary>Why a target was judged in or out of scope — surfaced in the audit trail and to the agent.</summary>
/// <param name="Target">The target a tool was about to act on.</param>
/// <param name="InScope">True only if an inclusion matched AND no exclusion matched AND the window is open.</param>
/// <param name="Reason">Human-readable explanation (matched rule, the exclusion that won, or "window closed").</param>
public record ScopeDecision(string Target, bool InScope, string Reason);

/// <summary>The preflight result for a proposed engagement before it is registered (parses scope, checks the window).</summary>
/// <param name="Valid">True when every scope entry parses and the validity window is non-empty and not already past.</param>
/// <param name="Problems">One message per rejected entry / window problem (empty when valid).</param>
public record EngagementSummary(bool Valid, string[] Problems);

/// <summary>
/// Thrown when an offensive operation targets a host/range/URL that the registered engagement does not
/// authorize (or authorizes only outside its validity window) — the architectural stop that keeps the
/// red server inside its rules of engagement. The red counterpart of <see cref="EvidenceSpoliationRiskException"/>.
/// </summary>
public class OutOfScopeException(ScopeDecision decision)
    : Exception($"The operation targeting '{decision.Target}' is outside the authorized engagement scope and was refused. {decision.Reason}")
{
    public ScopeDecision Decision { get; } = decision;
}

/// <summary>
/// Thrown when an offensive operation is attempted with no engagement registered. Fail-closed: the red
/// server does nothing offensive until <c>SetEngagement</c> has armed an authorization. (Blue has no
/// equivalent — DFIR reads need no engagement.)
/// </summary>
public class EngagementRequiredException()
    : Exception("No engagement is registered for this session. Call SetEngagement with the authorized scope and validity window before running any offensive tool.");
```

---

## 2. The environment gate — `AuditEnvironment` additions

A new `#region Engagement scope` mirroring the existing `#region Evidence integrity`. Same write-once
registration discipline; the matcher does CIDR/domain/host containment instead of path normalization.

```csharp
#region Engagement scope
/// <summary>The authorization under which offensive tools may act on this environment. Null until an
/// engagement is registered; while null the gate is fail-closed and <see cref="FailIfOutOfScope"/>
/// refuses everything. Mirrors <see cref="CaseEvidence"/> on the blue side.</summary>
protected EngagementInfo? Engagement { get; private set; }

private bool engagementRegistered;

/// <summary>True once an engagement has been registered for this environment/session.</summary>
public bool EngagementRegistered => engagementRegistered;

/// <summary>
/// Registers the engagement authorization for this environment — once. Returns true if accepted; false
/// if an engagement was already registered (write-once per session, exactly like evidence, so the scope
/// gate can't be silently widened mid-engagement). The caller (the <c>SetEngagement</c> tool) audits a
/// refused second attempt as a scope-violation event.
/// </summary>
public bool TrySetEngagement(EngagementInfo engagement)
{
    if (engagementRegistered || engagement is null) return false;
    Engagement = engagement;
    engagementRegistered = true;
    return true;
}

/// <summary>
/// Decides whether <paramref name="target"/> (an IP, hostname, CIDR, or URL a tool is about to act on)
/// is authorized: an inclusion must match, no exclusion may match, and the current time must be inside
/// the validity window. Returns a <see cref="ScopeDecision"/> carrying the reason either way.
/// </summary>
public ScopeDecision EvaluateScope(string target)
{
    if (Engagement is null)
        return new ScopeDecision(target, false, "No engagement registered (fail-closed).");
    if (!Engagement.IsWithinWindow(DateTime.UtcNow))
        return new ScopeDecision(target, false,
            $"Outside the authorized window ({Engagement.ValidFromUtc:u} – {Engagement.ValidUntilUtc:u}).");
    var excl = Engagement.Excluded.FirstOrDefault(t => Matches(t, target));
    if (excl is not null)
        return new ScopeDecision(target, false, $"Matched an explicit exclusion: {excl.Kind} {excl.Value}.");
    var incl = Engagement.Included.FirstOrDefault(t => Matches(t, target));
    return incl is not null
        ? new ScopeDecision(target, true, $"Authorized by {incl.Kind} {incl.Value} (RoE {Engagement.RulesOfEngagementRef}).")
        : new ScopeDecision(target, false, "No authorized scope entry matches this target.");
}

/// <summary>
/// Refuses an offensive operation that targets an unauthorized host/range/URL by throwing
/// <see cref="OutOfScopeException"/> (or <see cref="EngagementRequiredException"/> when nothing is
/// registered). Call this from any offensive toolkit/workflow path BEFORE it acts on a target — the
/// red-side counterpart of <see cref="FailIfEvidenceSpoliationRisk"/>.
/// </summary>
public void FailIfOutOfScope(string target)
{
    if (!engagementRegistered) throw new EngagementRequiredException();
    var decision = EvaluateScope(target);
    if (!decision.InScope) throw new OutOfScopeException(decision);
}

// host == exact (case-insensitive); cidr == IP containment; domain == suffix match incl. subdomains;
// url == host-of-url containment against the rule. Kept private so inclusion/exclusion use identical rules.
private static bool Matches(ScopeTarget rule, string target) => rule.Kind switch
{
    ScopeKind.Host   => string.Equals(rule.Value, target, StringComparison.OrdinalIgnoreCase),
    ScopeKind.Cidr   => IpInCidr(target, rule.Value),
    ScopeKind.Domain => HostOf(target).EndsWith(rule.Value, StringComparison.OrdinalIgnoreCase),
    ScopeKind.Url    => HostOf(target).Equals(HostOf(rule.Value), StringComparison.OrdinalIgnoreCase),
    _ => false
};
// IpInCidr / HostOf: standard IPAddress + prefix-length math; HostOf strips scheme/port/path from a URL or host.

/// <summary>Preflight a proposed engagement before registering it: every scope entry must parse and the
/// window must be non-empty and not already in the past. The <c>SetEngagement</c> tool refuses
/// registration when this is not <see cref="EngagementSummary.Valid"/>, so the gate is never armed with
/// an unparseable or already-expired authorization.</summary>
public EngagementSummary ValidateEngagement(EngagementInfo e)
{
    var problems = new List<string>();
    if (e.ValidUntilUtc <= e.ValidFromUtc) problems.Add("Validity window is empty or inverted.");
    if (e.ValidUntilUtc < DateTime.UtcNow)  problems.Add("Validity window is already in the past.");
    if (!e.Included.Any())                  problems.Add("No in-scope targets — nothing would be authorized.");
    foreach (var t in e.Scope)
        if (!ScopeEntryParses(t)) problems.Add($"Unparseable scope entry: {t.Kind} '{t.Value}'.");
    return new EngagementSummary(problems.Count == 0, problems.ToArray());
}
#endregion
```

### Where the gate is called

Two layers, mirroring how the evidence guard is both a per-toolkit call *and* a property of the
environment:

1. **Per-toolkit, at the target** — every offensive toolkit method calls `FailIfOutOfScope(target)`
   before it runs the tool, exactly as `DiskAnalysisToolkit` etc. call `FailIfEvidenceSpoliationRisk`
   on write targets today. This is where the *target* is known (the nmap host, the URL, the credential
   target), so it's the natural place to check.

2. **Fail-closed at the chokepoint** — offensive toolkits inherit from an `OffensiveToolkit` base whose
   `ExecuteTool` refuses to run at all when `!Environment.EngagementRegistered`. Even a buggy or
   hallucinated toolkit method that forgot step 1 cannot execute an offensive command without an
   engagement. (Read-only blue toolkits keep the existing base; the fail-closed default applies only to
   the offensive base, so DFIR is unaffected.)

Every refusal in either layer is audited as a `scope-violation` event — the red analogue of the
`evidence-spoliation` tag — so an attempt to act out of scope is part of the permanent record, not a
silent no-op.

---

## 3. The MCP tool — `SetEngagement`

In a red-server tool class (`CamelRedMCPTools`), parallel to `SetEvidence`: preflight → write-once →
audit. Registering the engagement also sets the audit case id so the whole engagement logs to
`audit-<engagementId>.clef`.

```csharp
[McpServerTool(Name = "SetEngagement"), Description(
    "Register the AUTHORIZATION for this pen-test session so the server can architecturally confine it to " +
    "the authorized scope and time window: every offensive tool refuses to run until this is set, and any " +
    "action targeting a host/range/URL outside 'scope' (or outside the validity window) is refused and " +
    "recorded as a scope-violation. Provide engagementId, client, authorizedBy, rulesOfEngagementRef, the " +
    "UTC validity window, and the in-/out-of-scope targets. Call this ONCE at the very start. Authorization " +
    "is write-once per session: a second call is refused and audited — start a new session to change scope.")]
public CallToolResult SetEngagement(EngagementInfo engagement, RequestContext<CallToolRequestParams> context)
{
    var session = registry.GetOrCreate(SessionId(context.Server));
    using (PushAuditProperty("CaseId", engagement?.EngagementId ?? session.CaseId))
    {
        // Write-once: a second attempt is a scope-widening attempt — audited and refused (cf. SetEvidence).
        if (session.Environment.EngagementRegistered)
        {
            AuditEvent("scope-violation",
                "Refused attempt to re-register the engagement for session {SessionId}: authorization is write-once.",
                session.SessionId);
            return Error("An engagement is already registered for this session and cannot be changed " +
                         "(write-once, to protect the scope gate). Start a new session to change scope.");
        }

        // Preflight: scope must parse and the window must be valid and not already expired.
        var summary = session.Environment.ValidateEngagement(engagement);
        if (!summary.Valid)
        {
            AuditEvent("engagement",
                "Refused to register engagement for session {SessionId}: {Problems}",
                session.SessionId, string.Join("; ", summary.Problems));
            return Error("Engagement NOT registered:" + Environment.NewLine +
                         string.Join(Environment.NewLine, summary.Problems));
        }

        session.Environment.TrySetEngagement(engagement);
        session.CaseId = engagement.EngagementId;   // engagement id drives the per-case audit file
        AuditEvent("engagement",
            "Registered engagement {EngagementId} (client {Client}, authorized by {AuthorizedBy}, RoE {Roe}) " +
            "for session {SessionId}; window {From:u}–{Until:u}; {InCount} in-scope / {ExCount} excluded.",
            engagement.EngagementId, engagement.Client, engagement.AuthorizedBy, engagement.RulesOfEngagementRef,
            session.SessionId, engagement.ValidFromUtc, engagement.ValidUntilUtc,
            engagement.Included.Count(), engagement.Excluded.Count());
        return Ok($"Engagement '{engagement.EngagementId}' registered; offensive tools are now confined to " +
                  $"{engagement.Included.Count()} authorized target(s) until {engagement.ValidUntilUtc:u}.");
    }
}
```

(`Error`/`Ok` here stand in for the existing `CallToolResult { IsError = … }` construction used by
`SetEvidence`.)

A companion **`EngagementStatus`** read-only tool (parallel to `VerifyEvidence`) lets the agent — or a
reviewer — print the active scope, window, and time remaining at any point.

---

## 4. Red / blue server split

The user's framing is two servers sharing one core. Concretely:

- **Toolkit binding.** Offensive toolkits (recon, web-app, exploitation, credential testing, C2) are
  bound into the JS engine **only** in the red server, the way the blue server binds DFIR toolkits +
  `anomaly`. The lazy/conditional binding already in place ([session-creation install stall] fix) is
  the seam to do this on.
- **Fail-closed base.** Offensive toolkits derive from `OffensiveToolkit : Toolkit`, whose `ExecuteTool`
  short-circuits with `EngagementRequiredException` when no engagement is registered. Blue toolkits are
  untouched.
- **Separate CLI verb / config.** A `red` server launch path (and case-template recipe) that advertises
  `SetEngagement` the way the blue path advertises `SetEvidence`/`SetCaseId`. Same MCP transport, same
  audit/report baking — the engagement window and every scope-violation show up in the same per-case
  CLEF log and the [report viewer].
- **Docs in two places.** Per the [js-sdk-doc] discipline, the red SDK methods and the `SetEngagement`
  contract get documented in both the MCP resources and the CLI case-template `CLAUDE.md`.

---

## 5. What this buys, in compliance terms

The earlier policy answer reduces "is this allowed?" to three properties: **authorization, scope,
intent.** This design makes the first two *enforced invariants* rather than promises:

- **Authorization** — offensive tools are inert until `SetEngagement` records a named authorizer and an
  RoE reference (fail-closed).
- **Scope** — every target is checked against the authorized hosts/ranges/URLs with exclusions winning;
  out-of-scope and out-of-window actions are refused at the environment, not left to the agent's
  judgment.
- **Intent / accountability** — the same per-case audit trail that backs DFIR chain-of-custody records
  the engagement, the window, and every refusal, so the whole engagement is reconstructable from the
  logs alone.

It does **not** (and cannot) decide whether the authorization itself is genuine — that remains an
operator responsibility, the same way the analyst is responsible for supplying real evidence hashes.
What it guarantees is that *whatever* authorization the operator attests to is the box the agent is
confined to.

---

## Open questions

- **Target extraction for free-form tools.** Step 1 works cleanly when a toolkit method takes an
  explicit `target` parameter. Tools driven by a config file or a target *list* need the toolkit to
  enumerate targets and gate each — or to refuse list inputs that include any out-of-scope entry.
- **Rate / intensity limits.** Scope answers "where"; it does not answer "how hard." A separate
  throttle (max concurrent hosts, scan-rate caps) would address the "mass/indiscriminate" prohibition
  more directly than scope alone. Possibly an `EngagementInfo` field (`MaxConcurrentTargets`,
  `MaxPacketRate`) enforced alongside `MaxConcurrentExecutions`.
- **Destructive-action classes.** Whether to add an allowed-activity-class field (recon / exploit /
  post-exploit / DoS-never) so the engagement can authorize recon-only vs full exploitation, refused at
  the toolkit base by activity tag.

---

## Keeping this work local

While the red server is in draft and the hackathon submission is frozen, the `redserver` branch is
committed locally only and kept off GitHub. Two independent guards prevent an accidental push. **Both
are local to this clone and not version-controlled** — they protect *you*, and won't follow the branch
to anyone else.

They were chosen to cover *different* push paths, so together they catch the realistic accidents:

| Guard | What it is | Which push it stops |
| --- | --- | --- |
| **`pre-push` hook** | `.git/hooks/pre-push` — refuses every push with a message and a non-zero exit, before anything contacts the remote | Any explicit push, e.g. `git push origin redserver`, and IDE/editor "Push" buttons |
| **Dead push remote** | `git config branch.redserver.pushRemote no-push-frozen` — a remote that doesn't exist | A bare `git push` while on `redserver` (which would otherwise resolve to `origin`) — fails to resolve `no-push-frozen` before the hook even runs |

Commits are unaffected by both — only `push` is blocked.

### Lifting the guards (after the hackathon)

```sh
rm .git/hooks/pre-push                          # remove the hook
git config --unset branch.redserver.pushRemote  # restore normal push target (origin)
```

A deliberate one-off bypass is also possible without removing anything: `git push --no-verify origin
redserver` skips the hook (but you must name a real remote, since the bare-push remote is the dead one).
This is by design — the guards stop *accidental* pushes, they are not a hard lock.
