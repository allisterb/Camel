namespace Camel.Environments;

using System;
using System.Collections.Generic;
using System.Linq;
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
/// <param name="AllowExternalTargetDisclosure">Whether the engagement permits sending a client asset (a target IP/
/// host/domain) to a third-party intelligence service — e.g. a Shodan host lookup. Default false (fail-closed):
/// target-keyed knowledge-base queries are refused until the RoE explicitly opts in, because such a query discloses
/// the client's asset to an external party that caches and indexes it. Knowledge queries (CVE lookups, etc.) carry
/// no target and are unaffected.</param>
public record EngagementInfo(
    string EngagementId,
    string Client,
    string AuthorizedBy,
    string RulesOfEngagementRef,
    DateTime ValidFromUtc,
    DateTime ValidUntilUtc,
    ScopeTarget[] Scope,
    bool AllowExternalTargetDisclosure = false)
{
    /// <summary>True if <paramref name="nowUtc"/> falls inside the authorized window.</summary>
    public bool IsWithinWindow(DateTime nowUtc) => nowUtc >= ValidFromUtc && nowUtc <= ValidUntilUtc;

    /// <summary>The authorized-target entries (exclusions removed).</summary>
    [JsonIgnore]
    public IEnumerable<ScopeTarget> Included => (Scope ?? Array.Empty<ScopeTarget>()).Where(t => !t.Excluded);

    /// <summary>The explicit carve-outs that override any inclusion.</summary>
    [JsonIgnore]
    public IEnumerable<ScopeTarget> Excluded => (Scope ?? Array.Empty<ScopeTarget>()).Where(t => t.Excluded);
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

/// <summary>
/// Thrown when a target-keyed external query (e.g. a Shodan host lookup) would disclose a client asset to a
/// third-party service but the registered engagement does not permit external disclosure
/// (<see cref="EngagementInfo.AllowExternalTargetDisclosure"/> is false). Fail-closed: such a query sends the
/// client's host/IP/domain to an external party, so it is refused until the rules of engagement opt in.
/// </summary>
public class ExternalDisclosureForbiddenException()
    : Exception("This engagement does not permit disclosing target details to external services. A target-keyed " +
                "knowledge-base query (e.g. Shodan) would send a client asset to a third party; set " +
                "AllowExternalTargetDisclosure on the engagement to authorize it.");
