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

/// <summary>The kind of signed engagement document, mirroring the distinct documents a real pen-test engagement
/// produces (see docs/PenTestBookGapAnalysis.md). The kind matters because not every document <em>authorizes</em>
/// testing: an NDA governs confidentiality, not permission. <see cref="Authorizes"/> identifies the kinds that
/// actually grant authorization (used by the scope tiering to decide whether a target has a backing authorization).</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EngagementDocumentKind
{
    RulesOfEngagement,    // RoE: scope, testing windows, off-limits targets, contacts
    AuthorizationLetter,  // authorization-to-test / "get out of jail free" letter
    Contract,             // the pen-test agreement / statement of work
    Nda,                  // non-disclosure agreement: confidentiality, NOT authorization to test
    TestPlan,             // the penetration test plan (Appendix A)
    Other                 // any other signed artifact (e.g. a sensitive-disclosure agreement)
}

/// <summary>
/// One signed document backing an engagement (RoE, authorization letter, contract, NDA, …). Recorded as a
/// <em>case-side</em> artifact, the red-side counterpart of registered <see cref="EvidenceInfo"/> on the blue
/// side: the <c>SetEngagement</c> tool confirms the file exists, hashes it (SHA-256), records the hash in the
/// audit trail, and copies it into the case's <c>reports/authorization/</c> so the signed proof travels with the
/// report. The operator still attests the enforceable <see cref="EngagementInfo.Scope"/>; documents are the
/// immutable proof the attestation rests on and are never parsed to <em>derive</em> scope. Optional: a self-owned
/// lab / loopback engagement may carry none.
/// </summary>
/// <param name="Kind">What this document is (an NDA does not authorize testing — see <see cref="EngagementDocumentKind"/>).</param>
/// <param name="FilePath">Path to the supplied document — relative to the case directory or absolute. The
/// provenance (where the operator pointed); the preserved copy is recorded in <paramref name="StoredPath"/>.</param>
/// <param name="HashType">Algorithm of <paramref name="HashValue"/>; <see cref="HashType.None"/> until
/// <c>SetEngagement</c> hashes the document (it computes SHA-256).</param>
/// <param name="HashValue">The document's hash, filled in by <c>SetEngagement</c>; empty until then.</param>
/// <param name="StoredPath">The case-relative path of the preserved copy (e.g. <c>reports/authorization/roe-acme.pdf</c>),
/// filled in by <c>SetEngagement</c>; what the report cites. Empty until the document is stored.</param>
public record EngagementDocument(
    EngagementDocumentKind Kind,
    string FilePath,
    HashType HashType = HashType.None,
    string HashValue = "",
    string StoredPath = "")
{
    /// <summary>True if this kind of document actually authorizes testing (RoE / authorization letter / contract),
    /// as opposed to an NDA / test plan / other supporting artifact. The scope tiering treats only these as a
    /// backing authorization for an in-scope target.</summary>
    [JsonIgnore]
    public bool Authorizes => Kind is EngagementDocumentKind.RulesOfEngagement
        or EngagementDocumentKind.AuthorizationLetter or EngagementDocumentKind.Contract;
}

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
/// <param name="Documents">The signed documents backing this engagement (RoE, authorization letter, contract,
/// NDA, …), if supplied. <c>SetEngagement</c> hashes each and preserves a copy under the case's reports/. Optional
/// (a self-owned lab may carry none); the enforceable scope is always the operator's attestation, never derived
/// from these documents.</param>
public record EngagementInfo(
    string EngagementId,
    string Client,
    string AuthorizedBy,
    string RulesOfEngagementRef,
    DateTime ValidFromUtc,
    DateTime ValidUntilUtc,
    ScopeTarget[] Scope,
    bool AllowExternalTargetDisclosure = false,
    EngagementDocument[]? Documents = null)
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
