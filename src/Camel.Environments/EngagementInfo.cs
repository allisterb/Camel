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
/// The engagement's authorization posture — the operator's deliberate declaration of how strict the proof of
/// authorization must be, which the address-class tiers sit inside as an automatic floor (see
/// docs/PenTestBookGapAnalysis.md C.2). <see cref="Lab"/> = a self-owned lab (private/internal addresses are
/// self-attested); <see cref="Internal"/> = an internal engagement (private addresses need a document or a
/// recorded waiver); <see cref="Client"/> = a real client engagement (strict: private and public alike need an
/// authorizing document). Public addresses always require a document regardless of posture.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EngagementPosture
{
    Internal,   // default: private targets need a document OR a recorded waiver; public needs a document
    Lab,        // self-owned lab: loopback AND private targets are self-attested; public still needs a document
    Client      // strict: every non-loopback target needs an authorizing document
}

/// <summary>The ownership tier of a target's address, a proxy for "do we provably own this?" used to decide how
/// strong the proof of authorization must be. Ordered most-permissive to most-restrictive so the most-restrictive
/// tier across a set of resolved addresses can be taken with <c>Max</c>.</summary>
public enum AddressTier
{
    SelfOwned = 0,  // loopback / link-local: the tester's own machine
    Private   = 1,  // RFC1918 / IPv6 ULA / CGNAT: private, but ownership is NOT implied (could be a client's net)
    Public    = 2   // routable / unknown: never provably self-owned
}

/// <summary>How strongly an in-scope target's authorization must be proven, given the posture and the target's
/// <see cref="AddressTier"/> (see <see cref="EngagementAuthorization.RequiredProof"/>).</summary>
public enum ProofRequirement
{
    SelfAttested,       // no document needed (the operator owns it / declared it a lab)
    DocumentOrWaiver,   // an authorizing document, or an explicit recorded waiver, is required
    DocumentRequired    // an authorizing document is required (no waiver escape) - the public hard gate
}

/// <summary>The per-entry authorization decision for one in-scope <see cref="ScopeTarget"/>: its address tier, the
/// proof the posture requires, whether that proof is satisfied, and on what basis (or why not).</summary>
/// <param name="Target">The in-scope entry this decision is about.</param>
/// <param name="Tier">The entry's classified address tier.</param>
/// <param name="Required">The proof the posture+tier demands.</param>
/// <param name="Satisfied">True if the demanded proof is present.</param>
/// <param name="Basis">How it was satisfied: <c>self</c>, <c>document</c>, or <c>waiver</c> (empty when unsatisfied).</param>
/// <param name="Problem">Why it was refused (null when satisfied) - surfaced to the operator.</param>
public record ScopeAuthorizationDecision(
    ScopeTarget Target, AddressTier Tier, ProofRequirement Required, bool Satisfied, string Basis, string? Problem);

/// <summary>The outcome of checking every in-scope entry's proof of authorization against the engagement's posture
/// and documents (see <see cref="AuditEnvironment.EvaluateEngagementAuthorization"/>). The <c>SetEngagement</c>
/// tool refuses registration when this is not <see cref="Valid"/>, the public-IP hard gate; entries satisfied by a
/// <c>waiver</c> are audited as <c>authorization-waiver</c> events and flagged as residual risk in the report.</summary>
/// <param name="Valid">True when every in-scope entry's required proof is satisfied.</param>
/// <param name="Decisions">One decision per in-scope entry, in order.</param>
public record EngagementAuthorizationResult(bool Valid, ScopeAuthorizationDecision[] Decisions)
{
    /// <summary>Entries allowed only because an explicit waiver was supplied (residual-risk items for the report).</summary>
    public IEnumerable<ScopeAuthorizationDecision> Waived => Decisions.Where(d => d.Satisfied && d.Basis == "waiver");

    /// <summary>One message per unsatisfied entry (empty when valid).</summary>
    public IEnumerable<string> Problems => Decisions.Where(d => !d.Satisfied).Select(d => d.Problem!);
}

/// <summary>Pure tiering logic for the engagement authorization gate: classify an address into an
/// <see cref="AddressTier"/> and map (posture, tier) to the <see cref="ProofRequirement"/>. No I/O — the DNS
/// resolution needed to classify a hostname/domain lives in <see cref="AuditEnvironment.ClassifyTier"/>.</summary>
public static class EngagementAuthorization
{
    /// <summary>Classify a literal IP address by ownership tier: loopback/link-local are the tester's own machine
    /// (<see cref="AddressTier.SelfOwned"/>); RFC1918 / IPv6 unique-local / CGNAT (100.64/10) are
    /// <see cref="AddressTier.Private"/> (private, but ownership not implied); everything else is
    /// <see cref="AddressTier.Public"/>.</summary>
    public static AddressTier ClassifyIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal) return AddressTier.SelfOwned;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            if (b[0] == 169 && b[1] == 254) return AddressTier.SelfOwned;             // 169.254/16 link-local
            if (b[0] == 10) return AddressTier.Private;                                // 10/8
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return AddressTier.Private;   // 172.16/12
            if (b[0] == 192 && b[1] == 168) return AddressTier.Private;                // 192.168/16
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return AddressTier.Private;  // 100.64/10 CGNAT
            return AddressTier.Public;
        }
        if (ip.IsIPv6UniqueLocal) return AddressTier.Private;                          // fc00::/7 ULA
        return AddressTier.Public;
    }

    /// <summary>The proof the (posture, tier) combination demands. Public always requires a document; a self-owned
    /// address is self-attested; a private address needs a document under <see cref="EngagementPosture.Client"/>,
    /// a document-or-waiver under <see cref="EngagementPosture.Internal"/>, and is self-attested under
    /// <see cref="EngagementPosture.Lab"/>.</summary>
    public static ProofRequirement RequiredProof(EngagementPosture posture, AddressTier tier) => tier switch
    {
        AddressTier.SelfOwned => ProofRequirement.SelfAttested,
        AddressTier.Public    => ProofRequirement.DocumentRequired,
        _ /* Private */       => posture switch
        {
            EngagementPosture.Lab    => ProofRequirement.SelfAttested,
            EngagementPosture.Client => ProofRequirement.DocumentRequired,
            _ /* Internal */         => ProofRequirement.DocumentOrWaiver,
        },
    };
}

/// <summary>A named point of contact for an engagement (a row of the RoE's Personnel / call-tree table). Recorded
/// only; surfaced in <c>EngagementStatus</c> and the report's Contact Information section. Mark the incident/
/// emergency contact via <paramref name="Role"/> so the report's incident-handling reference has someone to name.</summary>
/// <param name="Name">The person's name.</param>
/// <param name="Role">Their role (e.g. "Pentest lead", "Client POC", "Incident/emergency contact").</param>
/// <param name="Email">Contact email (optional).</param>
/// <param name="Phone">Contact phone (optional).</param>
public record EngagementContact(string Name, string Role, string Email = "", string Phone = "");

/// <summary>The permitted testing hours window from the RoE (NIST SP 800-115 App. B "Test Schedule"). Recorded
/// only for now — surfaced in <c>EngagementStatus</c> and the report; the validity *window* (ValidFrom/Until) is
/// the enforced control. A later increment may enforce this recurring daily/weekday window at the scope gate.</summary>
/// <param name="StartLocal">Daily start time, "HH:mm" in <paramref name="TimeZone"/> (e.g. "09:00").</param>
/// <param name="EndLocal">Daily end time, "HH:mm" in <paramref name="TimeZone"/> (e.g. "17:00").</param>
/// <param name="Days">Weekdays testing is permitted (e.g. ["Mon","Tue","Wed","Thu","Fri"]); empty = any day.</param>
/// <param name="TimeZone">The time zone the times are expressed in (e.g. "America/New_York"); empty = unspecified.</param>
public record TestingHours(string StartLocal = "", string EndLocal = "", string[]? Days = null, string TimeZone = "");

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
/// <param name="Posture">The authorization posture (<see cref="EngagementPosture"/>) — how strict the proof of
/// authorization must be for the address tiers in scope. Defaults to <see cref="EngagementPosture.Internal"/>.</param>
/// <param name="InternalAuthorizationWaiver">An explicit operator attestation that authorization exists for
/// internal (private) targets with no signed document on file, with the reason. Non-empty = a waiver is granted
/// (recorded as an <c>authorization-waiver</c> event and flagged as residual risk in the report). Only satisfies
/// private targets under <see cref="EngagementPosture.Internal"/>; never satisfies a public target.</param>
/// <param name="Contacts">Engagement points of contact (RoE Personnel / call tree). Record-only.</param>
/// <param name="SourceAddresses">The addresses the test team operates *from* (RoE "Test Site"); lets the client
/// attribute and whitelist test traffic. Record-only.</param>
/// <param name="TestType">Free-text description of the test type (e.g. "External gray-box network test"). Record-only.</param>
/// <param name="Announced">Whether the engagement is announced (vs covert/unannounced). Record-only; default true.</param>
/// <param name="AuthorizedTools">Tools the RoE authorizes the team to use (RoE "Test Equipment"). Record-only.</param>
/// <param name="TestingHours">The permitted daily testing-hours window (RoE "Test Schedule"). Record-only for now;
/// the enforced time control is the ValidFrom/Until window.</param>
public record EngagementInfo(
    string EngagementId,
    string Client,
    string AuthorizedBy,
    string RulesOfEngagementRef,
    DateTime ValidFromUtc,
    DateTime ValidUntilUtc,
    ScopeTarget[] Scope,
    bool AllowExternalTargetDisclosure = false,
    EngagementDocument[]? Documents = null,
    EngagementPosture Posture = EngagementPosture.Internal,
    string InternalAuthorizationWaiver = "",
    EngagementContact[]? Contacts = null,
    string[]? SourceAddresses = null,
    string TestType = "",
    bool Announced = true,
    string[]? AuthorizedTools = null,
    TestingHours? TestingHours = null)
{
    /// <summary>True if at least one supplied document is of a kind that actually authorizes testing
    /// (RoE / authorization letter / contract) — an NDA-only engagement is false. The backing-authorization
    /// signal the scope tiering uses for public/strict targets.</summary>
    [JsonIgnore]
    public bool HasAuthorizingDocument => (Documents ?? []).Any(d => d.Authorizes);

    /// <summary>True if the operator supplied an internal-authorization waiver reason.</summary>
    [JsonIgnore]
    public bool HasInternalWaiver => !string.IsNullOrWhiteSpace(InternalAuthorizationWaiver);

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
