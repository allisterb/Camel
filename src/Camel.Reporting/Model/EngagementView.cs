namespace Camel.Reporting.Model;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// A report-side read-model of the engagement authorization block, deserialized from a case's
/// <c>reports/authorization/engagement.json</c> (written by the <c>SetEngagement</c> MCP tool as a default-serialized
/// <c>EngagementInfo</c>). Deliberately decoupled from <c>Camel.Environments.EngagementInfo</c> — the reporting
/// library is a leaf that depends only on <c>Camel.Runtime</c> + the PDF stack, so it defines its own read-model of
/// the data rather than referencing the environment/SSH stack. Enum-valued fields are kept as strings (the source
/// serializes them as strings via <c>JsonStringEnumConverter</c>); the reporting layer only displays them.
/// </summary>
public sealed record EngagementView(
    string? EngagementId,
    string? Client,
    string? AuthorizedBy,
    string? RulesOfEngagementRef,
    DateTimeOffset? ValidFromUtc,
    DateTimeOffset? ValidUntilUtc,
    ScopeTargetView[]? Scope,
    bool AllowExternalTargetDisclosure,
    EngagementDocumentView[]? Documents,
    string? Posture,
    string? InternalAuthorizationWaiver,
    EngagementContactView[]? Contacts,
    string[]? SourceAddresses,
    string? TestType,
    bool Announced,
    string[]? AuthorizedTools,
    TestingHoursView? TestingHours,
    string[]? AllowedActivities,
    int? MaxPacketRate,
    int? MaxConcurrentTargets)
{
    /// <summary>The always-permitted information-gathering baseline (mirrors <c>EngagementActivities.Baseline</c>
    /// and the viewer's <c>BASELINE_ACTS</c>) — the report shows these plus <see cref="AllowedActivities"/>.</summary>
    public static readonly string[] BaselineActivities = ["Recon", "Scan", "Enumerate", "VulnScan"];

    /// <summary>Activity classes never permitted unless listed explicitly — flagged distinctly in the report.</summary>
    public static readonly HashSet<string> DangerousActivities = new(StringComparer.OrdinalIgnoreCase)
        { "SocialEngineering", "DenialOfService" };

    /// <summary>The in-scope (non-excluded) targets.</summary>
    [JsonIgnore] public IEnumerable<ScopeTargetView> Included => (Scope ?? []).Where(t => !t.Excluded);

    /// <summary>The explicit out-of-scope carve-outs.</summary>
    [JsonIgnore] public IEnumerable<ScopeTargetView> Excluded => (Scope ?? []).Where(t => t.Excluded);

    /// <summary>Baseline plus this engagement's authorized intrusive classes, de-duplicated and in a stable order.</summary>
    [JsonIgnore]
    public IEnumerable<string> EffectiveActivities =>
        BaselineActivities.Concat(AllowedActivities ?? []).Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>True if any supplied document actually authorizes testing (RoE / authorization letter / contract).</summary>
    [JsonIgnore]
    public bool HasAuthorizingDocument =>
        (Documents ?? []).Any(d => d.Kind is "RulesOfEngagement" or "AuthorizationLetter" or "Contract");

    private static readonly JsonSerializerOptions Opts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
    };

    /// <summary>Parse an <c>engagement.json</c> payload, or null if it is absent/blank/unparseable (the report then
    /// falls back to a DFIR-style layout with no Authorization section — the same fail-open the viewer uses).</summary>
    public static EngagementView? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<EngagementView>(json, Opts); }
        catch { return null; }
    }
}

/// <summary>One authorized or excluded target in the engagement scope (mirrors <c>ScopeTarget</c>).</summary>
public sealed record ScopeTargetView(string? Kind, string? Value, bool Excluded = false);

/// <summary>One signed engagement document with its preserved-copy path and SHA-256 (mirrors <c>EngagementDocument</c>).</summary>
public sealed record EngagementDocumentView(
    string? Kind, string? FilePath, string? HashType, string? HashValue, string? StoredPath);

/// <summary>A named engagement point of contact (mirrors <c>EngagementContact</c>).</summary>
public sealed record EngagementContactView(string? Name, string? Role, string? Email, string? Phone);

/// <summary>The permitted daily testing-hours window (mirrors <c>TestingHours</c>).</summary>
public sealed record TestingHoursView(string? StartLocal, string? EndLocal, string[]? Days, string? TimeZone)
{
    /// <summary>Human-readable one-liner for the report (e.g. "09:00-17:00 America/New_York Mon/Fri").</summary>
    public override string ToString()
    {
        var t = string.IsNullOrWhiteSpace(StartLocal) && string.IsNullOrWhiteSpace(EndLocal)
            ? "any time" : $"{StartLocal}-{EndLocal}";
        var tz = string.IsNullOrWhiteSpace(TimeZone) ? "UTC" : TimeZone;
        var days = Days is { Length: > 0 } ? string.Join("/", Days) : "any day";
        return $"{t} {tz} {days}";
    }
}
