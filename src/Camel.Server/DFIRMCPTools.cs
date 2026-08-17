namespace Camel;

using System;
using System.ComponentModel;
using System.Threading.Tasks;

using ModelContextProtocol;
using ModelContextProtocol.Server;
using ModelContextProtocol.Protocol;
using Jint;

using Camel.Environments;

/// <summary>
/// The DFIR (blue-team) MCP tool surface. Extends the shared code-mode engine
/// (<see cref="CamelMCPTools"/>) with the evidence-integrity tools (SetEvidence/VerifyEvidence) and binds
/// the DFIR domain globals — the SIFT toolkits, the analysis workflows, and the anomaly engine — into the
/// JavaScript engine the Execute tool runs.
/// </summary>
public class DFIRMCPTools : CamelMCPTools
{
    public DFIRMCPTools(SessionRegistry registry) : base(registry) { }

    public override string InvestigationName => "DFIR";

    // The DFIR toolkit config-section names, for the launch-time platform capability check.
    protected override IReadOnlyList<string> PlatformToolkitSections =>
        ["DiskAnalysis", "MemoryAnalysis", "WindowsAnalysis", "Timeline", "Yara", "UnixTools", "LinuxAnalysis", "PacketAnalysis"];

    [McpServerTool(Name = "SetEvidence"), Description(
        "Register the ORIGINAL evidence files for this session so the server can architecturally prevent their " +
        "spoliation: any subsequent tool execution that would write over, extract into, or otherwise modify a " +
        "registered evidence path (or its containing directory) is refused. Pass one entry per evidence artifact " +
        "(disk image, memory capture, mounted volume, hive, log, …) with its 'filePath'; include 'hashType' " +
        "(None/MD5/SHA1/SHA256) and 'hashValue' when the case provides a known hash, otherwise omit them. " +
        "Call this ONCE at the very start of an investigation, before any Execute call that touches the evidence. " +
        "Evidence is write-once per session: a second SetEvidence call is refused, recorded as an " +
        "evidence-spoliation event in the audit trail, and returns an error — start a new session to change it.")]
    public CallToolResult SetEvidence(EvidenceInfo[] evidence, RequestContext<CallToolRequestParams> context)
    {
        var session = registry.GetOrCreate(SessionId(context.Server));
        evidence ??= [];
        using (PushAuditProperty("CaseId", session.CaseId))
        {
            // Write-once per session: a second attempt is treated as a spoliation event (someone trying to
            // repoint the guard mid-case) — audited and refused rather than silently honoured.
            if (session.Environment.EvidenceRegistered)
            {
                AuditEvent("evidence-spoliation",
                    "Refused attempt to re-register evidence for session {SessionId}: evidence is write-once per session.",
                    session.SessionId);
                return new CallToolResult
                {
                    IsError = true,
                    Content = [new TextContentBlock { Text =
                        "Evidence has already been registered for this session and cannot be changed (write-once, " +
                        "to protect the spoliation guard). Start a new session to register different evidence." }],
                };
            }

            // Preflight: confirm every evidence file is actually present on the workstation before arming the
            // guard. If any is missing, refuse — do NOT register — so the guard is never set against a path that
            // doesn't exist (a sign the wrong path was given or the evidence isn't staged yet).
            var summary = session.Environment.GetEvidenceSummary(evidence);
            if (!summary.AllPresent)
            {
                var missing = summary.MissingFiles.ToArray();
                AuditEvent("evidence",
                    "Refused to register evidence for session {SessionId}: {Count} file(s) not found on the workstation: {Paths}",
                    session.SessionId, missing.Length, string.Join(", ", missing));
                return new CallToolResult
                {
                    IsError = true,
                    Content = [new TextContentBlock { Text =
                        $"Evidence NOT registered — {missing.Length} file(s) were not found on the SIFT workstation:" +
                        $"{Environment.NewLine}{string.Join(Environment.NewLine, missing)}{Environment.NewLine}" +
                        "Make sure every evidence file is present on the workstation at the path given, then call " +
                        "SetEvidence again." }],
                };
            }

            session.Environment.TrySetCaseEvidence(evidence);
            // Record the registered evidence so the trail shows exactly what was protected, with sizes, and from when.
            AuditEvent("evidence", "Registered {Count} evidence item(s) for session {SessionId}: {Paths}",
                evidence.Length, session.SessionId,
                string.Join(", ", summary.Files.Select(f => $"{f.FilePath} ({f.SizeBytes} bytes)")));
            return new CallToolResult
            {
                Content = [new TextContentBlock { Text =
                    $"Registered {evidence.Length} evidence item(s) for this session; writes to these paths are now refused." +
                    $"{Environment.NewLine}{string.Join(Environment.NewLine, summary.Files.Select(f => $"{f.FilePath}: present, {f.SizeBytes} bytes"))}" }],
            };
        }
    }

    [McpServerTool(Name = "VerifyEvidence"), Description(
        "Verify the integrity of the evidence registered with SetEvidence: each file is re-hashed on disk and, " +
        "when a hash was supplied, compared against it (a mismatch is a chain-of-custody alarm and returns an " +
        "error); for a file with no supplied hash the current SHA-1 is recorded as a baseline (it always passes). " +
        ".E01/EWF images with a supplied hash are content-verified with ewfverify (the supplied acquisition hash is " +
        "the digest of the imaged media, not of the .E01 container), so you CAN supply an E01's acquisition MD5/SHA1. " +
        "Returns one line per file with the computed hash and OK/MISMATCH/baseline status. This can take a while for " +
        "large images (it reads the whole image). Call it only after SetEvidence; it does not modify the evidence.")]
    public async Task<CallToolResult> VerifyEvidence(RequestContext<CallToolRequestParams> context)
    {
        var session = registry.GetOrCreate(SessionId(context.Server));
        using var _case = PushAuditProperty("CaseId", session.CaseId);

        if (!session.Environment.EvidenceRegistered)
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text =
                    "No evidence has been registered for this session — call SetEvidence first, then VerifyEvidence." }],
            };

        // Hashing a large image can take minutes; mark the session busy so the idle sweeper can't dispose its
        // SSH connection out from under the hash.
        session.EnterCall();
        CaseEvidenceVerification verification;
        try { verification = await session.Environment.VerifyCaseEvidenceAsync(); }
        finally { session.LeaveCall(); }

        // One human-readable line per item: matched / SHA-1 baseline / mismatch.
        static string Line(EvidenceHashCheck c)
        {
            var hasHash = c.Evidence.HashType != HashType.None && !string.IsNullOrEmpty(c.Evidence.HashValue);
            if (!hasHash)
                return $"{c.Evidence.FilePath}: SHA1 baseline {(c.CurrentHash.Length > 0 ? c.CurrentHash : "(unreadable)")}";
            return c.Matched
                ? $"{c.Evidence.FilePath}: {c.Evidence.HashType} OK ({c.CurrentHash})"
                : $"{c.Evidence.FilePath}: {c.Evidence.HashType} MISMATCH expected={c.Evidence.HashValue} " +
                  $"actual={(c.CurrentHash.Length > 0 ? c.CurrentHash : "(unreadable)")}";
        }
        var lines = string.Join(Environment.NewLine, verification.Results.Select(Line));

        if (!verification.Success)
        {
            // A supplied hash did not match the file on disk: the evidence is not what was acquired. Flag it loudly.
            var bad = verification.Results.Where(r => !r.Matched).Select(r => r.Evidence.FilePath);
            AuditEvent("evidence-spoliation",
                "Evidence hash verification FAILED for session {SessionId}: {Paths} do not match the supplied hash.",
                session.SessionId, string.Join(", ", bad));
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text =
                    $"HASH VERIFICATION FAILED — the file(s) on disk do not match the supplied hash. Treat this as a " +
                    $"chain-of-custody problem and stop.{Environment.NewLine}{lines}" }],
            };
        }

        AuditEvent("evidence-verification",
            "Verified {Count} evidence item(s) for session {SessionId}: all supplied hashes match.",
            verification.Results.Length, session.SessionId);
        return new CallToolResult
        {
            Content = [new TextContentBlock { Text =
                $"Evidence verification passed.{Environment.NewLine}{lines}" }],
        };
    }

    /// <summary>
    /// Binds the DFIR investigation globals into the code-mode JS engine: the anomaly engine and the high-level
    /// analysis workflows (always), plus each SIFT toolkit lazily — only when the script names it, so a script
    /// never pays a toolkit's one-time tool provisioning unless it actually uses it.
    /// </summary>
    // The DFIR globals the Execute engine binds, declared once so the SDK doc area list (SdkDocs.DfirAreas) can be
    // asserted against them — an area with no documentation, or a global with no area, is a build failure.
    // Eager globals are cheap to construct: the anomaly toolkit is pure compute over a canonical timeline (no
    // AuditEnvironment; see Camel.Inference), and a workflow only holds the toolkits api and resolves toolkits
    // lazily on use. A SIFT toolkit is bound only when the script references it by name, because constructing one
    // can run one-time provisioning (Toolkit.InstallMissingTools = synchronous wget/apt for the EZ tools, the YARA
    // rules pack, hayabusa, …) — binding unused toolkits would stall the first call in a fresh session installing
    // tools the script never uses.
    private static readonly (string Name, bool Eager, Func<SessionContext, object> Resolve)[] domainGlobals =
    [
        ("AnomalyDetectionToolkit",      true,  _ => new Camel.Inference.AnomalyDetectionToolkit()),
        ("MemoryAnalysisWorkflow",       true,  s => s.WorkflowsApi.MemoryAnalysis),
        ("DiskAnalysisWorkflow",         true,  s => s.WorkflowsApi.DiskAnalysis),
        ("WindowsAnalysisWorkflow",      true,  s => s.WorkflowsApi.WindowsAnalysis),
        ("TimelineAnalysisWorkflow",     true,  s => s.WorkflowsApi.TimelineAnalysis),
        ("AntiForensicsAnalysisWorkflow", true, s => s.WorkflowsApi.AntiForensicsAnalysis),
        ("WebServerAnalysisWorkflow",    true,  s => s.WorkflowsApi.WebServer),
        ("LinuxAnalysisWorkflow",        true,  s => s.WorkflowsApi.LinuxAnalysis),
        ("PacketAnalysisWorkflow",       true,  s => s.WorkflowsApi.PacketAnalysis),
        ("MemoryAnalysisToolkit",        false, s => s.ToolkitsApi.MemoryAnalysis),
        ("DiskAnalysisToolkit",          false, s => s.ToolkitsApi.DiskAnalysis),
        ("WindowsAnalysisToolkit",       false, s => s.ToolkitsApi.WindowsAnalysis),
        ("TimelineAnalysisToolkit",      false, s => s.ToolkitsApi.Timeline),
        ("YaraToolkit",                  false, s => s.ToolkitsApi.Yara),
        ("UnixToolsToolkit",             false, s => s.ToolkitsApi.UnixTools),
        ("LinuxAnalysisToolkit",         false, s => s.ToolkitsApi.LinuxAnalysis),
        ("PacketAnalysisToolkit",        false, s => s.ToolkitsApi.PacketAnalysis),
    ];

    /// <summary>The DFIR globals bound into the Execute engine — the SDK doc areas must cover exactly these.</summary>
    public static IEnumerable<string> DomainGlobalNames => domainGlobals.Select(g => g.Name);

    protected override void BindDomainGlobals(Engine jsinterp, SessionContext session, string script)
    {
        foreach (var (name, eager, resolve) in domainGlobals)
            if (eager || script.Contains(name, StringComparison.Ordinal)) jsinterp.SetValue(name, resolve(session));
    }
}
