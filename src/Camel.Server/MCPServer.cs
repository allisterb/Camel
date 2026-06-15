namespace Camel;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

using ModelContextProtocol;
using ModelContextProtocol.Server;
using ModelContextProtocol.Protocol;
using Jint;

using Camel.Environments;

public enum TransportType
{
    Stdio = 0,
    Http = 1,
}

/// <summary>
/// Thrown by the JS global <c>exit(message)</c> to unwind the engine and stop the script immediately —
/// throwing is just the most reliable way to halt. The <c>Execute</c> handler treats it as a deliberate early
/// exit: it logs the message and returns it as ordinary output (the result is <em>not</em> flagged as a tool
/// error), distinct from a script fault or an invented-API hallucination.
/// </summary>
public sealed class ExitException(string message) : Exception(message);

public class CamelMCPTools : Runtime
{
   public CamelMCPTools(SessionRegistry registry)
   {
        this.registry = registry;
        jsoptions = new Options();
        jsoptions.Host.StringCompilationAllowed = false;        
        jsoptions.ExperimentalFeatures = ExperimentalFeature.TaskInterop;
        jsoptions.Constraints.PromiseTimeout = TimeSpan.FromHours(24);
    }

    [McpServerTool(Name = "SetCaseId"), Description(
        "Set the case identifier for this session's audit trail. Call this ONCE at the start of an investigation " +
        "with a short, human-readable case id (e.g. 'srl-2018-rd01'). Every subsequent Execute tool " +
        "execution in this session is recorded in a per-case audit log file named for this id (audit-<caseId>.clef), " +
        "so findings can be traced to the exact tool executions that produced them. One case per session; call " +
        "again to switch cases. Returns the case id that was set.")]
    public string SetCaseId(string caseId, RequestContext<CallToolRequestParams> context)
    {
        var session = registry.GetOrCreate(SessionId(context.Server));
        var previous = session.CaseId;
        session.CaseId = string.IsNullOrWhiteSpace(caseId) ? session.SessionId : caseId.Trim();
        // Record the case association in the (new) case's audit file so the switch itself is auditable.
        using (PushAuditProperty("CaseId", session.CaseId))
            AuditEvent("case", "Case id set to {CaseId} (was {Previous}) for session {SessionId}",
                session.CaseId, previous, session.SessionId);
        return $"Case id set to '{session.CaseId}' for this session. Audit trail file: audit-{session.CaseId}.clef";
    }

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

    [McpServerTool(Name = "Execute"), Description(
        "Execute JavaScript code against the Camel DFIR API (toolkits + workflows + anomaly engine). " +
        "Before writing any script you MUST read the 'camel-sdk-core' resource (camel://sdk/core) for the " +
        "execution model and the full list of objects and methods, and the 'camel-sdk-schema' resource " +
        "(camel://sdk/schema) for the JSON schema of every value those methods return — without the schemas you " +
        "cannot read results correctly. Call ONLY methods listed in camel-sdk-core, and access ONLY object " +
        "properties listed in camel-sdk-schema; do not invent methods or properties that are not documented there.")]
    public async Task<CallToolResult> Execute(
        string script,
        RequestContext<CallToolRequestParams> context,
        IProgress<ProgressNotificationValue> progress,
        CancellationToken cancellationToken)
    {
        // Each MCP session gets its own environment/API (its own SSH connection); resolve it by session id.
        // The RequestContext is injected by the SDK per request; context.Server carries the session id.
        // progress + cancellationToken are injected by the SDK: progress sends notifications/progress to the
        // client (a no-op when it sent no progress token); cancellationToken trips when the client aborts the call.
        var sessioid = SessionId(context.Server);
        var session = registry.GetOrCreate(sessioid);

        // Open the audit scope for this code-mode call: every tool execution it drives is recorded in the case's
        // audit file tagged with this CaseId and a unique ExecutionId, which is returned to the agent so its
        // report can cite it and a judge can trace any finding back to the exact command. The scopes must bracket
        // the whole run so the properties flow across the async boundary into the command-execution events.
        var executionId = Guid.NewGuid().ToString("N")[..8];
        using var _case = PushAuditProperty("CaseId", session.CaseId);
        using var _exec = PushAuditProperty("ExecutionId", executionId);

        StringBuilder output = new StringBuilder();
        // exit(msg) lets a script bail out immediately: it throws ExitException to unwind the engine, and the flag
        // (set synchronously before the throw) tells the catch block this was an intentional exit — robust even if
        // Jint wraps the CLR exception as a promise rejection so the type is not preserved.
        bool exitRequested = false;
        string? exitMessage = null;
        var jsinterp = new Engine(jsoptions)
          .SetValue("log", new Action<string>((s) => output.AppendLine(s)))
          .SetValue("error", new Action<string>((s) => output.AppendLine("Error: " + s)))
          // Stop the script now and return its message to the agent as ordinary output (not a tool error).
          .SetValue("exit", new Action<string>((s) => { exitMessage = s; exitRequested = true; throw new ExitException(s); }))
          // auditInfo/auditError additionally record the line in the per-case audit log (CLEF) as an
          // information/error event, so agent-surfaced output survives in the trail, not just the response.
          .SetValue("auditInfo", new Action<string>((s) => AuditInfo(s, output)))
          .SetValue("auditError", new Action<string>((s) => AuditError(s, output)))
          // auditFinding stages a structured forensic finding (observation/interpretation/confidence + the
          // execution ids that prove it) as a `finding` event; auditReviewRec marks a high-consequence decision
          // a human should review as a `human-judgement-recommended` event. Both also echo to the response.
          .SetValue("auditFinding", new Action<string, string, string, string>(
              (observation, interpretation, confidence, evidenceExecutionIds) =>
                  AuditFinding(observation, interpretation, confidence, evidenceExecutionIds, output)))
          .SetValue("auditReviewRec", new Action<string>((s) => AuditReviewRec(s, output)))
          // IR-accuracy events: auditFalsePositive (a lead checked and rejected as benign), auditMissingEvidence
          // (a gap — absent/cleared/disabled logs), auditHallucination (the agent caught itself inventing an
          // artifact/method/field). Surfacing these in the trail is positive evidence of investigative rigour.
          .SetValue("auditFalsePositive", new Action<string>((s) => AuditFalsePositive(s, output)))
          .SetValue("auditMissingEvidence", new Action<string>((s) => AuditMissingEvidence(s, output)))
          .SetValue("auditHallucination", new Action<string>((s) => AuditHallucination(s, output)))
          .SetValue("table", new Action<string[], object[][]>((headers, dataRows) =>
              output.AppendLine(RenderAsciiTable(headers, dataRows))))
          // Per-session storage: a string-keyed bag that persists between Execute calls, so a script can cache an
          // expensive result (e.g. Session["mft"] = await Timeline.PsortAsync(...)) and reuse it later instead of
          // recomputing it. The same dictionary instance is bound on every call for this session.
          .SetValue("Session", session.Storage)

          // Pure-compute anomaly triage over a canonical timeline (no AuditEnvironment); see Camel.Inference.
          // Typical flow: const ev = await timeline.PsortAsync(plaso); log(anomaly.Summarize(anomaly.TriageTimeline(ev, 200)));
          .SetValue("AnomalyDetectionToolkit", new Camel.Inference.AnomalyDetectionToolkit())

          // Workflows are cheap to construct (they just hold a reference to the toolkits api and resolve toolkits
          // lazily on use), so bind them all unconditionally.
          .SetValue("MemoryAnalysisWorkflow", session.WorkflowsApi.MemoryAnalysis)
          .SetValue("DiskAnalysisWorkflow", session.WorkflowsApi.DiskAnalysis)
          .SetValue("WindowsAnalysisWorkflow", session.WorkflowsApi.WindowsAnalysis)
          .SetValue("TimelineAnalysisWorkflow", session.WorkflowsApi.TimelineAnalysis)
          .SetValue("AntiForensicsAnalysisWorkflow", session.WorkflowsApi.AntiForensicsAnalysis)
          .SetValue("WebServerWorkflow", session.WorkflowsApi.WebServer)
          .SetValue("LinuxAnalysisWorkflow", session.WorkflowsApi.LinuxAnalysis)
          .SetValue("PacketAnalysisWorkflow", session.WorkflowsApi.PacketAnalysis);

        // Bind a SIFT toolkit global only when the script actually references it by name. Constructing a toolkit
        // can run one-time provisioning (Toolkit.InstallMissingTools = synchronous wget/apt for the EZ tools,
        // YARA rules pack, hayabusa, …). Binding every toolkit on every call would make the first call in a fresh
        // session block on installing tools the script never uses — e.g. a mount-only script (DiskAnalysis only)
        // would otherwise stall on the YARA/hayabusa downloads and exceed the client's tool timeout. Workflows
        // resolve their toolkits lazily through the api, so a workflow that needs a toolkit still provisions it.
        void BindToolkitIfUsed(string name, Func<object> resolve)
        {
            if (script.Contains(name, StringComparison.Ordinal)) jsinterp.SetValue(name, resolve());
        }
        BindToolkitIfUsed("MemoryAnalysisToolkit", () => session.ToolkitsApi.MemoryAnalysis);
        BindToolkitIfUsed("DiskAnalysisToolkit", () => session.ToolkitsApi.DiskAnalysis);
        BindToolkitIfUsed("WindowsAnalysisToolkit", () => session.ToolkitsApi.WindowsAnalysis);
        BindToolkitIfUsed("TimelineAnalysisToolkit", () => session.ToolkitsApi.Timeline);
        BindToolkitIfUsed("YaraToolkit", () => session.ToolkitsApi.Yara);
        BindToolkitIfUsed("UnixToolsToolkit", () => session.ToolkitsApi.UnixTools);
        BindToolkitIfUsed("LinuxAnalysisToolkit", () => session.ToolkitsApi.LinuxAnalysis);
        BindToolkitIfUsed("PacketAnalysisToolkit", () => session.ToolkitsApi.PacketAnalysis);

        // Mark the session busy for the duration of the call so the idle sweeper can't dispose its SSH
        // environment out from under a long-running analysis (LastAccess is only stamped at call start).
        session.EnterCall();
        // If the client aborts the call (its timeout fires, or the user cancels), promptly cancel the session's
        // in-flight SSH command(s). Jint only observes its cancellation token at a JS/await boundary, so without
        // this a blocked command (e.g. reading a multi-GB tool output) would keep running for minutes after the
        // client has gone. CancelExecutions swaps in a fresh token source, so the session stays usable afterwards.
        using var cancelReg = cancellationToken.Register(() =>
        {
            try { session.Environment.CancelExecutions(); } catch { /* best-effort */ }
        });
        var auditSw = Stopwatch.StartNew();
        AuditExecution("started", script);   // records the exact code this execution ran, under the case file

        // Builds the result for an exit() call. This is a deliberate early exit, not a tool failure — the
        // throw is just the most reliable way to unwind the engine — so the result is NOT flagged IsError; the
        // message is appended to the output the agent receives and recorded in the trail.
        CallToolResult BuildExitResult()
        {
            var exitText = exitMessage ?? "";
            AuditEvent("execution", "{Message}", "exit: " + exitText);
            AuditExecution("exited", success: true, durationMs: auditSw.ElapsedMilliseconds);
            if (exitText.Length > 0) output.AppendLine(exitText);
            return new CallToolResult
            {
                Content = [new TextContentBlock { Text = output.ToString() }, ExecutionBlock(executionId, session.CaseId)],
            };
        }

        try
        {
            // Wrap in an async IIFE so scripts can `await` async toolkit methods: top-level await isn't allowed
            // in a plain Jint script, and modules can't drive a CLR-task top-level await synchronously. The
            // surrounding newlines guard against a trailing line comment swallowing the closer. ExecuteAsync
            // drains the awaited CLR tasks before returning; purely synchronous scripts run unchanged. The
            // cancellationToken lets Jint stop awaiting promises if the client aborts the request.
            var exec = jsinterp.ExecuteAsync($"(async () => {{\n{script}\n}})();", source: null, cancellationToken);

            // Heartbeat: a code-mode analysis can run for many minutes (super-timeline builds, multi-GB memory
            // triage). With no traffic on the response stream the MCP client's per-call idle timeout fires and it
            // aborts the request ("transport dropped mid-call; response was lost"). Emitting a progress
            // notification every HeartbeatInterval resets that client-side timer for the duration of the work.
            await RunWithHeartbeatAsync(exec, progress, HeartbeatInterval, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The client aborted the call; the response channel is already gone, so there is nothing to return.
            AuditExecution("cancelled", success: false, durationMs: auditSw.ElapsedMilliseconds);
            throw;
        }
        catch (Exception) when (exitRequested)
        {
            // exit(msg) was called: a deliberate early exit, not a fault — return its message as normal output.
            return BuildExitResult();
        }
        catch (Exception ex)
        {
            AuditExecution("failed", success: false, durationMs: auditSw.ElapsedMilliseconds);
            // Errors surface as JavaScriptException (synchronous throw) or, via the async IIFE, as
            // PromiseRejectedException; both carry the script-level error text in their message.
            var jsex = ex as Jint.Runtime.JavaScriptException
                       ?? ex.InnerException as Jint.Runtime.JavaScriptException;
            var jsErrorText = jsex?.Message
                ?? (ex is Jint.Runtime.PromiseRejectedException ? ex.Message : null);
            var message = jsErrorText is not null
                ? $"JavaScript error: {jsErrorText}"
                : $"Error executing script: {ex.Message}";

            // A script that names a non-existent toolkit/workflow object or method is evidence the model invented
            // part of the Camel API — a hallucination, not a logic bug. Record it as a `hallucination` event and
            // nudge the agent back to the documented SDK so the failure becomes self-correcting (criteria 1 & 2).
            if (ClassifyHallucination(jsErrorText) is string halluReason)
            {
                AuditEvent("hallucination", "{Message}", halluReason);
                message += $"{Environment.NewLine}[possible hallucination] {halluReason}. Only objects and methods " +
                           "documented in the camel-sdk-core resource exist — re-read it and do not invent APIs.";
            }

            // Include anything written via log()/error() before the failure for context.
            if (output.Length > 0)
            {
                message = output.ToString() + Environment.NewLine + message;
            }

            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = message }, ExecutionBlock(executionId, session.CaseId)],
            };
        }
        finally
        {
            // Clears the busy flag and re-stamps LastAccess, so the idle window starts when the call ends.
            session.LeaveCall();
        }

        // Defensive: if a script managed to catch the exit throw (e.g. wrapped it in try/catch) yet reached
        // the end, still honour the intent and return an exit result rather than a silent success.
        if (exitRequested) return BuildExitResult();

        AuditExecution("completed", success: true, durationMs: auditSw.ElapsedMilliseconds);
        return new CallToolResult
        {
            Content = [new TextContentBlock { Text = output.ToString() }, ExecutionBlock(executionId, session.CaseId)],
        };
    }

    // Pass the agent's text as a {Message} parameter, never as the template itself: script output can contain
    // '{' (e.g. JSON.stringify), which Serilog would otherwise try to parse as a property token.
    protected void AuditInfo(string text, StringBuilder output)
    {
        AuditEvent("information", "{Message}", text);
        output.AppendLine(text);
    }

    protected void AuditError(string text, StringBuilder output)
    {
        AuditEvent("error", "{Message}", text);
        output.AppendLine(text);
    }

    /// <summary>
    /// Records a structured forensic finding to the per-case audit trail as a <c>finding</c> event — observation
    /// and interpretation kept as distinct fields (forcing the agent to separate fact from inference), with the
    /// confidence level and the <c>execution</c> ids that prove it. Also echoes a one-line summary to the response.
    /// </summary>
    protected void AuditFinding(string observation, string interpretation, string confidence, string evidenceExecutionIds, StringBuilder output)
    {
        AuditEvent("finding",
            "FINDING [{Confidence}] {Observation} => {Interpretation} (evidence: {EvidenceExecutionIds})",
            confidence, observation, interpretation, evidenceExecutionIds);
        output.AppendLine($"[finding {confidence}] {observation} => {interpretation} (evidence: {evidenceExecutionIds})");
    }

    /// <summary>
    /// Flags a high-consequence conclusion (root cause, attribution, scope, exfiltration, insider, ruling-out)
    /// as a <c>human-judgement-recommended</c> event so a reviewer can grep the trail straight to the decision
    /// points the agent reached autonomously. The run does not stop; it presents candidates and continues.
    /// </summary>
    protected void AuditReviewRec(string reason, StringBuilder output)
    {
        AuditEvent("human-judgement-recommended", "{Message}", reason);
        output.AppendLine($"[human-judgement-recommended] {reason}");
    }

    /// <summary>Records a lead that was checked and rejected as benign as a <c>false-positive</c> event.</summary>
    protected void AuditFalsePositive(string text, StringBuilder output)
    {
        AuditEvent("false-positive", "{Message}", text);
        output.AppendLine(text);
    }

    /// <summary>Records an evidentiary gap (absent/cleared/disabled logs, unavailable artifact) as a
    /// <c>missing-evidence</c> event — "no evidence found", not "did not happen".</summary>
    protected void AuditMissingEvidence(string text, StringBuilder output)
    {
        AuditEvent("missing-evidence", "{Message}", text);
        output.AppendLine(text);
    }

    /// <summary>Records that the agent caught itself inventing an artifact, method, or field as a
    /// <c>hallucination</c> event. The server also emits this automatically on a script error that names a
    /// non-existent toolkit/workflow (see <see cref="ClassifyHallucination"/>).</summary>
    protected void AuditHallucination(string text, StringBuilder output)
    {
        AuditEvent("hallucination", "{Message}", text);
        output.AppendLine(text);
    }

    /// <summary>
    /// Heuristically classifies a Jint error message as a probable API hallucination: a reference to an undefined
    /// name, or a call to a non-existent method, where the message names a Camel <c>*Toolkit</c>/<c>*Workflow</c>.
    /// Scoped to those tokens so ordinary undeclared-variable typos and language-feature gaps are not misfiled.
    /// Returns a human-readable reason, or <c>null</c> when the error is not hallucination-shaped.
    /// </summary>
    static string? ClassifyHallucination(string? jsErrorMessage)
    {
        if (string.IsNullOrEmpty(jsErrorMessage)) return null;
        var namesApi = jsErrorMessage.Contains("Toolkit", StringComparison.Ordinal)
                       || jsErrorMessage.Contains("Workflow", StringComparison.Ordinal);
        if (!namesApi) return null;
        if (jsErrorMessage.Contains("is not defined", StringComparison.OrdinalIgnoreCase))
            return $"referenced a toolkit/workflow that does not exist ({jsErrorMessage})";
        if (jsErrorMessage.Contains("is not a function", StringComparison.OrdinalIgnoreCase))
            return $"called a method that does not exist on a Camel toolkit/workflow ({jsErrorMessage})";
        return null;
    }

    /// <summary>
    /// The audit-handle block appended to every <c>Execute</c> result: the case id and this call's
    /// execution id. The agent cites these in its report so a judge can grep the per-case audit file
    /// (<c>audit-&lt;CaseId&gt;.clef</c>) for the execution and see exactly which tool executions produced a finding.
    /// </summary>
    static TextContentBlock ExecutionBlock(string executionId, string caseId) =>
        new() { Text = $"\n[audit] case={caseId} execution={executionId}" };

    /// <summary>
    /// Awaits <paramref name="work"/> while emitting a progress notification every <see cref="HeartbeatInterval"/>
    /// so a long-running tool call keeps resetting the MCP client's idle timeout (otherwise the client aborts the
    /// request mid-call). Returns when the work completes (re-throwing any error it produced); throws
    /// <see cref="OperationCanceledException"/> if the client cancels first.
    /// </summary>
    internal static async Task RunWithHeartbeatAsync(Task work, IProgress<ProgressNotificationValue> progress, TimeSpan interval, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        float tick = 0;
        while (true)
        {
            // Cancel the pending delay as soon as the work finishes so we don't leak a timer per heartbeat.
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var delay = Task.Delay(interval, linked.Token);
            if (await Task.WhenAny(work, delay).ConfigureAwait(false) == work)
            {
                linked.Cancel();
                await work.ConfigureAwait(false);   // observe the result / surface the script exception
                return;
            }
            // The delay won the race: either the interval elapsed (emit a heartbeat) or the caller cancelled —
            // in which case the delay completed as cancelled and we must surface that rather than tick again.
            ct.ThrowIfCancellationRequested();
            progress.Report(new ProgressNotificationValue
            {
                Progress = ++tick,
                Message = $"Camel: executing… ({sw.Elapsed.TotalSeconds:F0}s elapsed)",
            });
        }
    }

    // How often to send a keep-alive progress notification while a script runs. Comfortably under typical MCP
    // client per-call idle timeouts (tens of seconds to minutes) so a multi-minute analysis is never aborted.
    static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(20);

    // Stdio (and any transport that doesn't assign one) yields a null/empty session id; bucket those under "default".
    static string SessionId(McpServer server) => string.IsNullOrEmpty(server.SessionId) ? "default" : server.SessionId;

    /// <summary>
    /// Renders the JS <c>table(headers, rows)</c> call as a fixed-width ASCII grid (psql/GitHub style) for the
    /// script's text output. <paramref name="headers"/> are the column titles; <paramref name="rows"/> is a jagged
    /// array of cell values (Jint marshals JS strings/numbers/bools/null). Columns are sized to the widest cell,
    /// cells are left-aligned, and short/long rows are padded/extended so the grid stays rectangular.
    /// </summary>
    internal static string RenderAsciiTable(string[]? headers, object[][]? rows)
    {
        headers ??= [];
        rows ??= [];

        // Column count spans the header and the widest row (ragged rows are tolerated).
        int cols = headers.Length;
        foreach (var r in rows) cols = Math.Max(cols, r?.Length ?? 0);
        if (cols == 0) return "(empty table)";

        // Stringify every cell up front (header row first), normalising control chars so they can't break the grid.
        string[] Header() => Array.ConvertAll(Pad(headers, cols), Cell);
        var grid = new List<string[]> { Header() };
        grid.AddRange(rows.Select(r => Array.ConvertAll(Pad(r ?? [], cols), Cell)));

        // Width of each column = widest cell in it.
        var widths = new int[cols];
        foreach (var row in grid)
            for (int c = 0; c < cols; c++)
                widths[c] = Math.Max(widths[c], row[c].Length);

        string separator = "+" + string.Join("+", widths.Select(w => new string('-', w + 2))) + "+";
        string Line(string[] row) =>
            "| " + string.Join(" | ", row.Select((c, i) => c.PadRight(widths[i]))) + " |";

        var sb = new StringBuilder();
        sb.AppendLine(separator);
        sb.AppendLine(Line(grid[0]));     // header
        sb.AppendLine(separator);
        for (int i = 1; i < grid.Count; i++) sb.AppendLine(Line(grid[i]));
        sb.Append(separator);
        return sb.ToString();

        // Pad/extend a row to exactly `cols` entries so every grid row is rectangular.
        static object?[] Pad(object?[] row, int cols)
        {
            if (row.Length == cols) return row;
            var padded = new object?[cols];
            Array.Copy(row, padded, Math.Min(row.Length, cols));
            return padded;
        }

        // One cell -> its display string. Numbers/bools use invariant formatting; null -> empty; control chars -> spaces.
        static string Cell(object? v)
        {
            string s = v switch
            {
                null => "",
                bool b => b ? "true" : "false",
                string str => str,
                IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
                _ => v.ToString() ?? "",
            };
            return s.Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');
        }
    }

    readonly SessionRegistry registry;
    readonly Options jsoptions;
}

/// <summary>
/// MCP resources exposing the Camel JavaScript SDK reference to the agent. The markdown docs are embedded in
/// this assembly (see Camel.Server.csproj) and served verbatim, so an agent can read the SDK surface before
/// generating code for the <c>Execute</c> tool without the docs having to exist on disk at runtime.
/// NOTE: these are served as <c>text/plain</c>, not <c>text/markdown</c>, on purpose — a client that renders a
/// markdown resource collapses single-newline line breaks (markdown only breaks on blank lines / hard breaks),
/// flattening the reference into one long line for the model. Plain text is surfaced to the model verbatim.
/// </summary>
public class CamelResources
{
    [McpServerResource(UriTemplate = "camel://sdk/core", Name = "camel-sdk-core",
        Title = "Camel JS SDK reference — core", MimeType = "text/plain")]
    [Description("Core reference for the Camel JavaScript SDK used by the Execute tool: the execution " +
        "model (await semantics, return-value shapes, PascalCase naming, positional optional params) and the full " +
        "method signature index — every toolkit and workflow object, each method's parameters and return type. " +
        "Read this FIRST and keep it in context when generating JS. The method return types reference model types " +
        "whose JSON schemas live in the companion 'camel-sdk-schema' resource (camel://sdk/schema).")]
    public static string SdkCore() => ReadEmbedded("Camel.core.md");

    [McpServerResource(UriTemplate = "camel://sdk/schema", Name = "camel-sdk-schema",
        Title = "Camel JS SDK reference — schemas", MimeType = "text/plain")]
    [Description("JSON schemas for every parameter and return model type in the Camel JavaScript SDK — the " +
        "companion to 'camel-sdk-core'. Consult this when you need the exact fields of an object a toolkit or " +
        "workflow method returns (e.g. TimelineEvent, FindMalwareReport, TriageReport). Schemas are grouped by " +
        "the object that returns them.")]
    public static string SdkSchema() => ReadEmbedded("Camel.schema.md");

    [McpServerResource(UriTemplate = "camel://sdk/discipline", Name = "camel-sdk-discipline",
        Title = "Camel JS SDK reference — forensic discipline", MimeType = "text/plain")]
    [Description("The forensic investigative discipline for the Execute tool: how to reason over what the SDK " +
        "returns — core principles (evidence is sovereign, absence ≠ absence, correlation ≠ causation, benign " +
        "until proven malicious), the analyze/collect/corroborate/record loop, the self-checks and golden rules " +
        "for grounding a finding in cited execution ids, and the high-consequence decisions to flag for human " +
        "judgement (via auditReviewRec) while still running autonomously. Read this alongside 'camel-sdk-core'.")]
    public static string SdkDiscipline() => ReadEmbedded("Camel.discipline.md");

    static string ReadEmbedded(string name)
    {
        using var stream = typeof(CamelResources).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded SDK doc '{name}' was not found in the assembly.");
        using var reader = new System.IO.StreamReader(stream);
        return reader.ReadToEnd();
    }
}

public class CamelMCPServer : Runtime
{
    const string CorsPolicyName = "CamelMcpCors";
   
    public static async Task RunStdioAsync(IConfigurationRoot config)
    {
        var builder = Host.CreateEmptyApplicationBuilder(null);
        // One environment per MCP session, created lazily and swept when idle.
        var registry = new SessionRegistry(config);
        builder.Services.AddSingleton(registry);
        builder.Services.AddHostedService<IdleSessionSweeper>();
        builder
            .Logging.AddProvider(loggerProvider)
            .SetMinimumLevel(LogLevel.Trace);

        var mcpServices = builder
            .Services
            .AddMcpServer()
            .WithTools(new CamelMCPTools(registry))
            .WithResources<CamelResources>()
            .WithStdioServerTransport();

        var app = builder.Build();
        app.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping.Register(() =>
        {
            registry.Dispose();
            CloseAndFlushAuditLog();   // flush buffered audit events to the per-case files on a clean shutdown
        });

        await app.RunAsync();
    }

    public static async Task RunHttpAsync(IConfigurationRoot config) => await BuildHttpApp(config).RunAsync();

    /// <summary>
    /// Builds the fully-configured HTTP MCP <see cref="WebApplication"/> (DI, CORS, transport, endpoints,
    /// lifecycle) without starting it. <see cref="RunHttpAsync"/> just runs the result; integration tests
    /// host it themselves (e.g. on an ephemeral port) and connect a real MCP client.
    /// </summary>
    public static WebApplication BuildHttpApp(IConfigurationRoot config)
    {
        var builder = WebApplication.CreateBuilder();
        // One environment per MCP session, created lazily and swept when idle.
        var registry = new SessionRegistry(config);
        builder.Services.AddSingleton(registry);
        builder.Services.AddHostedService<IdleSessionSweeper>();
        builder
            .Logging.ClearProviders()
            .AddProvider(loggerProvider)
            .SetMinimumLevel(LogLevel.Trace);

        // Allow browser-based MCP clients (served from a different origin) to call
        // the HTTP/SSE endpoints. AllowAnyOrigin is convenient for local/trusted use;
        // restrict it with WithOrigins(...) if Camel is exposed beyond a trusted host.
        // Mcp-Session-Id must be exposed so clients can read the session id the server
        // assigns on initialize and echo it back on subsequent requests.
        builder.Services.AddCors(options =>
        {
            options.AddPolicy(CorsPolicyName, policy =>
            {
                policy
                    .AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .WithExposedHeaders("Mcp-Session-Id");
            });
        });

        var mcpServices = builder
            .Services
            .AddMcpServer()
            .WithTools(new CamelMCPTools(registry))
            .WithResources<CamelResources>()
            .WithHttpTransport(options =>
            {
                // Use stateful sessions so the Streamable HTTP transport can
                // stream responses and push server-initiated messages back to
                // the client over its SSE (GET) channel. In stateless mode each
                // request gets a fresh context, which disables both of those and
                // is incompatible with the legacy SSE transport below.
                options.Stateless = false;

                // Also map the legacy HTTP+SSE endpoints (GET /sse, POST /message)
                // for older clients that don't support Streamable HTTP yet.
                options.EnableLegacySse = true;
            });

        var app = builder.Build();

        app.UseCors(CorsPolicyName);

        // Maps the Streamable HTTP endpoints at the root path and, because
        // EnableLegacySse is set above, the legacy "/sse" and "/message" endpoints.
        app.MapMcp();

        // Tear down all session environments (cancel in-flight commands, disconnect SSH) on shutdown.
        app.Lifetime.ApplicationStopping.Register(() => { registry.Dispose(); CloseAndFlushAuditLog(); });

        app.Lifetime.ApplicationStarted.Register(() =>
        {
            var addresses = app.Services
                .GetRequiredService<IServer>()
                .Features
                .Get<IServerAddressesFeature>()?
                .Addresses;

            if (addresses is null || addresses.Count == 0)
            {
                Info("Camel MCP server (HTTP transport) started, but no listening address was reported.");
            }
            else
            {
                foreach (var address in addresses)
                {
                    Info("Camel MCP server listening on {Address} (Streamable HTTP at '/', legacy SSE at '/sse' and '/message').", address);
                }
            }
        });

        return app;
    }
}
