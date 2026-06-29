namespace Camel.Environments;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;

public enum EnvironmentType
{
    Local,
    Ssh
}   

public abstract class AuditEnvironment : Runtime, IDisposable
{    
    #region Constructors
    public AuditEnvironment(EventHandler<EnvironmentEventArgs> message_handler, OperatingSystem os, LocalEnvironment host_environment)
    {
        this.OS = os;
        if (OS.Platform == PlatformID.Win32NT)
        {
            this.LineTerminator = "\r\n";
            this.PathSeparator = "\\";
        }
        else
        {
            this.LineTerminator = "\n";
            this.PathSeparator = "/";
        }
        this.MessageHandler = message_handler;
        this.HostEnvironment = host_environment;

    }

    public AuditEnvironment(OperatingSystem os, LocalEnvironment host_environment) : this(DefaultEnvironmentMessageHandler, os, host_environment) {}
    #endregion

    #region Abstract properties and methods
    public abstract bool FileExists(string file_path);
    public abstract bool DirectoryExists(string dir_path);

    /// <summary>Returns the size in bytes of the regular file at <paramref name="path"/>, or <c>-1</c> if it does
    /// not exist or cannot be sized (e.g. it is a directory or is unreadable).</summary>
    public abstract long GetFileSize(string path);
    public abstract CommandResult Execute(string command, string arguments,Dictionary<string, string>? EnvironmentVariables = null, Action<string>? OutputDataReceived = null, Action<string>? OutputErrorReceived = null);
    public abstract Task<CommandResult> ExecuteAsync(string command, string arguments, Dictionary<string, string>? EnvironmentVariables = null, Action<string>? OutputDataReceived = null, Action<string>? OutputErrorReceived = null);
    public abstract CommandResult ExecuteAsUser(string command, string arguments, string user, SecureString password, Action<string>? OutputDataReceived = null, Action<string>? OutputErrorReceived = null);
    public abstract AuditFileInfo ConstructFile(string file_path);
    public abstract AuditDirectoryInfo ConstructDirectory(string dir_path);
    public abstract Dictionary<AuditFileInfo, string> ReadFilesAsText(List<AuditFileInfo> files);

    /// <summary>Copies a file from this environment to <paramref name="localPath"/> and returns it (SCP for a remote
    /// SSH environment; a plain file copy locally), so a large output can be streamed/parsed from disk instead of
    /// captured through a command's stdout. Returns null on failure.</summary>
    public abstract FileInfo? GetFileAsLocal(string remotePath, string localPath);
    protected abstract TraceSource TraceSource { get; set; }
    #endregion

    #region Properties
    public bool IsWindows
    {
        get
        {
            if (this.OS != null && this.OS.Platform == PlatformID.Win32NT)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    public bool IsUnix
    {
        get
        {
            if (this.OS != null && this.OS.Platform == PlatformID.Unix)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    public bool IsMonoRuntime
    {
        get
        {
            return Type.GetType("Mono.Runtime") != null;
        }
    }

    public new string PathSeparator { get; protected set; } = string.Empty;
    
    public OperatingSystem OS { get; protected set; }

    public string? OSName { get; set; }

    public string? OSVersion { get; set; }

    public Dictionary<string, string>? OSEnvironmentVars { get; protected set; }

    public List<ProcessInfo>? OSProcesses { get; protected set; }

    public LocalEnvironment HostEnvironment { get; protected set; }

    public DirectoryInfo WorkDirectory { get; protected set; }

    internal string LineTerminator { get; set; }

    #endregion

    #region Concurrency limiting
    /// <summary>
    /// Maximum number of concurrent async command executions on this environment. <c>0</c> (default) means
    /// unlimited. A positive value bounds fan-out (e.g. a code-mode <c>Promise.all</c>) so a single session
    /// can't exhaust the connection's SSH channels or swamp the workstation. Typically set from config.
    /// </summary>
    public int MaxConcurrentExecutions { get; set; } = 0;

    private SemaphoreSlim? _executionLimiter;
    private readonly object _executionLimiterLock = new();

    // Lazily built (MaxConcurrentExecutions is usually assigned from config after construction). Null = unlimited.
    private SemaphoreSlim? ExecutionLimiter
    {
        get
        {
            if (MaxConcurrentExecutions <= 0) return null;
            if (_executionLimiter is null)
                lock (_executionLimiterLock) _executionLimiter ??= new SemaphoreSlim(MaxConcurrentExecutions);
            return _executionLimiter;
        }
    }

    /// <summary>
    /// Runs <paramref name="execute"/> under this environment's concurrency limit (see
    /// <see cref="MaxConcurrentExecutions"/>; 0 = unlimited). The wait honours the environment's cancellation
    /// token so a disconnect doesn't leave callers queued. Intended to wrap each <c>ExecuteAsync</c> override.
    /// </summary>
    protected async Task<CommandResult> RunWithLimitAsync(Func<Task<CommandResult>> execute)
    {
        var limiter = ExecutionLimiter;
        if (limiter is null) return await execute();

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(Runtime.Ct, ExecuteCt);
        await limiter.WaitAsync(linked.Token);   // throws OCE if cancelled while queued (nothing to release)
        try { return await execute(); }
        finally { limiter.Release(); }
    }
    #endregion

    #region Cancellation
    // Backing source whose token is observed by every async Execute call on this environment. Cancelling
    // it (via CancelExecutions) aborts all in-flight and pending async commands — e.g. on client disconnect.
    private CancellationTokenSource executeCts = new();

    /// <summary>The token all async Execute methods on this environment observe. Trip it via <see cref="CancelExecutions"/>.</summary>
    public CancellationToken ExecuteCt => executeCts.Token;

    /// <summary>
    /// Cancels every in-flight and pending async command on this environment, then swaps in a fresh source
    /// so subsequent calls execute normally. The old source is intentionally not disposed: a caller may have
    /// read it but not yet built its linked token, and disposing it would make that read throw
    /// <see cref="ObjectDisposedException"/>; a plain (timer-less) source holds no unmanaged handle, so GC
    /// reclaims it safely once the cancellation callbacks have run.
    /// </summary>
    public void CancelExecutions()
    {
        var old = Interlocked.Exchange(ref executeCts, new CancellationTokenSource());
        old.Cancel();
    }

    /// <summary>
    /// Releases this environment's idle transport (e.g. an SSH connection) while keeping the environment object
    /// usable — the next command transparently reconnects. Lets the idle sweeper reclaim the expensive connection
    /// without discarding the session's in-memory state (its <c>Session</c> storage). The base implementation is a
    /// no-op (e.g. the local environment holds no connection to release). Returns true if a live connection was
    /// actually released.
    /// </summary>
    public virtual bool DisconnectIdle() => false;
    #endregion

    #region Evidence integrity
    /// <summary>
    /// The original evidence registered against this environment (disk images, memory captures, mounted
    /// artifacts, …). Toolkits and workflows consult this — via <see cref="CheckAgainstEvidencePaths"/> —
    /// before any write/modify operation so that original data is never altered. Enforcing spoliation
    /// protection here, at the environment that is "closest" to where the physical evidence resides, makes
    /// it common to every toolkit rather than something each tool has to remember. Empty by default.
    /// </summary>
    protected EvidenceInfo[] CaseEvidence { get; private set; } = Array.Empty<EvidenceInfo>();

    // Set once TrySetCaseEvidence succeeds. Evidence is write-once per environment (i.e. per session), so the
    // spoliation guard can't be silently repointed mid-investigation.
    private bool evidenceRegistered;

    /// <summary>True once case evidence has been registered for this environment (see <see cref="TrySetCaseEvidence"/>).</summary>
    public bool EvidenceRegistered => evidenceRegistered;

    /// <summary>
    /// Registers the original case evidence for this environment — once. Returns true if accepted; false if
    /// evidence was already registered, in which case nothing changes and the existing evidence stands. Evidence
    /// is deliberately write-once per session so an analyst (or a confused agent) cannot silently repoint the
    /// spoliation guard part-way through a case; changing it requires a fresh session. The caller (the
    /// <c>SetEvidence</c> MCP tool) is responsible for auditing a refused second attempt as a spoliation event.
    /// </summary>
    public bool TrySetCaseEvidence(EvidenceInfo[] evidence)
    {
        if (evidenceRegistered) return false;
        CaseEvidence = evidence ?? Array.Empty<EvidenceInfo>();
        evidenceRegistered = true;
        return true;
    }

    /// <summary>
    /// Returns true if <paramref name="path"/> refers to a piece of registered case evidence (see
    /// <see cref="CaseEvidence"/>) — either the evidence file itself or the directory that contains it, since
    /// writing into an evidence directory can also disturb the original data. Comparison normalizes path
    /// separators to this environment's separator and honours its filesystem case-sensitivity
    /// (case-insensitive on Windows, case-sensitive on Unix), so a caller cannot slip past the check with an
    /// equivalent spelling of an evidence path.
    /// </summary>
    public bool CheckAgainstEvidencePaths(string path) => FindEvidenceForPath(path) is not null;

    /// <summary>
    /// Refuses an operation that targets registered evidence by throwing
    /// <see cref="EvidenceSpoliationRiskException"/> if <paramref name="targetPath"/> is an evidence file or its
    /// containing directory (see <see cref="CheckAgainstEvidencePaths"/>). Call this from any toolkit/workflow
    /// path that writes, overwrites, or deletes before it touches the filesystem so original evidence cannot be
    /// disturbed — turning spoliation protection into an architectural guard rather than a convention.
    /// </summary>
    public void FailIfEvidenceSpoliationRisk(string targetPath)
    {
        var evidence = FindEvidenceForPath(targetPath);
        if (evidence is not null) throw new EvidenceSpoliationRiskException(evidence, targetPath);
    }

    // The registered evidence that <paramref name="path"/> would put at risk (the evidence file itself or its
    // containing directory), or null if the path is not protected. Shared by the check and the guard so both
    // apply identical normalization and case-sensitivity rules.
    private EvidenceInfo? FindEvidenceForPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || CaseEvidence.Length == 0) return null;
        var comparison = IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var normalized = NormalizeEvidencePath(path);
        return CaseEvidence.FirstOrDefault(e =>
        {
            var file = NormalizeEvidencePath(e.FilePath);
            return file.Equals(normalized, comparison) || GetEvidenceDirectory(file).Equals(normalized, comparison);
        });
    }

    // Collapse mixed/duplicate separators to this environment's separator and strip a trailing one so that
    // equivalent spellings of the same path compare equal.
    private string NormalizeEvidencePath(string path)
    {
        var p = path.Trim().Replace('\\', '/').Replace('/', PathSeparator[0]);
        return p.Length > 1 ? p.TrimEnd(PathSeparator[0]) : p;
    }

    // The parent directory of an already-normalized evidence path (empty if it has no separator).
    private string GetEvidenceDirectory(string normalizedPath)
    {
        var i = normalizedPath.LastIndexOf(PathSeparator[0]);
        return i <= 0 ? normalizedPath[..(i + 1)] : normalizedPath[..i];
    }

    /// <summary>
    /// Preflight check run before registering evidence: for each supplied <paramref name="evidence"/> entry,
    /// reports whether the path exists on this environment and its size, as a <see cref="CaseEvidenceSummary"/>
    /// (<see cref="CaseEvidenceSummary.AllPresent"/> is false if any is missing). The <c>SetEvidence</c> tool calls
    /// this first and refuses registration when a file is absent, so the spoliation guard is never armed against
    /// paths that don't exist yet.
    /// </summary>
    public CaseEvidenceSummary GetEvidenceSummary(EvidenceInfo[] evidence)
    {
        var files = (evidence ?? Array.Empty<EvidenceInfo>()).Select(e =>
        {
            var exists = FileExists(e.FilePath) || DirectoryExists(e.FilePath);
            return new EvidenceFileSummary(e.FilePath, exists, exists ? GetFileSize(e.FilePath) : -1);
        }).ToArray();
        return new CaseEvidenceSummary(files.All(f => f.Exists), files);
    }

    /// <summary>
    /// Re-hashes every registered evidence file on disk and compares it against the hash that was supplied when
    /// it was registered, returning a <see cref="CaseEvidenceVerification"/>. For an item that supplied a hash,
    /// the same algorithm is recomputed and compared (case-insensitive); a mismatch — or a file that cannot be
    /// hashed — sets <see cref="CaseEvidenceVerification.Success"/> false. <b>EWF (.E01) images are content-verified
    /// with <c>ewfverify</c></b>, because the acquisition hash an analyst supplies is the digest of the acquired
    /// media content, not of the <c>.E01</c> container file — a plain file re-hash would never match it. For an
    /// item with no supplied hash, the file's current SHA-1 (of the file as it sits on disk) is recorded as a
    /// baseline and never fails the result. This is the integrity check a chain-of-custody report cites: the
    /// evidence on disk is the evidence that was acquired.
    /// </summary>
    public async Task<CaseEvidenceVerification> VerifyCaseEvidenceAsync()
    {
        var results = new List<EvidenceHashCheck>(CaseEvidence.Length);
        var success = true;
        foreach (var e in CaseEvidence)
        {
            var hasHash = e.HashType != HashType.None && !string.IsNullOrEmpty(e.HashValue);
            // With a supplied hash, recompute with that algorithm to compare; otherwise record SHA-1 as the baseline.
            // An E01 with a supplied hash is verified against its media-content digest (ewfverify), not the container.
            var current = hasHash && IsEwfImage(e.FilePath)
                ? await ComputeEwfContentHashAsync(e.FilePath, e.HashType)
                : await ComputeFileHashAsync(e.FilePath, hasHash ? e.HashType : HashType.SHA1);
            var matched = !hasHash || (current.Length > 0 && string.Equals(current, e.HashValue, StringComparison.OrdinalIgnoreCase));
            if (!matched) success = false;
            results.Add(new EvidenceHashCheck(e, current, matched));
        }
        return new CaseEvidenceVerification(success, results.ToArray());
    }

    // Computes the hex digest of a file on this environment with the given algorithm, or "" on failure. Unix uses
    // the coreutils sum tools (retrying under sudo for root-owned evidence on a forensic mount); Windows uses
    // certutil. The output is normalised to lower-case hex.
    private async Task<string> ComputeFileHashAsync(string path, HashType type)
    {
        if (IsWindows)
        {
            var alg = type switch { HashType.MD5 => "MD5", HashType.SHA256 => "SHA256", _ => "SHA1" };
            var rw = await ExecuteCommandAsync("certutil", $"-hashfile \"{path}\" {alg}");
            return rw.IsCompleted ? ExtractCertutilHash(rw.Output) : "";
        }
        var cmd = type switch { HashType.MD5 => "md5sum", HashType.SHA256 => "sha256sum", _ => "sha1sum" };
        var r = await ExecuteCommandAsync(cmd, $"'{path}'");
        if (!r.IsCompleted && IsUnix) r = await ExecuteCommandAsync(cmd, $"'{path}'", admin: true);   // root-owned evidence
        if (!r.IsCompleted) return "";
        // coreutils sum tools print "<hex>␣␣<path>"; take the leading hex token.
        var tok = r.Output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return tok.Length > 0 ? tok[0].Trim().ToLowerInvariant() : "";
    }

    // True for an EWF/Expert Witness image whose content hash must be verified with ewfverify rather than by
    // file-hashing the container (.E01 = EWF1 first/only segment, .Ex01 = EWF2).
    private static bool IsEwfImage(string path) =>
        path.EndsWith(".e01", StringComparison.OrdinalIgnoreCase) ||
        path.EndsWith(".ex01", StringComparison.OrdinalIgnoreCase);

    // Recomputes an EWF image's media-content digest with ewfverify and returns it as lower-case hex, or "" on
    // failure. ewfverify always calculates MD5; SHA-1/SHA-256 are requested with -d. Retries under sudo for
    // root-owned evidence on a forensic mount. Reads the whole image, so this can take minutes for a large disk.
    private async Task<string> ComputeEwfContentHashAsync(string path, HashType type)
    {
        var algo = type switch { HashType.MD5 => "md5", HashType.SHA256 => "sha256", _ => "sha1" };
        // -q keeps the progress chatter down but still prints the hash summary; -d adds the non-MD5 digest.
        var args = (type == HashType.MD5 ? "" : $"-d {algo} ") + $"-q '{path}'";
        var hash = ParseEwfDigest((await ExecuteCommandAsync("ewfverify", args)).Output, algo);
        if (hash.Length == 0 && IsUnix)
            hash = ParseEwfDigest((await ExecuteCommandAsync("ewfverify", args, admin: true)).Output, algo);
        return hash;
    }

    // ewfverify prints a line like "<ALGO> hash calculated over data:\t<hex>" per digest; return the hex for the
    // requested algorithm. Matching on the algorithm name disambiguates the MD5 line from an added SHA line.
    // (internal for unit testing the parser against captured ewfverify output.)
    internal static string ParseEwfDigest(string output, string algo)
    {
        foreach (var line in output.Split('\n'))
        {
            if (line.IndexOf("calculated over data", StringComparison.OrdinalIgnoreCase) < 0) continue;
            if (line.IndexOf(algo, StringComparison.OrdinalIgnoreCase) < 0) continue;
            var hex = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
                .LastOrDefault(t => t.Length >= 32 && t.All(Uri.IsHexDigit));
            if (hex is not null) return hex.ToLowerInvariant();
        }
        return "";
    }

    // certutil -hashfile prints the digest on its own line (often space-grouped) between a header and a footer
    // line; pick the first all-hex line once spaces are stripped.
    private static string ExtractCertutilHash(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Replace(" ", ""))
            .FirstOrDefault(l => l.Length >= 32 && l.All(Uri.IsHexDigit))?.ToLowerInvariant() ?? "";
    #endregion

    #region Engagement scope
    /// <summary>The authorization under which offensive tools may act on this environment. Null until an
    /// engagement is registered; while null the gate is fail-closed and <see cref="FailIfOutOfScope"/>
    /// refuses everything. Mirrors <see cref="CaseEvidence"/> on the blue side.</summary>
    protected EngagementInfo? Engagement { get; private set; }

    // Set once TrySetEngagement succeeds. The engagement is write-once per environment (i.e. per session), so
    // the scope gate can't be silently widened mid-engagement — exactly like the evidence guard.
    private bool engagementRegistered;

    /// <summary>True once an engagement has been registered for this environment/session.</summary>
    public bool EngagementRegistered => engagementRegistered;

    /// <summary>The registered engagement authorization, or null when none is set. Read-only — register via
    /// <see cref="TrySetEngagement"/>. Lets the <c>EngagementStatus</c> tool report the active scope/window.</summary>
    public EngagementInfo? RegisteredEngagement => Engagement;

    /// <summary>
    /// Registers the engagement authorization for this environment — once. Returns true if accepted; false if
    /// an engagement was already registered (write-once per session, exactly like evidence, so the scope gate
    /// can't be silently widened mid-engagement). The caller (the <c>SetEngagement</c> tool) audits a refused
    /// second attempt as a scope-violation event.
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

    /// <summary>
    /// Decides whether an entire range (a CIDR) may be SWEPT — used by host-discovery operations whose target is a
    /// network, not a single host. Authorized when the requested range is fully contained in an authorized
    /// <see cref="ScopeKind.Cidr"/> inclusion, the validity window is open, and the range is not wholly contained
    /// in a Cidr exclusion. A carve-out that only *partially* overlaps the range does not refuse the sweep: the
    /// individual hosts a sweep discovers are still checked per-host with <see cref="EvaluateScope"/>, so an
    /// excluded host inside an authorized range is dropped from the results rather than blocking the whole sweep.
    /// </summary>
    public ScopeDecision EvaluateRangeScope(string cidr)
    {
        if (Engagement is null)
            return new ScopeDecision(cidr, false, "No engagement registered (fail-closed).");
        if (!Engagement.IsWithinWindow(DateTime.UtcNow))
            return new ScopeDecision(cidr, false,
                $"Outside the authorized window ({Engagement.ValidFromUtc:u} – {Engagement.ValidUntilUtc:u}).");
        var excl = Engagement.Excluded.FirstOrDefault(t => t.Kind == ScopeKind.Cidr && CidrContainsCidr(t.Value, cidr));
        if (excl is not null)
            return new ScopeDecision(cidr, false, $"The range is wholly excluded by {excl.Kind} {excl.Value}.");
        var incl = Engagement.Included.FirstOrDefault(t => t.Kind == ScopeKind.Cidr && CidrContainsCidr(t.Value, cidr));
        return incl is not null
            ? new ScopeDecision(cidr, true, $"Authorized by Cidr {incl.Value} (RoE {Engagement.RulesOfEngagementRef}).")
            : new ScopeDecision(cidr, false, "No authorized CIDR fully contains this range.");
    }

    /// <summary>
    /// Refuses a range/host-discovery sweep whose CIDR is not fully within an authorized range by throwing
    /// <see cref="OutOfScopeException"/> (or <see cref="EngagementRequiredException"/> when nothing is
    /// registered). The range-level counterpart of <see cref="FailIfOutOfScope"/>; call it before sweeping, then
    /// still gate each discovered host with the per-host check so excluded carve-outs inside the range are dropped.
    /// </summary>
    public void FailIfRangeOutOfScope(string cidr)
    {
        if (!engagementRegistered) throw new EngagementRequiredException();
        var decision = EvaluateRangeScope(cidr);
        if (!decision.InScope) throw new OutOfScopeException(decision);
    }

    /// <summary>True when an engagement is registered AND it permits disclosing client targets to external
    /// services (see <see cref="EngagementInfo.AllowExternalTargetDisclosure"/>). Target-keyed knowledge-base
    /// facades consult this before sending a client asset to a third party.</summary>
    public bool ExternalDisclosureAllowed => engagementRegistered && Engagement is { AllowExternalTargetDisclosure: true };

    /// <summary>
    /// Refuses a target-keyed external query (one that would send a client asset to a third-party intelligence
    /// service) unless the registered engagement permits external disclosure — throwing
    /// <see cref="ExternalDisclosureForbiddenException"/> (or <see cref="EngagementRequiredException"/> when nothing
    /// is registered). Call it from a target-keyed KB facade (e.g. Shodan) alongside <see cref="FailIfOutOfScope"/>.
    /// </summary>
    public void FailIfExternalDisclosureForbidden()
    {
        if (!engagementRegistered) throw new EngagementRequiredException();
        if (!ExternalDisclosureAllowed) throw new ExternalDisclosureForbiddenException();
    }

    /// <summary>True when an engagement is registered and it permits <paramref name="activity"/> (a baseline class
    /// or one in its <see cref="EngagementInfo.AllowedActivities"/>). The activity-class counterpart of
    /// <see cref="EvaluateScope"/>: scope answers "where", this answers "what".</summary>
    public bool IsActivityAllowed(ActivityClass activity) =>
        engagementRegistered && Engagement is not null && Engagement.IsActivityAllowed(activity);

    /// <summary>
    /// Refuses an offensive operation whose <paramref name="activity"/> class the registered engagement does not
    /// authorize — throwing <see cref="ActivityNotAuthorizedException"/> (or <see cref="EngagementRequiredException"/>
    /// when nothing is registered). The activity-class counterpart of <see cref="FailIfOutOfScope"/>; call it from an
    /// offensive toolkit method (via <c>OffensiveToolkit.GuardActivity</c>) before acting.
    /// </summary>
    public void FailIfActivityNotAuthorized(ActivityClass activity)
    {
        if (!engagementRegistered) throw new EngagementRequiredException();
        if (!IsActivityAllowed(activity)) throw new ActivityNotAuthorizedException(activity);
    }

    /// <summary>The server-configured default scan packet-rate cap (packets/sec), used when the registered
    /// engagement does not specify one. Set from <c>PenTest:DefaultMaxPacketRate</c> at
    /// <see cref="CreateFromConfig"/>; defaults to <see cref="EngagementThrottle.FallbackMaxPacketRate"/>.</summary>
    public int DefaultMaxPacketRate { get; set; } = EngagementThrottle.FallbackMaxPacketRate;

    /// <summary>The server-configured default cap on concurrently-acted-on targets, used when the engagement does
    /// not specify one. Set from <c>PenTest:DefaultMaxConcurrentTargets</c>; defaults to
    /// <see cref="EngagementThrottle.FallbackMaxConcurrentTargets"/>.</summary>
    public int DefaultMaxConcurrentTargets { get; set; } = EngagementThrottle.FallbackMaxConcurrentTargets;

    /// <summary>
    /// Resolves the effective intensity caps an offensive operation runs under: each cap is the engagement's value
    /// when it specified one, else the server's configured default (fail-safe — never uncapped). The returned
    /// <see cref="EngagementThrottle"/> also records, per cap, whether it came from the engagement or the default,
    /// so the toolkits can apply it and the report can state it.
    /// </summary>
    public EngagementThrottle EffectiveThrottle()
    {
        var e = Engagement;
        bool rateFromEng = e?.MaxPacketRate is > 0;
        bool concFromEng = e?.MaxConcurrentTargets is > 0;
        return new EngagementThrottle(
            rateFromEng ? e!.MaxPacketRate!.Value : DefaultMaxPacketRate,
            concFromEng ? e!.MaxConcurrentTargets!.Value : DefaultMaxConcurrentTargets,
            rateFromEng, concFromEng);
    }

    /// <summary>
    /// Preflight a proposed engagement before registering it: every scope entry must parse and the window must
    /// be non-empty and not already in the past. The <c>SetEngagement</c> tool refuses registration when this is
    /// not <see cref="EngagementSummary.Valid"/>, so the gate is never armed with an unparseable or already-expired
    /// authorization.
    /// </summary>
    public EngagementSummary ValidateEngagement(EngagementInfo e)
    {
        var problems = new List<string>();
        if (e is null) return new EngagementSummary(false, ["No engagement supplied."]);
        if (e.ValidUntilUtc <= e.ValidFromUtc) problems.Add("Validity window is empty or inverted.");
        if (e.ValidUntilUtc < DateTime.UtcNow)  problems.Add("Validity window is already in the past.");
        if (!e.Included.Any())                  problems.Add("No in-scope targets — nothing would be authorized.");
        foreach (var t in e.Scope ?? Array.Empty<ScopeTarget>())
            if (!ScopeEntryParses(t)) problems.Add($"Unparseable scope entry: {t.Kind} '{t.Value}'.");
        if (e.TestingHours is { } th) problems.AddRange(th.Problems());   // refuse a malformed testing-hours window
        return new EngagementSummary(problems.Count == 0, problems.ToArray());
    }

    /// <summary>
    /// Classify an in-scope target by ownership <see cref="AddressTier"/>: an IP literal is classified directly; a
    /// CIDR by its network address; a hostname / domain / URL host is resolved via DNS and classified by the
    /// most-restrictive resolved address. A name that does not resolve is treated as <see cref="AddressTier.Public"/>
    /// (conservative — an unknown target gets the strongest proof requirement). This is the one piece of the
    /// tiering that does I/O; the pure mapping lives in <see cref="EngagementAuthorization"/>.
    /// </summary>
    public AddressTier ClassifyTier(ScopeTarget t)
    {
        if (t.Kind == ScopeKind.Cidr)
        {
            var addr = t.Value.Split('/', 2)[0];
            return IPAddress.TryParse(addr, out var nip) ? EngagementAuthorization.ClassifyIp(nip) : AddressTier.Public;
        }
        var host = HostOf(t.Value);
        if (IPAddress.TryParse(host, out var ip)) return EngagementAuthorization.ClassifyIp(ip);
        var resolved = ResolveHostAddresses(host);
        return resolved.Length == 0
            ? AddressTier.Public                                                   // unresolvable ⇒ treat as public
            : resolved.Select(EngagementAuthorization.ClassifyIp).Max();           // most-restrictive resolved tier
    }

    // DNS resolution for tier classification; returns empty on any failure (offline, NXDOMAIN, malformed) so the
    // caller treats an unresolvable name as Public — fail-closed toward the strongest proof requirement.
    private static IPAddress[] ResolveHostAddresses(string host)
    {
        try { return System.Net.Dns.GetHostAddresses(host); } catch { return Array.Empty<IPAddress>(); }
    }

    /// <summary>
    /// Evaluate the proof of authorization for every in-scope entry against the engagement's posture, documents,
    /// and waiver: each entry's <see cref="AddressTier"/> selects a <see cref="ProofRequirement"/>, satisfied by
    /// self-attestation, an authorizing document, or (private targets under <see cref="EngagementPosture.Internal"/>
    /// only) an explicit waiver. The <c>SetEngagement</c> tool refuses registration when the result is not
    /// <see cref="EngagementAuthorizationResult.Valid"/> — the public-IP hard gate — and audits each waived entry.
    /// </summary>
    public EngagementAuthorizationResult EvaluateEngagementAuthorization(EngagementInfo e)
    {
        var hasDoc = e.HasAuthorizingDocument;
        var hasWaiver = e.HasInternalWaiver;
        var decisions = e.Included.Select(t =>
        {
            var tier = ClassifyTier(t);
            var required = EngagementAuthorization.RequiredProof(e.Posture, tier);
            return required switch
            {
                ProofRequirement.SelfAttested =>
                    new ScopeAuthorizationDecision(t, tier, required, true, "self", null),
                ProofRequirement.DocumentRequired when hasDoc =>
                    new ScopeAuthorizationDecision(t, tier, required, true, "document", null),
                ProofRequirement.DocumentRequired =>
                    new ScopeAuthorizationDecision(t, tier, required, false, "",
                        $"Scope entry {t.Kind} {t.Value} is {tier}: an authorizing document " +
                        "(RulesOfEngagement / AuthorizationLetter / Contract) is required. Add one to documents, " +
                        "or remove the entry."),
                ProofRequirement.DocumentOrWaiver when hasDoc =>
                    new ScopeAuthorizationDecision(t, tier, required, true, "document", null),
                ProofRequirement.DocumentOrWaiver when hasWaiver =>
                    new ScopeAuthorizationDecision(t, tier, required, true, "waiver", null),
                _ =>
                    new ScopeAuthorizationDecision(t, tier, required, false, "",
                        $"Scope entry {t.Kind} {t.Value} is {tier}: supply an authorizing document, or set " +
                        "internalAuthorizationWaiver with the reason authorization exists for this internal target."),
            };
        }).ToArray();
        return new EngagementAuthorizationResult(decisions.All(d => d.Satisfied), decisions);
    }

    // host == exact (case-insensitive); cidr == IP containment; domain == suffix match incl. subdomains;
    // url == host-of-url containment against the rule. Kept private so inclusion/exclusion use identical rules.
    private static bool Matches(ScopeTarget rule, string target) => rule.Kind switch
    {
        ScopeKind.Host   => string.Equals(HostOf(rule.Value), HostOf(target), StringComparison.OrdinalIgnoreCase),
        ScopeKind.Cidr   => IpInCidr(HostOf(target), rule.Value),
        ScopeKind.Domain => DomainMatches(rule.Value, HostOf(target)),
        ScopeKind.Url    => string.Equals(HostOf(target), HostOf(rule.Value), StringComparison.OrdinalIgnoreCase),
        _ => false
    };

    // A domain rule matches the host itself and any subdomain of it (lab.local matches lab.local and a.lab.local,
    // but not evillab.local) — anchored on a dot boundary so a suffix can't straddle a label.
    private static bool DomainMatches(string domain, string host)
    {
        domain = domain.Trim('.').ToLowerInvariant();
        host = host.Trim('.').ToLowerInvariant();
        return host == domain || host.EndsWith("." + domain, StringComparison.Ordinal);
    }

    // Strips scheme/userinfo/port/path from a URL or bare host, leaving just the host (or the literal IP). Falls
    // back to the trimmed input when it is not a parseable URL (e.g. a bare hostname or IP).
    private static string HostOf(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        value = value.Trim();
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
            return uri.Host;
        // No scheme: drop any path and any :port so "host:8080/x" → "host". Leave bracketed IPv6 literals intact.
        var slash = value.IndexOf('/');
        if (slash >= 0) value = value[..slash];
        var colon = value.LastIndexOf(':');
        if (colon > 0 && !value.Contains(']') && value.IndexOf(':') == colon) value = value[..colon];
        return value;
    }

    // True when IP address <paramref name="target"/> falls inside CIDR <paramref name="cidr"/> (IPv4 or IPv6).
    // A non-IP target (a hostname not yet resolved) or a malformed CIDR yields false rather than throwing — the
    // caller treats "no match" as out-of-scope, which is the safe (fail-closed) direction.
    private static bool IpInCidr(string target, string cidr)
    {
        var parts = cidr.Split('/', 2);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network)
            || !IPAddress.TryParse(target, out var ip) || !int.TryParse(parts[1], out var prefix))
            return false;
        if (network.AddressFamily != ip.AddressFamily) return false;

        var netBytes = network.GetAddressBytes();
        var ipBytes = ip.GetAddressBytes();
        if (prefix < 0 || prefix > netBytes.Length * 8) return false;

        int fullBytes = prefix / 8, remBits = prefix % 8;
        for (int i = 0; i < fullBytes; i++)
            if (netBytes[i] != ipBytes[i]) return false;
        if (remBits == 0) return true;
        int mask = (byte)(0xFF << (8 - remBits));
        return (netBytes[fullBytes] & mask) == (ipBytes[fullBytes] & mask);
    }

    // True when CIDR <paramref name="inner"/> is entirely contained within CIDR <paramref name="outer"/>: the
    // outer prefix must be no longer than the inner one (a smaller/longer-prefix outer can't hold a bigger inner),
    // and inner's network address must fall inside outer. Malformed input yields false (fail-closed). Used to
    // authorize a range sweep against a broader authorized range (cidr-contained-in-cidr).
    private static bool CidrContainsCidr(string outer, string inner)
    {
        var i = inner.Split('/', 2);
        var o = outer.Split('/', 2);
        if (i.Length != 2 || o.Length != 2
            || !int.TryParse(i[1], out var innerPrefix) || !int.TryParse(o[1], out var outerPrefix))
            return false;
        if (outerPrefix > innerPrefix) return false;
        return IpInCidr(i[0], outer);   // inner's network address must lie within outer (same-family check inside)
    }

    // A scope entry parses when its Value is well-formed for its Kind: a CIDR splits into a valid address +
    // prefix; a Url is an absolute URL; Host/Domain just need a non-empty value.
    private static bool ScopeEntryParses(ScopeTarget t) => t.Kind switch
    {
        _ when string.IsNullOrWhiteSpace(t.Value) => false,
        ScopeKind.Cidr => t.Value.Split('/', 2) is [var addr, var pfx]
                          && IPAddress.TryParse(addr, out var a) && int.TryParse(pfx, out var p)
                          && p >= 0 && p <= a.GetAddressBytes().Length * 8,
        ScopeKind.Url  => Uri.TryCreate(t.Value, UriKind.Absolute, out _),
        _ => true
    };
    #endregion

    #region Methods
    public bool ExecuteCommand(string command, string arguments, out string output, bool admin = false)
    {
        string process_output = "", process_error = "";
        CommandResult? r;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        if (admin)
        {
            if (this.IsUnix)
            {
                r = this.Execute("sudo", command + " " + arguments);
            }
            else throw new NotImplementedException("ExecuteCommandAsAdmin is not implemented for Windows environments.");
        }
        else
        {
            r = this.Execute(command, arguments);
        }
        sw.Stop();
        // Audit the synchronous command path too (cleanup/plumbing and any sync tool call), so the per-case trail
        // is complete. Ambient case/execution/toolkit context is supplied from the log context as in the async path.
        AuditCommand(AuditHostName, command, arguments, admin, r.ExitCode, sw.ElapsedMilliseconds, r.IsCompleted);
        process_output = r.StdOut;
        process_error = r.StdErr;
        if (r.Status == ProcessExecuteStatus.Completed)
        {
            output = process_output.Trim();
            Debug("The command {0} {1} executed successfully. Output: {2}", command, arguments, output);
            return true;
        }
        else
        {
            output = process_output + process_error.Trim();            
            return false;
        }
    }

    public async Task<CommandResult> ExecuteCommandAsync(string command, string arguments, bool admin = false)
    {
        // Concurrency limiting is enforced in ExecuteAsync (the primitive both this wrapper and any direct
        // caller funnel through), so it is intentionally not applied here to avoid acquiring twice.
        CommandResult? r;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        if (admin)
        {
            if (this.IsUnix)
            {
                r = await this.ExecuteAsync("sudo", command + " " + arguments);
            }
            else throw new NotImplementedException("ExecuteCommandAsAdmin is not implemented for Windows environments.");
        }
        else
        {
            r = await this.ExecuteAsync(command, arguments);
        }
        sw.Stop();
        // Record this command in the per-case audit trail. CaseId/ExecutionId/Toolkit/Operation/Workflow are
        // enriched ambiently from the log context, so this single chokepoint ties every tool execution to the
        // case and agent step that drove it — the row a judge traces a finding back to.
        AuditCommand(AuditHostName, command, arguments, admin, r.ExitCode, sw.ElapsedMilliseconds, r.IsCompleted);
        if (r.Status == ProcessExecuteStatus.Completed)
        {
            Debug("The command {0} {1} executed successfully. Output: {2}", command, arguments, r.Output);
        }
        else
        {
            Debug("The command {0} {1} did not execute successfully. Output: {2}", command, arguments, r.Output);
        }
        return r;
    }

    /// <summary>
    /// The host name recorded in the audit trail for commands run on this environment. The base (local)
    /// environment reports the machine name; the SSH environment overrides this with the remote host.
    /// </summary>
    protected virtual string AuditHostName => System.Environment.MachineName;

    public virtual string GetOSName()
    {
        if (!string.IsNullOrEmpty(this.OSName)) return this.OSName;
        CallerInformation here = Here();
        string cmd = "", args = "";
        if (this.IsUnix)
        {
            cmd = "cat";
            args = "/etc/*release";
            string output;
            if (this.ExecuteCommand(cmd, args, out output, false) || !string.IsNullOrEmpty(output))
            {
                if (output.ToLower().Contains("ubuntu"))
                {
                    this.OSName = "ubuntu";
                }
                else if (output.ToLower().Contains("debian"))
                {
                    this.OSName = "debian";
                }
                else if (output.ToLower().Contains("centos"))
                {
                    this.OSName = "centos";
                }
                else if (output.ToLower().Contains("suse linux"))
                {
                    this.OSName = "suse";
                }
                else if (output.ToLower().Contains("red hat enterprise linux"))
                {
                    this.OSName = "rhel";
                }
                else if (output.ToLower().Contains("oracle linux server"))
                {
                    this.OSName = "oraclelinux";
                }
            }
            if (string.IsNullOrEmpty(this.OSName))
            {
                cmd = "lsb_release";
                args = "-a";
                if (this.ExecuteCommand(cmd, args, out output, false))
                {
                    if (output.ToLower().Contains("ubuntu"))
                    {
                        this.OSName = "ubuntu";
                    }
                    else if (output.ToLower().Contains("debian"))
                    {
                        this.OSName = "debian";
                    }
                    else if (output.ToLower().Contains("centos"))
                    {
                        this.OSName = "centos";
                    }
                    else if (output.ToLower().Contains("suse linux"))
                    {
                        this.OSName = "suse";
                    }
                    else if (output.ToLower().Contains("oracle linux"))
                    {
                        this.OSName = "oracle";
                    }

                    else if (output.ToLower().Contains("red hat enterprise linux"))
                    {
                        this.OSName = "rhel";
                    }
                }
                if (string.IsNullOrEmpty(this.OSName))
                {
                    cmd = "stat";
                    args = "/etc/oracle-release";
                    if (this.ExecuteCommand(cmd, args, out output, false))
                    {
                        this.OSName = "oraclelinux";
                    }
                    else
                    {
                        cmd = "stat";
                        args = "/etc/centos-release";
                        if (this.ExecuteCommand(cmd, args, out output, false))
                        {
                            this.OSName = "centos";
                        }
                        else
                        {
                            cmd = "stat";
                            args = "/etc/redhat-release";
                            if (this.ExecuteCommand(cmd, args, out output, false))
                            {
                                this.OSName = "rhel";
                            }
                            else
                            {
                                Error("GetOSName() failed.");
                            }
                        }
                    }
                }
            }
            if (!string.IsNullOrEmpty(this.OSName))
            {
                Success("Detected operating system of environment is {0}.", this.OSName);
            }
            else
            {
                Warning("GetOSName() failed. Falling back to unix");
                this.OSName = "unix";
            }

        }
        return this.OSName;
    }

    public virtual string GetOSVersion()
    {
        if (!string.IsNullOrEmpty(this.OSVersion)) return this.OSVersion;
        CallerInformation here = Here();
        string cmd = "", args = "", version = "";
        if (this.IsUnix)
        {
            if (this.OSName == "ubuntu")
            {
                cmd = "lsb_release";
                args = "-sr ";
                string output;
                if (this.ExecuteCommand(cmd, args, out output, false))
                {
                    version = output;
                    Debug(here, "GetOSVersion() returned {0}.", version);
                }
                else
                {
                    cmd = "bash";
                    args = "-c \"cat /etc/*release | grep -m 1 DISTRIB_RELEASE | cut -d '=\' -f2 && test \\${PIPESTATUS[0]} -eq 0\"";
                    if (this.ExecuteCommand(cmd, args, out output, false) && !string.IsNullOrEmpty(output))
                    {
                        version = output.Replace("Release:\t", string.Empty);
                        Debug(here, "GetOSVersion() returned {0}.", version);
                    }
                    else
                    {
                        Error("GetOSVersion() failed.");
                    }
                }

            }
            else if (this.OSName == "debian")
            {
                cmd = "cat";
                args = "/etc/debian_version";
                string output;
                if (this.ExecuteCommand(cmd, args, out output))
                {
                    version = output.Trim();
                    Debug(here, "GetOSVersion() returned {0}.", version);
                }
                else
                {
                    Error("GetOSVersion() failed.");
                }
            }
            else if (this.OSName == "centos")
            {
                cmd = "bash";
                args = "-c \"cat /etc/centos-release | cut -d' ' -f4 && test \\${PIPESTATUS[0]} -eq 0\"";
                string output;
                if (this.ExecuteCommand(cmd, args, out output, false))
                {
                    version = output.Trim();
                    Debug(here, "GetOSVersion() returned {0}.", version);
                }
                else
                {
                    cmd = "awk";
                    args = "'NR==1{print $3}' /etc/issue";
                    if (this.ExecuteCommand(cmd, args, out output, false))
                    {
                        version = output.Trim();
                        Debug(here, "GetOSVersion() returned {0}.", version);
                    }
                    else
                    {
                        Error("GetOSVersion() failed.");
                    }
                }
            }
            else if (this.OSName == "oraclelinux")
            {
                string output;
                cmd = "cat";
                args = "/etc/oracle-release";
                if (this.ExecuteCommand(cmd, args, out output, false) && !string.IsNullOrEmpty(output))
                {
                    version = output.Replace("Oracle Linux Server release ", string.Empty).Split('.').FirstOrDefault();
                }
                else
                {
                    Error("GetOSVersion() failed.");
                }
            }
            if (!string.IsNullOrEmpty(version))
            {
                this.OSVersion = version;
                Success("Detected operating system version of environment is {0}.", this.OSVersion);
            }
        }
        return this.OSVersion;
    }

    public virtual string OSExec(string command, string args)
    {
        CallerInformation here = Here();
        args = args + " 2>/dev/null";
        string output;
        if (this.ExecuteCommand(command, args, out output, false))
        {
            Debug("OSExec({0}, {1}) returned zero exit-code with stdout: {2}", command, args, output);
            return output;
        }
        else if (!string.IsNullOrEmpty(output))
        {
            Debug("OSExec({0}, {1}) returned non-zero exit-code with stdout: {2}", command, args, output);
            return output;
        }
        else
        {
            Debug("OSExec({0}, {1}) returned non-zero exit-code.", command, args);
            return string.Empty;
        }

    }

    public virtual string GetEnvironmentVar(string name)
    {
        CallerInformation here = Here();
        string var = "", cmd = "", args = "";
        if (this.IsWindows)
        {
            var = "%" + name + "%";
            cmd = "powershell";
            args = "(Get-Childitem env:" + name + ").Value";
        }
        else
        {
            var = "$" + name;
            cmd = "echo";
            args = var;
        }
        string output;
        if (this.ExecuteCommand(cmd, args, out output))
        {
            Debug(here, "GetEnvironmentVar({0}) returned {1}.", name, output);
            return output;
        }
        else
        {
            Error("GetEnvironmentVar({0}) failed.", var);
            return string.Empty;
        }
    }


    public virtual string GetUnixFileMode(string path, [CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        CallerInformation here = Here();
        if (this.IsWindows)
        {
            Error(here, "This method is not implemented in a Windows environment.");
            return string.Empty;
        }
        else
        {
            string output;
            if (this.ExecuteCommand("find", string.Format("{0} -prune -printf '%m'", path), out output))
            {
                Debug(here, "GetUnixFileMode({0}) returned {1}.", path, output);
                return output;
            }
            else
            {
                Debug(here, "Did not successfully execute GetUnixFileMode({0}).", path);
                return string.Empty;
            }
        }
    }

    public virtual string FindFiles(string path, string pattern, [CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        if (this.IsUnix)
        {
            CallerInformation here = Here();
            string output;
            string cmd = "find";
            string args = string.Format("{0} -name {1} -type f", path, pattern);
            if (this.ExecuteCommand(cmd, args, out output, false))
            {
                Debug(here, "FindFiles({0}, {1}) returned {2}.", path, pattern, output);
                return output;
            }
            else
            {
                string[] error = output.Split(this.LineTerminator.ToCharArray());
                if (error.All(e => e.EndsWith("Permission denied")))
                {
                    Debug(here, "FindFiles({0}, {1}) returned empty.", path, pattern);
                    return string.Empty;
                }
                else
                {
                    Error(here, "Did not successfully execute FindFiles({0}, {1}). Error: {2}.)", path, pattern, output);
                    return string.Empty;
                }
            }
                
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    public virtual string FindDirectories(string path, string pattern, [CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        if (this.IsUnix)
        {
            CallerInformation here = Here();
            string output;
            string cmd = "find";
            string args = string.Format("{0} -name {1} -type d", path, pattern);
            if (this.ExecuteCommand(cmd, args, out output, false))
            {
                Debug(here, "FindDirectories({0}, {1}) returned {2}", path, pattern, output);
                return output;
            }
            else
            {
                Error(here, "Did not successfully execute FindDirectories({0}, {1}). Error: {2}.)", path, pattern, output);
                return string.Empty;
            }

        }
        else
        {
            throw new NotSupportedException();
        }
    }

    public bool GetIsSymbolicLink(string f)
    {
        if (this.IsUnix)
        {
            string output;
            if (this.ExecuteCommand("stat", f, out output))
            {
                if (output.Contains("symbolic link"))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                this.Error("Did not successfully execute GetIsSymbolicLink({0}).", f);
                return false;
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    public string GetSymbolicLinkLocation(string f)
    {
        if (this.IsUnix)
        {
            string output;
            if (this.ExecuteCommand("ls", "-l " + f, out output))
            {
                if (output.Contains("->"))
                {
                    string l = output.Substring(output.IndexOf("->")).Trim();
                    Debug("GetSymbolicLinkLocation({0}) returned {1}.", f, l);
                    return l ;
                }
                else
                {
                    Debug("GetSymbolicLinkLocation({0}) returned null.", f);
                    return string.Empty;
                }
            }
            else
            {
                this.Error("Did not successfully execute GetSymbolicLinkLocation({0}).");
                return string.Empty;
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }
    public virtual List<ProcessInfo> GetAllRunningProcesses()
    {
        if (this.OSProcesses != null)
        {
            return this.OSProcesses;
        }
        if (this.IsUnix)
        {
            string output;
            if (this.ExecuteCommand("ps", "-eo uname,pid,start_time,args", out output, false))
            {
                string[] lines = output.Split('\n');
                if (!lines[0].StartsWith("USER"))
                {
                    this.Error("Could not parse output of ps command.");
                    return null;
                }
                List<ProcessInfo> p = new List<ProcessInfo>(lines.Length - 1);
                for (int i = 1; i < lines.Length; i++)
                {
                    string[] ps = Regex.Split(lines[i], @"\s+");
                    string u = ps[0];
                    string pid = ps[1];
                    string t = ps[2];
                    string c = string.Empty;
                    for (int j = 3; j < ps.Length; j++)
                    {
                        c = c + ps[j] + " ";
                    }
                    p.Add(new ProcessInfo(ps[0], int.Parse(ps[1]), ps[2], c.Trim()));
                }
                return this.OSProcesses = p;
            }
            else
            {
                this.Warning("Could not get running processes in environment.");
                this.Debug("Could not get running processes. Error: {0}", output);
                return this.OSProcesses = new List<ProcessInfo>();
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    public virtual Dictionary<string, string> GetEnvironmentVars()
    {
        if (this.OSEnvironmentVars != null)
        {
            return this.OSEnvironmentVars;
        }

        if (this.IsUnix)
        {
            string output;
            if (this.ExecuteCommand("printenv", string.Empty, out output))
            {
                string[] lines = output.Split('\n');
                
                Dictionary<string, string> vars = new Dictionary<string, string>(lines.Length);
                for (int i = 0; i < lines.Length; i++)
                {
                    string[] var = Regex.Split(lines[i], @"=");
                    vars.Add(var[0].Trim(), var[1].Trim());
                }
                return this.OSEnvironmentVars = vars;
            }
            else
            {
                this.Error("Could not get environment variables. Error: {0}", output);
                return null;
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }
    public string GetTimestamp()
    {
        return (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds.ToString();
    }

    public SecureString ToSecureString(string s)
    {
        SecureString r = new SecureString();
        foreach (char c in s)
        {
            r.AppendChar(c);
        }
        r.MakeReadOnly();
        return r;
    }

    public string ToInsecureString(object o)
    {
        SecureString s = o as SecureString;
        if (s == null) throw new ArgumentException("Object is not of type SecureString.", "o");
        string r = string.Empty;
        IntPtr ptr = Marshal.SecureStringToBSTR(s);
        try
        {
            r = Marshal.PtrToStringBSTR(ptr);
        }
        finally
        {
            Marshal.ZeroFreeBSTR(ptr);
        }
        return r;
    }

    [DebuggerStepThrough]
    internal void Message(EventMessageType message_type, string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(message_type, message_format, message));
    }

    [DebuggerStepThrough]
    internal new void Info(string message_format, params object[] message)
    {
        TraceSource.TraceInformation(message_format, message);
        OnMessage(new EnvironmentEventArgs(EventMessageType.INFO, message_format, message));
    }

    [DebuggerStepThrough]
    internal new void Error(string message_format, params object[] message)
    {
        TraceSource.TraceEvent(TraceEventType.Error, 0, message_format, message);
        OnMessage(new EnvironmentEventArgs(EventMessageType.ERROR, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Error(CallerInformation caller, string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(caller, EventMessageType.ERROR, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Error(Exception e)
    {
        OnMessage(new EnvironmentEventArgs(e));
    }

    [DebuggerStepThrough]
    internal void Error(CallerInformation caller, Exception e)
    {
        OnMessage(new EnvironmentEventArgs(caller, e));
    }

    [DebuggerStepThrough]
    internal void Error(Exception e, string message_format, params object[] message)
    {
        Error(message_format, message);
        Error(e);
    }

    [DebuggerStepThrough]
    internal void Error(CallerInformation caller, Exception e, string message_format, params object[] message)
    {
        Error(message_format, message);
        Error(caller, e);
    }

    [DebuggerStepThrough]
    internal void Error(AggregateException ae)
    {
        if (ae.InnerExceptions != null && ae.InnerExceptions.Count >= 1)
        {
            foreach (Exception e in ae.InnerExceptions)
            {
                Error(e);
            }
        }
    }
    

    [DebuggerStepThrough]
    internal void Error(AggregateException ae, string message_format, params object[] message)
    {
        Error(message_format, message);
        Error(ae);
    }

    [DebuggerStepThrough]
    internal void Error(CallerInformation caller, AggregateException ae, string message_format, params object[] message)
    {
        Error(caller, message_format, message);
        if (ae.InnerExceptions != null && ae.InnerExceptions.Count >= 1)
        {
            foreach (Exception e in ae.InnerExceptions)
            {
                Error(caller, e);
            }
        }
    }

    [DebuggerStepThrough]
    internal void Success(string message_format, params object[] message)
    {
        TraceSource.TraceEvent(TraceEventType.Information, 0, message_format, message);
        OnMessage(new EnvironmentEventArgs(EventMessageType.SUCCESS, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Warning(string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(EventMessageType.WARNING, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Status(string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(EventMessageType.STATUS, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Progress(string operation, int total, int complete, TimeSpan? time = null)
    {
        OnMessage(new EnvironmentEventArgs(new OperationProgress(operation, total, complete, time)));
    }

    [DebuggerStepThrough]
    internal void Debug(CallerInformation caller, string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(caller, EventMessageType.DEBUG, message_format, message));
    }

    [DebuggerStepThrough]
    internal new void Debug(string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(EventMessageType.DEBUG, message_format, message));
    }

    internal CallerInformation Here([CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        CallerInformation c;
        c.Name = memberName;
        c.File = fileName;
        c.LineNumber = lineNumber;
        return c;
    }

    public static void DefaultEnvironmentMessageHandler(object? sender, EnvironmentEventArgs e)
    {

        if (e.MessageType == EventMessageType.DEBUG)
        {
            Runtime.Debug(e.Message);
        }
        else if (e.MessageType == EventMessageType.ERROR)
        {
            if (e.Exception != null)
            {
                Runtime.Error(e.Exception, e.Message);
            }
            else
            {

                Runtime.Error(e.Message);

            }
        }
        else
        {
            Runtime.Info(e.Message);
        }
    }

    public static AuditEnvironment CreateFromConfig(IConfigurationRoot config)
    {
        // The active platform names the config profile holding this box's connection details (SIFT / Kali /
        // PTF / …); it defaults to SIFT so existing single-distro configs read exactly as before.
        var platform = config["Platform"] ?? "SIFT";
        var environmentType = Enum.Parse<EnvironmentType>(GetRequiredValue(config, $"{platform}:Environment"));
        // Optional cap on concurrent async executions (0/absent = unlimited).
        int maxConcurrent = int.TryParse(config[$"{platform}:MaxConcurrentExecutions"], out var n) ? n : 0;
        // Offensive intensity defaults (fail-safe, used when an engagement does not specify its own caps). Unlike
        // MaxConcurrentExecutions these are NOT platform-scoped — a packet rate is a property of the target network,
        // not the box we run from — so they live under a top-level PenTest section. Absent = built-in safe fallback.
        int defaultRate = int.TryParse(config["PenTest:DefaultMaxPacketRate"], out var r) ? r : EngagementThrottle.FallbackMaxPacketRate;
        int defaultConc = int.TryParse(config["PenTest:DefaultMaxConcurrentTargets"], out var c) ? c : EngagementThrottle.FallbackMaxConcurrentTargets;
        AuditEnvironment env;
        if (environmentType == EnvironmentType.Local)
        {
            env = new LocalEnvironment();
        }
        else if (environmentType == EnvironmentType.Ssh)
        {
            var host = GetRequiredValue(config, $"{platform}:Host");
            var port = Int32.Parse(GetRequiredValue(config, $"{platform}:Port"));
            var user = GetRequiredValue(config, $"{platform}:User");
            var password = GetRequiredValue(config, $"{platform}:Password");
            env = new SshAuditEnvironment("camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), new LocalEnvironment());
        }
        else throw new Exception($"Invalid environment type specified in configuration: {environmentType.ToString()}");
        env.MaxConcurrentExecutions = maxConcurrent;
        env.DefaultMaxPacketRate = defaultRate;
        env.DefaultMaxConcurrentTargets = defaultConc;
        return env;
    }
    #endregion

    #region Events
    public event EventHandler<EnvironmentEventArgs>? MessageHandler;

    protected virtual void OnMessage(EnvironmentEventArgs e) => MessageHandler?.Invoke(this, e);               
    #endregion

    #region Fields
    
    #endregion

    #region Disposer and Finalizer
    private bool IsDisposed { get; set; }
    /// <summary> 
    /// /// Implementation of Dispose according to .NET Framework Design Guidelines. 
    /// /// </summary> 
    /// /// <remarks>Do not make this method virtual. 
    /// /// A derived class should not be able to override this method. 
    /// /// </remarks>         
    public void Dispose()
    {
        Dispose(true); // This object will be cleaned up by the Dispose method. // Therefore, you should call GC.SupressFinalize to // take this object off the finalization queue // and prevent finalization code for this object // from executing a second time. // Always use SuppressFinalize() in case a subclass // of this type implements a finalizer. GC.SuppressFinalize(this); }
    }

    protected virtual void Dispose(bool isDisposing)
    {
        // TODO If you need thread safety, use a lock around these 
        // operations, as well as in your methods that use the resource. 
        try
        {
            if (!this.IsDisposed)
            {
                // Explicitly set root references to null to expressly tell the GarbageCollector 
                // that the resources have been disposed of and its ok to release the memory 
                // allocated for them. 
                if (isDisposing)
                {
                    // Release all managed resources here.
                    _executionLimiter?.Dispose();
                }
                // Release all unmanaged resources here 
                // (example) if (someComObject != null && Marshal.IsComObject(someComObject)) { Marshal.FinalReleaseComObject(someComObject); someComObject = null; 
            }
        }
        finally
        {
            this.IsDisposed = true;
        }
    }

    ~AuditEnvironment()
    {
        this.Dispose(false);
    }
    #endregion
}
