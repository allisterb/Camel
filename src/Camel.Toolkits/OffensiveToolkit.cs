using System.Collections.Generic;

using Camel.Environments;
using Microsoft.Extensions.Configuration;

namespace Camel.Toolkits;

/// <summary>
/// Base class for offensive (red-team) toolkits — recon, scanning, web-app testing, exploitation, etc.
/// Fail-closed: no wrapped tool runs until an engagement authorization has been registered on the
/// environment (via the <c>SetEngagement</c> MCP tool), and a method must clear each target through
/// <see cref="GuardTarget"/> before acting on it. This is the red-side counterpart of the
/// evidence-spoliation guard the DFIR toolkits rely on — see <c>docs/RedTeamEngagementGate.md</c>.
///
/// Two enforcement layers, mirroring the doc:
/// <list type="number">
/// <item><b>Chokepoint</b> — <see cref="OnBeforeExecute"/> refuses every tool execution when no engagement
/// is registered, so even a method that forgot step 2 cannot run an offensive command unauthorized.</item>
/// <item><b>Per-target</b> — <see cref="GuardTarget"/> checks the specific host/range/URL against the
/// engagement's scope and validity window where the target is known.</item>
/// </list>
/// </summary>
public abstract class OffensiveToolkit : Toolkit
{
    #region Constructors
    protected OffensiveToolkit(string name, AuditEnvironment env, IConfigurationRoot? config = null)
        : base(name, env, config) { }
    #endregion

    #region Methods
    /// <summary>
    /// Fail-closed chokepoint: every <c>ExecuteTool*</c> call routes through here first (see
    /// <see cref="Toolkit.OnBeforeExecute"/>), so an offensive command cannot run without a registered
    /// engagement. Throws <see cref="EngagementRequiredException"/> when none is armed.
    /// </summary>
    protected override void OnBeforeExecute(string toolName)
    {
        if (!auditEnvironment.EngagementRegistered) throw new EngagementRequiredException();
    }

    /// <summary>
    /// Refuses to act on <paramref name="target"/> (host / IP / CIDR / URL) unless the registered engagement
    /// authorizes it and the validity window is open — throwing <see cref="OutOfScopeException"/> otherwise
    /// (or <see cref="EngagementRequiredException"/> when nothing is registered). Call this at the start of
    /// every toolkit method, once per target, where the target is known. For a method that takes a target list
    /// or CIDR, call it for each entry so a single out-of-scope item is refused (see
    /// <see cref="GuardTargets"/>).
    /// </summary>
    protected void GuardTarget(string target) => auditEnvironment.FailIfOutOfScope(target);

    /// <summary>
    /// Clears every target in <paramref name="targets"/> through <see cref="GuardTarget"/>, so a single
    /// out-of-scope entry refuses the whole operation before any tool runs. Use for methods that accept a
    /// target list or expanded range.
    /// </summary>
    protected void GuardTargets(IEnumerable<string> targets)
    {
        foreach (var t in targets) GuardTarget(t);
    }
    #endregion
}
