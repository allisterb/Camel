using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Extensions.Configuration;

namespace Camel.Toolkits;

/// <summary>
/// One toolkit's tool availability on the active platform, computed from config alone (no toolkit is
/// constructed, so the check never triggers tool provisioning). <see cref="AvailableTools"/> counts the
/// tools in this toolkit's <c>{platform}:Tools:{Toolkit}</c> section that have a non-empty Command;
/// <see cref="ConfiguredTools"/> is how many entries that section declares.
/// </summary>
/// <param name="Toolkit">The toolkit's config-section name (e.g. "Scanning"), not its JS-global class name.</param>
/// <param name="AvailableTools">Tools with a runnable Command on the active platform.</param>
/// <param name="ConfiguredTools">Tool entries declared in the section (0 when the section is absent entirely).</param>
public record ToolkitCapability(string Toolkit, int AvailableTools, int ConfiguredTools)
{
    /// <summary>True when at least one of this toolkit's tools is runnable on the active platform.</summary>
    public bool Any => AvailableTools > 0;

    /// <summary>True when the toolkit has some but not all of its configured tools available (degraded).</summary>
    public bool Partial => AvailableTools > 0 && AvailableTools < ConfiguredTools;
}

/// <summary>
/// The launch-time capability report for an investigation on the active platform: per-toolkit tool
/// availability, computed from config. The server uses it to <b>refuse to start</b> when no toolkit has any
/// tool (e.g. a PenTest server pointed at a SIFT profile), and to <b>warn</b> when only some toolkits are
/// available (a legitimate degraded combo, e.g. DFIR on Kali). See <c>docs/PenTestEnvironments.md</c> part 1.
/// </summary>
/// <param name="Platform">The active platform the report was computed against.</param>
/// <param name="Toolkits">One <see cref="ToolkitCapability"/> per checked toolkit section, in order.</param>
public record PlatformCapabilityReport(string Platform, ToolkitCapability[] Toolkits)
{
    /// <summary>True when at least one checked toolkit has a runnable tool — i.e. the server can do something.</summary>
    public bool AnyAvailable => Toolkits.Any(t => t.Any);

    /// <summary>Toolkits with no runnable tool on this platform (a capability gap, named in the launch warning).</summary>
    public IEnumerable<ToolkitCapability> Unavailable => Toolkits.Where(t => !t.Any);

    /// <summary>Toolkits available only in part (some tools missing) — surfaced as a softer warning.</summary>
    public IEnumerable<ToolkitCapability> Degraded => Toolkits.Where(t => t.Partial);

    /// <summary>A one-line-per-toolkit human summary for the launch log.</summary>
    public string Summary() => string.Join(Environment.NewLine,
        Toolkits.Select(t => $"  {t.Toolkit}: {t.AvailableTools}/{t.ConfiguredTools} tools" +
                             (t.Any ? (t.Partial ? " (degraded)" : "") : " (UNAVAILABLE)")));

    /// <summary>The directive message printed when a server refuses to start because nothing is available.</summary>
    public string RefusalMessage(string investigation) =>
        $"Platform '{Platform}' has no {investigation} tools configured for any toolkit. " +
        $"Select a platform that has them (e.g. --platform kali|ptf|slingshot) or add a '{Platform}:Tools' " +
        $"section to the config.{Environment.NewLine}{Summary()}";
}

/// <summary>
/// Launch-time capability inspection: answers "does this investigation's toolkit set have any runnable tools
/// on the active platform?" purely from configuration, so it can run before the server serves a single request
/// and without constructing any toolkit (which would trigger tool installs). Mirrors the per-tool availability
/// the base <see cref="Toolkit"/> resolves at runtime, applying the same <c>{platform}:Tools:{name}</c> →
/// legacy <c>Tools:{name}</c> fallback.
/// </summary>
public static class PlatformCapability
{
    /// <summary>
    /// Computes the <see cref="PlatformCapabilityReport"/> for <paramref name="toolkitSections"/> (the config
    /// section names of the toolkits an investigation binds) against the active platform in
    /// <paramref name="config"/>.
    /// </summary>
    public static PlatformCapabilityReport Check(IConfigurationRoot config, IEnumerable<string> toolkitSections)
    {
        var platform = config["Platform"] ?? "SIFT";
        var results = toolkitSections.Select(name =>
        {
            // Same resolution order the base Toolkit uses: platform-scoped section first, legacy top-level fallback.
            var section = config.GetSection($"{platform}:Tools:{name}");
            if (!section.Exists()) section = config.GetSection($"Tools:{name}");
            var tools = section.GetChildren().ToArray();
            var available = tools.Count(t => !string.IsNullOrWhiteSpace(t["Command"]));
            return new ToolkitCapability(name, available, tools.Length);
        }).ToArray();
        return new PlatformCapabilityReport(platform, results);
    }
}
