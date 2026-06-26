using System.Collections.Generic;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

/// <summary>
/// Offline unit tests for the platform-aware tool config + graceful degradation in the base
/// <see cref="Toolkit"/> — no SIFT workstation needed. Uses an in-memory config and a LocalEnvironment;
/// UnixToolsToolkit is the vehicle because it needs no provisioning (its InstallMissingTools is a no-op), so
/// it can be constructed with a partial config without touching any environment.
/// </summary>
public class ToolAvailabilityTests
{
    static IConfigurationRoot Config(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Fact]
    public void MissingToolIsUnavailableNotAConstructionError()
    {
        // Only MD5Sum is defined; the rest of UnixTools' ToolList is omitted — the toolkit must still construct.
        var config = Config(new()
        {
            ["Tools:UnixTools:MD5Sum:Command"] = "/usr/bin/md5sum",
            ["Tools:UnixTools:MD5Sum:Description"] = "MD5",
        });

        var tk = new UnixToolsToolkit(new LocalEnvironment(), config);   // no throw, despite the missing tools

        Assert.True(tk.IsToolAvailable("MD5Sum"));
        Assert.True(tk.Tools["MD5Sum"].Available);
        Assert.False(tk.IsToolAvailable("Bunzip2"));        // present in ToolList, absent in config -> unavailable
        Assert.False(tk.Tools["Bunzip2"].Available);
        Assert.False(tk.IsToolAvailable("NotARealTool"));   // not in ToolList at all -> unavailable
    }

    [Fact]
    public void ExecuteToolOnUnavailableToolDegradesToNull()
    {
        var config = Config(new() { ["Tools:UnixTools:MD5Sum:Command"] = "/usr/bin/md5sum" });
        var tk = new UnixToolsToolkit(new LocalEnvironment(), config);

        // Bunzip2 has no command on this 'platform'; the guard must short-circuit to null without executing
        // anything (no command with an empty path is ever run).
        Assert.Null(tk.ExecuteToolText("Bunzip2", "anything"));
    }

    [Fact]
    public void PlatformPrefixSelectsTheProfilesToolsSection()
    {
        // Active platform Kali: tools are read from Kali:Tools, not the (absent) top-level Tools section.
        var kali = Config(new()
        {
            ["Platform"] = "Kali",
            ["Kali:Tools:UnixTools:MD5Sum:Command"] = "/usr/bin/md5sum",
        });
        Assert.True(new UnixToolsToolkit(new LocalEnvironment(), kali).IsToolAvailable("MD5Sum"));
    }

    [Fact]
    public void LegacyTopLevelToolsStillResolveUnderDefaultSiftPlatform()
    {
        // No Platform key -> defaults to SIFT; SIFT:Tools is absent, so it falls back to the legacy top-level
        // Tools section — existing single-distro configs keep working unchanged.
        var legacy = Config(new() { ["Tools:UnixTools:MD5Sum:Command"] = "/usr/bin/md5sum" });
        Assert.True(new UnixToolsToolkit(new LocalEnvironment(), legacy).IsToolAvailable("MD5Sum"));
    }
}
