using System.Collections.Generic;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

/// <summary>
/// End-to-end demo of platform-aware tool resolution + graceful degradation against the project's real Kali
/// VM: the same neutral UnixToolsToolkit runs on Kali via the "Kali" platform profile, executing the tools the
/// profile declares (real /usr/bin paths) and cleanly degrading one that is omitted — exactly how a tool a
/// distro lacks behaves. UnixToolsToolkit is used because it needs no provisioning. The Kali connection is the
/// same box as tests/Camel.Tests.Environments/testappsettings.json (hardcoded here so the demo is self-contained).
/// </summary>
public class KaliPlatformToolTests
{
    static IConfigurationRoot KaliConfig() => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Platform"] = "Kali",
        ["Kali:Environment"] = "Ssh",
        ["Kali:Host"] = "192.168.8.168",
        ["Kali:Port"] = "22",
        ["Kali:User"] = "kali",
        ["Kali:Password"] = "kali",
        // A partial UnixTools profile for Kali: md5sum/sha256sum present (real Kali paths); SevenZip omitted,
        // standing in for a tool this platform does not provide.
        ["Kali:Tools:UnixTools:MD5Sum:Command"] = "/usr/bin/md5sum",
        ["Kali:Tools:UnixTools:SHA256Sum:Command"] = "/usr/bin/sha256sum",
    }).Build();

    [Fact]
    public void ResolvesAndExecutesProfileToolsOnKaliAndDegradesTheRest()
    {
        var config = KaliConfig();
        var env = AuditEnvironment.CreateFromConfig(config);   // Platform=Kali -> connects to the Kali box
        var tk = new UnixToolsToolkit(env, config);            // tools resolved from Kali:Tools:UnixTools

        // Declared in the Kali profile -> available, and it actually runs ON KALI: md5sum of a known file.
        Assert.True(tk.IsToolAvailable("MD5Sum"));
        var output = tk.ExecuteToolText("MD5Sum", "/etc/hostname");
        Assert.False(string.IsNullOrWhiteSpace(output));
        Assert.Contains("/etc/hostname", output);              // md5sum prints "<hash>  /etc/hostname"

        // Omitted from the Kali profile -> unavailable; the call degrades to null (audited
        // capability-unavailable) without ever executing a command with an empty path.
        Assert.False(tk.IsToolAvailable("SevenZip"));
        Assert.Null(tk.ExecuteToolText("SevenZip", "x"));
    }
}
