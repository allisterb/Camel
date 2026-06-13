namespace Camel.Tests.Environments;

using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

using Camel.Environments;

/// <summary>
/// Tests for <see cref="LocalEnvironment"/> command execution. The toolkits compose <em>bash command lines</em>
/// (globs, pipes, redirects, command substitution, escaped <c>\( \)</c> grouping for <c>find</c>), so on Unix —
/// the on-SIFT "Local" deployment — the local environment must run them through a shell, exactly as the SSH
/// environment does. Without that, methods like <c>FindFilesAsync</c> fail with
/// <c>find: paths must precede expression: \(</c>. On Windows the tools are native and run directly.
/// </summary>
public class LocalEnvironmentTests
{
    private static bool IsUnixHost =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

    [Fact]
    public void ShellConstructsRunThroughBashOnUnix()
    {
        if (!IsUnixHost) return;   // Windows execs natively; the bash-wrap path is the Unix (SIFT) deployment
        var env = new LocalEnvironment();

        // A pipe with quoting — impossible without a shell to interpret '|'.
        var ok = env.ExecuteCommand("printf", @"'%s\n' one two three | grep -c o", out var output);
        Assert.True(ok, output);
        Assert.Equal("2", output.Trim());   // 'one' and 'two' contain 'o'
    }

    [Fact]
    public async Task FindWithEscapedGroupingWorksOnUnix()
    {
        if (!IsUnixHost) return;
        var env = new LocalEnvironment();
        var dir = "/tmp/camel_localenv_" + Guid.NewGuid().ToString("N");
        try
        {
            await env.ExecuteCommandAsync("mkdir", $"-p {dir}");
            await env.ExecuteCommandAsync("touch", $"{dir}/a.lnk {dir}/b.lnk {dir}/c.txt");

            // The exact shape DiskAnalysisToolkit.FindFilesAsync builds: escaped grouping + -printf. This is the
            // command that failed for the user when run without a shell.
            var r = await env.ExecuteCommandAsync("find",
                $@"'{dir}' -type f \( -iname '*.lnk' \) -printf '%p\n'");

            Assert.True(r.IsCompleted, r.Output);
            Assert.Contains("a.lnk", r.Output);
            Assert.Contains("b.lnk", r.Output);
            Assert.DoesNotContain("c.txt", r.Output);
        }
        finally { env.ExecuteCommand("rm", $"-rf {dir}", out _); }
    }

    [Fact]
    public void NativeCommandRunsDirectlyOnWindows()
    {
        if (IsUnixHost) return;   // this guards the unchanged Windows direct-exec path
        var env = new LocalEnvironment();
        var ok = env.ExecuteCommand("cmd.exe", "/c echo hi", out var output);
        Assert.True(ok, output);
        Assert.Equal("hi", output.Trim());
    }
}
