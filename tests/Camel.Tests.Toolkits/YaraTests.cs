using System;
using System.Text;

using Camel.Environments;
using Camel.Toolkits;
using Camel.DFIR.Toolkits;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;

namespace Camel.Tests.Toolkits;

public class YaraTests : TestsRuntime
{
    public YaraTests()
    {
        var sshconfig = EnsureSIFT(LoadConfigFile("sshtestappsettings.json"));
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new YaraToolkit(sshenv, sshconfig);

        // Lay down a test rule + sample files on the workstation (base64 avoids shell-quoting issues).
        sshenv.ExecuteCommand("mkdir", $"-p {Dir}", out _, false);
        WriteRemote($"{Dir}/test.yar",
            "rule CamelTest : test malware { meta: author = \"camel\" strings: $a = \"CamelForensics\" condition: $a }");
        WriteRemote($"{Dir}/sample.txt", "hello CamelForensics world");
        WriteRemote($"{Dir}/other.txt", "nothing to see here");
    }

    [Fact]
    public void CanLoadAllToolsFromConfig()
    {
        Assert.Equal(toolkit.ToolList.Length, toolkit.Tools.Count);
        Assert.All(toolkit.ToolList, name =>
        {
            Assert.True(toolkit.Tools.ContainsKey(name));
            Assert.StartsWith("/usr/bin/", toolkit.Tools[name].Command);
            Assert.NotEmpty(toolkit.Tools[name].Descriptioon);
        });
    }

    [Fact]
    public async Task CanRunScanBasic()
    {
        var r = (await toolkit.ScanAsync($"{Dir}/test.yar", $"{Dir}/sample.txt")).Result;
        Assert.NotNull(r);
        var match = Assert.Single(r);
        Assert.Equal("CamelTest", match.Rule);
        Assert.EndsWith("sample.txt", match.Target);
    }

    [Fact]
    public async Task CanRunScanWithTagsMetaAndStrings()
    {
        var r = (await toolkit.ScanAsync($"{Dir}/test.yar", $"{Dir}/sample.txt",
            new YaraOptions { PrintTags = true, PrintMeta = true, PrintStrings = true, PrintNamespace = true })).Result;
        Assert.NotNull(r);
        var match = Assert.Single(r);
        Assert.Equal("CamelTest", match.Rule);
        Assert.Equal("default", match.Namespace);          // -e
        Assert.Contains("malware", match.Tags);            // -g
        Assert.Contains("author", match.Meta ?? "");       // -m
        Assert.Contains(match.MatchedStrings, s => s.Contains("CamelForensics")); // -s
    }

    [Fact]
    public async Task CanRunScanRecursiveNoFalsePositive()
    {
        var r = (await toolkit.ScanAsync($"{Dir}/test.yar", Dir, new YaraOptions { Recurse = true })).Result;
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, m => m.Target.EndsWith("sample.txt"));
        Assert.DoesNotContain(r, m => m.Target.EndsWith("other.txt")); // no matching string
    }

    [Fact]
    public async Task CanRunCompileThenScanCompiled()
    {
        var compiled = $"{Dir}/test.yarc";
        sshenv.ExecuteCommand("rm", $"-f {compiled}", out _, false);

        Assert.True(await toolkit.CompileAsync($"{Dir}/test.yar", compiled));

        var r = (await toolkit.ScanAsync(compiled, $"{Dir}/sample.txt", new YaraOptions { Compiled = true })).Result;
        Assert.NotNull(r);
        var match = Assert.Single(r);
        Assert.Equal("CamelTest", match.Rule);
    }

    void WriteRemote(string path, string content)
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(content));
        sshenv.ExecuteCommand("bash", $"-c \"echo {b64} | base64 -d > '{path}'\"", out _, false);
    }

    const string Dir = "/tmp/camel_yara_test";

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    YaraToolkit toolkit;
}
