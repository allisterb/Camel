using System;

using Camel.Environments;
using Camel.Toolkits;
using Camel.DFIR.Toolkits;

namespace Camel.Tests.Toolkits;

public class UnixToolsTests : TestsRuntime
{
    public UnixToolsTests()
    {
        var sshconfig = EnsureSIFT(LoadConfigFile("sshtestappsettings.json"));
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new UnixToolsToolkit(sshenv, sshconfig);
    }

    [Fact]
    public void CanLoadAllToolsFromConfig()
    {
        // Constructing the toolkit loads every ToolList entry from config; verify all resolved.
        Assert.Equal(toolkit.ToolList.Length, toolkit.Tools.Count);
        Assert.All(toolkit.ToolList, name =>
        {
            Assert.True(toolkit.Tools.ContainsKey(name));
            Assert.Contains("bin/", toolkit.Tools[name].Command);
            Assert.NotEmpty(toolkit.Tools[name].Descriptioon);
        });
    }

    [Fact]
    public async Task CanRunBunzip2()
    {
        // Build a small .bz2 on the workstation (stands in for a compressed memory/disk image).
        sshenv.ExecuteCommand("bash",
            $"-c \"rm -rf {Dir}; mkdir -p {Dir}; printf '{Payload}' > {Dir}/mem.raw; bzip2 -k {Dir}/mem.raw\"", out _, false);

        var r = await toolkit.Bunzip2Async($"{Dir}/mem.raw.bz2", $"{Dir}/out.raw");
        Assert.NotNull(r);
        var f = Assert.Single(r.Files);
        Assert.Equal($"{Dir}/out.raw", f.Path);
        Assert.Equal(Payload.Length, f.Size);
        Assert.Equal(Payload.Length, r.TotalBytes);

        // Output content matches the original, and the source archive is kept.
        sshenv.ExecuteCommand("cat", $"{Dir}/out.raw", out var content, false);
        Assert.Equal(Payload, content.Trim());
        Assert.True(sshenv.ExecuteCommand("test", $"-e {Dir}/mem.raw.bz2", out _, false));

        sshenv.ExecuteCommand("rm", $"-rf {Dir}", out _, false);
    }

    [Fact]
    public async Task CanRunBunzip2DefaultOutput()
    {
        sshenv.ExecuteCommand("bash",
            $"-c \"rm -rf {Dir}; mkdir -p {Dir}; printf '{Payload}' > {Dir}/mem.raw; bzip2 -k {Dir}/mem.raw\"", out _, false);

        // No outputFile: the .bz2 suffix is stripped to derive the destination path.
        var r = await toolkit.Bunzip2Async($"{Dir}/mem.raw.bz2");
        Assert.NotNull(r);
        Assert.Equal($"{Dir}/mem.raw", r.OutputPath);
        Assert.Equal($"{Dir}/mem.raw", Assert.Single(r.Files).Path);

        sshenv.ExecuteCommand("rm", $"-rf {Dir}", out _, false);
    }

    [Fact]
    public async Task CanRunUnzip()
    {
        // Build a multi-file zip on the workstation.
        sshenv.ExecuteCommand("bash",
            $"-c \"rm -rf {Dir}; mkdir -p {Dir}; cd {Dir}; printf 'aaaa' > a.bin; printf 'bb' > b.bin; zip -q test.zip a.bin b.bin\"", out _, false);

        var r = await toolkit.UnzipAsync($"{Dir}/test.zip", $"{Dir}/ext");
        Assert.NotNull(r);
        Assert.Equal($"{Dir}/ext", r.OutputPath);
        Assert.Equal(2, r.Files.Length);
        Assert.Contains(r.Files, f => f.Path == $"{Dir}/ext/a.bin" && f.Size == 4);
        Assert.Contains(r.Files, f => f.Path == $"{Dir}/ext/b.bin" && f.Size == 2);
        Assert.Equal(6, r.TotalBytes);

        sshenv.ExecuteCommand("rm", $"-rf {Dir}", out _, false);
    }

    [Fact]
    public async Task CanRunUnzipSelectedMembers()
    {
        sshenv.ExecuteCommand("bash",
            $"-c \"rm -rf {Dir}; mkdir -p {Dir}; cd {Dir}; printf 'aaaa' > a.bin; printf 'bb' > b.bin; zip -q test.zip a.bin b.bin\"", out _, false);

        // Extract only a.bin (e.g. pulling one large image out of a multi-file archive).
        var r = await toolkit.UnzipAsync($"{Dir}/test.zip", $"{Dir}/ext", files: ["a.bin"]);
        Assert.NotNull(r);
        Assert.Equal($"{Dir}/ext/a.bin", Assert.Single(r.Files).Path);

        sshenv.ExecuteCommand("rm", $"-rf {Dir}", out _, false);
    }

    [Fact]
    public async Task CanRunSevenZipExtract()
    {
        // Build a multi-file .7z on the workstation.
        sshenv.ExecuteCommand("bash",
            $"-c \"rm -rf {Dir}; mkdir -p {Dir}; cd {Dir}; printf 'aaaa' > a.bin; printf 'bb' > b.bin; 7z a -bso0 -bsp0 test.7z a.bin b.bin\"", out _, false);

        var r = await toolkit.SevenZipExtractAsync($"{Dir}/test.7z", $"{Dir}/ext");
        Assert.NotNull(r);
        Assert.Equal($"{Dir}/ext", r.OutputPath);
        Assert.Equal(2, r.Files.Length);
        Assert.Contains(r.Files, f => f.Path == $"{Dir}/ext/a.bin" && f.Size == 4);
        Assert.Contains(r.Files, f => f.Path == $"{Dir}/ext/b.bin" && f.Size == 2);

        sshenv.ExecuteCommand("rm", $"-rf {Dir}", out _, false);
    }

    [Fact]
    public async Task CanRunSevenZipExtractSelectedMembers()
    {
        sshenv.ExecuteCommand("bash",
            $"-c \"rm -rf {Dir}; mkdir -p {Dir}; cd {Dir}; printf 'aaaa' > a.bin; printf 'bb' > b.bin; 7z a -bso0 -bsp0 test.7z a.bin b.bin\"", out _, false);

        var r = await toolkit.SevenZipExtractAsync($"{Dir}/test.7z", $"{Dir}/ext", files: ["a.bin"]);
        Assert.NotNull(r);
        Assert.Equal($"{Dir}/ext/a.bin", Assert.Single(r.Files).Path);

        sshenv.ExecuteCommand("rm", $"-rf {Dir}", out _, false);
    }

    [Fact]
    public async Task CanRunCopyFile()
    {
        // Source file in one dir; copy it to a (not-yet-existing) destination tree.
        sshenv.ExecuteCommand("bash",
            $"-c \"rm -rf {Dir}; mkdir -p {Dir}/src; printf '{Payload}' > {Dir}/src/image.raw\"", out _, false);

        // verify: true SHA-256s the source against the copy and reports the result.
        var r = await toolkit.CopyFileAsync($"{Dir}/src/image.raw", $"{Dir}/dst/staged.raw", verify: true);
        Assert.NotNull(r);
        Assert.Equal($"{Dir}/dst/staged.raw", r.Destination);
        var f = Assert.Single(r.Files);
        Assert.Equal($"{Dir}/dst/staged.raw", f.Path);
        Assert.Equal(Payload.Length, f.Size);
        Assert.True(r.Verified);
        Assert.Empty(r.Mismatches);

        // The copy landed and the parent dir was created.
        sshenv.ExecuteCommand("cat", $"{Dir}/dst/staged.raw", out var content, false);
        Assert.Equal(Payload, content.Trim());

        sshenv.ExecuteCommand("rm", $"-rf {Dir}", out _, false);
    }


    [Fact]
    public async Task CanRunCopyDir()
    {
        sshenv.ExecuteCommand("bash",
            $"-c \"rm -rf {Dir}; mkdir -p {Dir}/src/sub; printf 'aaaa' > {Dir}/src/a.bin; printf 'bb' > {Dir}/src/sub/b.bin\"", out _, false);

        var r = await toolkit.CopyDirAsync($"{Dir}/src", $"{Dir}/dst/copied", verify: true);
        Assert.NotNull(r);
        Assert.Equal($"{Dir}/dst/copied", r.Destination);
        Assert.Equal(2, r.Files.Length);
        Assert.Contains(r.Files, f => f.Path == $"{Dir}/dst/copied/a.bin" && f.Size == 4);
        Assert.Contains(r.Files, f => f.Path == $"{Dir}/dst/copied/sub/b.bin" && f.Size == 2);
        Assert.Equal(6, r.TotalBytes);
        // Every source file hashed equal to its copy.
        Assert.True(r.Verified);
        Assert.Empty(r.Mismatches);

        sshenv.ExecuteCommand("rm", $"-rf {Dir}", out _, false);
    }

    const string Dir = "/tmp/camel_unixtools_test";
    const string Payload = "hello camel image payload";

    AuditEnvironment sshenv;
    UnixToolsToolkit toolkit;
}
