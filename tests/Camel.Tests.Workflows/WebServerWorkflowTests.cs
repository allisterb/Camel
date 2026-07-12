using System;
using System.Linq;

using Camel.Environments;
using Camel.Workflows;
using Camel.DFIR.Workflows;

namespace Camel.Tests.Workflows;

public class WebServerWorkflowTests : TestsRuntime
{
    public WebServerWorkflowTests()
    {
        var sshconfig = EnsureSIFT(LoadConfigFile("sshtestappsettings.json"));
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelToolkitsApi(sshenv, sshconfig);
        workflow = new WebServerAnalysisWorkflow(api);
        EvidenceMounts.EnsureAll(sshenv);   // self-heal the /mnt/c4 (Ali Hadi web server) evidence mount on a reset VM
    }

    [Fact]
    public async Task CanAnalyzeWebServerLogs()
    {
        // The Ali Hadi "Web Server Case" XAMPP/DVWA disk, mounted at /mnt/c4. Its Apache access log records the
        // full sqlmap SQL-injection → os-shell takeover. The workflow must surface it end-to-end.
        var r = await workflow.AnalyzeWebServerLogsAsync(AccessLog);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.True(r.Result.SuspiciousLineCount > 0);

        // The attacker (Kali, 192.168.56.102) is by far the loudest client and is fingerprinted as sqlmap.
        Assert.Equal("192.168.56.102", r.Result.TopAttackerIps.First().Ip);
        Assert.Contains(r.Result.ScannerUserAgents, ua => ua.Contains("sqlmap", StringComparison.OrdinalIgnoreCase));

        // Both the injection itself and the resulting command-execution stub are categorised.
        var cats = r.Result.CategoryBreakdown.Select(c => c.Category).ToHashSet();
        Assert.Contains(WebServerAnalysisWorkflow.CatSqli, cats);
        Assert.Contains(WebServerAnalysisWorkflow.CatWebshellRce, cats);

        // The decisive result: the hex-smuggled INTO OUTFILE payload decodes to the injected PHP backdoor — the
        // "shellcode" recovered straight out of the log, never present on disk as a standalone file.
        Assert.NotEmpty(r.Result.DecodedPayloads);
        Assert.Contains(r.Result.DecodedPayloads, d => d.Decoded.Contains("<?php", StringComparison.OrdinalIgnoreCase));

        // Every detailed finding is internally consistent: at least one category, and each is a known one.
        string[] valid = [WebServerAnalysisWorkflow.CatScanner, WebServerAnalysisWorkflow.CatSqli, WebServerAnalysisWorkflow.CatWebshellRce,
                          WebServerAnalysisWorkflow.CatFileInclusion, WebServerAnalysisWorkflow.CatXss];
        Assert.All(r.Result.Findings, f =>
        {
            Assert.NotEmpty(f.Categories);
            Assert.All(f.Categories, c => Assert.Contains(c, valid));
        });
    }

    [Fact]
    public async Task AnalyzeWebServerLogsFailsForMissingLog()
    {
        var r = await workflow.AnalyzeWebServerLogsAsync("/mnt/c4/xampp/apache/logs/does_not_exist.log");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task CanScanWebRootForWebshells()
    {
        // The web root holds a C99 PHP web shell (DVWA/c99.php). The bundled web-shell pack must flag it, and a
        // genuine C99 trips many rules at once — so the file's rule count is high.
        var r = await workflow.ScanWebRootForWebshellsAsync(WebRoot);

        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result);
        Assert.NotEmpty(r.Result.Files);
        Assert.Contains(r.Result.Files, f => f.Path.EndsWith("c99.php", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(r.Result.Files, f => f.Rules.Length >= 2);
        // FilesFlagged is the distinct-file count and every match targets one of the flagged files.
        Assert.Equal(r.Result.Files.Length, r.Result.FilesFlagged);
        var flagged = r.Result.Files.Select(f => f.Path).ToHashSet();
        Assert.All(r.Result.Matches, m => Assert.Contains(m.Target, flagged));
    }

    [Fact]
    public async Task ScanWebRootForWebshellsFailsForMissingRoot()
    {
        var r = await workflow.ScanWebRootForWebshellsAsync("/mnt/c4/xampp/htdocs/does_not_exist");

        Assert.False(r.IsSuccess);
        Assert.Null(r.Result);
        Assert.NotNull(r.Message);
    }

    // Ali Hadi Web Server Case (s4a-challenge4), mounted read-only at /mnt/c4.
    const string AccessLog = "/mnt/c4/xampp/apache/logs/access.log";
    const string WebRoot = "/mnt/c4/xampp/htdocs";

    AuditEnvironment sshenv;
    CamelToolkitsApi api;
    WebServerAnalysisWorkflow workflow;
}
