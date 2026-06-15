namespace Camel.Workflows.Models;

using System;

using Camel.Toolkits.Models;

// =====================================================================================================
// Report models for LinuxAnalysisWorkflow. Each workflow returns a typed report carrying the raw artifacts it
// collected plus the items it flagged (with the reason it flagged them), so the agent can cite a concrete
// artifact for every finding. Grounded in Bruce Nikkel, "Practical Linux Forensics".
// =====================================================================================================

#region Accounts
/// <summary>Result of triaging local accounts (passwd/shadow/group/sudoers) for suspicious configurations.</summary>
public record UserAccountReport
{
    public LinuxUserAccount[] Accounts { get; init; } = [];
    public SudoRule[] SudoRules { get; init; } = [];
    /// <summary>Accounts/rules flagged as risky, with the reason.</summary>
    public AccountFinding[] Findings { get; init; } = [];
    public int TotalAccounts { get; init; }
}

/// <summary>One flagged account/privilege issue.</summary>
public record AccountFinding
{
    public required string Username { get; init; }
    /// <summary>uid0-extra / empty-password / service-account-login-shell / sudo-nopasswd / sudo-all.</summary>
    public required string Issue { get; init; }
    public string? Detail { get; init; }
}
#endregion

#region Logins
/// <summary>Result of analysing login records (wtmp via last, btmp via lastb).</summary>
public record LoginActivityReport
{
    public int SuccessfulCount { get; init; }
    public int FailedCount { get; init; }
    /// <summary>Source addresses ranked by total attempts, with the success/failure split.</summary>
    public IpLoginStat[] TopSourceIps { get; init; } = [];
    /// <summary>Usernames most targeted by failed logins (brute-force / spray indicator).</summary>
    public NameCount[] TopFailedUsers { get; init; } = [];
    /// <summary>A capped sample of successful sessions (most recent first).</summary>
    public LinuxLogin[] RecentSuccessful { get; init; } = [];
    public LoginFinding[] Findings { get; init; } = [];
}

public record IpLoginStat
{
    public required string Ip { get; init; }
    public int Successful { get; init; }
    public int Failed { get; init; }
}

public record NameCount
{
    public required string Name { get; init; }
    public int Count { get; init; }
}

/// <summary>One flagged login observation (brute-force source, successful login after failures, root login, …).</summary>
public record LoginFinding
{
    public required string Category { get; init; }
    public required string Detail { get; init; }
}

/// <summary>Result of parsing the authentication log (auth.log / secure) for sshd/sudo/su/account events.</summary>
public record AuthEventReport
{
    public string LogPath { get; init; } = "";
    public int AcceptedLogins { get; init; }
    public int FailedLogins { get; init; }
    public int SudoCommands { get; init; }
    /// <summary>SSH source IPs ranked by failed-auth count.</summary>
    public IpLoginStat[] TopSshSourceIps { get; init; } = [];
    /// <summary>A capped sample of the most security-relevant events.</summary>
    public AuthEvent[] Events { get; init; } = [];
    public AuthEvent[] Findings { get; init; } = [];
}

/// <summary>One parsed authentication-log event.</summary>
public record AuthEvent
{
    public DateTime? Time { get; init; }
    /// <summary>sshd-accepted / sshd-failed / sudo / su / useradd / usermod / groupadd / new-ssh-key / password-change.</summary>
    public required string Type { get; init; }
    public string? User { get; init; }
    public string? SourceIp { get; init; }
    public string Raw { get; init; } = "";
}
#endregion

#region Persistence
/// <summary>Result of hunting Linux persistence mechanisms across cron, systemd, init/rc, shell rc, ld.so.preload,
/// SSH authorized_keys, udev and motd. <see cref="Suspicious"/> is the subset scored as noteworthy.</summary>
public record LinuxPersistenceReport
{
    public PersistenceItem[] Items { get; init; } = [];
    public PersistenceItem[] Suspicious { get; init; } = [];
    public int TotalItems { get; init; }
}

/// <summary>One persistence point with a suspicion score and the reasons that raised it.</summary>
public record PersistenceItem
{
    /// <summary>cron / systemd-unit / systemd-timer / rc-local / init-script / shell-rc / ld-preload / authorized-key / udev / motd / cron-script.</summary>
    public required string Mechanism { get; init; }
    public required string Source { get; init; }
    /// <summary>The command / line / key that constitutes the persistence (truncated for keys).</summary>
    public string? Detail { get; init; }
    public int Score { get; init; }
    public string[] Reasons { get; init; } = [];
}
#endregion

#region Shell history
/// <summary>Result of triaging every user's shell history for attacker-pattern commands.</summary>
public record ShellHistoryReport
{
    public int TotalLines { get; init; }
    public int UsersWithHistory { get; init; }
    public SuspiciousCommand[] Suspicious { get; init; } = [];
}

/// <summary>One flagged history command with the categories it matched.</summary>
public record SuspiciousCommand
{
    public required string User { get; init; }
    public required string Command { get; init; }
    public string[] Categories { get; init; } = [];
    public DateTime? Timestamp { get; init; }
    public string HistoryFile { get; init; } = "";
}
#endregion

#region Packages
/// <summary>Result of analysing installed packages and the package-management timeline.</summary>
public record PackageReport
{
    public int InstalledCount { get; init; }
    /// <summary>The most recent package install/upgrade/remove events (capped).</summary>
    public PackageEvent[] RecentEvents { get; init; } = [];
    /// <summary>Install events for packages on the dual-use / hacktool watchlist (nmap, netcat, masscan, …).</summary>
    public PackageEvent[] Findings { get; init; } = [];
}
#endregion

#region Files & malware
/// <summary>Result of hunting anomalous files (SUID/SGID, world-writable, executables staged in temp dirs).</summary>
public record FileAnomalyReport
{
    /// <summary>SUID/SGID files not on the standard-distro baseline (the ones worth a look).</summary>
    public LinuxFile[] SuspiciousSetuid { get; init; } = [];
    public int TotalSetuid { get; init; }
    public LinuxFile[] WorldWritable { get; init; } = [];
    /// <summary>Executable files staged in /tmp, /dev/shm or /var/tmp.</summary>
    public LinuxFile[] ExecutablesInTempDirs { get; init; } = [];
}

/// <summary>Result of scanning a target with ClamAV and YARA.</summary>
public record LinuxMalwareReport
{
    public string Target { get; init; } = "";
    public ClamAvMatch[] ClamMatches { get; init; } = [];
    public YaraMatch[] YaraMatches { get; init; } = [];
    /// <summary>A note surfaced when ClamAV had no signatures loaded (run <c>freshclam</c>), else null.</summary>
    public string? Note { get; init; }
}
#endregion

#region Journal
/// <summary>Result of triaging the systemd journal for security-relevant activity.</summary>
public record JournalReport
{
    public string JournalDir { get; init; } = "";
    public int TotalEntries { get; init; }
    public int SudoEvents { get; init; }
    public int SshEvents { get; init; }
    public int ServiceStarts { get; init; }
    /// <summary>A capped sample of notable entries (sudo, ssh, segfaults, service installs).</summary>
    public JournalEntry[] Notable { get; init; } = [];
}
#endregion

#region Host triage
/// <summary>Roll-up of the host-triage orchestrator: each sub-report (null when that step failed) plus a flat
/// list of the highest-signal findings across all of them.</summary>
public record LinuxHostTriageReport
{
    public LinuxSystemInfo? System { get; init; }
    public UserAccountReport? Accounts { get; init; }
    public LoginActivityReport? Logins { get; init; }
    public AuthEventReport? Auth { get; init; }
    public LinuxPersistenceReport? Persistence { get; init; }
    public ShellHistoryReport? ShellHistory { get; init; }
    public FileAnomalyReport? Files { get; init; }
    /// <summary>One-line summaries of the top findings, for the agent to triage and cite.</summary>
    public string[] TopFindings { get; init; } = [];
}
#endregion
