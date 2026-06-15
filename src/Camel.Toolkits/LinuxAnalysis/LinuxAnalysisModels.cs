namespace Camel.Toolkits.Models;

using System;

// =====================================================================================================
// Linux host-artifact models produced by LinuxAnalysisToolkit. These are hand-parsed from flat files on a
// mounted Linux root filesystem (/etc, /var/log, …) or from the structured output of a handful of real
// binaries (last/lastb/utmpdump/journalctl/clamscan). Grounded in Bruce Nikkel, "Practical Linux Forensics".
// =====================================================================================================

/// <summary>
/// Core identity of a Linux system, parsed from <c>/etc/os-release</c>, <c>/etc/hostname</c>,
/// <c>/etc/timezone</c> and <c>/etc/machine-id</c> on a mounted root. Establishes "which host is this and what
/// distribution/version" before any deeper triage.
/// </summary>
public record LinuxSystemInfo
{
    public string? Hostname { get; init; }
    /// <summary><c>PRETTY_NAME</c> from os-release, e.g. "Ubuntu 22.04.3 LTS".</summary>
    public string? PrettyName { get; init; }
    /// <summary><c>ID</c> from os-release, e.g. "ubuntu", "debian", "centos", "fedora".</summary>
    public string? DistroId { get; init; }
    /// <summary><c>VERSION_ID</c> from os-release, e.g. "22.04".</summary>
    public string? VersionId { get; init; }
    public string? Name { get; init; }
    public string? Version { get; init; }
    public string? Timezone { get; init; }
    public string? MachineId { get; init; }
    /// <summary><c>ID_LIKE</c> family hint (e.g. "debian"), used to choose a package-manager strategy.</summary>
    public string? IdLike { get; init; }
}

/// <summary>
/// A local user account, joining <c>/etc/passwd</c> (identity) with <c>/etc/shadow</c> (password state). The
/// password hash itself is never surfaced — only a coarse <see cref="PasswordState"/> — so the model is safe to
/// log in a report. <see cref="HasLoginShell"/> and <see cref="IsSystemAccount"/> drive the account hunts.
/// </summary>
public record LinuxUserAccount
{
    public string Username { get; init; } = "";
    public int Uid { get; init; }
    public int Gid { get; init; }
    public string? Gecos { get; init; }
    public string? Home { get; init; }
    public string? Shell { get; init; }
    /// <summary>True when the login shell is a real interactive shell (not nologin/false/sync).</summary>
    public bool HasLoginShell { get; init; }
    /// <summary>True for UID &lt; 1000 (and != 0): a service/system account rather than a human login.</summary>
    public bool IsSystemAccount { get; init; }
    /// <summary>"set" (a hash), "empty" (no password — login with none), "locked" (! / *), "none" (no shadow entry), or "unknown".</summary>
    public string PasswordState { get; init; } = "unknown";
    /// <summary>Date the password was last changed (shadow field 3, days since epoch), or null when absent/0.</summary>
    public DateTime? PasswordLastChanged { get; init; }
}

/// <summary>A sudo grant parsed from <c>/etc/sudoers</c> or a file under <c>/etc/sudoers.d/</c>. Privilege
/// escalation rights are a primary persistence/escalation artifact.</summary>
public record SudoRule
{
    /// <summary>The file the rule came from (e.g. <c>/etc/sudoers</c> or <c>/etc/sudoers.d/90-cloud-init-users</c>).</summary>
    public string Source { get; init; } = "";
    public string Raw { get; init; } = "";
    /// <summary>The user or %group the rule applies to (left-hand side).</summary>
    public string? Principal { get; init; }
    /// <summary>The host=(runas) command spec (right-hand side).</summary>
    public string? Spec { get; init; }
    /// <summary>True when the rule grants passwordless sudo (<c>NOPASSWD:</c>).</summary>
    public bool NoPasswd { get; init; }
    /// <summary>True when the rule grants ALL commands (<c>… = (ALL) ALL</c> or <c>= ALL</c>).</summary>
    public bool GrantsAll { get; init; }
}

/// <summary>A scheduled cron job, from any of the system crontab locations or a user crontab. Cron is one of the
/// most common Linux persistence mechanisms.</summary>
public record CronEntry
{
    /// <summary>The file the entry came from (e.g. <c>/etc/crontab</c>, <c>/etc/cron.d/foo</c>, <c>/var/spool/cron/crontabs/root</c>).</summary>
    public string Source { get; init; } = "";
    /// <summary>The user the job runs as: the 6th field for system crontabs, or the crontab's owning user for user crontabs.</summary>
    public string? User { get; init; }
    /// <summary>The schedule expression (5 fields, or a <c>@</c> nickname like <c>@reboot</c>/<c>@daily</c>).</summary>
    public string? Schedule { get; init; }
    public string Command { get; init; } = "";
    public string Raw { get; init; } = "";
    /// <summary>True for an <c>@reboot</c> entry (runs every boot — a favourite persistence trigger).</summary>
    public bool IsReboot { get; init; }
}

/// <summary>A login session (from <c>last -f wtmp</c>) or a failed login attempt (from <c>lastb -f btmp</c>).
/// <see cref="Host"/> is the source address (with <c>-i</c>, an IP).</summary>
public record LinuxLogin
{
    public string User { get; init; } = "";
    public string? Terminal { get; init; }
    public string? Host { get; init; }
    public DateTime? Start { get; init; }
    /// <summary>The trailing status/end of the record verbatim: "still logged in", "- 10:32 (00:45)", "gone - no logout", "- down", "- crash".</summary>
    public string? Status { get; init; }
    public bool StillLoggedIn { get; init; }
    public string Raw { get; init; } = "";
}

/// <summary>A raw utmp/wtmp/btmp record from <c>utmpdump</c> — the structured view (type/pid/line/host/addr/time),
/// useful for tamper checks and for reboot/boot records that <c>last</c> renders specially.</summary>
public record UtmpRecord
{
    public int Type { get; init; }
    public string? TypeName { get; init; }
    public int Pid { get; init; }
    public string? Id { get; init; }
    public string? User { get; init; }
    public string? Line { get; init; }
    public string? Host { get; init; }
    public string? Address { get; init; }
    public DateTime? Time { get; init; }
}

/// <summary>One systemd-journal entry, parsed from <c>journalctl -o json</c>. Fields are normalized from the
/// journal's underscore-prefixed metadata (<c>_SYSTEMD_UNIT</c>, <c>_PID</c>, <c>MESSAGE</c>, …).</summary>
public record JournalEntry
{
    public DateTime? Timestamp { get; init; }
    /// <summary><c>_SYSTEMD_UNIT</c> when present, e.g. "sshd.service".</summary>
    public string? Unit { get; init; }
    /// <summary><c>SYSLOG_IDENTIFIER</c> or <c>_COMM</c>, e.g. "sshd", "sudo", "kernel".</summary>
    public string? Identifier { get; init; }
    public int? Pid { get; init; }
    public int? Uid { get; init; }
    public int? Priority { get; init; }
    public string? Hostname { get; init; }
    public string Message { get; init; } = "";
}

/// <summary>An installed package, parsed from <c>/var/lib/dpkg/status</c> (no external <c>dpkg</c> binary
/// needed). Install <em>timing</em> is not in this file — use <see cref="PackageEvent"/> from the dpkg/apt logs.</summary>
public record LinuxPackage
{
    public string Name { get; init; } = "";
    public string? Version { get; init; }
    public string? Architecture { get; init; }
    /// <summary>The dpkg status triple, e.g. "install ok installed", "deinstall ok config-files".</summary>
    public string? Status { get; init; }
    public string? Section { get; init; }
    public string? Priority { get; init; }
    /// <summary>True when <see cref="Status"/> indicates the package is currently installed.</summary>
    public bool Installed { get; init; }
}

/// <summary>A package-management event from <c>/var/log/dpkg.log</c> or <c>/var/log/apt/history.log</c>. Gives
/// the <em>when</em> a package was installed/upgraded/removed — the timeline the status file lacks.</summary>
public record PackageEvent
{
    public DateTime? Timestamp { get; init; }
    /// <summary>install / upgrade / remove / purge / configure / trigproc / status.</summary>
    public string Action { get; init; } = "";
    public string Package { get; init; } = "";
    public string? Version { get; init; }
    public string? PreviousVersion { get; init; }
    /// <summary>"dpkg.log" or "apt/history.log".</summary>
    public string Source { get; init; } = "";
}

/// <summary>A line from a user's shell history file (<c>.bash_history</c>, <c>.zsh_history</c>,
/// <c>.python_history</c>). <see cref="Timestamp"/> is populated only when the file carries bash
/// <c>HISTTIMEFORMAT</c> epoch markers.</summary>
public record ShellHistoryEntry
{
    public string User { get; init; } = "";
    public string HistoryFile { get; init; } = "";
    public int LineNumber { get; init; }
    public string Command { get; init; } = "";
    public DateTime? Timestamp { get; init; }
}

/// <summary>A ClamAV detection (<c>clamscan -i</c>): the infected file and the signature that matched.</summary>
public record ClamAvMatch
{
    public string Path { get; init; } = "";
    public string Signature { get; init; } = "";
}

/// <summary>
/// A file on the mounted filesystem with its permission/ownership metadata, produced by the file-anomaly
/// extractors (<c>find</c>-based: SUID/SGID, world-writable, files under temp dirs). Used to hunt for privilege
/// escalation and staging artifacts.
/// </summary>
public record LinuxFile
{
    public string Path { get; init; } = "";
    /// <summary>Octal permission bits (<c>find %m</c>), e.g. "4755" for a SUID root binary.</summary>
    public string? Mode { get; init; }
    /// <summary>Owning user name or uid (<c>find %u</c>).</summary>
    public string? Owner { get; init; }
    /// <summary>Owning group name or gid (<c>find %g</c>).</summary>
    public string? Group { get; init; }
    public long Size { get; init; }
    public DateTime? Modified { get; init; }
    /// <summary>True when the octal mode carries the SUID bit (4xxx).</summary>
    public bool IsSetuid { get; init; }
    /// <summary>True when the octal mode carries the SGID bit (2xxx).</summary>
    public bool IsSetgid { get; init; }
    /// <summary>True when the file is executable by some class (any x bit set).</summary>
    public bool IsExecutable { get; init; }
}
