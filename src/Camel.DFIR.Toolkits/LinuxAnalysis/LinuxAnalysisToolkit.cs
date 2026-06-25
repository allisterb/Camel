namespace Camel.DFIR.Toolkits;
using Camel.Toolkits;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

/// <summary>
/// Typed extractors for Linux host artifacts on a <em>mounted root filesystem</em> (a forensic image mounted
/// read-only, or a live root). Each method reads the relevant flat files under a root directory (<c>/etc</c>,
/// <c>/var/log</c>, user home dirs) or runs one of a small set of real binaries
/// (<c>last</c>/<c>lastb</c>/<c>utmpdump</c>/<c>journalctl</c>/<c>clamscan</c>) and returns a strongly-typed model.
/// All reads default to <c>sudo</c> because forensic mounts are root-owned. The toolkit is the "what's in the
/// artifact" layer; the hunting/scoring lives in <see cref="Camel.Workflows.LinuxAnalysisWorkflow"/>.
/// <para>
/// Tooling note (missing-tool assessment): everything here is satisfied by the base SIFT image — no installs are
/// needed for the default Debian/Ubuntu (dpkg) path. <c>clamscan</c>+YARA cover malware; <c>rkhunter</c>/
/// <c>chkrootkit</c> are deliberately not auto-provisioned (live-system oriented and awkward against a mounted
/// image). RPM-distro package support (<c>rpm --root</c>) is a clean future extension via <c>InstallAptPackage</c>.
/// </para>
/// Grounded in Bruce Nikkel, <em>Practical Linux Forensics</em> (No Starch, 2022).
/// </summary>
public class LinuxAnalysisToolkit : Toolkit
{
    public LinuxAnalysisToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null)
        : base("LinuxAnalysis", auditEnvironment, config) { }

    public override string[] ToolList { get; } = ["Last", "Lastb", "Utmpdump", "Journalctl", "ClamScan"];

    #region System identity & accounts
    /// <summary>
    /// Reads core system identity from a mounted root: <c>etc/os-release</c> (falling back to
    /// <c>usr/lib/os-release</c>), <c>etc/hostname</c>, <c>etc/timezone</c>, <c>etc/machine-id</c>. Returns a
    /// best-effort <see cref="LinuxSystemInfo"/> (fields that could not be read are null), or null only when the
    /// root has no readable os-release nor hostname (likely a wrong/unmounted path).
    /// </summary>
    public async Task<LinuxSystemInfo?> SystemInfoAsync(string rootDir, bool sudo = true)
    {
        var osr = await CatAsync(Combine(rootDir, "etc/os-release"), sudo)
                  ?? await CatAsync(Combine(rootDir, "usr/lib/os-release"), sudo);
        var hostname = (await CatAsync(Combine(rootDir, "etc/hostname"), sudo))?.Trim();
        if (osr is null && hostname is null) return null;

        var kv = ParseEnvFile(osr ?? "");
        return new LinuxSystemInfo
        {
            Hostname = hostname,
            PrettyName = kv.GetValueOrDefault("PRETTY_NAME"),
            DistroId = kv.GetValueOrDefault("ID"),
            VersionId = kv.GetValueOrDefault("VERSION_ID"),
            Name = kv.GetValueOrDefault("NAME"),
            Version = kv.GetValueOrDefault("VERSION"),
            IdLike = kv.GetValueOrDefault("ID_LIKE"),
            Timezone = (await CatAsync(Combine(rootDir, "etc/timezone"), sudo))?.Trim(),
            MachineId = (await CatAsync(Combine(rootDir, "etc/machine-id"), sudo))?.Trim(),
        };
    }

    /// <summary>
    /// Enumerates local accounts by joining <c>etc/passwd</c> with <c>etc/shadow</c>. The password hash is never
    /// returned — only a coarse <see cref="LinuxUserAccount.PasswordState"/>. Returns null when <c>etc/passwd</c>
    /// is unreadable.
    /// </summary>
    public async Task<LinuxUserAccount[]?> UserAccountsAsync(string rootDir, bool sudo = true)
    {
        var passwd = await CatAsync(Combine(rootDir, "etc/passwd"), sudo);
        if (passwd is null) return null;
        var shadow = await CatAsync(Combine(rootDir, "etc/shadow"), sudo);   // may be null (not permitted / absent)

        // shadow: user:hash:lastchg:min:max:warn:inactive:expire:
        var shadowMap = new Dictionary<string, (string hash, string lastchg)>();
        foreach (var line in Lines(shadow))
        {
            var f = line.Split(':');
            if (f.Length >= 3) shadowMap[f[0]] = (f[1], f[2]);
        }

        var accounts = new List<LinuxUserAccount>();
        foreach (var line in Lines(passwd))
        {
            var f = line.Split(':');
            if (f.Length < 7) continue;
            int.TryParse(f[2], out var uid);
            int.TryParse(f[3], out var gid);
            var shell = f[6];
            shadowMap.TryGetValue(f[0], out var sh);
            var (state, changed) = PasswordState(f[1], shadowMap.ContainsKey(f[0]) ? sh.hash : null, shadowMap.ContainsKey(f[0]) ? sh.lastchg : null);
            accounts.Add(new LinuxUserAccount
            {
                Username = f[0],
                Uid = uid,
                Gid = gid,
                Gecos = f[4],
                Home = f[5],
                Shell = shell,
                HasLoginShell = IsLoginShell(shell),
                IsSystemAccount = uid < 1000,
                PasswordState = state,
                PasswordLastChanged = changed,
            });
        }
        return accounts.ToArray();
    }

    /// <summary>
    /// Parses sudo grants from <c>etc/sudoers</c> and every file under <c>etc/sudoers.d/</c>. Alias/Defaults
    /// lines are skipped; only actual grants (user/%group rules) are returned. Returns null when no sudoers file
    /// is readable.
    /// </summary>
    public async Task<SudoRule[]?> SudoersAsync(string rootDir, bool sudo = true)
    {
        var files = await ReadGlobAsync($"{Combine(rootDir, "etc/sudoers")} {Combine(rootDir, "etc/sudoers.d")}/*", sudo);
        if (files.Count == 0) return null;
        var rules = new List<SudoRule>();
        foreach (var (path, content) in files)
            foreach (var raw in Lines(content))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                if (Regex.IsMatch(line, @"^(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|@includedir|#includedir)\b")) continue;
                var eq = line.IndexOf('=');
                if (eq <= 0) continue;   // not a grant
                var principal = line[..eq].Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                var spec = line[(eq + 1)..].Trim();
                rules.Add(new SudoRule
                {
                    Source = path,
                    Raw = line,
                    Principal = principal,
                    Spec = spec,
                    NoPasswd = line.Contains("NOPASSWD", StringComparison.OrdinalIgnoreCase),
                    GrantsAll = Regex.IsMatch(spec, @"(^|\)|\s)ALL\s*$"),
                });
            }
        return rules.ToArray();
    }
    #endregion

    #region Scheduled tasks
    /// <summary>
    /// Collects cron jobs from every standard location: <c>etc/crontab</c>, <c>etc/cron.d/*</c>, the
    /// <c>etc/cron.{hourly,daily,weekly,monthly}</c> script directories, and per-user crontabs under
    /// <c>var/spool/cron/</c> (and <c>var/spool/cron/crontabs/</c>). Environment-assignment and comment lines are
    /// dropped. Returns the parsed entries (empty when none), or null when no cron source is readable.
    /// </summary>
    public async Task<CronEntry[]?> CronEntriesAsync(string rootDir, bool sudo = true)
    {
        // System-format crontabs (5 fields + USER + command, or "@nick USER command").
        var system = await ReadGlobAsync($"{Combine(rootDir, "etc/crontab")} {Combine(rootDir, "etc/cron.d")}/*", sudo);
        // Per-user crontabs (5 fields + command, or "@nick command"); the file name is the owning user.
        var userCron = await ReadGlobAsync($"{Combine(rootDir, "var/spool/cron/crontabs")}/* {Combine(rootDir, "var/spool/cron")}/*", sudo);
        // Drop-in script directories run on a fixed cadence by cron/anacron.
        var dropDirs = new[] { "hourly", "daily", "weekly", "monthly" };
        var scripts = await ReadGlobAsync(string.Join(" ", dropDirs.Select(d => $"{Combine(rootDir, $"etc/cron.{d}")}/*")), sudo);

        if (system.Count == 0 && userCron.Count == 0 && scripts.Count == 0) return null;

        var entries = new List<CronEntry>();
        foreach (var (path, content) in system) entries.AddRange(ParseCron(path, content, systemFormat: true, user: null));
        foreach (var (path, content) in userCron) entries.AddRange(ParseCron(path, content, systemFormat: false, user: FileName(path)));
        // Script-dir members aren't crontab lines — each script *is* the job; record it as a scheduled command.
        foreach (var (path, _) in scripts)
        {
            var cadence = Regex.Match(path, @"cron\.(hourly|daily|weekly|monthly)");
            entries.Add(new CronEntry
            {
                Source = path,
                User = "root",
                Schedule = cadence.Success ? "@" + cadence.Groups[1].Value : "@periodic",
                Command = path,
                Raw = path,
            });
        }
        return entries.ToArray();
    }
    #endregion

    #region Login records
    /// <summary>
    /// Successful login/logout sessions from a wtmp file via <c>last -F -i -w -f &lt;wtmp&gt;</c> (full
    /// timestamps, numeric host/IP). Default path is <c>var/log/wtmp</c> under <paramref name="rootDir"/> when
    /// <paramref name="wtmpPath"/> is null. Returns null on tool failure.
    /// </summary>
    public async Task<LinuxLogin[]?> LastLoginsAsync(string? wtmpPath = null, string rootDir = "/", bool sudo = true)
    {
        var path = wtmpPath ?? Combine(rootDir, "var/log/wtmp");
        var o = await RunAsync("Last", $"-F -i -w -f {Q(path)}", sudo);
        return o is null ? null : ParseLast(o);
    }

    /// <summary>
    /// Failed login attempts from a btmp file via <c>lastb -F -i -w -f &lt;btmp&gt;</c> — the brute-force /
    /// password-spray view. Default path is <c>var/log/btmp</c> under <paramref name="rootDir"/>. Returns null on
    /// tool failure.
    /// </summary>
    public async Task<LinuxLogin[]?> FailedLoginsAsync(string? btmpPath = null, string rootDir = "/", bool sudo = true)
    {
        var path = btmpPath ?? Combine(rootDir, "var/log/btmp");
        var o = await RunAsync("Lastb", $"-F -i -w -f {Q(path)}", sudo);
        return o is null ? null : ParseLast(o);
    }

    /// <summary>
    /// Raw utmp/wtmp/btmp records via <c>utmpdump</c> — the structured (type/pid/line/host/addr/time) view, for
    /// reboot/boot records and for detecting gaps or zeroed records left by log tampering. Returns null on tool
    /// failure.
    /// </summary>
    public async Task<UtmpRecord[]?> UtmpDumpAsync(string path, bool sudo = true)
    {
        var o = await RunAsync("Utmpdump", Q(path), sudo);
        if (o is null) return null;
        var records = new List<UtmpRecord>();
        foreach (var line in Lines(o))
        {
            var m = Regex.Matches(line, @"\[([^\]]*)\]");
            if (m.Count < 8) continue;
            string g(int i) => m[i].Groups[1].Value.Trim();
            int.TryParse(g(0), out var type);
            int.TryParse(g(1), out var pid);
            records.Add(new UtmpRecord
            {
                Type = type,
                TypeName = UtmpType(type),
                Pid = pid,
                Id = g(2),
                User = g(3),
                Line = g(4),
                Host = g(5),
                Address = g(6),
                Time = ParseUtmpTime(g(7)),
            });
        }
        return records.ToArray();
    }
    #endregion

    #region Journal
    /// <summary>
    /// Reads the systemd journal under <paramref name="journalDir"/> (a <c>var/log/journal</c> directory on a
    /// mounted image) via <c>journalctl -D &lt;dir&gt; -o json</c>, normalizing each entry. Optionally cap the
    /// number of (most-recent) entries with <paramref name="maxEntries"/> and/or filter to a unit with
    /// <paramref name="unit"/>. Returns null on tool failure.
    /// </summary>
    public async Task<JournalEntry[]?> JournalAsync(string journalDir, int? maxEntries = null, string? unit = null, bool sudo = true)
    {
        var args = $"-D {Q(journalDir)} -o json --no-pager" +
                   (maxEntries is int n and > 0 ? $" -n {n}" : "") +
                   (unit is not null ? $" -u {Q(unit)}" : "");
        var o = await RunAsync("Journalctl", args, sudo);
        if (o is null) return null;
        var entries = new List<JournalEntry>();
        foreach (var line in Lines(o))
        {
            if (!line.StartsWith('{')) continue;
            JournalEntry? e = TryParseJournalLine(line);
            if (e is not null) entries.Add(e);
        }
        return entries.ToArray();
    }
    #endregion

    #region Packages
    /// <summary>
    /// Installed packages parsed directly from <c>var/lib/dpkg/status</c> (no external dpkg binary). The status
    /// file has no install timestamp — use <see cref="PackageLogAsync"/> for the <em>when</em>. Returns null when
    /// the status file is unreadable (e.g. an RPM-based image, which this path does not cover).
    /// </summary>
    public async Task<LinuxPackage[]?> InstalledPackagesAsync(string rootDir, bool sudo = true)
    {
        var status = await CatAsync(Combine(rootDir, "var/lib/dpkg/status"), sudo);
        if (status is null) return null;
        var packages = new List<LinuxPackage>();
        foreach (var block in status.Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = ParseDebControl(block);
            if (!kv.TryGetValue("Package", out var name)) continue;
            var st = kv.GetValueOrDefault("Status");
            packages.Add(new LinuxPackage
            {
                Name = name,
                Version = kv.GetValueOrDefault("Version"),
                Architecture = kv.GetValueOrDefault("Architecture"),
                Status = st,
                Section = kv.GetValueOrDefault("Section"),
                Priority = kv.GetValueOrDefault("Priority"),
                Installed = st is not null && st.StartsWith("install", StringComparison.Ordinal) && st.EndsWith("installed", StringComparison.Ordinal),
            });
        }
        return packages.ToArray();
    }

    /// <summary>
    /// Package install/upgrade/remove timeline from <c>var/log/dpkg.log</c> (and rotated <c>dpkg.log.1</c>) plus
    /// <c>var/log/apt/history.log</c>. Only meaningful actions are returned (install/upgrade/remove/purge);
    /// dpkg's per-step "status"/"trigproc" noise is dropped. Returns null when no log is readable.
    /// </summary>
    public async Task<PackageEvent[]?> PackageLogAsync(string rootDir, bool sudo = true)
    {
        var dpkgFiles = await ReadGlobAsync($"{Combine(rootDir, "var/log/dpkg.log")} {Combine(rootDir, "var/log/dpkg.log.1")}", sudo);
        var aptFiles = await ReadGlobAsync($"{Combine(rootDir, "var/log/apt/history.log")} {Combine(rootDir, "var/log/apt/history.log.1")}", sudo);
        if (dpkgFiles.Count == 0 && aptFiles.Count == 0) return null;

        var events = new List<PackageEvent>();
        foreach (var (_, content) in dpkgFiles) events.AddRange(ParseDpkgLog(content));
        foreach (var (_, content) in aptFiles) events.AddRange(ParseAptHistory(content));
        return events.OrderBy(e => e.Timestamp ?? DateTime.MinValue).ToArray();
    }
    #endregion

    #region Shell history & malware
    /// <summary>
    /// Reads shell history for every human user (home dirs under <c>home/</c> plus <c>root/</c>):
    /// <c>.bash_history</c>, <c>.zsh_history</c>, <c>.python_history</c>, <c>.sh_history</c>. Bash
    /// <c>HISTTIMEFORMAT</c> epoch markers and zsh extended-history timestamps are parsed into
    /// <see cref="ShellHistoryEntry.Timestamp"/> when present. Returns the lines (empty when none), or null when
    /// no history file is readable.
    /// </summary>
    public async Task<ShellHistoryEntry[]?> ShellHistoryAsync(string rootDir, bool sudo = true)
    {
        string[] names = [".bash_history", ".zsh_history", ".python_history", ".sh_history"];
        var glob = string.Join(" ",
            names.Select(n => $"{Combine(rootDir, "root")}/{n}")
                 .Concat(names.Select(n => $"{Combine(rootDir, "home")}/*/{n}")));
        var files = await ReadGlobAsync(glob, sudo);
        if (files.Count == 0) return null;

        var entries = new List<ShellHistoryEntry>();
        foreach (var (path, content) in files)
            entries.AddRange(ParseShellHistory(path, content, HomeUser(path, rootDir)));
        return entries.ToArray();
    }

    /// <summary>
    /// Scans <paramref name="path"/> (a mounted root, a web root, a user home, …) with ClamAV
    /// (<c>clamscan -r -i --no-summary</c>) and returns only the infected files. A virus-found run (clamscan exit
    /// 1) is success here, not a failure. When ClamAV has no signature database loaded the result is empty and
    /// the workflow surfaces a note to run <c>freshclam</c>. Returns null only if clamscan could not be launched.
    /// </summary>
    public async Task<ClamAvMatch[]?> ClamScanAsync(string path, bool recurse = true, bool sudo = true)
    {
        // clamscan exits 1 when it finds a virus, which ExecuteToolText would treat as failure; run it through a
        // bash wrapper that always exits 0 and parse the "<path>: <sig> FOUND" lines from stdout.
        var clam = Tools["ClamScan"].Command;
        var script = $"{clam} {(recurse ? "-r " : "")}-i --no-summary {Q(path)}; true";
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
        var r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"echo {b64} | base64 -d | bash\"", sudo || Tools["ClamScan"].Sudo);
        if (!r.IsCompleted) return null;
        var matches = new List<ClamAvMatch>();
        foreach (var line in Lines(r.Output))
        {
            var m = Regex.Match(line, @"^(?<path>.*): (?<sig>.+) FOUND$");
            if (m.Success) matches.Add(new ClamAvMatch { Path = m.Groups["path"].Value, Signature = m.Groups["sig"].Value });
        }
        return matches.ToArray();
    }
    #endregion

    #region File anomalies
    // The printf format every find-based extractor emits: octal-mode \t owner \t group \t size \t mtime-epoch \t path.
    private const string FindFmt = @"-printf '%m\t%u\t%g\t%s\t%T@\t%p\n'";

    /// <summary>
    /// Finds SUID/SGID files under <paramref name="rootDir"/> (<c>find -xdev \( -perm -4000 -o -perm -2000 \)
    /// -type f</c>) — the set-user/group-id binaries an attacker plants or abuses for privilege escalation.
    /// Stays on one filesystem (<c>-xdev</c>) so it doesn't descend into other mounts. Returns null on failure.
    /// </summary>
    public Task<LinuxFile[]?> SetuidFilesAsync(string rootDir, bool sudo = true) =>
        FindFilesAsync($"{Q(rootDir)} -xdev \\( -perm -4000 -o -perm -2000 \\) -type f {FindFmt}", sudo);

    /// <summary>
    /// Finds world-writable files under <paramref name="rootDir"/> (<c>find -xdev -type f -perm -0002</c>) —
    /// files any user can overwrite, a tampering/backdoor vector when they live in system locations. Returns null
    /// on failure.
    /// </summary>
    public Task<LinuxFile[]?> WorldWritableFilesAsync(string rootDir, bool sudo = true) =>
        FindFilesAsync($"{Q(rootDir)} -xdev -type f -perm -0002 {FindFmt}", sudo);

    /// <summary>
    /// Lists every file directly under the given <paramref name="dirs"/> (e.g. <c>/tmp</c>, <c>/dev/shm</c>,
    /// <c>/var/tmp</c>) so the caller can flag executables staged in world-writable scratch space. Paths are taken
    /// as-is (already absolute, or join them under a mounted root yourself). Returns null on failure.
    /// </summary>
    public Task<LinuxFile[]?> FilesInDirsAsync(IEnumerable<string> dirs, bool sudo = true)
    {
        var paths = string.Join(" ", dirs.Select(Q));
        return paths.Length == 0 ? Task.FromResult<LinuxFile[]?>([]) : FindFilesAsync($"{paths} -type f {FindFmt}", sudo);
    }

    // Runs `find <expr>` (the caller supplies the whole expression incl. the FindFmt printf) and parses the rows.
    // find exits non-zero when it cannot read some entry but still prints the matches it found, so the output is
    // parsed regardless of exit code (mirroring DiskAnalysisToolkit.FindFilesAsync). stderr is discarded.
    private async Task<LinuxFile[]?> FindFilesAsync(string expr, bool sudo)
    {
        var script = $"find {expr} 2>/dev/null";
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
        var r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"echo {b64} | base64 -d | bash\"", sudo);
        if (r.Output.Length == 0) return r.IsCompleted ? [] : null;
        var files = new List<LinuxFile>();
        foreach (var line in Lines(r.Output))
        {
            var f = line.Split('\t');
            if (f.Length < 6) continue;
            var mode = f[0];
            long.TryParse(f[3], out var size);
            files.Add(new LinuxFile
            {
                Mode = mode,
                Owner = f[1],
                Group = f[2],
                Size = size,
                Modified = ParseEpoch(f[4]),
                Path = f[5],
                IsSetuid = mode.Length == 4 && mode[0] is '4' or '6' or '7',
                IsSetgid = mode.Length == 4 && mode[0] is '2' or '3' or '6' or '7',
                IsExecutable = HasExecBit(mode),
            });
        }
        return files.ToArray();
    }

    private static bool HasExecBit(string octal)
    {
        // Any of the user/group/other execute bits (1) set in the last three octal digits.
        var perm = octal.Length >= 3 ? octal[^3..] : octal;
        return perm.Any(c => c is '1' or '3' or '5' or '7');
    }

    private static DateTime? ParseEpoch(string s) =>
        double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var e)
            ? DateTimeOffset.FromUnixTimeMilliseconds((long)(e * 1000)).UtcDateTime : null;
    #endregion

    #region Parsing helpers
    // Parse a KEY=VALUE env file (os-release), stripping surrounding quotes from values.
    private static Dictionary<string, string> ParseEnvFile(string text)
    {
        var d = new Dictionary<string, string>();
        foreach (var line in Lines(text))
        {
            var i = line.IndexOf('=');
            if (i <= 0 || line.StartsWith('#')) continue;
            var key = line[..i].Trim();
            var val = line[(i + 1)..].Trim().Trim('"', '\'');
            d[key] = val;
        }
        return d;
    }

    // Derive a coarse, hash-free password state from passwd field 2 and the shadow hash/lastchg.
    private static (string state, DateTime? changed) PasswordState(string passwdField, string? shadowHash, string? lastChg)
    {
        DateTime? changed = null;
        if (long.TryParse(lastChg, out var days) && days > 0)
            changed = DateTime.UnixEpoch.AddDays(days);

        // The real secret lives in shadow when passwd field is "x"; otherwise passwd field carries it directly.
        var secret = shadowHash ?? (passwdField == "x" ? null : passwdField);
        if (shadowHash is null && passwdField == "x") return ("none", changed);   // says "see shadow" but no shadow entry
        if (secret is null) return ("none", changed);
        if (secret.Length == 0) return ("empty", changed);
        if (secret is "!" or "*" or "!!" || secret.StartsWith('!') || secret.StartsWith('*')) return ("locked", changed);
        if (secret.StartsWith('$')) return ("set", changed);
        return ("unknown", changed);
    }

    private static bool IsLoginShell(string shell) =>
        shell.Length > 0 && shell != "/dev/null" &&
        !shell.EndsWith("nologin", StringComparison.Ordinal) &&
        !shell.EndsWith("false", StringComparison.Ordinal) &&
        !shell.EndsWith("/sync", StringComparison.Ordinal) &&
        !shell.EndsWith("/true", StringComparison.Ordinal);

    // Parse crontab lines. systemFormat true => "min hr dom mon dow USER command" (or "@nick USER command");
    // false (user crontab) => "min hr dom mon dow command" (or "@nick command"), the user being the file owner.
    private static IEnumerable<CronEntry> ParseCron(string source, string content, bool systemFormat, string? user)
    {
        foreach (var raw in Lines(content))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (Regex.IsMatch(line, @"^[A-Za-z_][A-Za-z0-9_]*\s*=")) continue;   // env assignment (SHELL=, PATH=, MAILTO=)

            string? schedule, command, who = user;
            if (line.StartsWith('@'))
            {
                var parts = line.Split((char[]?)null, systemFormat ? 3 : 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < (systemFormat ? 3 : 2)) continue;
                schedule = parts[0];
                if (systemFormat) { who = parts[1]; command = parts[2]; }
                else command = parts[1];
            }
            else
            {
                var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                int min = systemFormat ? 6 : 5;
                if (fields.Length < min + 1) continue;
                schedule = string.Join(' ', fields.Take(5));
                if (systemFormat) { who = fields[5]; command = string.Join(' ', fields.Skip(6)); }
                else command = string.Join(' ', fields.Skip(5));
            }
            yield return new CronEntry
            {
                Source = source, User = who, Schedule = schedule, Command = command, Raw = line,
                IsReboot = schedule.Contains("@reboot", StringComparison.OrdinalIgnoreCase),
            };
        }
    }

    // Parse "last"/"lastb -F -i -w" output: anchor on the full date (Www Mmm D HH:MM:SS YYYY); everything before
    // it is user/line/host, everything after is the status/end. Drops the "<file> begins …" summary tail.
    private static readonly Regex LastDate = new(
        @"\b([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\b", RegexOptions.Compiled);

    private static LinuxLogin[] ParseLast(string output)
    {
        var logins = new List<LinuxLogin>();
        foreach (var line in Lines(output))
        {
            var m = LastDate.Match(line);
            if (!m.Success) continue;   // summary/blank lines
            var head = line[..m.Index].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (head.Length == 0) continue;
            var tail = line[(m.Index + m.Length)..].Trim();
            // head: user [line tokens…] host. With -i the host is the last token (an IP / 0.0.0.0).
            var user = head[0];
            var host = head.Length >= 2 ? head[^1] : null;
            var term = head.Length >= 3 ? string.Join(' ', head[1..^1]) : (head.Length == 2 ? null : null);
            logins.Add(new LinuxLogin
            {
                User = user,
                Terminal = term,
                Host = host,
                Start = ParseLastDate(m.Groups[1].Value),
                Status = tail.Length > 0 ? tail : null,
                StillLoggedIn = tail.Contains("still logged in", StringComparison.OrdinalIgnoreCase),
                Raw = line.Trim(),
            });
        }
        return logins.ToArray();
    }

    private static DateTime? ParseLastDate(string s)
    {
        s = Regex.Replace(s.Trim(), @"\s+", " ");
        return DateTime.TryParseExact(s, "ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt) ? dt : null;
    }

    private static DateTime? ParseUtmpTime(string s)
    {
        // utmpdump prints ISO-8601 with a comma decimal separator, e.g. 2026-06-08T13:14:11,776931+00:00.
        s = s.Replace(',', '.');
        return DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var o)
            ? o.UtcDateTime : null;
    }

    private static string UtmpType(int t) => t switch
    {
        0 => "EMPTY", 1 => "RUN_LVL", 2 => "BOOT_TIME", 3 => "NEW_TIME", 4 => "OLD_TIME",
        5 => "INIT_PROCESS", 6 => "LOGIN_PROCESS", 7 => "USER_PROCESS", 8 => "DEAD_PROCESS", 9 => "ACCOUNTING",
        _ => "UNKNOWN",
    };

    private static JournalEntry? TryParseJournalLine(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            string? s(string k) => root.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            int? i(string k) => int.TryParse(s(k), out var n) ? n : null;

            DateTime? ts = null;
            if (long.TryParse(s("__REALTIME_TIMESTAMP"), out var us))
                ts = DateTimeOffset.FromUnixTimeMilliseconds(us / 1000).UtcDateTime;

            return new JournalEntry
            {
                Timestamp = ts,
                Unit = s("_SYSTEMD_UNIT"),
                Identifier = s("SYSLOG_IDENTIFIER") ?? s("_COMM"),
                Pid = i("_PID"),
                Uid = i("_UID"),
                Priority = i("PRIORITY"),
                Hostname = s("_HOSTNAME"),
                Message = JournalMessage(root),
            };
        }
        catch (JsonException) { return null; }
    }

    // MESSAGE is usually a string but can be an array of byte values for binary/multiline payloads.
    private static string JournalMessage(JsonElement root)
    {
        if (!root.TryGetProperty("MESSAGE", out var msg)) return "";
        if (msg.ValueKind == JsonValueKind.String) return msg.GetString() ?? "";
        if (msg.ValueKind == JsonValueKind.Array)
        {
            var bytes = msg.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.Number)
                           .Select(e => (byte)e.GetInt32()).ToArray();
            return Encoding.UTF8.GetString(bytes);
        }
        return "";
    }

    // Parse a Debian control stanza ("Key: value", with continuation lines starting with a space).
    private static Dictionary<string, string> ParseDebControl(string block)
    {
        var d = new Dictionary<string, string>();
        string? key = null;
        foreach (var line in block.Split('\n'))
        {
            if (line.Length == 0) continue;
            if ((line[0] == ' ' || line[0] == '\t') && key is not null) continue;   // folded continuation — ignore
            var i = line.IndexOf(':');
            if (i <= 0) continue;
            key = line[..i].Trim();
            d[key] = line[(i + 1)..].Trim();
        }
        return d;
    }

    // dpkg.log: "YYYY-MM-DD HH:MM:SS <action> <pkg:arch> <v1> [<v2>]". Keep install/upgrade/remove/purge.
    private static IEnumerable<PackageEvent> ParseDpkgLog(string content)
    {
        foreach (var line in Lines(content))
        {
            var f = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 5) continue;
            var action = f[2];
            if (action is not ("install" or "upgrade" or "remove" or "purge")) continue;
            var ts = ParseDpkgTime(f[0], f[1]);
            var pkg = f[3].Split(':')[0];
            string? v1 = f.Length > 4 ? NoneToNull(f[4]) : null;
            string? v2 = f.Length > 5 ? NoneToNull(f[5]) : null;
            yield return new PackageEvent
            {
                Timestamp = ts, Action = action, Package = pkg, Source = "dpkg.log",
                Version = action is "install" or "upgrade" ? v2 ?? v1 : v1,
                PreviousVersion = action == "upgrade" ? v1 : null,
            };
        }
    }

    // apt/history.log: blocks of "Start-Date:", "Commandline:", "Install:/Upgrade:/Remove:/Purge:", "End-Date:".
    private static IEnumerable<PackageEvent> ParseAptHistory(string content)
    {
        foreach (var block in content.Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
        {
            DateTime? ts = null;
            var sd = Regex.Match(block, @"Start-Date:\s*(.+)");
            if (sd.Success && DateTime.TryParse(sd.Groups[1].Value.Trim(), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)) ts = d;
            foreach (var (label, action) in new[] { ("Install", "install"), ("Upgrade", "upgrade"), ("Remove", "remove"), ("Purge", "purge") })
            {
                var m = Regex.Match(block, $@"^{label}:\s*(.+)$", RegexOptions.Multiline);
                if (!m.Success) continue;
                // "name:arch (ver), name2:arch (old, new), …" — split on commas that precede a "name (" token.
                foreach (var item in SplitAptItems(m.Groups[1].Value))
                {
                    var pm = Regex.Match(item.Trim(), @"^(?<name>\S+?)(?::\S+)?\s*\((?<vers>[^)]*)\)");
                    if (!pm.Success) continue;
                    var vers = pm.Groups["vers"].Value.Split(',').Select(x => x.Trim()).ToArray();
                    yield return new PackageEvent
                    {
                        Timestamp = ts, Action = action, Package = pm.Groups["name"].Value, Source = "apt/history.log",
                        Version = vers.Length > 1 ? vers[1] : vers.FirstOrDefault(),
                        PreviousVersion = action == "upgrade" && vers.Length > 1 ? vers[0] : null,
                    };
                }
            }
        }
    }

    // Split an apt history package list on top-level commas (commas inside "(...)" are version separators).
    private static IEnumerable<string> SplitAptItems(string s)
    {
        int depth = 0, start = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '(') depth++;
            else if (s[i] == ')') depth--;
            else if (s[i] == ',' && depth == 0) { yield return s[start..i]; start = i + 1; }
        }
        if (start < s.Length) yield return s[start..];
    }

    private static DateTime? ParseDpkgTime(string date, string time) =>
        DateTime.TryParse($"{date} {time}", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt) ? dt : null;

    private static IEnumerable<ShellHistoryEntry> ParseShellHistory(string path, string content, string user)
    {
        var lines = content.Split('\n');
        DateTime? pendingTs = null;
        int n = 0;
        for (int idx = 0; idx < lines.Length; idx++)
        {
            var line = lines[idx].TrimEnd('\r');
            if (line.Length == 0) continue;

            // bash HISTTIMEFORMAT marker: a line that is just "#<epoch>" preceding the command.
            if (Regex.IsMatch(line, @"^#\d{9,11}$"))
            {
                pendingTs = DateTime.UnixEpoch.AddSeconds(long.Parse(line[1..]));
                continue;
            }
            // zsh extended history: ": <epoch>:<elapsed>;<command>".
            var z = Regex.Match(line, @"^: (?<ts>\d{9,11}):\d+;(?<cmd>.*)$");
            DateTime? ts = pendingTs;
            string cmd = line;
            if (z.Success) { ts = DateTime.UnixEpoch.AddSeconds(long.Parse(z.Groups["ts"].Value)); cmd = z.Groups["cmd"].Value; }
            pendingTs = null;

            yield return new ShellHistoryEntry
            {
                User = user, HistoryFile = path, LineNumber = ++n, Command = cmd, Timestamp = ts,
            };
        }
    }

    private static string? NoneToNull(string v) => v is "<none>" or "-" ? null : v;
    private static string FileName(string path) => path.TrimEnd('/').Split('/').LastOrDefault() ?? path;

    // Infer the owning user from a history-file path: /home/<u>/… => u; /root/… => root.
    private static string HomeUser(string path, string rootDir)
    {
        var rel = path.StartsWith(rootDir.TrimEnd('/')) ? path[rootDir.TrimEnd('/').Length..] : path;
        var m = Regex.Match(rel, @"/home/([^/]+)/");
        return m.Success ? m.Groups[1].Value : "root";
    }
    #endregion

    #region I/O helpers
    /// <summary>
    /// Reads every file matching the given (shell-expanded) <paramref name="paths"/> — literal paths and/or globs
    /// — under sudo by default, returning a list of (path, content) pairs in directory order. Non-existent
    /// members are silently skipped. Intended for the higher-level workflows to slurp small artifact files
    /// (systemd units, <c>rc.local</c>, shell rc files, <c>ld.so.preload</c>, <c>authorized_keys</c>, udev rules)
    /// in one round trip without each needing a bespoke toolkit method.
    /// </summary>
    public Task<List<(string Path, string Content)>> ReadFilesAsync(IEnumerable<string> paths, bool sudo = true) =>
        ReadGlobAsync(string.Join(" ", paths), sudo);

    /// <summary>Reads a single file via <c>cat</c>, returning its content or null on failure.</summary>
    private async Task<string?> CatAsync(string path, bool sudo)
    {
        var r = await auditEnvironment.ExecuteCommandAsync("cat", Q(path), sudo);
        return r.IsCompleted ? r.Output : null;
    }

    /// <summary>
    /// Reads every file matching a (space-separated, shell-expanded) <paramref name="glob"/> in one round trip,
    /// returning (path, content) pairs in directory order. Each file's content is delimited with a SOH marker so
    /// multiple files come back in a single command. Non-existent glob members are silently skipped.
    /// </summary>
    private async Task<List<(string Path, string Content)>> ReadGlobAsync(string glob, bool sudo)
    {
        // Base64 the script so the glob/quoting never fights the SSH command shell (same trick as the EZ-tools
        // downloader). Each file is prefixed with a SOH byte + "<path>\n" then its bytes, so files come back in a
        // single command and split cleanly on the SOH delimiter (which text artifacts never contain).
        var script = $"for f in {glob}; do [ -f \"$f\" ] || continue; printf '\\001%s\\n' \"$f\"; cat -- \"$f\"; done";
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
        var r = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"echo {b64} | base64 -d | bash\"", sudo);
        var result = new List<(string, string)>();
        if (!r.IsCompleted || r.Output.Length == 0) return result;
        foreach (var chunk in r.Output.Split('', StringSplitOptions.RemoveEmptyEntries))
        {
            var nl = chunk.IndexOf('\n');
            if (nl < 0) continue;
            result.Add((chunk[..nl], chunk[(nl + 1)..]));
        }
        return result;
    }

    /// <summary>Runs tool <paramref name="name"/>, forcing sudo when the per-call flag or the config default is set.</summary>
    private async Task<string?> RunAsync(string name, string args, bool sudo)
    {
        var r = await auditEnvironment.ExecuteCommandAsync(Tools[name].Command, args, Tools[name].Sudo || sudo);
        if (r.IsCompleted) return r.Output;
        Error($"Failed to execute tool command {Tools[name].Command} {args}: {r.Output}.");
        return null;
    }

    private static string Q(string path) => $"'{path.Replace("'", "'\\''")}'";

    // Join a mounted-root path with a relative artifact path: Combine("/", "etc/passwd") => "/etc/passwd";
    // Combine("/mnt/img", "etc/passwd") => "/mnt/img/etc/passwd".
    private static string Combine(string root, string rel) => root.TrimEnd('/') + "/" + rel.TrimStart('/');

    private static IEnumerable<string> Lines(string? text) =>
        text is null ? [] : text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    #endregion
}
