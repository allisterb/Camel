using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Camel.Environments;
using Microsoft.Extensions.Configuration;

namespace Camel.Toolkits;

public record Tool
{
    public string Name { get; init; }
    public string Descriptioon { get; init; }
    public string Command { get; init; }
    public bool Sudo { get; init; } = false;

    /// <summary>
    /// False when the active platform's config supplied no Command for this logical tool — i.e. the tool is
    /// not present on this distro. Methods that need it degrade (see <see cref="Toolkit.IsToolAvailable"/> and
    /// the <c>ExecuteTool*</c> guards) instead of running a command with an empty path.
    /// </summary>
    public bool Available => !string.IsNullOrWhiteSpace(Command);

    public Tool(string name, string description, string command, bool sudo = false)
    {
        this.Name = name;
        this.Descriptioon = description;
        this.Command = command;
        this.Sudo = sudo;
    }
}

public abstract class Toolkit : Runtime
{
    #region Constructors
    public Toolkit(string name, AuditEnvironment env, IConfigurationRoot? config = null)
    {
        this.name = name;
        this.auditEnvironment = env;
        config = config ?? Runtime.config;
        if (config is null)
        {
            throw new Exception("Configuration file not loaded");
        }
        // The active platform (SIFT / Kali / PTF / …) names the config profile holding this distro's tool
        // definitions; it defaults to SIFT. Tools live under {platform}:Tools:{name}, falling back to the
        // legacy top-level Tools:{name} so existing single-distro configs keep working unchanged. GetSection
        // never throws, so a platform that has no tools for this toolkit yields an empty section — the toolkit
        // constructs inert (every tool unavailable) rather than crashing the session.
        this.platform = config["Platform"] ?? "SIFT";
        toolConfig = config.GetSection($"{platform}:Tools:{name}");
        if (!toolConfig.Exists()) toolConfig = config.GetSection($"Tools:{name}");
        foreach (string toolName in ToolList)
        {
            Tools[toolName] = GetTool(toolName);
        }
        InstallMissingTools();
    }
    #endregion

    #region Properties
    public abstract string[] ToolList { get; }
    public Dictionary<string, Tool> Tools { get; } = new Dictionary<string, Tool>();
    #endregion

    #region Methods
    // Builds a Tool from the active platform's config. A tool with no Command on this platform is returned as
    // *unavailable* (empty Command) rather than throwing, so the toolkit tolerates a distro that lacks it.
    public Tool GetTool(string name)
    {
        var command = toolConfig[$"{name}:Command"];
        return string.IsNullOrWhiteSpace(command)
            ? new Tool(name, toolConfig[$"{name}:Description"] ?? "", "", false)
            : new Tool(name, toolConfig[$"{name}:Description"] ?? "", command, bool.Parse(toolConfig[$"{name}:Sudo"] ?? "false"));
    }

    /// <summary>
    /// True when <paramref name="name"/> has a runnable command on the active platform. A toolkit method or
    /// workflow can branch on this to skip a step the current distro can't perform, instead of emitting a
    /// guaranteed failure. Unknown names (not in <see cref="ToolList"/>) report unavailable.
    /// </summary>
    public bool IsToolAvailable(string name) => Tools.TryGetValue(name, out var t) && t.Available;

    // Records a capability gap (a tool absent on the active platform) to the per-case audit trail and logs it;
    // the ExecuteTool* guards then return null instead of running a command with an empty path. This turns a
    // distro that lacks a tool into a clean, traceable degrade rather than a confusing execution failure.
    private void ReportToolUnavailable(string name)
    {
        using var _tk = PushAuditProperty("Toolkit", this.name);
        AuditEvent("capability-unavailable",
            "Tool '{Tool}' is not available on platform '{Platform}' (toolkit {Toolkit}).", name, platform, this.name);
        Error($"Tool '{name}' is not available on platform '{platform}'.");
    }

    /// <summary>
    /// Called at the end of the base constructor. Override in a derived toolkit to download/install any
    /// tools that are missing from the current SIFT workstation. The base implementation does nothing.
    /// </summary>
    protected virtual void InstallMissingTools() { }

    /// <summary>
    /// Installs an Eric Zimmerman .NET tool from its download-server zip into <c>/opt/zimmermantools</c>:
    /// downloads <paramref name="url"/> with wget, unzips it, and moves its contents into the tools dir
    /// (some zips contain a tool subfolder, e.g. <c>RECmd/</c>, others loose files, e.g. <c>PECmd.dll</c> —
    /// moving the extracted contents handles both). Skipped when <paramref name="checkPath"/> already
    /// exists. Returns true when the tool is present afterwards (already-installed or freshly installed).
    /// </summary>
    protected bool InstallZimmermanTool(string name, string url, string checkPath)
    {
        if (auditEnvironment.ExecuteCommand("test", $"-e {checkPath}", out _, false))
            return true; // already installed — nothing to do

        Info($"Installing missing tool {name} from {url} ...");
        string zip = $"/tmp/camel_ez_{name}.zip", extract = $"/tmp/camel_ez_{name}";
        try
        {
            if (!auditEnvironment.ExecuteCommand("wget", $"-q {url} -O {zip}", out string dl, false))
            { Error($"Failed to download {name}: {dl}"); return false; }
            auditEnvironment.ExecuteCommand("rm", $"-rf {extract}", out _, false);
            if (!auditEnvironment.ExecuteCommand("unzip", $"-o -q {zip} -d {extract}", out string uz, false))
            { Error($"Failed to unzip {name}: {uz}"); return false; }
            auditEnvironment.ExecuteCommand("mkdir", "-p /opt/zimmermantools", out _, true);
            if (!auditEnvironment.ExecuteCommand("mv", $"-f {extract}/* /opt/zimmermantools/", out string mv, true))
            { Error($"Failed to install {name}: {mv}"); return false; }
            Info($"Installed {name} to /opt/zimmermantools.");
            return auditEnvironment.ExecuteCommand("test", $"-e {checkPath}", out _, false);
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-rf {zip} {extract}", out _, false); }
    }

    /// <summary>
    /// Downloads a single file from <paramref name="url"/> to <paramref name="destPath"/> on the
    /// workstation with wget (under sudo, since the tools directory is typically root-owned), unless it
    /// already exists. Used for auxiliary files a tool needs alongside its install (e.g. RECmd batch
    /// files). Returns true when the file is present afterwards.
    /// </summary>
    protected bool InstallFile(string name, string url, string destPath)
    {
        if (auditEnvironment.ExecuteCommand("test", $"-e {destPath}", out _, false))
            return true; // already present — nothing to do

        Info($"Downloading {name} from {url} ...");
        if (!auditEnvironment.ExecuteCommand("wget", $"-q {url} -O {destPath}", out string dl, true))
        { Error($"Failed to download {name}: {dl}"); return false; }
        return auditEnvironment.ExecuteCommand("test", $"-e {destPath}", out _, false);
    }

    /// <summary>
    /// Installs the apt package <paramref name="package"/> on the workstation (<c>apt-get install -y</c>
    /// under sudo), unless the command at <paramref name="checkPath"/> already exists. Returns true when
    /// the command is present afterwards.
    /// </summary>
    protected bool InstallAptPackage(string package, string checkPath)
    {
        if (auditEnvironment.ExecuteCommand("test", $"-e {checkPath}", out _, false))
            return true; // already installed — nothing to do

        Info($"Installing missing apt package {package} ...");
        // Refresh package lists first — a fresh SIFT image often has a stale/empty apt cache, which makes
        // 'apt-get install' fail with "Unable to locate package".
        auditEnvironment.ExecuteCommand("apt-get", "update", out _, true);
        if (!auditEnvironment.ExecuteCommand("apt-get", $"install -y {package}", out string o, true))
        { Error($"Failed to install apt package {package}: {o}"); return false; }
        return auditEnvironment.ExecuteCommand("test", $"-e {checkPath}", out _, false);
    }

    /// <summary>
    /// Installs a tool shipped as a release zip (e.g. a GitHub release with a binary alongside its data
    /// directories): downloads <paramref name="url"/>, extracts it into <paramref name="installDir"/>, marks
    /// the binary <c>&lt;installDir&gt;/&lt;binary&gt;</c> executable, and symlinks it to <paramref name="linkPath"/>
    /// on the PATH (so the tool resolves its sibling rules/config directories from the install dir). Skipped
    /// when <paramref name="linkPath"/> already exists. Returns true when the tool is present afterwards.
    /// </summary>
    /// <summary>
    /// Clones a GitHub repository's default-branch contents into <paramref name="installDir"/> by downloading
    /// its codeload zip (<c>https://github.com/&lt;owner&gt;/&lt;repo&gt;/archive/refs/heads/&lt;branch&gt;.zip</c>),
    /// extracting it, and moving the contents of the single top-level <c>&lt;repo&gt;-&lt;branch&gt;</c> folder
    /// the archive contains into the install directory (so callers see <c>installDir/&lt;file&gt;</c> rather
    /// than <c>installDir/&lt;repo&gt;-&lt;branch&gt;/&lt;file&gt;</c>). Skipped when <paramref name="checkPath"/>
    /// already exists. Use this for reference datasets shipped as a GitHub repo (rules packs, signature
    /// databases, indicator collections). Returns true when the install is present afterwards.
    /// </summary>
    protected bool InstallGithubRepoZip(string name, string url, string installDir, string checkPath)
    {
        if (auditEnvironment.ExecuteCommand("test", $"-e {checkPath}", out _, false))
            return true; // already installed — nothing to do

        Info($"Installing missing repo {name} from {url} ...");
        string zip = $"/tmp/camel_repo_{name}.zip", extract = $"/tmp/camel_repo_{name}";
        try
        {
            if (!auditEnvironment.ExecuteCommand("wget", $"-q {url} -O {zip}", out string dl, false))
            { Error($"Failed to download {name}: {dl}"); return false; }
            auditEnvironment.ExecuteCommand("rm", $"-rf {extract}", out _, false);
            if (!auditEnvironment.ExecuteCommand("unzip", $"-o -q {zip} -d {extract}", out string uz, false))
            { Error($"Failed to unzip {name}: {uz}"); return false; }
            auditEnvironment.ExecuteCommand("mkdir", $"-p {installDir}", out _, true);
            // GitHub codeload archives contain a single top-level <repo>-<branch>/ folder; flatten it into
            // installDir so callers don't have to know the branch name. Glob expansion happens in the shell.
            if (!auditEnvironment.ExecuteCommand("bash",
                    $"-c \"mv -f {extract}/*/* {installDir}/\"", out string mv, true))
            { Error($"Failed to install {name}: {mv}"); return false; }
            Info($"Installed {name} to {installDir}.");
            return auditEnvironment.ExecuteCommand("test", $"-e {checkPath}", out _, false);
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-rf {zip} {extract}", out _, false); }
    }

    protected bool InstallZipRelease(string name, string url, string installDir, string binary, string linkPath)
    {
        if (auditEnvironment.ExecuteCommand("test", $"-e {linkPath}", out _, false))
            return true; // already installed — nothing to do

        Info($"Installing missing tool {name} from {url} ...");
        string zip = $"/tmp/camel_zip_{name}.zip";
        try
        {
            if (!auditEnvironment.ExecuteCommand("wget", $"-q {url} -O {zip}", out string dl, false))
            { Error($"Failed to download {name}: {dl}"); return false; }
            auditEnvironment.ExecuteCommand("mkdir", $"-p {installDir}", out _, true);
            if (!auditEnvironment.ExecuteCommand("unzip", $"-o -q {zip} -d {installDir}", out string uz, true))
            { Error($"Failed to unzip {name}: {uz}"); return false; }
            auditEnvironment.ExecuteCommand("chmod", $"+x {installDir}/{binary}", out _, true);
            auditEnvironment.ExecuteCommand("ln", $"-sf {installDir}/{binary} {linkPath}", out _, true);
            Info($"Installed {name} to {installDir}.");
            return auditEnvironment.ExecuteCommand("test", $"-e {linkPath}", out _, false);
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-f {zip}", out _, false); }
    }

    public T? ExecuteTool<T>(string name, string args) where T : class
    {
        if (!Tools[name].Available) { ReportToolUnavailable(name); return null; }
        if (auditEnvironment.ExecuteCommand(Tools[name].Command, args, out string output, Tools[name].Sudo))
        {
            return System.Text.Json.JsonSerializer.Deserialize<T>(output);
        }
        else
        {
            Error($"Failed to execute tool command ${Tools[name].Command} {args}: {output}.");
            return null;
        }
    }

    /// <summary>
    /// Execute a tool that emits plain-text (non-JSON) output and return its raw stdout,
    /// or null if the command failed. Used by tools (e.g. The Sleuth Kit / EWF) that do
    /// not support structured JSON output.
    /// </summary>
    public string? ExecuteToolText(string name, string args)
    {
        if (!Tools[name].Available) { ReportToolUnavailable(name); return null; }
        using var _tk = PushAuditProperty("Toolkit", this.name);
        using var _op = PushAuditProperty("Operation", name);
        if (auditEnvironment.ExecuteCommand(Tools[name].Command, args, out string output, Tools[name].Sudo))
        {
            return output;
        }
        else
        {
            Error($"Failed to execute tool command ${Tools[name].Command} {args}: {output}.");
            return null;
        }
    }

    /// <summary>
    /// Runs a tool that writes JSON-lines output to a directory (EZ Tools <c>--json</c>), reads the
    /// produced file, and deserializes each line to <typeparamref name="T"/>. Returns an empty array
    /// when the tool produced no records, or null when the command itself failed.
    /// </summary>
    public T[]? ExecuteToolJson<T>(string name, string args, string pattern = "*.json")
    {
        string dir = "/tmp/camel_ez_" + Guid.NewGuid().ToString("N");
        auditEnvironment.ExecuteCommand("mkdir", $"-p {dir}", out _, false);
        try
        {
            if (ExecuteToolText(name, $"{args} --json {dir}") is null) return null;
            if (!auditEnvironment.ExecuteCommand("cat", $"{dir}/{pattern}", out string json, false)) return [];
            return ParseJsonLines<T>(json);
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-rf {dir}", out _, false); }
    }

    /// <summary>
    /// Runs a tool that writes JSON-lines output to a single file (the tool's own <c>-w</c>/output flag),
    /// reads it, and deserializes each line to <typeparamref name="T"/>. <paramref name="buildArgs"/> is
    /// given the temp output-file path and returns the full argument string. Used by Plaso (psort/psteal).
    /// </summary>
    public T[]? ExecuteToolJsonLinesFile<T>(string name, Func<string, string> buildArgs)
    {
        string file = "/tmp/camel_jl_" + Guid.NewGuid().ToString("N") + ".jsonl";
        try
        {
            if (ExecuteToolText(name, buildArgs(file)) is null) return null;
            if (!auditEnvironment.ExecuteCommand("cat", file, out string json, false)) return [];
            return ParseJsonLines<T>(json);
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-f {file}", out _, false); }
    }

    private static readonly System.Text.Json.JsonSerializerOptions JsonLineOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>Parses newline-delimited JSON (one object per line) into <typeparamref name="T"/>[].</summary>
    protected static T[] ParseJsonLines<T>(string json) =>
        json.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.TrimStart('﻿'))   // some tools (e.g. EvtxECmd) prefix the file with a BOM
            .Where(l => l.StartsWith('{'))
            .Select(l => System.Text.Json.JsonSerializer.Deserialize<T>(l, JsonLineOptions))
            .Where(x => x is not null).Select(x => x!).ToArray();

    /// <summary>Streams newline-delimited JSON from a local file (read lazily, line by line) into
    /// <typeparamref name="T"/>[] — avoids materializing a large export as one in-memory string.</summary>
    protected static T[] ParseJsonLinesFile<T>(string localPath) =>
        System.IO.File.ReadLines(localPath)
            .Select(l => l.Trim().TrimStart('﻿'))
            .Where(l => l.StartsWith('{'))
            .Select(l => System.Text.Json.JsonSerializer.Deserialize<T>(l, JsonLineOptions))
            .Where(x => x is not null).Select(x => x!).ToArray();

    /// <summary>
    /// Runs a tool that writes CSV output to a directory (EZ Tools <c>--csv</c>), reads the produced
    /// file, and maps each row (keyed by header column) with <paramref name="map"/>. Returns an empty
    /// array when no rows were produced, or null when the command itself failed.
    /// </summary>
    public T[]? ExecuteToolCsv<T>(string name, string args, Func<IReadOnlyDictionary<string, string>, T> map, string pattern = "*.csv")
    {
        string dir = "/tmp/camel_ez_" + Guid.NewGuid().ToString("N");
        auditEnvironment.ExecuteCommand("mkdir", $"-p {dir}", out _, false);
        try
        {
            if (ExecuteToolText(name, $"{args} --csv {dir}") is null) return null;
            if (!auditEnvironment.ExecuteCommand("cat", $"{dir}/{pattern}", out string csv, false)) return [];
            return ParseCsv(csv).Select(map).ToArray();
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-rf {dir}", out _, false); }
    }

    /// <summary>
    /// Runs a tool that writes a single CSV file (the tool's own <c>-o</c>/output flag), reads it, and maps
    /// each row (keyed by header column) with <paramref name="map"/>. <paramref name="buildArgs"/> is given
    /// the temp output-file path. Used by hayabusa metrics subcommands.
    /// </summary>
    public T[]? ExecuteToolCsvFile<T>(string name, Func<string, string> buildArgs, Func<IReadOnlyDictionary<string, string>, T> map)
    {
        string file = "/tmp/camel_csv_" + Guid.NewGuid().ToString("N") + ".csv";
        try
        {
            if (ExecuteToolText(name, buildArgs(file)) is null) return null;
            if (!auditEnvironment.ExecuteCommand("cat", file, out string csv, false)) return [];
            return ParseCsv(csv).Select(map).ToArray();
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-f {file}", out _, false); }
    }

    public async Task<T?> ExecuteToolAsync<T>(string name, string args) where T : class
    {
        if (!Tools[name].Available) { ReportToolUnavailable(name); return null; }
        var r = await auditEnvironment.ExecuteCommandAsync(Tools[name].Command, args, Tools[name].Sudo);
        if (r.IsCompleted)
        {
            return System.Text.Json.JsonSerializer.Deserialize<T>(r.Output);
        }
        else
        {
            Error($"Failed to execute tool command ${Tools[name].Command} {args}: {r.Output}.");
            return null;
        }
    }

    /// <summary>
    /// Execute a tool that emits plain-text (non-JSON) output and return its raw stdout,
    /// or null if the command failed. Used by tools (e.g. The Sleuth Kit / EWF) that do
    /// not support structured JSON output.
    /// </summary>
    public async Task<string?> ExecuteToolTextAsync(string name, string args)
    {
        if (!Tools[name].Available) { ReportToolUnavailable(name); return null; }
        // Attribute the command(s) this runs to this toolkit and tool in the audit trail. The scopes bracket the
        // awaited execution so the properties flow onto the command-execution event emitted in the environment.
        using var _tk = PushAuditProperty("Toolkit", this.name);
        using var _op = PushAuditProperty("Operation", name);
        var r = await auditEnvironment.ExecuteCommandAsync(Tools[name].Command, args, Tools[name].Sudo);
        if (r.IsCompleted)
        {
            return r.Output;
        }
        else
        {
            Error($"Failed to execute tool command ${Tools[name].Command} {args}: {r.Output}.");
            return null;
        }
    }

    /// <summary>
    /// Runs a tool that writes JSON-lines output to a directory (EZ Tools <c>--json</c>), reads the
    /// produced file, and deserializes each line to <typeparamref name="T"/>. Returns an empty array
    /// when the tool produced no records, or null when the command itself failed.
    /// </summary>
    public async Task<T[]?> ExecuteToolJsonAsync<T>(string name, string args, string pattern = "*.json")
    {
        string dir = "/tmp/camel_ez_" + Guid.NewGuid().ToString("N");
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {dir}", false);
        try
        {
            if (await ExecuteToolTextAsync(name, $"{args} --json {dir}") is null) return null;
            return await DownloadJsonLinesAsync<T>(dir, pattern);
        }
        // Sync ExecuteCommand has no cancellation token, so cleanup runs even after the async work was
        // cancelled; guarded so a teardown failure can never mask the method's result.
        finally { try { auditEnvironment.ExecuteCommand("rm", $"-rf {dir}", out _, false); } catch { } }
    }

    /// <summary>
    /// Reads the JSON-lines file(s) an EZ tool wrote into <paramref name="dir"/> by SCP-ing each down and
    /// stream-parsing it from disk, rather than <c>cat</c>-ing it back through the SSH stdout channel. A large
    /// export (EvtxECmd on a multi-hundred-MB EVTX, MFTECmd on a big <c>$MFT</c>) buffers the whole file into one
    /// in-memory string and can take many minutes — even hang — through stdout; the binary file transfer is far
    /// faster and never holds the whole export in memory or on the wire at once. Returns an empty array when the
    /// tool produced no file.
    /// </summary>
    protected async Task<T[]> DownloadJsonLinesAsync<T>(string dir, string pattern)
    {
        // EZ tools embed the source artifact in the output filename (e.g. "..._$MFT_Output.json"). A '$' in the
        // remote path would be expanded by the shell the SCP client opens its copy channel through, so the
        // download would look for the wrong (empty) name. Rename every produced file to a shell-safe sequential
        // name first — shipped base64 to dodge all quoting — then transfer those by path. (The old cat-the-glob
        // path sidestepped this by never naming the file, but buffered the whole export through stdout.)
        var script = $"i=0; for f in {dir}/{pattern}; do [ -e \"$f\" ] || continue; mv -- \"$f\" {dir}/camel_dl_$i.jsonl; i=$((i+1)); done";
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(script));
        await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"echo {b64} | base64 -d | bash\"", false);

        var ls = await auditEnvironment.ExecuteCommandAsync("bash", $"-c \"ls -1 {dir}/camel_dl_*.jsonl 2>/dev/null\"", false);
        if (!ls.IsCompleted) return [];
        var results = new List<T>();
        foreach (var remote in ls.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            // SCP the file down (a binary stream — far faster than capturing a huge file through stdout) and
            // stream-parse it from disk, so neither the wire nor memory holds the whole export at once.
            string local = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "camel_ez_" + Guid.NewGuid().ToString("N") + ".jsonl");
            try
            {
                if (auditEnvironment.GetFileAsLocal(remote, local) is not null)
                    results.AddRange(ParseJsonLinesFile<T>(local));
            }
            finally { try { System.IO.File.Delete(local); } catch { } }
        }
        return [.. results];
    }

    /// <summary>
    /// Runs a tool that writes JSON-lines output to a single file (the tool's own <c>-w</c>/output flag),
    /// reads it, and deserializes each line to <typeparamref name="T"/>. <paramref name="buildArgs"/> is
    /// given the temp output-file path and returns the full argument string. Used by Plaso (psort/psteal).
    /// </summary>
    public async Task<T[]?> ExecuteToolJsonLinesFileAsync<T>(string name, Func<string, string> buildArgs)
    {
        string file = "/tmp/camel_jl_" + Guid.NewGuid().ToString("N") + ".jsonl";
        try
        {
            if (await ExecuteToolTextAsync(name, buildArgs(file)) is null) return null;
            var r = await auditEnvironment.ExecuteCommandAsync("cat", file, false);
            if (!r.IsCompleted) return [];
            return ParseJsonLines<T>(r.Output);
        }
        // Sync ExecuteCommand has no cancellation token, so cleanup runs even after the async work was
        // cancelled; guarded so a teardown failure can never mask the method's result.
        finally { try { auditEnvironment.ExecuteCommand("rm", $"-f {file}", out _, false); } catch { } }
    }
    
    /// <summary>
    /// Runs a tool that writes CSV output to a directory (EZ Tools <c>--csv</c>), reads the produced
    /// file, and maps each row (keyed by header column) with <paramref name="map"/>. Returns an empty
    /// array when no rows were produced, or null when the command itself failed.
    /// </summary>
    public async Task<T[]?> ExecuteToolCsvAsync<T>(string name, string args, Func<IReadOnlyDictionary<string, string>, T> map, string pattern = "*.csv")
    {
        string dir = "/tmp/camel_ez_" + Guid.NewGuid().ToString("N");
        await auditEnvironment.ExecuteCommandAsync("mkdir", $"-p {dir}", false);
        try
        {
            if (await ExecuteToolTextAsync(name, $"{args} --csv {dir}") is null) return null;
            var r = await auditEnvironment.ExecuteCommandAsync("cat", $"{dir}/{pattern}", false);
            if (!r.IsCompleted) return [];
            return ParseCsv(r.Output).Select(map).ToArray();
        }
        // Sync ExecuteCommand has no cancellation token, so cleanup runs even after the async work was
        // cancelled; guarded so a teardown failure can never mask the method's result.
        finally { try { auditEnvironment.ExecuteCommand("rm", $"-rf {dir}", out _, false); } catch { } }
    }

    /// <summary>
    /// Runs a tool that writes a single CSV file (the tool's own <c>-o</c>/output flag), reads it, and maps
    /// each row (keyed by header column) with <paramref name="map"/>. <paramref name="buildArgs"/> is given
    /// the temp output-file path. Used by hayabusa metrics subcommands.
    /// </summary>
    public async Task<T[]?> ExecuteToolCsvFileAsync<T>(string name, Func<string, string> buildArgs, Func<IReadOnlyDictionary<string, string>, T> map)
    {
        string file = "/tmp/camel_csv_" + Guid.NewGuid().ToString("N") + ".csv";
        try
        {
            if (await ExecuteToolTextAsync(name, buildArgs(file)) is null) return null;
            var r = await auditEnvironment.ExecuteCommandAsync("cat", file, false);
            if (!r.IsCompleted) return [];
            return ParseCsv(r.Output).Select(map).ToArray();
        }
        // Sync ExecuteCommand has no cancellation token, so cleanup runs even after the async work was
        // cancelled; guarded so a teardown failure can never mask the method's result.
        finally { try { auditEnvironment.ExecuteCommand("rm", $"-f {file}", out _, false); } catch { } }
    }

    /// <summary>Reads a CSV file on the audit environment and maps its rows; null on read failure.</summary>
    public T[]? ReadCsvFile<T>(string path, Func<IReadOnlyDictionary<string, string>, T> map) =>
        auditEnvironment.ExecuteCommand("cat", $"'{path}'", out string csv, false) ? ParseCsv(csv).Select(map).ToArray() : null;

    /// <summary>Reads a CSV file on the audit environment and maps its rows; null on read failure.</summary>
    public async Task<T[]?> ReadCsvFileAsync<T>(string path, Func<IReadOnlyDictionary<string, string>, T> map)
    {
        var r = await auditEnvironment.ExecuteCommandAsync("cat", $"'{path}'", false);
        if (r.IsCompleted)
        {
            return ParseCsv(r.Output).Select(map).ToArray();
        }
        else return null;
    }

    /// <summary>Parses CSV text (RFC4180-style quoting) into rows keyed by the header columns.</summary>
    public static IReadOnlyDictionary<string, string>[] ParseCsv(string text)
    {
        var records = new List<string[]>();
        var fields = new List<string>();
        var sb = new StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < text.Length && text[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQuotes = false;
                }
                else sb.Append(c);
            }
            else if (c == '"') inQuotes = true;
            else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else if (c == '\r') { }
            else if (c == '\n') { fields.Add(sb.ToString()); sb.Clear(); records.Add(fields.ToArray()); fields = []; }
            else sb.Append(c);
        }
        if (sb.Length > 0 || fields.Count > 0) { fields.Add(sb.ToString()); records.Add(fields.ToArray()); }
        if (records.Count == 0) return [];
        var header = records[0];
        return records.Skip(1).Select(r =>
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < header.Length && i < r.Length; i++) d[header[i]] = r[i];
            return (IReadOnlyDictionary<string, string>)d;
        }).ToArray();
    }
    #endregion

    #region Fields
    public readonly string name;
    public readonly string platform;
    public readonly IConfigurationSection toolConfig;
    public readonly AuditEnvironment auditEnvironment;
    #endregion
}