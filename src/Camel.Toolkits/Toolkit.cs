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
        toolConfig = config.GetRequiredSection($"Tools:{name}");
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
    public Tool GetTool(string name) => new Tool(name, GetRequiredValue(toolConfig, $"{name}:Description"), GetRequiredValue(toolConfig, $"{name}:Command"), bool.Parse(toolConfig[$"{name}:Sudo"] ?? "false"));

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

    public T? ExecuteTool<T>(string name, string args) where T : class
    {
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
    private static T[] ParseJsonLines<T>(string json) =>
        json.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.TrimStart('﻿'))   // some tools (e.g. EvtxECmd) prefix the file with a BOM
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

    /// <summary>Reads a CSV file on the audit environment and maps its rows; null on read failure.</summary>
    public T[]? ReadCsvFile<T>(string path, Func<IReadOnlyDictionary<string, string>, T> map) =>
        auditEnvironment.ExecuteCommand("cat", $"'{path}'", out string csv, false) ? ParseCsv(csv).Select(map).ToArray() : null;

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
    public readonly IConfigurationSection toolConfig;
    public readonly AuditEnvironment auditEnvironment;   
    #endregion
}