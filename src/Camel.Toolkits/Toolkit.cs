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
    }
    #endregion

    #region Properties
    public abstract string[] ToolList { get; }
    public Dictionary<string, Tool> Tools { get; } = new Dictionary<string, Tool>();
    #endregion

    #region Methods
    public Tool GetTool(string name) => new Tool(name, GetRequiredValue(toolConfig, $"{name}:Description"), GetRequiredValue(toolConfig, $"{name}:Command"), bool.Parse(toolConfig[$"{name}:Sudo"] ?? "false"));

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
            return json.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(l => l.TrimStart('﻿'))   // EvtxECmd prefixes the file with a BOM
                .Where(l => l.StartsWith('{'))
                .Select(l => System.Text.Json.JsonSerializer.Deserialize<T>(l))
                .Where(x => x is not null).Select(x => x!).ToArray();
        }
        finally { auditEnvironment.ExecuteCommand("rm", $"-rf {dir}", out _, false); }
    }

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

    /// <summary>Parses CSV text (RFC4180-style quoting) into rows keyed by the header columns.</summary>
    private static IReadOnlyDictionary<string, string>[] ParseCsv(string text)
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