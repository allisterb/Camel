namespace Camel.Toolkits.Models;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>
/// Optional flags for a YARA scan. All fields are nullable; only those that are set are passed to the
/// <c>yara</c> command. Mirrors the useful command-line flags from the yara-hunting reference.
/// </summary>
public class YaraOptions
{
    public bool? Recurse { get; set; }            // -r            recursive directory scan
    public bool? PrintStrings { get; set; }       // -s            print matching strings (with offset)
    public bool? PrintMeta { get; set; }          // -m            print rule metadata
    public bool? PrintTags { get; set; }          // -g            print rule tags
    public bool? PrintNamespace { get; set; }     // -e            print rule namespace
    public bool? PrintNonMatching { get; set; }   // -n            print rules that did NOT match
    public bool? FastScan { get; set; }           // -f            fast mode (first match per rule)
    public bool? Compiled { get; set; }           // -C            rules file is compiled (yarac output)
    public bool? NoFollowSymlinks { get; set; }   // -N            do not follow symlinks
    public bool? ScanList { get; set; }           // --scan-list   scan target is a file of paths
    public int? Threads { get; set; }             // -p N          worker threads
    public int? Timeout { get; set; }             // --timeout N   skip a file after N seconds
    public int? MaxRules { get; set; }            // --max-rules=N abort after N rules match
    public string? Tag { get; set; }              // -t TAG        only apply rules with this tag
    public Dictionary<string, string>? Define { get; set; } // -d var=val external variables

    /// <summary>Renders the set options as a yara argument prefix (trailing space included when non-empty).</summary>
    public string ToArgs()
    {
        var sb = new StringBuilder();
        if (Recurse == true) sb.Append("-r ");
        if (PrintStrings == true) sb.Append("-s ");
        if (PrintMeta == true) sb.Append("-m ");
        if (PrintTags == true) sb.Append("-g ");
        if (PrintNamespace == true) sb.Append("-e ");
        if (PrintNonMatching == true) sb.Append("-n ");
        if (FastScan == true) sb.Append("-f ");
        if (Compiled == true) sb.Append("-C ");
        if (NoFollowSymlinks == true) sb.Append("-N ");
        if (ScanList == true) sb.Append("--scan-list ");
        if (Threads is int p) sb.Append($"-p {p} ");
        if (Timeout is int t) sb.Append($"--timeout {t} ");
        if (MaxRules is int mr) sb.Append($"--max-rules={mr} ");
        if (Tag is { Length: > 0 } tag) sb.Append($"-t {tag} ");
        if (Define is not null)
            foreach (var kv in Define) sb.Append($"-d {kv.Key}={kv.Value} ");
        return sb.ToString();
    }
}

/// <summary>A single YARA scan match: a rule that matched a target file.</summary>
public class YaraMatch
{
    public string? Namespace { get; set; }
    public string Rule { get; set; } = "";
    public string[] Tags { get; set; } = [];
    public string? Meta { get; set; }
    public string Target { get; set; } = "";
    public List<string> MatchedStrings { get; set; } = [];

    // Header: "[namespace:]rule [tags] [meta] path". A tags bracket has no '='; a meta bracket does.
    private static readonly Regex Header = new(
        @"^(?:(?<ns>[^:\s\[]+):)?(?<rule>[A-Za-z_]\w*)(?<brackets>(?:\s+\[[^\]]*\])*)\s+(?<target>.+)$",
        RegexOptions.Compiled);
    // Detail line emitted by -s, e.g. "0x6:$a: CamelForensics".
    private static readonly Regex Detail = new(@"^0x[0-9a-fA-F]+:", RegexOptions.Compiled);
    private static readonly Regex Bracket = new(@"\[([^\]]*)\]", RegexOptions.Compiled);

    public static YaraMatch[] ParseAll(string s)
    {
        var matches = new List<YaraMatch>();
        YaraMatch? current = null;
        foreach (var raw in s.Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.Length == 0) continue;
            if (Detail.IsMatch(line)) { current?.MatchedStrings.Add(line.Trim()); continue; }

            var m = Header.Match(line);
            if (!m.Success) continue;

            current = new YaraMatch
            {
                Namespace = m.Groups["ns"].Success ? m.Groups["ns"].Value : null,
                Rule = m.Groups["rule"].Value,
                Target = m.Groups["target"].Value,
            };
            var tags = new List<string>();
            foreach (Match b in Bracket.Matches(m.Groups["brackets"].Value))
            {
                var inner = b.Groups[1].Value;
                if (inner.Contains('=')) current.Meta = inner;   // meta: key=value pairs
                else tags.AddRange(inner.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
            }
            current.Tags = tags.ToArray();
            matches.Add(current);
        }
        return matches.ToArray();
    }
}
