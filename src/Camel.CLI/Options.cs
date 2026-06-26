namespace Camel.CLI;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using CommandLine;

public class Options
{
    [Option("debug", Required = false, HelpText = "Enable debug mode.")]
    public bool Debug { get; set; }
   
    [Option("options", Required = false, HelpText = "Any additional options for the selected operation.")]
    public string AdditionalOptions { get; set; } = String.Empty;

    public static Dictionary<string, object> Parse(string o)
    {
        Dictionary<string, object> options = new Dictionary<string, object>();
        Regex re = new Regex(@"(\w+)\=([^\,]+)", RegexOptions.Compiled);
        string[] pairs = o.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string s in pairs)
        {
            Match m = re.Match(s);
            if (!m.Success)
            {
                options.Add("_ERROR_", s);
            }
            else if (options.ContainsKey(m.Groups[1].Value))
            {
                options[m.Groups[1].Value] = m.Groups[2].Value;
            }
            else
            {
                options.Add(m.Groups[1].Value, m.Groups[2].Value);
            }
        }
        return options;
    }
}


/// <summary>
/// Environment/connection options shared by the <c>server</c> and <c>create-case</c> verbs. Holds no
/// <see cref="VerbAttribute"/> itself so it is never treated as a verb; the verb classes inherit it.
/// </summary>
public class ConnectionOptions : Options
{
    [Option("local", Required = false, HelpText = "Use the local environment, overriding the configuration file environment setting.")]
    public bool Local { get; set; }

    [Option("ssh", Required = false, HelpText = "Use the SSH environment, overriding the configuration file environment setting. SSH login data will still be pulled from the configuration file unless overridden by --host/--user/--pass/--port.")]
    public bool Ssh { get; set; }

    [Option("host", Required = false, HelpText = "SSH host of the SIFT workstation, overriding the configuration file. Supplying it implies SSH mode unless --local is set.")]
    public string Host { get; set; } = String.Empty;

    [Option("user", Required = false, HelpText = "SSH user, overriding the configuration file. Supplying it implies SSH mode unless --local is set.")]
    public string User { get; set; } = String.Empty;

    [Option("pass", Required = false, HelpText = "SSH password, overriding the configuration file. Supplying it implies SSH mode unless --local is set.")]
    public string Password { get; set; } = String.Empty;

    [Option("port", Required = false, HelpText = "SSH port, overriding the configuration file (defaults to 22 when SSH connection details are supplied on the command line).")]
    public int? Port { get; set; }

    [Option("platform", Required = false, HelpText = "Tool/connection platform profile to use (e.g. SIFT, Kali, PTF, Slingshot), overriding the config 'Platform' key. Defaults to SIFT for DFIR and Kali for PenTest. Connection overrides (--host/--user/...) apply to this profile.")]
    public string Platform { get; set; } = String.Empty;
}


[Verb("server", HelpText = "Start the Camel MCP server (DFIR/blue-team; alias of dfir-server).")]
public class ServerOptions : ConnectionOptions
{
    [Option("http", Required = false, HelpText = "Enable the MCP server HTTP transport.")]
    public bool Http { get; set; }

    [Option("case-dir", Required = false, HelpText = "The case directory to write the per-case audit log into (as <case-dir>/audit/). `create-case` bakes this into the generated .mcp.json so the audit trail lands in the case. Defaults to <assembly-dir>/audit when omitted.")]
    public string CaseDir { get; set; } = String.Empty;
}


/// <summary>The DFIR (blue-team) MCP server verb. Same options as <see cref="ServerOptions"/>; selects the
/// DFIR tool surface (SIFT toolkits + workflows + anomaly engine + evidence guard).</summary>
[Verb("dfir-server", HelpText = "Start the Camel DFIR (blue-team) MCP server: SIFT toolkits/workflows, the anomaly engine, and the evidence-spoliation guard (SetEvidence).")]
public class DfirServerOptions : ServerOptions { }


/// <summary>The PenTest (red-team) MCP server verb. Same options as <see cref="ServerOptions"/>; selects the
/// offensive tool surface and the engagement gate (SetEngagement). Defaults the platform to Kali.</summary>
[Verb("pentest-server", HelpText = "Start the Camel PenTest (red-team) MCP server: offensive toolkits confined by the engagement authorization+scope gate (SetEngagement). Defaults --platform to Kali.")]
public class PenTestServerOptions : ServerOptions { }


[Verb("preserve-chatlog", Hidden = true, HelpText = "Internal Claude Code SessionEnd hook: read the hook payload from stdin and copy the client chat transcript into the case (analysis/chatlogs/). Wired into each case's .claude/settings.json by create-case.")]
public class PreserveChatlogOptions : Options
{
}


[Verb("bake-report", HelpText = "Regenerate a case's self-contained HTML report (reports/report.html + report.js) and embed its current data — audit log, chat log(s), accuracy.md, iocs.csv — so it opens by double-click with no server. Runs automatically at session end; run it manually to re-bake. Safe to re-run.")]
public class BakeReportOptions : Options
{
    [Value(0, MetaName = "case-dir", Required = true, HelpText = "The case directory (the one containing CLAUDE.md, logs/, and reports/).")]
    public string CaseDir { get; set; } = String.Empty;
}


[Verb("create-case", HelpText = "Create a Camel case directory (CLAUDE.md + .mcp.json + analysis/exports/reports) and register the MCP server. Accepts the same connection options as the server verb; they are baked into the generated .mcp.json so Claude Code launches Camel in that mode.")]
public class CreateCaseOptions : ConnectionOptions
{
    [Value(0, MetaName = "case-dir", Required = true, HelpText = "Parent directory under which the case subdirectory is created.")]
    public string CaseDir { get; set; } = String.Empty;

    [Value(1, MetaName = "case-id", Required = true, HelpText = "Case id — used as the subdirectory name, the SetCaseId value, and the audit log name (letters, digits, dot, underscore, dash).")]
    public string CaseId { get; set; } = String.Empty;

    [Option("type", Required = false, HelpText = "Investigation type: DFIR (blue-team; default) or PenTest (red-team). Selects the case's CLAUDE.md brief and the MCP server verb baked into .mcp.json (dfir-server vs pentest-server).")]
    public InvestigationType Type { get; set; } = InvestigationType.DFIR;
}
