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


[Verb("server", HelpText = "Start the Camel MCP server.")]
public class ServerOptions : Options
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

    [Option("http", Required = false, HelpText = "Enable the MCP server HTTP transport.")]
    public bool Http { get; set; }
}


[Verb("test", HelpText = "Test different CLI commands and options.")]
public class TestOptions : Options
{
    [Option("exec", Required = false, HelpText = "Execute JavaScript using the embedded interpreter.")]
    public string? Exec  { get; set; }
}
