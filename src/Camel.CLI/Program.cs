namespace Camel.CLI;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using CommandLine;
using CommandLine.Text;
using Microsoft.Extensions.AI;
using Spectre.Console;

using Camel.Environments;

internal class Program : Runtime
{
    static Program()
    {               
        config = LoadConfigFile(Path.Combine(AssemblyLocation, "appsettings.json"));
        if (config is null) throw new Exception("Configuration not loaded.");
        environmentType = Enum.Parse<EnvironmentType>(GetRequiredValue(config, "SIFT:Environment"));
        auditEnvironment = le;
    }

    static async Task Main(string[] args)
    {
        PrintLogo();
        Runtime.WithFileAndConsoleLogging("Camel", "CLI", args.Contains("--debug"));        
        var parser = new Parser(with =>
        {
            with.CaseInsensitiveEnumValues = true;
            with.HelpWriter = null;
        });
        var result = parser.ParseArguments<ServerOptions, CreateCaseOptions>(args);
        try
        {
            await result.MapResult(

                async (ServerOptions opts) => await HandleServerArgs(opts),
                async (CreateCaseOptions opts) => await HandleCreateCaseArgs(opts),               
                errs => HandleParseError(result, errs)
            );
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
        }
    }

    static async Task HandleServerArgs(ServerOptions opts)
    {
        if (config is null) throw new Exception("Configuration not loaded.");

        Runtime.WithAuditLog(Path.Combine(AssemblyLocation, "audit"));

        if (opts.Ssh)
        {
            config["SIFT:Environment"] = "Ssh";
        }
        else if (opts.Local)
        {
            config["SIFT:Environment"] = "Local";
        }

        // SSH connection overrides from the command line, so the user can point Camel at a remote SIFT
        // workstation without editing appsettings.json (e.g. running protocol-sift-camel on Windows against a
        // remote Linux SIFT box). Any supplied detail implies SSH mode unless the user explicitly forced --local.
        if (!string.IsNullOrWhiteSpace(opts.Host)) config["SIFT:Host"] = opts.Host;
        if (!string.IsNullOrWhiteSpace(opts.User)) config["SIFT:User"] = opts.User;
        if (!string.IsNullOrWhiteSpace(opts.Password)) config["SIFT:Password"] = opts.Password;
        if (opts.Port.HasValue) config["SIFT:Port"] = opts.Port.Value.ToString();
        if (!opts.Local && (!string.IsNullOrWhiteSpace(opts.Host) || !string.IsNullOrWhiteSpace(opts.User)
                            || !string.IsNullOrWhiteSpace(opts.Password) || opts.Port.HasValue))
        {
            config["SIFT:Environment"] = "Ssh";
        }
        // Default the SSH port when connection details were supplied on the command line but no port was set
        // anywhere, so SSH mode doesn't fail on a missing SIFT:Port.
        if (Enum.Parse<EnvironmentType>(GetRequiredValue(config, "SIFT:Environment")) == EnvironmentType.Ssh
            && string.IsNullOrWhiteSpace(config["SIFT:Port"]))
        {
            config["SIFT:Port"] = "22";
        }

        if (Enum.Parse<EnvironmentType>(GetRequiredValue(config, "SIFT:Environment")) == EnvironmentType.Ssh)
        {
            // Fail fast: verify SSH connectivity once at startup (sessions then connect lazily on first use).
            host = GetRequiredValue(config, "SIFT:Host");
            if (AuditEnvironment.CreateFromConfig(config) is SshAuditEnvironment se && !se.IsConnected)
            {
                Error($"Could not connect to SSH environment on host {host}.");
                Environment.Exit(1);
            }           
        }
        else
        {
            Info($"Using local environment on host {Environment.MachineName}");
        }
        if (opts.Http)
        {
            Info("Starting Camel MCP Server in HTTP mode.");
            await CamelMCPServer.RunHttpAsync(config);
        }
        else
        {
            Info("Starting Camel MCP Server in stdio mode.");
            await CamelMCPServer.RunStdioAsync(config);
        }
    }

    static Task HandleCreateCaseArgs(CreateCaseOptions opts)
    {
        // The case id becomes a directory name, the SetCaseId value, and the audit-<caseId>.clef filename,
        // so restrict it to a safe identifier (this also keeps the template substitution injection-free).
        if (string.IsNullOrWhiteSpace(opts.CaseId) || !CaseIdPattern.IsMatch(opts.CaseId))
        {
            Error("Case id must contain only letters, digits, dot, underscore, or dash.");
            Environment.Exit(2);
        }

        var caseDir = Path.Combine(opts.CaseDir, opts.CaseId);
        foreach (var sub in new[] { "analysis", "exports", "reports" })
            Directory.CreateDirectory(Path.Combine(caseDir, sub));

        // CLAUDE.md — write the embedded template with the case id substituted into the SetCaseId() call
        // (and the audit file name / overview). Leave an existing file untouched so re-running a case
        // doesn't clobber filled-in details.
        var claudePath = Path.Combine(caseDir, "CLAUDE.md");
        if (File.Exists(claudePath))
        {
            Info($"{claudePath} already exists — leaving it untouched.");
        }
        else
        {
            var claude = ReadEmbedded("Camel.CLI.CaseTemplate.CLAUDE.md").Replace("__CASE_ID__", opts.CaseId);
            File.WriteAllText(claudePath, claude);
            Info($"Wrote {claudePath}");
        }

        // .mcp.json — register the `camel` stdio server launching THIS CLI assembly, with the same
        // connection flags the user passed to create-case baked into the args so Claude Code starts
        // Camel in that mode. Leave an existing file untouched (e.g. a hand-tuned SSH registration).
        var mcpPath = Path.Combine(caseDir, ".mcp.json");
        if (File.Exists(mcpPath))
        {
            Info($"{mcpPath} already exists — leaving it untouched.");
        }
        else
        {
            var node = JsonNode.Parse(ReadEmbedded("Camel.CLI.CaseTemplate.mcp.json"))!;
            node["mcpServers"]!["camel"]!["args"] =
                new JsonArray(BuildServerArgs(opts).Select(a => (JsonNode)JsonValue.Create(a)).ToArray());
            File.WriteAllText(mcpPath, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            Info($"Wrote {mcpPath}");
        }

        // .claude/ — project-scoped settings (code-mode policy: deny Bash, allow only the Camel MCP tools
        // + scoped file writes) plus the SessionEnd hook that preserves the client chat log into the case.
        // Emitting these per case makes the case self-contained — nothing depends on a global ~/.claude
        // install (which matters on Windows, where there is no installer). Existing files are left untouched.
        var dotClaude = Path.Combine(caseDir, ".claude");
        Directory.CreateDirectory(dotClaude);

        WriteIfAbsent(Path.Combine(dotClaude, "settings.json"), "Camel.CLI.CaseTemplate.settings.json");
        WriteIfAbsent(Path.Combine(dotClaude, "preserve_chatlog.py"), "Camel.CLI.CaseTemplate.preserve_chatlog.py");

        Info($"Case '{opts.CaseId}' ready at {caseDir}.");
        AnsiConsole.MarkupLine($"[green][bold]\nFill in the case details in {Path.Combine(caseDir, "CLAUDE.md")}. When you are ready launch Claude in that directory.[/][/]");
        return Task.CompletedTask;

        // Write an embedded resource verbatim, unless the destination already exists (idempotent re-runs).
        void WriteIfAbsent(string path, string resource)
        {
            if (File.Exists(path)) { Info($"{path} already exists — leaving it untouched."); return; }
            File.WriteAllText(path, ReadEmbedded(resource));
            Info($"Wrote {path}");
        }
    }

    /// <summary>
    /// Builds the args array for the generated <c>.mcp.json</c>: launches this CLI assembly's <c>server</c>
    /// verb, carrying through the connection flags passed to <c>create-case</c> (any of --host/--user/--pass/
    /// --port implies --ssh unless --local was given), so Claude Code starts Camel in the requested mode.
    /// </summary>
    static List<string> BuildServerArgs(CreateCaseOptions opts)
    {
        // Path to this running CLI assembly (empty for single-file publishes — fall back to the assembly dir).
        var dll = Assembly.GetEntryAssembly()?.Location;
        if (string.IsNullOrEmpty(dll)) dll = Path.Combine(AssemblyLocation, "Camel.CLI.dll");

        var args = new List<string> { dll, "server" };
        bool conn = !string.IsNullOrWhiteSpace(opts.Host) || !string.IsNullOrWhiteSpace(opts.User)
                    || !string.IsNullOrWhiteSpace(opts.Password) || opts.Port.HasValue;
        if (opts.Local) args.Add("--local");
        else if (opts.Ssh || conn) args.Add("--ssh");
        if (!string.IsNullOrWhiteSpace(opts.Host)) { args.Add("--host"); args.Add(opts.Host); }
        if (!string.IsNullOrWhiteSpace(opts.User)) { args.Add("--user"); args.Add(opts.User); }
        if (!string.IsNullOrWhiteSpace(opts.Password)) { args.Add("--pass"); args.Add(opts.Password); }
        if (opts.Port.HasValue) { args.Add("--port"); args.Add(opts.Port.Value.ToString()); }
        return args;
    }

    static string ReadEmbedded(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded case template '{name}' was not found in the assembly.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    static readonly Regex CaseIdPattern = new("^[A-Za-z0-9._-]+$", RegexOptions.Compiled);

    static Task HandleParseError<T>(ParserResult<T> result, IEnumerable<CommandLine.Error> errs)
    {
        var helpText = HelpText.AutoBuild(result, h =>
        {
            h.AddOptions(result);
            return h;
        },
        e =>
        {
            return e;
        });
        Console.WriteLine(helpText);
        return Task.CompletedTask;
    }


    static void PrintLogo()
    {
        AnsiConsole.Write(new FigletText("Camel\n").Color(Color.Orange1));
    }
   
    static EnvironmentType environmentType = EnvironmentType.Local;
    static LocalEnvironment le = new LocalEnvironment();
    static AuditEnvironment auditEnvironment;
    static string user = "", host = "", password = "";
    static int port;

}
